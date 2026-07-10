package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// rwEngine wires a real engine (fake Caddy edge, deny-only, + internal AND public
// dnscontrol DNS) so the MCP write path can be exercised end to end: expose makes a
// public record (so the auth gate has teeth), and --scope internal has a public
// record to suppress.
func rwEngine(t *testing.T) (*core.Engine, *dnscontrolfake.Shell, *dnscontrolfake.Shell) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(cf.URL(), res)
	inSh := dnscontrolfake.New("example.com")
	pubSh := dnscontrolfake.New("example.com")
	internal := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: inSh})
	public := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh})
	return core.New(edge, "example.com", internal, public), inSh, pubSh
}

// driveRWMCP runs frames against a READ/WRITE MCP server over the given engine. Each
// call spins a FRESH server over the same engine, so a plan computed in one call and
// applied in a later call proves the plan_id gate is stateless (the applying server
// never saw the preview).
func driveRWMCP(t *testing.T, engine *core.Engine, frames ...string) []rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	var out bytes.Buffer
	srv := newReadWriteMCPServer(engine, "test-rw")
	if err := srv.serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []rpcResponse
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode: %v (raw=%q)", err, out.String())
		}
		resps = append(resps, r)
	}
	return resps
}

func callFrame(tool, argsJSON string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + argsJSON + `}}`
}

// mcpPlan calls crenel_plan and decodes the structured previewResult.
func mcpPlan(t *testing.T, engine *core.Engine, argsJSON string) previewResult {
	t.Helper()
	resps := driveRWMCP(t, engine, callFrame("crenel_plan", argsJSON))
	res := resultMap(t, resps[0])
	if res["isError"] == true {
		t.Fatalf("crenel_plan errored: %s", toolText(t, res))
	}
	var pr previewResult
	mustStructured(t, res, &pr)
	return pr
}

// TestMCP_WriteToolsGatedByMode proves the write tools appear ONLY in --write mode:
// the read-only server advertises 3 tools and cannot call crenel_plan; the
// read/write server advertises 5 and can.
func TestMCP_WriteToolsGatedByMode(t *testing.T) {
	engine, _, _ := rwEngine(t)

	// Read-only server: no write tools, not callable.
	ro := driveMCP(t, engine,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		callFrame("crenel_plan", `{"verb":"expose","service":"grafana"}`),
	)
	roList := resultMap(t, ro[0])
	if tools, _ := roList["tools"].([]any); len(tools) != 3 {
		t.Fatalf("read-only server should advertise 3 tools, got %d", len(tools))
	}
	if ro[1].Error == nil || !strings.Contains(ro[1].Error.Message, "unknown tool") {
		t.Fatalf("read-only server must reject crenel_plan as unknown, got %+v", ro[1])
	}

	// Read/write server: 5 tools incl. the write pair.
	rw := driveRWMCP(t, engine, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	names := map[string]bool{}
	for _, ti := range resultMap(t, rw[0])["tools"].([]any) {
		names[ti.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"crenel_status", "crenel_audit", "crenel_drift", "crenel_plan", "crenel_apply"} {
		if !names[want] {
			t.Errorf("read/write tools/list missing %q (got %v)", want, names)
		}
	}
}

// TestMCP_TwoPhaseHappyPath: plan an internal expose (no auth needed), then apply
// with the returned plan_id. The route lands, verifies, and (scope=internal) no
// public record is created — proving #1's --scope flows through the MCP.
func TestMCP_TwoPhaseHappyPath(t *testing.T) {
	engine, inSh, pubSh := rwEngine(t)

	pr := mcpPlan(t, engine, `{"verb":"expose","service":"grafana","scope":"internal"}`)
	if pr.PlanID == "" {
		t.Fatal("plan must return a plan_id")
	}
	if pr.GoesPublic || pr.AuthRequired {
		t.Fatalf("internal scope must not go public / require auth, got %+v", pr)
	}

	res := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"expose","service":"grafana","scope":"internal","confirm_plan_id":"`+pr.PlanID+`"}`))
	out := resultMap(t, res[0])
	if out["isError"] == true {
		t.Fatalf("apply should succeed: %s", toolText(t, out))
	}
	var ar applyResult
	mustStructured(t, out, &ar)
	if !ar.Applied || !ar.Verified {
		t.Fatalf("apply should be applied+verified, got %+v", ar)
	}
	if inSh.LiveCount() != 1 {
		t.Errorf("internal DNS should hold 1 record, got %d", inSh.LiveCount())
	}
	if pubSh.LiveCount() != 0 {
		t.Errorf("public DNS must stay empty under scope internal, got %d", pubSh.LiveCount())
	}
}

// TestMCP_ApplyRequiresConfirmID: crenel_apply with no confirm_plan_id is refused
// and mutates nothing.
func TestMCP_ApplyRequiresConfirmID(t *testing.T) {
	engine, inSh, _ := rwEngine(t)
	res := driveRWMCP(t, engine, callFrame("crenel_apply", `{"verb":"expose","service":"grafana","scope":"internal"}`))
	out := resultMap(t, res[0])
	if out["isError"] != true || !strings.Contains(toolText(t, out), "confirm_plan_id") {
		t.Fatalf("apply without confirm_plan_id must error, got %v", out)
	}
	if inSh.LiveCount() != 0 {
		t.Fatalf("no write should have happened, internal records=%d", inSh.LiveCount())
	}
}

// TestMCP_ApplyRejectsWrongID: a confirm_plan_id that does not match the live-
// computed change is refused (the anti-blind-write / TOCTOU gate) and mutates
// nothing. Here the id belongs to a DIFFERENT change (photos), applied to grafana.
func TestMCP_ApplyRejectsWrongID(t *testing.T) {
	engine, inSh, pubSh := rwEngine(t)

	other := mcpPlan(t, engine, `{"verb":"expose","service":"photos","scope":"internal"}`)

	res := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"expose","service":"grafana","scope":"internal","confirm_plan_id":"`+other.PlanID+`"}`))
	out := resultMap(t, res[0])
	if out["isError"] != true || !strings.Contains(toolText(t, out), "plan_id mismatch") {
		t.Fatalf("apply with a mismatched id must be refused, got %v", out)
	}
	if inSh.LiveCount() != 0 || pubSh.LiveCount() != 0 {
		t.Fatalf("a rejected apply must mutate nothing (internal=%d public=%d)", inSh.LiveCount(), pubSh.LiveCount())
	}
}

// TestMCP_PublicWithoutAuthRefused: planning a public expose flags auth_required;
// applying it without auth is refused even with a valid plan_id. Adding auth=none
// (a new plan) applies.
func TestMCP_PublicWithoutAuthRefused(t *testing.T) {
	engine, _, pubSh := rwEngine(t)

	// Public expose, no auth: preview flags it, apply refuses.
	pr := mcpPlan(t, engine, `{"verb":"expose","service":"grafana"}`)
	if !pr.GoesPublic || !pr.AuthRequired {
		t.Fatalf("public expose with no auth should flag goes_public + auth_required, got %+v", pr)
	}
	res := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"expose","service":"grafana","confirm_plan_id":"`+pr.PlanID+`"}`))
	out := resultMap(t, res[0])
	if out["isError"] != true || !strings.Contains(toolText(t, out), "no auth") {
		t.Fatalf("public-without-auth apply must be refused, got %v", out)
	}
	if pubSh.LiveCount() != 0 {
		t.Fatalf("nothing should be published, public records=%d", pubSh.LiveCount())
	}

	// With auth=none it is a different change (different id); plan + apply succeeds.
	pr2 := mcpPlan(t, engine, `{"verb":"expose","service":"grafana","auth":"none"}`)
	if pr2.AuthRequired {
		t.Fatalf("auth=none should satisfy the gate, got %+v", pr2)
	}
	res2 := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"expose","service":"grafana","auth":"none","confirm_plan_id":"`+pr2.PlanID+`"}`))
	out2 := resultMap(t, res2[0])
	if out2["isError"] == true {
		t.Fatalf("public expose WITH auth=none should apply: %s", toolText(t, out2))
	}
	if pubSh.LiveCount() != 1 {
		t.Fatalf("public record should now exist, got %d", pubSh.LiveCount())
	}
}

// TestMCP_SetAndUnexposeTwoPhase covers the set + unexpose verbs through the same
// gate: set on internal, then unexpose removes it.
func TestMCP_SetAndUnexposeTwoPhase(t *testing.T) {
	engine, inSh, _ := rwEngine(t)

	on := mcpPlan(t, engine, `{"verb":"set","service":"grafana","state":"on","scope":"internal"}`)
	res := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"set","service":"grafana","state":"on","scope":"internal","confirm_plan_id":"`+on.PlanID+`"}`))
	if resultMap(t, res[0])["isError"] == true {
		t.Fatalf("set on should apply: %s", toolText(t, resultMap(t, res[0])))
	}
	if inSh.LiveCount() != 1 {
		t.Fatalf("set on should create the internal record, got %d", inSh.LiveCount())
	}

	off := mcpPlan(t, engine, `{"verb":"unexpose","service":"grafana","scope":"internal"}`)
	res2 := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"unexpose","service":"grafana","scope":"internal","confirm_plan_id":"`+off.PlanID+`"}`))
	if resultMap(t, res2[0])["isError"] == true {
		t.Fatalf("unexpose should apply: %s", toolText(t, resultMap(t, res2[0])))
	}
	if inSh.LiveCount() != 0 {
		t.Fatalf("unexpose should remove the internal record, got %d", inSh.LiveCount())
	}
}

// TestMCP_PlanIsPureRead proves crenel_plan mutates nothing: after a plan, the edge
// still has no managed route and DNS is untouched.
func TestMCP_PlanIsPureRead(t *testing.T) {
	engine, inSh, pubSh := rwEngine(t)
	_ = mcpPlan(t, engine, `{"verb":"expose","service":"grafana"}`)
	st, err := engine.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, es := range st.Edges {
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				t.Fatalf("crenel_plan must not create a route, found %+v", r)
			}
		}
	}
	if inSh.LiveCount() != 0 || pubSh.LiveCount() != 0 {
		t.Fatalf("crenel_plan must not touch DNS (internal=%d public=%d)", inSh.LiveCount(), pubSh.LiveCount())
	}
}

// TestMCP_UnknownVerbRejected: a bogus verb is a clean tool error, not a panic.
func TestMCP_UnknownVerbRejected(t *testing.T) {
	engine, _, _ := rwEngine(t)
	res := driveRWMCP(t, engine, callFrame("crenel_plan", `{"verb":"nuke","service":"grafana"}`))
	out := resultMap(t, res[0])
	if out["isError"] != true || !strings.Contains(toolText(t, out), "unknown verb") {
		t.Fatalf("unknown verb should be a tool error, got %v", out)
	}
}

// TestMCP_WriteComposesWithEngineReadOnly proves the two-phase MCP write gate
// COMPOSES with the engine-level read-only posture (M-A1's Engine.ReadOnly):
// even if the operator starts `crenel mcp --write`, an engine constructed
// read-only refuses crenel_apply at the ENGINE layer (ErrReadOnlyEngine text),
// before any driver plan/apply. crenel_plan stays available — planning is a
// pure read, exactly like CLI preview on a read-only engine.
func TestMCP_WriteComposesWithEngineReadOnly(t *testing.T) {
	engine, _, _ := rwEngine(t)
	engine.ReadOnly = true

	// Plan still works: pure read, computes the diff and a plan_id.
	pr := mcpPlan(t, engine, `{"verb":"expose","service":"grafana","scope":"internal"}`)
	if pr.PlanID == "" {
		t.Fatalf("crenel_plan on a read-only engine should still preview; got %+v", pr)
	}

	// Apply with the CORRECT plan_id is refused by the engine's read-only gate.
	res := driveRWMCP(t, engine, callFrame("crenel_apply",
		`{"verb":"expose","service":"grafana","scope":"internal","confirm_plan_id":"`+pr.PlanID+`"}`))
	out := resultMap(t, res[0])
	if out["isError"] != true || !strings.Contains(toolText(t, out), "READ-ONLY") {
		t.Fatalf("apply on a read-only engine must refuse via the engine gate; got %v", toolText(t, out))
	}
}
