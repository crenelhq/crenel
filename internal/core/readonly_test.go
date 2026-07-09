package core_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// foreignEdge returns a generator-owned edge whose audit is otherwise CLEAN (deny
// enforced, fully parsed, the one route auth-protected) — so the ONLY severity
// that decides OK()/exit is the ownership/generator finding under test.
func foreignEdge() stubEdge {
	return stubEdge{name: "traefik", live: model.LiveEdgeState{
		Generator:           "pangolin",
		DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "vault.example.com", Upstream: model.Upstream{
			Mode: model.ModeHTTPProxy, Address: "10.0.0.7:8200", ServerName: "vault.example.com", Auth: "badger"}}},
	}}
}

// TestReadOnly_ForeignEdgeAuditIsOK: on a ReadOnly engine the edge-wide generator
// fact is the CONTRACT, not a surprise — audit re-frames it as ok-severity
// foreign_managed_readonly (always printed, never dropped) and an otherwise-clean
// foreign edge audits OK (the exit-0 cron case). See audit-any-edge §3.3.
func TestReadOnly_ForeignEdgeAuditIsOK(t *testing.T) {
	e := core.NewMulti([]core.EdgeBinding{{Name: "edge", Provider: foreignEdge()}}, "example.com")
	e.ReadOnly = true
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "foreign_managed_readonly")
	if !ok || f.Severity != "ok" {
		t.Fatalf("ReadOnly audit of a foreign edge should emit ok-severity foreign_managed_readonly, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "pangolin") || !strings.Contains(f.Message, "read-only") {
		t.Errorf("the re-framed finding must still name the generator and the posture, got %q", f.Message)
	}
	if _, ok := findCode(rep, "ownership_unconfirmed"); ok {
		t.Errorf("the edge-wide generator warning must be RE-FRAMED, not duplicated, got %+v", rep.Findings)
	}
	if !rep.OK() {
		t.Errorf("a clean foreign edge under ReadOnly must audit OK (exit 0), got %+v", rep.Findings)
	}
}

// TestReadOnly_WritableWarningUnchanged is the A.7 invariant: the severity
// downgrade is keyed STRICTLY on Engine.ReadOnly — on a WRITABLE engine the same
// edge keeps the ownership_unconfirmed WARNING (the gate and its warning never
// diverge), so the MISMANAGE net is never blunted.
func TestReadOnly_WritableWarningUnchanged(t *testing.T) {
	e := core.NewMulti([]core.EdgeBinding{{Name: "edge", Provider: foreignEdge()}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "ownership_unconfirmed")
	if !ok || f.Severity != "warning" {
		t.Fatalf("a writable engine must keep the ownership_unconfirmed WARNING, got %+v", rep.Findings)
	}
	if _, ok := findCode(rep, "foreign_managed_readonly"); ok {
		t.Errorf("foreign_managed_readonly must never leak into a writable engine's audit, got %+v", rep.Findings)
	}
	if rep.OK() {
		t.Error("a foreign edge on a writable engine must NOT audit OK")
	}
}

// TestReadOnly_PerRouteUnknownStaysWarning: only the EDGE-WIDE generator finding is
// re-framed. A per-route foreign/unknown ownership finding stays a warning even
// under ReadOnly — unknown is genuinely unresolved, and downgrading it would hide
// real ambiguity (§3.3).
func TestReadOnly_PerRouteUnknownStaysWarning(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "mystery.example.com", Ownership: model.OwnUnknown, Upstream: model.Upstream{
			Mode: model.ModeHTTPProxy, Address: "10.0.0.9:3000", ServerName: "mystery.example.com", Auth: "authelia"}}},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	e.ReadOnly = true
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "ownership_unconfirmed"); !ok || f.Severity != "warning" {
		t.Errorf("per-route unknown ownership must stay a WARNING under ReadOnly, got %+v", rep.Findings)
	}
}

// mutatingEdge wraps stubEdge to RECORD whether any Plan/Apply was ever reached —
// the read-only refusal must fire BEFORE planning, so both stay false.
type mutatingEdge struct {
	stubEdge
	planned, applied *bool
}

func (m mutatingEdge) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	*m.planned = true
	return m.stubEdge.Plan(op, live)
}
func (m mutatingEdge) Apply(context.Context, model.ChangeSet) error {
	*m.applied = true
	return nil
}

// TestReadOnly_EveryMutatingVerbRefuses: the belt half of §3.2 — EVERY mutating
// verb on a ReadOnly engine refuses with ErrReadOnlyEngine before planning; no
// driver Plan or Apply is ever reached.
func TestReadOnly_EveryMutatingVerbRefuses(t *testing.T) {
	var planned, applied bool
	edge := mutatingEdge{stubEdge: stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("grafana.example.com")},
	}}, planned: &planned, applied: &applied}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	e.ReadOnly = true
	ctx := context.Background()

	verbs := map[string]func() error{
		"expose": func() error {
			_, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
			return err
		},
		"unexpose": func() error {
			_, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
			return err
		},
		"rename": func() error {
			_, err := e.Rename(ctx, "grafana.example.com", "dash.example.com", core.AlwaysYes)
			return err
		},
		"resume": func() error {
			_, err := e.Resume(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
			return err
		},
		"reconcile": func() error {
			_, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
			return err
		},
		"import": func() error {
			_, err := e.Import(ctx, core.AlwaysYesImport)
			return err
		},
		"apply (declarative)": func() error {
			_, err := e.ApplyDeclarative(ctx, []core.Exposure{{Service: "grafana"}}, core.DeclarativeOptions{}, core.AlwaysYes)
			return err
		},
		"ack":   func() error { return e.Ack(ctx, "grafana.example.com", "known-good") },
		"unack": func() error { return e.Unack(ctx, "grafana.example.com") },
	}
	for name, call := range verbs {
		if err := call(); err == nil || !errors.Is(err, core.ErrReadOnlyEngine) {
			t.Errorf("%s on a ReadOnly engine must refuse with ErrReadOnlyEngine, got %v", name, err)
		}
	}
	if planned || applied {
		t.Errorf("a ReadOnly refusal must fire BEFORE planning: driver Plan reached=%v, Apply reached=%v", planned, applied)
	}

	// Reads stay open: audit is exactly what a ReadOnly engine is FOR.
	if _, err := e.Audit(ctx); err != nil {
		t.Errorf("Audit must remain available on a ReadOnly engine: %v", err)
	}
	if _, err := e.Status(ctx); err != nil {
		t.Errorf("Status must remain available on a ReadOnly engine: %v", err)
	}
}

// TestAudit_ScopeDeclared: the report DECLARES what it did not evaluate (§3.4) —
// no DNS providers means DNSEvaluated=false (public-ness used the conservative
// edge-boundary default), no chain means ChainDepth=0, and configuring DNS flips
// exactly the DNS claim.
func TestAudit_ScopeDeclared(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scope.DNSEvaluated || rep.Scope.ChainDepth != 0 || rep.Scope.TargetMode {
		t.Errorf("DNS-less, chain-less audit must declare the reduced scope, got %+v", rep.Scope)
	}

	dns := &stubDNS{name: "adguard", scope: model.ScopeInternal}
	e2 := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com", dns)
	rep2, err := e2.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.Scope.DNSEvaluated {
		t.Errorf("with a DNS provider configured the scope must declare DNSEvaluated, got %+v", rep2.Scope)
	}
}
