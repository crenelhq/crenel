package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
)

// driveMCP feeds the given newline-delimited JSON-RPC frames into a read-only MCP
// server wired to a test engine, and returns the decoded responses (in order). It
// drives the REAL serve loop, so it exercises framing + dispatch end-to-end.
func driveMCP(t *testing.T, engine core.ReadOnlyEngine, frames ...string) []rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	var out bytes.Buffer
	srv := newMCPServer(engine, "test-1.2.3")
	if err := srv.serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []rpcResponse
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode response: %v (raw=%q)", err, out.String())
		}
		resps = append(resps, r)
	}
	return resps
}

// mcpTestEngine returns a real engine wired to a fake Caddy seeded with grafana
// (managed) so status/audit/drift have something to report.
func mcpTestEngine(t *testing.T) core.ReadOnlyEngine {
	t.Helper()
	c, _ := newTestCLI(t, seedFake(t), false, "")
	return c.engine
}

func resultMap(t *testing.T, r rpcResponse) map[string]any {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", r.Error)
	}
	b, err := json.Marshal(r.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not an object: %v (%s)", err, b)
	}
	return m
}

// TestMCP_Handshake exercises the full MCP handshake against the real serve loop:
// initialize -> notifications/initialized (no reply) -> tools/list -> tools/call
// for EACH of the three read tools. It asserts the protocol shape and that each
// tool returns live data.
func TestMCP_Handshake(t *testing.T) {
	resps := driveMCP(t, mcpTestEngine(t),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"crenel_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"crenel_audit","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"crenel_drift","arguments":{}}}`,
	)

	// The notification produces NO response, so we expect 5 (initialize + list + 3 calls).
	if len(resps) != 5 {
		t.Fatalf("expected 5 responses (notification gets none), got %d", len(resps))
	}

	// 1) initialize
	init := resultMap(t, resps[0])
	if init["protocolVersion"] != "2024-11-05" {
		t.Errorf("initialize should echo protocolVersion, got %v", init["protocolVersion"])
	}
	caps, _ := init["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("initialize must advertise tools capability: %v", init["capabilities"])
	}
	si, _ := init["serverInfo"].(map[string]any)
	if si["name"] != "crenel-mcp" || si["version"] != "test-1.2.3" {
		t.Errorf("serverInfo wrong: %v", si)
	}

	// 2) tools/list — exactly the three read tools, each with a schema + description.
	list := resultMap(t, resps[1])
	tools, _ := list["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d: %v", len(tools), list["tools"])
	}
	names := map[string]bool{}
	for _, ti := range tools {
		tm := ti.(map[string]any)
		name, _ := tm["name"].(string)
		names[name] = true
		if d, _ := tm["description"].(string); d == "" {
			t.Errorf("tool %q missing description", name)
		}
		if _, ok := tm["inputSchema"].(map[string]any); !ok {
			t.Errorf("tool %q missing inputSchema", name)
		}
	}
	for _, want := range []string{"crenel_status", "crenel_audit", "crenel_drift"} {
		if !names[want] {
			t.Errorf("tools/list missing %q", want)
		}
	}

	// 3) tools/call crenel_status — live route shows through both content + structured.
	status := resultMap(t, resps[2])
	if status["isError"] == true {
		t.Fatalf("crenel_status should not be an error: %v", status)
	}
	if !strings.Contains(toolText(t, status), "grafana.example.com") {
		t.Errorf("crenel_status content should include the live route:\n%s", toolText(t, status))
	}
	if _, ok := status["structuredContent"]; !ok {
		t.Errorf("crenel_status should include structuredContent")
	}

	// 4) crenel_audit — returns findings (the seeded edge is fully parsed / enforced).
	audit := resultMap(t, resps[3])
	if audit["isError"] == true {
		t.Fatalf("crenel_audit should not be an error: %v", audit)
	}
	if !strings.Contains(toolText(t, audit), "\"Findings\"") && !strings.Contains(toolText(t, audit), "Severity") {
		t.Errorf("crenel_audit content should carry findings:\n%s", toolText(t, audit))
	}

	// 5) crenel_drift — returns a plan object (no drift on a freshly-seeded edge).
	drift := resultMap(t, resps[4])
	if drift["isError"] == true {
		t.Fatalf("crenel_drift should not be an error: %v", drift)
	}
}

// toolText pulls the text of the first content block out of a CallToolResult.
func toolText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("CallToolResult has no content: %v", result)
	}
	first, _ := content[0].(map[string]any)
	txt, _ := first["text"].(string)
	return txt
}

// TestMCP_NoMutatingToolAdvertised proves the read-only guarantee at the catalog
// level: tools/list advertises NONE of the mutating verbs.
func TestMCP_NoMutatingToolAdvertised(t *testing.T) {
	resps := driveMCP(t, mcpTestEngine(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	)
	list := resultMap(t, resps[0])
	tools, _ := list["tools"].([]any)
	advertised := map[string]bool{}
	for _, ti := range tools {
		advertised[ti.(map[string]any)["name"].(string)] = true
	}
	for _, mutator := range []string{
		"crenel_expose", "crenel_unexpose", "crenel_rename", "crenel_set",
		"crenel_apply", "crenel_reconcile", "crenel_import", "crenel_resume",
		"expose", "unexpose", "apply", "reconcile",
	} {
		if advertised[mutator] {
			t.Errorf("read-only server must NOT advertise mutating tool %q", mutator)
		}
	}
}

// TestMCP_MutatingToolNotCallable proves the second half of the guarantee: even a
// directly-named mutating tool is rejected (no such tool) and nothing is invoked.
// Dispatch is off the read-only catalog, so a mutator name simply does not resolve.
func TestMCP_MutatingToolNotCallable(t *testing.T) {
	for _, name := range []string{"crenel_expose", "expose", "crenel_apply", "crenel_reconcile", "anything"} {
		resps := driveMCP(t, mcpTestEngine(t),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":{"service":"grafana"}}}`,
		)
		if len(resps) != 1 {
			t.Fatalf("%s: expected 1 response, got %d", name, len(resps))
		}
		if resps[0].Error == nil {
			t.Errorf("calling mutating/unknown tool %q must be a protocol error, got result %v", name, resps[0].Result)
			continue
		}
		if resps[0].Error.Code != errInvalidParams || !strings.Contains(resps[0].Error.Message, "unknown tool") {
			t.Errorf("%s: expected 'unknown tool' invalid-params error, got %+v", name, resps[0].Error)
		}
	}
}

// TestMCP_EdgeFilter proves the optional `edge` filter narrows status to one edge,
// and an unknown edge name yields an empty edge list (not an error).
func TestMCP_EdgeFilter(t *testing.T) {
	engine := mcpTestEngine(t)

	// Unfiltered: learn the real edge name.
	all := driveMCP(t, engine, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crenel_status","arguments":{}}}`)
	var allRep core.StatusReport
	mustStructured(t, resultMap(t, all[0]), &allRep)
	if len(allRep.Edges) == 0 {
		t.Fatal("expected at least one edge unfiltered")
	}
	edgeName := allRep.Edges[0].Name

	// Filter to that edge: exactly one edge back.
	one := driveMCP(t, engine, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crenel_status","arguments":{"edge":"`+edgeName+`"}}}`)
	var oneRep core.StatusReport
	mustStructured(t, resultMap(t, one[0]), &oneRep)
	if len(oneRep.Edges) != 1 || oneRep.Edges[0].Name != edgeName {
		t.Errorf("edge filter %q should yield exactly that edge, got %+v", edgeName, oneRep.Edges)
	}

	// Filter to a bogus edge: empty, not an error.
	none := driveMCP(t, engine, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crenel_status","arguments":{"edge":"no-such-edge"}}}`)
	res := resultMap(t, none[0])
	if res["isError"] == true {
		t.Fatalf("unknown edge filter must not error: %v", res)
	}
	var noneRep core.StatusReport
	mustStructured(t, res, &noneRep)
	if len(noneRep.Edges) != 0 {
		t.Errorf("unknown edge filter should yield 0 edges, got %+v", noneRep.Edges)
	}
}

// mustStructured decodes a CallToolResult's structuredContent into v.
func mustStructured(t *testing.T, result map[string]any, v any) {
	t.Helper()
	b, err := json.Marshal(result["structuredContent"])
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode structuredContent: %v (%s)", err, b)
	}
}

// TestMCP_UnknownMethod returns a JSON-RPC method-not-found error for a request,
// and silently ignores an unknown NOTIFICATION (no id => no reply).
func TestMCP_UnknownMethod(t *testing.T) {
	resps := driveMCP(t, mcpTestEngine(t),
		`{"jsonrpc":"2.0","id":7,"method":"no/such/method"}`,
		`{"jsonrpc":"2.0","method":"notifications/somethingUnknown"}`,
	)
	if len(resps) != 1 {
		t.Fatalf("unknown request should reply once, unknown notification never; got %d", len(resps))
	}
	if resps[0].Error == nil || resps[0].Error.Code != errMethodNotFound {
		t.Errorf("expected method-not-found, got %+v", resps[0])
	}
}

// TestMCP_PingRoundTrip covers the MCP ping utility.
func TestMCP_Ping(t *testing.T) {
	resps := driveMCP(t, mcpTestEngine(t), `{"jsonrpc":"2.0","id":9,"method":"ping"}`)
	if len(resps) != 1 || resps[0].Error != nil {
		t.Fatalf("ping should succeed: %+v", resps)
	}
}

// compile-time: the concrete engine satisfies the narrow read-only interface, but
// the server only ever holds the interface. This var mirrors the production
// assertion and documents the by-construction guarantee in the test package.
var _ core.ReadOnlyEngine = (*core.Engine)(nil)
