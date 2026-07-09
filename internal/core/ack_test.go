package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// TestAudit_AcknowledgedUnknownIsOKAndNotCoverageIncomplete proves an edge whose
// ONLY unparsed entry is operator-acknowledged (docs/design/ack-marker.md)
// reports the acknowledged_unknown finding at "ok" severity, does NOT also fire
// coverage_incomplete, and certifies deny ENFORCED — the whole point of the
// marker: cron-clean audit on a brownfield edge with a vetted carve-out.
func TestAudit_AcknowledgedUnknownIsOKAndNotCoverageIncomplete(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "grafana.example.com", Upstream: model.Upstream{
			Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "grafana.example.com", Auth: "authelia"}}},
		Unparsed: []model.Unparsed{
			{Locator: "apps.http.servers.srv0.routes[1]", Kind: model.UnknownAcknowledged,
				Reason: "acknowledged by operator (hawser-tailnet-agents) — route scoped by a path matcher"},
		},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "acknowledged_unknown"); !ok || f.Severity != "ok" {
		t.Errorf("expected acknowledged_unknown at ok severity, got %+v", rep.Findings)
	}
	if _, ok := findCode(rep, "coverage_incomplete"); ok {
		t.Errorf("a fully-acknowledged edge must NOT also report coverage_incomplete, got %+v", rep.Findings)
	}
	if f, ok := findCode(rep, "deny_catchall_present"); !ok || f.Severity != "ok" {
		t.Errorf("an edge with only acknowledged unknowns must certify deny ENFORCED (deny_catchall_present), got %+v", rep.Findings)
	}
	if !rep.OK() {
		t.Errorf("an acknowledged-only edge should audit OK, got %+v", rep.Findings)
	}
}

// TestAudit_MixedAcknowledgedAndRealUnknown proves acks are per-route: a real
// (unacked) unknown alongside an acked one still fires coverage_incomplete
// (counting only the real one), while the acked one is reported separately and
// never folded into that count.
func TestAudit_MixedAcknowledgedAndRealUnknown(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("grafana.example.com")},
		Unparsed: []model.Unparsed{
			{Locator: "apps.http.servers.srv0.routes[1]", Kind: model.UnknownAcknowledged,
				Reason: "acknowledged by operator (hawser-tailnet-agents) — route scoped by a path matcher"},
			{Locator: "apps.http.servers.srv0.routes[2]", Kind: model.UnknownHandler,
				Reason: "route has no reverse_proxy/subroute crenel can resolve"},
		},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "acknowledged_unknown"); !ok {
		t.Errorf("acked entry should still be reported, got %+v", rep.Findings)
	}
	cov, ok := findCode(rep, "coverage_incomplete")
	if !ok || cov.Severity != "warning" {
		t.Fatalf("a real unacked unknown must still fire coverage_incomplete, got %+v", rep.Findings)
	}
	f, ok := findCode(rep, "deny_catchall_unknown")
	if !ok || f.Severity != "warning" {
		t.Fatalf("a real unacked unknown must still leave deny UNKNOWN, got %+v", rep.Findings)
	}
	// Regression guard (live dogfood on CT113, 2026-07-05): this message must count
	// only the REAL unknown (1), matching coverage_incomplete right below it — not
	// the raw Unparsed length (2, which would double-count the acked entry and
	// contradict the finding underneath it).
	if !strings.Contains(f.Message, "1 route(s) not understood") {
		t.Errorf("deny_catchall_unknown must report the ack-excluded count (1), got message: %q", f.Message)
	}
	if strings.Contains(f.Message, "2 route(s) not understood") {
		t.Errorf("deny_catchall_unknown must NOT count the acked entry, got message: %q", f.Message)
	}
}
