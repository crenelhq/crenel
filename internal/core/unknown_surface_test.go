package core_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// unparseableFixture is a faithful edge with deliberately-unmodeled shapes (a
// file_server terminal, a vars-only subroute leaf, a top-level host-less subroute)
// alongside one understood crenel route.
const unparseableFixture = "../drivers/edge/caddy/testdata/unparseable-prod.json"

func unparseableEngine(t *testing.T) *core.Engine {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	seed, err := os.ReadFile(unparseableFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.SeedJSON(string(seed)); err != nil {
		t.Fatal(err)
	}
	res := static.New(map[string]string{"grafana": "100.100.0.5:3000"})
	return core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: caddy.New(fake.URL(), res, caddy.WithGranularApply())}}, "homelab.example")
}

// TestStatus_IncompleteCoverageSurfaced proves status reports incomplete coverage,
// downgrades default-deny to UNKNOWN, and exposes the unparsed items first-class —
// never presenting the partial parse as a complete one (register §4.2 + §4.4).
func TestStatus_IncompleteCoverageSurfaced(t *testing.T) {
	st, err := unparseableEngine(t).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	es := st.Edges[0]
	understood, total := es.Coverage()
	if understood != 1 || total != 4 {
		t.Errorf("coverage should be 1/4, got %d/%d", understood, total)
	}
	if es.FullyParsed() {
		t.Error("edge has unparsed routes; FullyParsed must be false")
	}
	if es.DenyState() != model.DenyUnknown {
		t.Errorf("default-deny must DOWNGRADE to UNKNOWN, got %q", es.DenyState())
	}
	if len(es.Unparsed) != 3 {
		t.Fatalf("status must carry the 3 unparsed items, got %+v", es.Unparsed)
	}
}

// TestAudit_IncompleteCoverageDowngradesDeny proves the load-bearing rule: with any
// unparsed routes, audit emits deny_catchall_unknown (warning) + coverage_incomplete
// (warning) and NEVER the green deny_catchall_present — ENFORCED ⟹ FullyParsed.
func TestAudit_IncompleteCoverageDowngradesDeny(t *testing.T) {
	rep, err := unparseableEngine(t).Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "deny_catchall_present"); ok {
		t.Errorf("a partially-parsed edge must NEVER report deny ENFORCED (deny_catchall_present):\n%+v", rep.Findings)
	}
	if f, ok := findCode(rep, "deny_catchall_unknown"); !ok || f.Severity != "warning" {
		t.Errorf("expected deny_catchall_unknown warning, got %+v", rep.Findings)
	}
	if f, ok := findCode(rep, "coverage_incomplete"); !ok || f.Severity != "warning" {
		t.Errorf("expected coverage_incomplete warning, got %+v", rep.Findings)
	}
	if rep.HasCritical() {
		t.Error("a present-but-uncertifiable deny is amber, not critical")
	}
}

// TestAudit_OwnershipUnconfirmedAndIngressExternal proves the ownership + ingress
// findings fire from live state: a foreign-owned route (and an edge-level generator)
// yield ownership_unconfirmed, and a non-port ingress yields ingress_external.
func TestAudit_OwnershipUnconfirmedAndIngressExternal(t *testing.T) {
	// Per-route foreign ownership (no edge-level generator).
	foreignRoute := model.Route{Host: "app.example.com", Ownership: model.OwnForeign,
		Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "app.example.com"}}
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{foreignRoute},
		IngressKind:         model.IngressTunnel,
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "ownership_unconfirmed"); !ok || f.Severity != "warning" {
		t.Errorf("expected ownership_unconfirmed warning for a foreign route, got %+v", rep.Findings)
	}
	if f, ok := findCode(rep, "ingress_external"); !ok || f.Severity != "warning" {
		t.Errorf("expected ingress_external warning, got %+v", rep.Findings)
	}

	// Edge-level generator => edge-wide ownership_unconfirmed naming the generator.
	gen := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("grafana.example.com")},
		Generator:           "caddy-docker-proxy",
	}}
	eg := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: gen}}, "example.com")
	repg, err := eg.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(repg, "ownership_unconfirmed")
	if !ok {
		t.Fatalf("expected ownership_unconfirmed for a generator-owned edge, got %+v", repg.Findings)
	}
	if !strings.Contains(f.Message, "caddy-docker-proxy") {
		t.Errorf("ownership_unconfirmed should name the generator, got %q", f.Message)
	}
}
