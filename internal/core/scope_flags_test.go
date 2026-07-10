package core_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// newScopeEngine wires ONE granular caddy edge that fronts `ha` + an internal AND a
// public dnscontrol DNS provider, seeded empty (deny-only edge, empty zones). This
// is the minimal topology that exercises DNS-scope appointment: a public record is
// available to create, so `--scope internal` has something to suppress.
func newScopeEngine(t *testing.T) (*core.Engine, *dnscontrolfake.Shell, *dnscontrolfake.Shell) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	if err := cf.SeedJSON(emptyDeny); err != nil {
		t.Fatal(err)
	}
	origins := map[string]string{"ha": "10.0.0.19:8123"}
	edge := caddy.New(cf.URL(), static.New(origins), caddy.WithGranularApply())
	inSh := dnscontrolfake.New("example.com")
	pubSh := dnscontrolfake.New("example.com")
	internal := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: inSh})
	public := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh})
	e := core.NewMulti([]core.EdgeBinding{{Name: "caddy", Provider: edge, Fronts: frontsFor(origins)}}, "example.com", internal, public)
	return e, inSh, pubSh
}

// TestPlan_ScopeInternalSuppressesPublicDNS is the Deliverable-#1 acceptance case:
//
//	crenel expose ha --to 10.0.0.19:8123 --scope internal --auth none
//
// must produce a plan with ONLY the internal edge route + the internal DNS A record
// and NO public/Cloudflare record — and therefore NO "about to go public". Before
// inline scope, the default plan wrongly added a public record and warned.
func TestPlan_ScopeInternalSuppressesPublicDNS(t *testing.T) {
	ctx := context.Background()
	e, _, _ := newScopeEngine(t)

	op := e.BuildOp(model.Expose, "ha")
	op.To = "10.0.0.19:8123"
	op.Auth = model.AuthNone
	op.Scopes = []model.Scope{model.ScopeInternal} // what --scope internal expands to

	cs, err := e.Plan(ctx, op)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// Exactly the internal edge route.
	if len(cs.Edges) != 1 || len(cs.Edges[0].Change.AddRoutes) != 1 {
		t.Fatalf("expected exactly one edge AddRoute, got %+v", cs.Edges)
	}
	if h := cs.Edges[0].Change.AddRoutes[0].Host; h != "ha.example.com" {
		t.Fatalf("edge route host = %q, want ha.example.com", h)
	}

	// DNS slices stay positionally aligned with the two providers (internal, public).
	if len(cs.DNS) != 2 {
		t.Fatalf("expected 2 DNS entries (aligned with providers), got %d", len(cs.DNS))
	}
	// Internal provider (index 0): exactly one add.
	if cs.DNS[0].Scope != model.ScopeInternal || len(cs.DNS[0].Add) != 1 {
		t.Fatalf("internal DNS should add exactly one record, got %+v", cs.DNS[0])
	}
	// Public provider (index 1): EMPTY — no public record created.
	if cs.DNS[1].Scope != model.ScopePublic || !cs.DNS[1].Empty() {
		t.Fatalf("public DNS must be EMPTY under --scope internal, got %+v", cs.DNS[1])
	}

	// Nothing is about to go public.
	if len(cs.NewPublic) != 0 {
		t.Fatalf("internal scope must not flag anything public, got %v", cs.NewPublic)
	}
}

// TestApply_ScopeInternalVerifiesGreen proves the scope-restricted apply is not a
// false green: it applies the internal record + edge route, LEAVES the public
// provider untouched, and READ-BACK-VERIFIES all three (the public provider
// verifying trivially "scope not appointed", not by expecting a record it never
// wrote). Then the public record really is absent in live.
func TestApply_ScopeInternalVerifiesGreen(t *testing.T) {
	ctx := context.Background()
	e, inSh, pubSh := newScopeEngine(t)

	op := e.BuildOp(model.Expose, "ha")
	op.To = "10.0.0.19:8123"
	op.Auth = model.AuthNone
	op.Scopes = []model.Scope{model.ScopeInternal}

	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v (%+v)", err, rep.Verify)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("scope-internal apply should converge+verify, got %+v", rep)
	}
	if inSh.LiveCount() != 1 {
		t.Fatalf("internal zone should hold exactly one record, got %d", inSh.LiveCount())
	}
	if pubSh.LiveCount() != 0 {
		t.Fatalf("public zone must stay empty under --scope internal, got %d", pubSh.LiveCount())
	}
}

// TestPlan_ScopePublicStillGoesPublic is the mirror: --scope public creates the
// public record (and NOT the internal one), so the host IS about to go public and
// the auth guardrail (enforced at the CLI over NewPublic) has something to fire on.
func TestPlan_ScopePublicStillGoesPublic(t *testing.T) {
	ctx := context.Background()
	e, _, _ := newScopeEngine(t)

	op := e.BuildOp(model.Expose, "ha")
	op.Scopes = []model.Scope{model.ScopePublic}

	cs, err := e.Plan(ctx, op)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !cs.DNS[0].Empty() {
		t.Fatalf("internal DNS must be EMPTY under --scope public, got %+v", cs.DNS[0])
	}
	if cs.DNS[1].Scope != model.ScopePublic || len(cs.DNS[1].Add) != 1 {
		t.Fatalf("public DNS should add exactly one record, got %+v", cs.DNS[1])
	}
	if len(cs.NewPublic) != 1 || cs.NewPublic[0] != "ha.example.com" {
		t.Fatalf("public scope must flag ha.example.com public, got %v", cs.NewPublic)
	}
}

// TestPlan_EdgesAppointsSingleEdge proves --edges restricts the fan-out to the named
// edge in a two-edge topology, reusing the same predicate as Exposure.Edges.
func TestPlan_EdgesAppointsSingleEdge(t *testing.T) {
	ctx := context.Background()
	e, _, _ := heteroEngine(t) // grafana fronted by BOTH home (caddy) + vps (traefik)

	// Default: both edges participate.
	both, err := e.Plan(ctx, e.BuildOp(model.Expose, "grafana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(both.Edges) != 2 {
		t.Fatalf("default expose should fan out to both edges, got %d", len(both.Edges))
	}

	// --edges home: only the home edge.
	op := e.BuildOp(model.Expose, "grafana")
	op.Edges = []string{"home"}
	one, err := e.Plan(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Edges) != 1 || one.Edges[0].Edge != "home" {
		t.Fatalf("--edges home should appoint only the home edge, got %+v", one.Edges)
	}
}

// TestPlan_UnexposeScopeInternalLeavesPublic proves scope appointment is symmetric
// on teardown: unexpose --scope internal removes the internal record but leaves the
// public one standing (the public provider is not touched, and verify doesn't demand
// its absence).
func TestPlan_UnexposeScopeInternalLeavesPublic(t *testing.T) {
	ctx := context.Background()
	e, inSh, pubSh := newScopeEngine(t)

	// Seed BOTH records live by exposing across both scopes first.
	expose := e.BuildOp(model.Expose, "ha")
	expose.To = "10.0.0.19:8123"
	expose.Auth = model.AuthNone
	if _, err := e.Apply(ctx, expose, core.AlwaysYes); err != nil {
		t.Fatalf("seed expose: %v", err)
	}
	if inSh.LiveCount() != 1 || pubSh.LiveCount() != 1 {
		t.Fatalf("seed should populate both zones, got internal=%d public=%d", inSh.LiveCount(), pubSh.LiveCount())
	}

	op := e.BuildOp(model.Unexpose, "ha")
	op.Scopes = []model.Scope{model.ScopeInternal}
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose --scope internal: %v (%+v)", err, rep.Verify)
	}
	if inSh.LiveCount() != 0 {
		t.Fatalf("internal record should be removed, got %d", inSh.LiveCount())
	}
	if pubSh.LiveCount() != 1 {
		t.Fatalf("public record must survive unexpose --scope internal, got %d", pubSh.LiveCount())
	}
}
