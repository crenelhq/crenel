package core_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// newDeclEngine builds a single granular-caddy edge seeded from json, fronting the
// given origins.
func newDeclEngine(t *testing.T, seedJSON string, origins map[string]string) (*core.Engine, *caddyfake.Fake, core.EdgeBinding) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	if err := cf.SeedJSON(seedJSON); err != nil {
		t.Fatal(err)
	}
	b := core.EdgeBinding{
		Name:     "caddy",
		Provider: caddy.New(cf.URL(), static.New(origins), caddy.WithGranularApply()),
		Fronts:   frontsFor(origins),
	}
	return core.NewMulti([]core.EdgeBinding{b}, "example.com"), cf, b
}

const emptyDeny = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"handle":[{"handler":"static_response","status_code":403}]}
]}}}}}`

// TestApplyDeclarative_AdditiveExpose: applying a file that declares two exposures
// against an empty edge exposes both, highlights them as going public, and verifies.
func TestApplyDeclarative_AdditiveExpose(t *testing.T) {
	ctx := context.Background()
	origins := map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"}
	e, _, edge := newDeclEngine(t, emptyDeny, origins)

	exposures := []core.Exposure{
		{Service: "grafana"}, // host derived as grafana.example.com
		{Host: "photos.example.com", Service: "photos"},
	}

	plan, err := e.PlanDeclarative(ctx, exposures, core.DeclarativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NewPublic) != 2 {
		t.Fatalf("both hosts should be about to go public, got %v", plan.NewPublic)
	}

	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v (%+v)", err, rep.Verify)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("apply should converge+verify, got %+v", rep)
	}
	live, _ := edge.Provider.ReadLiveState(ctx)
	if !live.Reachable("grafana.example.com") || !live.Reachable("photos.example.com") {
		t.Fatal("both hosts should be reachable after apply")
	}

	// Idempotent: re-applying the same file is a no-op.
	plan2, _ := e.PlanDeclarative(ctx, exposures, core.DeclarativeOptions{})
	if !plan2.Empty() {
		t.Fatalf("second apply should be a no-op, got %+v", plan2.Change)
	}
}

// TestApplyDeclarative_BlocksUnmanagedWithoutAdopt: a file host that exists
// UNMANAGED must block apply (no duplicate) unless --adopt is given.
func TestApplyDeclarative_BlocksUnmanagedWithoutAdopt(t *testing.T) {
	ctx := context.Background()
	// grafana already present, UNMANAGED (no @id), backend matches origin.
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	origins := map[string]string{"grafana": "10.0.0.5:3000"}
	e, _, edge := newDeclEngine(t, seed, origins)
	exposures := []core.Exposure{{Service: "grafana"}}

	// Without --adopt: blocked.
	if _, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes); err == nil {
		t.Fatal("apply should refuse a present-unmanaged host without --adopt")
	}

	// With --adopt: adopts in place, no duplicate route.
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{Adopt: true}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply --adopt: %v (%+v)", err, rep.Verify)
	}
	if len(rep.Plan.Adopt) != 1 {
		t.Fatalf("expected 1 inline adoption, got %+v", rep.Plan.Adopt)
	}
	live, _ := edge.Provider.ReadLiveState(ctx)
	n := 0
	for _, r := range live.Routes {
		if r.Host == "grafana.example.com" {
			n++
			if !r.Managed {
				t.Fatal("grafana should be managed after apply --adopt")
			}
		}
	}
	if n != 1 {
		t.Fatalf("apply --adopt must not duplicate the route, found %d", n)
	}
}

// TestApplyDeclarative_Prune: --prune unexposes an OWNED host absent from the file
// but never an unmanaged one.
func TestApplyDeclarative_Prune(t *testing.T) {
	ctx := context.Background()
	// grafana is crenel-MANAGED (@id); legacy.example.com is UNMANAGED.
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"match":[{"host":["legacy.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.99:80"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	origins := map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"}
	e, _, edge := newDeclEngine(t, seed, origins)

	// File declares ONLY photos. grafana (owned) should be pruned; legacy (unmanaged)
	// must survive untouched.
	exposures := []core.Exposure{{Service: "photos"}}
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{Prune: true}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply --prune: %v (%+v)", err, rep.Verify)
	}
	if len(rep.Plan.Prune) != 1 || rep.Plan.Prune[0] != "grafana.example.com" {
		t.Fatalf("expected grafana pruned, got %v", rep.Plan.Prune)
	}
	live, _ := edge.Provider.ReadLiveState(ctx)
	if live.HasHost("grafana.example.com") {
		t.Fatal("owned grafana should be pruned")
	}
	if !live.HasHost("legacy.example.com") {
		t.Fatal("unmanaged legacy must NEVER be pruned")
	}
	if !live.Reachable("photos.example.com") {
		t.Fatal("photos from the file should be exposed")
	}
}

// TestApplyDeclarative_OriginMismatchBlocks: a present-unmanaged host whose backend
// differs from the configured origin is a conflict even with --adopt (no silent
// behavior change).
func TestApplyDeclarative_OriginMismatchBlocks(t *testing.T) {
	ctx := context.Background()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.200:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	origins := map[string]string{"grafana": "10.0.0.5:3000"}
	e, _, _ := newDeclEngine(t, seed, origins)
	_, err := e.ApplyDeclarative(ctx, []core.Exposure{{Service: "grafana"}}, core.DeclarativeOptions{Adopt: true}, core.AlwaysYes)
	if err == nil {
		t.Fatal("origin mismatch must block apply even with --adopt")
	}
}
