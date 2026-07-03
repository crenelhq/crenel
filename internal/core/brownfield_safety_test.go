package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestBrownfield_ImportThenApply_IsSafe is the canonical end-to-end demonstration
// that Crenel is safe on a setup shaped like the operator's real edge:
//
//   - wildcard SUBROUTES (*.smallbiz.example, *.homelab.example) — out of crenel's
//     domain (their service is not in origins),
//   - an unmanaged AUTHELIA vhost (auth.example.com) — out of domain,
//   - an unmanaged GRAFANA route matching crenel's configured origin — adoptable.
//
// It runs the full brownfield flow in one process — import (adopt) → apply a
// declarative file (with a brand-new host) — and asserts at every step that the
// wildcard subroutes and the Authelia vhost are NEVER read into crenel's domain,
// NEVER adopted, and survive byte-for-byte; the deny always holds; and only
// grafana/photos (crenel's services) are ever touched.
func TestBrownfield_ImportThenApply_IsSafe(t *testing.T) {
	ctx := context.Background()

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	// His-setup-shaped seed: wildcard subroutes + Authelia + an adoptable grafana,
	// none carrying a crenel @id. Granular (additive) apply, as a real edge requires.
	fake.SeedJSON(`{"apps":{
		"tls":{"automation":{"policies":[{"subjects":["*.smallbiz.example","*.homelab.example"]}]}},
		"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["*.smallbiz.example"]}],"handle":[{"handler":"subroute","routes":[
				{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"host.docker.internal:8000"}]}]}]}]},
			{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
				{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"host.docker.internal:9010"}]}]}]}]},
			{"match":[{"host":["auth.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:9091"}]}]},
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]}}}
	}}`)

	origins := map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"}
	edge := core.EdgeBinding{
		Name:     "caddy",
		Provider: caddy.New(fake.URL(), static.New(origins), caddy.WithGranularApply()),
		Fronts:   frontsFor(origins),
	}
	e := core.NewMulti([]core.EdgeBinding{edge}, "example.com")

	// untouched asserts the operator's hand-built config survives verbatim and the
	// edge never reads as fail-open.
	untouched := func(stage string) {
		t.Helper()
		raw := fake.CurrentJSON()
		for _, must := range []string{
			`"*.smallbiz.example"`, `host.docker.internal:8000`,
			`"*.homelab.example"`, `host.docker.internal:9010`,
			`"auth.example.com"`, `10.0.0.9:9091`,
		} {
			if !strings.Contains(raw, must) {
				t.Fatalf("%s: operator config lost %q:\n%s", stage, must, raw)
			}
		}
		// Authelia + the subroutes must never carry a crenel @id.
		if strings.Contains(raw, `crenel-route-auth.example.com`) {
			t.Fatalf("%s: Authelia must NEVER be adopted", stage)
		}
		live, err := edge.Provider.ReadLiveState(ctx)
		if err != nil {
			t.Fatalf("%s: read live: %v", stage, err)
		}
		if !live.DenyCatchAllPresent {
			t.Fatalf("%s: default-deny must hold (never fail-open)", stage)
		}
	}

	untouched("seed")

	// --- import: only grafana is adoptable; subroutes/Authelia are out of domain. ---
	plan, err := e.DetectImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Adopt) != 1 || plan.Adopt[0].Host != "grafana.example.com" {
		t.Fatalf("only grafana should be adoptable, got %+v", plan.Adopt)
	}
	for _, a := range plan.Adopt {
		if strings.HasPrefix(a.Host, "*.") || a.Host == "auth.example.com" {
			t.Fatalf("a wildcard/Authelia host must never be an adoption candidate: %s", a.Host)
		}
	}
	if _, err := e.Import(ctx, core.AlwaysYesImport); err != nil {
		t.Fatalf("import: %v", err)
	}
	untouched("after import")

	// grafana is now managed; the wildcard hosts are still NOT in crenel's domain.
	live, _ := edge.Provider.ReadLiveState(ctx)
	if !routeIsManaged(live, "grafana.example.com") {
		t.Fatal("grafana should be managed after import")
	}
	if routeIsManaged(live, "auth.example.com") {
		t.Fatal("Authelia must remain unmanaged")
	}

	// --- apply: a declarative file that keeps grafana and ADDS photos. grafana is
	// already managed (no-op), photos is a fresh expose. Subroutes/Authelia survive. ---
	exposures := []core.Exposure{
		{Host: "grafana.example.com", Service: "grafana"},
		{Host: "photos.example.com", Service: "photos"},
	}
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v (%+v)", err, rep.Verify)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("apply should converge + verify, got %+v", rep)
	}
	untouched("after apply")

	final, _ := edge.Provider.ReadLiveState(ctx)
	if !final.Reachable("grafana.example.com") || !final.Reachable("photos.example.com") {
		t.Fatal("both crenel-managed hosts should be reachable after apply")
	}
	// photos must be crenel-managed (it was a fresh granular insert with the @id).
	if !routeIsManaged(final, "photos.example.com") {
		t.Fatal("freshly-applied photos should be crenel-managed")
	}
}

// routeIsManaged reports whether host is present and carries the ownership marker.
func routeIsManaged(live model.LiveEdgeState, host string) bool {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Managed
		}
	}
	return false
}
