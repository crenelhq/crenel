package caddy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// routeByHost returns the normalized route for host (case-insensitive), or false.
func routeByHost(live model.LiveEdgeState, host string) (model.Route, bool) {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r, true
		}
	}
	return model.Route{}, false
}

// nestedResolver mirrors the trial VPS origins (per-host Tailscale dials). cloud's
// configured backend deliberately DIFFERS from the live leaf dial (a conflict).
func nestedResolver() *static.Resolver {
	return static.New(map[string]string{
		"vault":  "100.100.0.10:8200",
		"git":    "100.100.0.11:3000",
		"photos": "100.100.0.12:2342",
		"jelly":  "100.100.0.13:8096",
		"cloud":  "100.100.0.14:80", // != live 100.100.0.99:9999 -> conflict
	})
}

// TestReadLiveState_NestedSubrouteEnumeratesLeaves models the REAL VPS edge: two
// wildcard zones, each a subroute that nests per-host routes (wildcard → subroute
// → per-host route → subroute → leaf reverse_proxy). normalize must RECURSE and
// enumerate the real per-host SERVICES with their real leaf dials — not 2 opaque
// wildcards — while the default-deny reading stays PRESENT.
func TestReadLiveState_NestedSubrouteEnumeratesLeaves(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), nestedResolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Default-deny still reads PRESENT (wildcards are host-matched into subroutes;
	// no TOP-LEVEL host-less reverse_proxy forwards everything).
	if !live.DenyCatchAllPresent {
		t.Fatal("nested subroute edge must read as default-deny PRESENT, not fail-open")
	}

	// The opaque wildcards must NOT appear as routes — they are resolved to leaves.
	if live.HasHost("*.homelab.example") || live.HasHost("*.smallbiz.example") {
		t.Errorf("wildcard zones should be enumerated into per-host leaves, not surfaced opaquely: %v", live.Hosts())
	}

	// Each real per-host service is enumerated with its real leaf dial.
	want := map[string]string{
		"jelly.homelab.example":    "100.100.0.13:8096", // managed flat top-level route
		"vault.homelab.example":    "100.100.0.10:8200", // wildcard → subroute → per-host → subroute → leaf
		"git.homelab.example":      "100.100.0.11:3000", // adopted nested (carries crenel @id)
		"photos.homelab.example":   "100.100.0.12:2342", // nested with an auth handler
		"cloud.homelab.example":    "100.100.0.99:9999", // nested, per-host route forwards directly
		"status.smallbiz.example": "100.100.0.20:3001", // second wildcard zone
	}
	for host, dial := range want {
		r, ok := routeByHost(live, host)
		if !ok {
			t.Errorf("expected per-host service %s enumerated, got hosts %v", host, live.Hosts())
			continue
		}
		if r.Upstream.Address != dial {
			t.Errorf("%s: expected real leaf dial %s, got %s", host, dial, r.Upstream.Address)
		}
	}
	if len(live.Routes) != len(want) {
		t.Errorf("expected exactly %d enumerated services, got %d (%v)", len(want), len(live.Routes), live.Hosts())
	}

	// Ownership: the two routes carrying a crenel @id read back as managed; the
	// hand-built leaves do not.
	for host, wantManaged := range map[string]bool{
		"jelly.homelab.example":  true,  // top-level @id
		"git.homelab.example":    true,  // nested @id (a previously-adopted per-host route)
		"vault.homelab.example":  false, // hand-built
		"photos.homelab.example": false,
		"cloud.homelab.example":  false,
	} {
		r, _ := routeByHost(live, host)
		if r.Managed != wantManaged {
			t.Errorf("%s: Managed=%v, want %v", host, r.Managed, wantManaged)
		}
	}

	// Auth recognized read-only on the nested route that carries a hand-built auth
	// handler (one hop down, beside the subroute that holds the leaf).
	if r, _ := routeByHost(live, "photos.homelab.example"); r.Upstream.Auth != model.AuthDetected {
		t.Errorf("photos nested auth handler should be recognized as %q, got %q", model.AuthDetected, r.Upstream.Auth)
	}
	if r, _ := routeByHost(live, "vault.homelab.example"); r.Upstream.Auth != "" {
		t.Errorf("vault has no auth handler; expected empty auth, got %q", r.Upstream.Auth)
	}
}

// TestNestedRecursion_DenyReadingPreserved locks in the load-bearing invariant
// through the new recursion: a host-less reverse_proxy NESTED inside a wildcard
// subroute is SCOPED by the parent host matcher (a leaf for that wildcard, NOT
// fail-open), while a TOP-LEVEL host-less reverse_proxy still reads fail-open even
// when nested subroutes are present.
func TestNestedRecursion_DenyReadingPreserved(t *testing.T) {
	t.Run("nested host-less leaf is scoped, not fail-open", func(t *testing.T) {
		fake := caddyfake.New()
		defer fake.Close()
		// wildcard → subroute → host-less reverse_proxy (a per-wildcard catch-all
		// forwarding all subdomains of the zone to one backend).
		fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
				{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:80"}]}]}
			]}]}
		]}}}}}`)
		live, err := caddy.New(fake.URL(), nestedResolver()).ReadLiveState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !live.DenyCatchAllPresent {
			t.Error("a host-less reverse_proxy SCOPED inside a wildcard subroute must NOT read as fail-open")
		}
		r, ok := routeByHost(live, "*.homelab.example")
		if !ok || r.Upstream.Address != "10.0.0.9:80" {
			t.Errorf("nested host-less leaf should inherit the wildcard host with its real dial, got %+v (ok=%v)", r, ok)
		}
	})

	t.Run("top-level host-less reverse_proxy still fail-open with nested zones present", func(t *testing.T) {
		fake := caddyfake.New()
		defer fake.Close()
		fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
				{"match":[{"host":["vault.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"100.100.0.10:8200"}]}]}
			]}]},
			{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.1:80"}]}]}
		]}}}}}`)
		live, err := caddy.New(fake.URL(), nestedResolver()).ReadLiveState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if live.DenyCatchAllPresent {
			t.Error("a TOP-LEVEL host-less reverse_proxy forwards every host => must read as fail-open")
		}
		// The nested per-host leaf is still enumerated alongside the fail-open reading.
		if !live.HasHost("vault.homelab.example") {
			t.Errorf("nested per-host leaf should still be enumerated, got %v", live.Hosts())
		}
	})
}

// TestAdopt_NestedPerHostRoute proves adoption stamps the crenel @id onto a
// per-host route nested inside a wildcard subroute (not just a flat top-level
// route). After adopt the host reads back as managed, its backend is unchanged,
// and every other route (managed, unmanaged, the other zone) survives.
func TestAdopt_NestedPerHostRoute(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), nestedResolver(), caddy.WithGranularApply())
	ctx := context.Background()

	pre, _ := d.ReadLiveState(ctx)
	if r, _ := routeByHost(pre, "vault.homelab.example"); r.Managed {
		t.Fatal("vault must start unmanaged")
	}

	if err := d.Adopt(ctx, []string{"vault.homelab.example"}); err != nil {
		t.Fatalf("adopt nested vault: %v", err)
	}

	post, _ := d.ReadLiveState(ctx)
	r, ok := routeByHost(post, "vault.homelab.example")
	if !ok || !r.Managed {
		t.Fatalf("vault should be managed after nested adopt, got %+v (ok=%v)", r, ok)
	}
	if r.Upstream.Address != "100.100.0.10:8200" {
		t.Errorf("adopt must not change vault's backend, got %s", r.Upstream.Address)
	}
	if !post.DenyCatchAllPresent {
		t.Error("default-deny must hold after adopt")
	}

	// Adoption is behavior-preserving for everyone else: same set of services, same
	// dials, the other zone and the previously-managed routes intact.
	raw := fake.CurrentJSON()
	for _, must := range []string{
		"crenel-route-vault.homelab.example", // newly stamped
		"crenel-route-git.homelab.example",   // pre-existing nested @id survives
		"crenel-route-jelly.homelab.example", // top-level @id survives
		"100.100.0.99:9999",                  // cloud leaf untouched
		"status.smallbiz.example",           // other zone untouched
		`"http_basic"`,                      // photos' hand-built auth handler preserved
	} {
		if !strings.Contains(raw, must) {
			t.Errorf("adopt lost/omitted %q:\n%s", must, raw)
		}
	}

	// Idempotent: re-adopting vault is a no-op (already carries the @id).
	if err := d.Adopt(ctx, []string{"vault.homelab.example"}); err != nil {
		t.Fatalf("re-adopt should be idempotent no-op: %v", err)
	}
	again, _ := d.ReadLiveState(ctx)
	if len(again.Routes) != len(post.Routes) {
		t.Errorf("re-adopt changed route count: %d -> %d", len(post.Routes), len(again.Routes))
	}
}
