package caddy_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// countRoutesRaw counts routes and reports whether a given @id survives, by
// inspecting the fake's raw config — proving additivity at the config level.
func inspect(t *testing.T, fake *caddyfake.Fake) (ids map[string]bool, n int) {
	t.Helper()
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []map[string]any `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(fake.CurrentJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	ids = map[string]bool{}
	for _, s := range cfg.Apps.HTTP.Servers {
		for _, r := range s.Routes {
			n++
			if id, ok := r["@id"].(string); ok {
				ids[id] = true
			}
		}
	}
	return ids, n
}

// TestGranularApply_PreservesUnmanagedRoutes is the production-safety test that
// the full-load path could never pass: exposing a host on a rich edge must NOT
// disturb routes Crenel does not model (Authelia auth handler, other vendors'
// routes, the catch-all deny). This is the exact property whose absence blocked
// the live test.
func TestGranularApply_PreservesUnmanagedRoutes(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/rich-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())
	ctx := context.Background()

	// Sanity: the driver's lossy model only sees the two reverse_proxy hosts and
	// the deny — it does NOT model the auth handler — yet apply must preserve it.
	before, _ := inspect(t, fake)
	if !before["prod-vault"] || !before["prod-auth"] || !before["deny-catchall"] {
		t.Fatalf("fixture missing expected ids: %v", before)
	}

	op := model.Op{Verb: model.Expose, Service: "photos", Host: "crenel-selftest.homelab.example"}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	after, n := inspect(t, fake)
	// All pre-existing routes survive untouched.
	for _, id := range []string{"prod-vault", "prod-auth", "deny-catchall"} {
		if !after[id] {
			t.Errorf("granular apply DESTROYED unmanaged route %q", id)
		}
	}
	// Our route was added, tagged with its deterministic @id.
	if !after["crenel-route-crenel-selftest.homelab.example"] {
		t.Error("crenel route not inserted")
	}
	if n != 4 {
		t.Errorf("expected 4 routes (3 prod + 1 crenel), got %d", n)
	}

	// Verify the auth handler on prod-vault is still intact (byte check).
	if !strings.Contains(fake.CurrentJSON(), `"handler":"authentication"`) {
		t.Error("Authelia-style auth handler was lost — not additive!")
	}

	// Read-back: our host reachable, deny still present.
	st, _ := d.ReadLiveState(ctx)
	if !st.Reachable("crenel-selftest.homelab.example") {
		t.Error("test host should be reachable after granular expose")
	}
}

// TestGranularApply_RemoveByID removes only the Crenel route, leaving prod intact.
func TestGranularApply_RemoveByID(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/rich-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())
	ctx := context.Background()
	host := "crenel-selftest.homelab.example"

	// expose then unexpose.
	exposeCS, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: host}, mustState(t, d, ctx))
	if err := d.Apply(ctx, exposeCS); err != nil {
		t.Fatal(err)
	}
	unexposeCS, _ := d.Plan(model.Op{Verb: model.Unexpose, Service: "photos", Host: host}, mustState(t, d, ctx))
	if err := d.Apply(ctx, unexposeCS); err != nil {
		t.Fatal(err)
	}

	after, n := inspect(t, fake)
	if after["crenel-route-"+host] {
		t.Error("crenel route should be gone after unexpose")
	}
	for _, id := range []string{"prod-vault", "prod-auth", "deny-catchall"} {
		if !after[id] {
			t.Errorf("unmanaged route %q must survive unexpose", id)
		}
	}
	if n != 3 {
		t.Errorf("expected back to 3 prod routes, got %d", n)
	}

	st, _ := d.ReadLiveState(ctx)
	if st.HasHost(host) {
		t.Error("test host should no longer be exposed")
	}
}

// TestGranularApply_WildcardShadowingAdditive mirrors the live VPS shape exactly:
// the real edge routes *.homelab.example into a subroute that OWNS its per-host routing.
// crenel-selftest.homelab.example is covered by that wildcard, and exposing it inserts a
// MORE-SPECIFIC exact-host route at index 0 OF THAT SUBROUTE (not flat at the top
// level) — Caddy evaluates the subroute's routes in order, so the exact match wins for
// that one host. The wildcard structure and the other zone are never modified, the
// change is cleanly identifiable/removable by @id at that depth, and after unexpose the
// config is byte-for-byte the original. (Write-side mirror of collectLeaves; the flat
// top-level insert this replaces was the defect the live cross-chain trial caught.)
func TestGranularApply_WildcardShadowingAdditive(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	before := fake.CurrentJSON()
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())
	ctx := context.Background()
	host := "crenel-selftest.homelab.example"

	// The wildcard does not make the specific host an explicit route.
	live0, _ := d.ReadLiveState(ctx)
	if live0.HasHost(host) {
		t.Fatal("specific host must not pre-exist as an explicit route")
	}

	// Expose: insert exact-match route at index 0 of the *.homelab.example subroute.
	exposeCS, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: host}, live0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, exposeCS); err != nil {
		t.Fatal(err)
	}

	// NESTED, not flat: top-level count unchanged (2 wildcards), and the route landed
	// at index 0 INSIDE the *.homelab.example subroute (alongside its existing leaf).
	z := parseZones(t, fake)
	if z.top != 2 {
		t.Fatalf("top-level route count must stay 2 (no flat sibling), got %d", z.top)
	}
	shrimp := z.inner["*.homelab.example"]
	if len(shrimp) != 2 {
		t.Fatalf("*.homelab.example subroute should grow from 1 to 2 inner routes, got %d", len(shrimp))
	}
	if innerHosts(shrimp)[0] != host {
		t.Errorf("crenel exact-host route should be at index 0 of the zone subroute, got %v", innerHosts(shrimp))
	}
	if id, _ := shrimp[0]["@id"].(string); id != "crenel-route-"+host {
		t.Errorf("nested route must carry its @id, got %q", id)
	}
	if len(z.inner["*.smallbiz.example"]) != 1 {
		t.Errorf("the other zone must be untouched, got %d inner", len(z.inner["*.smallbiz.example"]))
	}

	// Read-back PASSES (default-deny present via implicit 404 + host routed at depth).
	st, _ := d.ReadLiveState(ctx)
	if !st.DenyCatchAllPresent {
		t.Error("default-deny must remain present")
	}
	if !st.Reachable(host) {
		t.Error("exact host should be reachable after nested expose (read-back-verify would PASS)")
	}
	if !st.HasHost("*.homelab.example") || !st.HasHost("*.smallbiz.example") {
		t.Error("wildcard subroutes must survive the additive insert")
	}

	// Unexpose by @id (found at its nested depth) and confirm byte-for-byte restoration.
	unexposeCS, _ := d.Plan(model.Op{Verb: model.Unexpose, Service: "photos", Host: host}, st)
	if err := d.Apply(ctx, unexposeCS); err != nil {
		t.Fatal(err)
	}
	if normalizeJSON(t, fake.CurrentJSON()) != normalizeJSON(t, before) {
		t.Errorf("config not restored byte-for-byte after unexpose\nbefore: %s\nafter:  %s", before, fake.CurrentJSON())
	}
}

// normalizeJSON re-marshals through a sorted-key form for stable comparison.
func normalizeJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func mustState(t *testing.T, d *caddy.Driver, ctx context.Context) model.LiveEdgeState {
	t.Helper()
	s, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAdopt_PreservesUnmodeledFields proves Caddy adoption stamps @id onto an
// existing unmanaged route via PATCH while preserving fields Crenel does not model
// (here a `terminal` flag and a header_up sub-config) verbatim — the reason adopt
// navigates the RAW config instead of re-marshaling the typed view. It also leaves
// the deny and other routes untouched, and is idempotent.
func TestAdopt_PreservesUnmodeledFields(t *testing.T) {
	ctx := context.Background()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"terminal":true,"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Up":["1"]}}},"upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}), caddy.WithGranularApply())

	live, _ := d.ReadLiveState(ctx)
	if managedHost(live, "grafana.example.com") {
		t.Fatal("hand-written route must read as unmanaged before adopt")
	}

	if err := d.Adopt(ctx, []string{"grafana.example.com"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	ids, n := inspect(t, fake)
	if !ids["crenel-route-grafana.example.com"] {
		t.Fatal("adopt must stamp the crenel @id")
	}
	if n != 2 {
		t.Fatalf("adopt must not add/remove routes, want 2 got %d", n)
	}
	raw := fake.CurrentJSON()
	if !strings.Contains(raw, `"terminal":true`) || !strings.Contains(raw, `"X-Up"`) {
		t.Fatalf("adopt must preserve unmodeled fields verbatim:\n%s", raw)
	}

	live2, _ := d.ReadLiveState(ctx)
	if !managedHost(live2, "grafana.example.com") {
		t.Fatal("adopted route must read as managed")
	}
	if !live2.Reachable("grafana.example.com") {
		t.Fatal("adopt must not change reachability")
	}

	// Idempotent: a second adopt makes no change.
	if err := d.Adopt(ctx, []string{"grafana.example.com"}); err != nil {
		t.Fatalf("second adopt: %v", err)
	}
	if _, n2 := inspect(t, fake); n2 != 2 {
		t.Fatalf("idempotent adopt must keep 2 routes, got %d", n2)
	}
}

func managedHost(live model.LiveEdgeState, host string) bool {
	for _, r := range live.Routes {
		if r.Host == host {
			return r.Managed
		}
	}
	return false
}
