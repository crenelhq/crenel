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

// zoneRoutes is the parsed view a nesting test needs: how many TOP-LEVEL routes the
// managed server holds, and the inner routes of the subroute owning a given wildcard
// host (so a test can assert WHERE a per-host route landed — nested vs flat).
type zoneRoutes struct {
	top   int
	inner map[string][]map[string]any // "*.zone" -> that subroute's inner routes
}

func parseZones(t *testing.T, fake *caddyfake.Fake) zoneRoutes {
	t.Helper()
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match  []struct {
							Host []string `json:"host"`
						} `json:"match"`
						Handle []struct {
							Handler string           `json:"handler"`
							Routes  []map[string]any `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(fake.CurrentJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	z := zoneRoutes{inner: map[string][]map[string]any{}}
	srv := cfg.Apps.HTTP.Servers["srv0"]
	z.top = len(srv.Routes)
	for _, r := range srv.Routes {
		var host string
		if len(r.Match) > 0 && len(r.Match[0].Host) > 0 {
			host = r.Match[0].Host[0]
		}
		for _, h := range r.Handle {
			if h.Handler == "subroute" && strings.HasPrefix(host, "*.") {
				z.inner[host] = h.Routes
			}
		}
	}
	return z
}

// innerHosts returns the first host matcher of each inner route (or "" for host-less),
// in order — so a test can assert the new per-host route is at index 0 of the subroute.
func innerHosts(routes []map[string]any) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		host := ""
		if matches, ok := r["match"].([]any); ok && len(matches) > 0 {
			if m, ok := matches[0].(map[string]any); ok {
				if hs, ok := m["host"].([]any); ok && len(hs) > 0 {
					host, _ = hs[0].(string)
				}
			}
		}
		out = append(out, host)
	}
	return out
}

func nestedResolverPlus() *static.Resolver {
	return static.New(map[string]string{
		"selftest": "100.100.0.42:8080", // the new host we expose in these tests
		"vault":    "100.100.0.10:8200",
		"git":      "100.100.0.11:3000",
		"photos":   "100.100.0.12:2342",
		"jelly":    "100.100.0.13:8096",
		"cloud":    "100.100.0.14:80",
	})
}

// TestGranularApply_NestsPerHostRouteIntoWildcardSubroute is the WRITE-SIDE mirror of
// collectLeaves and the regression test for the live cross-chain trial's nesting
// defect: on an edge whose per-host routing lives INSIDE a *.zone wildcard subroute
// (the real home/front shape), exposing a host must insert the per-host route INSIDE
// the matching wildcard subroute — NOT as a flat top-level sibling. The OLD flat
// insert (PUT …/routes/0) misplaced it at the top level, leaving the zone subroute
// untouched (the bug). After the fix the route lands at index 0 of the *.homelab.example
// subroute, read-back-verifies at that depth, every other route is byte-intact, and
// unexpose removes it from there → byte-for-byte restore.
func TestGranularApply_NestsPerHostRouteIntoWildcardSubroute(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	before := fake.CurrentJSON()
	d := caddy.New(fake.URL(), nestedResolverPlus(), caddy.WithGranularApply())
	ctx := context.Background()
	host := "selftest.homelab.example"

	pre := parseZones(t, fake)
	if pre.top != 3 || len(pre.inner["*.homelab.example"]) != 4 {
		t.Fatalf("fixture shape unexpected: top=%d shrimp-inner=%d", pre.top, len(pre.inner["*.homelab.example"]))
	}

	live0, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "selftest", Host: host}, live0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("granular expose: %v", err)
	}

	post := parseZones(t, fake)
	// TOP-LEVEL count UNCHANGED — the route did NOT flat-insert as a sibling.
	if post.top != 3 {
		t.Errorf("top-level route count must stay 3 (no flat sibling), got %d", post.top)
	}
	// It landed INSIDE the *.homelab.example subroute, at index 0 (exact match wins).
	shrimp := post.inner["*.homelab.example"]
	if len(shrimp) != 5 {
		t.Fatalf("*.homelab.example subroute should grow to 5 inner routes, got %d", len(shrimp))
	}
	if got := innerHosts(shrimp)[0]; got != host {
		t.Errorf("new per-host route should be at index 0 of the zone subroute, got first=%q (all=%v)", got, innerHosts(shrimp))
	}
	if id, _ := shrimp[0]["@id"].(string); id != "crenel-route-"+host {
		t.Errorf("nested route must carry its @id, got %q", id)
	}
	// The OTHER zone is untouched.
	if len(post.inner["*.smallbiz.example"]) != 1 {
		t.Errorf("the other zone must be untouched, got %d inner", len(post.inner["*.smallbiz.example"]))
	}

	// READ-BACK at the nested depth: host reachable with its real backend, deny holds.
	st, _ := d.ReadLiveState(ctx)
	if !st.DenyCatchAllPresent {
		t.Error("default-deny must remain present after nested insert")
	}
	r, ok := routeByHost(st, host)
	if !ok || !st.Reachable(host) {
		t.Fatalf("host must read back reachable at its nested location, got %+v ok=%v", r, ok)
	}
	if r.Upstream.Address != "100.100.0.42:8080" {
		t.Errorf("nested route should dial the resolved origin, got %q", r.Upstream.Address)
	}
	if !r.Managed {
		t.Error("nested route should read back as managed (carries the crenel @id)")
	}

	// Every pre-existing service survives the additive nested insert (byte presence).
	raw := fake.CurrentJSON()
	for _, must := range []string{
		"100.100.0.10:8200", "crenel-route-git.homelab.example", "100.100.0.12:2342",
		"100.100.0.99:9999", "crenel-route-jelly.homelab.example", "status.smallbiz.example",
		`"http_basic"`,
	} {
		if !strings.Contains(raw, must) {
			t.Errorf("nested insert lost/omitted %q", must)
		}
	}

	// Unexpose removes it FROM the nested location → byte-for-byte restore.
	st2, _ := d.ReadLiveState(ctx)
	unCS, _ := d.Plan(model.Op{Verb: model.Unexpose, Service: "selftest", Host: host}, st2)
	if err := d.Apply(ctx, unCS); err != nil {
		t.Fatalf("granular unexpose: %v", err)
	}
	if normalizeJSON(t, fake.CurrentJSON()) != normalizeJSON(t, before) {
		t.Errorf("config not restored byte-for-byte after nested unexpose\nbefore: %s\nafter:  %s", before, fake.CurrentJSON())
	}
}

// TestGranularApply_FlatEdgeStillFlatInserts locks in back-compat: an edge with NO
// wildcard subroutes (a flat / greenfield edge) keeps the historical top-level
// index-0 insert. Mixing the two would be the regression.
func TestGranularApply_FlatEdgeStillFlatInserts(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/rich-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{"selftest": "10.0.0.9:80"}), caddy.WithGranularApply())
	ctx := context.Background()
	host := "selftest.homelab.example"

	live0, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "selftest", Host: host}, live0)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	z := parseZones(t, fake)
	// Flat edge: the route is a TOP-LEVEL sibling (3 prod + 1 crenel), no subroutes.
	if z.top != 4 {
		t.Errorf("flat edge must keep flat top-level insert, got top=%d", z.top)
	}
	if len(z.inner) != 0 {
		t.Errorf("flat edge has no wildcard subroutes, got %v", z.inner)
	}
	st, _ := d.ReadLiveState(ctx)
	if !st.Reachable(host) || !st.DenyCatchAllPresent {
		t.Error("flat insert must read back reachable with deny present")
	}
}

// TestGranularApply_FlatZoneOnMixedEdge_FlatInserts is the per-ZONE decision: an edge
// can route SOME zones via wildcard subroutes while keeping others flat. A host whose
// OWN zone is flat (it has a flat top-level sibling in that zone) joins its flat
// siblings at the top level — it is NOT nested into an unrelated zone's wildcard
// subroute, and NOT refused. (This is the shape of the brownfield-safety fixture.)
func TestGranularApply_FlatZoneOnMixedEdge_FlatInserts(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// *.homelab.example routes via a wildcard subroute; example.com is FLAT (grafana is a
	// flat top-level per-host route). The new host is in the flat example.com zone.
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
			{"handle":[{"handler":"static_response","status_code":403}]}
		]}]},
		{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	d := caddy.New(fake.URL(), static.New(map[string]string{"photos": "10.0.0.6:2342"}), caddy.WithGranularApply())
	ctx := context.Background()
	host := "photos.example.com"

	live0, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: host}, live0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("flat-zone expose on a mixed edge must succeed, got: %v", err)
	}

	z := parseZones(t, fake)
	// Joined its flat siblings at the TOP level (was 3: wildcard + grafana + deny → 4).
	if z.top != 4 {
		t.Errorf("flat-zone host must flat-insert at top level, got top=%d", z.top)
	}
	// The unrelated *.homelab.example subroute is untouched (still just its deny).
	if len(z.inner["*.homelab.example"]) != 1 {
		t.Errorf("the unrelated wildcard zone must NOT receive the route, got %d inner", len(z.inner["*.homelab.example"]))
	}
	st, _ := d.ReadLiveState(ctx)
	if !st.Reachable(host) || !st.DenyCatchAllPresent {
		t.Error("flat-zone insert must read back reachable with deny present")
	}
}

// TestGranularApply_NoWildcardSubrouteForZone_Refused is the explicit honest edge
// case: a subroute-structured edge whose wildcard subroutes do NOT cover the host's
// zone must REFUSE rather than silently flat-insert a per-host route into a
// subroute-structured edge (where it would not be owned by any zone).
func TestGranularApply_NoWildcardSubrouteForZone_Refused(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// Only a *.homelab.example wildcard subroute exists; the host is in another zone.
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
			{"handle":[{"handler":"static_response","status_code":403}]}
		]}]}
	]}}}}}`)
	d := caddy.New(fake.URL(), static.New(map[string]string{"svc": "10.0.0.9:80"}), caddy.WithGranularApply())
	ctx := context.Background()
	host := "svc.example.org"

	live0, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "svc", Host: host}, live0)
	err := d.Apply(ctx, cs)
	if err == nil {
		t.Fatal("expected a refusal: no wildcard subroute covers this host's zone on a subroute-structured edge")
	}
	if !strings.Contains(err.Error(), host) {
		t.Errorf("refusal should name the host, got %v", err)
	}
	// Nothing was inserted.
	if z := parseZones(t, fake); z.top != 1 || len(z.inner["*.homelab.example"]) != 1 {
		t.Errorf("a refused insert must leave the edge untouched, got top=%d inner=%d", z.top, len(z.inner["*.homelab.example"]))
	}
}
