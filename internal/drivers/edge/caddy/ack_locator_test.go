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

// triageFixture is the brownfield first-audit shape: a path-scoped host route
// (declared matcher_conditional), a HOST-LESS unmodeled handler route (the
// case host-addressed ack cannot reach at all), a nested path-scoped route
// inside a wildcard subroute, and a trailing catch-all deny. Three real
// unknowns, three distinct locator shapes.
const triageFixture = `{
  "apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
    {"match": [{"host": ["grafana.example.com"], "path": ["/admin"]}],
     "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5:3000"}]}]},
    {"handle": [{"handler": "file_server"}]},
    {"match": [{"host": ["*.example.com"]}],
     "handle": [{"handler": "subroute", "routes": [
       {"match": [{"host": ["photos.example.com"], "path": ["/api"]}],
        "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.6:2342"}]}]}
     ]}]},
    {"handle": [{"handler": "static_response", "status_code": 403}]}
  ]}}}}
}`

func newLocatorDriver(t *testing.T) (*caddy.Driver, *caddyfake.Fake) {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	if err := fake.SeedJSON(triageFixture); err != nil {
		t.Fatal(err)
	}
	return caddy.New(fake.URL(), static.New(map[string]string{
		"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342",
	})), fake
}

// unparsedByLocator reads live and indexes Unparsed entries by Locator.
func unparsedByLocator(t *testing.T, d *caddy.Driver) map[string]model.Unparsed {
	t.Helper()
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.Unparsed{}
	for _, u := range live.Unparsed {
		out[u.Locator] = u
	}
	return out
}

// TestAckLocator_HostlessRoute is THE motivating case: routes[1] has no host
// matcher, so Ack(host,…) can never address it — AckLocator by structural path
// must stamp it, the next read must classify it acknowledged (read side is
// ack-aware for host-less declares), and it must be idempotent.
func TestAckLocator_HostlessRoute(t *testing.T) {
	d, _ := newLocatorDriver(t)
	ctx := context.Background()
	loc := "apps.http.servers.srv0.routes[1]"

	before := unparsedByLocator(t, d)
	if before[loc].Kind != model.UnknownHandler {
		t.Fatalf("fixture: routes[1] should be a host-less handler_unrecognized unknown, got %+v", before[loc])
	}

	if err := d.AckLocator(ctx, loc, "hostless-carveout"); err != nil {
		t.Fatalf("AckLocator: %v", err)
	}
	after := unparsedByLocator(t, d)
	if after[loc].Kind != model.UnknownAcknowledged {
		t.Fatalf("route at %s should read acknowledged_unknown after AckLocator, got %+v", loc, after[loc])
	}
	if !strings.Contains(after[loc].Reason, "hostless-carveout") {
		t.Errorf("acked entry should carry the reason slug, got %q", after[loc].Reason)
	}
	// Idempotent: exact re-ack is a tolerated no-op.
	if err := d.AckLocator(ctx, loc, "hostless-carveout"); err != nil {
		t.Fatalf("re-ack must be a no-op, got %v", err)
	}

	// Undo: UnackLocator reverts the route to its real unknown kind.
	if err := d.UnackLocator(ctx, loc); err != nil {
		t.Fatalf("UnackLocator: %v", err)
	}
	if k := unparsedByLocator(t, d)[loc].Kind; k != model.UnknownHandler {
		t.Fatalf("after unack the route must revert to handler_unrecognized, got %v", k)
	}
}

// TestAckLocator_NestedSubroute proves locator descent mirrors the read side:
// the ".handle[subroute].routes[j]" step lands on the nested route the audit
// flagged, and two routes acked with the SAME reason get DISTINCT markers
// (no global-@id collision — the fake enforces uniqueness like real Caddy).
func TestAckLocator_NestedSubroute(t *testing.T) {
	d, _ := newLocatorDriver(t)
	ctx := context.Background()
	nested := "apps.http.servers.srv0.routes[2].handle[subroute].routes[0]"
	top := "apps.http.servers.srv0.routes[0]"

	if err := d.AckLocator(ctx, nested, "same-reason"); err != nil {
		t.Fatalf("AckLocator nested: %v", err)
	}
	// Same reason on a second route: the qualifier (locator) differentiates the
	// @id, so this must NOT collide.
	if err := d.AckLocator(ctx, top, "same-reason"); err != nil {
		t.Fatalf("AckLocator with a reused reason must not collide on @id: %v", err)
	}
	after := unparsedByLocator(t, d)
	for _, loc := range []string{nested, top} {
		if after[loc].Kind != model.UnknownAcknowledged {
			t.Errorf("route at %s should be acknowledged, got %+v", loc, after[loc])
		}
	}
}

// TestAckLocator_Refusals: a stale/bogus locator errors clearly (config may
// have changed since the audit), a whole-server locator is not route-shaped,
// and RouteRawJSON returns the FULL route for the [o]pen action.
func TestAckLocator_Refusals(t *testing.T) {
	d, _ := newLocatorDriver(t)
	ctx := context.Background()

	if err := d.AckLocator(ctx, "apps.http.servers.srv0.routes[99]", "x"); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Errorf("out-of-range locator must name the staleness, got %v", err)
	}
	if err := d.AckLocator(ctx, "apps.http.servers.srv0", "x"); err == nil ||
		!strings.Contains(err.Error(), "whole server block") {
		t.Errorf("server-block locator must be refused as not route-shaped, got %v", err)
	}
	s, err := d.RouteRawJSON(ctx, "apps.http.servers.srv0.routes[1]")
	if err != nil {
		t.Fatalf("RouteRawJSON: %v", err)
	}
	if !strings.Contains(s, "file_server") {
		t.Errorf("RouteRawJSON should return the raw route, got %s", s)
	}
}
