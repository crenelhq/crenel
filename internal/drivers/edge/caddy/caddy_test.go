package caddy_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

func resolver() *static.Resolver {
	return static.New(map[string]string{
		"grafana": "10.0.0.5:3000",
		"photos":  "10.0.0.6:2342",
	})
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReadLiveState_NormalizesAndDetectsDeny(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/grafana.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())

	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("expected catch-all deny detected from fixture")
	}
	if len(live.Routes) != 1 || live.Routes[0].Host != "grafana.example.com" {
		t.Fatalf("unexpected routes: %+v", live.Routes)
	}
	if live.Routes[0].Upstream.Address != "10.0.0.5:3000" {
		t.Errorf("unexpected backend: %q", live.Routes[0].Upstream.Address)
	}
}

// TestReadLiveState_ImplicitDefaultDeny: a config with only host-scoped routes
// and NO explicit catch-all is still default-deny — unmatched hosts get Caddy's
// implicit 404. This is the corrected model (the old code wrongly flagged this
// as "missing deny / fail-open").
func TestReadLiveState_ImplicitDefaultDeny(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/no-deny.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("host-scoped-only config is default-deny via implicit 404; must read as present")
	}
	if !live.HasHost("grafana.example.com") {
		t.Error("grafana route should be listed")
	}
	if live.Reachable("evil.example.com") {
		t.Error("an unrouted host must not be reachable")
	}
}

// TestReadLiveState_PermissiveCatchAllIsFailOpen: a host-less reverse_proxy
// forwards EVERY host => genuinely fail-open => default-deny NOT present.
func TestReadLiveState_PermissiveCatchAllIsFailOpen(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/failopen.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.DenyCatchAllPresent {
		t.Error("a host-less reverse_proxy is a permissive catch-all; must read as fail-open")
	}
}

// TestReadLiveState_SubrouteWildcardEdge models the REAL production srv0:
// wildcard hosts routed into subroutes, separate crowdsec/tls apps, no flat
// reverse_proxy and no explicit catch-all. Must read as default-deny present and
// list both wildcard routes.
func TestReadLiveState_SubrouteWildcardEdge(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("subroute/wildcard edge with no permissive catch-all must read as default-deny present")
	}
	if !live.HasHost("*.homelab.example") || !live.HasHost("*.smallbiz.example") {
		t.Fatalf("expected both wildcard subroute hosts, got %v", live.Hosts())
	}
	// A specific host under the wildcard is NOT itself an explicit route.
	if live.HasHost("crenel-selftest.homelab.example") {
		t.Error("a specific host should not be reported as explicitly routed by the wildcard")
	}
}

func TestPlan_Expose(t *testing.T) {
	d := caddy.New("http://unused", resolver())
	live := model.LiveEdgeState{DenyCatchAllPresent: true}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edge.AddRoutes) != 1 || cs.Edge.AddRoutes[0].Upstream.Address != "10.0.0.6:2342" {
		t.Fatalf("unexpected add routes: %+v", cs.Edge.AddRoutes)
	}
	if !cs.Edge.DenyCatchAllWillBePresent {
		t.Error("deny must remain present after expose")
	}
	if len(cs.NewPublic) != 1 || cs.NewPublic[0] != "photos.example.com" {
		t.Errorf("expected NewPublic highlight, got %v", cs.NewPublic)
	}
}

func TestPlan_ExposeAlreadyExposedIsNoOp(t *testing.T) {
	d := caddy.New("http://unused", resolver())
	live := model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{{Host: "photos.example.com"}},
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Empty() {
		t.Errorf("re-exposing should be a no-op, got %+v", cs)
	}
}

func TestPlan_UnknownServiceFails(t *testing.T) {
	d := caddy.New("http://unused", resolver())
	_, err := d.Plan(model.Op{Verb: model.Expose, Service: "nope", Host: "nope.example.com"}, model.LiveEdgeState{})
	if err == nil {
		t.Error("expected error for unknown service")
	}
}

// TestApplyRoundTrip exercises Apply against the fake and verifies the rendered
// Caddyfile adapts back into the expected live state — and that the default-deny
// is always present afterward.
func TestApplyRoundTrip(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	d := caddy.New(fake.URL(), resolver())
	ctx := context.Background()

	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	after, _ := d.ReadLiveState(ctx)
	if !after.DenyCatchAllPresent {
		t.Fatal("default-deny missing after apply — invariant violated")
	}
	if !after.HasHost("photos.example.com") {
		t.Error("photos should be exposed after apply")
	}
	if !after.HasHost("grafana.example.com") {
		t.Error("grafana should remain exposed after apply")
	}
	// Negative: a never-exposed host is not reachable.
	if after.Reachable("evil.example.com") {
		t.Error("un-exposed host must not be reachable")
	}
}

func TestApply_RejectedLoadErrors(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	fake.RejectReload = "boom"
	d := caddy.New(fake.URL(), resolver())
	live, _ := d.ReadLiveState(context.Background())
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err := d.Apply(context.Background(), cs); err == nil {
		t.Error("expected error when /load returns 4xx")
	}
}

// TestPlan_RefusesNonHTTPProxyMode: Caddy terminates TLS and reverse-proxies; it
// must refuse SNI passthrough / mesh-grant intents loudly (model.ErrModeUnsupported).
func TestPlan_RefusesNonHTTPProxyMode(t *testing.T) {
	d := caddy.New("http://127.0.0.1:0", static.New(map[string]string{"photos": "10.0.0.6:2342"}))
	for _, m := range []model.RouteMode{model.ModeTCPPassthrough, model.ModeMeshGrant} {
		op := model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com", Mode: m}
		_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
		if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
			t.Errorf("mode %s should be refused with ErrModeUnsupported, got: %v", m, err)
		}
	}
}
