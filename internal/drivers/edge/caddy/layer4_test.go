package caddy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// l4Resolver resolves a passthrough-able backend.
func l4Resolver() *static.Resolver {
	return static.New(map[string]string{
		"grafana": "10.0.0.5:3000",
		"db":      "10.0.0.7:5432",
	})
}

// TestLayer4_PassthroughRoundTrip: with the layer4 capability + granular apply, a
// passthrough expose renders an SNI-matched proxy route in the layer4 app, reads
// back as ModeTCPPassthrough, and unexpose removes it — ADDITIVELY: the unmanaged
// http route and the default-deny are untouched throughout.
func TestLayer4_PassthroughRoundTrip(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// An existing http reverse-proxy route + the deny (the layer4 write must not
	// disturb these).
	fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")

	d := caddy.New(fake.URL(), l4Resolver(), caddy.WithGranularApply(), caddy.WithLayer4())
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "db", Host: "db.example.com", Mode: model.ModeTCPPassthrough}
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatalf("layer4 passthrough plan should succeed, got: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 || cs.Edge.AddRoutes[0].Upstream.Mode != model.ModeTCPPassthrough {
		t.Fatalf("plan should add one passthrough route, got %+v", cs.Edge)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("apply passthrough: %v", err)
	}

	// Read back: db is a passthrough route; grafana is still an http route; deny holds.
	after, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !after.DenyCatchAllPresent {
		t.Error("default-deny must still hold after a layer4 expose")
	}
	var dbMode model.RouteMode
	var grafanaMode model.RouteMode
	var grafanaFound bool
	for _, r := range after.Routes {
		switch r.Host {
		case "db.example.com":
			dbMode = r.Upstream.Mode
			if r.Upstream.Address != "10.0.0.7:5432" || !r.Upstream.TLSPassthrough {
				t.Errorf("db passthrough route has wrong upstream: %+v", r.Upstream)
			}
		case "grafana.example.com":
			grafanaFound, grafanaMode = true, r.Upstream.Mode
		}
	}
	if dbMode != model.ModeTCPPassthrough {
		t.Errorf("db should read back as passthrough, got %q", dbMode)
	}
	if !grafanaFound || grafanaMode != model.ModeHTTPProxy {
		t.Errorf("unmanaged http grafana route must survive as http_proxy, got found=%v mode=%q", grafanaFound, grafanaMode)
	}

	// The raw config must contain a layer4 app with an SNI match (the real shape).
	raw := fake.CurrentJSON()
	if !strings.Contains(raw, "layer4") || !strings.Contains(raw, "db.example.com") {
		t.Errorf("config should contain a layer4 SNI route for db, got: %s", raw)
	}

	// Unexpose removes the passthrough route; grafana + deny remain.
	un := model.Op{Verb: model.Unexpose, Service: "db", Host: "db.example.com", Mode: model.ModeTCPPassthrough}
	csU, err := d.Plan(un, after)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, csU); err != nil {
		t.Fatalf("unexpose passthrough: %v", err)
	}
	final, _ := d.ReadLiveState(ctx)
	for _, r := range final.Routes {
		if r.Host == "db.example.com" {
			t.Error("db passthrough route should be gone after unexpose")
		}
	}
	if !final.HasHost("grafana.example.com") || !final.DenyCatchAllPresent {
		t.Error("grafana http route + deny must survive the passthrough unexpose")
	}
}

// TestLayer4_RefusedWithoutCapability: without WithLayer4 the driver refuses
// passthrough LOUDLY (classified ErrModeUnsupported) — no leaky approximation.
func TestLayer4_RefusedWithoutCapability(t *testing.T) {
	d := caddy.New("http://unused", l4Resolver(), caddy.WithGranularApply()) // no WithLayer4
	op := model.Op{Verb: model.Expose, Service: "db", Host: "db.example.com", Mode: model.ModeTCPPassthrough}
	_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
		t.Fatalf("passthrough without layer4 should be refused with ErrModeUnsupported, got: %v", err)
	}
	if !strings.Contains(err.Error(), "layer4") {
		t.Errorf("refusal should point at the layer4 plugin, got: %v", err)
	}
}

// TestLayer4_RequiresGranular: layer4 passthrough needs additive granular apply so
// it can't disturb the http routes — Plan refuses it loudly under full-load.
func TestLayer4_RequiresGranular(t *testing.T) {
	d := caddy.New("http://unused", l4Resolver(), caddy.WithLayer4()) // layer4 but NOT granular
	op := model.Op{Verb: model.Expose, Service: "db", Host: "db.example.com", Mode: model.ModeTCPPassthrough}
	_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
		t.Fatalf("passthrough without granular should be refused, got: %v", err)
	}
	if !strings.Contains(err.Error(), "granular") {
		t.Errorf("refusal should point at granular apply, got: %v", err)
	}
}

// TestLayer4_StillRefusesMeshGrant: even with layer4, an identity-mesh grant is not
// something Caddy expresses — refuse it loudly.
func TestLayer4_StillRefusesMeshGrant(t *testing.T) {
	d := caddy.New("http://unused", l4Resolver(), caddy.WithGranularApply(), caddy.WithLayer4())
	op := model.Op{Verb: model.Expose, Service: "db", Host: "db.example.com", Mode: model.ModeMeshGrant}
	_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
		t.Fatalf("mesh-grant should still be refused even with layer4, got: %v", err)
	}
}
