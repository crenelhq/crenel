package caddy_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// forwardCS builds the ChangeSet a chain front's planForward produces for one host: an
// additive insert of a single forward route (DirectBackend dial to the downstream edge),
// carrying UpstreamTLS as given. This is exactly the route core hands the driver — the
// driver never synthesizes a forward itself, so a render test drives insertRoute through
// this ChangeSet directly.
func forwardCS(host, dial string, upstreamTLS bool) model.ChangeSet {
	return model.ChangeSet{
		Op: model.Op{Verb: model.Expose, Service: "selftest", Host: host},
		Edge: model.EdgeChange{
			DenyCatchAllWillBePresent: true,
			AddRoutes: []model.Route{{
				Host: host,
				Upstream: model.Upstream{
					Kind:        model.DirectBackend,
					Mode:        model.ModeHTTPProxy,
					Address:     dial,
					ServerName:  host,
					UpstreamTLS: upstreamTLS,
				},
			}},
		},
	}
}

// backendReverseProxy returns the BACKEND reverse_proxy handler map of the inner route
// at index 0 of the named wildcard subroute (where a forward to a covered host nests).
// It is the non-auth-gate reverse_proxy — the one carrying the upstream dial/transport.
func backendReverseProxy(t *testing.T, fake *caddyfake.Fake, zone string) map[string]any {
	t.Helper()
	z := parseZones(t, fake)
	inner := z.inner[zone]
	if len(inner) == 0 {
		t.Fatalf("zone %q has no inner routes", zone)
	}
	handlers, _ := inner[0]["handle"].([]any)
	for _, h := range handlers {
		hm, _ := h.(map[string]any)
		if hm["handler"] != "reverse_proxy" {
			continue
		}
		if _, isGate := hm["handle_response"]; isGate {
			continue // skip a forward-auth gate (dials the authorizer, not the backend)
		}
		return hm
	}
	t.Fatalf("no backend reverse_proxy in inner[0] of %q (got %v)", zone, inner[0])
	return nil
}

// TestForward_HTTPSDownstreamRendersUpstreamTLS is the WRITE-SIDE regression for the
// front-leg HTTPS gap the live cross-chain trial RUN 2 caught (TRIAL-FIX-4). A
// chain-forward to a `:443` downstream must render the reverse_proxy WITH an upstream TLS
// transport + a preserved Host — byte-faithful to the edge's OWN working forward routes
// (transport {protocol:http, tls:{insecure_skip_verify, server_name:{http.request.host}}}
// + request Host {http.request.host}) — nested at index 0 of the covering wildcard
// subroute. The OLD render emitted a bare reverse_proxy (no transport, no Host), so the
// downstream's TLS listener answered 400 "Client sent an HTTP request to an HTTPS server".
func TestForward_HTTPSDownstreamRendersUpstreamTLS(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(nil), caddy.WithGranularApply())
	ctx := context.Background()
	host := "selftest.homelab.example"

	if err := d.Apply(ctx, forwardCS(host, "10.0.0.13:443", true)); err != nil {
		t.Fatalf("granular forward insert: %v", err)
	}

	// The forward nested inside the covering wildcard subroute (not flat) — the read side
	// enumerates per-host routes there, so this is where unexpose/verify find it.
	rp := backendReverseProxy(t, fake, "*.homelab.example")

	// transport.tls — byte-faithful to the real VPS forward route.
	wantTransport := map[string]any{
		"protocol": "http",
		"tls": map[string]any{
			"insecure_skip_verify": true,
			"server_name":          "{http.request.host}",
		},
	}
	if got := rp["transport"]; !reflect.DeepEqual(got, wantTransport) {
		t.Errorf("upstream transport mismatch\n got: %#v\nwant: %#v", got, wantTransport)
	}
	// Host preservation — the downstream's host matcher routes by it.
	wantHeaders := map[string]any{
		"request": map[string]any{
			"set": map[string]any{"Host": []any{"{http.request.host}"}},
		},
	}
	if got := rp["headers"]; !reflect.DeepEqual(got, wantHeaders) {
		t.Errorf("request Host header mismatch\n got: %#v\nwant: %#v", got, wantHeaders)
	}
	// The dial still targets the downstream edge.
	ups, _ := rp["upstreams"].([]any)
	if len(ups) != 1 {
		t.Fatalf("expected 1 upstream, got %v", ups)
	}
	if dial, _ := ups[0].(map[string]any)["dial"].(string); dial != "10.0.0.13:443" {
		t.Errorf("forward should dial the downstream edge, got %q", dial)
	}

	// READ-BACK: the forward reads back carrying UpstreamTLS, so verify can confirm the
	// re-originated TLS hop landed (and chain.go still resolves the dial/forward).
	st, _ := d.ReadLiveState(ctx)
	r, ok := routeByHost(st, host)
	if !ok {
		t.Fatalf("forward host absent on read-back")
	}
	if !r.Upstream.UpstreamTLS {
		t.Error("HTTPS forward must read back with UpstreamTLS=true")
	}
	if r.Upstream.Address != "10.0.0.13:443" {
		t.Errorf("forward dial must round-trip, got %q", r.Upstream.Address)
	}
	if !st.DenyCatchAllPresent {
		t.Error("default-deny must remain present after the forward insert")
	}
}

// TestForward_HTTPDownstreamStaysPlain is the contrast that proves the fix is SCOPED:
// a chain-forward to a plain-HTTP downstream (UpstreamTLS=false) must still render a BARE
// reverse_proxy — no transport, no Host rewrite — exactly as before. This is the
// reproduce-the-gap control: the only difference from the HTTPS case is the TLS intent,
// and it is the ONLY thing that flips the transport/Host render on.
func TestForward_HTTPDownstreamStaysPlain(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(nil), caddy.WithGranularApply())
	ctx := context.Background()
	host := "selftest.homelab.example"

	if err := d.Apply(ctx, forwardCS(host, "10.0.0.50:8080", false)); err != nil {
		t.Fatalf("granular forward insert: %v", err)
	}

	rp := backendReverseProxy(t, fake, "*.homelab.example")
	if _, has := rp["transport"]; has {
		t.Errorf("plain-HTTP forward must NOT carry an upstream transport, got %#v", rp["transport"])
	}
	if _, has := rp["headers"]; has {
		t.Errorf("plain-HTTP forward must NOT rewrite Host, got %#v", rp["headers"])
	}

	st, _ := d.ReadLiveState(ctx)
	r, ok := routeByHost(st, host)
	if !ok {
		t.Fatalf("forward host absent on read-back")
	}
	if r.Upstream.UpstreamTLS {
		t.Error("plain-HTTP forward must read back with UpstreamTLS=false")
	}
}
