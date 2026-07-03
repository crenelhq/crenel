package caddy_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// brownfieldForwardAuthSeed mirrors the REAL home edge's Authelia routes (verified
// against live-backup/trial-chain-write-*/home-edge-config-*.json): a per-host route
// whose handle list is [forward-auth GATE, backend reverse_proxy]. The GATE is a
// reverse_proxy dialing the AUTHORIZER (authelia:9080) with a handle_response
// subrequest + a rewrite to the verify URI — exactly what Caddy's `forward_auth`
// directive compiles to. There is NO `{"handler":"forward_auth"}` JSON module — that
// shape (which crenel used to emit) does not exist in any real Caddy config.
const brownfieldForwardAuthSeed = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"match":[{"host":["link.example.com"]}],"handle":[
		{"handler":"reverse_proxy","upstreams":[{"dial":"authelia:9080"}],
		 "rewrite":{"method":"GET","uri":"/api/verify?rd=https://auth.example.com"},
		 "headers":{"request":{"set":{"X-Forwarded-Method":["{http.request.method}"],"X-Forwarded-Uri":["{http.request.uri}"]}}},
		 "handle_response":[{"match":{"status_code":[2]},"routes":[
			{"handle":[{"handler":"vars"}]},
			{"handle":[{"handler":"headers","request":{"set":{"Remote-User":["{http.reverse_proxy.header.Remote-User}"]}}}]}
		 ]}]},
		{"handler":"reverse_proxy","upstreams":[{"dial":"shlink-web:8080"}]}
	]},
	{"handle":[{"handler":"static_response","status_code":403}]}
]}}}}}`

// TestRead_ForwardAuthGateBackendAndRecognition proves the read-model fix the live
// trial demanded: on a real Authelia route ([gate reverse_proxy, backend reverse_proxy])
// crenel reads the BACKEND (not the authorizer) as the service upstream, and recognizes
// the forward-auth gate as auth "(detected)" — read-only, never rewritten.
func TestRead_ForwardAuthGateBackendAndRecognition(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(brownfieldForwardAuthSeed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := routeFor(live, "link.example.com")
	if r == nil {
		t.Fatal("link.example.com route missing")
	}
	if r.Upstream.Address != "shlink-web:8080" {
		t.Errorf("backend must be the SERVICE upstream, not the authorizer — got %q (want shlink-web:8080)", r.Upstream.Address)
	}
	if r.Upstream.Auth != model.AuthDetected {
		t.Errorf("a forward-auth gate (reverse_proxy+handle_response) must read back as %q, got %q", model.AuthDetected, r.Upstream.Auth)
	}
	if !live.DenyCatchAllPresent {
		t.Error("default-deny must still be recognized")
	}
}

// TestRead_VarsMarkerRoundTripsPolicyName proves crenel's OWN marker — a vars handler
// carrying crenel_policy ahead of the gate — round-trips the exact policy NAME on
// read-back (the property that lets status/audit show "auth: authelia" for a managed
// route, not the lossy "(detected)").
func TestRead_VarsMarkerRoundTripsPolicyName(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[
			{"handler":"vars","crenel_policy":"authelia"},
			{"handler":"reverse_proxy","upstreams":[{"dial":"authelia:9080"}],"handle_response":[{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"vars"}]}]}]},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}
		]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := routeFor(live, "grafana.example.com")
	if r == nil {
		t.Fatal("grafana route missing")
	}
	if r.Upstream.Auth != "authelia" {
		t.Errorf("crenel marker must round-trip the policy name, got %q", r.Upstream.Auth)
	}
	if r.Upstream.Address != "10.0.0.5:3000" {
		t.Errorf("backend behind the gate must be read, got %q", r.Upstream.Address)
	}
	if !r.Managed {
		t.Error("a crenel-@id'd route should read back managed")
	}
}
