package caddy_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// TestReadLiveState_HostlessSubrouteDenyIsDefaultDeny reproduces the EXACT shape the
// real Caddy Caddyfile adapter produces for the canonical default-deny spelling
//
//	:80 { respond 403 }
//
// Caddy wraps every site block's directives in a SUBROUTE handler, so the host-less
// catch-all deny is one level below the top-level route: a host-less route whose only
// handler is a subroute whose only leaf is `static_response 403`. crenel recognizes a
// DIRECT host-less static_response deny (testdata/grafana.json) but historically did
// NOT descend the host-less subroute — so a Caddyfile-configured default-deny edge
// (e.g. the crenel bundle, and the CT 110 proving-ground Caddy) misread as
// "subroute_not_descended" → Default-deny UNKNOWN. The in-repo fakes never caught this
// because SeedJSON fixtures hand-wrote the deny as a TOP-LEVEL static_response, a shape
// the real adapter never emits. This fixture is byte-faithful to the live bench srv0.
func TestReadLiveState_HostlessSubrouteDenyIsDefaultDeny(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/hostless-subroute-deny.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())

	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("a host-less subroute wrapping ONLY a static_response 403 IS the canonical Caddyfile default-deny; must read as present")
	}
	if len(live.Unparsed) != 0 {
		t.Errorf("the host-less subroute deny must be understood, not flagged unparsed: %+v", live.Unparsed)
	}
	if !live.HasHost("blog3.bench.local") {
		t.Error("the host-scoped route should still be enumerated")
	}
	if live.Reachable("anything-else.bench.local") {
		t.Error("an unrouted host must not be reachable behind the deny")
	}
}

// TestReadLiveState_HostlessSubroutePermissiveStillFailOpen guards the conservative
// half of the fix: a host-less subroute that wraps a PERMISSIVE forward (a reverse_proxy
// that serves every host) must STILL read fail-open — the descent recognizes only a
// deny-ONLY subroute, never silently blesses a catch-all that exposes traffic.
func TestReadLiveState_HostlessSubroutePermissiveStillFailOpen(t *testing.T) {
	const failopen = `{
      "apps": {"http": {"servers": {"srv0": {"listen": [":80"], "routes": [
        {"handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "whoami:80"}]}]}]}]}
      ]}}}}}`
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(failopen); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.DenyCatchAllPresent {
		t.Error("a host-less subroute wrapping a permissive reverse_proxy forwards every host — must read fail-open, not default-deny")
	}
}
