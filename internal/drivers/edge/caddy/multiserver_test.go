package caddy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_MultiServer_FoldsModeledSibling proves the multi-server fix (P1.5):
// a SECOND http server crenel can fully model has its leaf routes folded into the
// normalized view, so a host exposed on a sibling server is no longer INVISIBLE.
// Before this fix, normalize read only the configured server (srv0) and silently
// ignored srv1 — a MISREAD-by-omission that under-reports exposure.
func TestNormalize_MultiServer_FoldsModeledSibling(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// srv0 (configured): grafana + deny. srv1 (sibling): photos via reverse_proxy.
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv1":{"listen":["10.0.0.1:8443"],"routes":[
			{"match":[{"host":["photos.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.6:2342"}]}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// BOTH hosts must be visible — the sibling's route is real exposure.
	if !live.HasHost("grafana.example.com") {
		t.Errorf("configured-server host missing; got %v", live.Hosts())
	}
	if !live.HasHost("photos.example.com") {
		t.Errorf("sibling-server host must be folded in (was previously invisible); got %v", live.Hosts())
	}
	// A fully-modeled sibling adds no Unparsed; deny stays ENFORCED.
	if !live.FullyParsed() {
		t.Errorf("a fully-modeled sibling must not add Unparsed entries; got %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("deny should remain ENFORCED with a fully-modeled sibling, got %q", got)
	}
}

// TestNormalize_MultiServer_UnmodeledForwardingSiblingIsUnknown proves the safety
// half: a sibling server that FORWARDS (reverse_proxy/subroute) but carries a handler
// crenel cannot model surfaces as an UnknownServerBlock — and that downgrades
// default-deny to UNKNOWN (a forwarding server crenel cannot fully see could be
// exposing or fail-open). This is the hidden-exposure case the fix must catch.
func TestNormalize_MultiServer_UnmodeledForwardingSiblingIsUnknown(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// srv1 forwards (it has a reverse_proxy host) AND has an unmodeled host (file_server).
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv1":{"listen":["10.0.0.1:8443"],"routes":[
			{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.7:80"}]}]},
			{"match":[{"host":["files.example.com"]}],"handle":[{"handler":"file_server","root":"/srv"}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Exactly one UnknownServerBlock, attributed to srv1.
	var blocks int
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownServerBlock {
			blocks++
			if !strings.Contains(u.Locator, "srv1") {
				t.Errorf("UnknownServerBlock must be attributed to srv1, got locator %q", u.Locator)
			}
			if u.Reason == "" {
				t.Errorf("UnknownServerBlock must carry a reason: %+v", u)
			}
		}
	}
	if blocks != 1 {
		t.Fatalf("expected exactly 1 UnknownServerBlock, got %d: %+v", blocks, live.Unparsed)
	}
	// The configured server is still understood and present.
	if !live.HasHost("grafana.example.com") {
		t.Errorf("configured-server host must still be read; got %v", live.Hosts())
	}
	// Deny MUST downgrade to UNKNOWN — this is the safety property the fix closes.
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("an unparsed forwarding sibling must DOWNGRADE deny to UNKNOWN, got %q", got)
	}
}

// TestNormalize_MultiServer_BenignRedirectNotFlagged proves the no-cry-wolf half: a
// classic :80→:443 redirect-only server (static_response 308 + a Location header,
// NOT a forwarder) must NOT be flagged — it exposes nothing. Amber-flagging every
// helper listener would be the cry-wolf the register warns against.
func TestNormalize_MultiServer_BenignRedirectNotFlagged(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv_redirect":{"listen":[":80"],"routes":[
			{"handle":[{"handler":"static_response","status_code":308,"headers":{"Location":["https://{http.request.host}{http.request.uri}"]}}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !live.FullyParsed() {
		t.Errorf("a benign redirect-only sibling must NOT add Unparsed entries; got %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("deny must stay ENFORCED — a redirect server is not exposure, got %q", got)
	}
}

// TestNormalize_MultiServer_StaticFileServerNotFlagged proves a pure static/file
// server (no reverse_proxy, no subroute) is likewise treated as benign — it does not
// FORWARD, so it is not hidden proxy-exposure to surface.
func TestNormalize_MultiServer_StaticFileServerNotFlagged(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv_static":{"listen":[":8080"],"routes":[
			{"match":[{"host":["docs.example.com"]}],"handle":[{"handler":"file_server","root":"/var/www"}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.FullyParsed() {
		t.Errorf("a non-forwarding static sibling must NOT be flagged; got %+v", live.Unparsed)
	}
}

// TestNormalize_MultiServer_SeparateAppsNotMisreadAsServers confirms his real edge
// shape: crowdsec/tls live as separate Caddy *apps*, not http.servers, so they must
// never be misread as server blocks. The Config type only models the http+layer4
// apps, so unknown apps are simply ignored — assert no phantom servers/unparsed.
func TestNormalize_MultiServer_SeparateAppsNotMisreadAsServers(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{
		"http":{"servers":{
			"srv0":{"listen":[":443"],"routes":[
				{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
				{"handle":[{"handler":"static_response","status_code":403}]}
			]}
		}},
		"tls":{"automation":{"policies":[{"issuers":[{"module":"acme"}]}]}},
		"crowdsec":{"api_url":"http://127.0.0.1:8080","api_key":"redacted"}
	}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Routes) != 1 || !live.HasHost("grafana.example.com") {
		t.Errorf("only the one http route should be read; tls/crowdsec are apps not servers; got %v", live.Hosts())
	}
	if !live.FullyParsed() {
		t.Errorf("separate apps must not produce Unparsed entries; got %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("deny ENFORCED expected, got %q", got)
	}
}

// TestFullLoad_RefusesMultiForwardingServerEdge proves the multi-server full-load
// guard: because renderCaddyfile emits a SINGLE server, a full-config replace on an
// edge with a forwarding sibling would collapse/restructure it. The default
// (non-granular) path must refuse and point at --granular, leaving live untouched.
func TestFullLoad_RefusesMultiForwardingServerEdge(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv1":{"listen":["10.0.0.1:8443"],"routes":[
			{"match":[{"host":["photos.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.6:2342"}]}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver()) // NOT granular => full-load path
	ctx := context.Background()
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "new.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Apply(ctx, cs)
	if err == nil || !strings.Contains(err.Error(), "forwarding http server") {
		t.Fatalf("full-load on a multi-forwarding-server edge must refuse, got %v", err)
	}
	// Nothing clobbered: both servers still present.
	got := fake.CurrentJSON()
	if !strings.Contains(got, "srv1") || !strings.Contains(got, "photos.example.com") {
		t.Errorf("a refused full-load must not restructure the edge; srv1 gone:\n%s", got)
	}
}

// TestGranular_MultiServer_PreservesSiblingServer proves the granular path is safe on
// a multi-server edge: an additive insert touches only crenel's @id-tagged route on
// the managed server and leaves the sibling server (and its routes) byte-for-byte.
func TestGranular_MultiServer_PreservesSiblingServer(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{
		"srv0":{"listen":[":443"],"routes":[
			{"handle":[{"handler":"static_response","status_code":403}]}
		]},
		"srv1":{"listen":["10.0.0.1:8443"],"routes":[
			{"match":[{"host":["photos.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.6:2342"}]}]}
		]}
	}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())
	ctx := context.Background()
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("granular apply on a multi-server edge should succeed, got %v", err)
	}
	after, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Reachable("grafana.example.com") {
		t.Errorf("the newly exposed host should be reachable")
	}
	if !after.HasHost("photos.example.com") {
		t.Errorf("the sibling-server route must be preserved across a granular apply; got %v", after.Hosts())
	}
}
