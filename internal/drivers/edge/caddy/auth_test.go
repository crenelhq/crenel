package caddy_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// authSeed is a minimal granular-ready edge: an empty managed server + the deny.
const authSeed = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"handle":[{"handler":"static_response","status_code":403}]}
]}}}}}`

// homeAuthRef configures the authelia policy the way the maintainer's home edge expresses it:
// the canonical forward_auth expansion (endpoint + verify URI + the four Remote-* copy
// headers), so the granular path renders the EXACT reverse_proxy+handle_response shape
// the live home Caddy accepts (verified against live-backup/trial-chain-write-*).
func homeAuthRef() caddy.Option {
	return caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {
		ForwardAuth: "authelia:9080",
		VerifyURI:   "/api/verify?rd=https://auth.example.com",
		CopyHeaders: []string{"Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email"},
	}})
}

// TestAuth_GranularRendersCanonicalForwardAuth proves a crenel-managed expose with a
// forward-auth policy renders the VALID, Caddy-accepted gate the live trial demanded:
// a `vars` policy marker + the canonical reverse_proxy+handle_response gate (NOT the
// synthetic {"handler":"forward_auth"} module that no Caddy registers) BEFORE the
// backend reverse_proxy — accepted by the now-faithful fake, with the policy round-
// tripping on read-back as Upstream.Auth and the backend read correctly behind the gate.
func TestAuth_GranularRendersCanonicalForwardAuth(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(authSeed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply(), homeAuthRef())
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatal(err)
	}
	if got := cs.Edge.AddRoutes[0].Upstream.Auth; got != "authelia" {
		t.Fatalf("plan should carry the auth policy, got %q", got)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("apply must be ACCEPTED by the faithful fake (valid JSON), got: %v", err)
	}

	raw := fake.CurrentJSON()
	for _, must := range []string{
		`"handler":"vars"`, `"crenel_policy":"authelia"`, // the policy marker
		`"handle_response"`, `authelia:9080`, // the canonical gate
		`/api/verify?rd=https://auth.example.com`, `Remote-User`, // operator-declared internals
		`10.0.0.5:3000`, // the backend, intact behind the gate
	} {
		if !strings.Contains(raw, must) {
			t.Fatalf("rendered config missing %q:\n%s", must, raw)
		}
	}
	// The invalid synthetic handler must NEVER appear again.
	if strings.Contains(raw, `"handler":"forward_auth"`) {
		t.Fatalf("must not emit the synthetic forward_auth JSON handler:\n%s", raw)
	}

	// Read-back: the policy round-trips, the backend (not the authorizer) is the
	// service upstream, deny holds.
	after, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !after.DenyCatchAllPresent {
		t.Fatal("default-deny must still hold")
	}
	r := routeFor(after, "grafana.example.com")
	if r == nil {
		t.Fatal("grafana route missing after apply")
	}
	if r.Upstream.Auth != "authelia" {
		t.Errorf("auth policy should round-trip, got %q", r.Upstream.Auth)
	}
	if r.Upstream.Address != "10.0.0.5:3000" {
		t.Errorf("backend should be intact behind auth (not the authorizer), got %q", r.Upstream.Address)
	}
	if !r.Managed {
		t.Error("crenel-rendered route should be managed")
	}
}

// TestAuth_GranularVerbatimHandlerBlob proves the purest by-reference escape hatch: an
// operator-provided handler JSON blob is inserted VERBATIM as the gate (crenel owns none
// of the provider's internals), accepted by the faithful fake, with the policy name
// round-tripping off the marker.
func TestAuth_GranularVerbatimHandlerBlob(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(authSeed); err != nil {
		t.Fatal(err)
	}
	// A known-good gate the operator pasted from their live config (valid Caddy modules).
	blob := `{"handler":"reverse_proxy","upstreams":[{"dial":"authelia:9080"}],` +
		`"handle_response":[{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"vars"}]}]}]}`
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply(),
		caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {Handler: []byte(blob)}}))
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(op, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("verbatim blob must be accepted by the faithful fake, got: %v", err)
	}
	after, _ := d.ReadLiveState(ctx)
	r := routeFor(after, "grafana.example.com")
	if r == nil || r.Upstream.Auth != "authelia" || r.Upstream.Address != "10.0.0.5:3000" {
		t.Fatalf("verbatim-gated route should round-trip auth + backend, got %+v", r)
	}
}

// TestAuth_GranularSnippetOnlyRefused proves the renderer never emits invalid JSON for a
// snippet-only / default policy: with no caddy_forward_auth endpoint or caddy_handler_json
// blob, the admin API has no representation of a Caddyfile `import`, so the granular path
// REFUSES loudly at Plan (the failure the live trial would otherwise hit) — directing the
// operator to the renderable reference. The snippet still works on the persistence path.
func TestAuth_GranularSnippetOnlyRefused(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(authSeed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply()) // no WithAuthPolicies
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(context.Background())
	_, err := d.Plan(op, live)
	if err == nil {
		t.Fatal("granular auth with only a default snippet must refuse, not emit invalid JSON")
	}
	for _, must := range []string{"caddy_handler_json", "caddy_forward_auth", "persistence"} {
		if !strings.Contains(err.Error(), must) {
			t.Errorf("refusal should guide the operator (missing %q): %v", must, err)
		}
	}
}

// TestAuth_ForwardAuthWithoutVerifyURIRefused proves the TRIAL-FIX-502 guard: a
// forward-auth policy that sets an authorizer endpoint (caddy_forward_auth) but NO verify
// URI is REFUSED at Plan with a SPECIFIC error — not the generic "no renderable reference"
// (which would misleadingly tell an operator who DID set caddy_forward_auth to set it). The
// under-configured gate is exactly what produced the live 502 (authorizer receives the app
// path, not its verify endpoint). This is fail-CLOSED: an incomplete policy never applies.
func TestAuth_ForwardAuthWithoutVerifyURIRefused(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(authSeed); err != nil {
		t.Fatal(err)
	}
	// The live trial's exact policy: authorizer set, verify URI + copy-headers absent.
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply(),
		caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {ForwardAuth: "authelia:9091"}}))
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(context.Background())
	_, err := d.Plan(op, live)
	if err == nil {
		t.Fatal("forward-auth policy with no verify URI must refuse, not render a footgun gate")
	}
	// Specific guidance: names the verify-URI key and the escape hatch, NOT the generic
	// "no renderable reference" phrasing.
	for _, must := range []string{"caddy_forward_auth_verify_uri", "verify endpoint", "caddy_handler_json"} {
		if !strings.Contains(err.Error(), must) {
			t.Errorf("refusal must be specific (missing %q): %v", must, err)
		}
	}
	if strings.Contains(err.Error(), "no renderable Caddy reference") {
		t.Errorf("must not fall back to the generic snippet-only error: %v", err)
	}
}

// TestAuth_RequiresGranular proves crenel refuses to attach a policy on the
// full-load path (which cannot carry the operator's auth snippet) — loud, not a
// silent drop. Mirrors the layer4 capability gate.
func TestAuth_RequiresGranular(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(authSeed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver()) // NOT granular
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(context.Background())
	if _, err := d.Plan(op, live); err == nil || !strings.Contains(err.Error(), "granular") {
		t.Fatalf("auth without granular must refuse loudly, got %v", err)
	}
}

// TestAuth_RecognizesBrownfieldAuth proves read-only recognition: a hand-built
// route with a stock `authentication` handler surfaces as auth "(detected)" without
// being rewritten.
func TestAuth_RecognizesBrownfieldAuth(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["secure.example.com"]}],"handle":[
			{"handler":"authentication","providers":{"http_basic":{}}},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.8:80"}]}
		]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := routeFor(live, "secure.example.com")
	if r == nil || r.Upstream.Auth != model.AuthDetected {
		t.Fatalf("brownfield auth should be recognized as %q, got %+v", model.AuthDetected, r)
	}
}

// TestAuth_PersistEmitsImportSnippet proves on-disk persistence renders the
// canonical Caddyfile auth-by-reference form (`import <snippet>`) for a managed
// route carrying a forward-auth policy — the operator owns the snippet.
func TestAuth_PersistEmitsImportSnippet(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte("{\n\tadmin localhost:2019\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	// A managed grafana route gated by crenel's forward_auth reference (policy=authelia).
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[
			{"handler":"forward_auth","crenel_policy":"authelia","upstreams":[{"dial":"authelia:9080"}]},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	cli := &recordCLI{}
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}),
		caddy.WithGranularApply(), caddy.WithPersistPath(caddyfilePath), caddy.WithCaddyCLI(cli),
		caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {Import: "authelia"}}))

	if err := d.Persist(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got := string(mustReadFile(t, caddyfilePath))
	if !strings.Contains(got, "import authelia") {
		t.Fatalf("persisted Caddyfile must reference the auth snippet via import:\n%s", got)
	}
	if !strings.Contains(got, "reverse_proxy 10.0.0.5:3000") {
		t.Errorf("backend should still be persisted behind auth:\n%s", got)
	}
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// routeFor returns a pointer to the route for host, or nil.
func routeFor(live model.LiveEdgeState, host string) *model.Route {
	for i := range live.Routes {
		if strings.EqualFold(live.Routes[i].Host, host) {
			return &live.Routes[i]
		}
	}
	return nil
}
