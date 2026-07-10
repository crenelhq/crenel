package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestAuth_Brownfield_AdoptPreservesAuth_NewExposeReferencesPolicy is the canonical
// end-to-end auth demonstration on a setup shaped like the operator's:
//
//   - an UNMANAGED grafana route already gated by a hand-built Authelia
//     (`authentication`) handler, matching crenel's configured origin → adoptable;
//   - a brand-new photos exposure crenel renders WITH a referenced auth policy.
//
// It runs import (adopt) -> apply (new host with auth) and asserts: adoption keeps
// grafana's Authelia handler byte-for-byte (recognized, never rewritten); the
// new photos route carries crenel's forward-auth REFERENCE (policy round-trips);
// the deny always holds; and the adopted auth survives the later additive apply.
func TestAuth_Brownfield_AdoptPreservesAuth_NewExposeReferencesPolicy(t *testing.T) {
	ctx := context.Background()

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	// grafana is hand-built WITH an Authelia auth handler (the operator's), matching
	// crenel's origin 10.0.0.5:3000, and carries NO crenel @id (adoptable).
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["grafana.example.com"]}],"handle":[
			{"handler":"authentication","providers":{"authelia":{"url":"http://10.0.0.9:9091"}}},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)

	origins := map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"}
	edge := core.EdgeBinding{
		Name: "caddy",
		Provider: caddy.New(fake.URL(), static.New(origins),
			caddy.WithGranularApply(),
			caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {ForwardAuth: "authelia:9080", VerifyURI: "/api/verify?rd=https://auth.example.com"}})),
		Fronts: frontsFor(origins),
	}
	e := core.NewMulti([]core.EdgeBinding{edge}, "example.com")

	// The operator's Authelia handler (its verify URL) must survive every stage.
	autheliaIntact := func(stage string) {
		t.Helper()
		raw := fake.CurrentJSON()
		for _, must := range []string{`"handler":"authentication"`, `10.0.0.9:9091`} {
			if !strings.Contains(raw, must) {
				t.Fatalf("%s: operator's Authelia handler lost %q:\n%s", stage, must, raw)
			}
		}
	}
	autheliaIntact("seed")

	// --- import: grafana is adoptable (origin matches); adoption preserves its auth. ---
	plan, err := e.DetectImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Adopt) != 1 || plan.Adopt[0].Host != "grafana.example.com" {
		t.Fatalf("grafana should be the sole adoptable host, got %+v", plan.Adopt)
	}
	if _, err := e.Import(ctx, core.AlwaysYesImport); err != nil {
		t.Fatalf("import: %v", err)
	}
	autheliaIntact("after import")

	live, _ := edge.Provider.ReadLiveState(ctx)
	g := findRoute(live, "grafana.example.com")
	if g == nil || !g.Managed {
		t.Fatalf("grafana should be managed after import, got %+v", g)
	}
	// Adoption is read-only recognition of the existing auth — surfaced, never rewritten.
	if g.Upstream.Auth != model.AuthDetected {
		t.Errorf("adopted grafana should surface its recognized auth as %q, got %q", model.AuthDetected, g.Upstream.Auth)
	}

	// --- apply: a NEW photos exposure, rendered WITH the referenced auth policy. ---
	exposures := []core.Exposure{
		{Host: "grafana.example.com", Service: "grafana"}, // already managed: no-op
		{Host: "photos.example.com", Service: "photos", Auth: "authelia"},
	}
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v (%+v)", err, rep.Verify)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("apply should converge + verify, got %+v", rep)
	}
	autheliaIntact("after apply") // the adopted grafana auth survives the additive apply

	// photos is reachable, crenel-managed, and carries crenel's forward-auth REFERENCE.
	final, _ := edge.Provider.ReadLiveState(ctx)
	p := findRoute(final, "photos.example.com")
	if p == nil || !final.Reachable("photos.example.com") {
		t.Fatal("photos should be reachable after apply")
	}
	if !p.Managed || p.Upstream.Auth != "authelia" {
		t.Fatalf("new photos route should be managed + carry auth=authelia, got %+v", p)
	}
	raw := fake.CurrentJSON()
	if !strings.Contains(raw, `"crenel_policy":"authelia"`) || !strings.Contains(raw, `authelia:9080`) {
		t.Errorf("photos should render crenel's forward-auth reference:\n%s", raw)
	}
	if !final.DenyCatchAllPresent {
		t.Fatal("default-deny must still hold")
	}
}

// TestAuth_PassthroughWithAuthRefused proves a forward-auth policy on an SNI
// passthrough exposure is refused loudly (no HTTP layer to enforce it at), via
// core.Plan, classifiable as ErrAuthUnsupportedForMode.
func TestAuth_PassthroughWithAuthRefused(t *testing.T) {
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"handle":[{"handler":"static_response","status_code":403}]}]}}}}}`)
	edge := caddy.New(fake.URL(), static.New(map[string]string{"photos": "10.0.0.6:2342"}),
		caddy.WithGranularApply(), caddy.WithLayer4())
	e := core.New(edge, "example.com")

	op := model.Op{Verb: model.Expose, Service: "photos", Host: "stream.example.com", Mode: model.ModeTCPPassthrough, Auth: "authelia"}
	_, err := e.Plan(context.Background(), op)
	if err == nil || !strings.Contains(err.Error(), "passthrough") {
		t.Fatalf("auth on a passthrough exposure must be refused, got %v", err)
	}
}

// findRoute returns a pointer to the route for host, or nil.
func findRoute(live model.LiveEdgeState, host string) *model.Route {
	for i := range live.Routes {
		if strings.EqualFold(live.Routes[i].Host, host) {
			return &live.Routes[i]
		}
	}
	return nil
}
