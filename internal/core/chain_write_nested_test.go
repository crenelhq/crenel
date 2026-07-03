package core_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// frontNestedSeed mirrors the real VPS FRONT: it routes the *.homelab.example zone
// through a wildcard subroute (per-zone deny inside), serving nothing itself.
const frontNestedSeed = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}]}
]}}}}}`

// homeNestedSeed mirrors the real HOME edge: the *.homelab.example zone is a wildcard
// subroute holding per-host routes (one pre-existing unmanaged leaf) + a per-zone deny.
const homeNestedSeed = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
		{"match":[{"host":["dash.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.50:80"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}]}
]}}}}}`

// normJSON re-marshals a config through a sorted-key form for stable byte comparison.
func normJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// zoneStructure parses a fake's config into (top-level route count, inner-route host
// list of the *.homelab.example wildcard subroute) — so a chain test can assert WHERE a
// route landed: nested inside the wildcard subroute vs flat at the top level.
func zoneStructure(t *testing.T, fake *caddyfake.Fake) (top int, innerHosts []string) {
	t.Helper()
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
						Handle []struct {
							Handler string `json:"handler"`
							Routes  []struct {
								Match []struct {
									Host []string `json:"host"`
								} `json:"match"`
							} `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(fake.CurrentJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.Apps.HTTP.Servers["srv0"]
	top = len(srv.Routes)
	for _, r := range srv.Routes {
		isShrimp := len(r.Match) > 0 && len(r.Match[0].Host) > 0 && r.Match[0].Host[0] == "*.homelab.example"
		if !isShrimp {
			continue
		}
		for _, h := range r.Handle {
			if h.Handler != "subroute" {
				continue
			}
			for _, inner := range h.Routes {
				host := ""
				if len(inner.Match) > 0 && len(inner.Match[0].Host) > 0 {
					host = inner.Match[0].Host[0]
				}
				innerHosts = append(innerHosts, host)
			}
		}
	}
	return top, innerHosts
}

// chainWriteEngineNested wires the SAME front→home chain as chainWriteEngine, but both
// fakes are seeded with the REAL wildcard-subroute shape (per-host routing lives inside
// a *.homelab.example subroute), so the cross-chain write must NEST on both edges.
func chainWriteEngineNested(t *testing.T, log *[]string) (*core.Engine, *caddyfake.Fake, *caddyfake.Fake, *dnscontrolfake.Shell) {
	t.Helper()

	frontFake := caddyfake.New()
	t.Cleanup(frontFake.Close)
	if err := frontFake.SeedJSON(frontNestedSeed); err != nil {
		t.Fatal(err)
	}
	front := core.EdgeBinding{
		Name:              "vps",
		Provider:          labelEdge{EdgeProvider: caddy.New(frontFake.URL(), static.New(map[string]string{}), caddy.WithGranularApply()), label: "vps", log: log},
		Fronts:            frontsFor(map[string]string{}),
		DownstreamEdge:    "home",
		DownstreamAddress: "10.0.0.13:443",
	}

	homeOrigins := map[string]string{"vault": "10.0.0.7:8200"}
	homeFake := caddyfake.New()
	t.Cleanup(homeFake.Close)
	if err := homeFake.SeedJSON(homeNestedSeed); err != nil {
		t.Fatal(err)
	}
	home := core.EdgeBinding{
		Name:     "home",
		Provider: labelEdge{EdgeProvider: caddy.New(homeFake.URL(), static.New(homeOrigins), caddy.WithGranularApply(), homeAuthRef()), label: "home", log: log},
		Fronts:   frontsFor(homeOrigins),
	}

	pubSh := dnscontrolfake.New("homelab.example")
	public := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "homelab.example", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh,
	}), log: log}

	e := core.NewMulti([]core.EdgeBinding{front, home}, "homelab.example", public)
	return e, frontFake, homeFake, pubSh
}

// TestChainWrite_NestsAcrossWildcardSubrouteChain is the end-to-end proof that the
// write-side nesting fix carries through the WHOLE cross-chain transaction on the real
// edge shape: a single `expose vault --auth authelia` on a chain whose BOTH edges route
// the zone via a *.homelab.example wildcard subroute lands —
//   - the home TERMINAL route (reverse_proxy → real origin + the authelia reference)
//     NESTED inside home's *.homelab.example subroute, and
//   - the front FORWARD route (reverse_proxy → downstream, no auth) NESTED inside
//     front's *.homelab.example subroute —
// each at the correct depth (top-level count unchanged on both), applied downstream →
// front → public-DNS, read-back-verified at depth. Unexpose tears both nested routes
// out → byte-for-byte restore. This is the fixture analog of the live trial.
func TestChainWrite_NestsAcrossWildcardSubrouteChain(t *testing.T) {
	var log []string
	e, frontFake, homeFake, pubSh := chainWriteEngineNested(t, &log)
	ctx := context.Background()

	frontBefore := frontFake.CurrentJSON()
	homeBefore := homeFake.CurrentJSON()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("nested chain expose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified, got %+v\nverify=%+v", rep, rep.Verify)
	}

	// Order unchanged: downstream (home) → front (vps) → public DNS LAST.
	if want := []string{"edge:home", "edge:vps", "dns/public"}; !reflect.DeepEqual(log, want) {
		t.Errorf("chain expose order: got %v, want %v", log, want)
	}

	// HOME: vault landed NESTED inside the *.homelab.example subroute (top-level
	// unchanged at 1), at index 0, alongside the pre-existing dash leaf + deny.
	homeTop, homeInner := zoneStructure(t, homeFake)
	if homeTop != 1 {
		t.Errorf("home top-level routes must stay 1 (no flat sibling), got %d", homeTop)
	}
	if len(homeInner) != 3 || homeInner[0] != "vault.homelab.example" {
		t.Errorf("home *.homelab.example subroute should be [vault, dash, (deny)] with vault first, got %v", homeInner)
	}
	hv, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example")
	if !ok || hv.Upstream.Address != "10.0.0.7:8200" || hv.Upstream.Auth != "authelia" {
		t.Errorf("home terminal route should serve the real origin WITH authelia at depth, got %+v", hv)
	}
	if _, ok := liveRoute(liveOf(t, homeFake), "dash.homelab.example"); !ok {
		t.Error("pre-existing nested dash leaf must survive the additive nested insert")
	}

	// FRONT: the forward route landed NESTED inside front's *.homelab.example subroute
	// (top-level unchanged at 1), carrying NO auth, dialing the downstream edge.
	frontTop, frontInner := zoneStructure(t, frontFake)
	if frontTop != 1 {
		t.Errorf("front top-level routes must stay 1 (no flat sibling), got %d", frontTop)
	}
	if len(frontInner) != 2 || frontInner[0] != "vault.homelab.example" {
		t.Errorf("front *.homelab.example subroute should be [vault-forward, (deny)] with vault first, got %v", frontInner)
	}
	fv, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example")
	if !ok || fv.Upstream.Address != "10.0.0.13:443" || fv.Upstream.Auth != "" {
		t.Errorf("front forward route should dial downstream with NO auth at depth, got %+v", fv)
	}

	if pubSh.LiveCount() != 1 {
		t.Errorf("expected 1 public DNS record, got %d", pubSh.LiveCount())
	}

	// Unexpose reverses across the chain, removing BOTH nested routes by @id at depth.
	log = log[:0]
	if _, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "vault"), core.AlwaysYes); err != nil {
		t.Fatalf("nested chain unexpose failed: %v", err)
	}
	if normJSON(t, frontFake.CurrentJSON()) != normJSON(t, frontBefore) {
		t.Errorf("front not restored byte-for-byte after nested unexpose\nbefore: %s\nafter: %s", frontBefore, frontFake.CurrentJSON())
	}
	if normJSON(t, homeFake.CurrentJSON()) != normJSON(t, homeBefore) {
		t.Errorf("home not restored byte-for-byte after nested unexpose\nbefore: %s\nafter: %s", homeBefore, homeFake.CurrentJSON())
	}
	if pubSh.LiveCount() != 0 {
		t.Errorf("public DNS record should be removed, got %d", pubSh.LiveCount())
	}
}

// TestChainWrite_ValidAuthGateNestedOnBothEdges is the JSON-level proof the live trial
// re-run depends on: a cross-chain `expose vault --auth authelia` lands, on the HOME
// terminal edge, the VALID Caddy auth gate (a vars policy marker + the canonical
// reverse_proxy+handle_response expansion of authelia:9080 + the operator-declared
// verify URI) NESTED inside the *.homelab.example subroute ahead of the backend — accepted
// by the now-faithful fake (which rejects an unknown module) and read-back-verified —
// while the FRONT relay carries a plain forward with NO auth handler. This is exactly
// what the home Caddy REJECTED before the renderer fix.
func TestChainWrite_ValidAuthGateNestedOnBothEdges(t *testing.T) {
	var log []string
	e, frontFake, homeFake, _ := chainWriteEngineNested(t, &log)
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("chain expose --auth authelia failed (must be ACCEPTED by the faithful fakes): %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + read-back-verified end-to-end, got %+v\nverify=%+v", rep, rep.Verify)
	}

	// HOME: vault landed NESTED (top-level unchanged), and its JSON carries the VALID
	// gate — the marker, the canonical handle_response gate, the authorizer endpoint, the
	// operator-declared verify URI, and the real backend behind it.
	homeTop, homeInner := zoneStructure(t, homeFake)
	if homeTop != 1 || len(homeInner) == 0 || homeInner[0] != "vault.homelab.example" {
		t.Fatalf("vault must nest first inside the home *.homelab.example subroute, got top=%d inner=%v", homeTop, homeInner)
	}
	homeJSON := homeFake.CurrentJSON()
	for _, must := range []string{
		`"handler":"vars"`, `"crenel_policy":"authelia"`, // policy marker (round-trips the name)
		`"handle_response"`, `authelia:9080`, // the canonical forward-auth gate
		`/api/verify?rd=https://auth.homelab.example`, // operator-declared verify URI
		`10.0.0.7:8200`,                              // the real backend, behind the gate
	} {
		if !strings.Contains(homeJSON, must) {
			t.Errorf("home edge JSON missing %q (valid nested gate):\n%s", must, homeJSON)
		}
	}
	if strings.Contains(homeJSON, `"handler":"forward_auth"`) {
		t.Errorf("home edge must NOT carry the synthetic forward_auth handler:\n%s", homeJSON)
	}

	// FRONT: a plain forward to the downstream edge, NO auth gate at all.
	frontJSON := frontFake.CurrentJSON()
	if strings.Contains(frontJSON, "handle_response") || strings.Contains(frontJSON, "crenel_policy") {
		t.Errorf("front relay must carry NO auth handler:\n%s", frontJSON)
	}
	fv, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example")
	if !ok || fv.Upstream.Address != "10.0.0.13:443" || fv.Upstream.Auth != "" {
		t.Errorf("front forward route should dial downstream with no auth, got %+v", fv)
	}
}

// TestChainWrite_AuthNoneNoGateRendered proves `--auth none` (the explicit opt-out)
// behaves on the chain: the host publishes, read-back-verifies, and NO auth handler is
// rendered on either edge (no handle_response, no marker) — distinct from a real policy.
func TestChainWrite_AuthNoneNoGateRendered(t *testing.T) {
	var log []string
	e, frontFake, homeFake, pubSh := chainWriteEngineNested(t, &log)
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = model.AuthNone
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("chain expose --auth none failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified for --auth none, got %+v", rep)
	}
	if pubSh.LiveCount() != 1 {
		t.Errorf("--auth none should still publish the host, got %d DNS records", pubSh.LiveCount())
	}
	for _, j := range []string{homeFake.CurrentJSON(), frontFake.CurrentJSON()} {
		if strings.Contains(j, "handle_response") || strings.Contains(j, "crenel_policy") {
			t.Errorf("--auth none must render NO auth handler:\n%s", j)
		}
	}
	hv, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example")
	if !ok || hv.Upstream.Auth != "" {
		t.Errorf("--auth none must read back as no auth on the terminal edge, got %+v", hv)
	}
}
