package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/crenelhq/crenel/internal/ports"
)

// labelEdge wraps an edge provider and records "edge:<label>" into a shared log on
// Apply, so a chain transaction test can assert the cross-edge apply ORDER (the
// downstream edge must be brought up before the front, public DNS last on expose).
type labelEdge struct {
	ports.EdgeProvider
	label string
	log   *[]string
}

func (l labelEdge) Apply(ctx context.Context, cs model.ChangeSet) error {
	*l.log = append(*l.log, "edge:"+l.label)
	return l.EdgeProvider.Apply(ctx, cs)
}

const chainDeny = ":443 {\n\trespond 403\n}\n"

// homeAuthRef configures the authelia policy as the real home edge expresses it — the
// canonical forward_auth expansion (authorizer endpoint + verify URI + the four
// Remote-* copy headers) — so the granular path renders the EXACT
// reverse_proxy+handle_response gate the live home Caddy accepts (and the now-faithful
// caddyfake requires). The terminal (home) edge attaches auth; the front does not.
func homeAuthRef() caddy.Option {
	return caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {
		ForwardAuth: "authelia:9080",
		VerifyURI:   "/api/verify?rd=https://auth.homelab.example",
		CopyHeaders: []string{"Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email"},
	}})
}

// chainWriteEngine wires a two-edge CHAIN against REAL caddy fakes mirroring the maintainer's
// front→home shape: a public VPS FRONT (empty origins — it serves nothing itself,
// only relays) that names home as its downstream, and a downstream HOME edge that
// resolves the real per-host backends and is where forward-auth attaches. DNS is an
// internal + public dnscontrol fake. Every provider is wrapped to record apply order
// into log. Both edges use granular apply (the production path; required for auth).
func chainWriteEngine(t *testing.T, log *[]string) (*core.Engine, *caddyfake.Fake, *caddyfake.Fake, *dnscontrolfake.Shell, *dnscontrolfake.Shell) {
	t.Helper()

	frontFake := caddyfake.New()
	t.Cleanup(frontFake.Close)
	frontFake.SeedCaddyfile(chainDeny)
	front := core.EdgeBinding{
		Name:              "vps",
		Provider:          labelEdge{EdgeProvider: caddy.New(frontFake.URL(), static.New(map[string]string{}), caddy.WithGranularApply()), label: "vps", log: log},
		Fronts:            frontsFor(map[string]string{}), // pure front: fronts no service itself
		DownstreamEdge:    "home",
		DownstreamAddress: "10.0.0.13:443",
	}

	homeOrigins := map[string]string{"vault": "10.0.0.7:8200", "books": "10.0.0.9:80"}
	homeFake := caddyfake.New()
	t.Cleanup(homeFake.Close)
	homeFake.SeedCaddyfile(chainDeny)
	home := core.EdgeBinding{
		Name:     "home",
		Provider: labelEdge{EdgeProvider: caddy.New(homeFake.URL(), static.New(homeOrigins), caddy.WithGranularApply(), homeAuthRef()), label: "home", log: log},
		Fronts:   frontsFor(homeOrigins),
	}

	inSh := dnscontrolfake.New("homelab.example")
	pubSh := dnscontrolfake.New("homelab.example")
	internal := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "homelab.example", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: inSh,
	}), log: log}
	public := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "homelab.example", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh,
	}), log: log}

	e := core.NewMulti([]core.EdgeBinding{front, home}, "homelab.example", internal, public)
	return e, frontFake, homeFake, inSh, pubSh
}

// liveOf reads a fake's live state through a throwaway read-only caddy driver (no
// chain overlay) so a test can assert the RAW route each edge actually holds.
func liveOf(t *testing.T, fake *caddyfake.Fake) model.LiveEdgeState {
	t.Helper()
	live, err := caddy.New(fake.URL(), static.New(nil)).ReadLiveState(context.Background())
	if err != nil {
		t.Fatalf("read live: %v", err)
	}
	return live
}

func liveRoute(live model.LiveEdgeState, host string) (model.Route, bool) {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r, true
		}
	}
	return model.Route{}, false
}

// TestChainWrite_ExposeLandsAcrossChainInOrder is the headline P4-write test: a single
// `expose vault --auth authelia` on a CHAIN lands the coordinated entries across the
// downstream edge (real backend + auth), the front edge (a forward, no auth), AND DNS
// as ONE transaction — applied in the safe order (downstream → front → public DNS) and
// read-back-verified.
func TestChainWrite_ExposeLandsAcrossChainInOrder(t *testing.T) {
	var log []string
	e, frontFake, homeFake, _, pubSh := chainWriteEngine(t, &log)
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("chain expose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified across the chain, got %+v\nverify=%+v", rep, rep.Verify)
	}

	// ORDERING: downstream (home) is brought up BEFORE the front (vps); the public DNS
	// record is announced LAST — so the world only learns the name once both edges serve.
	want := []string{"edge:home", "edge:vps", "dns/internal", "dns/public"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("chain expose order: got %v, want %v", log, want)
	}

	// DOWNSTREAM (home) serves the REAL backend and carries the auth policy.
	homeVault, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example")
	if !ok {
		t.Fatal("vault missing from the downstream (home) edge")
	}
	if homeVault.Upstream.Address != "10.0.0.7:8200" {
		t.Errorf("home vault should dial the real origin, got %q", homeVault.Upstream.Address)
	}
	if homeVault.Upstream.Auth != "authelia" {
		t.Errorf("auth must attach at the downstream edge that SERVES the host, got %q", homeVault.Upstream.Auth)
	}

	// FRONT (vps) FORWARDS to the downstream edge and carries NO auth (it is a relay).
	frontVault, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example")
	if !ok {
		t.Fatal("vault missing from the front (vps) edge")
	}
	if frontVault.Upstream.Address != "10.0.0.13:443" {
		t.Errorf("front vault should FORWARD to the downstream edge, got %q", frontVault.Upstream.Address)
	}
	if frontVault.Upstream.Auth != "" {
		t.Errorf("front forward route must carry no auth (auth lives downstream), got %q", frontVault.Upstream.Auth)
	}
	// FRONT forward dials an HTTPS (:443) downstream, so it must re-originate TLS —
	// read back carrying UpstreamTLS (TRIAL-FIX-4); the home terminal dials a plain
	// origin (:8200) and must NOT.
	if !frontVault.Upstream.UpstreamTLS {
		t.Error("front forward to a :443 downstream must read back with UpstreamTLS=true")
	}
	if homeVault.Upstream.UpstreamTLS {
		t.Error("home terminal dials a plain origin and must read back with UpstreamTLS=false")
	}

	// The public name was actually published.
	if pubSh.LiveCount() != 1 {
		t.Errorf("expected 1 public DNS record, got %d", pubSh.LiveCount())
	}
	if len(rep.NewPublic) != 1 || rep.NewPublic[0] != "vault.homelab.example" {
		t.Errorf("NewPublic should flag the chain host, got %v", rep.NewPublic)
	}

	// READ-MODEL CONSISTENCY: status now follows the freshly-written chain through to
	// the real downstream destination + observed auth.
	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vps, _ := statusEdge(st, "vps")
	sv, _ := routeByHost(vps, "vault.homelab.example")
	if sv.Chain == nil || !sv.Chain.Resolved || sv.Chain.DownstreamAddress != "10.0.0.7:8200" || sv.Chain.DownstreamAuth != "authelia" {
		t.Errorf("status should resolve the written chain through to home, got %+v", sv.Chain)
	}
}

// TestChainWrite_IdempotentReExposeIsNoOp proves a chain expose of an already-exposed
// host is a converge no-op on BOTH edges, not a duplicate.
func TestChainWrite_IdempotentReExposeIsNoOp(t *testing.T) {
	var log []string
	e, _, _, _, _ := chainWriteEngine(t, &log)
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	if _, err := e.Apply(ctx, op, core.AlwaysYes); err != nil {
		t.Fatalf("first expose failed: %v", err)
	}

	log = log[:0]
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("re-expose failed: %v", err)
	}
	if !rep.NoOp || rep.Applied {
		t.Errorf("a re-expose of a fully-present chain must be a no-op, got %+v", rep)
	}
	if len(log) != 0 {
		t.Errorf("a no-op chain expose must apply nothing, got %v", log)
	}
}

// TestChainWrite_GeneratorDownstreamRefused proves the gate spans BOTH edges: a chain
// write whose downstream edge is generator-owned is refused (the front forward would
// point at a route crenel must not manage).
func TestChainWrite_GeneratorDownstreamRefused(t *testing.T) {
	front := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true}}
	home := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true, Generator: "caddy-docker-proxy"}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: func(string) bool { return false }, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13:443"},
		{Name: "home", Provider: home, Fronts: func(string) bool { return true }},
	}, "homelab.example")

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	_, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if !errors.Is(err, core.ErrRefuseToManage) {
		t.Fatalf("a generator-owned downstream must refuse the chain write, got %v", err)
	}
	if !strings.Contains(err.Error(), "caddy-docker-proxy") {
		t.Errorf("refusal should name the generator, got %v", err)
	}
}

// TestChainWrite_ForeignDownstreamHostRefused proves the cross-edge gate catches a
// pre-existing FOREIGN route on the downstream even when that edge's planned change
// converges to a no-op (host already present) — the case the standard per-edge gate
// would miss because the empty change is skipped.
func TestChainWrite_ForeignDownstreamHostRefused(t *testing.T) {
	foreign := model.Route{Host: "vault.homelab.example", Ownership: model.OwnForeign,
		Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.7:8200"}}
	front := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true}}
	home := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{foreign}}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: func(string) bool { return false }, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13:443"},
		{Name: "home", Provider: home, Fronts: func(string) bool { return true }},
	}, "homelab.example")

	_, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "vault"), core.AlwaysYes)
	if !errors.Is(err, core.ErrRefuseToManage) {
		t.Fatalf("a foreign downstream host must refuse the chain write, got %v", err)
	}
	if !strings.Contains(err.Error(), "vault.homelab.example") {
		t.Errorf("refusal should name the host, got %v", err)
	}
}

// memEdge is a MUTABLE in-memory edge double for chain-write rollback tests: it
// applies changes to its own live state (so read-back-verify observes them), records
// apply order, resolves terminal origins from an origins map, and can INJECT failures
// — an apply error for a host, or a SILENT auth drop — to exercise cross-chain rollback
// and the auth read-back. Precise control the real fakes don't give per-step.
type memEdge struct {
	name         string
	origins      map[string]string // service -> addr (terminal); empty => never terminal
	live         *model.LiveEdgeState
	log          *[]string
	failHost     string // Apply of a route for this host returns an error (injected)
	dropAuthHost string // Apply attaches the route but with auth stripped (silent loss)
	dropTLSHost  string // Apply attaches the route but with upstream TLS stripped (the old bare-HTTP forward bug)
}

func (m *memEdge) Name() string                   { return m.name }
func (m *memEdge) Validate(context.Context) error { return nil }

func (m *memEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	cp := *m.live
	cp.Routes = append([]model.Route(nil), m.live.Routes...)
	return cp, nil
}

func (m *memEdge) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	switch op.Verb {
	case model.Expose:
		if live.HasHost(op.Host) {
			return cs, nil
		}
		addr, ok := m.origins[op.Service]
		if !ok {
			return cs, fmt.Errorf("memEdge %s: no origin for service %q", m.name, op.Service)
		}
		cs.Edge.AddRoutes = []model.Route{{Host: op.Host, Upstream: model.Upstream{
			Kind: model.ForwardToOrigin, Mode: op.Mode, Address: addr, ServerName: op.Host, Auth: op.Auth}}}
	case model.Unexpose:
		if live.HasHost(op.Host) {
			cs.Edge.RemoveHosts = []string{op.Host}
		}
	}
	return cs, nil
}

func (m *memEdge) Apply(_ context.Context, cs model.ChangeSet) error {
	if m.log != nil {
		*m.log = append(*m.log, "edge:"+m.name)
	}
	for _, r := range cs.Edge.AddRoutes {
		if m.failHost != "" && strings.EqualFold(r.Host, m.failHost) {
			return fmt.Errorf("memEdge %s: injected apply failure for %s", m.name, r.Host)
		}
	}
	for _, h := range cs.Edge.RemoveHosts { // removes before adds (mirror a real driver)
		var kept []model.Route
		for _, r := range m.live.Routes {
			if !strings.EqualFold(r.Host, h) {
				kept = append(kept, r)
			}
		}
		m.live.Routes = kept
	}
	for _, r := range cs.Edge.AddRoutes {
		r.Managed, r.Ownership = true, model.OwnCrenel
		if m.dropAuthHost != "" && strings.EqualFold(r.Host, m.dropAuthHost) {
			r.Upstream.Auth = "" // silent auth loss — must fail the auth read-back
		}
		if m.dropTLSHost != "" && strings.EqualFold(r.Host, m.dropTLSHost) {
			r.Upstream.UpstreamTLS = false // the OLD bare-HTTP forward — must fail the upstream-TLS read-back
		}
		m.live.Routes = append(m.live.Routes, r)
	}
	m.live.DenyCatchAllPresent = true
	return nil
}

// memChainEngine wires a two-edge chain over two memEdges (front forwards to home),
// optionally with DNS providers, for precise rollback control.
func memChainEngine(front, home *memEdge, dns ...ports.DNSProvider) *core.Engine {
	return core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: func(string) bool { return false }, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13:443"},
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example", dns...)
}

func newMemChain(log *[]string) (*memEdge, *memEdge) {
	front := &memEdge{name: "vps", live: &model.LiveEdgeState{DenyCatchAllPresent: true}, log: log}
	home := &memEdge{name: "home", origins: map[string]string{"vault": "10.0.0.7:8200"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true}, log: log}
	return front, home
}

func exposeVaultAuth(e *core.Engine) (core.ApplyReport, error) {
	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	return e.Apply(context.Background(), op, core.AlwaysYes)
}

func assertChainTornDown(t *testing.T, front, home *memEdge) {
	t.Helper()
	if home.live.HasHost("vault.homelab.example") {
		t.Errorf("downstream must be rolled back — vault still present on home: %+v", home.live.Routes)
	}
	if front.live.HasHost("vault.homelab.example") {
		t.Errorf("front must be rolled back — vault still present on vps: %+v", front.live.Routes)
	}
}

// TestChainWrite_RollbackOnFrontFailure: the downstream applies first, then the FRONT
// fails — the whole chain rolls back, leaving nothing half-applied on either edge.
func TestChainWrite_RollbackOnFrontFailure(t *testing.T) {
	var log []string
	front, home := newMemChain(&log)
	front.failHost = "vault.homelab.example"
	rep, err := exposeVaultAuth(memChainEngine(front, home))
	if err == nil {
		t.Fatal("expected the chain expose to fail when the front apply fails")
	}
	if !rep.RolledBack {
		t.Errorf("a mid-chain failure must roll back, got %+v", rep)
	}
	assertChainTornDown(t, front, home)
}

// TestChainWrite_RollbackOnDownstreamFailure: the downstream applies FIRST, so a
// downstream failure leaves nothing applied anywhere (the front is never reached).
func TestChainWrite_RollbackOnDownstreamFailure(t *testing.T) {
	var log []string
	front, home := newMemChain(&log)
	home.failHost = "vault.homelab.example"
	_, err := exposeVaultAuth(memChainEngine(front, home))
	if err == nil {
		t.Fatal("expected the chain expose to fail when the downstream apply fails")
	}
	if log[0] != "edge:home" {
		t.Errorf("downstream must be the FIRST step on expose, got order %v", log)
	}
	assertChainTornDown(t, front, home)
}

// TestChainWrite_RollbackOnPublicDNSFailure: both edges apply, then publishing the
// public DNS name LAST fails — the front and downstream both unwind.
func TestChainWrite_RollbackOnPublicDNSFailure(t *testing.T) {
	var log []string
	front, home := newMemChain(&log)
	rep, err := exposeVaultAuth(memChainEngine(front, home, failDNS{scope: model.ScopePublic}))
	if err == nil {
		t.Fatal("expected the chain expose to fail when public DNS fails")
	}
	if !rep.RolledBack {
		t.Errorf("a DNS failure after both edges applied must roll the edges back, got %+v", rep)
	}
	assertChainTornDown(t, front, home)
}

// TestChainWrite_AuthReadBackFailureRollsBack proves the NEW auth read-back closes the
// gap: a downstream that "applies" the route but SILENTLY drops the auth policy fails
// verification and the whole chain rolls back — a protected host is never left exposed
// unprotected while reading green.
func TestChainWrite_AuthReadBackFailureRollsBack(t *testing.T) {
	var log []string
	front, home := newMemChain(&log)
	home.dropAuthHost = "vault.homelab.example"
	rep, err := exposeVaultAuth(memChainEngine(front, home))
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("a dropped downstream auth must fail the read-back with an auth error, got %v", err)
	}
	if !rep.RolledBack {
		t.Errorf("an auth read-back failure must roll back, got %+v", rep)
	}
	assertChainTornDown(t, front, home)
}

// TestChainWrite_ForwardTLSReadBackFailureRollsBack proves the NEW upstream-TLS read-back
// closes the front-leg gap (TRIAL-FIX-4): a FRONT that "applies" the forward but renders
// it as bare HTTP to the HTTPS :443 downstream (the exact pre-fix bug) fails verification
// and the whole chain rolls back — a forward that would 400 at request time is never left
// in place reading green.
func TestChainWrite_ForwardTLSReadBackFailureRollsBack(t *testing.T) {
	var log []string
	front, home := newMemChain(&log)
	front.dropTLSHost = "vault.homelab.example" // simulate the OLD transport-less forward render
	rep, err := exposeVaultAuth(memChainEngine(front, home))
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("a transport-less front forward must fail the read-back with an upstream-TLS error, got %v", err)
	}
	if !rep.RolledBack {
		t.Errorf("an upstream-TLS read-back failure must roll back, got %+v", rep)
	}
	assertChainTornDown(t, front, home)
}

// TestChainWrite_UnexposeReversesAcrossChain proves unexpose tears the chain down in
// the REVERSE order — public DNS first, then the front, then the downstream — and
// leaves nothing behind on either edge or in DNS.
func TestChainWrite_UnexposeReversesAcrossChain(t *testing.T) {
	var log []string
	e, frontFake, homeFake, _, pubSh := chainWriteEngine(t, &log)
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	if _, err := e.Apply(ctx, op, core.AlwaysYes); err != nil {
		t.Fatalf("setup expose failed: %v", err)
	}

	log = log[:0]
	rep, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "vault"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("chain unexpose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified, got %+v", rep)
	}
	// REVERSE order: stop announcing globally first, tear down the public front, then
	// the backend route last.
	want := []string{"dns/public", "dns/internal", "edge:vps", "edge:home"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("chain unexpose order: got %v, want %v", log, want)
	}
	if _, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example"); ok {
		t.Error("vault should be gone from the front edge")
	}
	if _, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example"); ok {
		t.Error("vault should be gone from the downstream edge")
	}
	if pubSh.LiveCount() != 0 {
		t.Errorf("public DNS record should be removed, got %d", pubSh.LiveCount())
	}
}

// TestChainWrite_FrontForwardTLSAndAuthRoundTrips is the end-to-end TRIAL-FIX-4 proof: a
// single `expose vault --auth authelia` on the chain must produce, in ONE verified
// transaction, (a) the TLS-correct FRONT forward — the rendered reverse_proxy carries the
// upstream TLS transport + server_name + Host so it can complete the TLS hop to the
// HTTPS :443 downstream (no more 400) — AND (b) the valid-auth HOME terminal that serves
// the real backend behind the Authelia gate. Both must read back so verify passes, and a
// follow-up unexpose must restore BOTH edges byte-for-byte (zero residue).
func TestChainWrite_FrontForwardTLSAndAuthRoundTrips(t *testing.T) {
	var log []string
	e, frontFake, homeFake, _, _ := chainWriteEngine(t, &log)
	ctx := context.Background()

	frontBefore := canonJSON(t, frontFake.CurrentJSON())
	homeBefore := canonJSON(t, homeFake.CurrentJSON())

	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("chain expose failed: %v", err)
	}
	// verify() now includes the upstream-TLS read-back on the front forward AND the auth
	// read-back on the home terminal — Verified() being true means BOTH landed.
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified (front TLS + home auth), got %+v\nverify=%+v", rep, rep.Verify)
	}

	// (a) FRONT: the rendered forward is byte-faithful to the real VPS HTTPS forward —
	// upstream TLS transport (insecure_skip_verify + SNI placeholder) + preserved Host.
	front := frontFake.CurrentJSON()
	for _, must := range []string{
		`"protocol":"http"`,
		`"insecure_skip_verify":true`,
		`"server_name":"{http.request.host}"`,
		`"Host":["{http.request.host}"]`,
		`"dial":"10.0.0.13:443"`,
	} {
		if !strings.Contains(front, must) {
			t.Errorf("front forward render missing %s\n%s", must, front)
		}
	}
	// The front carries NO auth handler (auth lives downstream).
	if strings.Contains(front, "crenel_policy") || strings.Contains(front, "handle_response") {
		t.Errorf("front forward must carry no auth gate/marker\n%s", front)
	}

	// (b) HOME: the terminal serves the real origin behind the valid Authelia gate.
	home := homeFake.CurrentJSON()
	for _, must := range []string{
		`"dial":"authelia:9080"`, // the gate dials the authorizer
		`"handle_response"`,      // the forward-auth subrequest
		`"dial":"10.0.0.7:8200"`, // the real backend behind the gate
		`"crenel_policy":"authelia"`,
	} {
		if !strings.Contains(home, must) {
			t.Errorf("home terminal render missing %s\n%s", must, home)
		}
	}

	// Unexpose restores BOTH edges byte-for-byte (zero crenel residue on either).
	if _, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "vault"), core.AlwaysYes); err != nil {
		t.Fatalf("chain unexpose failed: %v", err)
	}
	if got := canonJSON(t, frontFake.CurrentJSON()); got != frontBefore {
		t.Errorf("front edge not restored byte-for-byte after unexpose\nbefore: %s\nafter:  %s", frontBefore, got)
	}
	if got := canonJSON(t, homeFake.CurrentJSON()); got != homeBefore {
		t.Errorf("home edge not restored byte-for-byte after unexpose\nbefore: %s\nafter:  %s", homeBefore, got)
	}
}

// canonJSON re-marshals a JSON document through Go's sorted-key encoder so two
// structurally-identical configs compare equal regardless of incidental key ordering.
func canonJSON(t *testing.T, doc string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("canonJSON unmarshal: %v\n%s", err, doc)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("canonJSON marshal: %v", err)
	}
	return string(b)
}

func chainDrift(plan core.ReconcilePlan, kind core.DriftKind, target string) bool {
	for _, d := range plan.Drift {
		if d.Kind == kind && d.Target == target {
			return true
		}
	}
	return false
}

// TestChainReconcile_HealsMissingFrontForward: a chain whose downstream serves the
// host (with auth) but whose FRONT forward route is missing is half-present. `drift`
// reports it and `reconcile` re-adds the front forward in one transaction — fully
// recovering the chain (the downstream auth is preserved, the new front carries none).
func TestChainReconcile_HealsMissingFrontForward(t *testing.T) {
	front := &memEdge{name: "vps", live: &model.LiveEdgeState{DenyCatchAllPresent: true}}
	home := &memEdge{name: "home", origins: map[string]string{"vault": "10.0.0.7:8200"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{{
			Host: "vault.homelab.example", Managed: true, Ownership: model.OwnCrenel,
			Upstream: model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy,
				Address: "10.0.0.7:8200", ServerName: "vault.homelab.example", Auth: "authelia"}}}}}
	e := memChainEngine(front, home)
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !chainDrift(plan, core.DriftMissingRoute, "vps") {
		t.Fatalf("drift should report the missing front forward, got %+v", plan.Drift)
	}

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected converged + verified, got %+v\n%+v", rep, rep.Verify)
	}
	fv, ok := liveRoute(*front.live, "vault.homelab.example")
	if !ok || fv.Upstream.Address != "10.0.0.13:443" || fv.Upstream.Auth != "" {
		t.Errorf("front forward should be re-added (dial downstream, no auth), got %+v", fv)
	}
	hv, _ := liveRoute(*home.live, "vault.homelab.example")
	if hv.Upstream.Auth != "authelia" {
		t.Errorf("downstream auth must be preserved through reconcile, got %q", hv.Upstream.Auth)
	}
}

// TestChainReconcile_HealsMissingDownstream: the dual — the front forwards the host but
// the DOWNSTREAM has no route for it (a dangling forward). `reconcile` re-serves it at
// the downstream, recovering the backend by the downstream's own resolver. (Auth is not
// recoverable from the front relay — there is no stored desired state — so the re-served
// route carries none until the operator re-runs `expose --auth`; audit then flags it.)
func TestChainReconcile_HealsMissingDownstream(t *testing.T) {
	front := &memEdge{name: "vps", live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{{
		Host: "vault.homelab.example", Managed: true, Ownership: model.OwnCrenel,
		Upstream: model.Upstream{Kind: model.DirectBackend, Mode: model.ModeHTTPProxy,
			Address: "10.0.0.13:443", ServerName: "vault.homelab.example"}}}}}
	home := &memEdge{name: "home", origins: map[string]string{"vault": "10.0.0.7:8200"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true}}
	e := memChainEngine(front, home)
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !chainDrift(plan, core.DriftMissingRoute, "home") {
		t.Fatalf("drift should report the missing downstream route, got %+v", plan.Drift)
	}

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected converged + verified, got %+v\n%+v", rep, rep.Verify)
	}
	hv, ok := liveRoute(*home.live, "vault.homelab.example")
	if !ok || hv.Upstream.Address != "10.0.0.7:8200" {
		t.Errorf("downstream should be re-served at its real backend, got %+v", hv)
	}
}

// failDNS is a DNS provider whose Apply always fails — used to inject a public-DNS
// failure as the LAST step of a chain expose.
type failDNS struct{ scope model.Scope }

func (failDNS) Name() string         { return "faildns" }
func (f failDNS) Scope() model.Scope { return f.scope }
func (f failDNS) DesiredRecords(op model.Op) ([]model.Record, error) {
	return []model.Record{{Name: op.Host, Type: "A", Value: "203.0.113.9", Scope: f.scope}}, nil
}
func (f failDNS) Diff(_ context.Context, op model.Op, desired []model.Record) (model.DNSChange, error) {
	return model.DNSChange{Scope: f.scope, Add: desired}, nil
}
func (failDNS) Apply(context.Context, model.DNSChange) error {
	return errors.New("injected DNS failure")
}
func (failDNS) LiveRecords(context.Context) ([]model.Record, error) { return nil, nil }
