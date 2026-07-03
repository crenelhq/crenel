package core_test

import (
	"context"
	"os/exec"
	"reflect"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/drivers/transport"
	"github.com/crenelhq/crenel/internal/model"
)

// shCapableExec reports whether real sh + curl + `base64 -d` are usable, so the
// mixed-transport test can self-skip on a minimal CI without them. The hermetic
// transport-package tests carry the always-on coverage; this test additionally proves
// the WHOLE core chain-write transaction works when an edge is reached over ssh-exec.
func shCapableExec(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		return false
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return false
	}
	o, err := exec.Command("sh", "-c", "printf aGk= | base64 -d").Output()
	return err == nil && string(o) == "hi"
}

// TestChainWrite_MixedTransports_ExposeUnexpose proves the coordinated cross-chain WRITE
// is transport-agnostic: the FRONT edge is reached over `direct` HTTP and the DOWNSTREAM
// (home) edge is reached over `ssh-exec` (a real local `sh` running curl against an
// in-process caddy fake — the exact channel that reaches the maintainer's loopback-only home
// admin with no port published). One `expose vault --auth authelia` lands the front
// forward + the downstream real-backend+auth route + DNS as ONE ordered, verified
// transaction; `unexpose` tears it down. This is the trial shape (front=direct,
// home=ssh-exec) exercised end to end against fakes — no live infra.
func TestChainWrite_MixedTransports_ExposeUnexpose(t *testing.T) {
	if !shCapableExec(t) {
		t.Skip("sh/curl/base64 not available — skipping the mixed-transport chain-write test")
	}
	var log []string
	ctx := context.Background()

	// FRONT (vps): reached over the default direct transport.
	frontFake := caddyfake.New()
	t.Cleanup(frontFake.Close)
	frontFake.SeedCaddyfile(chainDeny)
	front := core.EdgeBinding{
		Name:              "vps",
		Provider:          labelEdge{EdgeProvider: caddy.New(frontFake.URL(), static.New(map[string]string{}), caddy.WithGranularApply()), label: "vps", log: &log},
		Fronts:            frontsFor(map[string]string{}),
		DownstreamEdge:    "home",
		DownstreamAddress: "10.0.0.13:443",
	}

	// HOME (downstream): reached over ssh-exec — a real `sh` running curl against the
	// home fake's admin URL. admin_url passed to New is unused (the transport routes).
	homeOrigins := map[string]string{"vault": "10.0.0.7:8200", "books": "10.0.0.9:80"}
	homeFake := caddyfake.New()
	t.Cleanup(homeFake.Close)
	homeFake.SeedCaddyfile(chainDeny)
	homeXport := &transport.SSHExec{Command: []string{"sh"}, AdminURL: homeFake.URL()}
	homeDriver := caddy.New("http://unused.invalid", static.New(homeOrigins),
		caddy.WithGranularApply(), caddy.WithTransport(homeXport), homeAuthRef())
	home := core.EdgeBinding{
		Name:     "home",
		Provider: labelEdge{EdgeProvider: homeDriver, label: "home", log: &log},
		Fronts:   frontsFor(homeOrigins),
	}

	pubSh := dnscontrolfake.New("homelab.example")
	inSh := dnscontrolfake.New("homelab.example")
	internal := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "homelab.example", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: inSh,
	}), log: &log}
	public := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "homelab.example", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh,
	}), log: &log}

	e := core.NewMulti([]core.EdgeBinding{front, home}, "homelab.example", internal, public)

	// --- expose vault --auth authelia over the mixed transports ---
	op := e.BuildOp(model.Expose, "vault")
	op.Auth = "authelia"
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("mixed-transport chain expose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified across the mixed-transport chain, got %+v\nverify=%+v", rep, rep.Verify)
	}
	// Same safe order as the all-direct chain: downstream → front → public DNS last.
	want := []string{"edge:home", "edge:vps", "dns/internal", "dns/public"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("mixed-transport expose order: got %v, want %v", log, want)
	}

	// Downstream (reached over ssh-exec) serves the real backend AND carries the auth.
	homeVault, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example")
	if !ok {
		t.Fatal("vault missing from the downstream (home) edge written over ssh-exec")
	}
	if homeVault.Upstream.Address != "10.0.0.7:8200" || homeVault.Upstream.Auth != "authelia" {
		t.Errorf("home vault over ssh-exec: addr=%q auth=%q; want 10.0.0.7:8200/authelia", homeVault.Upstream.Address, homeVault.Upstream.Auth)
	}
	// Front (direct) forwards to the downstream edge with no auth.
	frontVault, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example")
	if !ok {
		t.Fatal("vault missing from the front (vps) edge")
	}
	if frontVault.Upstream.Address != "10.0.0.13:443" || frontVault.Upstream.Auth != "" {
		t.Errorf("front vault: addr=%q auth=%q; want 10.0.0.13:443/none", frontVault.Upstream.Address, frontVault.Upstream.Auth)
	}

	// --- unexpose: tear it down across the mixed transports ---
	log = nil
	un := e.BuildOp(model.Unexpose, "vault")
	urep, err := e.Apply(ctx, un, core.AlwaysYes)
	if err != nil {
		t.Fatalf("mixed-transport chain unexpose failed: %v", err)
	}
	if !urep.Applied || !urep.Verified() {
		t.Fatalf("expected unexpose applied + verified, got %+v", urep)
	}
	if _, ok := liveRoute(liveOf(t, homeFake), "vault.homelab.example"); ok {
		t.Error("vault should be gone from the downstream edge after unexpose over ssh-exec")
	}
	if _, ok := liveRoute(liveOf(t, frontFake), "vault.homelab.example"); ok {
		t.Error("vault should be gone from the front edge after unexpose")
	}
}
