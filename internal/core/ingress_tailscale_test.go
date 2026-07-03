package core_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// Tailscale serve.json per-host recovery (the P3 follow-on flagged in
// docs/DNS-DESIGN.md and STATE-OF-CRENEL.md). The cloudflared path already recovers
// per-host external reachability from the tunnel's own ingress rules so the audit's
// public_without_auth catches a tunnel-published host without auth — but the
// Tailscale path stayed coarse. That's a SILENT MISS on a funnel-published host:
// AllowFunnel makes a host internet-reachable, but with no per-host recovery
// `tunnelPublic[host]` is never set, so a missing forward-auth policy on that host
// stays invisible.
//
// Scope (honest): only AllowFunnel keys are treated as PUBLIC here. A `Web` entry
// WITHOUT AllowFunnel is a tailnet-scoped serve (identity-enforced by the tailnet,
// not internet-reachable) — out of scope for the public_without_auth axis, and
// deliberately left declared-unknown so we don't false-positive on a mesh-private
// host.

// writeServeConfig writes a Tailscale serve.json with the given (host:port → funnel?)
// pairs (funnel=true => AllowFunnel for that key; funnel=false => Web entry only).
func writeServeConfig(t *testing.T, hosts map[string]bool) string {
	t.Helper()
	var web, fun []string
	for h, isFunnel := range hosts {
		web = append(web, `"`+h+`":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}`)
		if isFunnel {
			fun = append(fun, `"`+h+`":true`)
		}
	}
	body := `{"TCP":{"443":{"HTTPS":true}},"Web":{` + strings.Join(web, ",") + `}`
	if len(fun) > 0 {
		body += `,"AllowFunnel":{` + strings.Join(fun, ",") + `}`
	}
	body += `}`
	p := filepath.Join(t.TempDir(), "serve.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIngress_TailscaleFunnel_PublicWithoutAuthFires is the RED→GREEN headline: a
// host published over AllowFunnel that has no forward-auth policy on its edge route
// must surface as public_without_auth — without per-host recovery this miss was
// silent (no public DNS managed, no other signal made it "public" to the audit).
func TestIngress_TailscaleFunnel_PublicWithoutAuthFires(t *testing.T) {
	cfg := writeServeConfig(t, map[string]bool{"app.example.com:443": true})
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("app.example.com")}, // NO auth
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "public_without_auth")
	if !ok {
		t.Fatalf("AllowFunnel host with no auth must fire public_without_auth, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "app.example.com") {
		t.Errorf("public_without_auth must name the funnel host, got %q", f.Message)
	}
}

// TestIngress_TailscaleFunnel_PerHostObservedFires mirrors the cloudflared
// per-host_observed assertion: the funnel-published host is OBSERVED public via the
// recovered serve rules, surfaced as ingress_public_hosts (positive, ok-severity).
func TestIngress_TailscaleFunnel_PerHostObservedFires(t *testing.T) {
	cfg := writeServeConfig(t, map[string]bool{"app.example.com:443": true})
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{{Host: "app.example.com", Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "app.example.com", Auth: "authelia"}}},
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := findCode(rep, "ingress_public_hosts")
	if !ok {
		t.Fatalf("expected ingress_public_hosts naming the funnel-published host, got %+v", rep.Findings)
	}
	if !strings.Contains(pub.Message, "app.example.com") {
		t.Errorf("ingress_public_hosts must name the funnel host, got %q", pub.Message)
	}
}

// TestIngress_TailscaleFunnel_DanglingHostFires: a funnel key published in serve.json
// that no edge route serves is dangling (the tunnel publishes a hostname clients can
// hit, but it lands at nothing) — must fire tunnel_route_without_edge.
func TestIngress_TailscaleFunnel_DanglingHostFires(t *testing.T) {
	// ghost is funnel-published but not served on any edge.
	cfg := writeServeConfig(t, map[string]bool{
		"app.example.com:443":   true,
		"ghost.example.com:443": true,
	})
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{{Host: "app.example.com", Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "app.example.com", Auth: "authelia"}}},
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "tunnel_route_without_edge")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected tunnel_route_without_edge for the dangling funnel host, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "ghost.example.com") {
		t.Errorf("dangling-funnel message must name the host, got %q", f.Message)
	}
}

// TestIngress_TailscaleWebWithoutFunnel_IsNotClaimedPublic codifies the careful guard:
// a Web entry WITHOUT AllowFunnel is tailnet-scoped (identity-enforced by the tailnet),
// not internet-public. It must NOT be claimed tunnelPublic — i.e. it must not pull a
// no-auth tailnet-only serve into public_without_auth. The edge still gets the coarse
// ingress_external warning (correctly: external overlay, mechanism per-host known).
func TestIngress_TailscaleWebWithoutFunnel_IsNotClaimedPublic(t *testing.T) {
	// vault is Web-only (tailnet), NOT AllowFunnel. The route has no forward-auth: this
	// is intentional in a tailnet-only setup (identity is the tailnet ACL).
	cfg := writeServeConfig(t, map[string]bool{"vault.example.com:443": false})
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("vault.example.com")},
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A tailnet-only serve host must NOT be claimed PUBLIC: no public_without_auth fires
	// (a public DNS for it would be a separate signal; none is configured here).
	if f, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("Web-only (no AllowFunnel) host is tailnet-scoped — must not pull public_without_auth, got %q", f.Message)
	}
	// And no false ingress_public_hosts claim (recovery is funnel-only).
	if f, ok := findCode(rep, "ingress_public_hosts"); ok && strings.Contains(f.Message, "vault.example.com") {
		t.Errorf("Web-only host must not be claimed PUBLIC by ingress_public_hosts, got %q", f.Message)
	}
	// And no false dangling claim (the host IS served on the edge).
	if f, ok := findCode(rep, "tunnel_route_without_edge"); ok {
		t.Errorf("a tailnet-scoped Web host that IS served on the edge must not fire dangling, got %q", f.Message)
	}
}

// TestIngress_TailscaleFunnel_StripsPort: serve.json keys are `host:port`. The
// per-host recovery must extract the host (without the port) so matches against the
// edge's host-keyed route map and the audit's `host` keys work — a regression in
// stripping would silently miss every funnel host.
func TestIngress_TailscaleFunnel_StripsPort(t *testing.T) {
	cfg := writeServeConfig(t, map[string]bool{"app.example.com:8443": true})
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("app.example.com")}, // NO auth
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "public_without_auth"); !ok || !strings.Contains(f.Message, "app.example.com") {
		t.Fatalf("a port-suffixed funnel key (host:8443) must still match the host (no port) — public_without_auth must fire, got %+v", rep.Findings)
	}
}
