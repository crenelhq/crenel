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

// cloudflaredWith writes a cloudflared config.yml publishing the given hostnames and
// returns its path. The trailing http_status:404 is cloudflared's required catch-all.
func cloudflaredWith(t *testing.T, hostnames ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef\n")
	b.WriteString("credentials-file: /etc/cloudflared/6ff42ae2.json\n")
	b.WriteString("ingress:\n")
	for _, h := range hostnames {
		b.WriteString("  - hostname: " + h + "\n")
		b.WriteString("    service: http://localhost:3000\n")
	}
	b.WriteString("  - service: http_status:404\n")
	p := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIngress_RecoversPerHostTunnelMapping closes the P3 CORRECT-ness step: instead of a
// blanket edge-level "public/private is UNKNOWN", crenel now reads the tunnel's OWN
// ingress rules and recovers the per-host mapping by OBSERVATION (the tunnel analogue of
// P4's chain follow-through). The edge serves books + vault; the cloudflared config
// publishes books (→ observed public) and ghost (→ published but no edge route serves it,
// a dangling tunnel ingress that was previously INVISIBLE). vault is served but not in the
// tunnel rules.
func TestIngress_RecoversPerHostTunnelMapping(t *testing.T) {
	cfg := cloudflaredWith(t, "books.example.com", "ghost.example.com")
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{
			httpRoute("books.example.com"), // tunnel-published, no auth
			{Host: "vault.example.com", Upstream: model.Upstream{ // served but NOT tunnel-published
				Mode: model.ModeHTTPProxy, Address: "10.0.0.7:8200", ServerName: "vault.example.com", Auth: "authelia"}},
		},
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfg,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Back-compat: the edge is still flagged externally fronted.
	if _, ok := findCode(rep, "ingress_external"); !ok {
		t.Errorf("a tunnel-fronted edge must still fire ingress_external, got %+v", rep.Findings)
	}

	// OBSERVED per-host public: the finding must NAME books (recovered from the tunnel
	// rules) and must NOT claim vault is tunnel-public (it has no ingress rule).
	pub, ok := findCode(rep, "ingress_public_hosts")
	if !ok {
		t.Fatalf("expected ingress_public_hosts naming the observed tunnel-published hosts, got %+v", rep.Findings)
	}
	if !strings.Contains(pub.Message, "books.example.com") {
		t.Errorf("ingress_public_hosts must name books.example.com (observed in the tunnel rules), got %q", pub.Message)
	}
	if strings.Contains(pub.Message, "vault.example.com") {
		t.Errorf("vault.example.com is NOT in the tunnel rules — it must not be claimed tunnel-public, got %q", pub.Message)
	}

	// DANGLING tunnel ingress: ghost is published to the internet but no edge route serves
	// it — previously invisible, now surfaced.
	dang, ok := findCode(rep, "tunnel_route_without_edge")
	if !ok || dang.Severity != "warning" {
		t.Fatalf("expected a tunnel_route_without_edge warning for the dangling ghost host, got %+v", rep.Findings)
	}
	if !strings.Contains(dang.Message, "ghost.example.com") {
		t.Errorf("the dangling finding must name ghost.example.com, got %q", dang.Message)
	}
}

// TestIngress_UnparsedTunnelKeepsCoarseDeclaration locks the safe-by-default FALLBACK:
// when the ingress file is external but crenel cannot recover its per-host rules (an
// unrecognized/opaque config → IngressUnknown), it keeps the coarse declared-unknown
// ingress_external finding and emits NO per-host claims — never fabricating a mapping.
func TestIngress_UnparsedTunnelKeepsCoarseDeclaration(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "mystery.conf")
	if err := os.WriteFile(cfgPath, []byte("some: opaque\nproxy: front\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true, Routes: []model.Route{httpRoute("app.example.com")},
	}}
	e := core.NewMulti([]core.EdgeBinding{{
		Name: "home", Provider: edge, IngressConfigPath: cfgPath,
	}}, "example.com")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "ingress_external")
	if !ok || !strings.Contains(f.Message, "could not classify") {
		t.Errorf("an unclassifiable external ingress must keep the coarse declared-unknown finding, got %+v", rep.Findings)
	}
	if _, ok := findCode(rep, "ingress_public_hosts"); ok {
		t.Errorf("no per-host claim may be fabricated when the tunnel rules cannot be parsed: %+v", rep.Findings)
	}
	if _, ok := findCode(rep, "tunnel_route_without_edge"); ok {
		t.Errorf("no dangling claim may be fabricated when the tunnel rules cannot be parsed: %+v", rep.Findings)
	}
}
