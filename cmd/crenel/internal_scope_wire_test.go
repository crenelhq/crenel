package main

// internal_scope_wire_test.go pins the WIRING half of internal-scope service
// declarations: structured origins entries aggregate into engine.InternalScope,
// and a cross-edge scope conflict is refused loudly at build time.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
)

// seedFile writes a Caddyfile fixture for a fake-seeded edge and returns its path.
func seedFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seed.caddyfile")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBuild_InternalScopeAggregates: a per-edge structured origins entry lands
// in the engine's InternalScope set; plain siblings do not.
func TestBuild_InternalScopeAggregates(t *testing.T) {
	s := config.Settings{
		Zone: "example.com",
		Edges: []config.EdgeSettings{
			{Name: "home", Driver: "caddy", FakeSeed: seedFile(t, "grafana.example.com {\n  reverse_proxy 10.0.0.5:3000\n}\n"),
				Origins: config.Origins{
					"grafana": {Addr: "10.0.0.5:3000"},
					"ha":      {Addr: "10.0.0.19:8123", Scope: config.OriginScopeInternal},
				}},
		},
	}
	w, err := build(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer w.cleanup()
	if !w.engine.InternalScope["ha"] {
		t.Errorf("declared internal service must reach engine.InternalScope, got %v", w.engine.InternalScope)
	}
	if w.engine.InternalScope["grafana"] {
		t.Errorf("plain entry must not be internal-scope, got %v", w.engine.InternalScope)
	}
	if !w.engine.InternalScopedHost("ha.example.com") {
		t.Errorf("host mapping through serviceOf must tag ha.example.com internal")
	}
}

// TestBuild_InternalScopeConflictRefused: the same service declared internal on
// one edge and default-scope on another is a contradiction — refused loudly,
// never a silent precedence guess.
func TestBuild_InternalScopeConflictRefused(t *testing.T) {
	seed := seedFile(t, "grafana.example.com {\n  reverse_proxy 10.0.0.5:3000\n}\n")
	s := config.Settings{
		Zone: "example.com",
		Edges: []config.EdgeSettings{
			{Name: "home", Driver: "caddy", FakeSeed: seed,
				Origins: config.Origins{"ha": {Addr: "10.0.0.19:8123", Scope: config.OriginScopeInternal}}},
			{Name: "vps", Driver: "caddy", FakeSeed: seed,
				Origins: config.Origins{"ha": {Addr: "100.100.1.2:8123"}}},
		},
	}
	if _, err := build(s); err == nil || !strings.Contains(err.Error(), "declared scope internal") {
		t.Fatalf("cross-edge scope conflict must refuse the build, got %v", err)
	}
}
