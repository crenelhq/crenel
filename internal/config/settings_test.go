package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
)

func TestLoad_EmptyPathReturnsDefaults(t *testing.T) {
	s, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	d := config.Defaults()
	if s.AdminURL != d.AdminURL || s.Zone != d.Zone {
		t.Errorf("empty path should return defaults, got %+v", s)
	}
}

func TestLoad_FileOverridesAndBackfills(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	// Only set zone + DNS; admin_url omitted should backfill from defaults.
	if err := os.WriteFile(path, []byte(`{"zone":"my.lan","dns":{"enabled":true,"scope":"public","mock":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Zone != "my.lan" {
		t.Errorf("zone not loaded: %q", s.Zone)
	}
	if s.AdminURL != config.Defaults().AdminURL {
		t.Errorf("admin_url should backfill from defaults, got %q", s.AdminURL)
	}
	if !s.DNS.Enabled || s.DNS.Scope != "public" || !s.DNS.Mock {
		t.Errorf("DNS settings not loaded: %+v", s.DNS)
	}
}

func TestLoad_ChainFieldsDecode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	cfg := `{
	  "zone": "homelab.example",
	  "edges": [
	    {"name": "vps", "driver": "caddy", "downstream_edge": "home", "downstream_address": "10.0.0.13", "origins": {}},
	    {"name": "home", "driver": "caddy", "origins": {}}
	  ]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Edges) != 2 {
		t.Fatalf("want 2 edges, got %d", len(s.Edges))
	}
	if s.Edges[0].DownstreamEdge != "home" || s.Edges[0].DownstreamAddress != "10.0.0.13" {
		t.Errorf("chain fields not decoded: %+v", s.Edges[0])
	}
	if s.Edges[1].DownstreamEdge != "" {
		t.Errorf("downstream edge should not be a chain front: %+v", s.Edges[1])
	}
}

// TestLoad_NoPhantomDemoOrigins is the papercut regression: a real user config must
// NOT inherit the bundled demo origins (grafana/photos/vault from Defaults). Before
// the fix, Load decoded the file UNDER Defaults(), so json.Unmarshal merged the user
// origins into the pre-seeded demo map and the demo entries leaked (surfacing as
// phantom adoptions in `import --dry-run`).
func TestLoad_NoPhantomDemoOrigins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "real.json")
	// A real config with exactly one origin and a custom zone.
	if err := os.WriteFile(path, []byte(`{"zone":"my.lan","origins":{"jelly":"10.1.1.9:8096"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Origins) != 1 {
		t.Fatalf("real config should carry ONLY its own origin, got %d: %+v", len(s.Origins), s.Origins)
	}
	if _, ok := s.Origins["jelly"]; !ok {
		t.Errorf("the user's origin is missing: %+v", s.Origins)
	}
	for _, phantom := range []string{"grafana", "photos", "vault"} {
		if _, ok := s.Origins[phantom]; ok {
			t.Errorf("demo origin %q leaked into a real config: %+v", phantom, s.Origins)
		}
	}
	// Connection scalars still backfill from Defaults when omitted.
	if s.AdminURL != config.Defaults().AdminURL {
		t.Errorf("admin_url should backfill, got %q", s.AdminURL)
	}
}

func TestLoad_EmptyPathStillSeedsDemoOrigins(t *testing.T) {
	// The no-config demo/scaffold path keeps the helpful example origins.
	s, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Origins) == 0 {
		t.Error("empty-path Load should still provide demo origins for the no-infra demo")
	}
}

func TestLoad_BadJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o644)
	if _, err := config.Load(path); err == nil {
		t.Error("expected parse error for bad JSON")
	}
}

func TestToolNamingCentralized(t *testing.T) {
	// The rename seam: these must be non-empty and consistent.
	if config.ToolName == "" || config.ToolTitle == "" || config.ToolTagline == "" {
		t.Error("tool naming constants must be set")
	}
}
