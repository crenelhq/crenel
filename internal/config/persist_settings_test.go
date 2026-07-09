package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
)

// TestLoad_DurablePersistDecodes proves the home-edge durable-persist block decodes:
// the two exec channels (file channel to the LXC host, caddy channel to the container)
// and the boot path the reconciler reloads.
func TestLoad_DurablePersistDecodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "durable.json")
	cfg := `{
	  "zone": "homelab.example",
	  "edges": [
	    {
	      "name": "home", "driver": "caddy", "granular_apply": true, "origins": {},
	      "transport": {"type": "ssh-exec", "command": ["ssh","root@ml350","pct","exec","113","--","docker","exec","-i","caddy","sh"]},
	      "caddy_persist": {
	        "boot_path": "/etc/caddy/Caddyfile",
	        "file_command": ["ssh","root@ml350","pct","exec","113","--","sh"],
	        "file_path": "/opt/stacks/caddy/conf/Caddyfile",
	        "caddy_command": ["ssh","root@ml350","pct","exec","113","--","docker","exec","-i","caddy","sh"]
	      }
	    }
	  ]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(s.Edges))
	}
	p := s.Edges[0].CaddyPersist
	if p == nil {
		t.Fatal("caddy_persist did not decode")
	}
	if p.BootPath != "/etc/caddy/Caddyfile" {
		t.Errorf("boot_path = %q", p.BootPath)
	}
	if p.FilePath != "/opt/stacks/caddy/conf/Caddyfile" {
		t.Errorf("file_path = %q", p.FilePath)
	}
	if len(p.FileCommand) == 0 || p.FileCommand[0] != "ssh" {
		t.Errorf("file_command = %v", p.FileCommand)
	}
	if len(p.CaddyCommand) == 0 || p.CaddyCommand[len(p.CaddyCommand)-1] != "sh" {
		t.Errorf("caddy_command = %v", p.CaddyCommand)
	}
}
