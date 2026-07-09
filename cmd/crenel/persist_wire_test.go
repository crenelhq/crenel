package main

import (
	"testing"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/ports"
)

// TestDurablePersist_WiresDurableFileEdge proves a `caddy_persist` block wires the
// durable reconciler: the resulting Caddy edge declares model.PersistDurableFile (so
// status/audit surface it durable and the write path does NOT warn ephemeral). It builds
// against an in-process fake admin, so no infra is touched.
func TestDurablePersist_WiresDurableFileEdge(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()

	spec := edgeSpec{
		name:     "home",
		driver:   "caddy",
		adminURL: fake.URL(),
		granular: true,
		caddyPersist: &config.PersistSettings{
			BootPath:     "/etc/caddy/Caddyfile",
			FileCommand:  []string{"ssh", "root@ml350", "pct", "exec", "113", "--", "sh"},
			FilePath:     "/opt/stacks/caddy/conf/Caddyfile",
			CaddyCommand: []string{"ssh", "root@ml350", "pct", "exec", "113", "--", "docker", "exec", "-i", "caddy", "sh"},
		},
		origins: map[string]string{},
	}
	prov, err := buildCaddyEdge(spec, static.New(map[string]string{}), &wiring{cleanup: func() {}})
	if err != nil {
		t.Fatalf("buildCaddyEdge: %v", err)
	}
	dr, ok := prov.(ports.DurabilityReporter)
	if !ok {
		t.Fatal("caddy edge must report durability")
	}
	if m := dr.PersistenceModel(); !m.Durable() || string(m) != "durable-file" {
		t.Fatalf("a caddy_persist edge must be durable-file, got %q", m)
	}
}
