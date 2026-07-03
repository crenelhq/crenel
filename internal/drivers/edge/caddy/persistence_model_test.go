package caddy_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// TestPersistenceModel_Derivation locks how the Caddy driver declares its durability
// posture: a bare admin edge is ephemeral-admin (the safe default), a persist-path edge
// is durable-file, and an explicit operator declaration overrides both. It checks BOTH
// the ports.DurabilityReporter method AND the value surfaced on ReadLiveState.
func TestPersistenceModel_Derivation(t *testing.T) {
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})

	t.Run("bare admin => ephemeral-admin", func(t *testing.T) {
		fake := caddyfake.New()
		t.Cleanup(fake.Close)
		fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
		d := caddy.New(fake.URL(), res)
		assertModel(t, d, model.PersistEphemeralAdmin)
	})

	t.Run("persist path => durable-file", func(t *testing.T) {
		fake := caddyfake.New()
		t.Cleanup(fake.Close)
		fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
		d := caddy.New(fake.URL(), res, caddy.WithPersistPath(filepath.Join(t.TempDir(), "Caddyfile")))
		assertModel(t, d, model.PersistDurableFile)
	})

	t.Run("declared resume overrides", func(t *testing.T) {
		fake := caddyfake.New()
		t.Cleanup(fake.Close)
		fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
		// Even with a persist path, an explicit declaration wins.
		d := caddy.New(fake.URL(), res,
			caddy.WithPersistPath(filepath.Join(t.TempDir(), "Caddyfile")),
			caddy.WithPersistenceModel(model.PersistResume))
		assertModel(t, d, model.PersistResume)
	})
}

func assertModel(t *testing.T, d *caddy.Driver, want model.PersistenceModel) {
	t.Helper()
	dr, ok := any(d).(ports.DurabilityReporter)
	if !ok {
		t.Fatal("caddy driver must implement ports.DurabilityReporter")
	}
	if got := dr.PersistenceModel(); got != want {
		t.Errorf("PersistenceModel() = %q, want %q", got, want)
	}
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatalf("read live: %v", err)
	}
	if live.Persistence != want {
		t.Errorf("live.Persistence = %q, want %q", live.Persistence, want)
	}
}
