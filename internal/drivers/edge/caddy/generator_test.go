package caddy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// cdpAdminConfig is a caddy-docker-proxy-SHAPED admin-API config: routes whose
// upstreams are Docker service DNS names, no crenel @id, no explicit deny — exactly
// what CDP generates from labels. Crucially it carries NO marker in the admin API
// itself (verified against CDP docs), so detection relies on the on-disk autosave
// file, not this JSON.
const cdpAdminConfig = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"match":[{"host":["whoami.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"whoami:80"}]}]},
	{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"grafana:3000"}]}]}
]}}}}}`

// TestNormalize_DetectsCaddyDockerProxyForeign proves P2 generator detection for
// caddy-docker-proxy: pointed at CDP's on-disk `Caddyfile.autosave`, crenel marks the
// whole edge FOREIGN-managed (the admin API has no CDP marker, so the mounted autosave
// file is the signal). The routes are still READ (understanding != ownership) but the
// gate will refuse to mutate them — a crenel edit would be reverted on the next Docker
// event.
func TestNormalize_DetectsCaddyDockerProxyForeign(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(cdpAdminConfig); err != nil {
		t.Fatal(err)
	}
	// CDP's generated Caddyfile, mounted where crenel can read it.
	autosave := filepath.Join(t.TempDir(), "Caddyfile.autosave")
	if err := os.WriteFile(autosave, []byte("whoami.example.com {\n\treverse_proxy whoami:80\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGeneratorConfigPath(autosave))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "caddy-docker-proxy" {
		t.Fatalf("expected caddy-docker-proxy detection, got %q", live.Generator)
	}
	if !live.HasHost("whoami.example.com") || !live.HasHost("grafana.example.com") {
		t.Fatalf("CDP routes should still be READ, got %v", live.Hosts())
	}
	for _, r := range live.Routes {
		if r.Ownership != model.OwnForeign || r.Managed {
			t.Errorf("a CDP-owned route must be foreign + unmanaged, got %+v", r)
		}
	}
}

// TestNormalize_DeclaredGeneratorMarksForeign proves the operator-DECLARED hint path
// (WithGenerator): for a generator the admin API carries no detectable marker for, the
// operator can declare it and the gate engages edge-wide.
func TestNormalize_DeclaredGeneratorMarksForeign(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(cdpAdminConfig); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGenerator("caddy-docker-proxy"))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "caddy-docker-proxy" {
		t.Fatalf("declared generator should be honored, got %q", live.Generator)
	}
	for _, r := range live.Routes {
		if r.Ownership != model.OwnForeign {
			t.Errorf("declared-generator routes must be foreign, got %+v", r)
		}
	}
}

// TestNormalize_NoGeneratorForHandWrittenCaddy guards against false positives: a
// hand-written Caddy edge with NO generator path/declaration is NOT flagged
// generator-owned, and an unrelated config file (not a CDP autosave) does not trip
// detection either. CDP detection must never fire on ordinary Caddy.
func TestNormalize_NoGeneratorForHandWrittenCaddy(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(cdpAdminConfig); err != nil {
		t.Fatal(err)
	}
	// No generator option at all.
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "" {
		t.Errorf("hand-written Caddy must NOT be flagged generator-owned, got %q", live.Generator)
	}
	for _, r := range live.Routes {
		if r.Ownership == model.OwnForeign {
			t.Errorf("no detection => routes must not be foreign, got %+v", r)
		}
	}

	// Pointed at an ORDINARY config file (not a CDP autosave), detection still must
	// not fire.
	other := filepath.Join(t.TempDir(), "snippets.conf")
	if err := os.WriteFile(other, []byte("(authelia) {\n\tforward_auth authelia:9080\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d2 := caddy.New(fake.URL(), resolver(), caddy.WithGeneratorConfigPath(other))
	live2, err := d2.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live2.Generator != "" {
		t.Errorf("a non-CDP config file must not trip detection, got %q", live2.Generator)
	}
}

// TestNormalize_MissingGeneratorFileDoesNotError proves a configured-but-absent
// generator path is a tolerated no-op (detection simply doesn't fire) — a missing
// optional signal must never break a read.
func TestNormalize_MissingGeneratorFileDoesNotError(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(cdpAdminConfig); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver(), caddy.WithGeneratorConfigPath("/nonexistent/Caddyfile.autosave"))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatalf("a missing generator file must not error the read, got %v", err)
	}
	if live.Generator != "" {
		t.Errorf("an absent file must not flag a generator, got %q", live.Generator)
	}
}
