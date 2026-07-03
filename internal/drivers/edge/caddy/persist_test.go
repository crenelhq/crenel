package caddy_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// recordCLI is a fake CaddyCLI: it records validate/reload invocations and can be
// made to fail validation, so tests assert the correct invocation + ordering
// without execing a real caddy binary.
type recordCLI struct {
	validated []string
	reloaded  []string
	failValid bool
	lastValid string // file content seen at validate time
}

func (c *recordCLI) Validate(ctx context.Context, path string) error {
	c.validated = append(c.validated, path)
	if b, err := os.ReadFile(path); err == nil {
		c.lastValid = string(b)
	}
	if c.failValid {
		return errors.New("simulated invalid Caddyfile")
	}
	return nil
}
func (c *recordCLI) Reload(ctx context.Context, path string) error {
	c.reloaded = append(c.reloaded, path)
	return nil
}

// TestPersist_AdditiveInjectionValidateReload proves on-disk persistence injects
// crenel's managed routes between sentinels WITHOUT touching the operator's
// surrounding config, validates BEFORE replacing the live file, and reloads ONCE.
func TestPersist_AdditiveInjectionValidateReload(t *testing.T) {
	ctx := context.Background()

	// Operator's hand-written base Caddyfile (no crenel region yet).
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")
	base := "{\n\tadmin localhost:2019\n}\n\nauth.example.com {\n\treverse_proxy 10.0.0.9:9091\n}\n"
	if err := os.WriteFile(caddyfilePath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}

	// A live edge with one crenel-MANAGED route (and an unmanaged one that must NOT
	// be mirrored to disk).
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"match":[{"host":["legacy.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.99:80"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	cli := &recordCLI{}
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}),
		caddy.WithGranularApply(), caddy.WithPersistPath(caddyfilePath), caddy.WithCaddyCLI(cli))

	if err := d.Persist(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}

	out, _ := os.ReadFile(caddyfilePath)
	got := string(out)
	// Operator config preserved.
	if !strings.Contains(got, "admin localhost:2019") || !strings.Contains(got, "auth.example.com {") {
		t.Fatalf("operator config must be preserved:\n%s", got)
	}
	// crenel region injected with the MANAGED route only.
	if !strings.Contains(got, "# crenel-managed-begin") || !strings.Contains(got, "grafana.example.com {") {
		t.Fatalf("managed route must be injected:\n%s", got)
	}
	// The UNMANAGED live route must NOT be mirrored to disk.
	if strings.Contains(got, "legacy.example.com {") {
		t.Fatalf("unmanaged route must not be persisted:\n%s", got)
	}
	// Validate happened (once), and exactly one reload.
	if len(cli.validated) != 1 || len(cli.reloaded) != 1 {
		t.Fatalf("want 1 validate + 1 reload (debounced), got %d/%d", len(cli.validated), len(cli.reloaded))
	}
	if cli.reloaded[0] != caddyfilePath {
		t.Fatalf("reload must target the persist path %q, got %q", caddyfilePath, cli.reloaded[0])
	}

	// Idempotent re-persist replaces the region cleanly (no duplicate sentinels).
	if err := d.Persist(ctx); err != nil {
		t.Fatalf("re-persist: %v", err)
	}
	out2, _ := os.ReadFile(caddyfilePath)
	if n := strings.Count(string(out2), "# crenel-managed-begin"); n != 1 {
		t.Fatalf("want exactly 1 managed region after re-persist, got %d", n)
	}
}

// TestPersist_InvalidCandidateNeverTouchesLiveFile proves a failing `caddy
// validate` aborts persistence WITHOUT modifying the live Caddyfile or reloading.
func TestPersist_InvalidCandidateNeverTouchesLiveFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")
	base := "auth.example.com {\n\treverse_proxy 10.0.0.9:9091\n}\n"
	if err := os.WriteFile(caddyfilePath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	cli := &recordCLI{failValid: true}
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}),
		caddy.WithGranularApply(), caddy.WithPersistPath(caddyfilePath), caddy.WithCaddyCLI(cli))

	if err := d.Persist(ctx); err == nil {
		t.Fatal("persist must fail when validate fails")
	}
	out, _ := os.ReadFile(caddyfilePath)
	if string(out) != base {
		t.Fatalf("live file must be untouched on validate failure, got:\n%s", out)
	}
	if len(cli.reloaded) != 0 {
		t.Fatal("must NOT reload after a failed validate")
	}
}
