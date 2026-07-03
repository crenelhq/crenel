package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// failingCLI fails reload, to prove a persistence failure is a WARNING, not a
// rollback (the apply already succeeded + verified).
type failingCLI struct{}

func (failingCLI) Validate(ctx context.Context, path string) error { return nil }
func (failingCLI) Reload(ctx context.Context, path string) error {
	return errors.New("simulated reload failure")
}

// TestApply_PersistsAfterVerify proves core calls the edge's Persister after a
// verified apply: the on-disk Caddyfile gains the managed route.
func TestApply_PersistsAfterVerify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cfPath, []byte("auth.example.com {\n\treverse_proxy 10.0.0.9:9091\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	prov := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}),
		caddy.WithGranularApply(), caddy.WithPersistPath(cfPath), caddy.WithCaddyCLI(caddy.LogCaddyCLI{}))
	e := core.New(prov, "example.com")

	rep, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("apply should succeed + verify, got %+v", rep)
	}
	if len(rep.PersistWarnings) != 0 {
		t.Fatalf("no persist warnings expected, got %v", rep.PersistWarnings)
	}
	out, _ := os.ReadFile(cfPath)
	if !strings.Contains(string(out), "grafana.example.com {") || !strings.Contains(string(out), "auth.example.com {") {
		t.Fatalf("on-disk Caddyfile should hold both the new managed route and the operator's:\n%s", out)
	}
}

// TestApply_PersistFailureIsWarningNotRollback proves a persistence failure does
// NOT roll back a verified apply — the running state is correct; only durability
// is in question.
func TestApply_PersistFailureIsWarningNotRollback(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cfPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	prov := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}),
		caddy.WithGranularApply(), caddy.WithPersistPath(cfPath), caddy.WithCaddyCLI(failingCLI{}))
	e := core.New(prov, "example.com")

	rep, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply must SUCCEED despite a persist failure, got %v", err)
	}
	if rep.RolledBack {
		t.Fatal("a persist failure must NOT trigger rollback")
	}
	if !rep.Verified() || len(rep.PersistWarnings) != 1 {
		t.Fatalf("expected verified apply + 1 persist warning, got verified=%v warnings=%v", rep.Verified(), rep.PersistWarnings)
	}
	// The route is still live (the apply stuck) even though disk persistence failed.
	live, _ := prov.ReadLiveState(ctx)
	if !live.Reachable("grafana.example.com") {
		t.Fatal("route should remain live after a persist warning")
	}
}
