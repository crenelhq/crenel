package core_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// partialEngine simulates a mid-apply INTERRUPTION of a double-write: the home
// edge already has grafana exposed (the apply got that far), the vps edge does
// not (it was interrupted before reaching it). Both front grafana.
func partialEngine(t *testing.T) (*core.Engine, string) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(seedGrafana) // home: grafana already exposed
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil { // vps: not yet exposed
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	return core.NewMulti([]core.EdgeBinding{home, vps}, "example.com"), path
}

// TestResume_CompletesInterruptedDoubleWrite: resume diagnoses home as done and
// completes the pending vps edge, leaving both consistent.
func TestResume_CompletesInterruptedDoubleWrite(t *testing.T) {
	e, _ := partialEngine(t)
	ctx := context.Background()

	rr, err := e.Resume(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if rr.NothingToDo {
		t.Fatal("there WAS a pending edge; resume should not be a no-op")
	}
	if len(rr.Already) != 1 || !strings.Contains(rr.Already[0], "home") {
		t.Errorf("home should be diagnosed already-done, got %v", rr.Already)
	}
	if len(rr.Pending) != 1 || !strings.Contains(rr.Pending[0], "vps") {
		t.Errorf("vps should be the pending edge, got %v", rr.Pending)
	}
	if !rr.Apply.Verified() {
		t.Fatalf("completing vps should verify, got %+v", rr.Apply.Verify)
	}

	// Both edges now consistent.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		found := false
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				found = true
			}
		}
		if !found {
			t.Errorf("grafana should be exposed on edge %s after resume", es.Name)
		}
	}
}

// TestResume_RollsBackCleanlyOnFailedCompletion: if completing the remaining
// delta fails (DNS push fails), resume rolls back its OWN attempt — the pending
// edge it just applied is reverted — while the already-done edge is left intact.
func TestResume_RollsBackCleanlyOnFailedCompletion(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana) // home: grafana already exposed
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil { // vps: pending
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	sh := dnscontrolfake.New("example.com")
	sh.FailPush = true // completing DNS will fail
	dns := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: sh})

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com", dns)
	ctx := context.Background()

	rr, err := e.Resume(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err == nil {
		t.Fatal("expected resume to fail on DNS push")
	}
	if !rr.Apply.RolledBack {
		t.Error("resume should roll back its own attempt on failed completion")
	}
	// vps (the pending edge resume applied) must be reverted; home (already done,
	// untouched by this resume) must remain exposed.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		has := false
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				has = true
			}
		}
		switch es.Name {
		case "home":
			if !has {
				t.Error("home (already-done) must remain exposed after a failed resume")
			}
		case "vps":
			if has {
				t.Error("vps must be rolled back after resume's completion failed")
			}
		}
	}
}

// TestResume_NothingToDoWhenConsistent: a fully-consistent world resumes to a
// clean no-op.
func TestResume_NothingToDoWhenConsistent(t *testing.T) {
	e, _ := partialEngine(t)
	ctx := context.Background()
	// First resume completes it...
	if _, err := e.Resume(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes); err != nil {
		t.Fatal(err)
	}
	// ...a second resume has nothing to do.
	rr, err := e.Resume(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatal(err)
	}
	if !rr.NothingToDo {
		t.Errorf("expected NothingToDo on a consistent world, got pending=%v", rr.Pending)
	}
	if len(rr.Already) != 2 {
		t.Errorf("both edges should be diagnosed done, got %v", rr.Already)
	}
}
