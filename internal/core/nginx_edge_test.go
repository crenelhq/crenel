package core_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/nginx"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestCore_DrivesNginxEdge proves the EdgeProvider port holds for a FOURTH,
// structurally-different edge: core (unchanged) drives the nginx config-file driver
// end-to-end — plan, apply, read-back-verify, structural default-deny — exactly as
// it drives Caddy and Traefik. Breadth-validation of the vendor-agnostic claim.
func TestCore_DrivesNginxEdge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.conf")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	e := core.New(nginx.New(path, res), "example.com")
	ctx := context.Background()

	rep, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("core should drive the nginx edge: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("nginx expose should read-back-verify, got %+v", rep.Verify)
	}

	st, _ := e.Status(ctx)
	if len(st.Edges) != 1 || st.Edges[0].Driver != "nginx" {
		t.Fatalf("status should report the nginx edge, got %+v", st.Edges)
	}
	if !st.Edges[0].DenyCatchAllPresent {
		t.Error("default-deny must hold on the nginx edge")
	}
	found := false
	for _, r := range st.Edges[0].Routes {
		if r.Host == "grafana.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("grafana should be exposed on the nginx edge")
	}

	// Unexpose verifies too; deny remains.
	repU, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose: %v", err)
	}
	if !repU.Verified() {
		t.Fatalf("unexpose should verify, got %+v", repU.Verify)
	}
	stF, _ := e.Status(ctx)
	if !stF.Edges[0].DenyCatchAllPresent {
		t.Error("deny must remain after unexpose")
	}
}

// TestCore_NginxInHeterogeneousReconcile proves the nginx driver participates in the
// cross-driver machinery: an nginx home edge + a Caddy-less Traefik vps edge both
// front grafana; nginx is missing it; reconcile converges with nginx's own resolver.
func TestCore_NginxInHeterogeneousReconcile(t *testing.T) {
	ctx := context.Background()

	// nginx home edge, fronts grafana, currently empty.
	dir := t.TempDir()
	npath := filepath.Join(dir, "edge.conf")
	if err := os.WriteFile(npath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: nginx.New(npath, static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	// A second edge already exposing grafana so it is in the canonical set. Reuse a
	// simple nginx vps edge with grafana pre-applied.
	vpath := filepath.Join(dir, "vps.conf")
	if err := os.WriteFile(vpath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vpsDriver := nginx.New(vpath, static.New(vpsOrigins))
	if err := vpsDriver.Apply(ctx, model.ChangeSet{Edge: model.EdgeChange{
		AddRoutes: []model.Route{{Host: "grafana.example.com", Upstream: model.Upstream{Address: "100.100.0.5:3000"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	vps := core.EdgeBinding{Name: "vps", Provider: vpsDriver, Fronts: frontsFor(vpsOrigins)}

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile across nginx edges: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("reconcile should verify, got %+v", rep.Verify)
	}
	// home should now expose grafana at its OWN address (per-edge resolver).
	live, _ := home.Provider.ReadLiveState(ctx)
	got := ""
	for _, r := range live.Routes {
		if r.Host == "grafana.example.com" {
			got = r.Upstream.Address
		}
	}
	if got != "10.0.0.5:3000" {
		t.Errorf("home nginx should expose grafana at its LAN address after reconcile, got %q", got)
	}
}
