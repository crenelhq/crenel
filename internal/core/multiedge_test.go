package core_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// frontsFor builds a projection predicate from an edge's origin map: it fronts a
// service iff that service is in its origins.
func frontsFor(origins map[string]string) func(string) bool {
	return func(service string) bool {
		_, ok := origins[service]
		return ok
	}
}

// heteroEngine wires a HETEROGENEOUS two-edge topology to prove the abstraction
// spans drivers: a home Caddy edge and a VPS Traefik edge, each with its OWN
// origins (home proxies LAN IPs; VPS proxies Tailscale IPs). grafana is fronted by
// BOTH (a real double-write); photos only home; vault only VPS.
func heteroEngine(t *testing.T) (*core.Engine, *caddyfake.Fake, string) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n") // home starts empty (deny only)
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"}
	home := core.EdgeBinding{
		Name:     "home",
		Provider: caddy.New(cf.URL(), static.New(homeOrigins)),
		Fronts:   frontsFor(homeOrigins),
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000", "vault": "100.100.0.7:8200"}
	vps := core.EdgeBinding{
		Name:     "vps",
		Provider: traefik.New(path, static.New(vpsOrigins)),
		Fronts:   frontsFor(vpsOrigins),
	}

	return core.NewMulti([]core.EdgeBinding{home, vps}, "example.com"), cf, path
}

func edgePlanFor(cs model.ChangeSet, name string) (model.EdgePlan, bool) {
	for _, ep := range cs.Edges {
		if ep.Edge == name {
			return ep, true
		}
	}
	return model.EdgePlan{}, false
}

// TestMultiEdge_Projection: a service is planned only onto edges that front it,
// and each edge resolves its OWN origin address.
func TestMultiEdge_Projection(t *testing.T) {
	e, _, _ := heteroEngine(t)
	ctx := context.Background()

	// grafana: both edges, different addresses.
	cs, err := e.Plan(ctx, e.BuildOp(model.Expose, "grafana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edges) != 2 {
		t.Fatalf("grafana should project onto both edges, got %d", len(cs.Edges))
	}
	h, _ := edgePlanFor(cs, "home")
	v, _ := edgePlanFor(cs, "vps")
	if len(h.Change.AddRoutes) != 1 || h.Change.AddRoutes[0].Upstream.Address != "10.0.0.5:3000" {
		t.Errorf("home should add grafana -> LAN addr, got %+v", h.Change)
	}
	if len(v.Change.AddRoutes) != 1 || v.Change.AddRoutes[0].Upstream.Address != "100.100.0.5:3000" {
		t.Errorf("vps should add grafana -> Tailscale addr, got %+v", v.Change)
	}

	// photos: home only.
	csP, _ := e.Plan(ctx, e.BuildOp(model.Expose, "photos"))
	if len(csP.Edges) != 1 || csP.Edges[0].Edge != "home" {
		t.Errorf("photos should project onto home only, got %+v", csP.Edges)
	}
	// vault: vps only.
	csV, _ := e.Plan(ctx, e.BuildOp(model.Expose, "vault"))
	if len(csV.Edges) != 1 || csV.Edges[0].Edge != "vps" {
		t.Errorf("vault should project onto vps only, got %+v", csV.Edges)
	}
	// unknown service: no edge fronts it => error.
	if _, err := e.Plan(ctx, e.BuildOp(model.Expose, "nope")); err == nil {
		t.Error("expose of an un-fronted service should error")
	}
}

// TestMultiEdge_DoubleWriteVerifiesBoth: exposing grafana writes BOTH edges and
// read-back-verifies each; status reflects it on both.
func TestMultiEdge_DoubleWriteVerifiesBoth(t *testing.T) {
	e, _, _ := heteroEngine(t)
	ctx := context.Background()

	rep, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("double-write apply failed: %v", err)
	}
	if !rep.Verified() || len(rep.Verify) != 2 {
		t.Fatalf("both edges must verify, got %+v", rep.Verify)
	}
	st, _ := e.Status(ctx)
	if len(st.Edges) != 2 {
		t.Fatalf("status should report both edges, got %d", len(st.Edges))
	}
	for _, es := range st.Edges {
		if !es.DenyCatchAllPresent {
			t.Errorf("deny must hold on edge %s", es.Name)
		}
		found := false
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				found = true
			}
		}
		if !found {
			t.Errorf("grafana must be exposed on edge %s after double-write", es.Name)
		}
	}
}

// failOnApply is an edge whose Apply always fails — used to prove the cross-edge
// transaction is all-or-nothing.
type failOnApply struct{ live model.LiveEdgeState }

func (f failOnApply) Name() string                   { return "boomedge" }
func (f failOnApply) Validate(context.Context) error { return nil }
func (f failOnApply) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return f.live, nil
}
func (f failOnApply) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true
	if op.Verb == model.Expose && !live.HasHost(op.Host) {
		cs.Edge.AddRoutes = []model.Route{{Host: op.Host, Upstream: model.Upstream{Address: "1.1.1.1:1"}}}
	}
	return cs, nil
}
func (f failOnApply) Apply(context.Context, model.ChangeSet) error {
	return fmt.Errorf("boom: second edge apply failed")
}

// TestMultiEdge_AllOrNothingRollback: edge A (real Caddy) applies, edge B fails —
// the WHOLE transaction reverts, so A's route is rolled back. No half double-write.
func TestMultiEdge_AllOrNothingRollback(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(
		map[string]string{"grafana": "10.0.0.5:3000"}))} // Fronts nil => fronts all
	bad := core.EdgeBinding{Name: "vps", Provider: failOnApply{
		live: model.LiveEdgeState{DenyCatchAllPresent: true}}}

	e := core.NewMulti([]core.EdgeBinding{home, bad}, "example.com")
	ctx := context.Background()

	rep, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err == nil {
		t.Fatal("expected the failing second edge to fail the transaction")
	}
	if !rep.RolledBack {
		t.Error("expected RolledBack=true across edges")
	}
	if len(rep.RollbackErrors) != 0 {
		t.Errorf("home rollback should succeed cleanly, got %v", rep.RollbackErrors)
	}
	// The crucial assertion: the first edge's route was reverted — no orphaned
	// half double-write left behind.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		if es.Name != "home" {
			continue
		}
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				t.Error("home edge route must have been rolled back after the other edge failed")
			}
		}
	}
}

// TestMultiEdge_AuditCrossEdgeInconsistency: grafana is exposed on home but NOT on
// vps, though vps also fronts it — audit must flag the inconsistent double-write.
func TestMultiEdge_AuditCrossEdgeInconsistency(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana) // home has grafana exposed
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil { // vps empty
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"} // vps ALSO fronts grafana
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_inconsistent_exposure")
	if !ok || f.Severity != "warning" {
		t.Errorf("expected cross-edge inconsistency warning, got %+v", rep.Findings)
	}
}
