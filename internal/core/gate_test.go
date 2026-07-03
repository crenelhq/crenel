package core_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// gateStub is an EdgeProvider double whose live state is fully controllable
// (ownership, generator) and whose Plan/Apply implement the ordinary expose/unexpose
// against that live — so the refuse-to-manage gate can be exercised on real
// (non-empty) ChangeSets that touch a foreign/unknown-owned route or edge.
type gateStub struct {
	name string
	live model.LiveEdgeState
	addr map[string]string // service -> backend addr
}

func (g *gateStub) Name() string                   { return g.name }
func (g *gateStub) Validate(context.Context) error { return nil }
func (g *gateStub) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return g.live, nil
}

func (g *gateStub) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true
	switch op.Verb {
	case model.Expose:
		if live.HasHost(op.Host) {
			return cs, nil
		}
		a := g.addr[op.Service]
		if a == "" {
			return cs, fmt.Errorf("no origin for %q", op.Service)
		}
		cs.Edge.AddRoutes = []model.Route{{Host: op.Host, Upstream: model.Upstream{
			Kind: model.ForwardToOrigin, Address: a, ServerName: op.Host}}}
	case model.Unexpose:
		if !live.HasHost(op.Host) {
			return cs, nil
		}
		cs.Edge.RemoveHosts = []string{op.Host}
	}
	return cs, nil
}

// Apply mutates the stub's live so a downstream read-back-verify reflects the change
// (only reached when the gate PERMITS the mutation).
func (g *gateStub) Apply(_ context.Context, cs model.ChangeSet) error {
	for _, h := range cs.Edge.RemoveHosts {
		var keep []model.Route
		for _, r := range g.live.Routes {
			if r.Host != h {
				keep = append(keep, r)
			}
		}
		g.live.Routes = keep
	}
	g.live.Routes = append(g.live.Routes, cs.Edge.AddRoutes...)
	return nil
}

// Adopt records adopted hosts (stamping ownership). Enough to satisfy ports.Adopter
// so import can classify a clean unmanaged route as adoptable.
func (g *gateStub) Adopt(_ context.Context, hosts []string) error {
	for i := range g.live.Routes {
		for _, h := range hosts {
			if g.live.Routes[i].Host == h {
				g.live.Routes[i].Managed = true
				g.live.Routes[i].Ownership = model.OwnCrenel
			}
		}
	}
	return nil
}

func foreignEngine(t *testing.T, force bool, own model.Ownership, generator string) *core.Engine {
	t.Helper()
	stub := &gateStub{
		name: "caddy",
		addr: map[string]string{"app": "10.0.0.5:3000"},
		live: model.LiveEdgeState{
			DenyCatchAllPresent: true,
			Generator:           generator,
			Routes: []model.Route{{
				Host: "app.example.com", Ownership: own, Managed: own == model.OwnCrenel,
				Upstream: model.Upstream{Kind: model.ForwardToOrigin, Address: "10.0.0.5:3000", ServerName: "app.example.com"},
			}},
		},
	}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: stub}}, "example.com")
	e.Force = force
	return e
}

// TestGate_ForeignRouteRefusesEvenWithYes proves a mutation of a FOREIGN-owned route
// is refused LOUDLY, and --yes (AlwaysYes) does NOT bypass it — nor does --force,
// since a generator-owned edit has no safe force (it would be reverted).
func TestGate_ForeignRouteRefusesEvenWithYes(t *testing.T) {
	for _, force := range []bool{false, true} {
		e := foreignEngine(t, force, model.OwnForeign, "")
		_, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "app.example.com"), core.AlwaysYes)
		if err == nil || !errors.Is(err, core.ErrRefuseToManage) {
			t.Errorf("force=%v: unexpose of a foreign route must refuse (ErrRefuseToManage), got %v", force, err)
		}
	}
}

// TestGate_GeneratorEdgeRefusesEvenAdditive proves an edge crenel detects as
// generator-owned refuses ANY mutation edge-wide — even an additive expose of a
// brand-new host — because nothing crenel writes there will stick.
func TestGate_GeneratorEdgeRefusesEvenAdditive(t *testing.T) {
	stub := &gateStub{
		name: "caddy",
		addr: map[string]string{"grafana": "10.0.0.5:3000"},
		live: model.LiveEdgeState{DenyCatchAllPresent: true, Generator: "caddy-docker-proxy"},
	}
	e := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: stub}}, "example.com")
	e.Force = true // force must NOT rescue a generator-owned edge
	_, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "grafana"), core.AlwaysYes)
	if err == nil || !errors.Is(err, core.ErrRefuseToManage) {
		t.Fatalf("expose onto a generator-owned edge must refuse, got %v", err)
	}
}

// TestGate_UnknownRouteRefusesUnlessForced proves an UNKNOWN-owned route is refused
// by default but the documented --force escape lets the operator proceed (after
// verifying ownership out-of-band).
func TestGate_UnknownRouteRefusesUnlessForced(t *testing.T) {
	// Default: refuse.
	e := foreignEngine(t, false, model.OwnUnknown, "")
	if _, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "app.example.com"), core.AlwaysYes); err == nil || !errors.Is(err, core.ErrRefuseToManage) {
		t.Fatalf("unknown-owned route must refuse without --force, got %v", err)
	}
	// With --force: the gate permits it; the mutation goes through and verifies.
	ef := foreignEngine(t, true, model.OwnUnknown, "")
	rep, err := ef.Apply(context.Background(), ef.BuildOp(model.Unexpose, "app.example.com"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("--force should let an unknown-owned mutation proceed, got %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Errorf("forced unexpose should apply + verify, got %+v", rep)
	}
}

// TestGate_CrenelOwnedStillMutable proves the gate is dormant for the safe-to-manage
// classes: a crenel-owned route unexposes cleanly (no false refusal).
func TestGate_CrenelOwnedStillMutable(t *testing.T) {
	e := foreignEngine(t, false, model.OwnCrenel, "")
	rep, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "app.example.com"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("a crenel-owned route must remain mutable, got %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Errorf("crenel-owned unexpose should apply + verify, got %+v", rep)
	}
}

// TestImport_RefusesForeignAdoptsClean proves import refuses to STAMP a marker onto a
// foreign-owned route (it would be regenerated away — itself a MISMANAGE) while a
// clean unmanaged route in the managed domain is still adoptable.
func TestImport_RefusesForeignAdoptsClean(t *testing.T) {
	stub := &gateStub{
		name: "caddy",
		addr: map[string]string{"app": "10.0.0.5:3000", "clean": "10.0.0.6:3000"},
		live: model.LiveEdgeState{DenyCatchAllPresent: true, Generator: "", Routes: []model.Route{
			{Host: "app.example.com", Ownership: model.OwnForeign,
				Upstream: model.Upstream{Kind: model.ForwardToOrigin, Address: "10.0.0.5:3000", ServerName: "app.example.com"}},
			{Host: "clean.example.com", Ownership: model.OwnUnmanaged,
				Upstream: model.Upstream{Kind: model.ForwardToOrigin, Address: "10.0.0.6:3000", ServerName: "clean.example.com"}},
		}},
	}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: stub}}, "example.com")

	plan, err := e.DetectImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// clean is adoptable; app (foreign) is NOT.
	adopt := map[string]bool{}
	for _, a := range plan.Adopt {
		adopt[a.Host] = true
	}
	if !adopt["clean.example.com"] || adopt["app.example.com"] {
		t.Errorf("clean must be adoptable and app must NOT, got %+v", plan.Adopt)
	}
	var foreignConflict bool
	for _, c := range plan.Conflicts {
		if c.Host == "app.example.com" && c.Reason == "foreign_managed" {
			foreignConflict = true
		}
	}
	if !foreignConflict {
		t.Errorf("app.example.com should be a foreign_managed conflict, got %+v", plan.Conflicts)
	}
}
