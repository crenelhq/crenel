package core_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestCore_DrivesTraefikEdge proves the EdgeProvider port holds for a SECOND,
// structurally-different edge: core (unchanged) drives the Traefik file-provider
// driver end-to-end — plan, apply, read-back-verify, structural default-deny —
// exactly as it drives Caddy. This is the de-risking the second driver exists to
// provide: the abstraction is real, not Caddy-shaped.
func TestCore_DrivesTraefikEdge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	edge := traefik.New(path, res)

	// Pair it with a public DNS provider to confirm cross-provider ordering also
	// works over the second edge.
	pub := dnscontrolfake.New("example.com")
	dns := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pub,
	})
	e := core.New(edge, "example.com", dns)
	e.AllowUnverified = true // no runtime probe configured; not what this test is about
	ctx := context.Background()

	// Expose.
	op := e.BuildOp(model.Expose, "grafana")
	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("expose over traefik failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expose should apply+verify over traefik, got %+v", rep)
	}
	if len(rep.NewPublic) != 1 || rep.NewPublic[0] != "grafana.example.com" {
		t.Errorf("public DNS should drive NewPublic over traefik too, got %v", rep.NewPublic)
	}
	st, _ := e.Status(ctx)
	if !only(st).DenyCatchAllPresent {
		t.Error("default-deny invariant must hold on the traefik edge")
	}

	// Unexpose — verifies removal + deny stays.
	rep2, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose over traefik failed: %v", err)
	}
	if !rep2.Verified() {
		t.Fatalf("unexpose should verify over traefik, got %+v", rep2)
	}
	st2, _ := e.Status(ctx)
	if len(only(st2).Routes) != 0 || !only(st2).DenyCatchAllPresent {
		t.Errorf("after unexpose: nothing exposed, deny present; got %+v", st2)
	}
}
