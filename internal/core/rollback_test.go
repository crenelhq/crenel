package core_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestRollback_DNSFailureRevertsEdge is the M1 headline: edge apply succeeds,
// then DNS push fails. The edge change must be rolled back so we don't leave a
// host exposed at the edge with no DNS (a partial, inconsistent apply).
func TestRollback_DNSFailureRevertsEdge(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(cf.URL(), res)

	sh := dnscontrolfake.New("example.com")
	sh.FailPush = true // DNS push will fail
	dns := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: sh,
	})
	e := core.New(edge, "example.com", dns)

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected apply to fail on DNS push")
	}
	if !rep.RolledBack {
		t.Error("expected RolledBack=true after partial failure")
	}
	if len(rep.RollbackErrors) != 0 {
		t.Errorf("rollback itself should succeed, got errors: %v", rep.RollbackErrors)
	}

	// The edge must be back to its prior state: photos NOT exposed, grafana yes,
	// deny present.
	st, _ := e.Status(context.Background())
	if contains(only(st).Routes, "photos.example.com") {
		t.Error("photos should have been rolled back off the edge")
	}
	if !contains(only(st).Routes, "grafana.example.com") {
		t.Error("grafana should remain exposed")
	}
	if !only(st).DenyCatchAllPresent {
		t.Error("default-deny must remain present after rollback")
	}
}

// TestRollback_UnexposeDNSFirstLeavesEdgeIntact verifies the M3 apply ORDERING
// for decreasing exposure: on unexpose, DNS is torn down BEFORE the edge route
// (public-DNS → edge). So when DNS removal fails first, the edge route is never
// touched — the world's name still resolves to a route that still serves it, a
// consistent prior state. Nothing was applied, so there is nothing to roll back.
func TestRollback_UnexposeDNSFirstLeavesEdgeIntact(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	edge := caddy.New(cf.URL(), res)

	sh := dnscontrolfake.New("example.com", model.Record{
		Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopePublic,
	})
	sh.FailPush = true
	dns := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "10.0.0.1", Shell: sh,
	})
	e := core.New(edge, "example.com", dns)

	op := e.BuildOp(model.Unexpose, "grafana")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected failure on DNS removal")
	}
	// DNS was the FIRST step and failed, so the edge was never mutated: there is
	// nothing applied to roll back, and the route remains up (consistent prior
	// state — we removed nothing, not a half-removed exposure).
	if rep.RolledBack {
		t.Error("no edge step ran before the failure, so nothing should roll back")
	}
	st, _ := e.Status(context.Background())
	if !contains(only(st).Routes, "grafana.example.com") {
		t.Error("edge route must remain intact when DNS teardown fails first")
	}
}

// TestRollback_DisabledLeavesPartialState confirms opting out of rollback leaves
// the partial state in place (and reports it was not rolled back).
func TestRollback_DisabledLeavesPartialState(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(cf.URL(), res)
	sh := dnscontrolfake.New("example.com")
	sh.FailPush = true
	dns := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: sh,
	})
	e := core.New(edge, "example.com", dns)
	e.Rollback = false

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected failure")
	}
	if rep.RolledBack {
		t.Error("rollback disabled: RolledBack should be false")
	}
	st, _ := e.Status(context.Background())
	if !contains(only(st).Routes, "photos.example.com") {
		t.Error("with rollback disabled, partial edge change should remain")
	}
}

func contains(routes []model.Route, host string) bool {
	for _, r := range routes {
		if r.Host == host {
			return true
		}
	}
	return false
}
