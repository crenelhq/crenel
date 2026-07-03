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

// newUnifiedEngine wires a fake Caddy edge + a fake-shell dnscontrol DNS provider
// (internal scope) so we can exercise the unified ChangeSet end to end.
func newUnifiedEngine(t *testing.T) (*core.Engine, *dnscontrolfake.Shell) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(seedGrafana)

	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(cf.URL(), res)

	sh := dnscontrolfake.New("example.com")
	dns := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: sh,
	})
	return core.New(edge, "example.com", dns), sh
}

func TestUnified_PlanAggregatesEdgeAndDNS(t *testing.T) {
	e, _ := newUnifiedEngine(t)
	op := e.BuildOp(model.Expose, "photos")
	cs, err := e.Plan(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edges) != 1 || len(cs.Edges[0].Change.AddRoutes) != 1 {
		t.Errorf("expected 1 edge add, got %+v", cs.Edges)
	}
	if len(cs.DNS) != 1 || len(cs.DNS[0].Add) != 1 {
		t.Errorf("expected 1 DNS add, got %+v", cs.DNS)
	}
}

func TestUnified_ApplyVerifiesBothProviders(t *testing.T) {
	e, sh := newUnifiedEngine(t)
	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("both providers should verify, got %+v", rep.Verify)
	}
	if len(rep.Verify) != 2 {
		t.Errorf("expected verify results for edge + dns, got %d", len(rep.Verify))
	}
	// DNS record actually pushed.
	if sh.LiveCount() != 1 {
		t.Errorf("expected 1 live DNS record after apply, got %d", sh.LiveCount())
	}
	// Status reflects both.
	st, _ := e.Status(context.Background())
	if !only(st).DenyCatchAllPresent || len(st.DNS) != 1 || len(st.DNS[0].Records) != 1 {
		t.Errorf("status missing unified state: %+v", st)
	}
}
