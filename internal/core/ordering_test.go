package core_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// recEdge / recDNS wrap a real provider and append a label to a shared log when
// Apply is called, so a test can assert the ORDER providers were applied in.

type recEdge struct {
	ports.EdgeProvider
	log *[]string
}

func (r recEdge) Apply(ctx context.Context, cs model.ChangeSet) error {
	*r.log = append(*r.log, "edge")
	return r.EdgeProvider.Apply(ctx, cs)
}

type recDNS struct {
	ports.DNSProvider
	log *[]string
}

func (r recDNS) Apply(ctx context.Context, ch model.DNSChange) error {
	*r.log = append(*r.log, "dns/"+string(r.DNSProvider.Scope()))
	return r.DNSProvider.Apply(ctx, ch)
}

// newOrderingEngine wires a fake Caddy edge + internal + public dnscontrol fakes,
// each wrapped to record apply order. seedExposed controls whether grafana is
// already exposed (edge route + both DNS records) so unexpose has work to do.
func newOrderingEngine(t *testing.T, log *[]string, seedExposed bool) (*core.Engine, *dnscontrolfake.Shell, *dnscontrolfake.Shell) {
	t.Helper()
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	if seedExposed {
		cf.SeedCaddyfile(seedGrafana)
	} else {
		cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	}
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := recEdge{EdgeProvider: caddy.New(cf.URL(), res), log: log}

	var inSeed, pubSeed []model.Record
	if seedExposed {
		inSeed = []model.Record{{Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal}}
		pubSeed = []model.Record{{Name: "grafana.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic}}
	}
	inSh := dnscontrolfake.New("example.com", inSeed...)
	pubSh := dnscontrolfake.New("example.com", pubSeed...)
	internal := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: inSh,
	}), log: log}
	public := recDNS{DNSProvider: dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.9", Shell: pubSh,
	}), log: log}

	return core.New(edge, "example.com", internal, public), inSh, pubSh
}

// TestApplyOrdering_ExposeBringsUpEdgeBeforeAnnouncingPublic asserts increasing
// exposure applies low→high rank: edge first, public DNS LAST.
func TestApplyOrdering_ExposeBringsUpEdgeBeforeAnnouncingPublic(t *testing.T) {
	var log []string
	e, _, _ := newOrderingEngine(t, &log, false)

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("all three providers should verify, got %+v", rep.Verify)
	}
	want := []string{"edge", "dns/internal", "dns/public"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("expose order: got %v, want %v", log, want)
	}
	// The hero highlight: the host is "about to go public" via the public record.
	if len(rep.NewPublic) != 1 || rep.NewPublic[0] != "photos.example.com" {
		t.Errorf("NewPublic should flag the public host, got %v", rep.NewPublic)
	}
}

// TestApplyOrdering_UnexposeStopsAnnouncingBeforeTearingDownEdge asserts
// decreasing exposure applies high→low rank: public DNS first, edge LAST.
func TestApplyOrdering_UnexposeStopsAnnouncingBeforeTearingDownEdge(t *testing.T) {
	var log []string
	e, _, _ := newOrderingEngine(t, &log, true)

	op := e.BuildOp(model.Unexpose, "grafana")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("all three providers should verify, got %+v", rep.Verify)
	}
	want := []string{"dns/public", "dns/internal", "edge"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("unexpose order: got %v, want %v", log, want)
	}
	// Decreasing exposure: nothing is "going public".
	if len(rep.NewPublic) != 0 {
		t.Errorf("unexpose should flag nothing public, got %v", rep.NewPublic)
	}
}

// TestUnified_ExposeAggregatesThreeProviders proves one ChangeSet carries the
// edge add, the internal-DNS add, and the public-DNS add — the unified plan.
func TestUnified_ExposeAggregatesThreeProviders(t *testing.T) {
	var log []string
	e, inSh, pubSh := newOrderingEngine(t, &log, false)

	op := e.BuildOp(model.Expose, "photos")
	cs, err := e.Plan(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edges) != 1 || len(cs.Edges[0].Change.AddRoutes) != 1 {
		t.Errorf("expected 1 edge add, got %+v", cs.Edges)
	}
	// Positionally aligned: cs.DNS[0]=internal, cs.DNS[1]=public.
	if len(cs.DNS) != 2 {
		t.Fatalf("expected 2 DNS changes (internal+public), got %d", len(cs.DNS))
	}
	if cs.DNS[0].Scope != model.ScopeInternal || len(cs.DNS[0].Add) != 1 {
		t.Errorf("cs.DNS[0] should be the internal add, got %+v", cs.DNS[0])
	}
	if cs.DNS[1].Scope != model.ScopePublic || len(cs.DNS[1].Add) != 1 {
		t.Errorf("cs.DNS[1] should be the public add, got %+v", cs.DNS[1])
	}

	// Apply and confirm both DNS scopes were actually pushed.
	if _, err := e.Apply(context.Background(), op, core.AlwaysYes); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if inSh.LiveCount() != 1 || pubSh.LiveCount() != 1 {
		t.Errorf("expected 1 record each scope, got internal=%d public=%d", inSh.LiveCount(), pubSh.LiveCount())
	}
}
