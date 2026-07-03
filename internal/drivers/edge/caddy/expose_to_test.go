package caddy_test

import (
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestPlan_ExposeWithTo_OverridesResolver: Op.To is the explicit backend the
// operator typed as `crenel expose <svc> --to <host:port>`. Plan MUST use it
// verbatim (no resolver call), so the hero command works before the service
// has been pre-declared in the origins map.
func TestPlan_ExposeWithTo_OverridesResolver(t *testing.T) {
	d := caddy.New("http://unused", resolver()) // resolver KNOWS grafana/photos, NOT "immich"
	live := model.LiveEdgeState{DenyCatchAllPresent: true}
	op := model.Op{
		Verb:    model.Expose,
		Service: "immich",
		Host:    "photos.example.com",
		To:      "10.0.0.99:2283",
	}
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatalf("Plan(--to) must succeed for a service NOT in origins: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 {
		t.Fatalf("expected one add-route, got %+v", cs.Edge.AddRoutes)
	}
	if got, want := cs.Edge.AddRoutes[0].Upstream.Address, "10.0.0.99:2283"; got != want {
		t.Errorf("upstream address = %q, want %q (--to backend)", got, want)
	}
}

// TestPlan_ExposeWithTo_UnknownServiceStillWorks: the whole point of --to is
// that a service NOT pre-declared in origins can still be exposed. With no --to,
// planning must fail (the pre-flag behavior); with --to, it must succeed.
func TestPlan_ExposeWithTo_UnknownServiceStillWorks(t *testing.T) {
	empty := static.New(map[string]string{}) // empty origins
	d := caddy.New("http://unused", empty)
	live := model.LiveEdgeState{DenyCatchAllPresent: true}

	// Without --to: fails (this is the pre-launch UX we're fixing).
	if _, err := d.Plan(model.Op{Verb: model.Expose, Service: "immich", Host: "photos.example.com"}, live); err == nil {
		t.Fatal("without --to, an unknown service must still fail (pre-flag path unchanged)")
	}
	// With --to: succeeds.
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "immich", Host: "photos.example.com", To: "immich:2283"}, live)
	if err != nil {
		t.Fatalf("with --to, planning must succeed for an unknown service: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 || !strings.HasSuffix(cs.Edge.AddRoutes[0].Upstream.Address, ":2283") {
		t.Errorf("expected --to backend on the planned route, got %+v", cs.Edge.AddRoutes)
	}
}

// TestPlan_ExposeWithoutTo_UnchangedFallsThroughToResolver: pre-declared
// origins still work exactly as before when --to is absent. This is the
// existing-users-must-not-break guarantee.
func TestPlan_ExposeWithoutTo_UnchangedFallsThroughToResolver(t *testing.T) {
	d := caddy.New("http://unused", resolver())
	live := model.LiveEdgeState{DenyCatchAllPresent: true}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cs.Edge.AddRoutes[0].Upstream.Address, "10.0.0.6:2342"; got != want {
		t.Errorf("resolver path regressed: got %q want %q", got, want)
	}
}
