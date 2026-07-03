package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// managedRoute is an httpRoute crenel physically wrote (OwnCrenel) — the durability-
// relevant case (a restart of an ephemeral edge would drop it).
func managedRoute(host string) model.Route {
	r := httpRoute(host)
	r.Managed = true
	r.Ownership = model.OwnCrenel
	return r
}

// TestAudit_EphemeralEdgeWithManagedRoutesWarns proves the read-time durability net:
// an ephemeral edge that carries crenel-managed routes (something a restart would lose)
// raises the ephemeral_writes warning.
func TestAudit_EphemeralEdgeWithManagedRoutesWarns(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Persistence:         model.PersistEphemeralAdmin,
		Routes:              []model.Route{managedRoute("grafana.example.com")},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "ephemeral_writes")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected ephemeral_writes warning, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "restart") {
		t.Errorf("message should explain the restart loss, got %q", f.Message)
	}
}

// TestAudit_EphemeralEdgeNoManagedRoutesIsQuiet proves no cry-wolf: a brownfield
// ephemeral edge crenel only READS (no crenel-managed routes) has nothing ephemeral of
// its own — the operator's config persists their routes — so no warning fires.
func TestAudit_EphemeralEdgeNoManagedRoutesIsQuiet(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Persistence:         model.PersistEphemeralAdmin,
		Routes:              []model.Route{httpRoute("legacy.example.com")}, // unmanaged
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "ephemeral_writes"); ok {
		t.Errorf("must NOT warn ephemeral on a read-only brownfield edge, got %+v", rep.Findings)
	}
}

// TestAudit_DurableEdgeNoEphemeralWarning proves a durable edge (file provider /
// reconciled-to-disk) never raises the ephemeral warning even with managed routes.
func TestAudit_DurableEdgeNoEphemeralWarning(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Persistence:         model.PersistDurableFile,
		Routes:              []model.Route{managedRoute("grafana.example.com")},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "ephemeral_writes"); ok {
		t.Errorf("durable edge must not warn ephemeral, got %+v", rep.Findings)
	}
}

// TestStatus_PersistenceFlowsThrough proves the durability posture reaches EdgeStatus
// so the CLI can render the DURABILITY line.
func TestStatus_PersistenceFlowsThrough(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Persistence:         model.PersistEphemeralAdmin,
		Routes:              []model.Route{managedRoute("grafana.example.com")},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Edges[0].Persistence; got != model.PersistEphemeralAdmin {
		t.Errorf("EdgeStatus.Persistence = %q, want ephemeral-admin", got)
	}
}

// TestApply_EphemeralEdgeDeclaresWriteNotDurable proves the WRITE-path declaration: a
// real expose against a bare Caddy admin edge (no persist path → ephemeral-admin) is
// applied + verified LIVE, but the report carries a PersistWarning that the write will
// not survive a restart. This is the write-time analogue of the audit finding, via the
// real driver's ports.DurabilityReporter.
func TestApply_EphemeralEdgeDeclaresWriteNotDurable(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	e := newEngine(t, fake) // bare admin caddy, no persist path

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified LIVE, got %+v", rep)
	}
	var found bool
	for _, w := range rep.PersistWarnings {
		if strings.Contains(w, "EPHEMERAL") && strings.Contains(w, "restart") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an ephemeral write-path declaration, got %v", rep.PersistWarnings)
	}
}
