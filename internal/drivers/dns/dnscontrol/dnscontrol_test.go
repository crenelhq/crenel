package dnscontrol_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/model"
)

func newDriver(t *testing.T, sh dnscontrol.Shell) *dnscontrol.Driver {
	t.Helper()
	return dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com",
		Scope:    model.ScopeInternal,
		EdgeAddr: "10.0.0.1",
		Shell:    sh,
	})
}

func TestRenderTagsInsideOutside(t *testing.T) {
	// Internal scope -> !inside; public -> !outside. We verify via the fake
	// round-trip: push an internal record, read it back with correct scope.
	sh := dnscontrolfake.New("example.com")
	d := newDriver(t, sh)
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Add) != 1 {
		t.Fatalf("expected 1 add, got %+v", change)
	}
	if !strings.Contains(change.Rendered, "CREATE") {
		t.Errorf("preview text should mention CREATE: %q", change.Rendered)
	}

	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}
	live, err := d.LiveRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].Name != "grafana.example.com" || live[0].Scope != model.ScopeInternal {
		t.Fatalf("unexpected live records: %+v", live)
	}
}

func TestPublicScopeTag(t *testing.T) {
	sh := dnscontrolfake.New("example.com")
	d := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.5", Shell: sh,
	})
	ctx := context.Background()
	op := model.Op{Verb: model.Expose, Service: "vault", Host: "vault.example.com"}
	desired, _ := d.DesiredRecords(op)
	change, _ := d.Diff(ctx, op, desired)
	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}
	live, _ := d.LiveRecords(ctx)
	if len(live) != 1 || live[0].Scope != model.ScopePublic {
		t.Fatalf("expected one public record, got %+v", live)
	}
}

func TestDiffUnexposeRemoves(t *testing.T) {
	sh := dnscontrolfake.New("example.com", model.Record{
		Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal,
	})
	d := newDriver(t, sh)
	ctx := context.Background()
	op := model.Op{Verb: model.Unexpose, Service: "grafana", Host: "grafana.example.com"}
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Remove) != 1 {
		t.Fatalf("expected 1 remove, got %+v", change)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}
	if sh.LiveCount() != 0 {
		t.Errorf("record should be gone after unexpose push, have %d", sh.LiveCount())
	}
}

func TestExposeAlreadyPresentIsNoDiff(t *testing.T) {
	sh := dnscontrolfake.New("example.com", model.Record{
		Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal,
	})
	d := newDriver(t, sh)
	ctx := context.Background()
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}
	desired, _ := d.DesiredRecords(op)
	change, _ := d.Diff(ctx, op, desired)
	if !change.Empty() {
		t.Errorf("re-exposing existing record should be empty diff, got %+v", change)
	}
}

// The whole-zone push is refused when the live zone holds a record Crenel cannot
// faithfully re-render (here an MX), protecting it from deletion/corruption.
func TestPushRefusedOnUnrepresentableRecord(t *testing.T) {
	sh := dnscontrolfake.New("example.com", model.Record{
		Name: "example.com", Type: "MX", Value: "10 mail.example.com", Scope: model.ScopeInternal,
	})
	d := newDriver(t, sh)
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(context.Background(), op, desired); err == nil || !strings.Contains(err.Error(), "refusing to push") {
		t.Fatalf("expected refuse-to-push on an MX-bearing zone, got %v", err)
	}
}

func TestPushFailurePropagates(t *testing.T) {
	sh := dnscontrolfake.New("example.com")
	sh.FailPush = true
	d := newDriver(t, sh)
	ctx := context.Background()
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}
	desired, _ := d.DesiredRecords(op)
	change, _ := d.Diff(ctx, op, desired)
	if err := d.Apply(ctx, change); err == nil {
		t.Error("expected push failure to propagate")
	}
}
