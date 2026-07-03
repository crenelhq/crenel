package dnscontrol_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/cloudflarefake"
	"github.com/crenelhq/crenel/internal/model"
)

func newCFDedicated(t *testing.T, sh dnscontrol.Shell, zone, token string) *dnscontrol.Driver {
	t.Helper()
	return dnscontrol.New(dnscontrol.Config{
		ZoneName: zone, Scope: model.ScopePublic, EdgeAddr: "203.0.113.5", Shell: sh,
		DedicatedZone: true,
		Provider:      dnscontrol.Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": token}},
	})
}

func cfExpose(host string) model.Op {
	return model.Op{Verb: model.Expose, Service: "x", Host: host}
}

// GAP 1: a zone whose only record is a foreign load-bearing wildcard (the real
// homelab.example shape) must be REFUSED on a non-dedicated provider — crenel would
// otherwise become whole-zone authoritative over a record it does not own. The SAME
// zone is allowed once dedicated_zone is set.
func TestLoneWildcardRefusedUnlessDedicated(t *testing.T) {
	wildcard := model.Record{Name: "*.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic}
	op := cfExpose("svc.example.com")
	ctx := context.Background()

	// NON-dedicated -> refuse, no push.
	cf := cloudflarefake.New("example.com", wildcard)
	cf.AcceptToken = "t"
	d := newCF(t, cf, "example.com", "t")
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(ctx, op, desired); err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("lone-wildcard non-dedicated must be refused, got %v", err)
	}
	if cf.Pushes != 0 || cf.LiveCount() != 1 {
		t.Errorf("a refused plan must not push (pushes=%d live=%d)", cf.Pushes, cf.LiveCount())
	}

	// dedicated_zone:true -> allowed; push proceeds, wildcard preserved + svc added.
	cf2 := cloudflarefake.New("example.com", wildcard)
	cf2.AcceptToken = "t"
	d2 := newCFDedicated(t, cf2, "example.com", "t")
	desired2, _ := d2.DesiredRecords(op)
	change, err := d2.Diff(ctx, op, desired2)
	if err != nil {
		t.Fatalf("dedicated zone must be allowed: %v", err)
	}
	if err := d2.Apply(ctx, change); err != nil {
		t.Fatalf("dedicated apply: %v", err)
	}
	if cf2.LiveCount() != 2 {
		t.Errorf("dedicated push should preserve the wildcard + add svc (live=%d, want 2)", cf2.LiveCount())
	}
}

// First-expose onto an EMPTY zone is allowed without dedicated_zone (nothing foreign).
func TestEmptyZoneAllowedWithoutDedicated(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "t"
	d := newCF(t, cf, "example.com", "t")
	ctx := context.Background()
	op := cfExpose("svc.example.com")
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("first-expose onto an empty zone must be allowed: %v", err)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// Unexpose / re-expose of crenel's OWN host must work without dedicated_zone — the op's
// own record is never "foreign", even though it is pre-existing.
func TestOwnRecordOpsAllowedWithoutDedicated(t *testing.T) {
	own := model.Record{Name: "svc.example.com", Type: "A", Value: "203.0.113.5", Scope: model.ScopePublic}
	ctx := context.Background()

	// unexpose own record
	cf := cloudflarefake.New("example.com", own)
	cf.AcceptToken = "t"
	d := newCF(t, cf, "example.com", "t")
	un := model.Op{Verb: model.Unexpose, Service: "x", Host: "svc.example.com"}
	desired, _ := d.DesiredRecords(un)
	change, err := d.Diff(ctx, un, desired)
	if err != nil {
		t.Fatalf("unexpose of own record must be allowed: %v", err)
	}
	if len(change.Remove) != 1 {
		t.Fatalf("expected 1 remove, got %+v", change)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cf.LiveCount() != 0 {
		t.Errorf("own record should be gone after unexpose (live=%d)", cf.LiveCount())
	}

	// idempotent re-expose of own record (no foreign) -> no-op, allowed
	cf2 := cloudflarefake.New("example.com", own)
	cf2.AcceptToken = "t"
	d2 := newCF(t, cf2, "example.com", "t")
	re := cfExpose("svc.example.com")
	desired2, _ := d2.DesiredRecords(re)
	if _, err := d2.Diff(ctx, re, desired2); err != nil {
		t.Fatalf("idempotent re-expose of own record must be allowed: %v", err)
	}
}

// Finding #2: an already-correct managed record (host2) must NOT be flagged foreign
// when the change carries the FULL managed set (the reconcile/declarative shape), even
// though host2 is not in the Add/Remove delta. (Apply must gate on change.Managed, not
// the bare delta.)
func TestApplyRecognizesFullManagedSet(t *testing.T) {
	cf := cloudflarefake.New("example.com", model.Record{Name: "host2.example.com", Type: "A", Value: "203.0.113.5", Scope: model.ScopePublic})
	cf.AcceptToken = "t"
	d := newCF(t, cf, "example.com", "t") // NON-dedicated; EdgeAddr 203.0.113.5
	rec := func(n string) model.Record {
		return model.Record{Name: n, Type: "A", Value: "203.0.113.5", Scope: model.ScopePublic}
	}
	// reconcile-shape: add the missing host1; Managed carries BOTH canonical hosts.
	change := model.DNSChange{
		Scope:   model.ScopePublic,
		Add:     []model.Record{rec("host1.example.com")},
		Managed: []model.Record{rec("host1.example.com"), rec("host2.example.com")},
	}
	if err := d.Apply(context.Background(), change); err != nil {
		t.Fatalf("the full managed set must let an already-present managed record pass: %v", err)
	}
	if cf.LiveCount() != 2 {
		t.Errorf("host1 (added) + host2 (preserved) should both be live, got %d", cf.LiveCount())
	}
}

// GAP 2 end-to-end: a proxied, pinned-TTL SIBLING that crenel REPRODUCES (carries
// through a whole-zone push without changing) must keep its TTL + proxied state across
// the full render -> push -> get-zones -> parse round-trip.
func TestReproducedRecordKeepsTTLAndProxied(t *testing.T) {
	sibling := model.Record{Name: "www.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic, TTL: 300, Proxied: true}
	cf := cloudflarefake.New("example.com", sibling)
	cf.AcceptToken = "t"
	d := newCFDedicated(t, cf, "example.com", "t") // dedicated: the sibling is owned-zone data
	ctx := context.Background()

	op := cfExpose("api.example.com")
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}

	live, err := d.LiveRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range live {
		if r.Name == "www.example.com" {
			found = true
			if r.TTL != 300 || !r.Proxied {
				t.Errorf("reproduced sibling lost TTL/proxied through the push: %+v", r)
			}
		}
	}
	if !found {
		t.Error("the reproduced sibling vanished after the whole-zone push")
	}
}
