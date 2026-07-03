package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// Reconcile is the "detect + fix ALL drift" verb. It matched records by Key (scope/type/
// NAME) only, so a crenel-OWNED record present at the right name but pointing at the WRONG
// target read as "converged" — reconcile left it silently misdirecting. These tests cover
// the value-drift detection + correction (DriftValueDNS), scoped to owned records so it
// never clobbers a legitimately-foreign record on a marker-less provider.

// TestReconcile_OwnedDNSValueDriftIsDetectedAndCorrected is the RED→GREEN headline: a
// surgical-Cloudflare-owned record for an EXPOSED host points at the wrong IP; reconcile
// must flag DriftValueDNS and re-assert crenel's configured target.
func TestReconcile_OwnedDNSValueDriftIsDetectedAndCorrected(t *testing.T) {
	ctx := context.Background()

	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile("app.crenel.sh {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	origins := map[string]string{"app": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(origins)), Fronts: frontsFor(origins)}

	// Owned (marked) record at the WRONG value; configured edge target is 203.0.113.9.
	fake := cfapifake.New("crenel.sh", "zone1", cfapifake.Record{
		Type: "A", Name: "app.crenel.sh", Content: "203.0.113.99", // DRIFTED
		Comment: cloudflare.MarkerPrefix + " host=app",
	})
	cfd := cloudflare.New(cloudflare.Config{
		ZoneName: "crenel.sh", ZoneID: "zone1", Scope: model.ScopePublic,
		EdgeAddr: "203.0.113.9", Doer: fake,
	})
	e := core.NewMulti([]core.EdgeBinding{home}, "crenel.sh", cfd)

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if n := driftCount(rep, core.DriftValueDNS); n != 1 {
		t.Fatalf("expected 1 wrong_dns_target drift, got %d (drift=%+v)", n, rep.Plan.Drift)
	}
	if rep.Converged {
		t.Fatal("there WAS value drift; reconcile must not report converged")
	}
	// The record value must now be corrected to the configured edge target.
	var got string
	for _, r := range fake.Records() {
		if strings.EqualFold(r.Name, "app.crenel.sh") {
			got = r.Content
		}
	}
	if got != "203.0.113.9" {
		t.Errorf("reconcile should have re-asserted the value to 203.0.113.9, got %q", got)
	}
}

// TestReconcile_MarkerlessDNSValueDriftIsNotTouched proves the cry-wolf scoping: a value
// mismatch on a provider that does NOT prove ownership (the marker-less dnscontrol/AdGuard
// case) is NOT flagged as DriftValueDNS and the record is left untouched — reconcile must
// not clobber what could be a legitimately-foreign record.
func TestReconcile_MarkerlessDNSValueDriftIsNotTouched(t *testing.T) {
	ctx := context.Background()

	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile("app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	origins := map[string]string{"app": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(origins)), Fronts: frontsFor(origins)}

	// dnscontrol is marker-less: it does not implement ports.OwnedRecordReporter, so a
	// value mismatch must NOT trigger a value-correction.
	sh := dnscontrolfake.New("example.com", model.Record{
		Name: "app.example.com", Type: "A", Value: "10.0.0.99", Scope: model.ScopeInternal, // mismatch vs EdgeAddr
	})
	dns := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.13", Shell: sh})
	e := core.NewMulti([]core.EdgeBinding{home}, "example.com", dns)

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if n := driftCount(rep, core.DriftValueDNS); n != 0 {
		t.Errorf("a marker-less provider must NOT raise wrong_dns_target (no cry-wolf), got %d: %+v", n, rep.Plan.Drift)
	}
}
