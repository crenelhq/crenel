package adguard_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/model"
)

const (
	zone = "homelab.example"
	edge = "10.0.0.13" // the internal home Caddy
)

func newAG(doer adguard.Doer) *adguard.Driver {
	return adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge, Doer: doer})
}

func exposeOp() model.Op {
	return model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana." + zone}
}

func TestAdguardExposeAddsRewrite(t *testing.T) {
	fake := adguardfake.New()
	d := newAG(fake)
	ctx := context.Background()

	op := exposeOp()
	desired, err := d.DesiredRecords(op)
	if err != nil {
		t.Fatal(err)
	}
	if desired[0].Type != "A" || desired[0].Value != edge {
		t.Fatalf("desired record wrong: %+v", desired)
	}
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Add) != 1 {
		t.Fatalf("expected 1 add, got %+v", change)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}
	if got := fake.List()["grafana."+zone]; got != edge {
		t.Errorf("rewrite not applied: %v", fake.List())
	}
}

func TestAdguardExposeIsIdempotent(t *testing.T) {
	fake := adguardfake.New("grafana."+zone, edge) // already present, exactly right
	d := newAG(fake)
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(context.Background(), op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !change.Empty() {
		t.Errorf("re-expose of an identical rewrite should be a no-op, got %+v", change)
	}
}

func TestAdguardConflictRefusesOverwrite(t *testing.T) {
	// Same domain, DIFFERENT answer already present -> ambiguous split-horizon.
	fake := adguardfake.New("grafana."+zone, "192.168.1.99")
	d := newAG(fake)
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "conflicting rewrite") {
		t.Fatalf("expected conflict error, got %v", err)
	}
	if fake.Adds != 0 {
		t.Errorf("a conflict must not add anything, Adds=%d", fake.Adds)
	}
}

func TestAdguardUnexposeRemovesRewrite(t *testing.T) {
	fake := adguardfake.New("grafana."+zone, edge)
	d := newAG(fake)
	ctx := context.Background()
	op := model.Op{Verb: model.Unexpose, Service: "grafana", Host: "grafana." + zone}
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
	if fake.Count() != 0 {
		t.Errorf("rewrite should be gone, have %v", fake.List())
	}
}

// THE dangerous case: AdGuard itself would accept an out-of-zone domain (it has no
// zones), hijacking e.g. www.smallbiz.example. The DRIVER must refuse BEFORE any call
// reaches AdGuard.
func TestAdguardRefusesOutOfZoneDomain(t *testing.T) {
	fake := adguardfake.New()
	d := newAG(fake)
	op := model.Op{Verb: model.Expose, Service: "www", Host: "www.smallbiz.example"}
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "outside the managed zone") {
		t.Fatalf("expected out-of-zone refusal, got %v", err)
	}
	if fake.Adds != 0 || fake.Count() != 0 {
		t.Errorf("an out-of-zone op must reach AdGuard with NO write (Adds=%d, live=%d)", fake.Adds, fake.Count())
	}
}

func TestAdguardRefusesWildcard(t *testing.T) {
	fake := adguardfake.New()
	d := newAG(fake)
	op := model.Op{Verb: model.Expose, Service: "wild", Host: "*." + zone}
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(context.Background(), op, desired); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard refusal, got %v", err)
	}
}

func TestAdguardSurfacesAuthFailure(t *testing.T) {
	fake := adguardfake.New()
	fake.Unauthorized = true
	d := newAG(fake)
	if _, err := d.LiveRecords(context.Background()); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 401 auth failure, got %v", err)
	}
}

func TestAdguardSurfacesRateLimit(t *testing.T) {
	fake := adguardfake.New()
	fake.RateLimited = true
	d := newAG(fake)
	if _, err := d.LiveRecords(context.Background()); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected 429 rate limit, got %v", err)
	}
}

// The fake faithfully rejects an exact-duplicate add with 400 (recent AdGuard),
// matching the documented rejection. The driver's own dedupe means this is reached
// only on a direct POST, which is what we exercise here.
func TestAdguardFakeRejectsDuplicateAdd(t *testing.T) {
	fake := adguardfake.New("grafana."+zone, edge)
	body := []byte(`{"domain":"grafana.` + zone + `","answer":"` + edge + `"}`)
	status, _, err := fake.Do(context.Background(), "POST", "/control/rewrite/add", body)
	if err != nil {
		t.Fatal(err)
	}
	if status != 400 {
		t.Fatalf("exact-duplicate add should be 400, got %d", status)
	}
}

// LiveRecords reports only rewrites under the managed zone — the operator's unrelated
// rewrites stay invisible (so status/audit never imply crenel manages them).
func TestAdguardLiveRecordsScopedToZone(t *testing.T) {
	fake := adguardfake.New(
		"grafana."+zone, edge, // in-zone
		"unrelated.example.org", "1.2.3.4", // out-of-zone
	)
	d := newAG(fake)
	recs, err := d.LiveRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "grafana."+zone {
		t.Fatalf("expected only the in-zone rewrite, got %+v", recs)
	}
}

// TestAdguardNameInstanceLabel: a bare driver is "adguard"; one given an Instance is
// "adguard[<instance>]" so two same-scope providers are distinguishable everywhere a
// provider label is built (plan/apply/verify/audit + the conflict/guard errors).
func TestAdguardNameInstanceLabel(t *testing.T) {
	if got := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge}).Name(); got != "adguard" {
		t.Errorf("bare instance: want %q, got %q", "adguard", got)
	}
	if got := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge, Instance: "home"}).Name(); got != "adguard[home]" {
		t.Errorf("labeled instance: want %q, got %q", "adguard[home]", got)
	}
}

// TestAdguardPerInstanceOwnershipRefusesForeign proves the dual-resolver invariant: each
// AdGuard instance owns/guards its rewrites INDEPENDENTLY against its own endpoint. The
// SAME expose hits two instances with different live state — the "vps" instance already
// carries a FOREIGN rewrite for the host (a different answer), the "home" instance does
// not:
//   - the vps instance REFUSES (conflict) and writes nothing, and the error names the
//     instance ("adguard[vps]") so the operator knows WHICH resolver is blocked;
//   - the home instance, evaluated independently, plans the add cleanly.
//
// (RED before the per-instance Name(): the conflict error read a bare "adguard:", so the
// instance attribution this asserts did not exist.)
func TestAdguardPerInstanceOwnershipRefusesForeign(t *testing.T) {
	ctx := context.Background()
	host := "grafana." + zone

	// vps resolver: a foreign rewrite already points the host elsewhere (vantage target).
	vpsFake := adguardfake.New(host, "10.9.9.9")
	vps := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge, Instance: "vps", Doer: vpsFake})
	// home resolver: clean; same op, independent live state.
	homeFake := adguardfake.New()
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge, Instance: "home", Doer: homeFake})

	op := exposeOp()
	desired, _ := vps.DesiredRecords(op)

	// vps refuses the foreign overwrite and names itself.
	if _, err := vps.Diff(ctx, op, desired); err == nil ||
		!strings.Contains(err.Error(), "conflicting rewrite") ||
		!strings.Contains(err.Error(), "adguard[vps]") {
		t.Fatalf("vps instance should refuse foreign overwrite and name itself, got %v", err)
	}
	if vpsFake.Adds != 0 {
		t.Errorf("a conflict must not add anything on vps, Adds=%d", vpsFake.Adds)
	}

	// home, evaluated independently against its own (empty) live state, plans the add.
	change, err := home.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("home instance should plan a clean add independently, got %v", err)
	}
	if len(change.Add) != 1 || change.Add[0].Name != host {
		t.Fatalf("home should add the host independently, got %+v", change)
	}
}

// --- residency selector (per-host targets; docs/REFERENCE-ARCH-split-horizon.md §2) ---

// TestResidencyTarget_Contract pins the driver-side resolver contract: the empty
// class is the home-resident default (EdgeAddr, back-compat), a configured class
// resolves to THIS instance's vantage target, and a missing class is a loud,
// instance-naming refusal — never a silent EdgeAddr fallback.
func TestResidencyTarget_Contract(t *testing.T) {
	d := adguard.New(adguard.Config{
		Zone: "example.com", EdgeAddr: "10.0.0.13", Instance: "home",
		Targets: map[string]string{"vps": "203.0.113.9"},
	})
	if got, err := d.ResidencyTarget(""); err != nil || got != "10.0.0.13" {
		t.Errorf("default class must resolve to EdgeAddr: got %q, %v", got, err)
	}
	if got, err := d.ResidencyTarget("vps"); err != nil || got != "203.0.113.9" {
		t.Errorf("vps class must resolve to the configured target: got %q, %v", got, err)
	}
	_, err := d.ResidencyTarget("edge-resident")
	if err == nil {
		t.Fatal("an unconfigured class must refuse")
	}
	if !strings.Contains(err.Error(), "adguard[home]") || !strings.Contains(err.Error(), `"edge-resident"`) {
		t.Errorf("refusal must name the instance and the class: %v", err)
	}
}

// TestDesiredRecords_ResidencyResolved: DesiredRecords carries the residency-
// resolved value (and infers the record type from IT, not from EdgeAddr).
func TestDesiredRecords_ResidencyResolved(t *testing.T) {
	d := adguard.New(adguard.Config{
		Zone: "example.com", EdgeAddr: "10.0.0.13",
		Targets: map[string]string{"vps": "2001:db8::9"},
	})
	recs, err := d.DesiredRecords(model.Op{Verb: model.Expose, Host: "vault.example.com", Residency: "vps"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Value != "2001:db8::9" || recs[0].Type != "AAAA" {
		t.Errorf("expected one AAAA record at the residency target, got %+v", recs)
	}
}
