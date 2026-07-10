package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole/piholefake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// The dns_coverage_parity audit: when two or more INTERNAL DNS providers are managed
// (a dual-resolver split-horizon — one AdGuard per vantage), a host present on one but
// missing from another is surfaced as a first-class drift finding. Coverage parity is
// about PRESENCE, not target value: each resolver may answer with its own vantage-correct
// address, but both must cover the same managed host set.

// TestAudit_DNSCoverageParity_DetectsDrift is the RED→GREEN headline: the "vps" resolver
// carries adguard.example.com (the live adguard.homelab.example asymmetry) while the
// "home" resolver does not. Without the cross-instance check this drift is invisible.
func TestAudit_DNSCoverageParity_DetectsDrift(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
		{Name: "adguard.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected dns_coverage_parity warning, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "adguard.example.com") ||
		!strings.Contains(f.Message, "adguard[vps]") ||
		!strings.Contains(f.Message, "adguard[home]") {
		t.Errorf("parity message should name the drifted host and both resolvers, got %q", f.Message)
	}
	// grafana is on BOTH internal resolvers — it must NOT be flagged as drift.
	if strings.Contains(f.Message, "grafana.example.com") {
		t.Errorf("grafana is covered on both resolvers; it must not appear in a parity finding: %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_InSyncNoFinding: identical coverage on both resolvers → no
// parity finding.
func TestAudit_DNSCoverageParity_InSyncNoFinding(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("resolvers are in coverage parity; no finding expected, got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_DifferentTargetsAreNotDrift encodes the vantage rule: the
// SAME host with DIFFERENT (vantage-correct) targets on the two resolvers is in coverage
// parity and must NOT be flagged — parity compares presence, never the answer value.
func TestAudit_DNSCoverageParity_DifferentTargetsAreNotDrift(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "vault.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopeInternal}, // public edge (no tunnel)
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "vault.example.com", Type: "A", Value: "100.100.0.2", Scope: model.ScopeInternal}, // tunnel-direct
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("same host with vantage-correct different targets is parity-clean; got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_RealAdguardDrivers exercises the WHOLE feature through the
// real AdGuard driver (not a stub): two adguard.New instances over faithful fakes, with
// distinct Instance labels and different live rewrite sets, wired into the engine. It
// proves the real LiveRecords zone-scoping + the instance-qualified Name() + the parity
// finding all compose — the vps resolver carries adguard.example.com that home lacks.
func TestAudit_DNSCoverageParity_RealAdguardDrivers(t *testing.T) {
	const zone = "example.com"
	homeFake := adguardfake.New("grafana."+zone, "10.0.0.13")
	vpsFake := adguardfake.New(
		"grafana."+zone, "10.0.0.13",
		"adguard."+zone, "203.0.113.9", // the asymmetric host (live drift)
		"unrelated.example.org", "9.9.9.9", // out-of-zone: LiveRecords must ignore it
	)
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: homeFake})
	vps := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "vps", Doer: vpsFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	edge := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	e := core.New(edge, zone, []ports.DNSProvider{home, vps}...)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected dns_coverage_parity warning from real drivers, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "adguard."+zone) ||
		!strings.Contains(f.Message, "adguard[vps]") ||
		!strings.Contains(f.Message, "adguard[home]") {
		t.Errorf("parity message should name the drifted host and both real instances, got %q", f.Message)
	}
	// The out-of-zone rewrite must NOT leak into parity (LiveRecords is zone-scoped).
	if strings.Contains(f.Message, "unrelated.example.org") {
		t.Errorf("out-of-zone rewrite leaked into the parity check: %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_WildcardCoversAdjacentHost is the headline cry-wolf fix
// pulled straight from the live drift incident: the audit flagged adguard.homelab.example as
// "on vps, missing on home" even though home's *.homelab.example wildcard rewrite already
// resolves it. A host is PRESENT on a resolver if either an explicit rewrite OR a wildcard
// rewrite there covers it. With matching targets, this must not be flagged as drift.
func TestAudit_DNSCoverageParity_WildcardCoversAdjacentHost(t *testing.T) {
	// home has ONLY a wildcard pointing at the home edge; vps has an explicit rewrite for
	// adguard.example.com pointing at the SAME target (both answers agree on value).
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
		{Name: "adguard.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("home's *.example.com wildcard covers adguard.example.com at the same value; this must not be flagged as drift, got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_WildcardLiteralNotInUnion: a wildcard rewrite is a PATTERN,
// not a host name. A `*.zone` present on one resolver but not on the other must not be
// flagged as a missing-host drift — the union of compared hosts is built from explicit
// rewrites only.
func TestAudit_DNSCoverageParity_WildcardLiteralNotInUnion(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("a wildcard pattern must not be compared as a host name; got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_WildcardValueMismatchStillDrift codifies the careful caveat:
// suppression only kicks in when the wildcard's substituted value actually matches the
// explicit answer on the other resolver. An explicit `host`→A on one resolver vs a
// covering wildcard→B (B ≠ A) on the other is NOT silently hidden — the wildcard answers
// the wrong target for that host and is still flagged as drift.
func TestAudit_DNSCoverageParity_WildcardValueMismatchStillDrift(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		// wildcard answers EVERY subdomain with 10.0.0.13 (the home edge),
		// including adguard.example.com — but vps's explicit says a different target.
		{Name: "*.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},   // matches wildcard value
		{Name: "adguard.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopeInternal}, // mismatched value
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected dns_coverage_parity warning for the adguard.example.com value mismatch, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "adguard.example.com") {
		t.Errorf("parity message should name the value-mismatched host, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "203.0.113.9") || !strings.Contains(f.Message, "10.0.0.13") {
		t.Errorf("parity message should name BOTH the explicit and wildcard values for diagnosability, got %q", f.Message)
	}
	if !strings.Contains(strings.ToLower(f.Message), "wildcard") {
		t.Errorf("parity message should clarify that the mismatch is a wildcard answering the wrong target, got %q", f.Message)
	}
	// Make sure grafana (wildcard value matches vps's explicit) is NOT flagged.
	if strings.Contains(f.Message, "grafana.example.com") {
		t.Errorf("grafana's wildcard value matches; it must not appear in a parity finding: %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_WildcardAware_RealAdguardDrivers exercises the wildcard
// suppression end-to-end through the REAL AdGuard driver (LiveRecords' zone scoping
// admits wildcards; the parity check must treat them as covering patterns, not as
// missing hosts). Mirrors the bit-us live shape: home's `*.example.com` rewrite covers
// adguard.example.com, vps holds the explicit one — both at the same value, so the
// audit must NOT flag drift.
func TestAudit_DNSCoverageParity_WildcardAware_RealAdguardDrivers(t *testing.T) {
	const zone = "example.com"
	// home: ONLY a wildcard rewrite — no explicit adguard. entry.
	homeFake := adguardfake.New("*."+zone, "10.0.0.13")
	vpsFake := adguardfake.New(
		"grafana."+zone, "10.0.0.13",
		"adguard."+zone, "10.0.0.13", // explicit, same answer as home's wildcard substitution
	)
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: homeFake})
	vps := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "vps", Doer: vpsFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	edge := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	e := core.New(edge, zone, []ports.DNSProvider{home, vps}...)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("home's *.example.com wildcard covers adguard.example.com with matching value through the real driver; this must not be flagged, got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_OutOfZoneWildcardDoesNotCover: a wildcard `*.elsewhere.com`
// must not be treated as covering hosts in `*.example.com`. The wildcard zone has to match
// the host's parent for coverage to apply — otherwise we'd hide real missing-host drift.
func TestAudit_DNSCoverageParity_OutOfZoneWildcardDoesNotCover(t *testing.T) {
	home := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		// wrong-zone wildcard: a `*.other.test` record does not cover `*.example.com` hosts
		{Name: "*.other.test", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	vps := &stubDNS{name: "adguard[vps]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "adguard.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, home, vps)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok {
		t.Fatalf("expected dns_coverage_parity finding: out-of-zone wildcard does NOT cover adguard.example.com, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "adguard.example.com") {
		t.Errorf("parity message should name the still-missing host, got %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_MixedAdguardPihole proves coverage parity is
// PROVIDER-AGNOSTIC: the cross-instance check compares internal resolvers by their
// LiveRecords, not by driver type, so an adguard[home] + pihole[vps] pair (a mixed
// split-horizon — different resolver software per vantage) drifts and clears exactly
// as a dual-adguard pair does. Both real drivers run over their faithful fakes; the
// pihole side also proves its zone-scoped LiveRecords and instance-qualified Name()
// compose with the engine the same way adguard's do.
func TestAudit_DNSCoverageParity_MixedAdguardPihole(t *testing.T) {
	const zone = "example.com"
	agFake := adguardfake.New("grafana."+zone, "10.0.0.13")
	phFake := piholefake.New(
		"grafana."+zone, "10.0.0.13",
		"pihole."+zone, "203.0.113.9", // the asymmetric host (live drift)
		"unrelated.example.org", "192.0.2.9", // out-of-zone: LiveRecords must ignore it
	)
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: agFake})
	vps := pihole.New(pihole.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "vps", Doer: phFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	edge := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	e := core.New(edge, zone, []ports.DNSProvider{home, vps}...)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected dns_coverage_parity warning from mixed real drivers, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "pihole."+zone) ||
		!strings.Contains(f.Message, "pihole[vps]") ||
		!strings.Contains(f.Message, "adguard[home]") {
		t.Errorf("parity message should name the drifted host and both mixed instances, got %q", f.Message)
	}
	// grafana is on BOTH resolvers; the out-of-zone pihole entry is zone-filtered.
	if strings.Contains(f.Message, "grafana."+zone) || strings.Contains(f.Message, "unrelated.example.org") {
		t.Errorf("covered/out-of-zone hosts must not appear in the parity finding: %q", f.Message)
	}
}

// TestAudit_DNSCoverageParity_MixedAdguardPiholeInSync: the quiet half of the mixed
// pair — identical in-zone coverage (values may differ per vantage; parity compares
// PRESENCE) across an adguard and a pihole instance yields NO parity finding.
func TestAudit_DNSCoverageParity_MixedAdguardPiholeInSync(t *testing.T) {
	const zone = "example.com"
	agFake := adguardfake.New("grafana."+zone, "10.0.0.13")
	phFake := piholefake.New("grafana."+zone, "203.0.113.9") // vantage-correct different target
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: agFake})
	vps := pihole.New(pihole.Config{Zone: zone, EdgeAddr: "203.0.113.9", Instance: "vps", Doer: phFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	edge := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	e := core.New(edge, zone, []ports.DNSProvider{home, vps}...)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("mixed resolvers in coverage parity must stay quiet, got %q", f.Message)
	}
}
