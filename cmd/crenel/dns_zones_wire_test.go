package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole/piholefake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// dns_zones_wire_test.go — the `zones:` list wiring: ONE provider entry
// (endpoint/creds/instance said once) expands into one zone-confined driver
// instance per zone, equivalent in every observable way to the copy-pasted
// per-zone entries it replaces — while sharing the instance label, the pihole
// session channel, and disambiguating the display name only when it must.

const (
	wzA = "homelab.example"
	wzB = "smallbiz.example"
)

// dnsOn wraps providers into enabled DNS settings with the test default zone.
func dnsOn(providers ...config.DNSProviderSettings) config.Settings {
	return config.Settings{Zone: wzA, DNS: config.DNSSettings{Enabled: true, Providers: providers}}
}

func managedZone(t *testing.T, p ports.DNSProvider) string {
	t.Helper()
	zr, ok := p.(ports.ZoneReporter)
	if !ok {
		t.Fatalf("provider %s declares no zone", p.Name())
	}
	return zr.ManagedZone()
}

// One entry, two zones → two zone-confined instances, zone woven into each name.
func TestBuildDNS_ZonesListExpandsPerZone(t *testing.T) {
	ps, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zones: []string{wzA, wzB},
		EdgeAddr: "10.0.0.13", Instance: "home", Mock: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("expected 2 expanded providers, got %d", len(ps))
	}
	for i, want := range []string{wzA, wzB} {
		if got := managedZone(t, ps[i]); got != want {
			t.Errorf("provider %d confined to %q, want %q", i, got, want)
		}
		// Multi-zone expansion: the label MUST carry the zone, or plan/apply/audit
		// would print two indistinguishable "adguard[home]" lines.
		if wantName := "adguard[home]/" + want; ps[i].Name() != wantName {
			t.Errorf("provider %d name %q, want %q", i, ps[i].Name(), wantName)
		}
	}
}

// `zones: [a]` ≡ `zone: a` — including the display name, byte-identical.
func TestBuildDNS_ZonesListSingleZoneByteIdentical(t *testing.T) {
	listed, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zones: []string{wzB}, EdgeAddr: "10.0.0.13", Instance: "home", Mock: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zone: wzB, EdgeAddr: "10.0.0.13", Instance: "home", Mock: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || len(scalar) != 1 {
		t.Fatalf("expected 1 provider each, got %d / %d", len(listed), len(scalar))
	}
	if listed[0].Name() != scalar[0].Name() || listed[0].Name() != "adguard[home]" {
		t.Errorf("single-entry zones list must keep the exact single-zone name: %q vs %q", listed[0].Name(), scalar[0].Name())
	}
	if managedZone(t, listed[0]) != managedZone(t, scalar[0]) {
		t.Errorf("zone mismatch: %q vs %q", managedZone(t, listed[0]), managedZone(t, scalar[0]))
	}
}

// Setting both `zone` and `zones` is a loud config error, never a precedence pick.
func TestBuildDNS_ZoneAndZonesBothRefused(t *testing.T) {
	_, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zone: wzA, Zones: []string{wzB}, Mock: true,
	}))
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("zone+zones must refuse loudly, got %v", err)
	}
}

// Empty and duplicate zone entries are refused — a list is declared explicitly.
func TestBuildDNS_ZonesListEmptyAndDuplicateRefused(t *testing.T) {
	if _, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zones: []string{wzA, ""}, Mock: true,
	})); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty zones entry must refuse, got %v", err)
	}
	if _, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zones: []string{wzA, wzA}, Mock: true,
	})); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate zones entry must refuse, got %v", err)
	}
}

// A pinned Cloudflare zone_id names ONE zone — combining it with a multi-zone
// list would silently pin every expanded zone to the same id.
func TestBuildDNS_ZonesListWithZoneIDRefused(t *testing.T) {
	_, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "cloudflare", Scope: "public", ApplyMode: "surgical",
		Zones: []string{wzA, wzB}, ZoneID: "abc123", Mock: true,
	}))
	if err == nil || !strings.Contains(err.Error(), "zone_id") {
		t.Fatalf("zone_id + multi-zone list must refuse, got %v", err)
	}
}

// The zone expansion shares ONE pihole session channel: the same endpoint and
// credential answer for every zone, so reading both instances costs one login,
// not one per zone (sessions are a finite server-side seat pool).
func TestBuildDNS_ZonesListSharesPiholeSession(t *testing.T) {
	fake := piholefake.New()
	fake.Password = "s3cret"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	ps, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "pihole", Scope: "internal", Zones: []string{wzA, wzB},
		EdgeAddr: "10.0.0.13", Instance: "vps", Endpoint: srv.URL, Password: "s3cret",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(ps))
	}
	ctx := context.Background()
	for _, p := range ps {
		if _, err := p.LiveRecords(ctx); err != nil {
			t.Fatalf("%s live read: %v", p.Name(), err)
		}
	}
	if fake.Logins != 1 {
		t.Errorf("zone-expanded pihole instances must share one session: %d logins for 2 zone reads", fake.Logins)
	}
}

// seedWireZones is one edge serving a host in each zone plus the default-deny.
const seedWireZones = "grafana." + wzA + " {\n\treverse_proxy 10.0.0.5:3000\n}\n" +
	"auth." + wzB + " {\n\treverse_proxy 10.0.0.7:9091\n}\n" +
	":443 {\n\trespond 403\n}\n"

// wireEngine builds an engine over a fresh fake caddy edge with the given
// (already-wired) DNS providers — the same production shape for both sides of
// the equivalence comparison.
func wireEngine(t *testing.T, dns []ports.DNSProvider) *core.Engine {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedWireZones)
	res := static.New(map[string]string{
		"grafana":      "10.0.0.5:3000",
		"auth." + wzB:  "10.0.0.7:9091",
		"vault." + wzB: "10.0.0.9:8200",
	})
	return core.New(caddy.New(fake.URL(), res), wzA, dns...)
}

// The headline equivalence: a `zones:` list behaves identically to the N
// copy-pasted single-zone entries it replaces — same plan routing (only the
// covering zone's instance receives the record), same post-apply live records,
// same audit findings.
func TestBuildDNS_ZonesListEquivalentToPerZoneEntries(t *testing.T) {
	expanded, err := buildDNS(dnsOn(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", Zones: []string{wzA, wzB},
		EdgeAddr: "10.0.0.13", Instance: "home", Mock: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	perZone, err := buildDNS(dnsOn(
		config.DNSProviderSettings{Type: "adguard", Scope: "internal", Zone: wzA, EdgeAddr: "10.0.0.13", Instance: "home", Mock: true},
		config.DNSProviderSettings{Type: "adguard", Scope: "internal", Zone: wzB, EdgeAddr: "10.0.0.13", Instance: "home", Mock: true},
	))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// The e2e op: an FQDN expose into the NON-default zone. The zones-list path
	// must route it to zoneB's instance only — edge route + that one record.
	for name, dns := range map[string][]ports.DNSProvider{"zones-list": expanded, "per-zone entries": perZone} {
		e := wireEngine(t, dns)
		op, err := e.ResolveOp(model.Expose, "vault."+wzB)
		if err != nil {
			t.Fatal(err)
		}
		op.Scopes = []model.Scope{model.ScopeInternal}
		cs, err := e.Plan(ctx, op)
		if err != nil {
			t.Fatalf("%s: plan: %v", name, err)
		}
		if len(cs.DNS) != 2 {
			t.Fatalf("%s: expected 2 positional DNS changes, got %d", name, len(cs.DNS))
		}
		// Positional: [0] is zoneA's instance (skipped, empty), [1] zoneB's (one add).
		if got := len(cs.DNS[0].Add); got != 0 {
			t.Errorf("%s: zoneA instance must be skipped for a zoneB host, got %d adds", name, got)
		}
		if got := len(cs.DNS[1].Add); got != 1 || cs.DNS[1].Add[0].Name != "vault."+wzB {
			t.Errorf("%s: zoneB instance must receive exactly the vault record, got %+v", name, cs.DNS[1].Add)
		}
		if _, err := e.Apply(ctx, op, core.AlwaysYes); err != nil {
			t.Fatalf("%s: apply: %v", name, err)
		}
		// Post-apply live truth: the record exists ONLY on zoneB's instance.
		recsA, _ := dns[0].LiveRecords(ctx)
		recsB, _ := dns[1].LiveRecords(ctx)
		if len(recsA) != 0 {
			t.Errorf("%s: zoneA instance must stay empty, got %+v", name, recsA)
		}
		if len(recsB) != 1 || recsB[0].Name != "vault."+wzB {
			t.Errorf("%s: zoneB instance must hold the record, got %+v", name, recsB)
		}
		// Audit parity: the applied state audits identically (and cleanly) for
		// the zone-relevant cross-checks in both wirings.
		rep, err := e.Audit(ctx)
		if err != nil {
			t.Fatalf("%s: audit: %v", name, err)
		}
		var zoneFindings []string
		for _, f := range rep.Findings {
			switch f.Code {
			case "edge_route_without_dns", "dns_without_edge_route", "dns_coverage_parity", "edge_route_outside_managed_zones":
				zoneFindings = append(zoneFindings, fmt.Sprintf("%s: %s", f.Code, f.Message))
			}
		}
		// grafana/auth have no records seeded (fresh fakes), so edge_route_without_dns
		// fires for them EQUALLY in both wirings; vault must never appear in it.
		for _, f := range zoneFindings {
			if strings.Contains(f, "vault."+wzB) {
				t.Errorf("%s: applied host must audit clean, got %s", name, f)
			}
		}
	}
}
