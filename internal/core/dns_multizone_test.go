package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// dns_multizone_test.go — multi-zone internal DNS (the production gap this fixes).
//
// The live shape that motivated it: ONE edge serves hosts under TWO apex zones
// (homelab.example + smallbiz.example here), with a zone-confined provider entry per
// (zone × resolver instance): adguard[home]+adguard[vps] for EACH zone (four
// internal providers total) plus one PUBLIC provider for only the first zone —
// the second zone is internal-only ON PURPOSE (its public DNS is managed
// elsewhere and is none of crenel's business). Before zone-aware routing this
// config either hard-errored (a zone-confined driver refusing the out-of-zone
// write on every plan/reconcile) or cried wolf permanently (parity comparing
// resolvers of different zones; edge_route_without_dns flagging every host of
// the provider-less zone on every audit).

const (
	zoneA = "homelab.example"  // has internal (×2) AND public providers
	zoneB = "smallbiz.example" // internal-only (×2) — deliberately NO public provider
)

// seedTwoZones is a Caddyfile exposing one host per zone on the same edge,
// plus the mandatory default-deny catch-all.
const seedTwoZones = "grafana." + zoneA + " {\n\treverse_proxy 10.0.0.5:3000\n}\n" +
	"auth." + zoneB + " {\n\treverse_proxy 10.0.0.7:9091\n}\n" +
	":443 {\n\trespond 403\n}\n"

// zonedStubDNS is a stubDNS that additionally DECLARES a managed zone
// (ports.ZoneReporter) — the public single-zone provider in these tests.
type zonedStubDNS struct {
	stubDNS
	zone string
}

func (z *zonedStubDNS) ManagedZone() string { return z.zone }

// newAG builds a real AdGuard driver over its fake, seeded with live rewrites
// (domain, value pairs) — one (zone × instance) provider entry.
func newAG(zone, instance string, rewrites ...string) *adguard.Driver {
	return adguard.New(adguard.Config{
		Zone: zone, EdgeAddr: "10.0.0.13", Instance: instance,
		Doer: adguardfake.New(rewrites...),
	})
}

// multiZoneEngine wires the production shape: one caddy edge (both zones'
// hosts), the given DNS providers, engine zone = zoneA (the top-level zone —
// zoneB hosts are addressed as full FQDNs, exactly like the live config).
func multiZoneEngine(t *testing.T, dns ...ports.DNSProvider) *core.Engine {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedTwoZones)
	res := static.New(map[string]string{
		"grafana":       "10.0.0.5:3000",
		"auth." + zoneB: "10.0.0.7:9091",
	})
	return core.New(caddy.New(fake.URL(), res), zoneA, dns...)
}

// prodProviders returns the full five-provider production wiring, fully
// covered: both instances of both zones carry their zone's host rewrite, and
// the public provider carries zoneA's record. Values differ per vantage on
// purpose (parity compares presence, never values).
func prodProviders() []ports.DNSProvider {
	pub := &zonedStubDNS{
		stubDNS: stubDNS{name: "cloudflare", scope: model.ScopePublic, live: []model.Record{
			{Name: "grafana." + zoneA, Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic},
		}},
		zone: zoneA,
	}
	return []ports.DNSProvider{
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneA, "vps", "grafana."+zoneA, "100.100.0.2"),
		newAG(zoneB, "home", "auth."+zoneB, "10.0.0.13"),
		newAG(zoneB, "vps", "auth."+zoneB, "100.100.0.2"),
		pub,
	}
}

// TestAudit_MultiZone_ProductionShapeIsClean is the headline: the exact live
// shape — hosts of an internal-only second zone covered by that zone's own
// resolvers, NO public provider for it — audits with NO dns cross-check noise.
// Before zone-awareness, auth.smallbiz.example flagged edge_route_without_dns on
// EVERY audit (its rewrites existed but sat outside the zoneA providers'
// confinement), and any attempt to add zoneB providers set cross-zone parity
// on fire. This is the cry-wolf fix, end to end through the real driver.
func TestAudit_MultiZone_ProductionShapeIsClean(t *testing.T) {
	e := multiZoneEngine(t, prodProviders()...)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{
		"edge_route_without_dns",           // both zones' hosts are covered by their zone's providers
		"dns_without_edge_route",           // every record backs a live route
		"dns_coverage_parity",              // in-parity within each zone; cross-zone never compared
		"edge_route_outside_managed_zones", // every host IS inside a managed zone
	} {
		if f, ok := findCode(rep, code); ok {
			t.Errorf("production multi-zone shape must audit clean of %s, got %q", code, f.Message)
		}
	}
}

// TestAudit_MultiZone_CrossZoneParityNeverFires isolates the grouping rule
// with a minimal 1-instance-per-zone pair: two internal resolvers confined to
// DIFFERENT zones hold disjoint sets by construction and must never be
// compared against each other — no parity finding, ever.
func TestAudit_MultiZone_CrossZoneParityNeverFires(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneB, "home", "auth."+zoneB, "10.0.0.13"),
	)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_coverage_parity"); ok {
		t.Errorf("resolvers of different zones must never be parity-compared, got %q", f.Message)
	}
}

// TestAudit_MultiZone_WithinZoneParityStillFires: grouping must not blunt the
// real check — zoneB's two instances drift (vps carries auth, home does not)
// and the finding names exactly the zoneB pair, never the (in-sync) zoneA one.
func TestAudit_MultiZone_WithinZoneParityStillFires(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneA, "vps", "grafana."+zoneA, "100.100.0.2"),
		newAG(zoneB, "home"), // MISSING auth.smallbiz.example — the within-zone drift
		newAG(zoneB, "vps", "auth."+zoneB, "100.100.0.2"),
	)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_coverage_parity")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected within-zone dns_coverage_parity warning, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "auth."+zoneB) {
		t.Errorf("parity should name the drifted zoneB host, got %q", f.Message)
	}
	if strings.Contains(f.Message, "grafana."+zoneA) {
		t.Errorf("in-sync zoneA host must not appear in the parity finding: %q", f.Message)
	}
}

// TestAudit_HostOutsideManagedZones_QuietDeclaration: a host whose domain NO
// configured provider covers gets the honest, quieter statement — an ok-severity
// "no provider is configured for this host's zone" declaration, NOT the
// actionable "missing record" warning (crenel did not evaluate what it has no
// provider for; saying otherwise trains the operator to ignore the audit).
// Here only zoneA has providers, so auth.smallbiz.example is out of remit.
func TestAudit_HostOutsideManagedZones_QuietDeclaration(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
	)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_route_outside_managed_zones")
	if !ok || f.Severity != "ok" {
		t.Fatalf("expected ok-severity edge_route_outside_managed_zones declaration, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "auth."+zoneB) {
		t.Errorf("declaration should name the out-of-remit host, got %q", f.Message)
	}
	if g, bad := findCode(rep, "edge_route_without_dns"); bad {
		t.Errorf("a host outside every managed zone is not a missing record, got %q", g.Message)
	}
}

// TestAudit_HostInsideManagedZoneStillWarns: the flip side — when a provider
// IS configured for the host's zone and the record is genuinely absent, the
// actionable edge_route_without_dns warning is unchanged (the quiet path must
// never swallow real drift within a managed zone).
func TestAudit_HostInsideManagedZoneStillWarns(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneB, "home"), // zoneB IS managed, but auth's rewrite is missing
	)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_route_without_dns")
	if !ok || f.Severity != "warning" {
		t.Fatalf("expected edge_route_without_dns warning for the in-zone missing record, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "auth."+zoneB) {
		t.Errorf("warning should name the in-zone host, got %q", f.Message)
	}
	if g, bad := findCode(rep, "edge_route_outside_managed_zones"); bad {
		t.Errorf("no host is outside a managed zone here, got %q", g.Message)
	}
}

// TestPlan_MultiZone_RoutesOpToZoneProviders: an expose for a zoneB host must
// plan records ONLY on zoneB's providers; the zoneA providers contribute an
// EMPTY (positionally aligned) change instead of a zone-guard refusal — before
// zone routing, this exact plan hard-errored ("outside the managed zone").
func TestPlan_MultiZone_RoutesOpToZoneProviders(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneB, "home"),
	)
	op := e.BuildOp(model.Expose, "auth."+zoneB)
	cs, err := e.Plan(context.Background(), op)
	if err != nil {
		t.Fatalf("multi-zone plan must not trip the out-of-zone guard: %v", err)
	}
	if len(cs.DNS) != 2 {
		t.Fatalf("cs.DNS must stay positionally aligned with e.DNS: got %d entries", len(cs.DNS))
	}
	if !cs.DNS[0].Empty() {
		t.Errorf("zoneA provider must plan an empty change for a zoneB host, got %+v", cs.DNS[0])
	}
	if len(cs.DNS[1].Add) != 1 || !strings.EqualFold(cs.DNS[1].Add[0].Name, "auth."+zoneB) {
		t.Errorf("zoneB provider should add the zoneB record, got %+v", cs.DNS[1])
	}
}

// TestReconcile_MultiZone_ConvergedIsQuiet: with both zones' hosts exposed and
// each covered on its OWN zone's providers, DetectDrift is empty — a zoneB
// host is NOT "missing" from a zoneA provider (that provider is forbidden to
// hold it). Before zone routing this reported phantom missing_dns_record drift
// whose fix the driver would then refuse, wedging every reconcile.
func TestReconcile_MultiZone_ConvergedIsQuiet(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneB, "home", "auth."+zoneB, "10.0.0.13"),
	)
	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Errorf("fully covered multi-zone world must be converged, got drift %+v", plan.Drift)
	}
}

// TestReconcile_MultiZone_MissingRecordTargetsOwnZoneProvider: real in-zone
// drift still reconciles — a zoneB host missing its rewrite yields exactly one
// missing_dns_record targeting the zoneB provider, never the zoneA ones.
func TestReconcile_MultiZone_MissingRecordTargetsOwnZoneProvider(t *testing.T) {
	e := multiZoneEngine(t,
		newAG(zoneA, "home", "grafana."+zoneA, "10.0.0.13"),
		newAG(zoneB, "home"), // auth's rewrite missing — genuine drift
	)
	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var missing []core.Drift
	for _, d := range plan.Drift {
		if d.Kind == core.DriftMissingDNS {
			missing = append(missing, d)
		}
	}
	if len(missing) != 1 {
		t.Fatalf("expected exactly one missing_dns_record (the zoneB host on its own provider), got %+v", plan.Drift)
	}
	if !strings.EqualFold(missing[0].Host, "auth."+zoneB) || !strings.Contains(missing[0].Target, "adguard[home]") {
		t.Errorf("drift should target the zoneB host on the zoneB provider, got %+v", missing[0])
	}
	if strings.Contains(missing[0].Target, zoneA) {
		t.Errorf("drift must never target a foreign-zone provider, got %+v", missing[0])
	}
}
