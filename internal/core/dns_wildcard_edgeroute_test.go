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

// The sibling cry-wolf fix: `dns_without_edge_route` and `edge_route_without_dns` both
// read NAMES only. A `*.zone` wildcard rewrite is a PATTERN (covers any name in .zone),
// not a host — so the existing host-name diffs read both as silently wrong:
//   - `dns_without_edge_route`: a wildcard always reads as "dangling" (no edge route
//     literally named `*.zone`).
//   - `edge_route_without_dns`: a host backed ONLY by a covering wildcard reads as
//     "exposed but no DNS record" (the wildcard's literal name doesn't match the host).
// The wildcard-aware fix mirrors the parity check: a wildcard COVERS subdomains of its
// zone, so the audit treats both as parity-clean — but a wildcard that backs nothing
// under .zone (truly dangling) or a wildcard from a DIFFERENT zone (doesn't cover) still
// flags. Mirror of dns_parity_test.go.

// TestAudit_DNSWithoutEdgeRoute_WildcardCoveringExposedHostIsNotDangling: a
// `*.example.com` rewrite that covers grafana.example.com (which is exposed at the
// edge) is NOT a dangling DNS record — it's an intentional zone catch-all backing
// the exposed surface.
func TestAudit_DNSWithoutEdgeRoute_WildcardCoveringExposedHostIsNotDangling(t *testing.T) {
	dns := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_without_edge_route"); ok {
		t.Errorf("*.example.com covers grafana.example.com (exposed on edge); must not be flagged as dangling, got %q", f.Message)
	}
}

// TestAudit_DNSWithoutEdgeRoute_WildcardWithNoBackingHostStillDangling: a wildcard
// whose zone has NO exposed host on any edge is genuinely dangling (it answers names
// crenel cannot reach) and must still flag. This is the value-mismatch-style guard:
// suppression only kicks in when the wildcard actually backs something.
func TestAudit_DNSWithoutEdgeRoute_WildcardWithNoBackingHostStillDangling(t *testing.T) {
	// edge exposes grafana.example.com; the wildcard lives in a DIFFERENT zone, so
	// it backs no exposed host — truly dangling.
	dns := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.elsewhere.test", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_without_edge_route")
	if !ok {
		t.Fatalf("expected dns_without_edge_route for the no-backing wildcard, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "*.elsewhere.test") {
		t.Errorf("dangling-wildcard message should name the wildcard pattern, got %q", f.Message)
	}
}

// TestAudit_DNSWithoutEdgeRoute_PublicWildcardWithNoBackingHostIsCritical: severity
// follows the existing rule — a PUBLIC dangling wildcard is internet-misdirect class
// and must be critical, mirroring `dns_without_edge_route` for explicit public records.
func TestAudit_DNSWithoutEdgeRoute_PublicWildcardWithNoBackingHostIsCritical(t *testing.T) {
	dns := &stubDNS{name: "dnscontrol", scope: model.ScopePublic, live: []model.Record{
		{Name: "*.elsewhere.test", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_without_edge_route")
	if !ok || f.Severity != "critical" {
		t.Fatalf("expected critical dns_without_edge_route for the no-backing public wildcard, got %+v", rep.Findings)
	}
}

// TestAudit_EdgeRouteWithoutDNS_CoveringWildcardSuppresses: grafana.example.com is
// exposed on the edge; DNS has ONLY a `*.example.com` wildcard. The host is reachable
// by name via the wildcard — must not be flagged as exposed-without-DNS.
func TestAudit_EdgeRouteWithoutDNS_CoveringWildcardSuppresses(t *testing.T) {
	dns := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "edge_route_without_dns"); ok {
		t.Errorf("grafana.example.com is covered by *.example.com; must not be flagged as exposed-without-DNS, got %q", f.Message)
	}
}

// TestAudit_EdgeRouteWithoutDNS_OutOfZoneWildcardStillFlags: an out-of-zone wildcard
// does not cover grafana.example.com — the host is genuinely unreachable by name, and
// the existing warning must still fire (no over-suppression).
func TestAudit_EdgeRouteWithoutDNS_OutOfZoneWildcardStillFlags(t *testing.T) {
	dns := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "*.elsewhere.test", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_route_without_dns")
	if !ok {
		t.Fatalf("expected edge_route_without_dns for the out-of-zone wildcard, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "grafana.example.com") {
		t.Errorf("message should name the uncovered host, got %q", f.Message)
	}
}

// TestAudit_EdgeRouteWithoutDNS_ExplicitStillTakesPrecedence: pre-existing explicit
// coverage path must continue working as-is (regression guard) — a host with a literal
// matching DNS record is still parity-clean even when no wildcard is present.
func TestAudit_EdgeRouteWithoutDNS_ExplicitStillTakesPrecedence(t *testing.T) {
	dns := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.13", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "edge_route_without_dns"); ok {
		t.Errorf("explicit DNS for grafana exists; reverse check must not fire, got %q", f.Message)
	}
}

// TestAudit_WildcardAwareSiblings_RealAdguardDriver wires the WHOLE feature through the
// real AdGuard driver against the faithful fake: a single `*.example.com` wildcard
// rewrite covers an exposed grafana.example.com — no `dns_without_edge_route` for the
// wildcard, and no `edge_route_without_dns` for grafana.
func TestAudit_WildcardAwareSiblings_RealAdguardDriver(t *testing.T) {
	const zone = "example.com"
	fakeAG := adguardfake.New("*."+zone, "10.0.0.13")
	dns := adguard.New(adguard.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: fakeAG})

	fakeCaddy := caddyfake.New()
	t.Cleanup(fakeCaddy.Close)
	fakeCaddy.SeedCaddyfile(seedGrafana)
	edge := caddy.New(fakeCaddy.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	e := core.New(edge, zone, []ports.DNSProvider{dns}...)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_without_edge_route"); ok {
		t.Errorf("*.example.com backs grafana.example.com through the real driver; must not be flagged, got %q", f.Message)
	}
	if f, ok := findCode(rep, "edge_route_without_dns"); ok {
		t.Errorf("grafana.example.com is reachable via *.example.com through the real driver; must not be flagged, got %q", f.Message)
	}
}
