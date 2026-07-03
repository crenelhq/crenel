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
	"github.com/crenelhq/crenel/internal/ports"
)

// The drift-verb sibling of the audit wildcard-awareness fix (#15/#16). Reconcile
// matched DNS records by NAME only, so a live wildcard rewrite (`*.zone`) that COVERS
// an exposed host silently read two ways wrong:
//   - a covering `*.zone` was treated as "not the record we want" → reconcile flagged
//     `missing_dns_record` and would have added an explicit record on top of the
//     already-answering wildcard.
//   - the wildcard itself is never a canonical exposed host, so it was ALSO flagged
//     `stale_dns_record` and reconcile would have proposed DELETING it. On the maintainer's home
//     resolver that would have wiped the load-bearing `*.homelab.example` — the exact
//     bug this fix prevents.
//
// The fix mirrors the audit siblings: a wildcard COVERS subdomains of its zone (so a
// host it correctly answers is NOT missing, and the wildcard itself is NOT stale while
// any exposed host lives under its zone). A real VALUE mismatch under the wildcard
// STILL flags — the wildcard answers the wrong target, so an explicit record is
// genuinely needed. And crenel never OWNS a wildcard (the AdGuard driver's guard
// refuses to emit one), so reconcile categorically leaves wildcards in place rather
// than clobbering an operator's intentional catch-all.

func driftHostsByKind(plan core.ReconcilePlan, kind core.DriftKind) []string {
	var out []string
	for _, d := range plan.Drift {
		if d.Kind == kind {
			out = append(out, d.Host)
		}
	}
	return out
}

// grafanaEdgeAndAdguardWildcard wires the shared test shape: a single caddy edge
// exposing grafana.example.com and an AdGuard driver whose only live rewrite is the
// `*.example.com` wildcard answering wildcardValue.
func grafanaEdgeAndAdguardWildcard(t *testing.T, wildcardValue, edgeAddr string) (ports.EdgeProvider, ports.DNSProvider) {
	t.Helper()
	const zone = "example.com"
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(seedGrafana)
	edge := caddy.New(cf.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	fake := adguardfake.New("*."+zone, wildcardValue)
	dns := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edgeAddr, Instance: "home", Doer: fake})
	return edge, dns
}

// TestDetectDrift_MissingDNS_WildcardCoveringWithMatchingValueIsClean is the headline
// missing-check fix: an exposed host is already answered by a covering wildcard whose
// value matches crenel's desired target — reconcile must NOT propose an explicit
// record on top of the already-answering wildcard.
func TestDetectDrift_MissingDNS_WildcardCoveringWithMatchingValueIsClean(t *testing.T) {
	edge, dns := grafanaEdgeAndAdguardWildcard(t, "10.0.0.13", "10.0.0.13")
	e := core.New(edge, "example.com", dns)

	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hosts := driftHostsByKind(plan, core.DriftMissingDNS); len(hosts) > 0 {
		t.Errorf("*.example.com already answers grafana.example.com at the desired value; must not flag missing_dns_record, got %v", hosts)
	}
	// And no add should be scheduled against the wildcard's zone.
	for _, dc := range plan.Change.DNS {
		if len(dc.Add) > 0 {
			t.Errorf("reconcile would have added an explicit record on top of the covering wildcard: %+v", dc.Add)
		}
	}
}

// TestDetectDrift_StaleDNS_WildcardBackingExposedHostIsNotStale is the load-bearing
// stale-check fix: a live `*.example.com` wildcard that backs an exposed
// grafana.example.com must NOT be proposed for removal. Prior behaviour would have
// deleted the wildcard — a destructive misdiagnosis (crenel does not own operator
// wildcards, and the wildcard is actively answering an exposed host).
func TestDetectDrift_StaleDNS_WildcardBackingExposedHostIsNotStale(t *testing.T) {
	edge, dns := grafanaEdgeAndAdguardWildcard(t, "10.0.0.13", "10.0.0.13")
	e := core.New(edge, "example.com", dns)

	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hosts := driftHostsByKind(plan, core.DriftStaleDNS); len(hosts) > 0 {
		t.Errorf("*.example.com backs the exposed grafana.example.com; must not flag stale_dns_record, got %v", hosts)
	}
	for _, dc := range plan.Change.DNS {
		for _, r := range dc.Remove {
			if strings.Contains(r.Name, "*") {
				t.Errorf("reconcile would have DELETED the load-bearing wildcard %q — the exact bug the fix must prevent", r.Name)
			}
		}
	}
}

// TestDetectDrift_MissingDNS_WildcardWithWrongValueStillFlags is the value-mismatch
// guard: if the covering wildcard's value differs from crenel's desired target, the
// wildcard is answering the WRONG target for the exposed host — a real drift, so the
// explicit missing record must STILL be flagged. Mirrors the audit-side #15 value
// guard: wildcard-awareness must not silence a genuine mis-answer.
func TestDetectDrift_MissingDNS_WildcardWithWrongValueStillFlags(t *testing.T) {
	edge, dns := grafanaEdgeAndAdguardWildcard(t, "10.0.0.99", "10.0.0.13")
	e := core.New(edge, "example.com", dns)

	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hosts := driftHostsByKind(plan, core.DriftMissingDNS)
	found := false
	for _, h := range hosts {
		if strings.EqualFold(h, "grafana.example.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("wildcard answers the WRONG value; grafana.example.com must still flag missing_dns_record, got drift %+v", plan.Drift)
	}
}
