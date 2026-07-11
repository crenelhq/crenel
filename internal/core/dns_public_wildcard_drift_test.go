package core_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// The PUBLIC-scope cry-wolf sibling of the internal wildcard-awareness fix
// (dns_parity / dns_wildcard_drift): on the maintainer's production edge the public
// zone's whole coverage comes from ONE unowned `*.zone → <public-edge-ip>` record —
// no crenel marker, created by the operator. The surgical Cloudflare driver's
// LiveRecords is (correctly, for mutation safety) marker-filtered to crenel-owned
// records, so the presence checks could not SEE the wildcard: `crenel drift` flagged
// a permanent missing_dns_record for every exposed host (64 in prod) and audit
// flagged edge_route_without_dns for each — pure cry-wolf under a healthy wildcard.
//
// The fix is the read-only ports.CoverageReporter capability: the full owned+foreign
// zone view, consumed ONLY by presence/coverage checks. A covering wildcard whose
// answer MATCHES the expected target satisfies public presence (the same matching
// rule as the internal dns_coverage_parity value guard); a value-MISMATCHED wildcard
// still drifts, with a message naming the wildcard and both values. Ownership stays
// exactly where it was: mutation, stale removal, and owned-value drift remain
// marker-gated, and crenel never touches a foreign record.

const publicEdgeIP = "203.0.113.9"

// prodHosts is the production shape in miniature: a dozen exposed hosts, all under
// the public zone, all expected to answer at the public edge IP.
func prodHosts() map[string]string {
	origins := map[string]string{}
	for i := 0; i < 12; i++ {
		origins[fmt.Sprintf("svc%02d", i)] = fmt.Sprintf("10.0.0.%d:8080", 10+i)
	}
	return origins
}

// pubWildcardEngine wires a caddy edge exposing every origins host as
// <name>.crenel.sh, plus a surgical Cloudflare public provider whose zone is seeded
// with the given records (Comment left empty = genuinely foreign / unowned).
func pubWildcardEngine(t *testing.T, origins map[string]string, seed ...cfapifake.Record) (*core.Engine, *cfapifake.Server) {
	t.Helper()
	var b strings.Builder
	for name, addr := range origins {
		fmt.Fprintf(&b, "%s.crenel.sh {\n\treverse_proxy %s\n}\n", name, addr)
	}
	b.WriteString(":443 {\n\trespond 403\n}\n")
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(b.String())
	edge := core.EdgeBinding{Name: "vps", Provider: caddy.New(cf.URL(), static.New(origins)), Fronts: frontsFor(origins)}

	fake := cfapifake.New("crenel.sh", "zone1", seed...)
	dns := cloudflare.New(cloudflare.Config{
		ZoneName: "crenel.sh", ZoneID: "zone1", Scope: model.ScopePublic,
		EdgeAddr: publicEdgeIP, Doer: fake,
	})
	return core.NewMulti([]core.EdgeBinding{edge}, "crenel.sh", dns), fake
}

// TestDetectDrift_PublicUnownedWildcardMatchingValueIsClean is the RED→GREEN headline
// (the exact production shape): zero owned records, ONE unowned `*.crenel.sh` A
// record answering the public edge IP, a dozen exposed hosts whose desired target is
// that same IP. Drift must be CLEAN — the wildcard IS the coverage.
func TestDetectDrift_PublicUnownedWildcardMatchingValueIsClean(t *testing.T) {
	e, _ := pubWildcardEngine(t, prodHosts(), cfapifake.Record{
		Type: "A", Name: "*.crenel.sh", Content: publicEdgeIP, // Comment empty: UNOWNED
	})
	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("unowned wildcard answers every host at the expected target; drift must be clean, got %+v", plan.Drift)
	}
}

// TestAudit_PublicUnownedWildcardSatisfiesReverseCheck: the same shape must AUDIT
// clean of edge_route_without_dns — the wildcard-covered hosts ARE reachable by name.
// And the foreign wildcard itself must never be flagged (dns_without_edge_route /
// dns_value_drift iterate only crenel-owned records).
func TestAudit_PublicUnownedWildcardSatisfiesReverseCheck(t *testing.T) {
	e, _ := pubWildcardEngine(t, prodHosts(), cfapifake.Record{
		Type: "A", Name: "*.crenel.sh", Content: publicEdgeIP,
	})
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"edge_route_without_dns", "dns_without_edge_route", "dns_value_drift"} {
		if f, ok := findCode(rep, code); ok {
			t.Errorf("audit must be clean of %s under a matching unowned wildcard, got %q", code, f.Message)
		}
	}
}

// TestDetectDrift_PublicUnownedWildcardWrongValueStillFlags is the value-mismatch
// guard: the unowned wildcard answers a DIFFERENT target than crenel's configured
// edge — a silent misdirect for every covered host, so missing_dns_record must STILL
// flag, with a message naming the wildcard's answer and the expected target.
func TestDetectDrift_PublicUnownedWildcardWrongValueStillFlags(t *testing.T) {
	origins := map[string]string{"app": "10.0.0.5:3000"}
	e, _ := pubWildcardEngine(t, origins, cfapifake.Record{
		Type: "A", Name: "*.crenel.sh", Content: "198.51.100.7", // WRONG target
	})
	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var d core.Drift
	found := false
	for _, dr := range plan.Drift {
		if dr.Kind == core.DriftMissingDNS && strings.EqualFold(dr.Host, "app.crenel.sh") {
			d, found = dr, true
		}
	}
	if !found {
		t.Fatalf("wildcard answers the WRONG value; app.crenel.sh must still flag missing_dns_record, got %+v", plan.Drift)
	}
	// The message must say the WILDCARD's value differs — not the generic "missing".
	for _, want := range []string{"*.crenel.sh", "198.51.100.7", publicEdgeIP} {
		if !strings.Contains(d.Detail, want) {
			t.Errorf("mismatch detail should name the wildcard and both values (missing %q): %q", want, d.Detail)
		}
	}
}

// TestDetectDrift_PublicNoWildcardNoRecordStillMissing guards against blanket
// suppression: a zone with NO wildcard and no record for the host must keep flagging
// missing_dns_record exactly as before.
func TestDetectDrift_PublicNoWildcardNoRecordStillMissing(t *testing.T) {
	origins := map[string]string{"app": "10.0.0.5:3000"}
	e, _ := pubWildcardEngine(t, origins) // empty zone
	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(driftHostsByKind(plan, core.DriftMissingDNS)); n != 1 {
		t.Fatalf("empty zone: expected exactly 1 missing_dns_record, got %d (%+v)", n, plan.Drift)
	}
}

// TestDetectDrift_PublicMixedExplicitOwnedPlusWildcard: one host holds an explicit
// crenel-OWNED record (correct value) while the wildcard covers the rest — both
// paths must read clean, and the owned record's value-drift semantics must survive:
// if that owned record's value drifts, DriftValueDNS still fires even though the
// wildcard would "cover" the name.
func TestDetectDrift_PublicMixedExplicitOwnedPlusWildcard(t *testing.T) {
	origins := map[string]string{"app": "10.0.0.5:3000", "grafana": "10.0.0.6:3000", "vault": "10.0.0.7:8200"}

	t.Run("all correct is clean", func(t *testing.T) {
		e, _ := pubWildcardEngine(t, origins,
			cfapifake.Record{Type: "A", Name: "*.crenel.sh", Content: publicEdgeIP},
			cfapifake.Record{Type: "A", Name: "app.crenel.sh", Content: publicEdgeIP,
				Comment: cloudflare.MarkerPrefix + " host=app"}, // crenel-OWNED explicit
		)
		plan, err := e.DetectDrift(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Empty() {
			t.Fatalf("explicit owned record + covering wildcard are both correct; drift must be clean, got %+v", plan.Drift)
		}
	})

	t.Run("owned explicit value drift still detected under the wildcard", func(t *testing.T) {
		e, _ := pubWildcardEngine(t, origins,
			cfapifake.Record{Type: "A", Name: "*.crenel.sh", Content: publicEdgeIP},
			cfapifake.Record{Type: "A", Name: "app.crenel.sh", Content: "203.0.113.99", // DRIFTED
				Comment: cloudflare.MarkerPrefix + " host=app"},
		)
		plan, err := e.DetectDrift(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var kinds []core.DriftKind
		for _, d := range plan.Drift {
			kinds = append(kinds, d.Kind)
		}
		if len(plan.Drift) != 1 || plan.Drift[0].Kind != core.DriftValueDNS {
			t.Fatalf("expected exactly one wrong_dns_target for the owned explicit record, got %v (%+v)", kinds, plan.Drift)
		}
		if !strings.EqualFold(plan.Drift[0].Host, "app.crenel.sh") {
			t.Errorf("value drift should name app.crenel.sh, got %q", plan.Drift[0].Host)
		}
	})
}

// TestReconcile_PublicUnownedWildcardNeverTouched: reconcile over the wrong-value
// wildcard shape must ADD explicit owned records — and must never mutate or delete
// the foreign wildcard itself (the coverage view is read-only by contract; the fake
// records every id a PUT/DELETE targeted).
func TestReconcile_PublicUnownedWildcardNeverTouched(t *testing.T) {
	origins := map[string]string{"app": "10.0.0.5:3000"}
	e, fake := pubWildcardEngine(t, origins, cfapifake.Record{
		ID: "wild1", Type: "A", Name: "*.crenel.sh", Content: "198.51.100.7", // WRONG target
	})
	rep, err := e.Reconcile(context.Background(), core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Applied {
		t.Fatal("expected reconcile to apply the corrective explicit record")
	}
	for _, id := range fake.Touched {
		if id == "wild1" {
			t.Fatal("reconcile mutated the FOREIGN wildcard record — coverage must be read-only")
		}
	}
	// The corrective explicit record now exists, owned, at crenel's target.
	var got string
	for _, r := range fake.Records() {
		if r.Name == "app.crenel.sh" && r.Type == "A" {
			got = r.Content
		}
	}
	if got != publicEdgeIP {
		t.Fatalf("expected explicit owned app.crenel.sh -> %s to override the wildcard, got %q", publicEdgeIP, got)
	}
}

// TestCoverageReporter_CapabilityScope pins the capability wiring: the surgical
// Cloudflare driver implements ports.CoverageReporter (it can serve the full zone
// pre-marker-filter); the marker-less stubDNS does not need to (its LiveRecords is
// already the full coverage view, so core falls back to it).
func TestCoverageReporter_CapabilityScope(t *testing.T) {
	drv := cloudflare.New(cloudflare.Config{ZoneName: "crenel.sh", Scope: model.ScopePublic, EdgeAddr: publicEdgeIP,
		Doer: cfapifake.New("crenel.sh", "zone1")})
	if _, ok := ports.DNSProvider(drv).(ports.CoverageReporter); !ok {
		t.Fatal("surgical cloudflare driver must implement ports.CoverageReporter")
	}
	if _, ok := ports.DNSProvider(&stubDNS{}).(ports.CoverageReporter); ok {
		t.Fatal("test premise broken: stubDNS must not implement CoverageReporter (fallback path must stay covered)")
	}
}
