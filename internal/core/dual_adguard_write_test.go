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

// The dual-AdGuard WRITE gate (docs/REFERENCE-ARCH-split-horizon.md, build step 1):
// two `scope: internal` AdGuard providers — one per client vantage, each with its own
// endpoint (its own fake here) and its own Instance label — managed by ONE engine.
// These tests prove the transactional machinery treats them as two independent
// providers end to end: an expose writes to BOTH, read-back verification reads EACH
// through its own endpoint, a mid-transaction failure rolls back EACH independently,
// and every operator-facing label distinguishes adguard[home] from adguard[vps].
//
// Target semantics covered:
//   - COINCIDING (the runbook's first build: home-resident hosts) — both instances
//     get the SAME target, because for a home-resident host every vantage resolves
//     to the home edge.
//   - DIVERGING PER PROVIDER — each instance answers with its own vantage-correct
//     EdgeAddr. This is expressible today because the target is per-PROVIDER config;
//     what is NOT expressible (and deliberately not built) is a per-HOST target
//     within one provider — see the note on dualEngine.

// dualEngine wires one caddy edge (over a caddyfake) + two REAL adguard drivers
// (each over its own adguardfake — separate endpoints, like the real home + VPS
// instances). homeAddr/vpsAddr are each instance's EdgeAddr: the ONE target that
// instance answers for every host it manages. A per-host target inside one instance
// is not expressible in today's config (adguard.Config has a single EdgeAddr), so
// the diverging tests below diverge per PROVIDER, which is exactly the runbook's
// vantage split.
func dualEngine(t *testing.T, homeFake, vpsFake *adguardfake.Server, homeAddr, vpsAddr string) *core.Engine {
	t.Helper()
	const zone = "example.com"
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: homeAddr, Instance: "home", Doer: homeFake})
	vps := adguard.New(adguard.Config{Zone: zone, EdgeAddr: vpsAddr, Instance: "vps", Doer: vpsFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	return core.New(edge, zone, []ports.DNSProvider{home, vps}...)
}

// verifyByProvider indexes an ApplyReport's verify results by provider label so a
// test can assert each instance was read back INDEPENDENTLY (one labelled result
// per provider, not one blended DNS verdict).
func verifyByProvider(rep core.ApplyReport) map[string]core.VerifyResult {
	out := map[string]core.VerifyResult{}
	for _, v := range rep.Verify {
		out[v.Provider] = v
	}
	return out
}

// TestDualAdguard_ExposeWritesBoth_CoincidingTarget is the runbook's first-build
// shape (a HOME-RESIDENT host): both instances get the SAME target, because every
// vantage reaches a home-resident host at the home edge. One expose must land the
// rewrite on BOTH endpoints, and verification must read each back separately under
// its instance-qualified label.
func TestDualAdguard_ExposeWritesBoth_CoincidingTarget(t *testing.T) {
	homeFake := adguardfake.New()
	vpsFake := adguardfake.New()
	e := dualEngine(t, homeFake, vpsFake, "10.0.0.13", "10.0.0.13")

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	// BOTH endpoints hold the rewrite — one write fanned out to two instances.
	for name, f := range map[string]*adguardfake.Server{"home": homeFake, "vps": vpsFake} {
		if got := f.List()["photos.example.com"]; got != "10.0.0.13" {
			t.Errorf("instance %s: expected photos.example.com -> 10.0.0.13, got %q (rewrites %v)", name, got, f.List())
		}
	}
	// Verification is PER INSTANCE, under the instance-qualified label — an operator
	// reading the report can tell WHICH resolver each read-back verdict belongs to.
	byProv := verifyByProvider(rep)
	for _, label := range []string{"adguard[home]/internal", "adguard[vps]/internal"} {
		v, ok := byProv[label]
		if !ok {
			t.Fatalf("expected an independent verify result labelled %q, got %+v", label, rep.Verify)
		}
		if !v.OK {
			t.Errorf("%s: verify not OK: %s", label, v.Detail)
		}
	}
}

// TestDualAdguard_ExposeWritesBoth_VantageDivergentTargets: the vantage split that
// IS expressible today — each provider carries its own EdgeAddr, so one expose
// writes a DIFFERENT, vantage-correct target to each instance (home clients get the
// home edge, tunnel clients the tunnel address). Verification must pass on both
// (each instance is checked against ITS OWN desired value, never the other's), and
// a subsequent audit must be parity-CLEAN: coverage matches, targets legitimately
// differ — the exact "same coverage, vantage-correct targets" runbook rule.
func TestDualAdguard_ExposeWritesBoth_VantageDivergentTargets(t *testing.T) {
	homeFake := adguardfake.New()
	vpsFake := adguardfake.New()
	e := dualEngine(t, homeFake, vpsFake, "10.0.0.13", "100.100.0.2")

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if got := homeFake.List()["photos.example.com"]; got != "10.0.0.13" {
		t.Errorf("home instance: expected vantage target 10.0.0.13, got %q", got)
	}
	if got := vpsFake.List()["photos.example.com"]; got != "100.100.0.2" {
		t.Errorf("vps instance: expected vantage target 100.100.0.2, got %q", got)
	}

	// Coverage matches with different answers → the parity audit must stay quiet
	// (parity compares COVERAGE, never values — the vantage rule, end to end).
	arep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(arep, "dns_coverage_parity"); ok {
		t.Errorf("vantage-divergent targets with matching coverage must be parity-clean, got %q", f.Message)
	}
}

// TestDualAdguard_SecondInstanceFailureRollsBackFirst: the all-or-nothing guarantee
// across SAME-SCOPE providers. The home instance applies, then the vps instance
// fails (rate-limited) — the transaction must roll back the home rewrite AND the
// edge route, each through its own compensator, and the error must name the
// FAILING instance so the operator knows which resolver to look at.
func TestDualAdguard_SecondInstanceFailureRollsBackFirst(t *testing.T) {
	homeFake := adguardfake.New()
	vpsFake := adguardfake.New()
	e := dualEngine(t, homeFake, vpsFake, "10.0.0.13", "10.0.0.13")

	// Trip the vps endpoint AFTER planning (Plan reads both live lists), so the
	// failure lands mid-apply: edge OK → home DNS OK → vps DNS 429.
	confirm := func(model.ChangeSet) (bool, error) {
		vpsFake.RateLimited = true
		return true, nil
	}
	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), confirm)
	if err == nil {
		t.Fatal("expected the vps instance failure to fail the apply")
	}
	if !strings.Contains(err.Error(), "adguard[vps]") {
		t.Errorf("error should name the FAILING instance adguard[vps], got: %v", err)
	}
	if !rep.RolledBack {
		t.Fatalf("expected rollback, got %+v", rep)
	}
	// The already-applied home rewrite was compensated independently…
	if _, ok := homeFake.List()["photos.example.com"]; ok {
		t.Errorf("home instance still holds the rewrite after rollback: %v", homeFake.List())
	}
	if homeFake.Adds != 1 || homeFake.Deletes != 1 {
		t.Errorf("home instance: expected exactly one add + one compensating delete, got adds=%d deletes=%d", homeFake.Adds, homeFake.Deletes)
	}
	// …and the failed vps instance was never mutated (nothing to compensate).
	if vpsFake.Adds != 0 {
		t.Errorf("vps instance rejected the add; expected 0 adds, got %d", vpsFake.Adds)
	}
}

// TestDualAdguard_UnexposeRemovesFromEach: the teardown dual — one unexpose removes
// the host's rewrite from EACH instance, each matched against that instance's OWN
// vantage value (a divergent pair, so a blended removal would delete the wrong
// record on one side), leaving unrelated rewrites untouched.
func TestDualAdguard_UnexposeRemovesFromEach(t *testing.T) {
	homeFake := adguardfake.New(
		"grafana.example.com", "10.0.0.13",
		"photos.example.com", "10.0.0.13",
	)
	vpsFake := adguardfake.New(
		"grafana.example.com", "100.100.0.2",
		"photos.example.com", "100.100.0.2",
	)
	e := dualEngine(t, homeFake, vpsFake, "10.0.0.13", "100.100.0.2")

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	for name, f := range map[string]*adguardfake.Server{"home": homeFake, "vps": vpsFake} {
		if _, ok := f.List()["grafana.example.com"]; ok {
			t.Errorf("instance %s: grafana rewrite should be removed, got %v", name, f.List())
		}
		if _, ok := f.List()["photos.example.com"]; !ok {
			t.Errorf("instance %s: unrelated photos rewrite must survive, got %v", name, f.List())
		}
	}
	// The verify report distinguishes the two instances on teardown too.
	byProv := verifyByProvider(rep)
	for _, label := range []string{"adguard[home]/internal", "adguard[vps]/internal"} {
		if v, ok := byProv[label]; !ok || !v.OK {
			t.Errorf("expected an OK verify result labelled %q, got %+v", label, rep.Verify)
		}
	}
}

// TestDualAdguard_ConflictNamesTheInstance: a same-domain/different-answer conflict
// on ONE instance must abort the plan naming THAT instance — with two same-scope
// providers a bare "adguard" error would leave the operator guessing which resolver
// holds the ambiguous rewrite.
func TestDualAdguard_ConflictNamesTheInstance(t *testing.T) {
	homeFake := adguardfake.New()
	vpsFake := adguardfake.New("photos.example.com", "9.9.9.9") // foreign, conflicting answer
	e := dualEngine(t, homeFake, vpsFake, "10.0.0.13", "10.0.0.13")

	_, err := e.Plan(context.Background(), e.BuildOp(model.Expose, "photos"))
	if err == nil {
		t.Fatal("expected the conflicting vps rewrite to abort the plan")
	}
	if !strings.Contains(err.Error(), "adguard[vps]") {
		t.Errorf("conflict error should name adguard[vps], got: %v", err)
	}
	if strings.Contains(err.Error(), "adguard[home]") {
		t.Errorf("conflict is on vps only; error must not implicate adguard[home]: %v", err)
	}
}
