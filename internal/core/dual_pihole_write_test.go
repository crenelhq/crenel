package core_test

import (
	"context"
	"net/http/httptest"
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

// The dual-Pi-hole WRITE gate — the pihole sibling of dual_adguard_write_test.go
// (read that file's header for the runbook framing; this one proves the SAME
// transactional guarantees hold when the internal resolvers are Pi-holes, and when
// they are a MIXED adguard+pihole pair). Real pihole drivers over piholefakes,
// through the full core engine: an expose fans out to BOTH instances, read-back
// verification is per instance under its instance-qualified label, a mid-transaction
// failure rolls back each already-applied surface independently, the residency
// selector diverges per instance, and the OSDoer session-expiry retry composes with
// Apply without double-writing.
//
// The audit-parity side of the mixed pair already lives in dns_parity_test.go; this
// file is the WRITE path that was missing.

// Compile-time guard: the pihole driver resolves residency classes, so core's
// residency gate treats it as a first-class internal resolver (like adguard).
var _ ports.ResidencyTargeter = (*pihole.Driver)(nil)

// dualPiholeEngine wires one caddy edge (over a caddyfake) + two REAL pihole
// drivers, each over its own piholefake (separate endpoints, like the real home +
// VPS instances). homeAddr/vpsAddr are each instance's home-resident default
// EdgeAddr; homeTargets/vpsTargets are each instance's optional residency-class
// maps (nil = none configured). Mirrors dualEngine/residencyEngine exactly.
func dualPiholeEngine(t *testing.T, homeFake, vpsFake *piholefake.Server, homeAddr, vpsAddr string, homeTargets, vpsTargets map[string]string) *core.Engine {
	t.Helper()
	const zone = "example.com"
	home := pihole.New(pihole.Config{Zone: zone, EdgeAddr: homeAddr, Targets: homeTargets, Instance: "home", Doer: homeFake})
	vps := pihole.New(pihole.Config{Zone: zone, EdgeAddr: vpsAddr, Targets: vpsTargets, Instance: "vps", Doer: vpsFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	return core.New(edge, zone, []ports.DNSProvider{home, vps}...)
}

// mixedEngine wires the MIXED dual-resolver split-horizon: adguard[home] (over an
// adguardfake) + pihole[vps] (over a piholefake) in ONE engine — the pair the
// audit-parity tests already exercise, now on the write path. Targets maps are the
// residency layer for the mixed-divergence test (nil = none).
func mixedEngine(t *testing.T, agFake *adguardfake.Server, phFake *piholefake.Server, agAddr, phAddr string, agTargets, phTargets map[string]string) *core.Engine {
	t.Helper()
	const zone = "example.com"
	ag := adguard.New(adguard.Config{Zone: zone, EdgeAddr: agAddr, Targets: agTargets, Instance: "home", Doer: agFake})
	ph := pihole.New(pihole.Config{Zone: zone, EdgeAddr: phAddr, Targets: phTargets, Instance: "vps", Doer: phFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	return core.New(edge, zone, []ports.DNSProvider{ag, ph}...)
}

// TestDualPihole_ExposeWritesBoth_CoincidingTarget: the home-resident shape — one
// expose lands the SAME host entry on BOTH pihole endpoints, and verification reads
// each back independently under its instance-qualified label.
func TestDualPihole_ExposeWritesBoth_CoincidingTarget(t *testing.T) {
	homeFake := piholefake.New()
	vpsFake := piholefake.New()
	e := dualPiholeEngine(t, homeFake, vpsFake, "10.0.0.13", "10.0.0.13", nil, nil)

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	// BOTH endpoints hold the host entry — one write fanned out to two instances.
	for name, f := range map[string]*piholefake.Server{"home": homeFake, "vps": vpsFake} {
		if got := f.List()["photos.example.com"]; got != "10.0.0.13" {
			t.Errorf("instance %s: expected photos.example.com -> 10.0.0.13, got %q (hosts %v)", name, got, f.List())
		}
	}
	// Verification is PER INSTANCE, under the instance-qualified label.
	byProv := verifyByProvider(rep)
	for _, label := range []string{"pihole[home]/internal", "pihole[vps]/internal"} {
		v, ok := byProv[label]
		if !ok {
			t.Fatalf("expected an independent verify result labelled %q, got %+v", label, rep.Verify)
		}
		if !v.OK {
			t.Errorf("%s: verify not OK: %s", label, v.Detail)
		}
	}
}

// TestMixedAdguardPihole_ExposeWritesBoth: the MIXED coordinated write — one engine
// managing adguard[home] + pihole[vps] (different driver types, same scope+zone).
// One expose must land the rewrite on the adguard endpoint AND the host entry on
// the pihole endpoint, each verified under its own driver+instance label. This is
// the write-path twin of the mixed audit-parity tests in dns_parity_test.go.
func TestMixedAdguardPihole_ExposeWritesBoth(t *testing.T) {
	agFake := adguardfake.New()
	phFake := piholefake.New()
	e := mixedEngine(t, agFake, phFake, "10.0.0.13", "100.100.0.2", nil, nil)

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	// Each backend holds ITS OWN vantage-correct value (per-provider divergence).
	if got := agFake.List()["photos.example.com"]; got != "10.0.0.13" {
		t.Errorf("adguard[home]: expected 10.0.0.13, got %q", got)
	}
	if got := phFake.List()["photos.example.com"]; got != "100.100.0.2" {
		t.Errorf("pihole[vps]: expected 100.100.0.2, got %q", got)
	}
	// Labels distinguish DRIVER TYPE and instance in one report.
	byProv := verifyByProvider(rep)
	for _, label := range []string{"adguard[home]/internal", "pihole[vps]/internal"} {
		if v, ok := byProv[label]; !ok || !v.OK {
			t.Errorf("expected an OK verify result labelled %q, got %+v", label, rep.Verify)
		}
	}
}

// TestMixedAdguardPihole_UnexposeRemovesFromEach: the mixed teardown — one unexpose
// removes each backend's OWN divergent value (a blended removal would miss on one
// side), leaving unrelated entries untouched on both.
func TestMixedAdguardPihole_UnexposeRemovesFromEach(t *testing.T) {
	agFake := adguardfake.New(
		"grafana.example.com", "10.0.0.13",
		"photos.example.com", "10.0.0.13",
	)
	phFake := piholefake.New(
		"grafana.example.com", "100.100.0.2",
		"photos.example.com", "100.100.0.2",
	)
	e := mixedEngine(t, agFake, phFake, "10.0.0.13", "100.100.0.2", nil, nil)

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if _, ok := agFake.List()["grafana.example.com"]; ok {
		t.Errorf("adguard[home]: grafana rewrite should be removed, got %v", agFake.List())
	}
	if _, ok := phFake.List()["grafana.example.com"]; ok {
		t.Errorf("pihole[vps]: grafana host entry should be removed, got %v", phFake.List())
	}
	// Unrelated entries survive on BOTH backends.
	if _, ok := agFake.List()["photos.example.com"]; !ok {
		t.Errorf("adguard[home]: unrelated photos rewrite must survive, got %v", agFake.List())
	}
	if _, ok := phFake.List()["photos.example.com"]; !ok {
		t.Errorf("pihole[vps]: unrelated photos entry must survive, got %v", phFake.List())
	}
}

// TestDualPihole_SecondInstanceFailureRollsBackFirst: the all-or-nothing guarantee.
// The home pihole applies, then the vps pihole fails (rate-limited — the fake's
// captured 429 surface) — the transaction must roll back the home host entry AND
// the edge route via their compensators, and the error must name the FAILING
// instance so the operator knows which resolver to look at.
func TestDualPihole_SecondInstanceFailureRollsBackFirst(t *testing.T) {
	homeFake := piholefake.New()
	vpsFake := piholefake.New()
	e := dualPiholeEngine(t, homeFake, vpsFake, "10.0.0.13", "10.0.0.13", nil, nil)

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
	if !strings.Contains(err.Error(), "pihole[vps]") {
		t.Errorf("error should name the FAILING instance pihole[vps], got: %v", err)
	}
	if !rep.RolledBack {
		t.Fatalf("expected rollback, got %+v", rep)
	}
	// The already-applied home entry was compensated independently…
	if _, ok := homeFake.List()["photos.example.com"]; ok {
		t.Errorf("home instance still holds the entry after rollback: %v", homeFake.List())
	}
	if homeFake.Puts != 1 || homeFake.Deletes != 1 {
		t.Errorf("home instance: expected exactly one put + one compensating delete, got puts=%d deletes=%d", homeFake.Puts, homeFake.Deletes)
	}
	// …and the failed vps instance was never mutated (nothing to compensate).
	if vpsFake.Puts != 0 {
		t.Errorf("vps instance rejected the put; expected 0 puts, got %d", vpsFake.Puts)
	}
}

// TestMixedAdguardPihole_PiholeFailureRollsBackAdguard: the mixed-pair failure —
// the pihole (second in wiring order) 429s mid-apply, and the compensators must
// unwind the OTHER DRIVER TYPE's already-applied rewrite plus the edge route. The
// error names pihole[vps]; adguard[home] ends where it started.
func TestMixedAdguardPihole_PiholeFailureRollsBackAdguard(t *testing.T) {
	agFake := adguardfake.New()
	phFake := piholefake.New()
	e := mixedEngine(t, agFake, phFake, "10.0.0.13", "100.100.0.2", nil, nil)

	confirm := func(model.ChangeSet) (bool, error) {
		phFake.RateLimited = true
		return true, nil
	}
	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), confirm)
	if err == nil {
		t.Fatal("expected the pihole failure to fail the apply")
	}
	if !strings.Contains(err.Error(), "pihole[vps]") {
		t.Errorf("error should name pihole[vps], got: %v", err)
	}
	if !rep.RolledBack {
		t.Fatalf("expected rollback, got %+v", rep)
	}
	if _, ok := agFake.List()["photos.example.com"]; ok {
		t.Errorf("adguard[home] still holds the rewrite after rollback: %v", agFake.List())
	}
	if phFake.Puts != 0 {
		t.Errorf("pihole[vps] rejected the put; expected 0 puts, got %d", phFake.Puts)
	}
}

// TestDualPihole_ResidencyDivergesPerInstance: the residency selector on piholes —
// ONE expose of a vps-resident host writes a DIFFERENT, vantage-correct answer to
// each pihole instance (non-tunnel → the public edge, tunnel → tunnel-direct),
// read-back verified per instance; the home-resident default stays coinciding.
func TestDualPihole_ResidencyDivergesPerInstance(t *testing.T) {
	homeFake := piholefake.New()
	vpsFake := piholefake.New()
	e := dualPiholeEngine(t, homeFake, vpsFake, homeEdge, homeEdge,
		map[string]string{"vps": publicEdge}, map[string]string{"vps": tunnelVPS})

	op := e.BuildOp(model.Expose, "photos")
	op.Residency = "vps"
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if got := homeFake.List()["photos.example.com"]; got != publicEdge {
		t.Errorf("home (non-tunnel) instance: vps-resident host must answer the PUBLIC edge %s, got %q", publicEdge, got)
	}
	if got := vpsFake.List()["photos.example.com"]; got != tunnelVPS {
		t.Errorf("vps (tunnel) instance: vps-resident host must answer tunnel-direct %s, got %q", tunnelVPS, got)
	}
	// Divergent values with matching coverage are the vantage rule, not drift.
	arep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(arep, "dns_coverage_parity"); ok {
		t.Errorf("residency divergence with matching coverage must be parity-clean, got %q", f.Message)
	}
}

// TestMixedAdguardPihole_ResidencyDivergesAcrossDriverTypes: the residency selector
// across the MIXED pair — one vps-class expose resolves each DRIVER TYPE's own
// `targets` entry (adguard[home] → public edge, pihole[vps] → tunnel-direct); the
// unexpose (same class) then removes each backend's OWN value, proving the class
// rides through teardown too (a default-class removal would miss both).
func TestMixedAdguardPihole_ResidencyDivergesAcrossDriverTypes(t *testing.T) {
	agFake := adguardfake.New()
	phFake := piholefake.New()
	e := mixedEngine(t, agFake, phFake, homeEdge, homeEdge,
		map[string]string{"vps": publicEdge}, map[string]string{"vps": tunnelVPS})

	op := e.BuildOp(model.Expose, "photos")
	op.Residency = "vps"
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("expose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if got := agFake.List()["photos.example.com"]; got != publicEdge {
		t.Errorf("adguard[home]: vps-resident host must answer %s, got %q", publicEdge, got)
	}
	if got := phFake.List()["photos.example.com"]; got != tunnelVPS {
		t.Errorf("pihole[vps]: vps-resident host must answer %s, got %q", tunnelVPS, got)
	}

	// Teardown with the SAME class: each backend's own divergent value is removed.
	unop := e.BuildOp(model.Unexpose, "photos")
	unop.Residency = "vps"
	rep, err = e.Apply(context.Background(), unop, core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified teardown, got %+v", rep)
	}
	if _, ok := agFake.List()["photos.example.com"]; ok {
		t.Errorf("adguard[home]: vps-class unexpose must remove its own value, got %v", agFake.List())
	}
	if _, ok := phFake.List()["photos.example.com"]; ok {
		t.Errorf("pihole[vps]: vps-class unexpose must remove its own value, got %v", phFake.List())
	}
}

// osDoerEngine wires ONE pihole driver over the REAL pihole.OSDoer against a
// loopback httptest server fronting the piholefake — the session login/expiry/
// re-auth flow doer_test.go proves for reads, now composed with the FULL Apply
// transaction. Password-protected, like a real Pi-hole.
func osDoerEngine(t *testing.T, phFake *piholefake.Server) *core.Engine {
	t.Helper()
	const zone = "example.com"
	srv := httptest.NewServer(phFake)
	t.Cleanup(srv.Close)
	doer := &pihole.OSDoer{BaseURL: srv.URL, Password: "trialpass"}
	ph := pihole.New(pihole.Config{Zone: zone, EdgeAddr: "10.0.0.13", Instance: "home", Doer: doer})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	return core.New(edge, zone, ph)
}

// TestPihole_SessionExpiryMidApplyIsTransparent: the doer contract under WRITE
// load. The sid is granted during planning (LiveRecords), then EXPIRES server-side
// before the apply's PUT lands (the validity-1800s path a plan→confirm pause will
// hit). OSDoer promises to discard the sid, re-auth ONCE, and retry — so the Apply
// must succeed with NO double-write (exactly one PUT accepted; the 401'd attempt
// never mutated state) and exactly two logins (initial + re-auth).
func TestPihole_SessionExpiryMidApplyIsTransparent(t *testing.T) {
	phFake := piholefake.New()
	phFake.Password = "trialpass"
	e := osDoerEngine(t, phFake)

	// Expire every session AFTER planning, so the first WRITE hits the 401.
	confirm := func(model.ChangeSet) (bool, error) {
		phFake.ExpireSessions()
		return true, nil
	}
	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), confirm)
	if err != nil {
		t.Fatalf("apply should survive a mid-apply session expiry, got: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if got := phFake.List()["photos.example.com"]; got != "10.0.0.13" {
		t.Errorf("expected photos.example.com -> 10.0.0.13, got %q", got)
	}
	// No double-apply: the 401'd PUT never landed, the retried one did — once.
	if phFake.Puts != 1 {
		t.Errorf("expected exactly one accepted PUT (no double-apply), got %d", phFake.Puts)
	}
	// Initial login (planning) + one re-auth (mid-apply expiry) — never a stampede.
	if phFake.Logins != 2 {
		t.Errorf("expected exactly two logins (initial + re-auth), got %d", phFake.Logins)
	}
}

// TestPihole_PersistentUnauthorizedMidApplySurfacesAndRollsBack: the honest half of
// the doer contract — when the 401 is NOT an expiry (the server keeps rejecting
// even a fresh sid, e.g. an API password rotated mid-flight), OSDoer retries ONCE
// and then surfaces the failure; the transaction must roll back the already-applied
// edge route, never loop, and never leave a host entry behind.
func TestPihole_PersistentUnauthorizedMidApplySurfacesAndRollsBack(t *testing.T) {
	phFake := piholefake.New()
	phFake.Password = "trialpass"
	e := osDoerEngine(t, phFake)

	// Force 401 on every non-auth call AFTER planning: login still succeeds, so the
	// re-auth path completes — and the retried PUT still 401s. That second 401 must
	// come back as a real error, not another retry.
	confirm := func(model.ChangeSet) (bool, error) {
		phFake.Unauthorized = true
		return true, nil
	}
	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), confirm)
	if err == nil {
		t.Fatal("expected the persistent 401 to fail the apply")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error should surface the auth failure honestly, got: %v", err)
	}
	if !rep.RolledBack {
		t.Fatalf("expected the edge route to roll back, got %+v", rep)
	}
	// Nothing landed on the resolver — the write path never mutated state.
	if phFake.Puts != 0 {
		t.Errorf("expected 0 accepted PUTs under persistent 401, got %d", phFake.Puts)
	}
}
