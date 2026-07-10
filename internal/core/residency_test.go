package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// The RESIDENCY SELECTOR (docs/REFERENCE-ARCH-split-horizon.md §2 "the target
// rule"): a host's operator-declared residency class × the provider's vantage
// decides each internal resolver's answer. The dual-AdGuard suite proved
// per-PROVIDER divergence (one EdgeAddr per instance); these tests prove the
// per-HOST layer on top: a `vps`-class host gets DIFFERENT, vantage-correct
// answers on the two instances of the SAME engine (home/non-tunnel → the PUBLIC
// edge, vps/tunnel → tunnel-direct) while home-resident hosts keep today's
// coinciding-target behavior byte-identically. Refusal semantics are load-
// bearing: a class a provider has no target for aborts at PLAN time — a vantage
// target is never guessed.

// Compile-time guards: the internal resolver drivers implement the capability;
// residency resolution is a driver concern core can gate on.
var (
	_ ports.ResidencyTargeter = (*adguard.Driver)(nil)
)

// Vantage-correct targets for the tests (REFERENCE-ARCH §2 table, vps-resident
// row): the home (non-tunnel) resolver answers the PUBLIC edge; the vps (tunnel)
// resolver answers tunnel-direct.
const (
	homeEdge   = "10.0.0.13"   // HOME_EDGE_IP — the home-resident answer everywhere internal
	publicEdge = "203.0.113.9" // EDGE_PUBLIC_IP — the 203.0.113-style public edge
	tunnelVPS  = "100.100.0.2" // TUNNEL_VPS_IP — the 100.64-style tunnel-direct answer
)

// residencyEngine wires one caddy edge + two REAL adguard drivers (separate fakes =
// separate endpoints, like the live home + VPS resolvers), each with its own
// vantage-correct `targets` map for the "vps" class layered over the shared
// home-resident EdgeAddr default. homeTargets/vpsTargets nil = that instance has NO
// residency targets configured (the missing-target refusal shape).
func residencyEngine(t *testing.T, homeFake, vpsFake *adguardfake.Server, homeTargets, vpsTargets map[string]string, extraDNS ...ports.DNSProvider) *core.Engine {
	t.Helper()
	const zone = "example.com"
	home := adguard.New(adguard.Config{Zone: zone, EdgeAddr: homeEdge, Targets: homeTargets, Instance: "home", Doer: homeFake})
	vps := adguard.New(adguard.Config{Zone: zone, EdgeAddr: homeEdge, Targets: vpsTargets, Instance: "vps", Doer: vpsFake})

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seedGrafana)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	dps := append([]ports.DNSProvider{home, vps}, extraDNS...)
	return core.New(edge, zone, dps...)
}

// vpsTargetsFor returns the two instances' vantage-correct maps for class "vps".
func vpsTargetsFor() (home, vps map[string]string) {
	return map[string]string{"vps": publicEdge}, map[string]string{"vps": tunnelVPS}
}

// TestResidency_HomeDefaultUnchanged is the REGRESSION guard: with residency
// targets CONFIGURED but the op declaring no class (the home-resident bulk), both
// instances still answer the plain EdgeAddr default — the targets map is inert
// until a class is declared, so pre-residency behavior is preserved exactly.
func TestResidency_HomeDefaultUnchanged(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Expose, "photos"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	for name, f := range map[string]*adguardfake.Server{"home": homeFake, "vps": vpsFake} {
		if got := f.List()["photos.example.com"]; got != homeEdge {
			t.Errorf("instance %s: home-resident default must stay %s, got %q", name, homeEdge, got)
		}
	}
}

// TestResidency_VPSExposeDivergesPerInstance is the headline: ONE expose of a
// vps-resident host writes a DIFFERENT, vantage-correct answer to each instance —
// non-tunnel clients are sent to the PUBLIC edge, tunnel clients tunnel-direct —
// read-back verified PER INSTANCE against each one's OWN resolved value, and the
// subsequent audit stays quiet (parity is coverage-based; the divergence is the
// point, not drift).
func TestResidency_VPSExposeDivergesPerInstance(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

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
	// Per-instance read-back under the instance-qualified labels.
	byProv := map[string]core.VerifyResult{}
	for _, v := range rep.Verify {
		byProv[v.Provider] = v
	}
	for _, label := range []string{"adguard[home]/internal", "adguard[vps]/internal"} {
		v, ok := byProv[label]
		if !ok || !v.OK {
			t.Errorf("expected an OK per-instance verify result labelled %q, got %+v", label, rep.Verify)
		}
	}
	// Audit posture: divergent VALUES with matching COVERAGE are the vantage rule
	// working, not drift — parity (coverage-based) and value-drift (owned/public
	// records only) must both stay quiet.
	arep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(arep, "dns_coverage_parity"); ok {
		t.Errorf("residency divergence with matching coverage must be parity-clean, got %q", f.Message)
	}
	if f, ok := findCode(arep, "dns_value_drift"); ok {
		t.Errorf("marker-less internal divergence must never raise value drift, got %q", f.Message)
	}
}

// TestResidency_MissingTargetRefusesAtPlan: an exposure declaring a class that ONE
// instance has no target for must abort at PLAN time, naming the instance and the
// class, with NOTHING written anywhere — a vantage target is never guessed.
func TestResidency_MissingTargetRefusesAtPlan(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, _ := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, nil) // vps instance: no targets at all

	op := e.BuildOp(model.Expose, "photos")
	op.Residency = "vps"
	_, err := e.Plan(context.Background(), op)
	if err == nil {
		t.Fatal("expected the missing vps target to refuse the plan")
	}
	if !strings.Contains(err.Error(), "adguard[vps]") || !strings.Contains(err.Error(), `"vps"`) {
		t.Errorf("refusal must name the instance and the class: %v", err)
	}
	if homeFake.Count() != 0 || vpsFake.Count() != 0 {
		t.Errorf("plan-time refusal must write nothing: home=%v vps=%v", homeFake.List(), vpsFake.List())
	}
}

// TestResidency_UnsupportedProviderRefusesAtPlan: an INTERNAL provider that does
// not resolve residency classes at all (no ports.ResidencyTargeter) must refuse a
// non-default class loudly — it would otherwise silently write its default
// edge_addr and misdirect its whole vantage.
func TestResidency_UnsupportedProviderRefusesAtPlan(t *testing.T) {
	stub := &stubDNS{name: "stub-internal", scope: model.ScopeInternal}
	if _, ok := ports.DNSProvider(stub).(ports.ResidencyTargeter); ok {
		t.Fatal("test premise broken: stubDNS must not implement ResidencyTargeter")
	}
	e := auditEngine(t, seedGrafana, stub)

	op := e.BuildOp(model.Expose, "grafana")
	op.Residency = "vps"
	_, err := e.Plan(context.Background(), op)
	if err == nil {
		t.Fatal("expected the residency-unaware internal provider to refuse the plan")
	}
	if !strings.Contains(err.Error(), "stub-internal") || !strings.Contains(err.Error(), "residency") {
		t.Errorf("refusal must name the provider and the residency gap: %v", err)
	}
}

// TestResidency_DeclarativeApply: the durable declaration shape — an apply file's
// `residency:` key per exposure drives the same divergent per-instance write,
// with value-aware declarative read-back (each instance verified against ITS OWN
// resolved value).
func TestResidency_DeclarativeApply(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

	exposures := []core.Exposure{{Service: "photos", Residency: "vps"}}
	rep, err := e.ApplyDeclarative(context.Background(), exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("declarative apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if got := homeFake.List()["photos.example.com"]; got != publicEdge {
		t.Errorf("home instance: expected the public edge %s, got %q", publicEdge, got)
	}
	if got := vpsFake.List()["photos.example.com"]; got != tunnelVPS {
		t.Errorf("vps instance: expected tunnel-direct %s, got %q", tunnelVPS, got)
	}
}

// TestResidency_DeclarativeMissingTargetRefuses: the declarative twin of the
// plan-time refusal — the file declares a class one instance cannot resolve, and
// the whole apply aborts before any mutation.
func TestResidency_DeclarativeMissingTargetRefuses(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, _ := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, nil)

	exposures := []core.Exposure{{Service: "photos", Residency: "vps"}}
	_, err := e.ApplyDeclarative(context.Background(), exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected the missing vps target to refuse the declarative apply")
	}
	if !strings.Contains(err.Error(), "adguard[vps]") {
		t.Errorf("refusal must name the instance: %v", err)
	}
	if homeFake.Count() != 0 || vpsFake.Count() != 0 {
		t.Errorf("declarative refusal must write nothing: home=%v vps=%v", homeFake.List(), vpsFake.List())
	}
}

// TestResidency_UnexposeRemovesEachInstancesOwnValue: teardown must match each
// instance's OWN vantage value — the removal is value-matched per instance, so the
// same unexpose (re-declaring the class) deletes the public-edge answer on home
// and the tunnel answer on vps, leaving unrelated rewrites untouched.
func TestResidency_UnexposeRemovesEachInstancesOwnValue(t *testing.T) {
	homeFake := adguardfake.New(
		"grafana.example.com", publicEdge, // vps-resident host, home vantage value
		"photos.example.com", homeEdge,
	)
	vpsFake := adguardfake.New(
		"grafana.example.com", tunnelVPS, // vps-resident host, tunnel vantage value
		"photos.example.com", homeEdge,
	)
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

	op := e.BuildOp(model.Unexpose, "grafana")
	op.Residency = "vps"
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
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
		if got := f.List()["photos.example.com"]; got != homeEdge {
			t.Errorf("instance %s: unrelated photos rewrite must survive untouched, got %q", name, got)
		}
	}
}

// TestResidency_UnexposeWithoutClassFailsLoudly: residency is DECLARED, never
// inferred — an unexpose of a vps-resident host WITHOUT re-declaring the class
// matches each instance's default value, removes nothing, FAILS read-back (the
// records are still present) and rolls the whole transaction back. Loud, never a
// silent partial teardown or a wrong-record delete.
func TestResidency_UnexposeWithoutClassFailsLoudly(t *testing.T) {
	homeFake := adguardfake.New("grafana.example.com", publicEdge)
	vpsFake := adguardfake.New("grafana.example.com", tunnelVPS)
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

	rep, err := e.Apply(context.Background(), e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err == nil {
		t.Fatal("expected the class-less unexpose of a residency host to fail read-back")
	}
	if !rep.RolledBack {
		t.Fatalf("expected the failed unexpose to roll back, got %+v", rep)
	}
	// Neither instance's divergent record was deleted (the value-match guard).
	if got := homeFake.List()["grafana.example.com"]; got != publicEdge {
		t.Errorf("home instance record must survive the refused teardown, got %q", got)
	}
	if got := vpsFake.List()["grafana.example.com"]; got != tunnelVPS {
		t.Errorf("vps instance record must survive the refused teardown, got %q", got)
	}
}

// TestResidency_PublicProviderClassInvariant: the §2 table's Cloudflare column —
// the PUBLIC record for a vps-resident host points at the public edge exactly as
// for any other host (residency is deliberately ignored by public providers), and
// the owned-record value-drift audit therefore keeps working unchanged: the
// just-written record matches its class-invariant desired value, so no drift.
func TestResidency_PublicProviderClassInvariant(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	cfFake := cfapifake.New("example.com", "zone1")
	cf := cloudflare.New(cloudflare.Config{
		ZoneName: "example.com", ZoneID: "zone1", Scope: model.ScopePublic,
		EdgeAddr: publicEdge, Doer: cfFake,
	})
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt, cf)

	op := e.BuildOp(model.Expose, "photos")
	op.Residency = "vps"
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	// The public record is the plain public-edge A record — class-invariant.
	found := false
	for _, r := range cfFake.Records() {
		if strings.EqualFold(r.Name, "photos.example.com") && r.Type == "A" {
			found = true
			if r.Content != publicEdge {
				t.Errorf("public record must point at the public edge %s for every class, got %q", publicEdge, r.Content)
			}
		}
	}
	if !found {
		t.Fatalf("expected a public A record for photos.example.com, got %+v", cfFake.Records())
	}
	// Owned-record value drift compares against the residency-resolved desired value,
	// which for the public provider IS edge_addr — a correct record raises nothing.
	arep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(arep, "dns_value_drift"); ok {
		t.Errorf("a class-invariant public record at the public edge must not drift, got %q", f.Message)
	}
}

// TestResidency_RollbackCompensatesEachInstance: a mid-transaction failure after
// the home instance took its vps-class write must compensate the home instance
// with ITS OWN divergent value (delete exactly what was added) — the residency
// analogue of the dual-adguard rollback proof.
func TestResidency_RollbackCompensatesEachInstance(t *testing.T) {
	homeFake, vpsFake := adguardfake.New(), adguardfake.New()
	ht, vt := vpsTargetsFor()
	e := residencyEngine(t, homeFake, vpsFake, ht, vt)

	confirm := func(model.ChangeSet) (bool, error) {
		vpsFake.RateLimited = true // trips the SECOND instance mid-apply
		return true, nil
	}
	op := e.BuildOp(model.Expose, "photos")
	op.Residency = "vps"
	rep, err := e.Apply(context.Background(), op, confirm)
	if err == nil {
		t.Fatal("expected the vps instance failure to fail the apply")
	}
	if !rep.RolledBack {
		t.Fatalf("expected rollback, got %+v", rep)
	}
	if _, ok := homeFake.List()["photos.example.com"]; ok {
		t.Errorf("home instance still holds the residency rewrite after rollback: %v", homeFake.List())
	}
	if vpsFake.Count() != 0 {
		t.Errorf("failed vps instance must hold nothing, got %v", vpsFake.List())
	}
}
