package pihole_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/pihole"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole/piholefake"
	"github.com/crenelhq/crenel/internal/model"
)

const (
	zone = "homelab.example"
	edge = "10.0.0.13" // the internal home Caddy
)

func newPH(doer pihole.Doer) *pihole.Driver {
	return pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge, Doer: doer})
}

func exposeOp() model.Op {
	return model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana." + zone}
}

func TestPiholeExposeAddsHostEntry(t *testing.T) {
	fake := piholefake.New()
	d := newPH(fake)
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
		t.Errorf("host entry not applied: %v", fake.List())
	}
}

func TestPiholeExposeIsIdempotent(t *testing.T) {
	fake := piholefake.New("grafana."+zone, edge) // already present, exactly right
	d := newPH(fake)
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(context.Background(), op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !change.Empty() {
		t.Errorf("re-expose of an identical entry should be a no-op, got %+v", change)
	}
}

// Pi-hole (captured) would ACCEPT a second entry for the same host with a different
// IP — both coexist, an ambiguous split-horizon. The driver must refuse to create
// that ambiguity, exactly like adguard's conflict rule.
func TestPiholeConflictRefusesSecondAnswer(t *testing.T) {
	fake := piholefake.New("grafana."+zone, "192.168.1.99")
	d := newPH(fake)
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "conflicting host entry") {
		t.Fatalf("expected conflict error, got %v", err)
	}
	if fake.Puts != 0 {
		t.Errorf("a conflict must not add anything, Puts=%d", fake.Puts)
	}
}

func TestPiholeUnexposeRemovesHostEntry(t *testing.T) {
	fake := piholefake.New("grafana."+zone, edge)
	d := newPH(fake)
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
		t.Errorf("host entry should be gone, have %v", fake.List())
	}
}

// Removing an entry that vanished out from under us (rollback of a half-applied
// change, or a racing manual delete) answers 404 from the API — the driver treats
// that as the outcome it wanted, not an error.
func TestPiholeApplyRemoveTolerates404(t *testing.T) {
	fake := piholefake.New() // entry NOT present
	d := newPH(fake)
	change := model.DNSChange{
		Scope:  model.ScopeInternal,
		Remove: []model.Record{{Name: "grafana." + zone, Type: "A", Value: edge, Scope: model.ScopeInternal}},
	}
	if err := d.Apply(context.Background(), change); err != nil {
		t.Fatalf("delete of an absent entry (404) must be a tolerated no-op, got %v", err)
	}
}

// THE dangerous case: Pi-hole itself would accept an entry for an out-of-zone domain
// (it has no zones), hijacking e.g. www.smallbiz.example. The DRIVER must refuse
// BEFORE any call reaches Pi-hole.
func TestPiholeRefusesOutOfZoneDomain(t *testing.T) {
	fake := piholefake.New()
	d := newPH(fake)
	op := model.Op{Verb: model.Expose, Service: "www", Host: "www.smallbiz.example"}
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "outside the managed zone") {
		t.Fatalf("expected out-of-zone refusal, got %v", err)
	}
	if fake.Puts != 0 || fake.Count() != 0 {
		t.Errorf("an out-of-zone op must reach Pi-hole with NO write (Puts=%d, live=%d)", fake.Puts, fake.Count())
	}
}

// Wildcards are refused with the honest, captured reason: the v6 dns.hosts API
// itself 400s a wildcard hostname; wildcard answers live in custom dnsmasq confs
// outside the API. The error must say so, and nothing may reach the fake.
func TestPiholeRefusesWildcard(t *testing.T) {
	fake := piholefake.New()
	d := newPH(fake)
	op := model.Op{Verb: model.Expose, Service: "wild", Host: "*." + zone}
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "wildcard") || !strings.Contains(err.Error(), "dnsmasq") {
		t.Fatalf("expected wildcard refusal naming the dnsmasq-conf reality, got %v", err)
	}
	if fake.Puts != 0 {
		t.Errorf("a wildcard op must not reach Pi-hole, Puts=%d", fake.Puts)
	}
}

// dns.hosts values MUST be IPs (captured 400 for anything else); a CNAME-style
// EdgeAddr is a config error surfaced at DesiredRecords, before any plan.
func TestPiholeRefusesNonIPEdgeAddr(t *testing.T) {
	d := pihole.New(pihole.Config{Zone: zone, EdgeAddr: "edge.homelab.example", Doer: piholefake.New()})
	if _, err := d.DesiredRecords(exposeOp()); err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("expected non-IP edge_addr refusal, got %v", err)
	}
}

func TestPiholeIPv6EdgeAddrIsAAAA(t *testing.T) {
	d := pihole.New(pihole.Config{Zone: zone, EdgeAddr: "fd00::13", Doer: piholefake.New()})
	desired, err := d.DesiredRecords(exposeOp())
	if err != nil {
		t.Fatal(err)
	}
	if desired[0].Type != "AAAA" {
		t.Fatalf("IPv6 edge addr should yield AAAA, got %+v", desired)
	}
}

func TestPiholeSurfacesAuthFailure(t *testing.T) {
	fake := piholefake.New()
	fake.Unauthorized = true
	d := newPH(fake)
	if _, err := d.LiveRecords(context.Background()); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 401 auth failure, got %v", err)
	}
}

func TestPiholeSurfacesRateLimit(t *testing.T) {
	fake := piholefake.New()
	fake.RateLimited = true
	d := newPH(fake)
	if _, err := d.LiveRecords(context.Background()); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected 429 rate limit, got %v", err)
	}
}

// The fake faithfully rejects an exact-duplicate PUT with the captured 400 envelope
// ("Item already present"). The driver's own Diff dedupe means this is reached only
// on a direct PUT, which is what we exercise here — and the driver's httpErr must
// surface Pi-hole's message, not a bare status.
func TestPiholeFakeRejectsDuplicatePut(t *testing.T) {
	fake := piholefake.New("grafana."+zone, edge)
	path := "/api/config/dns/hosts/" + "10.0.0.13%20grafana." + zone
	status, body, err := fake.Do(context.Background(), "PUT", path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != 400 || !strings.Contains(string(body), "Item already present") {
		t.Fatalf("exact-duplicate PUT should be 400 'Item already present', got %d %s", status, body)
	}
}

// LiveRecords reports only entries under the managed zone; unparseable dnsmasq
// lines and the operator's unrelated entries stay invisible (so status/audit never
// imply crenel manages them).
func TestPiholeLiveRecordsScopedToZone(t *testing.T) {
	fake := piholefake.New(
		"grafana."+zone, edge, // in-zone
		"unrelated.example.org", "192.0.2.4", // out-of-zone
	)
	d := newPH(fake)
	recs, err := d.LiveRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "grafana."+zone {
		t.Fatalf("expected only the in-zone entry, got %+v", recs)
	}
	if recs[0].Type != "A" || recs[0].Value != edge {
		t.Fatalf("record shape wrong: %+v", recs[0])
	}
}

// TestPiholeNameInstanceLabel: a bare driver is "pihole"; one given an Instance is
// "pihole[<instance>]" so mixed multi-resolver setups (adguard[home] + pihole[vps])
// are distinguishable everywhere a provider label is built.
func TestPiholeNameInstanceLabel(t *testing.T) {
	if got := pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge}).Name(); got != "pihole" {
		t.Errorf("bare instance: want %q, got %q", "pihole", got)
	}
	if got := pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge, Instance: "vps"}).Name(); got != "pihole[vps]" {
		t.Errorf("labeled instance: want %q, got %q", "pihole[vps]", got)
	}
}

// TestPiholePerInstanceOwnershipRefusesForeign mirrors adguard's dual-resolver
// invariant: each instance guards its entries INDEPENDENTLY against its own
// endpoint, and a conflict error names WHICH instance is blocked.
func TestPiholePerInstanceOwnershipRefusesForeign(t *testing.T) {
	ctx := context.Background()
	host := "grafana." + zone

	vpsFake := piholefake.New(host, "10.9.9.9") // foreign answer already live
	vps := pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge, Instance: "vps", Doer: vpsFake})
	homeFake := piholefake.New()
	home := pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge, Instance: "home", Doer: homeFake})

	op := exposeOp()
	desired, _ := vps.DesiredRecords(op)

	if _, err := vps.Diff(ctx, op, desired); err == nil ||
		!strings.Contains(err.Error(), "conflicting host entry") ||
		!strings.Contains(err.Error(), "pihole[vps]") {
		t.Fatalf("vps instance should refuse foreign entry and name itself, got %v", err)
	}
	if vpsFake.Puts != 0 {
		t.Errorf("a conflict must not add anything on vps, Puts=%d", vpsFake.Puts)
	}

	change, err := home.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("home instance should plan a clean add independently, got %v", err)
	}
	if len(change.Add) != 1 || change.Add[0].Name != host {
		t.Fatalf("home should add the host independently, got %+v", change)
	}
}

// --- residency selector (per-host targets; mirrors the adguard contract) ---

// TestResidencyTarget_Contract pins the resolver contract on Pi-hole: default
// class → EdgeAddr, configured class → this instance's vantage target, missing
// class → loud instance-naming refusal; and a resolved NON-IP target is refused
// at DesiredRecords (dns.hosts entries are "IP host" lines), never mid-apply.
func TestResidencyTarget_Contract(t *testing.T) {
	d := pihole.New(pihole.Config{
		Zone: "example.com", EdgeAddr: "10.0.0.13", Instance: "vps",
		Targets: map[string]string{"vps": "100.100.0.2", "bad": "edge.example.com"},
	})
	if got, err := d.ResidencyTarget(""); err != nil || got != "10.0.0.13" {
		t.Errorf("default class must resolve to EdgeAddr: got %q, %v", got, err)
	}
	if got, err := d.ResidencyTarget("vps"); err != nil || got != "100.100.0.2" {
		t.Errorf("vps class must resolve to the configured target: got %q, %v", got, err)
	}
	if _, err := d.ResidencyTarget("nope"); err == nil || !strings.Contains(err.Error(), "pihole[vps]") {
		t.Errorf("an unconfigured class must refuse naming the instance, got %v", err)
	}
	recs, err := d.DesiredRecords(model.Op{Verb: model.Expose, Host: "vault.example.com", Residency: "vps"})
	if err != nil || len(recs) != 1 || recs[0].Value != "100.100.0.2" || recs[0].Type != "A" {
		t.Errorf("expected one A record at the residency target, got %+v, %v", recs, err)
	}
	if _, err := d.DesiredRecords(model.Op{Verb: model.Expose, Host: "vault.example.com", Residency: "bad"}); err == nil ||
		!strings.Contains(err.Error(), "not an IP") {
		t.Errorf("a non-IP residency target must be refused at DesiredRecords, got %v", err)
	}
}
