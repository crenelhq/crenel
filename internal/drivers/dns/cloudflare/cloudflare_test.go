package cloudflare

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/model"
)

const (
	zone = "crenel.sh"
	edge = "192.0.2.10"
)

// foreignSeed is a zone PRE-SEEDED with records crenel does NOT own: a wildcard A, an
// MX, and a plain A — none carrying the ownership marker. The whole point of surgical
// mode is that these survive every crenel operation byte-identical.
func foreignSeed() []cfapifake.Record {
	return []cfapifake.Record{
		{Type: "A", Name: "*." + zone, Content: "203.0.113.1", TTL: 1, Comment: ""},
		{Type: "MX", Name: zone, Content: "mail.crenel.sh", TTL: 1, Comment: ""},
		{Type: "A", Name: "www." + zone, Content: "203.0.113.5", TTL: 300, Comment: "marketing site"},
		{Type: "TXT", Name: zone, Content: "v=spf1 include:_spf.example.com ~all", TTL: 1, Comment: ""},
	}
}

func newDriver(t *testing.T, fake *cfapifake.Server, proxied bool) *Driver {
	t.Helper()
	return New(Config{ZoneName: zone, ZoneID: fake.ZoneID(), Scope: model.ScopePublic, EdgeAddr: edge, Proxied: proxied, Doer: fake})
}

// foreignSnapshot captures only the foreign (unmarked) records, for a byte-identical
// before/after comparison that ignores crenel's own additions.
func foreignSnapshot(t *testing.T, fake *cfapifake.Server) string {
	t.Helper()
	var b strings.Builder
	for _, r := range fake.Records() {
		if strings.HasPrefix(r.Comment, MarkerPrefix) {
			continue
		}
		b.WriteString(r.ID + "|" + r.Type + "|" + r.Name + "|" + r.Content + "|" + itoa(r.TTL) + "|" + r.Comment + "\n")
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func exposeOp(host string) model.Op   { return model.Op{Verb: model.Expose, Host: host} }
func unexposeOp(host string) model.Op { return model.Op{Verb: model.Unexpose, Host: host} }

// applyOp runs the full Diff→Apply cycle for an op, as core does.
func applyOp(t *testing.T, d *Driver, op model.Op) error {
	t.Helper()
	desired, err := d.DesiredRecords(op)
	if err != nil {
		return err
	}
	change, err := d.Diff(context.Background(), op, desired)
	if err != nil {
		return err
	}
	return d.Apply(context.Background(), change)
}

// --- THE CORE SAFETY PROOF: foreign records untouched ---

func TestExpose_CreatesOnlyOwnRecord_ForeignUntouched(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	before := foreignSnapshot(t, fake)

	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}

	if after := foreignSnapshot(t, fake); after != before {
		t.Fatalf("FOREIGN RECORDS CHANGED by expose:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// Exactly one record was created, and it is crenel's, marked, at the right name.
	if fake.Creates != 1 {
		t.Fatalf("want 1 create, got %d", fake.Creates)
	}
	if len(fake.Touched) != 0 {
		t.Fatalf("expose must not PUT/DELETE any existing record, touched %v", fake.Touched)
	}
	var got *cfapifake.Record
	for i := range fake.Records() {
		r := fake.Records()[i]
		if r.Name == "app."+zone {
			got = &r
		}
	}
	if got == nil {
		t.Fatal("crenel's record was not created")
	}
	if !strings.HasPrefix(got.Comment, MarkerPrefix) {
		t.Fatalf("created record lacks ownership marker: comment=%q", got.Comment)
	}
	if got.Content != edge || got.Type != "A" {
		t.Fatalf("created record wrong: %+v", *got)
	}
}

func TestUnexpose_RemovesOnlyOwnRecord_ForeignUntouched(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	before := foreignSnapshot(t, fake)

	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}
	if err := applyOp(t, d, unexposeOp("app."+zone)); err != nil {
		t.Fatalf("unexpose: %v", err)
	}

	if after := foreignSnapshot(t, fake); after != before {
		t.Fatalf("FOREIGN RECORDS CHANGED by expose+unexpose:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// crenel's record is gone; only crenel's own records were ever deleted.
	for _, r := range fake.Records() {
		if strings.HasPrefix(r.Comment, MarkerPrefix) {
			t.Fatalf("crenel record survived unexpose: %+v", r)
		}
	}
	if fake.Deletes != 1 {
		t.Fatalf("want exactly 1 delete (crenel's own), got %d", fake.Deletes)
	}
}

// --- OWNERSHIP REFUSAL: never overwrite/shadow a foreign record at our name ---

func TestExpose_RefusesForeignRecordAtName(t *testing.T) {
	seed := append(foreignSeed(), cfapifake.Record{Type: "A", Name: "app." + zone, Content: "10.10.10.10", Comment: ""})
	fake := cfapifake.New(zone, "", seed...)
	d := newDriver(t, fake, false)
	before := fake.Snapshot()

	err := applyOp(t, d, exposeOp("app."+zone))
	if err == nil {
		t.Fatal("expected refusal: a foreign A record sits at app.crenel.sh")
	}
	if !strings.Contains(err.Error(), "does NOT own") {
		t.Fatalf("wrong error: %v", err)
	}
	// NOTHING was mutated.
	if fake.Creates != 0 || fake.Updates != 0 || fake.Deletes != 0 || len(fake.Touched) != 0 {
		t.Fatalf("a refused expose mutated the zone: creates=%d updates=%d deletes=%d touched=%v",
			fake.Creates, fake.Updates, fake.Deletes, fake.Touched)
	}
	if after := fake.Snapshot(); after != before {
		t.Fatalf("zone changed on a refused expose:\n%s\n---\n%s", before, after)
	}
}

func TestUnexpose_ForeignAtName_NoOp(t *testing.T) {
	seed := append(foreignSeed(), cfapifake.Record{Type: "A", Name: "app." + zone, Content: "10.10.10.10", Comment: ""})
	fake := cfapifake.New(zone, "", seed...)
	d := newDriver(t, fake, false)
	before := fake.Snapshot()

	if err := applyOp(t, d, unexposeOp("app."+zone)); err != nil {
		t.Fatalf("unexpose of a name we don't own should be a clean no-op, got: %v", err)
	}
	if fake.Deletes != 0 || len(fake.Touched) != 0 {
		t.Fatalf("unexpose touched a foreign record: deletes=%d touched=%v", fake.Deletes, fake.Touched)
	}
	if after := fake.Snapshot(); after != before {
		t.Fatalf("zone changed on a no-op unexpose")
	}
}

// REGRESSION (adversarial review #1): a FOREIGN comment that merely starts with the
// marker bytes but has no word boundary ("managed-by:crenel-not-ours") must NOT be
// classified as owned. Before the boundary fix, crenel would overwrite it on expose and
// delete it on unexpose.
func TestOwnership_PrefixCollision_TreatedAsForeign(t *testing.T) {
	for _, spoof := range []string{
		MarkerPrefix + "-not-ours",
		MarkerPrefix + "vpn keepme",
		MarkerPrefix + "-staging host=app." + zone,
	} {
		t.Run(spoof, func(t *testing.T) {
			seed := append(foreignSeed(), cfapifake.Record{Type: "A", Name: "app." + zone, Content: "10.10.10.10", Comment: spoof})
			fake := cfapifake.New(zone, "", seed...)
			d := newDriver(t, fake, false)
			before := fake.Snapshot()

			// Expose must REFUSE — the spoofed record is foreign at our name.
			if err := applyOp(t, d, exposeOp("app."+zone)); err == nil || !strings.Contains(err.Error(), "does NOT own") {
				t.Fatalf("expose did not refuse a prefix-collision foreign record: %v", err)
			}
			// Unexpose must be a clean no-op (the spoofed record is not ours to delete).
			if err := applyOp(t, d, unexposeOp("app."+zone)); err != nil {
				t.Fatalf("unexpose should no-op on a foreign record: %v", err)
			}
			if fake.Creates != 0 || fake.Updates != 0 || fake.Deletes != 0 || len(fake.Touched) != 0 {
				t.Fatalf("a prefix-collision foreign record was MUTATED: creates=%d updates=%d deletes=%d touched=%v",
					fake.Creates, fake.Updates, fake.Deletes, fake.Touched)
			}
			if after := fake.Snapshot(); after != before {
				t.Fatalf("zone changed despite a foreign prefix-collision record:\n%s\n---\n%s", before, after)
			}
		})
	}
}

// And a genuinely-owned record (exact marker, or marker + space) is still managed.
func TestOwnership_RealMarker_Managed(t *testing.T) {
	for _, c := range []string{MarkerPrefix, MarkerPrefix + " host=app." + zone} {
		fake := cfapifake.New(zone, "", cfapifake.Record{Type: "A", Name: "app." + zone, Content: "198.51.100.1", Comment: c})
		d := newDriver(t, fake, false)
		if err := applyOp(t, d, unexposeOp("app."+zone)); err != nil {
			t.Fatalf("unexpose of an owned (%q) record failed: %v", c, err)
		}
		if fake.Deletes != 1 {
			t.Fatalf("owned record comment %q was not deleted (deletes=%d)", c, fake.Deletes)
		}
	}
}

// --- the hard primitive boundary: refuse to delete/update an unowned record ---

func TestDeletePrimitive_RefusesUnowned(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	foreign := cfRecord{ID: "rec001", Type: "A", Name: "*." + zone, Content: "203.0.113.1", Comment: ""}
	if err := d.deleteRecord(context.Background(), foreign); err == nil {
		t.Fatal("deleteRecord must refuse an unowned record")
	} else if !strings.Contains(err.Error(), "ownership marker") {
		t.Fatalf("wrong refusal: %v", err)
	}
	if fake.Deletes != 0 || len(fake.Touched) != 0 {
		t.Fatal("refused delete still reached the API")
	}
}

func TestUpdatePrimitive_RefusesUnowned(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	foreign := cfRecord{ID: "rec003", Type: "A", Name: "www." + zone, Content: "203.0.113.5", Comment: "marketing site"}
	err := d.updateRecord(context.Background(), foreign, model.Record{Name: "www." + zone, Type: "A", Value: edge})
	if err == nil {
		t.Fatal("updateRecord must refuse an unowned record")
	}
	if fake.Updates != 0 || len(fake.Touched) != 0 {
		t.Fatal("refused update still reached the API")
	}
}

// --- idempotency + value update on OUR OWN record ---

func TestExpose_Idempotent(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	for i := 0; i < 3; i++ {
		if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
			t.Fatalf("expose #%d: %v", i, err)
		}
	}
	if fake.Creates != 1 {
		t.Fatalf("idempotent expose created %d records, want 1", fake.Creates)
	}
	if fake.Updates != 0 {
		t.Fatalf("idempotent expose issued %d updates, want 0", fake.Updates)
	}
}

func TestExpose_ValueUpdate_OnOwnRecord_PreservesMarkerAndForeign(t *testing.T) {
	// Pre-seed an OWNED record at app with a STALE value (as if the edge IP changed).
	seed := append(foreignSeed(), cfapifake.Record{
		Type: "A", Name: "app." + zone, Content: "198.51.100.99", TTL: 300, Comment: MarkerPrefix + " host=app." + zone,
	})
	fake := cfapifake.New(zone, "", seed...)
	d := newDriver(t, fake, false)
	before := foreignSnapshot(t, fake)

	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}
	if fake.Updates != 1 || fake.Creates != 0 {
		t.Fatalf("value update should PUT once, not create: updates=%d creates=%d", fake.Updates, fake.Creates)
	}
	// The owned record now carries the new value, keeps its marker; foreign untouched.
	var app *cfapifake.Record
	for i := range fake.Records() {
		r := fake.Records()[i]
		if r.Name == "app."+zone {
			app = &r
		}
	}
	if app == nil || app.Content != edge {
		t.Fatalf("owned record not updated to new value: %+v", app)
	}
	if !strings.HasPrefix(app.Comment, MarkerPrefix) {
		t.Fatalf("update dropped the ownership marker: %q", app.Comment)
	}
	if app.TTL != 300 {
		t.Fatalf("update reset TTL (want preserved 300): %d", app.TTL)
	}
	if after := foreignSnapshot(t, fake); after != before {
		t.Fatal("foreign records changed during a value update")
	}
}

// A desired record carrying a SHORT name must match Cloudflare's FQDN, so re-expose is
// idempotent (no duplicate created).
func TestExpose_ShortName_Idempotent(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	short := model.Op{Verb: model.Expose, Host: "app"} // short, not FQDN
	for i := 0; i < 2; i++ {
		if err := applyOp(t, d, short); err != nil {
			t.Fatalf("expose #%d: %v", i, err)
		}
	}
	if fake.Creates != 1 {
		t.Fatalf("short-name expose not idempotent: %d creates", fake.Creates)
	}
	// And it landed as the FQDN under the zone.
	found := false
	for _, r := range fake.Records() {
		if r.Name == "app."+zone && strings.HasPrefix(r.Comment, MarkerPrefix) {
			found = true
		}
	}
	if !found {
		t.Fatal("short-name expose did not create app.crenel.sh")
	}
}

// --- guard rails ---

func TestWildcardRefused(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	_, err := d.Diff(context.Background(), exposeOp("*."+zone), []model.Record{{Name: "*." + zone, Type: "A", Value: edge}})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("want wildcard refusal, got: %v", err)
	}
}

func TestOutOfZoneRefused(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	_, err := d.Diff(context.Background(), exposeOp("app.example.org"), []model.Record{{Name: "app.example.org", Type: "A", Value: edge}})
	if err == nil || !strings.Contains(err.Error(), "outside the managed zone") {
		t.Fatalf("want out-of-zone refusal, got: %v", err)
	}
}

func TestNonIPContentRejected(t *testing.T) {
	fake := cfapifake.New(zone, "")
	d := New(Config{ZoneName: zone, ZoneID: fake.ZoneID(), Scope: model.ScopePublic, EdgeAddr: "not-an-ip", Doer: fake})
	err := applyOp(t, d, exposeOp("app."+zone))
	if err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("want non-IP rejection, got: %v", err)
	}
	if fake.Creates != 0 {
		t.Fatal("a non-IP A record was created")
	}
}

// --- faithful-fake failure surface ---

func TestAuthFailure(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	fake.Unauthorized = true
	d := newDriver(t, fake, false)
	if err := applyOp(t, d, exposeOp("app."+zone)); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want auth failure, got: %v", err)
	}
}

func TestRateLimited(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	fake.RateLimited = true
	d := newDriver(t, fake, false)
	if err := applyOp(t, d, exposeOp("app."+zone)); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("want rate-limit error, got: %v", err)
	}
}

func TestZoneNotFound(t *testing.T) {
	fake := cfapifake.New(zone, "") // serves only crenel.sh
	d := New(Config{ZoneName: "other.example", Scope: model.ScopePublic, EdgeAddr: edge, Doer: fake})
	if err := applyOp(t, d, exposeOp("app.other.example")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want zone-not-found, got: %v", err)
	}
}

func TestCNAMECollisionRejectedByFake(t *testing.T) {
	// A foreign CNAME at the name: crenel refuses (foreign at name) BEFORE the API, but
	// this proves the fake itself enforces CF's A/CNAME collision as a backstop.
	fake := cfapifake.New(zone, "", cfapifake.Record{Type: "CNAME", Name: "app." + zone, Content: "elsewhere.example", Comment: MarkerPrefix})
	// Directly create an A where a CNAME exists -> fake returns the CF 81053 collision.
	status, body, _ := fake.Do(context.Background(), "POST", "/zones/"+fake.ZoneID()+"/dns_records",
		[]byte(`{"type":"A","name":"app.`+zone+`","content":"`+edge+`","comment":"`+MarkerPrefix+`"}`))
	if status != 400 || !strings.Contains(string(body), "81053") {
		t.Fatalf("fake did not enforce A/CNAME collision: status=%d body=%s", status, body)
	}
}

// LiveRecords shows ONLY crenel's footprint, never foreign records.
func TestLiveRecords_OnlyOwned(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}
	live, err := d.LiveRecords(context.Background())
	if err != nil {
		t.Fatalf("LiveRecords: %v", err)
	}
	if len(live) != 1 || live[0].Name != "app."+zone {
		t.Fatalf("LiveRecords should show only crenel's 1 record, got %+v", live)
	}
}

// CoverageRecords (ports.CoverageReporter) shows the FULL zone — foreign records
// INCLUDING the unowned wildcard, plus crenel's own — while LiveRecords stays
// marker-filtered. The read-only coverage view is what lets core's presence checks
// see an operator wildcard without ever widening the mutation boundary.
func TestCoverageRecords_FullZoneIncludingForeignWildcard(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	d := newDriver(t, fake, false)
	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}
	cov, err := d.CoverageRecords(context.Background())
	if err != nil {
		t.Fatalf("CoverageRecords: %v", err)
	}
	if len(cov) != len(foreignSeed())+1 {
		t.Fatalf("coverage should show all %d zone records (foreign + crenel's), got %d: %+v", len(foreignSeed())+1, len(cov), cov)
	}
	var sawWildcard bool
	for _, r := range cov {
		if r.Name == "*."+zone && r.Value == "203.0.113.1" {
			sawWildcard = true
		}
	}
	if !sawWildcard {
		t.Fatal("coverage view must include the unowned wildcard record")
	}
	// The ownership boundary is untouched: LiveRecords is still crenel-only.
	live, err := d.LiveRecords(context.Background())
	if err != nil {
		t.Fatalf("LiveRecords: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("LiveRecords must remain marker-filtered (1 owned record), got %+v", live)
	}
}

// Pagination: a zone larger than one page is fully read.
func TestListZone_Paginates(t *testing.T) {
	var seed []cfapifake.Record
	for i := 0; i < 250; i++ {
		seed = append(seed, cfapifake.Record{Type: "TXT", Name: "r" + itoa(i) + "." + zone, Content: "x", Comment: ""})
	}
	fake := cfapifake.New(zone, "", seed...)
	d := newDriver(t, fake, false)
	all, err := d.listZone(context.Background())
	if err != nil {
		t.Fatalf("listZone: %v", err)
	}
	if len(all) != 250 {
		t.Fatalf("pagination dropped records: got %d want 250", len(all))
	}
}

// Proxied flag flows onto created records.
func TestProxiedFlagApplied(t *testing.T) {
	fake := cfapifake.New(zone, "")
	d := newDriver(t, fake, true /* proxied */)
	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose: %v", err)
	}
	for _, r := range fake.Records() {
		if r.Name == "app."+zone && !r.Proxied {
			t.Fatal("proxied flag not applied to created record")
		}
	}
}

// REGRESSION (adversarial review #2): a proxied record must carry TTL=auto, else real
// Cloudflare rejects with 9207. The driver coerces TTL to 1 when Proxied even if a
// non-auto TTL is configured, and the fake enforces the 9207 rule.
func TestProxied_CoercesTTLToAuto(t *testing.T) {
	fake := cfapifake.New(zone, "")
	d := New(Config{ZoneName: zone, ZoneID: fake.ZoneID(), Scope: model.ScopePublic, EdgeAddr: edge, Proxied: true, TTL: 300, Doer: fake})
	if err := applyOp(t, d, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose with proxied+ttl=300 should succeed (TTL coerced), got: %v", err)
	}
	for _, r := range fake.Records() {
		if r.Name == "app."+zone {
			if !r.Proxied || r.TTL != 1 {
				t.Fatalf("proxied record not coerced to TTL=auto: %+v", r)
			}
		}
	}
}

// The fake faithfully rejects proxied+non-auto-TTL (9207) — proving the coercion above
// is load-bearing, not vacuous.
func TestFake_RejectsProxiedNonAutoTTL(t *testing.T) {
	fake := cfapifake.New(zone, "")
	status, body, _ := fake.Do(context.Background(), "POST", "/zones/"+fake.ZoneID()+"/dns_records",
		[]byte(`{"type":"A","name":"app.`+zone+`","content":"`+edge+`","ttl":300,"proxied":true,"comment":"`+MarkerPrefix+`"}`))
	if status != 400 || !strings.Contains(string(body), "9207") {
		t.Fatalf("fake did not enforce proxied TTL rule: status=%d body=%s", status, body)
	}
}

// REGRESSION (adversarial review #3): a bare-label host round-trips so read-back verify
// keys match — DesiredRecords qualifies to the FQDN, matching LiveRecords.
func TestDesiredRecords_FQDNKeyMatchesLive(t *testing.T) {
	fake := cfapifake.New(zone, "")
	d := newDriver(t, fake, false)
	op := model.Op{Verb: model.Expose, Host: "app"} // bare label
	desired, err := d.DesiredRecords(op)
	if err != nil {
		t.Fatalf("DesiredRecords: %v", err)
	}
	if err := applyOp(t, d, op); err != nil {
		t.Fatalf("expose: %v", err)
	}
	live, err := d.LiveRecords(context.Background())
	if err != nil {
		t.Fatalf("LiveRecords: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("want 1 live record, got %d", len(live))
	}
	// The desired Key must equal the live Key — otherwise read-back verify rolls back.
	if desired[0].Key() != live[0].Key() {
		t.Fatalf("desired Key %q != live Key %q — read-back verify would spuriously fail", desired[0].Key(), live[0].Key())
	}
}
