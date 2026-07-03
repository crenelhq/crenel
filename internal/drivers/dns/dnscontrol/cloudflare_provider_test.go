package dnscontrol_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/cloudflarefake"
	"github.com/crenelhq/crenel/internal/model"
)

// newCF builds a public-scope dnscontrol driver wired to a faithful Cloudflare fake,
// authenticating with the given token (the driver writes it into creds.json, the fake
// reads it back).
func newCF(t *testing.T, sh dnscontrol.Shell, zone, token string) *dnscontrol.Driver {
	t.Helper()
	return dnscontrol.New(dnscontrol.Config{
		ZoneName: zone,
		Scope:    model.ScopePublic,
		EdgeAddr: "203.0.113.5",
		Shell:    sh,
		Provider: dnscontrol.Provider{
			CredsKey: "cloudflare",
			Type:     "CLOUDFLAREAPI",
			Creds:    map[string]string{"apitoken": token},
		},
	})
}

func exposeOp() model.Op {
	return model.Op{Verb: model.Expose, Service: "vault", Host: "vault.example.com"}
}

func TestCloudflareHappyPathPushes(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "good-token"
	d := newCF(t, cf, "example.com", "good-token")
	ctx := context.Background()

	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(change.Add) != 1 {
		t.Fatalf("expected 1 add, got %+v", change)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cf.LiveCount() != 1 {
		t.Errorf("record should be live after push, have %d", cf.LiveCount())
	}
}

func TestCloudflareRejectsBadToken(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "good-token"
	d := newCF(t, cf, "example.com", "WRONG-token")
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("expected auth failure, got %v", err)
	}
}

func TestCloudflareRejectsZoneMismatch(t *testing.T) {
	cf := cloudflarefake.New("example.com") // the account owns example.com ...
	cf.AcceptToken = "good-token"
	d := newCF(t, cf, "not-mine.com", "good-token") // ... but the driver manages a different zone
	op := model.Op{Verb: model.Expose, Service: "x", Host: "x.not-mine.com"}
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "could not find zone") {
		t.Fatalf("expected zone mismatch, got %v", err)
	}
}

func TestCloudflareRejectsConflictingRecord(t *testing.T) {
	// A CNAME already exists at the name; adding an A there is a Cloudflare 81053.
	cf := cloudflarefake.New("example.com", model.Record{
		Name: "vault.example.com", Type: "CNAME", Value: "edge.example.net", Scope: model.ScopePublic,
	})
	cf.AcceptToken = "good-token"
	// dedicated_zone:true — opt past the foreign-record gate so the A/CNAME CONFLICT
	// (the behavior under test) surfaces. The seeded CNAME is a different Key than the
	// desired A, so on a non-dedicated zone it would be refused as foreign first.
	d := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.5", Shell: cf,
		DedicatedZone: true,
		Provider:      dnscontrol.Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": "good-token"}},
	})
	ctx := context.Background()
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if err := d.Apply(ctx, change); err == nil || !strings.Contains(err.Error(), "81053") {
		t.Fatalf("expected A/CNAME conflict (81053), got %v", err)
	}
}

func TestCloudflareRejectsInvalidContent(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "good-token"
	// EdgeAddr is not an IP -> the A record content is invalid (CF 9005).
	d := dnscontrol.New(dnscontrol.Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "not-an-ip", Shell: cf,
		Provider: dnscontrol.Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": "good-token"}},
	})
	ctx := context.Background()
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, _ := d.Diff(ctx, op, desired)
	if err := d.Apply(ctx, change); err == nil || !strings.Contains(err.Error(), "9005") {
		t.Fatalf("expected invalid-content (9005), got %v", err)
	}
}

func TestCloudflareRejectsRateLimited(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "good-token"
	cf.RateLimited = true
	d := newCF(t, cf, "example.com", "good-token")
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "971") {
		t.Fatalf("expected rate-limit (971), got %v", err)
	}
}

// Auth is checked BEFORE rate-limit (real Cloudflare precedence): a bad token on a
// rate-limited account still returns the auth error, not 971.
func TestCloudflareAuthCheckedBeforeRateLimit(t *testing.T) {
	cf := cloudflarefake.New("example.com")
	cf.AcceptToken = "good-token"
	cf.RateLimited = true
	d := newCF(t, cf, "example.com", "WRONG-token")
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	_, err := d.Diff(context.Background(), op, desired)
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("auth must precede rate-limit, got %v", err)
	}
}

// A live record at the same name/type but a DIFFERENT value is an UPDATE: the diff
// must produce a change and the push must land the new value (else a stale public IP
// is never corrected). On a DEDICATED zone (where crenel owns the record), the update
// must also PRESERVE the record's TTL + proxied state — only the value changes.
// (On a non-dedicated zone the value-change is refused by the ownership gate, since
// crenel can't prove it owns a record whose value it didn't author — see
// TestForeignSameNameValueRefused.)
func TestCloudflareUpdatesChangedValuePreservingTTLProxied(t *testing.T) {
	cf := cloudflarefake.New("example.com", model.Record{
		Name: "vault.example.com", Type: "A", Value: "1.2.3.4", Scope: model.ScopePublic, TTL: 300, Proxied: true,
	})
	cf.AcceptToken = "good-token"
	d := newCFDedicated(t, cf, "example.com", "good-token") // dedicated; EdgeAddr 203.0.113.5
	ctx := context.Background()
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Add) != 1 {
		t.Fatalf("a value change must produce an update, got %+v", change)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatal(err)
	}
	live, _ := d.LiveRecords(ctx)
	if len(live) != 1 || live[0].Value != "203.0.113.5" {
		t.Fatalf("value not updated to the edge addr: %+v", live)
	}
	if live[0].TTL != 300 || !live[0].Proxied {
		t.Errorf("value update must PRESERVE TTL + proxied, got %+v", live[0])
	}
}

// On a NON-dedicated zone, a pre-existing record at the op's own name but a value crenel
// did not author is FOREIGN — refused, never silently overwritten by the whole-zone push.
func TestForeignSameNameValueRefused(t *testing.T) {
	cf := cloudflarefake.New("example.com", model.Record{
		Name: "vault.example.com", Type: "A", Value: "9.9.9.9", Scope: model.ScopePublic, // operator's record
	})
	cf.AcceptToken = "good-token"
	d := newCF(t, cf, "example.com", "good-token") // NON-dedicated
	ctx := context.Background()
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(ctx, op, desired); err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("a foreign-valued record at the op name must be refused, got %v", err)
	}
	if cf.Pushes != 0 {
		t.Errorf("nothing must be pushed when refused (pushes=%d)", cf.Pushes)
	}
}

// THE critical guard: a zone containing a record Crenel cannot faithfully re-render
// (e.g. MX) must REFUSE the whole-zone push rather than delete/corrupt it.
func TestCloudflareRefusesUnrepresentableZone(t *testing.T) {
	cf := cloudflarefake.New("example.com", model.Record{
		Name: "example.com", Type: "MX", Value: "10 aspmx.l.google.com", Scope: model.ScopePublic,
	})
	cf.AcceptToken = "good-token"
	d := newCF(t, cf, "example.com", "good-token")
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(context.Background(), op, desired); err == nil || !strings.Contains(err.Error(), "refusing to push") {
		t.Fatalf("expected refuse-to-push on an MX-bearing zone, got %v", err)
	}
}
