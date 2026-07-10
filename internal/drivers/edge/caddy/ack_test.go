package caddy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_AckedRouteReclassified proves the crenel-ack:<slug> marker (an
// @id on the route node, docs/design/ack-marker.md) reclassifies a would-be
// matcher_conditional route as UnknownAcknowledged — visible, carrying the
// reason slug — while a SIBLING unacked matcher route in the same fixture is
// unaffected: acks are per-route, never a blanket. Because one real unknown
// remains, deny still reads UNKNOWN overall.
func TestNormalize_AckedRouteReclassified(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/ack-matcher-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{
		"grafana": "10.0.0.5:3000", "app": "10.0.0.9:8080", "api": "10.0.0.10:9000",
	}))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var acked, stillUnknown []model.Unparsed
	for _, u := range live.Unparsed {
		switch u.Kind {
		case model.UnknownAcknowledged:
			acked = append(acked, u)
		case model.UnknownMatcher:
			stillUnknown = append(stillUnknown, u)
		}
	}
	if len(acked) != 1 {
		t.Fatalf("expected exactly 1 acknowledged_unknown entry, got %d: %+v", len(acked), live.Unparsed)
	}
	if !strings.Contains(acked[0].Reason, "hawser-tailnet-agents") {
		t.Errorf("acked entry's Reason should carry the operator's reason slug, got %q", acked[0].Reason)
	}
	if len(stillUnknown) != 1 {
		t.Fatalf("the sibling unacked matcher route must still be declared matcher_conditional, got %d: %+v", len(stillUnknown), live.Unparsed)
	}

	// Coverage still counts the acked entry (never hidden): 1 understood (grafana)
	// + 2 unparsed (1 acked, 1 not) = 3.
	if _, total := live.Coverage(); total != 3 {
		t.Errorf("acked entries must still be counted in Coverage total, got total=%d", total)
	}
	// One genuine unknown remains => deny stays UNKNOWN (acks are per-route).
	if live.FullyParsed() {
		t.Error("a real (unacked) unknown remains; FullyParsed must still be false")
	}
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("deny must stay UNKNOWN while a real unknown remains, got %q", got)
	}
}

// TestNormalize_FullyAckedEdgeCertifiesEnforced proves the whole point of the
// ack marker: once EVERY unparsed route on an edge is acknowledged, default-deny
// certifies ENFORCED — the acked entry no longer blocks — while still being
// listed (Acknowledged()) rather than silently disappearing.
func TestNormalize_FullyAckedEdgeCertifiesEnforced(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/ack-matcher-fully-acked-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{
		"grafana": "10.0.0.5:3000", "app": "10.0.0.9:8080",
	}))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.FullyParsed() {
		t.Errorf("an edge with only acknowledged unknowns must read FullyParsed, got unparsed: %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("an edge with only acknowledged unknowns must certify ENFORCED, got %q", got)
	}
	if len(live.Unparsed) != 1 || live.Unparsed[0].Kind != model.UnknownAcknowledged {
		t.Errorf("the acked entry must still be listed in Unparsed, never hidden: %+v", live.Unparsed)
	}
}

// TestAck_StampsMarkerAndReadsBackAcknowledged proves the WRITE side end to
// end: Ack finds the matcher-scoped route by host and stamps @id via PATCH
// (docs/design/ack-marker.md), and a fresh ReadLiveState immediately confirms
// it now reads acknowledged_unknown — the read-back-verify posture every
// mutating verb uses. Unack then reverts it to matcher_conditional.
func TestAck_StampsMarkerAndReadsBackAcknowledged(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/path-granular-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{
		"grafana": "10.0.0.5:3000", "app": "10.0.0.9:8080", "api": "10.0.0.10:9000",
	}))
	ctx := context.Background()

	if err := d.Ack(ctx, "app.example.com", "brownfield-carveout"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownAcknowledged && strings.Contains(u.Reason, "brownfield-carveout") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an acknowledged_unknown entry for app.example.com after Ack, got %+v", live.Unparsed)
	}

	// Idempotent: acking again with the SAME reason is a no-op, not an error.
	if err := d.Ack(ctx, "app.example.com", "brownfield-carveout"); err != nil {
		t.Errorf("re-Ack with the same reason should be idempotent, got: %v", err)
	}

	// Unack reverts it — the route is still matcher-scoped, so it goes back to
	// matcher_conditional (not silently dropped).
	if err := d.Unack(ctx, "app.example.com"); err != nil {
		t.Fatalf("Unack: %v", err)
	}
	live, err = d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownAcknowledged {
			t.Errorf("Unack should have removed the marker, but an acknowledged_unknown entry remains: %+v", u)
		}
	}
	found = false
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			found = true
		}
	}
	if !found {
		t.Errorf("after Unack the route should revert to matcher_conditional (still declared unknown), got %+v", live.Unparsed)
	}
}

// TestAck_RefusesCrenelManagedRoute proves Ack refuses a route that already
// carries crenel's OWNERSHIP marker (a different question from ack) rather
// than silently overwriting its @id.
func TestAck_RefusesCrenelManagedRoute(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "@id": "crenel-route-grafana.example.com",
              "match": [{"host": ["grafana.example.com"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5:3000"}]}]
            },
            {"handle": [{"handler": "static_response", "status_code": 403}]}
          ]
        }
      }
    }
  }
}`); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	if err := d.Ack(context.Background(), "grafana.example.com", "should-be-refused"); err == nil {
		t.Fatal("Ack must refuse a route already carrying crenel's ownership marker")
	}
}

// TestNormalize_LegacyBareMarkerStillRecognized is the backward-compat guard
// for the host-qualified marker change: real edges already carry the LEGACY
// bare form (@id crenel-ack:<reason>, no host segment). Read-side it must
// still classify UnknownAcknowledged with its reason slug, and Unack must
// still remove it (prefix match, not exact-marker match).
func TestNormalize_LegacyBareMarkerStillRecognized(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "@id": "crenel-ack:legacy-carveout",
              "match": [{"host": ["app.example.com"], "path": ["/api/hawser"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.9:8080"}]}]
            },
            {"handle": [{"handler": "static_response", "status_code": 403}]}
          ]
        }
      }
    }
  }
}`); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{"app": "10.0.0.9:8080"}))
	ctx := context.Background()

	// Classify: the bare legacy marker still reads acknowledged, slug intact.
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Unparsed) != 1 || live.Unparsed[0].Kind != model.UnknownAcknowledged {
		t.Fatalf("legacy bare marker must still classify acknowledged_unknown, got %+v", live.Unparsed)
	}
	if !strings.Contains(live.Unparsed[0].Reason, "legacy-carveout") {
		t.Errorf("Reason must carry the legacy slug, got %q", live.Unparsed[0].Reason)
	}

	// Unack: prefix matching must strip the bare form too.
	if err := d.Unack(ctx, "app.example.com"); err != nil {
		t.Fatalf("Unack of a legacy bare marker: %v", err)
	}
	live, err = d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Unparsed) != 1 || live.Unparsed[0].Kind != model.UnknownMatcher {
		t.Errorf("after unack the route must revert to matcher_conditional, got %+v", live.Unparsed)
	}
}
