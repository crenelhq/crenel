package traefik

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_AckedRouterReclassified proves a router's crenelAck field (the
// per-router analogue of Caddy's @id, docs/design/ack-marker.md) reclassifies a
// would-be matcher_conditional router as UnknownAcknowledged, while a SIBLING
// unacked router is unaffected (acks are per-route, never blanket) and deny
// stays UNKNOWN because a real unknown remains.
func TestNormalize_AckedRouterReclassified(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "crenel-grafana.example.com": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "svc-grafana"},
          "app-webhook": {"rule": "Host(` + "`app.example.com`" + `) && PathPrefix(` + "`/api/webhook`" + `)", "service": "svc-app-webhook", "crenelAck": "crenel-ack:webhook-tailnet-agents"},
          "api-ro":   {"rule": "Host(` + "`api.example.com`" + `) && Method(` + "`GET`" + `)", "service": "svc-api"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "svc-grafana":     {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}},
          "svc-app-webhook":  {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8080"}]}},
          "svc-api":         {"loadBalancer": {"servers": [{"url": "http://10.0.0.10:9000"}]}},
          "crenel-deny":     {"loadBalancer": {}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
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
	if !strings.Contains(acked[0].Reason, "webhook-tailnet-agents") {
		t.Errorf("acked entry's Reason should carry the operator's reason slug, got %q", acked[0].Reason)
	}
	if len(stillUnknown) != 1 {
		t.Fatalf("the sibling unacked router must still be declared matcher_conditional, got %d: %+v", len(stillUnknown), live.Unparsed)
	}
	if live.FullyParsed() {
		t.Error("a real (unacked) unknown remains; FullyParsed must still be false")
	}
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("deny must stay UNKNOWN while a real unknown remains, got %q", got)
	}
}

// TestNormalize_FullyAckedRoutersCertifyEnforced proves that once every
// unparsed router on the edge is acknowledged, default-deny certifies ENFORCED,
// while the acked entry stays listed (never hidden).
func TestNormalize_FullyAckedRoutersCertifyEnforced(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "crenel-grafana.example.com": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "svc-grafana"},
          "app-webhook": {"rule": "Host(` + "`app.example.com`" + `) && PathPrefix(` + "`/api/webhook`" + `)", "service": "svc-app-webhook", "crenelAck": "crenel-ack:webhook-tailnet-agents"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "svc-grafana":    {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}},
          "svc-app-webhook": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8080"}]}},
          "crenel-deny":    {"loadBalancer": {}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
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
