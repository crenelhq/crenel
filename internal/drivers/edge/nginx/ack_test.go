package nginx

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_AckedServerReclassified proves a leading `# crenel-ack:<slug>`
// comment inside a server block (the comment-marker analogue of Caddy's @id,
// docs/design/ack-marker.md) reclassifies a would-be matcher_conditional vhost
// as UnknownAcknowledged, while a SIBLING unacked vhost is unaffected (acks are
// per-route, never blanket) and deny stays UNKNOWN because a real unknown
// remains.
func TestNormalize_AckedServerReclassified(t *testing.T) {
	cfg := `# operator config
server {
    listen 443 ssl;
    server_name grafana.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}

# crenel-ack:webhook-tailnet-agents
server {
    listen 443 ssl;
    server_name app.example.com;
    location /api/webhook {
        proxy_pass http://10.0.0.9:8080;
    }
    location /other {
        proxy_pass http://10.0.0.9:8081;
    }
}

server {
    listen 443 ssl;
    server_name api.example.com;
    location /v1 {
        proxy_pass http://10.0.0.10:9000;
    }
    location /v2 {
        proxy_pass http://10.0.0.10:9001;
    }
}

# crenel-deny: default-deny catch-all
server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}
`
	d := New(tempConfig(t, cfg), resolver())
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
		t.Fatalf("the sibling unacked vhost must still be declared matcher_conditional, got %d: %+v", len(stillUnknown), live.Unparsed)
	}
	if live.FullyParsed() {
		t.Error("a real (unacked) unknown remains; FullyParsed must still be false")
	}
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("deny must stay UNKNOWN while a real unknown remains, got %q", got)
	}
}

// TestNormalize_FullyAckedServersCertifyEnforced proves that once every
// unparsed vhost on the edge is acknowledged, default-deny certifies ENFORCED,
// while the acked entry stays listed (never hidden).
func TestNormalize_FullyAckedServersCertifyEnforced(t *testing.T) {
	cfg := `# operator config
server {
    listen 443 ssl;
    server_name grafana.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}

# crenel-ack:webhook-tailnet-agents
server {
    listen 443 ssl;
    server_name app.example.com;
    location /api/webhook {
        proxy_pass http://10.0.0.9:8080;
    }
    location /other {
        proxy_pass http://10.0.0.9:8081;
    }
}

# crenel-deny: default-deny catch-all
server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}
`
	d := New(tempConfig(t, cfg), resolver())
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
