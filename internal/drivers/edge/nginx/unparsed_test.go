package nginx

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresNonProxyVhost proves nginx's normalize DECLARES a vhost it
// can see (server_name) but that does NOT reverse-proxy (a static/fastcgi/return
// block crenel does not model) instead of dropping it silently — and downgrades the
// default-deny verdict to UNKNOWN accordingly. The forwarding vhost still enumerates.
func TestNormalize_DeclaresNonProxyVhost(t *testing.T) {
	cfg := `# operator config
server {
    listen 443 ssl;
    server_name grafana.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}

server {
    listen 443 ssl;
    server_name static.example.com;
    root /var/www/static;
    index index.html;
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
	if !live.HasHost("grafana.example.com") || len(live.Routes) != 1 {
		t.Fatalf("the reverse-proxy vhost should enumerate, got %v", live.Hosts())
	}
	if len(live.Unparsed) != 1 || live.Unparsed[0].Kind != model.UnknownHandler {
		t.Fatalf("expected one handler_unrecognized entry for the static vhost, got %+v", live.Unparsed)
	}
	if live.DenyState() != model.DenyUnknown {
		t.Errorf("unparsed vhost must downgrade deny to UNKNOWN, got %q", live.DenyState())
	}
}
