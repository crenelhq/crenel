package nginx

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresPathScopedServer proves nginx's normalize does not SILENTLY
// collapse a path-routed vhost to its FIRST proxy_pass. classify() matched the first
// proxy_pass in a server block, so a vhost split across `location /api → A` and
// `location /app → B` read as ONE host forwarding to A — the rest of the routing
// dropped, a MISREAD-↓ (the Caddy/Traefik path-matcher analogue).
//
// The fixture mirrors that: app.example.com is split across two proxying locations;
// grafana is a normal single-`/` vhost; auth.example.com is a brownfield forward-auth
// vhost whose SECOND proxy_pass is only the auth_request subrequest location (which must
// NOT be mistaken for path-granular routing). After the fix only the path-split vhost is
// DECLARED matcher_conditional; the plain and auth'd vhosts still enumerate.
func TestNormalize_DeclaresPathScopedServer(t *testing.T) {
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
    server_name app.example.com;
    location /api {
        proxy_pass http://10.0.0.9:8443;
    }
    location /app {
        proxy_pass http://10.0.0.9:8080;
    }
}

server {
    listen 443 ssl;
    server_name auth.example.com;
    location / {
        auth_request /authelia;
        proxy_pass http://10.0.0.7:8200;
    }
    location = /authelia {
        internal;
        proxy_pass http://authelia:9080;
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

	// The plain and the forward-auth single-`/` vhosts enumerate; the path-split one does not.
	if !live.HasHost("grafana.example.com") {
		t.Errorf("the plain-/ grafana vhost must enumerate; got %v", live.Hosts())
	}
	if !live.HasHost("auth.example.com") {
		t.Errorf("the forward-auth single-/ vhost must enumerate (its 2nd proxy_pass is the auth subrequest, not path routing); got %v", live.Hosts())
	}
	if live.HasHost("app.example.com") {
		t.Errorf("a path-split vhost must NOT read as a plain host route, but app.example.com enumerated: %v", live.Hosts())
	}
	if len(live.Routes) != 2 {
		t.Fatalf("exactly the two single-/ vhosts should enumerate, got %d: %v", len(live.Routes), live.Hosts())
	}

	// One matcher_conditional declaration for the path-split vhost, naming the paths.
	var conds []model.Unparsed
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			conds = append(conds, u)
		}
	}
	if len(conds) != 1 {
		t.Fatalf("expected exactly 1 matcher_conditional declaration (app.example.com), got %d: %+v", len(conds), live.Unparsed)
	}
	if !strings.Contains(conds[0].Reason, "/api") || !strings.Contains(conds[0].Reason, "/app") {
		t.Errorf("the declaration must name the location paths (/api, /app); got %q", conds[0].Reason)
	}

	if !live.DenyCatchAllPresent {
		t.Error("the 444 default_server is present => DenyCatchAllPresent")
	}
	if live.DenyState() != model.DenyUnknown {
		t.Errorf("a path-scoped vhost must downgrade deny to UNKNOWN, got %q", live.DenyState())
	}
}

// TestNormalize_SingleRootProxyNotPathScoped locks the no-cry-wolf side: an ordinary
// single `location / { proxy_pass }` vhost — and crenel's own managed render — must NEVER
// raise matcher_conditional. The fully-modeled fixture reads at full coverage.
func TestNormalize_SingleRootProxyNotPathScoped(t *testing.T) {
	cfg := `# operator config
server {
    listen 443 ssl;
    server_name grafana.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
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
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			t.Errorf("a single-/ proxy vhost must not raise matcher_conditional (cry-wolf): %+v", u)
		}
	}
	if !live.FullyParsed() || live.DenyState() != model.DenyEnforced {
		t.Errorf("single-/ edge must read fully-parsed + deny ENFORCED, got unparsed=%+v deny=%q", live.Unparsed, live.DenyState())
	}
}
