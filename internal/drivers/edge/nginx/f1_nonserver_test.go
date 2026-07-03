package nginx

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// F1 regression: a config with no top-level server{} crenel can enumerate must NEVER
// certify default-deny ENFORCED. Before the fix, normalize silently skipped every
// non-server chunk, so realistic server-less shapes (a full nginx.conf wrapping its
// vhosts in http{}, a stream-only L4 config, an include-only main file, a map/upstream
// helper file) read as DenyEnforced with zero routes and zero warnings — a false green.
// Each must now surface a declared UNKNOWN (server_not_read) and downgrade to UNKNOWN.
func TestNormalize_F1_NonServerConfigsAreUnknownNotEnforced(t *testing.T) {
	cases := map[string]string{
		// THE standard nginx.conf layout: servers wrapped in http{}.
		"http-wrapper": `http {
    upstream app { server 10.0.0.5:3000; }
    server {
        listen 80;
        server_name app.example.com;
        location / { proxy_pass http://app; }
    }
}`,
		// A pure L4/stream (TCP/SNI passthrough) config — no http server blocks.
		"stream-only": `stream {
    upstream db { server 10.0.0.7:5432; }
    server {
        listen 5432;
        proxy_pass db;
    }
}`,
		// An include-only delegating main config.
		"include-only": `include /etc/nginx/conf.d/*.conf;
include /etc/nginx/sites-enabled/*;`,
		// Only map/upstream helper blocks (a shared snippet file).
		"map-upstream-only": `map $http_host $backend {
    default 10.0.0.1;
    app.example.com 10.0.0.5;
}
upstream pool { server 10.0.0.5:3000; }`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			d := New(tempConfig(t, cfg), resolver())
			live, err := d.ReadLiveState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if live.DenyState() == model.DenyEnforced {
				t.Errorf("%s: config with no enumerable server{} must NOT read ENFORCED (false green), got unparsed=%+v", name, live.Unparsed)
			}
			if live.DenyState() != model.DenyUnknown {
				t.Errorf("%s: expected DenyUnknown, got %q", name, live.DenyState())
			}
			if len(live.Unparsed) == 0 {
				t.Errorf("%s: the unrecognized block must be DECLARED, not silently skipped", name)
			}
			foundServerBlock := false
			for _, u := range live.Unparsed {
				if u.Kind == model.UnknownServerBlock {
					foundServerBlock = true
				}
			}
			if !foundServerBlock {
				t.Errorf("%s: expected a server_not_read declaration, got %+v", name, live.Unparsed)
			}
		})
	}
}

// F1 no-cry-wolf: a pure comment/blank chunk (e.g. a trailing license comment) alongside
// real server blocks must NOT be declared unknown — otherwise a legit fragment would be
// needlessly downgraded. Paired with the ENFORCED regression below.
func TestNormalize_F1_CommentOnlyChunkNotDeclared(t *testing.T) {
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

# end of file — trailing operator note, no config here
`
	d := New(tempConfig(t, cfg), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.FullyParsed() || live.DenyState() != model.DenyEnforced {
		t.Errorf("a comment-only trailing chunk must not downgrade a clean fragment, got unparsed=%+v deny=%q", live.Unparsed, live.DenyState())
	}
}

// F1 designed-for case (regression guard): a legit bare-server{} sites-enabled fragment —
// a real proxy vhost plus the crenel default-deny — must STILL read fully-parsed, deny
// ENFORCED, with the route correctly enumerated. The fix must not break the case the
// driver is designed for.
func TestNormalize_F1_BareServerFragmentStillEnforced(t *testing.T) {
	cfg := `# crenel-managed nginx config v1
# crenel-managed: grafana.example.com
server {
    listen 80;
    server_name grafana.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}

# crenel-deny: default-deny catch-all
server {
    listen 80 default_server;
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
		t.Errorf("bare-server fragment must be fully parsed, got unparsed=%+v", live.Unparsed)
	}
	if live.DenyState() != model.DenyEnforced {
		t.Errorf("bare-server fragment with a deny default_server must read ENFORCED, got %q", live.DenyState())
	}
	if !live.HasHost("grafana.example.com") || len(live.Routes) != 1 {
		t.Errorf("the managed proxy vhost must enumerate as one route, got %v", live.Hosts())
	}
}
