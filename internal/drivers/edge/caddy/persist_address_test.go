package caddy

import (
	"strings"
	"testing"
)

// TestOSCaddyCLI_ReloadArgs_ExplicitAddress pins the TRIAL-FIX-DURABLE-3 fix: the
// `caddy reload` invocation must carry an explicit `--address <host:port>` so it can
// never fall back to the CLI's bare `localhost:2019` default (which resolves to ::1
// first on a dual-stack host and misses an IPv4-only admin listener, failing the
// on-disk persist's reload while the admin-API writes still succeed). When no address
// is configured the flag is omitted (caddy's own default applies).
func TestOSCaddyCLI_ReloadArgs_ExplicitAddress(t *testing.T) {
	cli := OSCaddyCLI{Address: "127.0.0.1:2019"}
	got := strings.Join(cli.reloadArgs("/etc/caddy/Caddyfile"), " ")
	want := "reload --config /etc/caddy/Caddyfile --address 127.0.0.1:2019"
	if got != want {
		t.Fatalf("reload argv = %q, want %q", got, want)
	}
	// Never bare localhost — that is the exact regression the live trial hit.
	if strings.Contains(got, "localhost") {
		t.Fatalf("reload argv must not rely on localhost resolution: %q", got)
	}

	// Empty address => no --address flag (fall back to caddy's default).
	bare := strings.Join(OSCaddyCLI{}.reloadArgs("/f"), " ")
	if strings.Contains(bare, "--address") {
		t.Fatalf("empty Address must omit --address flag, got %q", bare)
	}
}

// TestDriver_AdminAddress proves the admin address threaded into the default
// OSCaddyCLI is derived from the driver's admin_url (scheme + path stripped), so the
// reload targets the exact IPv4 endpoint crenel's HTTP writes already use.
func TestDriver_AdminAddress(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:2019":    "127.0.0.1:2019",
		"http://127.0.0.1:2019/":   "127.0.0.1:2019",
		"https://10.0.0.13:2019/x": "10.0.0.13:2019",
		"127.0.0.1:2019":           "127.0.0.1:2019",
		"":                         "",
	}
	for in, want := range cases {
		d := &Driver{adminURL: in}
		if got := d.adminAddress(); got != want {
			t.Errorf("adminAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
