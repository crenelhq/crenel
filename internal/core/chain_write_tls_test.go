package core

import (
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestForwardRoute_UpstreamTLSDecision pins the front-leg HTTPS decision (TRIAL-FIX-4):
// a chain-forward to a `:443` downstream must carry UpstreamTLS so the driver renders
// upstream TLS + Host (else the downstream answers 400 "HTTP request to an HTTPS
// server"); a plain-HTTP downstream must stay plain. An explicit DownstreamScheme wins
// over the port inference in both directions.
func TestForwardRoute_UpstreamTLSDecision(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		scheme  string
		wantTLS bool
	}{
		{"infer https from :443", "10.0.0.13:443", "", true},
		{"infer http from non-443 port", "10.0.0.7:8200", "", false},
		{"bare host infers plain (conservative)", "10.0.0.13", "", false},
		{"explicit https overrides non-443 port", "10.0.0.7:8443", "https", true},
		{"explicit http overrides :443", "10.0.0.13:443", "http", false},
		{"explicit scheme is case-insensitive", "10.0.0.7:8200", "HTTPS", true},
		{"ipv6 literal reads its port not an address colon", "[2001:db8::1]:443", "", true},
		{"ipv6 literal non-443 stays plain", "[2001:db8::1]:8200", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := EdgeBinding{
				Name:              "vps",
				DownstreamEdge:    "home",
				DownstreamAddress: tc.addr,
				DownstreamScheme:  tc.scheme,
			}
			r, err := b.forwardRoute("vault.homelab.example")
			if err != nil {
				t.Fatalf("forwardRoute: %v", err)
			}
			if r.Upstream.UpstreamTLS != tc.wantTLS {
				t.Errorf("UpstreamTLS = %v, want %v (addr=%q scheme=%q)",
					r.Upstream.UpstreamTLS, tc.wantTLS, tc.addr, tc.scheme)
			}
			// The forward always carries the host as its SNI/cert host and never auth
			// (auth lives at the terminal/downstream edge).
			if r.Upstream.ServerName != "vault.homelab.example" {
				t.Errorf("ServerName = %q, want the host", r.Upstream.ServerName)
			}
			if r.Upstream.Auth != "" {
				t.Errorf("front forward must carry no auth, got %q", r.Upstream.Auth)
			}
			if r.Upstream.Mode != model.ModeHTTPProxy {
				t.Errorf("forward mode = %q, want http_proxy", r.Upstream.Mode)
			}
		})
	}
}

// TestDialIsTLSPort covers the port sniff directly, including the bare-host and IPv6
// edges the decision relies on.
func TestDialIsTLSPort(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.13:443":   true,
		"10.0.0.7:8200":     false,
		"10.0.0.13":       false,
		"host:443":          true,
		"[2001:db8::1]:443": true,
		"[2001:db8::1]:80":  false,
		"":                  false,
	}
	for dial, want := range cases {
		if got := dialIsTLSPort(dial); got != want {
			t.Errorf("dialIsTLSPort(%q) = %v, want %v", dial, got, want)
		}
	}
}
