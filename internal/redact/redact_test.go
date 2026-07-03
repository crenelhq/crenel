package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValue(t *testing.T) {
	cases := map[string]string{
		"cf_token_abcdEFGH1234": "••••1234", // long: keep last 4
		"shortpass":             "REDACTED", // < 12: fully redacted
		"":                      "REDACTED",
	}
	for in, want := range cases {
		if got := Value(in); got != want {
			t.Errorf("Value(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSecretKey(t *testing.T) {
	secret := []string{"api_token", "apiToken", "API_KEY", "password", "client_secret",
		"private_key", "tls_private_key", "access_key", "passphrase", "email", "cf_api_token"}
	for _, k := range secret {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false, want true", k)
		}
	}
	// `key` alone, and ordinary config keys, must NOT match (else everything redacts).
	notSecret := []string{"key", "host", "dial", "address", "upstreams", "handler",
		"server_name", "listen", "routes", "match"}
	for _, k := range notSecret {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true, want false", k)
		}
	}
}

// caddyish is a Caddy-admin-config-shaped doc carrying one of each secret class plus
// non-secret routing fields that must survive untouched.
const caddyish = `{
  "apps": {
    "tls": {
      "automation": {
        "policies": [{
          "issuers": [{
            "module": "acme",
            "email": "ops@example.com",
            "challenges": {"dns": {"provider": {"name": "cloudflare", "api_token": "cf-SECRET-abcd1234WXYZ"}}}
          }]
        }]
      }
    },
    "http": {
      "servers": {"srv0": {"listen": [":443"], "routes": [
        {"match": [{"host": ["grafana.example.com"]}],
         "handle": [
           {"handler": "basic_auth", "accounts": [{"username": "admin", "password": "$2a$14$abcdefghijklmnopqrstuv"}]},
           {"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5:3000"}]}
         ]}
      ]}}
    }
  }
}`

func TestJSONMasksEverySecretClass(t *testing.T) {
	out, ok := JSON([]byte(caddyish))
	if !ok {
		t.Fatal("JSON() reported invalid input on valid JSON")
	}
	s := string(out)

	// Secrets gone.
	for _, leak := range []string{"cf-SECRET-abcd1234WXYZ", "ops@example.com", "$2a$14$"} {
		if strings.Contains(s, leak) {
			t.Errorf("secret %q leaked through JSON redaction:\n%s", leak, s)
		}
	}
	// Non-secret routing fields preserved.
	for _, keep := range []string{"grafana.example.com", "10.0.0.5:3000", "reverse_proxy", ":443"} {
		if !strings.Contains(s, keep) {
			t.Errorf("non-secret %q was lost by redaction:\n%s", keep, s)
		}
	}
	// Output is still valid JSON.
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Errorf("redacted output is not valid JSON: %v", err)
	}
}

func TestJSONValueHeuristicCatchesSecretUnderInnocuousKey(t *testing.T) {
	// A PEM private key under a key name that matches NO secret pattern ("data") must
	// still be masked by the value heuristic.
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
	in, _ := json.Marshal(map[string]string{"data": pem, "host": "ok.example.com"})
	out, ok := JSON(in)
	if !ok {
		t.Fatal("JSON() reported invalid input")
	}
	s := string(out)
	if strings.Contains(s, "BEGIN PRIVATE KEY") {
		t.Errorf("PEM key under innocuous key leaked:\n%s", s)
	}
	if !strings.Contains(s, "ok.example.com") {
		t.Errorf("non-secret host lost:\n%s", s)
	}
}

func TestJSONLeavesCleanConfigUntouched(t *testing.T) {
	// No secrets at all → byte-identical semantics (no over-redaction of addresses).
	clean := `{"host":"a.example.com","dial":"10.0.0.1:80","handler":"reverse_proxy"}`
	out, ok := JSON([]byte(clean))
	if !ok {
		t.Fatal("JSON() reported invalid input")
	}
	for _, keep := range []string{"a.example.com", "10.0.0.1:80", "reverse_proxy"} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("clean config lost %q: %s", keep, out)
		}
	}
}

func TestTextHandlesTruncatedExcerpt(t *testing.T) {
	// A bounded RawExcerpt is truncated JSON (won't parse) — Text must still mask the
	// crenel_policy reference and an embedded hash.
	trunc := `{"@id":"crenel-route-x","handle":[{"handler":"forward_auth","crenel_policy":"authelia"},{"handler":"basic_auth","password":"$2y$12$abcdefghijklmnop"`
	got := Text(trunc)
	if strings.Contains(got, "$2y$12$abcdefghijklmnop") {
		t.Errorf("hash leaked through Text: %s", got)
	}
}

func TestTextDirectiveForms(t *testing.T) {
	cases := []struct{ in, leak string }{
		{`api_token cf-abcd-1234-SECRET`, "cf-abcd-1234-SECRET"}, // nginx/caddyfile space form
		{`password=hunter2-the-password`, "hunter2-the-password"},
		{`client_secret: oauth-XYZ-9876-secret`, "oauth-XYZ-9876-secret"},
	}
	for _, c := range cases {
		if got := Text(c.in); strings.Contains(got, c.leak) {
			t.Errorf("Text(%q) leaked %q: %s", c.in, c.leak, got)
		}
	}
}

func TestSnippetRoutesJSONvsText(t *testing.T) {
	// Valid JSON → structural walker.
	if got := Snippet(`{"api_token":"abc-DEF-1234-secret"}`); strings.Contains(got, "abc-DEF-1234-secret") {
		t.Errorf("Snippet leaked secret from valid JSON: %s", got)
	}
	// Invalid/truncated JSON → text fallback.
	if got := Snippet(`...api_token cf-abcd-1234-SECRET truncated`); strings.Contains(got, "cf-abcd-1234-SECRET") {
		t.Errorf("Snippet leaked secret from non-JSON: %s", got)
	}
}

func TestPEMAndJWTStandalone(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
	if got := Text(jwt); strings.Contains(got, jwt) {
		t.Errorf("JWT not redacted: %s", got)
	}
}
