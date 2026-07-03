// Package redact masks secret-bearing field values in OUTPUT that Crenel shows to
// the operator, writes to a shareable export, or formats into an error/log line.
//
// It is a presentation concern only. Crenel reads and writes the FULL edge config —
// which can carry Cloudflare DNS-01 tokens, ACME account keys/email, basic-auth
// password hashes, and forward-auth secrets (see SECURITY.md §1) — and those bytes
// can reach a printed status excerpt, a JSON dump, or an admin-API error echo. This
// package scrubs them at the OUTPUT BOUNDARY. It is NEVER applied to the apply /
// read-back-verify / preserve-unmanaged paths: Crenel must write the operator's real
// config and verify the edge against the real live state, so those paths always use
// real values. Redaction only changes what is displayed, and `--show-secrets` turns
// it off when the operator deliberately wants raw values.
//
// Detection is value-aware: a conservative KEY match (a key whose name looks like a
// credential) plus a VALUE heuristic (a string that looks like a credential — a PEM
// private key, a bcrypt/argon hash, a JWT) so a secret in an unexpected field is
// still caught. It is intentionally a leaf package: it imports nothing of Crenel's,
// so core, the drivers, and cmd can all use it without touching the dependency rule.
package redact

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// secretKeyParts are case-insensitive substrings that mark a config KEY (a JSON key
// or a config directive name) as secret-bearing. The list is deliberately specific —
// `key` alone matches far too much (every JSON map key, `serverName`, `pubkey`), so
// only compound credential keys (`private_key`, `access_key`, …) are included. The
// value heuristic (looksSecret) is the backstop for a secret under an unlisted key.
var secretKeyParts = []string{
	"token", "secret", "password", "passwd",
	"apikey", "api_key", "api_token",
	"client_secret", "private_key", "privatekey",
	"access_key", "auth_key", "signing_key", "encryption_key",
	"credential", "passphrase",
	"email", // ACME account email (PII + account-identifying); explicitly requested
}

// IsSecretKey reports whether a config key name looks secret-bearing. Case- and
// separator-insensitive substring match against secretKeyParts.
func IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, p := range secretKeyParts {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

var (
	// pemKey matches an inline PEM private-key block (any key type).
	pemKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// cryptHash matches a bcrypt / argon2 / apr1 password hash — the shape a Caddy
	// basic_auth account's `password` field holds.
	cryptHash = regexp.MustCompile(`\$(?:2[aby]|argon2[id]{0,2}|apr1|6|5|1)\$[^\s"',}<]+`)
	// jwtLike matches a JWT-shaped triple of base64url segments (header.payload.sig),
	// long enough not to collide with ordinary dotted identifiers.
	jwtLike = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	// authzScheme matches an HTTP Authorization-style credential — `Bearer <token>`,
	// `Basic <base64>`, `Token <token>` — as found in a `proxy_set_header
	// Authorization "Bearer …"` or a forward-auth header. The scheme word is kept; the
	// credential (12+ chars, so ordinary prose like "Token expired" never matches) is
	// masked.
	authzScheme = regexp.MustCompile(`(?i)\b(Bearer|Basic|Token|ApiKey)\s+([A-Za-z0-9._~+/=-]{12,})`)
)

// looksSecret reports whether a string VALUE looks like a credential regardless of
// the key it sits under — the heuristic backstop for a secret in an unexpected
// field. Conservative on purpose: only concrete, high-confidence shapes (PEM private
// key, crypt hash, JWT) so ordinary addresses/hosts/paths are never masked.
func looksSecret(v string) bool {
	return pemKey.MatchString(v) || cryptHash.MatchString(v) ||
		jwtLike.MatchString(v) || authzScheme.MatchString(v)
}

// Value masks a single secret value: a long value keeps a short, non-sensitive
// suffix (so the field stays recognizable) behind a bullet run; a short value is
// fully redacted (keeping a suffix would reveal too much of it).
func Value(v string) string {
	const keepSuffix = 4
	const minForSuffix = 12
	if len(v) >= minForSuffix {
		return "••••" + v[len(v)-keepSuffix:]
	}
	return "REDACTED"
}

// JSON walks a JSON document and masks every string value that sits under a
// secret-looking key OR itself looks like a credential, preserving structure and all
// non-secret values. It returns (redacted, true) when the input parsed as JSON, or
// (input, false) when it did not (so callers can fall back to text redaction). A
// re-marshal sorts object keys, which is fine for display.
func JSON(b []byte) ([]byte, bool) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return b, false
	}
	redactValue(&v, false)
	out, err := marshalNoEscape(v)
	if err != nil {
		return b, false
	}
	return out, true
}

// redactValue mutates v in place. underSecretKey is true when v is the value of a
// secret-named key, in which case a string value is masked unconditionally.
func redactValue(v *any, underSecretKey bool) {
	switch t := (*v).(type) {
	case string:
		if underSecretKey || looksSecret(t) {
			*v = Value(t)
		}
	case map[string]any:
		for k, val := range t {
			child := val
			redactValue(&child, IsSecretKey(k))
			t[k] = child
		}
	case []any:
		for i := range t {
			child := t[i]
			redactValue(&child, underSecretKey)
			t[i] = child
		}
	}
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// keyName is the secret-key alternation used by the text-mode regexes. Built from
// secretKeyParts so the two detectors stay in sync.
var keyName = func() string {
	parts := make([]string, len(secretKeyParts))
	for i, p := range secretKeyParts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return "(?:" + strings.Join(parts, "|") + ")"
}()

var (
	// jsonKV matches a JSON-ish "secret_key": "value" pair even in INVALID or
	// TRUNCATED JSON (a bounded RawExcerpt, an error body) where the structural JSON
	// walker can't run. Captures the value (group 3) for masking.
	jsonKV = regexp.MustCompile(`(?i)("[^"]*` + keyName + `[^"]*"\s*:\s*)"([^"]*)"`)
	// directiveKV matches an unquoted directive form — `api_token VALUE`,
	// `password=VALUE`, `secret: VALUE` — as found in nginx/Caddyfile/env/error text.
	directiveKV = regexp.MustCompile(`(?i)(\b\w*` + keyName + `\w*\s*[:=]?\s+|\b\w*` + keyName + `\w*\s*=\s*)([^\s"',}();]+)`)
)

// Text masks secrets in a NON-JSON (or truncated/invalid-JSON) string: key/value
// directive forms whose key looks secret, plus standalone credential-shaped values
// (PEM blocks, crypt hashes, JWTs). Best-effort by design — see SECURITY.md §5.
func Text(s string) string {
	s = pemKey.ReplaceAllString(s, "REDACTED")
	s = cryptHash.ReplaceAllStringFunc(s, Value)
	s = jwtLike.ReplaceAllStringFunc(s, Value)
	s = authzScheme.ReplaceAllStringFunc(s, func(m string) string {
		g := authzScheme.FindStringSubmatch(m)
		return g[1] + " " + Value(g[2])
	})
	s = jsonKV.ReplaceAllStringFunc(s, func(m string) string {
		g := jsonKV.FindStringSubmatch(m)
		return g[1] + `"` + Value(g[2]) + `"`
	})
	s = directiveKV.ReplaceAllStringFunc(s, func(m string) string {
		g := directiveKV.FindStringSubmatch(m)
		return g[1] + Value(g[2])
	})
	return s
}

// Snippet redacts a bounded config excerpt or an error body that MAY be JSON: it
// uses the structural JSON walker when the input parses, and falls back to text
// redaction (which also handles truncated/invalid JSON) otherwise. This is the
// general entry point for RawExcerpt fields and admin-API error echoes.
func Snippet(s string) string {
	if out, ok := JSON([]byte(s)); ok {
		return string(out)
	}
	return Text(s)
}
