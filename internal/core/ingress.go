package core

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// ingress.go detects an edge's OFF-EDGE reachability mechanism (a tunnel/overlay)
// from a configured ingress file — the axis-4 "exposed isn't a public port" gap
// (TOPOLOGY-RISK-REGISTER §4.3). Detection is driver-agnostic (cloudflared/Tailscale
// front any proxy), lives in core, and is conservative: a recognized signature
// classifies the mechanism; a present-but-unrecognized ingress file is DECLARED
// UNKNOWN (externally fronted, mechanism undetermined) rather than assumed internal;
// an absent/unreadable file yields no claim ("").

// detectIngressFile classifies an ingress config file. The operator pointing crenel
// at the file is itself the signal that an external front exists, so a readable file
// always yields at least IngressUnknown — never "" (which would read as "ordinary
// public listener"). An unreadable/absent file yields "" (genuinely no signal): a
// missing optional path must not fabricate a posture.
func detectIngressFile(path string) model.IngressKind {
	b, err := os.ReadFile(path)
	if err != nil {
		return "" // absent/unreadable — no signal (do not assume external OR internal)
	}
	s := string(b)
	switch {
	case looksLikeCloudflared(s):
		return model.IngressTunnel
	case looksLikeTailscaleServe(s):
		return model.IngressOverlay
	default:
		// A configured ingress front crenel cannot classify: declare UNKNOWN
		// (externally reachable, mechanism undetermined) — never assume internal.
		return model.IngressUnknown
	}
}

// tunnelIngressHosts recovers the PER-HOST public mapping from a tunnel ingress config —
// the P3 correctness step beyond the coarse edge-level IngressKind. For a recognized
// cloudflared config it returns the exact published hostnames + wildcard zones and
// parsed=true; for a recognized Tailscale ServeConfig (serve.json) it returns the
// AllowFunnel-published hosts (the public set — tailnet-only Web entries are NOT
// returned and are deliberately left declared-unknown, since they are identity-enforced
// by the tailnet, not internet-public). So audit can resolve each host's external
// reachability by OBSERVATION (the tunnel analogue of P4's chain follow-through)
// instead of declaring the whole edge UNKNOWN. An unrecognized/unparseable config
// returns parsed=false — the safe-by-default fallback keeps the coarse declared-unknown
// finding (a mapping is never fabricated).
func tunnelIngressHosts(path string) (exact map[string]bool, wildcards []string, parsed bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
	s := string(b)
	switch {
	case looksLikeCloudflared(s):
		exact, wildcards = cloudflaredIngressHosts(s)
		return exact, wildcards, true
	case looksLikeTailscaleServe(s):
		exact = tailscaleFunnelHosts(s)
		return exact, nil, true
	}
	return nil, nil, false
}

// tailscaleFunnelHosts extracts the PUBLIC funnel hosts from a Tailscale ServeConfig
// (serve.json). AllowFunnel keys are `host:port`; this returns the set of HOSTS (port
// stripped) whose ServeConfig opts them into the public funnel. Tailnet-only Web
// entries (Web key without a matching AllowFunnel) are NOT returned: they are
// identity-enforced by the tailnet ACL and not internet-public, so claiming them as
// `tunnel_public` would over-claim. A malformed JSON yields an empty set (the caller
// keeps the safe coarse declaration).
func tailscaleFunnelHosts(s string) map[string]bool {
	out := map[string]bool{}
	var cfg struct {
		AllowFunnel map[string]bool `json:"AllowFunnel"`
	}
	if err := json.Unmarshal([]byte(s), &cfg); err != nil {
		return out
	}
	for key, allowed := range cfg.AllowFunnel {
		if !allowed {
			continue
		}
		host := key
		if i := strings.LastIndex(host, ":"); i >= 0 {
			// `host:port` — strip the port. A bare IPv6 in brackets is not a host
			// Tailscale serves under (its ServeConfig keys are tailnet/DNS hostnames),
			// so the simple LastIndex strip is faithful to the real shape.
			host = host[:i]
		}
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		out[host] = true
	}
	return out
}

// cloudflaredIngressHosts extracts the hostnames a cloudflared config.yml publishes via
// its `ingress:` rule list (`- hostname: <host>`). A `*.zone` rule is a wildcard; an exact
// host is exact. The trailing catch-all (`- service: http_status:404`, no hostname) and the
// `service:` lines are ignored. Line-based + quote-tolerant, matching the conservative
// signature scan; no YAML dependency (the build stays zero-dependency).
func cloudflaredIngressHosts(s string) (exact map[string]bool, wildcards []string) {
	exact = map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(strings.TrimSpace(line))
		t = strings.TrimSpace(strings.TrimPrefix(t, "-")) // a list item: "- hostname: x"
		if !strings.HasPrefix(t, "hostname:") {
			continue
		}
		val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "hostname:")), `"'`)
		if val == "" {
			continue
		}
		if strings.HasPrefix(val, "*.") {
			wildcards = append(wildcards, strings.ToLower(strings.TrimPrefix(val, "*.")))
		} else {
			exact[strings.ToLower(val)] = true
		}
	}
	return exact, wildcards
}

// ingressPublishes reports whether a host is published externally by a recovered tunnel
// ingress mapping — an exact match, or a subdomain of a `*.zone` wildcard. The wildcard
// test is a conservative superset of Cloudflare's single-label semantics (it also matches
// deeper subdomains), so it never UNDER-reports a host as private.
func ingressPublishes(host string, exact map[string]bool, wildcards []string) bool {
	h := strings.ToLower(host)
	if exact[h] {
		return true
	}
	for _, w := range wildcards {
		if h != w && strings.HasSuffix(h, "."+w) {
			return true
		}
	}
	return false
}

// looksLikeCloudflared recognizes a cloudflared tunnel config (config.yml): it pairs
// a `tunnel:` identifier with an `ingress:` rule list (hostname -> service), and/or a
// `credentials-file:`. Requiring two co-occurring markers keeps it conservative — a
// stray `ingress:` key alone does not fire.
func looksLikeCloudflared(s string) bool {
	hasTunnel := containsKey(s, "tunnel:") || containsKey(s, "credentials-file:")
	hasIngress := containsKey(s, "ingress:") || strings.Contains(s, "cloudflared") ||
		strings.Contains(s, ".cfargotunnel.com")
	return hasTunnel && hasIngress
}

// looksLikeTailscaleServe recognizes a Tailscale serve/funnel ServeConfig (serve.json):
// its distinctive top-level keys are `TCP`/`Web`/`AllowFunnel`. AllowFunnel marks a
// PUBLIC funnel; Web/TCP without it is a tailnet-scoped serve — both decouple
// reachability from the local listener, so both classify as overlay ingress.
func looksLikeTailscaleServe(s string) bool {
	return strings.Contains(s, "AllowFunnel") ||
		(strings.Contains(s, "\"Web\"") && strings.Contains(s, "\"Handlers\"")) ||
		strings.Contains(s, "tailscale serve") || strings.Contains(s, "funnel")
}

// containsKey reports whether a YAML-ish key appears at a line start (optionally
// indented), so `tunnel:` matches a real key but a substring inside a value does not.
func containsKey(s, key string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			return true
		}
	}
	return false
}
