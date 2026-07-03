package traefik

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// codec.go isolates the two format-specific concerns: (1) serializing the
// dynamic-config document, and (2) parsing a Traefik router `rule` enough to
// know which host(s) it matches and whether it is a permissive catch-all.
//
// READ format (T1): a real Traefik file provider is fed YAML (or TOML), not JSON, so
// decode() AUTO-DETECTS the wire format. A document that opens with `{` is parsed as
// JSON (crenel's own output, and the historical fixtures); anything else is parsed by
// the zero-dependency YAML-SUBSET decoder in yaml.go, which produces a generic tree
// that we marshal to JSON and unmarshal into dynamicConfig — REUSING the struct tags so
// both formats share one shape mapping. TOML is NOT supported (declared, see below).
//
// WRITE format stays JSON (see encode): JSON ⊂ YAML, so Traefik's YAML parser accepts
// crenel's JSON output verbatim; only the reader needs YAML.
func decode(b []byte) (dynamicConfig, error) {
	var cfg dynamicConfig
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" || trimmed == "~" {
		return cfg, nil
	}
	if looksLikeJSON(trimmed) {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return dynamicConfig{}, err
		}
		return cfg, nil
	}
	// YAML subset: parse to a generic tree, then reuse JSON struct mapping.
	tree, err := parseYAMLSubset(string(b))
	if err != nil {
		return dynamicConfig{}, fmt.Errorf("parse YAML dynamic-config: %w", err)
	}
	jb, err := json.Marshal(tree)
	if err != nil {
		return dynamicConfig{}, fmt.Errorf("re-encode YAML tree: %w", err)
	}
	if err := json.Unmarshal(jb, &cfg); err != nil {
		return dynamicConfig{}, fmt.Errorf("map YAML dynamic-config to schema: %w", err)
	}
	return cfg, nil
}

// looksLikeJSON reports whether a (trimmed) document is JSON rather than YAML. A
// Traefik dynamic config is a top-level MAPPING; crenel's JSON output (and the JSON
// fixtures) open with `{`, while a YAML file opens with a bare key, a comment, or a
// document marker. Detection is by the first meaningful byte so a genuine YAML file is
// never fed to the JSON parser (which is what produced the `invalid character 'h'`
// failure on a real dynamic.yml).
func looksLikeJSON(trimmed string) bool {
	return strings.HasPrefix(trimmed, "{")
}

// encode serializes the dynamic config, OMITTING an empty `http` (or `tcp`) element.
// Bench gap T6: the struct's `HTTP httpConfig json:"http"` has no omitempty, so an
// emptied config marshaled to `{"http":{}}` (or `{"http":{"routers":{},...}}`), which
// real Traefik REJECTS ("http cannot be a standalone element" / "routers cannot be a
// standalone element") — so removing the LAST managed route silently failed to take
// effect (the route lingered). An empty document `{}` IS accepted by Traefik and
// correctly contributes nothing, so we emit the elements only when non-empty.
func encode(cfg dynamicConfig) ([]byte, error) {
	doc := map[string]any{}
	if len(cfg.HTTP.Routers) > 0 || len(cfg.HTTP.Services) > 0 {
		doc["http"] = cfg.HTTP
	}
	if cfg.TCP != nil && (len(cfg.TCP.Routers) > 0 || len(cfg.TCP.Services) > 0) {
		doc["tcp"] = cfg.TCP
	}
	return json.MarshalIndent(doc, "", "  ")
}

var hostRuleRE = regexp.MustCompile("Host\\(`([^`]+)`\\)")

// parseHosts extracts the exact hostnames a router rule matches via Host(`...`)
// matchers (Traefik allows several, comma/||-separated). Returns nil for a rule
// with no exact Host() matcher (host-less / catch-all / path-only).
func parseHosts(rule string) []string {
	var hosts []string
	for _, m := range hostRuleRE.FindAllStringSubmatch(rule, -1) {
		// A Host() rule may list several backtick-quoted hosts: Host(`a`,`b`).
		for _, part := range strings.Split(m[1], "`,`") {
			h := strings.TrimSpace(part)
			if h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

// detectGenerator best-effort recognizes a dynamic config DERIVED from container
// labels / an orchestrator rather than a static file: such routers carry a provider
// suffix (`<name>@docker`, `@swarm`, `@kubernetescrd`, …) that the file provider
// never produces. When seen, the config is generated elsewhere and crenel's file
// edit would be overwritten on the next provider re-sync, so the edge is marked
// foreign-managed and the refuse-to-manage gate engages (register §3.2/§4.6).
// Deterministic (sorted scan); conservative (only an explicit provider suffix fires).
//
// Pangolin (fosrl/pangolin) is detected FIRST and separately: it is a self-hosted
// tunneled reverse proxy that GENERATES Traefik dynamic config from its database
// (served via Traefik's HTTP provider from `pangolin:3001`), attaching its access
// plugin middleware `badger` (github.com/fosrl/badger) to every generated router.
// A file edit crenel made would be overwritten on Pangolin's next sync, so the edge
// is foreign. `badger` is Pangolin-specific (its WireGuard/identity access plugin),
// so keying on it is a strong, low-false-positive signal that survives whether the
// config reaches crenel via the file or HTTP provider (the `@http` suffix alone is
// NOT a generator signal — a plain HTTP provider is hand-authorable).
func detectGenerator(cfg dynamicConfig) string {
	if hasPangolinSignature(cfg) {
		return "pangolin"
	}
	names := make([]string, 0, len(cfg.HTTP.Routers))
	for name := range cfg.HTTP.Routers {
		names = append(names, name)
	}
	if cfg.TCP != nil {
		for name := range cfg.TCP.Routers {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		at := strings.LastIndex(name, "@")
		if at < 0 {
			continue
		}
		switch strings.ToLower(name[at+1:]) {
		case "docker":
			return "traefik-docker-labels"
		case "swarm":
			return "traefik-swarm-labels"
		case "kubernetes", "kubernetescrd", "kubernetesingress", "kubernetesgateway":
			return "traefik-kubernetes"
		case "nomad":
			return "traefik-nomad-labels"
		case "consulcatalog":
			return "traefik-consul-catalog"
		case "ecs":
			return "traefik-ecs"
		}
	}
	return ""
}

// pangolinMiddleware is Pangolin's access-control plugin middleware. Its base name
// is `badger`; via the HTTP/file provider it surfaces as `badger`, `badger@http`,
// or `badger@file`. Matching the base name (before any `@provider` suffix) catches
// all forms.
const pangolinMiddleware = "badger"

// hasPangolinSignature reports whether any HTTP router attaches Pangolin's `badger`
// access middleware — the marker that the dynamic config is generated by Pangolin.
func hasPangolinSignature(cfg dynamicConfig) bool {
	for _, r := range cfg.HTTP.Routers {
		if r == nil {
			continue
		}
		for _, mw := range r.Middlewares {
			if middlewareBaseName(mw) == pangolinMiddleware {
				return true
			}
		}
	}
	return false
}

// middlewareBaseName strips a Traefik provider suffix (`name@provider`) from a
// middleware reference, returning just the name.
func middlewareBaseName(mw string) string {
	if at := strings.LastIndex(mw, "@"); at >= 0 {
		return mw[:at]
	}
	return mw
}

// withScheme renders a model upstream address (host:port) as a Traefik server
// URL. If it already carries a scheme it is left as-is.
func withScheme(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "http://" + addr
}

// stripScheme is the inverse: it reduces a Traefik server URL to the host:port
// form the model uses, so a read-back round-trips to the same Route.Address.
func stripScheme(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		return url[i+3:]
	}
	return url
}

// predicateRE captures every Traefik routing-predicate function name in a rule
// (`Name(`), after backtick-quoted VALUES are stripped so a `(` inside a regexp value
// is never mistaken for a predicate.
var predicateRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*)\s*\(`)

// backtickValueRE matches a backtick-quoted predicate argument, removed before scanning.
var backtickValueRE = regexp.MustCompile("`[^`]*`")

// hostPredicates are the matcher functions crenel models as a host (or host-family)
// match. Every OTHER routing predicate (Path / PathPrefix / PathRegexp / Method /
// Headers / HeadersRegexp / Query / ClientIP / …) scopes a route BEYOND host
// granularity, which the host-granular model cannot represent.
var hostPredicates = map[string]bool{
	"Host": true, "HostRegexp": true, "HostSNI": true, "HostSNIRegexp": true, "HostHeader": true,
}

// nonHostPredicates returns the sorted, deduped set of NON-host routing predicates a
// rule carries. A non-empty result means the router's reachability is conditioned on
// more than the host (a path/method/header/query/IP scope), so reading it as a plain
// host route would be a MISREAD-↓ — the read model must DECLARE it (matcher_conditional)
// instead. Unknown future predicates are treated as non-host (conservative). Empty => a
// pure host-family rule crenel fully understands.
func nonHostPredicates(rule string) []string {
	stripped := backtickValueRE.ReplaceAllString(rule, "``")
	seen := map[string]bool{}
	for _, m := range predicateRE.FindAllStringSubmatch(stripped, -1) {
		if name := m[1]; !hostPredicates[name] {
			seen[name] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var hostSNIRE = regexp.MustCompile("HostSNI\\(`([^`]+)`\\)")

// parseHostSNI extracts the SNI host(s) a TCP router rule matches.
func parseHostSNI(rule string) []string {
	var hosts []string
	for _, m := range hostSNIRE.FindAllStringSubmatch(rule, -1) {
		for _, part := range strings.Split(m[1], "`,`") {
			if h := strings.TrimSpace(part); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

var catchAllRE = regexp.MustCompile(`HostRegexp\(`)

// isCatchAll reports whether a rule matches an unbounded set of hosts — a
// HostRegexp(...) (commonly `.+`/`.*`) or a rule with no Host()/HostRegexp()
// constraint at all (e.g. PathPrefix(`/`) only). Such a rule, if it forwards to a
// real backend, is a permissive catch-all that defeats the default-deny.
func isCatchAll(rule string) bool {
	if len(parseHosts(rule)) > 0 {
		return false // has an exact Host() constraint => not a catch-all
	}
	if catchAllRE.MatchString(rule) {
		return true
	}
	// No Host() and no HostRegexp(): the rule constrains only path/headers/etc.,
	// so it matches every host.
	return true
}
