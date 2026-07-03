package nginx

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// codec.go isolates the nginx-config FORMAT concerns: splitting the file into
// top-level chunks, classifying each as a crenel-managed server block / the
// crenel-deny block / unmanaged text, and rendering crenel's own blocks. This is
// deliberately a DIFFERENT shape than the other drivers' formats — Caddy's admin
// JSON, Traefik's JSON tree, NetBird's grant store — which is the point of a fourth
// driver: it stresses the EdgeProvider port against a brace-DSL config with
// COMMENT-MARKER ownership rather than key-prefix or @id ownership.

const (
	// managedMarker tags a server block crenel owns; everything without it (and not
	// the deny) is unmanaged and preserved verbatim across a read-modify-write.
	managedMarker = "# crenel-managed:"
	// denyMarker tags the always-rendered default-deny catch-all server block.
	denyMarker = "# crenel-deny:"
	// header is the file preamble crenel writes.
	header = "# crenel-managed nginx config v1 — crenel blocks are regenerated; edit other blocks freely\n"
)

// chunk is one top-level element of the config: its verbatim text plus a parsed
// view when it is a server block.
type chunk struct {
	raw      string
	isServer bool
	managed  bool   // a crenel-managed server block
	isDeny   bool   // the crenel-deny default-deny block
	host     string // server_name (first real name; "" for the catch-all "_")
	addr     string // proxy_pass backend, scheme-stripped (host:port)
	catchAll bool   // default_server or wildcard server_name (_/*)
	forwards bool   // has a proxy_pass to a real backend
	authURI  string // auth_request URI (forward-auth reference), "" if none
	ports    []int  // the listen port(s) of this server block (for implicit-default-server modeling)
	// pathScoped marks a vhost that routes by location PATH beyond a single root
	// `location /` — several proxying locations, or one non-root location. The
	// host-granular model cannot represent it (reading it as host->firstBackend would
	// silently drop the other paths), so normalize DECLARES it matcher_conditional.
	pathScoped bool
	extraPaths []string // the proxying location paths, for the declaration's reason
}

var (
	serverNameRE   = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	proxyPassRE    = regexp.MustCompile(`(?m)^\s*proxy_pass\s+([^;]+);`)
	authRequestRE  = regexp.MustCompile(`(?m)^\s*auth_request\s+([^;]+);`)
	locationHeadRE = regexp.MustCompile(`^\s*location\s+(.+?)\s*\{`)
	// listenRE pulls the numeric port from a `listen` directive, tolerating an
	// address/host prefix (`127.0.0.1:8080`, `[::]:80`) and trailing flags
	// (`ssl`, `default_server`). Used to model nginx's per-port implicit default
	// server, so default-deny is judged on the port that actually serves traffic.
	listenRE = regexp.MustCompile(`(?m)^\s*listen\s+(?:[^;]*?[:\s])?(\d+)\b`)
)

// normalizeLocationURI strips an nginx location modifier (=, ~, ~*, ^~) from a location
// header, returning the bare uri (e.g. `= /authelia` -> `/authelia`, `/api` -> `/api`,
// `@named` -> `@named`). Used to compare a location against an auth_request URI.
func normalizeLocationURI(head string) string {
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "=", "~", "~*", "^~":
		if len(fields) > 1 {
			return fields[1]
		}
		return ""
	}
	return fields[0]
}

// proxyLocationPaths returns the uri of every `location` block in a server that contains
// a proxy_pass to a backend, in source order. Brace depth is tracked so a proxy_pass in a
// nested block is attributed to its enclosing location. This is how crenel SEES whether a
// vhost routes by path: a single root `location /` is an ordinary host route, but several
// proxying locations (or a single non-root one) are path-granular routing the
// host-granular model cannot represent.
func proxyLocationPaths(serverRaw string) []string {
	var paths []string
	lines := strings.Split(serverRaw, "\n")
	for i := 0; i < len(lines); i++ {
		m := locationHeadRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		uri := normalizeLocationURI(m[1])
		depth := strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		hasProxy := proxyPassRE.MatchString(lines[i])
		j := i + 1
		for j < len(lines) && depth > 0 {
			if proxyPassRE.MatchString(lines[j]) {
				hasProxy = true
			}
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			j++
		}
		if hasProxy {
			paths = append(paths, uri)
		}
		i = j - 1 // skip the consumed body (a nested location belongs to this one's scope)
	}
	return paths
}

// splitTopLevel breaks the config text into top-level chunks. Leading comment and
// blank lines attach to the block that follows (so a managedMarker stays with its
// server block). Brace depth is tracked so nested location{} blocks don't split a
// server block.
func splitTopLevel(text string) []string {
	var chunks []string
	var buf []string
	depth := 0
	opened := false

	flush := func() {
		if strings.TrimSpace(strings.Join(buf, "\n")) != "" {
			chunks = append(chunks, strings.Join(buf, "\n"))
		}
		buf = nil
		opened = false
	}

	for _, line := range strings.Split(text, "\n") {
		buf = append(buf, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth < 0 {
			depth = 0
		}
		if strings.Contains(line, "{") {
			opened = true
		}
		switch {
		case opened && depth == 0:
			flush() // a block just closed
		case !opened && depth == 0 && strings.HasSuffix(strings.TrimSpace(line), ";"):
			flush() // a simple top-level directive
		}
	}
	flush()
	return chunks
}

// classify parses a chunk into its typed view.
func classify(raw string) chunk {
	c := chunk{raw: raw}
	// A server block opens with a "server" token before its first brace.
	head := raw
	if i := strings.Index(raw, "{"); i >= 0 {
		head = raw[:i]
	}
	for _, line := range strings.Split(head, "\n") {
		if t := strings.TrimSpace(line); t == "server" || strings.HasPrefix(t, "server ") || strings.HasPrefix(t, "server\t") {
			c.isServer = true
			break
		}
	}
	if !c.isServer {
		return c
	}
	c.managed = strings.Contains(raw, managedMarker)
	c.isDeny = strings.Contains(raw, denyMarker)

	if m := serverNameRE.FindStringSubmatch(raw); m != nil {
		names := strings.Fields(strings.TrimSpace(m[1]))
		for _, n := range names {
			if n == "_" || n == "*" {
				c.catchAll = true
				continue
			}
			if c.host == "" {
				c.host = n
			}
		}
	}
	if strings.Contains(raw, "default_server") {
		c.catchAll = true
	}
	for _, m := range listenRE.FindAllStringSubmatch(raw, -1) {
		if p, err := strconv.Atoi(m[1]); err == nil {
			c.ports = append(c.ports, p)
		}
	}
	if m := proxyPassRE.FindStringSubmatch(raw); m != nil {
		c.addr = stripScheme(strings.TrimSpace(m[1]))
		c.forwards = true
	}
	if m := authRequestRE.FindStringSubmatch(raw); m != nil {
		c.authURI = strings.TrimSpace(m[1])
	}
	// Path-granularity detection: a vhost that proxies from more than a single root
	// `location /` routes by path, which the host-granular model cannot represent. The
	// auth_request subrequest location (its proxy_pass dials the authorizer, not the
	// host's backend) is excluded so a forward-auth vhost is not mistaken for path routing.
	if c.forwards {
		var real []string
		for _, p := range proxyLocationPaths(raw) {
			if c.authURI != "" && p == c.authURI {
				continue
			}
			real = append(real, p)
		}
		if len(real) > 1 || (len(real) == 1 && real[0] != "/") {
			c.pathScoped = true
			c.extraPaths = real
		}
	}
	return c
}

// detectGenerator best-effort recognizes a config GENERATED by another tool from an
// in-band signature, so the edge can be marked foreign-managed (read-only) and the
// refuse-to-manage gate engages (TOPOLOGY-RISK-REGISTER §3.3/§4.6). Nginx Proxy
// Manager — the most common homelab proxy — regenerates `/data/nginx/proxy_host/*.conf`
// from its SQLite DB on every UI save, so a crenel comment-marker edit would be
// wiped; NPM's generated files carry a recognizable signature. Detection is
// conservative (a clear signature only): a false negative is still covered by the
// rest of the unknown net, and a false positive only costs a (safe) refusal.
func detectGenerator(text string) string {
	if strings.Contains(text, "Nginx Proxy Manager") ||
		strings.Contains(text, "/data/nginx/proxy_host") {
		return "nginx-proxy-manager"
	}
	return ""
}

// boundedExcerpt returns a length-bounded snippet of a config chunk for an
// Unparsed entry's RawExcerpt, so a large block never floods status output.
func boundedExcerpt(s string) string {
	s = strings.TrimSpace(s)
	const max = 240
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// parseChunks splits + classifies the whole config.
func parseChunks(text string) []chunk {
	var out []chunk
	for _, raw := range splitTopLevel(text) {
		out = append(out, classify(raw))
	}
	return out
}

// tlsConfig describes how crenel's own server blocks terminate TLS. Default
// (zero value) is HTTP on :80 — which LOADS on a stock nginx; the previous
// hardcoded `listen 443 ssl` emitted NO ssl_certificate and made `nginx -t` FAIL
// (bench gap N1), so the file never reloaded. TLS is the operator's cert to own:
// when CertPath/KeyPath are configured crenel emits `listen 443 ssl` WITH the
// ssl_certificate directives; otherwise it serves HTTP so the config is valid.
type tlsConfig struct {
	Port     int    // listen port for crenel's blocks (0 => 80)
	SSL      bool   // emit `ssl` + ssl_certificate directives
	CertPath string // ssl_certificate (required when SSL)
	KeyPath  string // ssl_certificate_key (required when SSL)
}

func (t tlsConfig) port() int {
	if t.Port != 0 {
		return t.Port
	}
	if t.SSL {
		return 443
	}
	return 80
}

// listenLine renders the `listen` directive for a crenel block. extra is appended
// (e.g. "default_server" for the deny block).
func (t tlsConfig) listenLine(extra string) string {
	parts := []string{"listen", strconv.Itoa(t.port())}
	if t.SSL {
		parts = append(parts, "ssl")
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ") + ";"
}

// tlsDirectives renders the indented ssl_certificate lines (empty unless SSL).
func (t tlsConfig) tlsDirectives() string {
	if !t.SSL {
		return ""
	}
	return fmt.Sprintf("    ssl_certificate %s;\n    ssl_certificate_key %s;\n", t.CertPath, t.KeyPath)
}

// renderConfig rebuilds the config: the header, every unmanaged chunk verbatim (in
// original order), then crenel's managed server blocks (sorted by host), then the
// always-present default-deny block. Only crenel's own blocks are regenerated. The
// deny's `default_server` sits on the SAME listen port as the managed blocks, so an
// unmatched host on that port is actually denied (444) rather than falling through to
// nginx's implicit default server (the first server on the port) — bench gap N4.
func renderConfig(unmanaged []string, managed []model.Route, authURIFor func(string) string, tls tlsConfig) string {
	var b strings.Builder
	b.WriteString(header)
	for _, raw := range unmanaged {
		b.WriteString("\n")
		b.WriteString(strings.Trim(raw, "\n"))
		b.WriteString("\n")
	}
	sorted := append([]model.Route(nil), managed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })
	for _, r := range sorted {
		// A forward-auth policy emits an `auth_request <uri>;` reference inside
		// location / (the operator defines the internal auth location).
		authLine := ""
		if policy := r.Upstream.Auth; policy != "" && policy != model.AuthNone {
			authLine = fmt.Sprintf("        auth_request %s;\n", authURIFor(policy))
		}
		fmt.Fprintf(&b, "\n%s %s\nserver {\n    %s\n%s    server_name %s;\n    location / {\n%s        proxy_pass %s;\n    }\n}\n",
			managedMarker, r.Host, tls.listenLine(""), tls.tlsDirectives(), r.Host, authLine, withScheme(r.Upstream.Address))
	}
	// Structural default-deny: a default_server that closes the connection (444) for
	// any host not matched above, on the managed listen port. ALWAYS rendered.
	fmt.Fprintf(&b, "\n%s default-deny catch-all\nserver {\n    %s\n%s    server_name _;\n    return 444;\n}\n",
		denyMarker, tls.listenLine("default_server"), tls.tlsDirectives())
	return b.String()
}

// portsOf returns a server chunk's listen port(s). A server with no `listen`
// directive defaults to :80 in nginx's http context (the common case), so an
// absent listen is modeled as port 80 rather than dropped — otherwise its
// implicit-default-server role on :80 would be invisible to the deny model.
func portsOf(c chunk) []int {
	if len(c.ports) == 0 {
		return []int{80}
	}
	return c.ports
}

// withScheme renders a model upstream address (host:port) as an nginx proxy_pass
// target. If it already carries a scheme it is left as-is.
func withScheme(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "http://" + addr
}

// stripScheme reduces a proxy_pass target to the host:port form the model uses, so
// a read-back round-trips to the same Route.Address.
func stripScheme(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		return url[i+3:]
	}
	return url
}
