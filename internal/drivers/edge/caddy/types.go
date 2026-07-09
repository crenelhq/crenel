package caddy

// This file models the subset of Caddy's admin-API JSON config that Crenel
// needs to read and normalize. It is intentionally minimal — just enough to
// identify reverse-proxy routes and the catch-all default-deny.

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// authDetected is the marker for a recognized-but-unnamed brownfield auth policy.
const authDetected = model.AuthDetected

// Config is the top-level Caddy config returned by GET /config/.
type Config struct {
	Apps Apps `json:"apps"`
}

type Apps struct {
	HTTP HTTPApp `json:"http"`
	// Layer4 is Caddy's L4 app (github.com/mholt/caddy-l4) — present only on an
	// edge built with that plugin. Crenel uses it to render SNI passthrough
	// (ModeTCPPassthrough): match by tls.sni, proxy the raw TLS connection without
	// terminating it. omitempty keeps it absent for edges that don't use it.
	Layer4 *Layer4App `json:"layer4,omitempty"`
}

// Layer4App models the subset of the caddy-l4 config Crenel reads/writes: SNI-
// matched proxy routes. Crenel only ever touches routes tagged with its @id.
type Layer4App struct {
	Servers map[string]Layer4Server `json:"servers"`
}

type Layer4Server struct {
	Listen []string      `json:"listen,omitempty"`
	Routes []Layer4Route `json:"routes"`
}

type Layer4Route struct {
	ID     string          `json:"@id,omitempty"`
	Match  []Layer4Match   `json:"match,omitempty"`
	Handle []Layer4Handler `json:"handle"`
}

type Layer4Match struct {
	TLS *Layer4TLSMatch `json:"tls,omitempty"`
}

type Layer4TLSMatch struct {
	SNI []string `json:"sni,omitempty"`
}

type Layer4Handler struct {
	Handler   string           `json:"handler"`
	Upstreams []Layer4Upstream `json:"upstreams,omitempty"`
}

// Layer4Upstream's dial is a LIST of addresses (unlike http reverse_proxy's
// single dial string) — the caddy-l4 proxy handler shape.
type Layer4Upstream struct {
	Dial []string `json:"dial,omitempty"`
}

// firstSNIProxy returns the first SNI host + dial address of an l4 proxy route.
func (r Layer4Route) firstSNIProxy() (host, dial string, ok bool) {
	for _, m := range r.Match {
		if m.TLS != nil && len(m.TLS.SNI) > 0 {
			host = m.TLS.SNI[0]
		}
	}
	for _, h := range r.Handle {
		if h.Handler == handlerL4Proxy && len(h.Upstreams) > 0 && len(h.Upstreams[0].Dial) > 0 {
			dial = h.Upstreams[0].Dial[0]
		}
	}
	return host, dial, host != "" && dial != ""
}

type HTTPApp struct {
	Servers map[string]Server `json:"servers"`
}

type Server struct {
	Listen []string    `json:"listen,omitempty"`
	Routes []JSONRoute `json:"routes"`
}

type JSONRoute struct {
	// ID is Caddy's `@id` handle. Crenel tags every route it writes with
	// routeID(host) ("crenel-route-<host>"); an empty or non-crenel @id marks an
	// unmanaged (hand-written) route — the brownfield case adoption stamps.
	ID     string    `json:"@id,omitempty"`
	Match  []Match   `json:"match,omitempty"`
	Handle []Handler `json:"handle"`
}

// Match is one Caddy matcher set. crenel MODELS only the `host` matcher; every OTHER
// matcher key (path, path_regexp, method, header, query, remote_ip, expression, …)
// scopes the route BEYOND host granularity, which the host-granular model cannot
// represent. Rather than decode-and-drop those keys (which would silently read a
// `host + path` route as a plain host route — a MISREAD-↓), Extra CAPTURES them so
// the read model can DECLARE such a route `matcher_conditional` (detect-and-declare,
// register §4). The custom (un)marshalers keep Extra byte-faithful so an Unparsed
// entry's RawExcerpt shows the operator the real offending matcher.
type Match struct {
	Host  []string
	Extra map[string]json.RawMessage
}

// UnmarshalJSON splits a matcher set into the modeled `host` key and Extra (every other
// matcher key, kept raw). An absent `host` leaves Host nil (a host-less / path-only
// matcher); a matcher with extra keys populates Extra so the route is declared, not
// silently flattened to host granularity.
func (m *Match) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if h, ok := raw["host"]; ok {
		if err := json.Unmarshal(h, &m.Host); err != nil {
			return err
		}
		delete(raw, "host")
	}
	if len(raw) > 0 {
		m.Extra = raw
	}
	return nil
}

// MarshalJSON re-emits the matcher set (host + every Extra key) so excerpt() round-trips
// the real matcher faithfully — the operator inspecting a declared path-granular route
// sees its actual `path`/`method`/… constraint, not a stripped `{host}`.
func (m Match) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(m.Extra)+1)
	for k, v := range m.Extra {
		out[k] = v
	}
	if len(m.Host) > 0 {
		h, err := json.Marshal(m.Host)
		if err != nil {
			return nil, err
		}
		out["host"] = h
	}
	return json.Marshal(out)
}

type Handler struct {
	Handler string `json:"handler"`
	// reverse_proxy
	Upstreams []Upstream `json:"upstreams,omitempty"`
	// static_response (used for the catch-all deny: status_code >= 400)
	StatusCode int `json:"status_code,omitempty"`
	// Abort, on a static_response, closes the connection with no response — Caddy's
	// other way to spell a deny (`abort` in a Caddyfile). A real edge's per-zone
	// catch-all is often `{"handler":"static_response","abort":true}` with NO
	// status_code, so deny detection must honor it too (else the closing route reads
	// as an unmodeled handler → false UNKNOWN default-deny).
	Abort bool `json:"abort,omitempty"`
	// Routes are a subroute handler's NESTED routes (handler=="subroute"). Real
	// production edges route a wildcard host (*.homelab.example) into a subroute that
	// nests further — wildcard → subroute → per-host route → subroute → leaf
	// reverse_proxy — so normalize must RECURSE through these to enumerate the real
	// per-host services rather than stopping at the opaque wildcard. See docs/internal/DESIGN.md
	// "Caddy edge driver" and the trial that surfaced this.
	Routes []JSONRoute `json:"routes,omitempty"`
	// HandleResponse, present on a reverse_proxy handler, is the forward-auth
	// SUBREQUEST block: Caddy's `forward_auth` directive compiles to a reverse_proxy
	// (dialing the AUTHORIZER) with a handle_response that, on a 2xx, copies the auth
	// headers and continues to the backend — else returns the authorizer's challenge.
	// Its mere PRESENCE is what marks a reverse_proxy as an auth gate (isAuthGate), so
	// the read model skips it for leaf enumeration and claims it for auth detection. It
	// is read as opaque raw JSON (crenel never models the operator's verify URI /
	// copy-headers — that is the auth-by-reference boundary). See docs/internal/AUTH-DESIGN.md §2.
	HandleResponse json.RawMessage `json:"handle_response,omitempty"`
	// CrenelPolicy carries the forward-auth POLICY name on crenel's own auth marker
	// handler — a `vars` handler (handler=="vars") emitted ahead of the gate. crenel
	// uses a vars handler because real Caddy PRESERVES a vars handler's arbitrary keys
	// on read-back (unlike a reverse_proxy's unknown fields, which Caddy drops on
	// normalize), so the policy NAME round-trips off a real edge — not just the fake.
	// It is crenel's marker, not a stock-Caddy field: a documented fidelity boundary
	// (the granular JSON auth reference). See docs/internal/AUTH-DESIGN.md §2.
	CrenelPolicy string `json:"crenel_policy,omitempty"`
	// Transport, on a reverse_proxy, configures the UPSTREAM connection. A non-nil tls
	// block means the edge dials the downstream over HTTPS — the shape crenel renders on
	// a chain-forward to a `:443` downstream (TRIAL-FIX-4) and the edge's own working
	// forward routes carry. Read back so normalize can set Upstream.UpstreamTLS and
	// verify confirms the TLS hop survived. Absent on a plain reverse_proxy (no field).
	Transport *ReverseProxyTransport `json:"transport,omitempty"`
}

type Upstream struct {
	Dial string `json:"dial"`
}

// ReverseProxyTransport is the subset of a reverse_proxy's upstream transport crenel
// reads back: the protocol and (when the upstream is HTTPS) the tls block. Read-only —
// crenel renders the transport from a map literal (caddy.go insertRoute); this type
// exists to RECOGNIZE it on the way back so a chain-forward's TLS hop round-trips.
type ReverseProxyTransport struct {
	Protocol string                    `json:"protocol,omitempty"`
	TLS      *ReverseProxyTransportTLS `json:"tls,omitempty"`
}

// ReverseProxyTransportTLS is the upstream TLS settings crenel recognizes on read-back.
type ReverseProxyTransportTLS struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
}

const (
	handlerReverseProxy   = "reverse_proxy"
	handlerStaticResp     = "static_response"
	handlerSubroute       = "subroute"
	handlerVars           = "vars"           // crenel's auth-policy MARKER handler (round-trips the name)
	handlerHeaders        = "headers"        // forward-auth copy-headers expansion
	handlerL4Proxy        = "proxy"          // caddy-l4 raw-TCP proxy handler
	handlerForwardAuth    = "forward_auth"   // Caddyfile directive; recognized brownfield, NEVER emitted as a JSON handler
	handlerAuthentication = "authentication" // stock Caddy auth handler (recognized brownfield)
	denyStatusCode        = 403
	defaultManagedServer  = "srv0"
	defaultL4Server       = "crenel-l4" // managed layer4 server key
	defaultListen         = ":443"
	// requestHostPlaceholder is Caddy's runtime placeholder for the inbound request
	// host. crenel renders it as the upstream SNI (transport.tls.server_name) and the
	// preserved request Host on a chain-forward to an HTTPS downstream, mirroring the
	// edge's own working forward routes — so one rendering serves every host the
	// wildcard forwards. See caddy.go insertRoute (TRIAL-FIX-4).
	requestHostPlaceholder = "{http.request.host}"
)

// l4RouteID is the deterministic @id Crenel tags a managed layer4 (passthrough)
// route with — distinct from the http routeID so a host can never collide across
// the two trees.
func l4RouteID(host string) string { return "crenel-l4-" + strings.ToLower(host) }

// isDeny reports whether a handler denies — a static_response that either returns
// a >= 400 status or aborts the connection (`abort: true`). Both are connection-
// closing terminals that expose nothing; recognizing abort (which carries no
// status_code) keeps a real edge's per-zone catch-all from reading as an unmodeled
// handler.
func (h Handler) isDeny() bool {
	return h.Handler == handlerStaticResp && (h.StatusCode >= 400 || h.Abort)
}

// isAuthGate reports whether this handler is a forward-auth GATE: a reverse_proxy
// carrying a handle_response subrequest — the shape Caddy's `forward_auth` directive
// compiles to, and the shape crenel renders for an attached policy. Such a
// reverse_proxy dials the AUTHORIZER, not the service backend, so leaf enumeration
// must SKIP it (firstReverseProxyDial) and auth detection must CLAIM it (detectAuth).
func (h Handler) isAuthGate() bool {
	return h.Handler == handlerReverseProxy && len(h.HandleResponse) > 0
}

// firstReverseProxyDial returns the first upstream dial address of a reverse_proxy
// handler in this route, SKIPPING any forward-auth gate (a reverse_proxy with a
// handle_response, which dials the authorizer). On a route gated by forward-auth the
// gate's reverse_proxy precedes the backend's, so without this skip the leaf would
// read the AUTHORIZER as the service backend — the misread the live trial exposed on
// the home edge's real Authelia routes.
func (r JSONRoute) firstReverseProxyDial() (string, bool) {
	for _, h := range r.Handle {
		if h.Handler == handlerReverseProxy && !h.isAuthGate() && len(h.Upstreams) > 0 {
			return h.Upstreams[0].Dial, true
		}
	}
	return "", false
}

// firstReverseProxyUpstreamTLS reports whether the BACKEND reverse_proxy (the same
// non-auth-gate handler firstReverseProxyDial selects) dials its upstream over HTTPS —
// a transport with a non-nil tls block. It is how a chain-forward to an HTTPS downstream
// reads back as Upstream.UpstreamTLS so verify confirms the front-leg TLS hop landed
// (TRIAL-FIX-4). The auth gate's reverse_proxy is skipped for the same reason the dial
// scan skips it (it dials the authorizer, not the backend).
func (r JSONRoute) firstReverseProxyUpstreamTLS() bool {
	for _, h := range r.Handle {
		if h.Handler == handlerReverseProxy && !h.isAuthGate() && len(h.Upstreams) > 0 {
			return h.Transport != nil && h.Transport.TLS != nil
		}
	}
	return false
}

// detectAuth recognizes a forward-auth reference on the route. crenel's own MARKER (a
// vars handler carrying CrenelPolicy) round-trips the exact policy NAME — even off a
// real edge. A hand-built / canonical auth gate with no crenel marker (a reverse_proxy
// +handle_response, a stock authentication handler, or a literal forward_auth artifact)
// is recognized as "(detected)" — read-only recognition, never rewritten. Returns ""
// when no auth is present.
func (r JSONRoute) detectAuth() string {
	detected := ""
	for _, h := range r.Handle {
		if h.CrenelPolicy != "" { // crenel's marker — the policy name round-trips
			return h.CrenelPolicy
		}
		if h.isAuthGate() || h.Handler == handlerAuthentication || h.Handler == handlerForwardAuth {
			detected = authDetected
		}
	}
	return detected
}

// hostMatch returns the first host in the route's matchers, if any.
func (r JSONRoute) hostMatch() (string, bool) {
	for _, m := range r.Match {
		if len(m.Host) > 0 {
			return m.Host[0], true
		}
	}
	return "", false
}

// hostMatches returns EVERY host this route matches, across all matcher sets,
// deduped and order-preserving. A single Caddy route routinely lists many hosts in
// one matcher (`host: [a, b, c]`) — a real edge groups dozens of vhosts that share
// one backend into one route — and each host is independently reachable to the
// route's handler. Enumerating only the first (hostMatch) would silently drop the
// rest: a MISREAD-↓ by omission that under-reports what is exposed. Returns
// (nil, false) for a host-less / catch-all route.
func (r JSONRoute) hostMatches() ([]string, bool) {
	var hosts []string
	seen := make(map[string]bool)
	for _, m := range r.Match {
		for _, h := range m.Host {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return hosts, len(hosts) > 0
}

// extraMatcherKeys returns the sorted, deduped union of NON-host matcher keys across
// every matcher set on this route — `path`, `path_regexp`, `method`, `header`, `query`,
// `remote_ip`, `expression`, etc. A non-empty result means the route's reachability is
// conditioned on more than the host, so the host-granular model cannot faithfully
// represent it and the read model must DECLARE it (matcher_conditional) rather than
// enumerate it as a plain host route. Empty => a pure host (or host-less) matcher crenel
// fully understands.
func (r JSONRoute) extraMatcherKeys() []string {
	seen := make(map[string]bool)
	for _, m := range r.Match {
		for k := range m.Extra {
			seen[k] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hasDenyHandler reports whether this route carries a denying static_response
// (status >= 400) — a per-host or catch-all deny, which crenel understands (it
// closes a host rather than exposing one).
func (r JSONRoute) hasDenyHandler() bool {
	for _, h := range r.Handle {
		if h.isDeny() {
			return true
		}
	}
	return false
}

// handlerNames returns the comma-joined handler types on this route, for an
// Unparsed entry's human reason (e.g. "file_server, encode").
func (r JSONRoute) handlerNames() string {
	names := make([]string, 0, len(r.Handle))
	for _, h := range r.Handle {
		if h.Handler != "" {
			names = append(names, h.Handler)
		}
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// excerpt returns a bounded JSON snippet of the route for an Unparsed entry's
// RawExcerpt, so the operator can inspect what crenel could not model. Bounded so a
// huge nested block never floods status output.
func (r JSONRoute) excerpt() string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	const max = 240
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// isCatchAllDeny reports whether this route is a host-less denying route.
func (r JSONRoute) isCatchAllDeny() bool {
	if _, hasHost := r.hostMatch(); hasHost {
		return false
	}
	for _, h := range r.Handle {
		if h.isDeny() {
			return true
		}
	}
	return false
}

// hasSubroute reports whether any handler is a subroute (nested per-host
// routing). Real production edges route wildcard hosts (e.g. *.homelab.example)
// into subroutes rather than flat reverse_proxy handlers.
func (r JSONRoute) hasSubroute() bool {
	_, ok := r.subroutes()
	return ok
}

// subroutes returns the NESTED routes of the first subroute handler on this
// route, if any. It is the recursion step normalize/Adopt use to descend a
// wildcard → subroute → per-host chain down to the leaf reverse_proxy. A
// subroute with no nested routes still reports ok=true (an empty subroute is a
// subroute), so callers can distinguish "has a subroute" from "forwards directly".
func (r JSONRoute) subroutes() ([]JSONRoute, bool) {
	for _, h := range r.Handle {
		if h.Handler == handlerSubroute {
			return h.Routes, true
		}
	}
	return nil, false
}

// subrouteHandlerIndex returns the index within Handle of the first subroute
// handler, if any — the WRITE-side counterpart to subroutes(). The granular insert
// uses it to address the nested routes array
// (…/routes/<w>/handle/<subrouteHandlerIndex>/routes/0) so a new per-host route lands
// INSIDE the wildcard subroute, mirroring where collectLeaves enumerates per-host
// routes on read.
func (r JSONRoute) subrouteHandlerIndex() (int, bool) {
	for i, h := range r.Handle {
		if h.Handler == handlerSubroute {
			return i, true
		}
	}
	return 0, false
}

// isWildcardHost reports whether a host matcher is a single-label zone wildcard
// (*.zone) — the shape a real edge uses to route an entire zone into a subroute.
func isWildcardHost(h string) bool { return strings.HasPrefix(h, "*.") && len(h) > len("*.") }

// zoneOf returns host's parent domain (everything after the first label):
// vault.homelab.example -> homelab.example. "" for a single-label / dotless name.
// Case-folded so zone comparison never turns on casing.
func zoneOf(host string) string {
	if i := strings.Index(host, "."); i >= 0 {
		return strings.ToLower(host[i+1:])
	}
	return ""
}

// sameZone reports whether two hosts share a parent zone (vault.homelab.example and
// git.homelab.example do). Used to recognize that a host's zone is represented FLAT on
// an edge (a flat top-level sibling exists in the same zone), so a new host joins its
// flat siblings rather than being refused on an otherwise subroute-structured edge.
func sameZone(a, b string) bool {
	za := zoneOf(a)
	return za != "" && za == zoneOf(b)
}

// wildcardCovers reports whether the zone wildcard matcher (*.zone) covers host under
// Caddy's ONE-LABEL wildcard semantics: host must be exactly one additional label
// under zone (a.zone matches *.zone; a.b.zone and zone itself do not). Case-folded so
// matcher/host casing never changes the routing decision.
func wildcardCovers(matcher, host string) bool {
	if !isWildcardHost(matcher) {
		return false
	}
	suffix := strings.ToLower(matcher[1:]) // ".zone" (keep the leading dot)
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}
