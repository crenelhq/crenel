// Package model holds the pure domain types for Crenel.
//
// These types are deliberately free of any I/O, driver, or transport concern.
// model is imported by core, ports, and every driver; it imports nothing of
// ours in return. Keeping it pure is what lets the dependency rule hold.
package model

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Verb is the imperative kind of an Op.
type Verb string

const (
	Expose   Verb = "expose"
	Unexpose Verb = "unexpose"
	// Rename moves a service from one hostname to another as ONE atomic transaction:
	// add the new host (copying the source route's exact backend/auth/mode) + remove the
	// old, read-back-verified together, rolled back as a unit. The new host is brought up
	// BEFORE the old is torn down (make-before-break) for a zero-downtime move. See
	// core.Rename.
	Rename Verb = "rename"
)

// RouteMode is the TRANSPORT/exposure semantics an exposed route requests. It is
// the typed intent that lets a driver express what it can and ERROR LOUDLY on what
// it can't (instead of silently approximating). See docs/internal/STRAIN.md §2.
type RouteMode string

const (
	// ModeHTTPProxy (the zero value / default): the edge terminates TLS and
	// reverse-proxies host → backend. Caddy and Traefik express this.
	ModeHTTPProxy RouteMode = ""
	// ModeTCPPassthrough: the edge routes by SNI WITHOUT terminating TLS (an L4
	// passthrough). Expressible as intent; no driver renders it yet, so every
	// driver currently errors on it — the latent gap surfaced in docs/internal/STRAIN.md §2, now
	// representable.
	ModeTCPPassthrough RouteMode = "tcp_passthrough"
	// ModeMeshGrant: exposure is an identity-mesh ACL grant (a WireGuard grant to a
	// peer/group), not host→backend HTTP routing. The NetBird driver expresses
	// this NATIVELY; Caddy/Traefik error on it.
	ModeMeshGrant RouteMode = "mesh_grant"
)

// Canonical returns the mode with the empty default normalised to ModeHTTPProxy's
// display form for messages.
func (m RouteMode) Canonical() RouteMode {
	if m == ModeHTTPProxy {
		return ModeHTTPProxy
	}
	return m
}

// String renders a mode for humans (the default has a name, not "").
func (m RouteMode) String() string {
	if m == ModeHTTPProxy {
		return "http_proxy"
	}
	return string(m)
}

// ErrModeUnsupported classifies a driver's refusal to express a requested
// RouteMode. Drivers wrap it; core/CLI surface it; tests assert on it with
// errors.Is. Refusing loudly beats a leaky approximation.
var ErrModeUnsupported = errors.New("edge cannot express the requested route mode")

// AuthNone is the EXPLICIT "no auth policy" value. It is distinct from the empty
// string: "" means unspecified (silently no auth — flagged when a host is public),
// while AuthNone is a deliberate, acknowledged choice to expose without auth (the
// loud opt-out the public-without-auth guardrail requires). See docs/internal/AUTH-DESIGN.md §1.
const AuthNone = "none"

// AuthDetected is the read-back marker a driver's normalize sets on Upstream.Auth
// when it RECOGNIZES a hand-built forward-auth directive whose policy name it
// cannot recover (a brownfield route's auth). It signals "auth is present" to
// status/audit without claiming a specific policy. crenel's OWN auth reference
// round-trips the real policy name instead. See docs/internal/AUTH-DESIGN.md §5.
const AuthDetected = "(detected)"

// AuthDownstream is the display marker for a host whose auth is enforced ONE HOP
// DOWNSTREAM in an edge CHAIN, not at this (front) edge. It is NOT a per-route
// config value a driver reads from live (the front edge genuinely carries no auth
// handler) — core OVERLAYS it on a route's Upstream.Auth for status display when
// the route's edge is marked auth-downstream, and audit uses the same assertion to
// suppress the (then-spurious) public_without_auth warning. See docs/internal/DESIGN.md
// "Chain topology — front edge → downstream edge".
const AuthDownstream = "downstream"

// ErrAuthUnsupportedForMode classifies a refusal to attach a forward-auth POLICY
// to an exposure whose mode has no HTTP layer to enforce it at (SNI passthrough)
// or that enforces identity itself (an identity-mesh grant). Refused loudly rather
// than silently dropped. Wrapped by ValidateAuth; classifiable with errors.Is.
var ErrAuthUnsupportedForMode = errors.New("forward-auth policy cannot be attached to this route mode")

// ValidateAuth reports whether attaching auth policy `auth` to a route of `mode`
// is coherent. Forward-auth needs an HTTP layer, so a REAL policy (anything other
// than "" or AuthNone) is allowed only on ModeHTTPProxy: passthrough has no HTTP
// layer to inject auth at, and a mesh grant enforces identity itself. "" and
// AuthNone attach nothing and are valid on every mode. Centralized here so every
// path (preview/expose/apply/reconcile/declarative) refuses identically.
func ValidateAuth(mode RouteMode, auth string) error {
	if auth == "" || auth == AuthNone {
		return nil
	}
	switch mode {
	case ModeHTTPProxy:
		return nil
	case ModeTCPPassthrough:
		return fmt.Errorf("%w: auth=%q on a tcp_passthrough exposure — SNI/L4 passthrough has no HTTP layer to forward-auth at; "+
			"terminate TLS (http_proxy) to attach auth, or drop the policy", ErrAuthUnsupportedForMode, auth)
	case ModeMeshGrant:
		return fmt.Errorf("%w: auth=%q on a mesh_grant exposure — an identity mesh enforces identity itself; "+
			"the grant IS the authn/authz, so a forward-auth policy is not applicable", ErrAuthUnsupportedForMode, auth)
	default:
		return fmt.Errorf("%w: auth=%q on mode %s", ErrAuthUnsupportedForMode, auth, mode)
	}
}

// Op is the transient imperative intent of a single CLI invocation.
//
// It is the ONLY notion of "desired state" in Crenel, and it is NEVER persisted.
// An Op exists for the duration of one command and is then discarded. There is
// no config file that is "the truth"; the truth is always live state.
type Op struct {
	Verb    Verb
	Service string // logical service name, e.g. "grafana"
	// Host is the public-facing hostname the service is exposed at.
	// For M0 we derive it as "<service>.<zone>" if not given explicitly.
	Host string
	// Mode is the requested transport/exposure mode (default ModeHTTPProxy). A
	// driver that cannot express it must error (model.ErrModeUnsupported).
	Mode RouteMode
	// Params carries mode-specific intent that the core Op shape does not model —
	// e.g. mesh_grant needs Params["group"] (the identity/group to grant). Empty
	// for the common HTTP-proxy case.
	Params map[string]string
	// Auth names a forward-auth POLICY to attach to the exposure (e.g. "authelia",
	// "authentik"), provider-agnostic. "" = unspecified (no auth; flagged when the
	// host is public), AuthNone = explicit opt-out, anything else = a named policy
	// crenel renders a per-driver REFERENCE to. See docs/internal/AUTH-DESIGN.md.
	Auth string
	// To is an explicit backend override for THIS op (host:port). When set, drivers
	// use it as the upstream address for Plan instead of asking the per-edge
	// OriginResolver — the `crenel expose <svc> --to <host:port>` shape so the
	// hero command works without a pre-edited origins map. Persistence is done at
	// the CLI layer (writes the entry into the config's origins map on a verified
	// apply), so `status`/`audit`/`drift`/`reconcile` stay coherent on later runs.
	// Empty = resolver path (the pre-declared-origins default).
	To string
}

// HasAuthPolicy reports whether the op attaches a REAL forward-auth policy (not
// unspecified, not the explicit "none" opt-out).
func (o Op) HasAuthPolicy() bool { return o.Auth != "" && o.Auth != AuthNone }

func (o Op) String() string {
	switch {
	case o.Mode != ModeHTTPProxy && o.HasAuthPolicy():
		return fmt.Sprintf("%s %s (host=%s, mode=%s, auth=%s)", o.Verb, o.Service, o.Host, o.Mode, o.Auth)
	case o.Mode != ModeHTTPProxy:
		return fmt.Sprintf("%s %s (host=%s, mode=%s)", o.Verb, o.Service, o.Host, o.Mode)
	case o.HasAuthPolicy():
		return fmt.Sprintf("%s %s (host=%s, auth=%s)", o.Verb, o.Service, o.Host, o.Auth)
	}
	return fmt.Sprintf("%s %s (host=%s)", o.Verb, o.Service, o.Host)
}

// UpstreamKind distinguishes how a route reaches its backend.
type UpstreamKind string

const (
	// ForwardToOrigin proxies (reverse-proxy) to a backend resolved from the
	// service name via an OriginResolver. This is the common case.
	ForwardToOrigin UpstreamKind = "forward_to_origin"
	// DirectBackend points at an explicit address with no origin resolution.
	DirectBackend UpstreamKind = "direct_backend"
)

// Upstream describes where an exposed route sends traffic.
type Upstream struct {
	Kind UpstreamKind
	// Mode is the realized transport/exposure mode of this route (default
	// ModeHTTPProxy). It is set by the driver's Plan from the Op's requested Mode.
	Mode RouteMode
	// Address is the resolved/explicit backend, e.g. "10.0.0.5:3000".
	Address string
	// SNI handling. If TLSPassthrough is true the edge does not terminate TLS
	// and instead routes by SNI to the backend. Otherwise the edge terminates
	// TLS for ServerName. (For ModeTCPPassthrough this is implied true.)
	TLSPassthrough bool
	ServerName     string // SNI / cert host the edge serves
	// UpstreamTLS marks that the edge dials this UPSTREAM over HTTPS — distinct from
	// TLSPassthrough (which is about NOT terminating client TLS) and from ServerName
	// (the cert host the edge SERVES). It is the load-bearing flag for a chain-FORWARD
	// route whose downstream edge listens on TLS (`:443`): the front terminates the
	// client's TLS, then must re-originate TLS to the downstream and preserve the Host
	// so the downstream's host matcher routes it. A driver renders the upstream TLS
	// transport (+ Host preservation) when this is set; a plain-HTTP downstream leaves
	// it false. Set by chain_write's forwardRoute (from the downstream scheme) and by a
	// driver's normalize on read-back (so verify confirms the TLS hop survived). The
	// front-leg HTTPS gap the cross-chain live trial caught (TRIAL-FIX-4): a forward
	// rendered as bare HTTP to a `:443` downstream gets "Client sent an HTTP request to
	// an HTTPS server" (400). See docs/internal/DESIGN.md "Transport / Connection" and chain_write.go.
	UpstreamTLS bool
	// Auth is the realized forward-auth POLICY attached to this route ("" = none).
	// Set by a driver's Plan (from the Op) and by normalize on read-back: crenel's
	// own auth reference round-trips the policy name; a recognized hand-built auth
	// directive surfaces as "(detected)". Read by status/audit/verify. See
	// docs/internal/AUTH-DESIGN.md §2.
	Auth string
}

// Ownership is the TERNARY+ classification of who controls a route's config — the
// load-bearing input to the refuse-to-manage gate (TOPOLOGY-RISK-REGISTER §4.5).
// Binary "managed/unmanaged" hid the dangerous middle: a route a config GENERATOR
// owns reads back fine but a crenel edit would be silently reverted (MISMANAGE), and
// a route whose owner crenel cannot determine must not be touched blind. Each
// driver's normalize sets it from what it can detect; when unsure it must be
// OwnUnknown (the safe default — the gate refuses), never an optimistic guess.
type Ownership string

const (
	// OwnCrenel: the route carries crenel's marker (Caddy @id, Traefik crenel-* key,
	// nginx comment) — crenel physically wrote it and may mutate it.
	OwnCrenel Ownership = "crenel"
	// OwnUnmanaged: clearly hand-written, no marker, fully understood — adoptable
	// (`crenel import` stamps a marker in-place without changing behavior).
	OwnUnmanaged Ownership = "unmanaged"
	// OwnForeign: generated/owned by another tool (caddy-docker-proxy, NPM,
	// Traefik Docker labels, Pangolin, …). A crenel edit would be reverted on the
	// generator's next regeneration — DO NOT mutate; manage at the source.
	OwnForeign Ownership = "foreign"
	// OwnUnknown: crenel cannot determine ownership — DO NOT mutate (the gate refuses;
	// a documented --force escape exists for an operator who verified it out-of-band).
	OwnUnknown Ownership = "unknown"
)

// OwnershipFromMarker maps the legacy "carries crenel's marker" boolean to the
// ternary: a marked route is OwnCrenel, an unmarked one is OwnUnmanaged. Generator
// detection (OwnForeign) and genuine ambiguity (OwnUnknown) are layered on top of
// this by a driver that can detect them; until then unmarked == unmanaged, which
// preserves the pre-ownership behavior exactly.
func OwnershipFromMarker(hasMarker bool) Ownership {
	if hasMarker {
		return OwnCrenel
	}
	return OwnUnmanaged
}

// Mutable reports whether crenel may safely mutate a route with this ownership:
// only OwnCrenel and OwnUnmanaged. OwnForeign would be reverted; OwnUnknown is
// unsafe to touch blind. The empty value (a synthetic/planned route that never came
// from live) is treated as mutable — the gate only ever consults LIVE ownership.
func (o Ownership) Mutable() bool {
	return o == OwnCrenel || o == OwnUnmanaged || o == ""
}

// Route is one normalized exposed route on the edge.
type Route struct {
	Host     string
	Upstream Upstream
	// Managed reports whether THIS block carries Crenel's ownership marker (Caddy
	// @id, Traefik crenel-* key, nginx comment marker) — i.e. Crenel physically
	// wrote it. It is distinct from "in the managed domain" (whether the host's
	// service is in an edge's origins): a brownfield route can be in the managed
	// domain yet unmanaged (hand-written). Adoption (`crenel import`) flips an
	// unmanaged route to managed in-place without changing behavior. Read-only
	// metadata set by each driver's normalize; the default false means "unmanaged".
	//
	// Managed is kept as the compat shorthand for Ownership==OwnCrenel; the richer
	// Ownership classification (which adds foreign/unknown) is what the refuse-to-
	// manage gate reads. A driver's normalize MUST keep them consistent.
	Managed bool
	// Ownership is the ternary+ classification of who controls this route's config
	// (see Ownership). It augments Managed: Managed==(Ownership==OwnCrenel). The
	// mutation gate consults Ownership so it can refuse foreign/unknown routes that
	// the old binary view would have treated as plainly "unmanaged". Read-only
	// metadata set by each driver's normalize.
	Ownership Ownership `json:"ownership,omitempty"`
	// Chain, when non-nil, records that this route FORWARDS into a downstream edge in
	// an edge CHAIN rather than to a terminal origin (P4). It is NOT set by a driver
	// (a driver only sees its own leaf dial); core OVERLAYS it during a chain-aware
	// read when this edge is the front of a chain (EdgeBinding.DownstreamEdge) and the
	// route's backend dials the downstream edge. It carries the host's REAL backend +
	// the auth OBSERVED at the downstream edge (when readable), or declares the
	// destination "downstream, not observed" when it is not. See ChainLink and
	// docs/internal/DESIGN.md "Chain-aware model (P4)".
	Chain *ChainLink `json:"chain,omitempty"`
}

// ChainLink describes a route that FORWARDS into a DOWNSTREAM edge (an edge CHAIN:
// front → downstream → origin) rather than to a terminal origin. It is core-overlaid
// metadata (drivers never set it): a front edge's leaf honestly dials the downstream
// edge's address, and core recognizes that and FOLLOWS THROUGH to resolve the host's
// true backend + the auth actually enforced one hop down. The whole point of P4 is
// that a forwarded host's real destination + protection are OBSERVED (when the
// downstream is readable) rather than guessed — and DECLARED unresolved, never
// assumed safe, when they cannot be. See docs/internal/DESIGN.md "Chain-aware model (P4)".
type ChainLink struct {
	// DownstreamEdge is the topology name of the edge this route forwards to.
	DownstreamEdge string `json:"downstream_edge"`
	// Resolved is true when crenel READ the downstream edge AND found this host there
	// — so DownstreamAddress/DownstreamAuth are observed truth. When false the chain
	// destination is "downstream, not observed" (see Reason); crenel falls back to the
	// auth_downstream assertion for the auth posture and NEVER assumes the host safe.
	Resolved bool `json:"resolved"`
	// DownstreamAddress is the host's REAL backend at the downstream edge (set only
	// when Resolved) — the true destination the front merely relays toward.
	DownstreamAddress string `json:"downstream_address,omitempty"`
	// DownstreamAuth is the auth OBSERVED at the downstream edge for this host (set
	// only when Resolved): a real policy name, AuthDetected, or "" (none enforced
	// downstream — which makes the host genuinely public_without_auth despite the
	// chain). This is the field that lets audit resolve protection by observation.
	DownstreamAuth string `json:"downstream_auth,omitempty"`
	// Reason explains an UNRESOLVED link (Resolved==false): the downstream edge was
	// unreadable, not configured in the topology, or readable but does not route this
	// host (a dangling forward). Surfaced honestly, never swallowed.
	Reason string `json:"reason,omitempty"`
}

// UnknownKind classifies WHY crenel could not fully understand something it saw in
// an edge's live config. It is the vocabulary of the detect-and-declare-unknown net
// (TOPOLOGY-RISK-REGISTER §4): every entry is a place crenel STOPPED understanding,
// surfaced rather than swallowed.
type UnknownKind string

const (
	// UnknownHandler: a handler/terminal crenel does not model (not reverse_proxy /
	// subroute / deny / a recognized auth handler) — e.g. file_server, php_fastcgi.
	UnknownHandler UnknownKind = "handler_unrecognized"
	// UnknownNestedRoute: routing exists below where crenel stopped — an undescended
	// or empty subroute whose per-host leaves could not be enumerated.
	UnknownNestedRoute UnknownKind = "subroute_not_descended"
	// UnknownMatcher: a route gated by a matcher crenel did not evaluate (CIDR,
	// header, method) so its true reachability is uncertain.
	UnknownMatcher UnknownKind = "matcher_conditional"
	// UnknownBackend: the effective backend is indirect (map/vars/rewrite, or a
	// router/service crenel cannot resolve to a dial) — the target is unknown.
	UnknownBackend UnknownKind = "backend_indirect"
	// UnknownServerBlock: an http.server (or sibling block) crenel did not enumerate.
	UnknownServerBlock UnknownKind = "server_not_read"
	// UnknownGenerator: the config is owned by a generator (cdp/NPM/labels/Pangolin).
	UnknownGenerator UnknownKind = "foreign_managed"
	// UnknownIngress: reachability is determined off-edge (tunnel/overlay/CDN).
	UnknownIngress UnknownKind = "ingress_external"
	// UnknownAcknowledged: a route crenel could not fully understand, but which
	// the OPERATOR has explicitly acknowledged in the live config itself (a
	// `crenel-ack:<slug>` marker — see docs/design/ack-marker.md). Unlike every
	// other UnknownKind, this one does NOT block default-deny certification
	// (see LiveEdgeState.FullyParsed) — but it is never hidden: status/audit
	// still list it as its own "ACK" state, distinct from both a verified-green
	// route and an unaddressed unknown.
	UnknownAcknowledged UnknownKind = "acknowledged_unknown"
)

// AckMarkerPrefix is the literal prefix of a crenel-ack marker (see
// docs/design/ack-marker.md), for callers that need to recognize the prefix
// itself rather than extract the reason slug (e.g. distinguishing "ack'd with
// a different reason" from "not ack'd at all").
const AckMarkerPrefix = "crenel-ack:"

// ackMarkerRE extracts the reason slug from a crenel-ack:<slug> marker wherever
// it appears — a Caddy @id (exact match), a driver-specific field, or a
// substring inside a raw comment/config blob (nginx). [a-z0-9-]+ mirrors the
// slug shape docs/design/ack-marker.md specifies.
var ackMarkerRE = regexp.MustCompile(AckMarkerPrefix + `([a-z0-9-]+)`)

// ParseAckMarker scans s (an @id, a driver-specific marker field, or a raw
// comment/config excerpt) for the crenel-ack:<slug> marker an operator writes
// to acknowledge an intentionally-unmodeled route, and returns the reason slug.
// See docs/design/ack-marker.md.
func ParseAckMarker(s string) (reason string, ok bool) {
	m := ackMarkerRE.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// AckMarker formats the crenel-ack marker for a given reason slug — the
// inverse of ParseAckMarker, used when stamping the marker on write.
func AckMarker(reason string) string { return AckMarkerPrefix + reason }

// Unparsed is one thing crenel SAW in the live config but did not fully understand.
// It is first-class output: counted into Coverage, listed by status, surfaced by
// audit, and (for ownership/ingress kinds) mutation-blocking. The whole point of
// the register's safety net is that an Unparsed entry is NEVER a silent drop.
type Unparsed struct {
	// Locator is where it lives, e.g. "apps.http.servers.srv0.routes[1]" or
	// "cloudflared:ingress" or "edge".
	Locator string      `json:"locator"`
	Kind    UnknownKind `json:"kind"`
	// Reason is the human explanation, e.g. "subroute with nested routes not descended".
	Reason string `json:"reason"`
	// RawExcerpt is a bounded snippet for the operator to inspect (may be empty).
	RawExcerpt string `json:"raw_excerpt,omitempty"`
}

// IngressKind classifies HOW an edge's hosts are reached from outside — the axis-4
// "exposed isn't a public port" gap (TOPOLOGY-RISK-REGISTER §4.3). The local proxy's
// listener bind does NOT decide public/private when a tunnel or overlay fronts it: a
// service behind cloudflared or a Tailscale funnel/serve is reachable off-box even if
// the proxy binds 127.0.0.1. Reading only the local listener and calling such a host
// "internal" is a MISREAD-↓. So ingress is a first-class, DECLARED posture: when the
// mechanism can't be determined for an externally-fronted edge, crenel declares it
// UNKNOWN rather than assume internal.
type IngressKind string

const (
	// IngressPublicListener: hosts are reached via a public listener PORT on this edge
	// (the ordinary case). "" (unset) is treated identically — no off-edge mechanism.
	IngressPublicListener IngressKind = "public-listener"
	// IngressTunnel: an outbound tunnel fronts the edge (cloudflared / a named tunnel).
	// Reachability is PUBLIC regardless of the local proxy's bind address.
	IngressTunnel IngressKind = "tunnel"
	// IngressOverlay: an overlay/mesh fronts the edge (Tailscale serve/funnel,
	// WireGuard). Reachability is decided on the overlay, not the local listener.
	IngressOverlay IngressKind = "overlay"
	// IngressUnknown: the edge is externally fronted but crenel could not determine the
	// mechanism — DECLARED unknown (counted, surfaced), never assumed internal.
	IngressUnknown IngressKind = "unknown"
)

// External reports whether reachability is decided OFF this edge — a tunnel, an
// overlay, or an undetermined-but-external front. In those cases reading the local
// listener bind would MISREAD public/private, so status/audit must surface it. A
// public listener (or unset) is not external in this sense.
func (k IngressKind) External() bool {
	switch k {
	case IngressTunnel, IngressOverlay, IngressUnknown:
		return true
	}
	return false
}

// PersistenceModel classifies HOW an edge's running config is made DURABLE across a
// control-plane restart — the "will this write survive a restart?" axis the durable-
// persist work makes first-class. Like IngressKind it is a detect-and-declare posture:
// the admin API carries NO marker for the boot source (a Caddy `GET /config/` cannot
// tell you whether the process booted from a Caddyfile, a JSON file, or `--resume`), so
// the model is DECLARED from config, never inferred — and an edge whose model crenel
// cannot determine is PersistUnknown, never assumed durable.
//
// The motivating fact: an admin-API edge (Caddy) mutates its IN-MEMORY config; unless
// that config ALSO lands in whatever the control plane BOOTS from, a restart drops the
// change. Trusting "the admin API answered 200" and calling the write done is a
// DURABILITY MISREAD — the change is live but EPHEMERAL. So crenel surfaces the model
// (status/audit) and WARNS on a write to an edge whose writes do not persist. See
// docs/internal/DESIGN.md "Durability — the persistence model".
type PersistenceModel string

const (
	// PersistDurableConfig: the driver WRITES the same file the control plane boots
	// from (a Traefik/nginx file provider). A mutation is already durable with no extra
	// step — the file IS the source. The common case for file-based drivers.
	PersistDurableConfig PersistenceModel = "durable-config"
	// PersistDurableFile: an admin-API edge whose in-memory writes crenel ALSO
	// reconciles into the on-disk config the control plane boots from (a mounted
	// Caddyfile / JSON), so a restart reproduces them. This is the durable-persist path
	// the home edge needs: live admin write (immediate) + on-disk reconcile (durable),
	// read-back-verified consistent. See caddy/persist_caddyfile.go.
	PersistDurableFile PersistenceModel = "durable-file"
	// PersistResume: the control plane boots with Caddy's `--resume`, so an admin-API
	// write is autosaved and reloaded on restart by the control plane ITSELF — durable
	// with no crenel action. DECLARED by the operator (no boot-flag marker on the wire).
	PersistResume PersistenceModel = "resume"
	// PersistEphemeralAdmin: an admin-API edge with NO durable path — in-memory writes
	// are LOST on a control-plane restart. The SAFE DEFAULT for a bare Caddy admin edge:
	// admin writes ARE ephemeral unless persisted, and crenel must never assume durable.
	// A write is still applied + verified LIVE; only its durability is declared absent,
	// so the operator is warned and can configure a durable path.
	PersistEphemeralAdmin PersistenceModel = "ephemeral-admin"
	// PersistUnknown: crenel cannot determine the model — DECLARED, never assumed
	// durable. Treated as ephemeral-for-warning (the conservative side).
	PersistUnknown PersistenceModel = "unknown"
)

// Durable reports whether a write to an edge with this model SURVIVES a control-plane
// restart. Ephemeral-admin and unknown do not; everything else does. The empty value
// ("" — a driver/edge that does not classify itself, e.g. a mesh edge that refuses
// mutation) is NOT durable and NOT ephemeral-warning either (see EphemeralWrites): it
// is simply not applicable, surfaced as nothing.
func (m PersistenceModel) Durable() bool {
	switch m {
	case PersistDurableConfig, PersistDurableFile, PersistResume:
		return true
	}
	return false
}

// EphemeralWrites reports whether a write to this edge is applied LIVE but does NOT
// persist across a restart — the condition status/audit warn on and the write path
// declares. PersistUnknown counts (never assume durable); the empty value does NOT (an
// edge that does not take writes / does not classify itself must not cry wolf).
func (m PersistenceModel) EphemeralWrites() bool {
	return m == PersistEphemeralAdmin || m == PersistUnknown
}

// Classified reports whether this edge declared a persistence model at all (non-empty).
// status/audit only surface durability for a classified edge — an unclassified one
// (e.g. NetBird, which refuses mutation) is silent.
func (m PersistenceModel) Classified() bool { return m != "" }

// String renders the model for humans; the empty value reads as "n/a".
func (m PersistenceModel) String() string {
	if m == "" {
		return "n/a"
	}
	return string(m)
}

// DenyState is the TERNARY default-deny verdict (TOPOLOGY-RISK-REGISTER §4.4 — the
// single most important rule in the register). A structural default-deny "ENFORCED"
// claim is a statement about the ENTIRE config ("nothing not-listed is reachable");
// it is only sound if the entire config was parsed. So:
//
//	!DenyCatchAllPresent                 -> DenyMissing  (critical — fail-open)
//	DenyCatchAllPresent && FullyParsed   -> DenyEnforced (green)
//	DenyCatchAllPresent && unparsed > 0  -> DenyUnknown  (amber — an unparsed route
//	                                        could itself be a permissive catch-all)
type DenyState string

const (
	DenyMissing  DenyState = "missing"
	DenyEnforced DenyState = "enforced"
	DenyUnknown  DenyState = "unknown"
)

// LiveEdgeState is a normalized snapshot of what the edge reports RIGHT NOW.
//
// DenyCatchAllPresent is load-bearing: every EdgeProvider must always render and
// report the catch-all default-deny. A host is reachable iff an explicit route
// exists for it AND the catch-all deny is present (so anything not listed is
// denied). If DenyCatchAllPresent is ever false, that is a critical invariant
// violation surfaced by `audit`.
type LiveEdgeState struct {
	Routes              []Route
	DenyCatchAllPresent bool
	// Unparsed is everything the driver SAW but did not fully understand (unknown
	// handlers, undescended subroutes, indirect backends, …). It is additive and
	// never a silent drop: a driver's normalize appends here instead of dropping.
	// Its presence DOWNGRADES the default-deny verdict to UNKNOWN (see DenyState).
	Unparsed []Unparsed
	// Generator names the config generator that owns this edge, if detected
	// ("" = none / a static crenel-ownable config). When set, the whole edge is
	// foreign-managed and the mutation gate refuses to touch it.
	Generator string
	// IngressKind names the off-edge reachability mechanism, if detected
	// ("" = a public listener port). When External(), public/private status is
	// determined somewhere crenel cannot read (a tunnel/overlay/CDN) — declared,
	// never inferred. Usually overlaid by core from an edge's ingress posture
	// (declared or detected from a cloudflared/tailscale config), since ingress is
	// orthogonal to the proxy driver.
	IngressKind IngressKind
	// Persistence DECLARES whether a write to this edge survives a control-plane
	// restart (see PersistenceModel). The driver sets it from its own config: a file
	// provider is durable-config; a Caddy admin edge is durable-file when a persist
	// path is configured, resume when the operator declares it, else ephemeral-admin
	// (the safe default — admin writes are in-memory). "" = not classified (a mesh edge
	// that refuses mutation). status/audit surface it; the write path warns when it is
	// EphemeralWrites. The admin API carries no boot-source marker, so this is declared
	// from config, never inferred from the wire.
	Persistence PersistenceModel
	// Raw is the provider's untouched config payload, kept for export/debug.
	Raw string
}

// Coverage reports how much of the live config crenel actually understood:
// understood = len(Routes), total = understood + len(Unparsed). A status read uses
// it to say "read N/M routes — K NOT UNDERSTOOD".
func (s LiveEdgeState) Coverage() (understood, total int) {
	return len(s.Routes), len(s.Routes) + len(s.Unparsed)
}

// FullyParsed reports whether crenel understood the ENTIRE config, treating an
// operator-ACKNOWLEDGED unknown (UnknownAcknowledged) as resolved rather than
// blocking — every OTHER Unparsed entry still downgrades this to false. It is
// the precondition for certifying default-deny ENFORCED.
func (s LiveEdgeState) FullyParsed() bool {
	for _, u := range s.Unparsed {
		if u.Kind != UnknownAcknowledged {
			return false
		}
	}
	return true
}

// DenyState returns the ternary default-deny verdict (see DenyState). ENFORCED ⟹
// FullyParsed: crenel never certifies default-deny over config it did not read.
func (s LiveEdgeState) DenyState() DenyState {
	if !s.DenyCatchAllPresent {
		return DenyMissing
	}
	if !s.FullyParsed() {
		return DenyUnknown
	}
	return DenyEnforced
}

// HasHost reports whether an explicit route exists for host.
func (s LiveEdgeState) HasHost(host string) bool {
	for _, r := range s.Routes {
		if strings.EqualFold(r.Host, host) {
			return true
		}
	}
	return false
}

// Hosts returns the sorted set of exposed hostnames.
func (s LiveEdgeState) Hosts() []string {
	out := make([]string, 0, len(s.Routes))
	for _, r := range s.Routes {
		out = append(out, r.Host)
	}
	sort.Strings(out)
	return out
}

// Reachable encodes the structural default-deny rule: a host is reachable iff an
// explicit route exists for it AND the catch-all deny is present.
func (s LiveEdgeState) Reachable(host string) bool {
	return s.DenyCatchAllPresent && s.HasHost(host)
}

// Scope distinguishes internal vs public DNS.
type Scope string

const (
	ScopeInternal Scope = "internal"
	ScopePublic   Scope = "public"
)

// Record is a single DNS record.
//
// TTL and Proxied are PRESERVATION attributes: when a provider reproduces a record it
// did not change (e.g. a whole-zone push carries a sibling record through verbatim),
// these carry the live record's settings unchanged so the push does not silently reset
// them. They are NOT part of Key() — identity stays name/type/scope, so a value/TTL/
// proxied change at the same name is still recognized as the same record (an update,
// not a second record).
type Record struct {
	Name  string // FQDN or relative name, e.g. "grafana"
	Type  string // "A", "CNAME", ...
	Value string // target
	Scope Scope
	// TTL is the record TTL in seconds; 0/1 mean "auto / provider default". Preserved so
	// a reproduced record keeps its TTL instead of being reset to the provider default.
	TTL int
	// Proxied is the Cloudflare orange-cloud state (true = proxied through Cloudflare).
	// Preserved so a reproduced A/AAAA/CNAME is never silently un-proxied. Meaningful
	// only for Cloudflare A/AAAA/CNAME; false/ignored for every other type/provider.
	Proxied bool
}

func (r Record) Key() string {
	return fmt.Sprintf("%s/%s/%s", r.Scope, r.Type, strings.ToLower(r.Name))
}

// EdgeChange is the edge half of a ChangeSet.
type EdgeChange struct {
	AddRoutes   []Route
	RemoveHosts []string
	// DenyCatchAllWillBePresent is what the catch-all deny state will be AFTER
	// applying. It must be true for any safe ChangeSet.
	DenyCatchAllWillBePresent bool
}

func (e EdgeChange) Empty() bool {
	return len(e.AddRoutes) == 0 && len(e.RemoveHosts) == 0
}

// DNSChange is the DNS half of a ChangeSet.
type DNSChange struct {
	Scope  Scope
	Add    []Record
	Remove []Record
	// Managed is the FULL set of records crenel manages for this scope/op (with their
	// expected values) — NOT just the Add/Remove delta. The whole-zone-push ownership
	// gate uses it to recognize crenel's OWN records (so it doesn't flag an already-
	// correct managed record as foreign) and to refuse pre-existing records it does not
	// own. Set by the driver's Diff (= the op's desired records) and by reconcile /
	// declarative apply (= the full canonical desired set); carried through to Apply.
	Managed []Record
	// Rendered is the dnsconfig.js (or provider preview text) for display.
	Rendered string
}

func (d DNSChange) Empty() bool {
	return len(d.Add) == 0 && len(d.Remove) == 0
}

// EdgePlan is one edge's slice of a multi-edge ChangeSet — the change projected
// onto a single named edge in the topology (M4). The core engine aggregates one
// EdgePlan per participating edge; a driver itself never sees these (a driver only
// ever deals with the single-edge ChangeSet.Edge field).
type EdgePlan struct {
	Edge   string     // topology name of the edge, e.g. "home", "vps"
	Driver string     // provider name, e.g. "caddy", "traefik"
	Change EdgeChange // the change projected onto this edge
}

// ChangeSet is the full computed diff for an Op versus live state.
//
// Two edge representations coexist by design:
//   - Edge  — a SINGLE edge's change. This is the driver-level field: an
//     EdgeProvider.Plan sets it, and EdgeProvider.Apply reads it. A driver is
//     multi-edge-unaware; it only ever handles its own Edge.
//   - Edges — the CORE-level aggregation across the whole edge topology (M4), one
//     EdgePlan per participating edge. core.Plan fills this; the preview, apply
//     ordering, and rollback operate over it. For a single-edge engine it holds
//     exactly one entry.
type ChangeSet struct {
	Op    Op
	Edge  EdgeChange  // single-edge (driver-level) change
	Edges []EdgePlan  // multi-edge (core-level) aggregation
	DNS   []DNSChange // one per DNS provider/scope, may be empty in edge-only flows

	// NewPublic is the "about to go public" highlight: hostnames that will
	// become publicly reachable as a result of applying this ChangeSet. This is
	// the headline a human must see before confirming.
	NewPublic []string
}

// Empty reports whether the ChangeSet would change nothing.
func (c ChangeSet) Empty() bool {
	if !c.Edge.Empty() {
		return false
	}
	for _, ep := range c.Edges {
		if !ep.Change.Empty() {
			return false
		}
	}
	for _, d := range c.DNS {
		if !d.Empty() {
			return false
		}
	}
	return true
}
