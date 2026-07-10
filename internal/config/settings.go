package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/config/yaml"
)

// Settings is the wiring configuration for a Crenel invocation. It is NOT a
// stored desired state — it only says WHERE the providers live and how to talk
// to them (admin URLs, the zone, the static origin map). What is exposed is
// always read live.
type Settings struct {
	// EdgeDriver selects the edge provider: "caddy" (default), "traefik", "nginx",
	// or "netbird". caddy talks to a Caddy admin API; traefik rewrites a
	// file-provider dynamic config (TraefikConfigPath); nginx rewrites an nginx
	// config file (NginxConfigPath); netbird reads an identity-mesh grant store.
	EdgeDriver string `json:"edge_driver,omitempty"`
	// TraefikConfigPath is the dynamic-config file the Traefik file provider
	// watches (used only when EdgeDriver == "traefik").
	TraefikConfigPath string `json:"traefik_config_path,omitempty"`
	// NginxConfigPath is the nginx config file crenel manages (used only when
	// EdgeDriver == "nginx"). crenel does an additive read-modify-write of it,
	// regenerating only its own marker-tagged server blocks + the default-deny.
	NginxConfigPath string `json:"nginx_config_path,omitempty"`

	// --- file-driver runtime surfaces (optional; enable a TRUE runtime verify) ---
	// TraefikAPIURL is the Traefik HTTP API base (e.g. "http://127.0.0.1:8080"). When
	// set, an apply CONFIRMS routes against the running daemon's /api/http/routers
	// rather than re-reading crenel's own file (the hollow-verify gap). Without it,
	// runtime verify reports "unavailable" (honest, never a false "verified").
	TraefikAPIURL string `json:"traefik_api_url,omitempty"`
	// NginxRuntime makes nginx writes LIVE and confirmable: a validate (nginx -t) +
	// reload command on apply, and an HTTP probe base to confirm a host through the
	// running daemon. Without it, an nginx write is on-disk only and reports
	// "written; runtime verify unavailable".
	NginxRuntime *NginxRuntimeSettings `json:"nginx_runtime,omitempty"`
	// NginxTLS, when set, makes crenel's nginx blocks terminate TLS with the operator's
	// cert (`listen 443 ssl` + ssl_certificate). Without it crenel serves HTTP on
	// NginxListenPort (default 80) — a valid config a stock nginx loads.
	NginxTLS *NginxTLSSettings `json:"nginx_tls,omitempty"`
	// NginxListenPort overrides the plain-HTTP listen port for crenel's blocks (default
	// 80). Ignored when NginxTLS is set.
	NginxListenPort int `json:"nginx_listen_port,omitempty"`
	// NetbirdGrantsPath is the ACL grant store for the NetBird identity-mesh edge
	// (used only when EdgeDriver == "netbird"). That edge is read-only in crenel;
	// mutations error loudly (it can't express reverse-proxy routing).
	NetbirdGrantsPath string `json:"netbird_grants_path,omitempty"`

	// Edges, when non-empty, defines a MULTI-EDGE topology (M4: home + VPS
	// double-write). Each entry is one NAMED edge with its own driver, endpoint,
	// and origins — and the origins double as the projection set (an Expose lands
	// on an edge iff that edge's origins contain the service). Takes precedence
	// over the single top-level edge fields above; when empty, the single
	// top-level edge is used (degenerate N=1, back-compat).
	Edges []EdgeSettings `json:"edges,omitempty"`

	// AdminURL is the Caddy admin API base URL, e.g. "http://127.0.0.1:2019".
	AdminURL string `json:"admin_url"`
	// Zone derives a host from a service name, e.g. "example.com".
	Zone string `json:"zone"`
	// Origins is the static service->backend map for the M0 OriginResolver.
	Origins map[string]string `json:"origins"`
	// DNS configures DNS providers (optional in early milestones).
	DNS DNSSettings `json:"dns"`

	// FakeSeed, when set, points at a fixture file (Caddyfile or JSON) used to
	// seed an IN-PROCESS fake Caddy admin API. This is the safe, no-infra demo
	// mode. When empty, AdminURL is used as-is.
	FakeSeed string `json:"fake_seed,omitempty"`

	// ReadOnly declares this whole topology AUDIT-ONLY ("I only ever audit this
	// edge"): every mutating verb refuses before planning (core.ErrReadOnlyEngine)
	// and no write capability is ever invoked. It also re-frames audit's edge-wide
	// generator finding to ok-severity `foreign_managed_readonly` — a foreign edge
	// is the expected posture here, not a problem to fix. Reads (status/audit/
	// drift/preview/export) are unaffected. There is deliberately NO flag for this:
	// audit is already read-only; the posture is a property of the CONFIG, not of
	// an invocation. Default false.
	ReadOnly bool `json:"read_only,omitempty"`

	// GranularApply uses additive structured-admin-API operations instead of a
	// full `POST /load` replace. REQUIRED for any rich/production edge: it never
	// rewrites routes Crenel does not manage. Default false keeps the simple
	// full-load path for greenfield/fixture edges.
	//
	// Note: granular ops are additive but NOT lighter than POST /load — Caddy
	// regenerates and reloads the WHOLE config on every /config/ mutation. crenel
	// settles (re-checks admin health) between ops to avoid a reload storm.
	GranularApply bool `json:"granular_apply"`

	// CaddyLayer4 declares the Caddy edge was built with the caddy-l4 plugin, so
	// crenel can render ModeTCPPassthrough (SNI passthrough) via the layer4 app. It
	// is a CAPABILITY gate: without it the driver refuses passthrough loudly. Requires
	// GranularApply (the layer4 write is additive). Default false.
	CaddyLayer4 bool `json:"caddy_layer4,omitempty"`

	// CaddyPersistPath, when set, enables ON-DISK PERSISTENCE for the Caddy edge:
	// after a verified apply, crenel additively mirrors its managed routes into this
	// mounted Caddyfile (between sentinels), validates it, and reloads — so the
	// routes survive a `docker restart` (which otherwise reverts the in-memory
	// admin-API config). Default off. See docs/internal/USABILITY-DESIGN.md §B.
	CaddyPersistPath string `json:"caddy_persist_path,omitempty"`

	// CaddyPersist configures the DURABLE wildcard-site reconciler (the home-edge path):
	// where the boot Caddyfile lives, over which channel to read/write it, and where the
	// caddy binary runs for validate/reload/adapt. When set it supersedes
	// CaddyPersistPath. See PersistSettings and docs/internal/DESIGN.md "Durability".
	CaddyPersist *PersistSettings `json:"caddy_persist,omitempty"`

	// CaddyGenerator DECLARES that the Caddy edge is generated/owned by the named
	// tool (e.g. "caddy-docker-proxy"). The Caddy admin API carries no marker for
	// such generators, so this explicit hint engages the refuse-to-manage gate
	// edge-wide. Optional; prefer CaddyGeneratorConfigPath when the artifact is
	// mountable. See TOPOLOGY-RISK-REGISTER §3.3.
	CaddyGenerator string `json:"caddy_generator,omitempty"`
	// CaddyGeneratorConfigPath points crenel at an on-disk artifact to SCAN for a
	// generator signature — caddy-docker-proxy's `Caddyfile.autosave` (mount it into
	// crenel's filesystem). When present + matching, the edge reads foreign and the
	// gate refuses to mutate it. Optional; absent => no detection (P0 net still applies).
	CaddyGeneratorConfigPath string `json:"caddy_generator_config_path,omitempty"`

	// AuthPolicies maps a provider-agnostic forward-auth POLICY name (e.g.
	// "authelia") to its per-driver REFERENCE. Optional: with no entry for a policy,
	// crenel falls back to sensible default conventions (Caddy `import <name>`,
	// Traefik `<name>@file`, nginx `auth_request /<name>`). The operator always owns
	// the actual snippet/middleware/location; crenel only emits the reference. See
	// docs/internal/AUTH-DESIGN.md §2.
	AuthPolicies map[string]AuthPolicy `json:"auth_policies,omitempty"`

	// AuthDownstream marks the (single top-level) edge as the FRONT of an edge
	// CHAIN: it fronts a downstream edge that enforces forward-auth, so this edge
	// legitimately carries no auth handler of its own. When true, `status` labels
	// its hosts `auth: downstream` and `audit` suppresses the (then-spurious)
	// public_without_auth warning. Default false (a terminal edge — the warning
	// fires). For a multi-edge topology set it per-edge on EdgeSettings instead. See
	// docs/internal/DESIGN.md "Chain topology".
	//
	// `auth_downstream` is the blunt ASSERTION; `downstream_edge` below is the
	// OBSERVED chain (P4) — prefer it when the downstream edge is also configured so
	// crenel resolves auth by reading it. The flag remains the fallback when the
	// downstream edge cannot be read.
	AuthDownstream bool `json:"auth_downstream,omitempty"`

	// DownstreamEdge names another edge in the topology that this (front) edge
	// FORWARDS to in a CHAIN (P4): a front leaf whose backend dials the downstream
	// edge is a chain forward whose REAL destination + auth live one hop down. When
	// set, `status`/`audit` FOLLOW THROUGH — reading the named edge to resolve each
	// forwarded host's true backend + observed auth (or declaring it "downstream, not
	// observed" when unreadable). Requires a multi-edge `edges[]` topology (the
	// downstream must be a named, readable edge); on the single top-level edge it is
	// inert. See docs/internal/DESIGN.md "Chain-aware model (P4)".
	DownstreamEdge string `json:"downstream_edge,omitempty"`
	// DownstreamAddress is the address (host or host:port) the front dials to reach
	// the downstream edge. A front leaf whose backend HOST matches it is a chain
	// forward; a leaf dialing anything else is a terminal origin the front serves
	// itself. Empty => every non-mesh data-plane route on the front is treated as a
	// forward (the "pure front" case). Only meaningful with DownstreamEdge.
	DownstreamAddress string `json:"downstream_address,omitempty"`
	// DownstreamScheme declares whether the front dials the downstream edge over
	// "https" (re-originate TLS to a `:443` downstream, preserving Host) or "http"
	// (plain). Empty => INFER from DownstreamAddress: a `:443` dial is treated as
	// https, anything else as http. Set it explicitly for a `:443` downstream that is
	// NOT TLS, or a TLS downstream on a non-443 port. Only meaningful with
	// DownstreamEdge. See docs/internal/DESIGN.md "Transport / Connection".
	DownstreamScheme string `json:"downstream_scheme,omitempty"`

	// IngressKind DECLARES this edge's off-edge reachability mechanism when the
	// operator knows it: "tunnel" (cloudflared), "overlay" (Tailscale serve/funnel,
	// WireGuard), "public-listener" (an ordinary port), or "unknown". A
	// tunnel/overlay-fronted edge is PUBLIC even when the local proxy binds localhost,
	// so reading only the listener would MISREAD it internal. Empty => fall back to
	// IngressConfigPath detection. See TOPOLOGY-RISK-REGISTER §4.3.
	IngressKind string `json:"ingress_kind,omitempty"`
	// IngressConfigPath points crenel at a tunnel/overlay config to SCAN for an
	// ingress signature (a cloudflared config.yml, a Tailscale serve.json). Present +
	// recognized => the mechanism is detected; present + unrecognized => UNKNOWN
	// (declared external, never assumed internal); absent => no claim. Optional.
	IngressConfigPath string `json:"ingress_config_path,omitempty"`

	// AdminReadTimeoutSeconds bounds read calls (GET /config/). Default 10s.
	// AdminWriteTimeoutSeconds bounds mutating calls (POST /load and granular
	// /config/ writes), which trigger a full Caddy reload and can legitimately
	// take tens of seconds on a Cloudflare DNS-01 build — but are still bounded so
	// crenel never hangs on a wedged admin API. Default 60s. Zero => default.
	AdminReadTimeoutSeconds  int `json:"admin_read_timeout_seconds,omitempty"`
	AdminWriteTimeoutSeconds int `json:"admin_write_timeout_seconds,omitempty"`

	// Transport selects HOW crenel physically reaches this (Caddy admin-API) edge —
	// decoupled from the driver, which knows the API shape. Empty/absent (or
	// type "direct") = real HTTP to admin_url, exactly today's behavior. "ssh-exec"
	// runs the admin call as a nested-exec curl against a loopback admin (no port, no
	// tunnel); "ssh-tunnel" opens a crenel-managed local forward. For a multi-edge
	// topology set it per-edge on EdgeSettings instead. See docs/internal/DESIGN.md "Transport /
	// Connection".
	Transport *TransportSettings `json:"transport,omitempty"`
}

// TransportSettings configures the connection channel for an admin-API edge. Only
// the Caddy driver consumes it; file-based drivers ignore it. Default (nil / empty
// Type / "direct") is real HTTP to admin_url — fully back-compatible.
type TransportSettings struct {
	// Type: "direct" (default) | "ssh-exec" | "ssh-tunnel".
	Type string `json:"type,omitempty"`

	// --- ssh-exec ---
	// Command is the exec PREFIX argv (NOT shell-parsed) that lands a stdin-reading
	// POSIX shell where the admin loopback lives, e.g.
	//   ["ssh","root@ml350","pct","exec","113","--","docker","exec","-i","caddy","sh"]
	Command []string `json:"command,omitempty"`
	// AdminURL is the admin API base URL AS SEEN FROM the far end of the exec chain
	// (default "http://127.0.0.1:2019"). Distinct from the edge's local admin_url.
	AdminURL string `json:"admin_url,omitempty"`
	// Curl is the far-end HTTP client: "curl" (default; all methods) or "wget" (GET).
	Curl string `json:"curl,omitempty"`

	// --- ssh-tunnel ---
	SSHTarget   string `json:"ssh_target,omitempty"`   // user@host
	SSHIdentity string `json:"ssh_identity,omitempty"` // ssh -i identity path
	LocalPort   int    `json:"local_port,omitempty"`   // local forward port
	RemoteHost  string `json:"remote_host,omitempty"`  // remote side (default 127.0.0.1)
	RemotePort  int    `json:"remote_port,omitempty"`  // remote admin port (default 2019)
}

// PersistSettings configures the DURABLE wildcard-site Caddyfile reconciler — how crenel
// makes an admin-API write SURVIVE a control-plane restart by reconciling it into the
// on-disk boot config. It captures the home edge's two-channel reality: the boot
// Caddyfile lives on the LXC HOST (bind-mounted read-only into the container), but `caddy
// validate/reload/adapt` must run INSIDE the container. Absent => the simple flat
// persister over CaddyPersistPath (local FS). See docs/internal/DESIGN.md "Durability".
type PersistSettings struct {
	// BootPath is the boot Caddyfile path AS caddy validate/reload/adapt see it (e.g.
	// "/etc/caddy/Caddyfile" inside the container). It is also the persist path that
	// declares the edge durable-file. Falls back to CaddyPersistPath when empty.
	BootPath string `json:"boot_path,omitempty"`
	// FileCommand is the exec PREFIX (argv, NOT shell-parsed; innermost element a bare
	// `sh`) landing a shell on the host that HOLDS the boot file — for the home edge the
	// LXC host: ["ssh","root@ml350","pct","exec","113","--","sh"]. Empty => the boot file
	// is on crenel's local filesystem (read/written directly).
	FileCommand []string `json:"file_command,omitempty"`
	// FilePath is the boot Caddyfile path on the FileCommand host (e.g.
	// "/opt/stacks/caddy/conf/Caddyfile"). Required when FileCommand is set.
	FilePath string `json:"file_path,omitempty"`
	// CaddyCommand is the exec PREFIX landing a shell where the caddy BINARY runs — for
	// the home edge inside the container:
	// ["ssh","root@ml350","pct","exec","113","--","docker","exec","-i","caddy","sh"].
	// Empty => a local `caddy` binary.
	CaddyCommand []string `json:"caddy_command,omitempty"`
	// Adapter is the caddy config adapter (default "caddyfile").
	Adapter string `json:"adapter,omitempty"`
	// VerifyAdapt runs the `caddy adapt` re-adaptation read-back (the strongest
	// durability proof: the candidate is proven to re-adapt to the live managed state
	// before commit). Default true; set false to skip it (self-check + validate only) on
	// an edge where `caddy adapt` is unavailable.
	VerifyAdapt *bool `json:"verify_adapt,omitempty"`
}

// AdminReadTimeout returns the configured read timeout, or 0 if unset (the driver
// then applies its own default).
func (s Settings) AdminReadTimeout() time.Duration {
	return time.Duration(s.AdminReadTimeoutSeconds) * time.Second
}

// AdminWriteTimeout returns the configured write timeout, or 0 if unset.
func (s Settings) AdminWriteTimeout() time.Duration {
	return time.Duration(s.AdminWriteTimeoutSeconds) * time.Second
}

// NginxRuntimeSettings is the operator-owned recipe for reaching the running nginx so
// crenel's writes go LIVE and can be CONFIRMED (bench gaps N1/N2/N3). Commands run
// verbatim via os/exec — the operator's own (e.g. a `docker exec <ctr> nginx ...`).
type NginxRuntimeSettings struct {
	// TestCmd validates the written config before reload (e.g. ["docker","exec","ng","nginx","-t"]).
	// A non-zero exit FAILS the apply (so an invalid render rolls back, never "applied").
	TestCmd []string `json:"test_cmd,omitempty"`
	// ReloadCmd makes the write live (e.g. ["docker","exec","ng","nginx","-s","reload"]).
	ReloadCmd []string `json:"reload_cmd,omitempty"`
	// ProbeURL is the HTTP base crenel requests a host through to confirm it is served
	// (expose) / denied (unexpose), e.g. "http://127.0.0.1:8081".
	ProbeURL string `json:"probe_url,omitempty"`
}

// NginxTLSSettings makes crenel's nginx blocks terminate TLS with the operator's cert.
type NginxTLSSettings struct {
	Port     int    `json:"port,omitempty"` // listen port (default 443)
	CertPath string `json:"cert_path"`      // ssl_certificate
	KeyPath  string `json:"key_path"`       // ssl_certificate_key
}

// AuthPolicy is the per-driver REFERENCE for one forward-auth policy. Every field
// is optional; an unset field falls back to the driver's default convention for
// the policy name. crenel is auth-provider-agnostic — these are pointers to config
// the operator owns (a Caddy snippet, a Traefik middleware, an nginx location),
// never the auth provider's internals.
type AuthPolicy struct {
	// CaddyImport names a Caddyfile snippet crenel `import`s inside the route
	// (full-load path). Default convention: the policy name.
	CaddyImport string `json:"caddy_import,omitempty"`
	// CaddyForwardAuth, when set, is the authorizer endpoint (e.g. "authelia:9091")
	// crenel expands on the granular admin-API path into the CANONICAL forward-auth gate
	// (a reverse_proxy + handle_response subrequest — the exact shape Caddy's
	// `forward_auth` directive compiles to and the home edge accepts). The provider's
	// verify URI / copy-headers are declared below; crenel never invents them.
	CaddyForwardAuth string `json:"caddy_forward_auth,omitempty"`
	// CaddyForwardAuthVerifyURI is the verify path (with ?rd=…) crenel rewrites the auth
	// subrequest to, e.g. "/api/verify?rd=https://auth.example.com". Operator-declared.
	CaddyForwardAuthVerifyURI string `json:"caddy_forward_auth_verify_uri,omitempty"`
	// CaddyForwardAuthCopyHeaders are the auth headers copied from a 2xx authorizer
	// response into the request (e.g. Remote-User, Remote-Groups, Remote-Name,
	// Remote-Email). Operator-declared; crenel renders the copy, not the policy.
	CaddyForwardAuthCopyHeaders []string `json:"caddy_forward_auth_copy_headers,omitempty"`
	// CaddyHandlerJSON is an operator-provided VERBATIM Caddy JSON handler object for the
	// granular path — the purest auth-by-reference: crenel inserts it unchanged ahead of
	// the backend reverse_proxy, owning NONE of the provider's internals. Paste a
	// known-good forward-auth handler (e.g. the reverse_proxy+handle_response block from
	// a live config). Takes precedence over CaddyForwardAuth.
	CaddyHandlerJSON json.RawMessage `json:"caddy_handler_json,omitempty"`
	// TraefikMiddleware is the named middleware attached to the crenel router.
	// Default convention: "<name>@file".
	TraefikMiddleware string `json:"traefik_middleware,omitempty"`
	// NginxAuthRequest is the auth_request URI (an internal location the operator
	// defines). Default convention: "/<name>".
	NginxAuthRequest string `json:"nginx_auth_request,omitempty"`
}

// EdgeSettings configures one named edge in a multi-edge topology (M4).
type EdgeSettings struct {
	Name              string `json:"name"`
	Driver            string `json:"driver"` // "caddy" | "traefik" | "nginx" | "netbird"
	AdminURL          string `json:"admin_url,omitempty"`
	FakeSeed          string `json:"fake_seed,omitempty"`
	TraefikConfigPath string `json:"traefik_config_path,omitempty"`
	NginxConfigPath   string `json:"nginx_config_path,omitempty"`
	NetbirdGrantsPath string `json:"netbird_grants_path,omitempty"`
	// File-driver runtime surfaces (see the top-level Settings fields of the same name).
	TraefikAPIURL    string                `json:"traefik_api_url,omitempty"`
	NginxRuntime     *NginxRuntimeSettings `json:"nginx_runtime,omitempty"`
	NginxTLS         *NginxTLSSettings     `json:"nginx_tls,omitempty"`
	NginxListenPort  int                   `json:"nginx_listen_port,omitempty"`
	GranularApply    bool                  `json:"granular_apply,omitempty"`
	CaddyLayer4      bool                  `json:"caddy_layer4,omitempty"`
	CaddyPersistPath string                `json:"caddy_persist_path,omitempty"`
	// CaddyPersist configures the durable wildcard-site reconciler for this edge (see
	// the top-level Settings field of the same name). Supersedes CaddyPersistPath.
	CaddyPersist *PersistSettings `json:"caddy_persist,omitempty"`
	// CaddyGenerator / CaddyGeneratorConfigPath: per-edge generator ownership hints
	// (see the top-level Settings fields of the same name).
	CaddyGenerator           string `json:"caddy_generator,omitempty"`
	CaddyGeneratorConfigPath string `json:"caddy_generator_config_path,omitempty"`
	// IngressKind / IngressConfigPath: per-edge off-edge reachability posture (see the
	// top-level Settings fields of the same name).
	IngressKind       string `json:"ingress_kind,omitempty"`
	IngressConfigPath string `json:"ingress_config_path,omitempty"`
	// Origins is this edge's service->backend map. It is BOTH the resolver source
	// (per-edge addresses: home proxies a LAN IP, VPS proxies a Tailscale IP) AND
	// the projection set (this edge fronts exactly these services).
	Origins map[string]string `json:"origins"`
	// AuthDownstream marks this edge as the FRONT of an edge CHAIN (it fronts a
	// downstream edge that enforces forward-auth), suppressing public_without_auth
	// for its hosts and labeling them `auth: downstream`. Default false. See
	// docs/internal/DESIGN.md "Chain topology".
	AuthDownstream bool `json:"auth_downstream,omitempty"`
	// DownstreamEdge / DownstreamAddress: the OBSERVED chain (P4). DownstreamEdge
	// names the edge in this topology that this front forwards to; a front leaf that
	// dials DownstreamAddress (host match; empty => all non-mesh routes) is a chain
	// forward whose real backend + auth crenel resolves by READING the downstream
	// edge. See the top-level Settings fields of the same name and docs/internal/DESIGN.md
	// "Chain-aware model (P4)".
	DownstreamEdge    string `json:"downstream_edge,omitempty"`
	DownstreamAddress string `json:"downstream_address,omitempty"`
	// DownstreamScheme: "https"/"http" for the front→downstream dial; empty infers
	// from a `:443` DownstreamAddress. See the top-level Settings field of the same name.
	DownstreamScheme         string `json:"downstream_scheme,omitempty"`
	AdminReadTimeoutSeconds  int    `json:"admin_read_timeout_seconds,omitempty"`
	AdminWriteTimeoutSeconds int    `json:"admin_write_timeout_seconds,omitempty"`
	// Transport selects HOW crenel reaches this edge's admin API (direct / ssh-exec /
	// ssh-tunnel). Absent => direct to admin_url. See the top-level Settings field and
	// docs/internal/DESIGN.md "Transport / Connection".
	Transport *TransportSettings `json:"transport,omitempty"`
}

// DNSSettings configures the DNS provider(s).
//
// Two shapes are supported:
//   - Single provider (back-compat): set the top-level Scope/Zone/EdgeAddr/Mock
//     fields. Used when only one DNS scope is managed.
//   - Multiple providers (M3): set Providers with one entry per scope. This is
//     how Crenel manages internal (AdGuard, !inside) AND public (Cloudflare,
//     !outside) DNS at once, so a single ChangeSet aggregates edge, internal-DNS,
//     and public-DNS into the unified "about to go public" view.
type DNSSettings struct {
	Enabled bool `json:"enabled"`

	// Single-provider fields (used only when Providers is empty).
	Type     string `json:"type,omitempty"` // "" | "mock" | "cloudflare" | "adguard"
	Scope    string `json:"scope"`          // "internal" | "public"
	Zone     string `json:"zone"`           // DNS zone managed
	EdgeAddr string `json:"edge_addr"`      // address records point at (the edge)
	// Targets (see DNSProviderSettings) — single-provider form: per-residency-class
	// answer addresses layered over the edge_addr default.
	Targets map[string]string `json:"targets,omitempty"`
	// Mock, when true, wires an in-process fake provider instead of contacting a
	// real backend — the safe, no-infra demo path (mirrors --fake-seed for edge).
	Mock bool `json:"mock"`
	// DedicatedZone (see DNSProviderSettings) — single-provider form.
	DedicatedZone bool `json:"dedicated_zone,omitempty"`
	// ApplyMode / ZoneID / Proxied / TTL (see DNSProviderSettings) — single-provider form.
	ApplyMode string `json:"apply_mode,omitempty"`
	ZoneID    string `json:"zone_id,omitempty"`
	Proxied   bool   `json:"proxied,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
	// Single-provider credential fields (see DNSProviderSettings for semantics).
	APIToken    string `json:"api_token,omitempty"`
	APITokenEnv string `json:"api_token_env,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`

	// Providers, when non-empty, defines multiple DNS providers (one per scope).
	// Takes precedence over the single-provider fields above.
	Providers []DNSProviderSettings `json:"providers,omitempty"`
}

// DNSProviderSettings configures one DNS provider (one scope) within DNSSettings.
//
// Type selects the backend: "" / "mock" is the in-process fake (the safe default,
// touches no real infra); "cloudflare" drives the public authoritative zone via the
// dnscontrol CLOUDFLAREAPI provider; "adguard" drives the internal resolver rewrites
// via the AdGuard Home control API; "pihole" drives the internal resolver's Local
// DNS host entries via the Pi-hole v6 API. Credentials are NEVER hardcoded — prefer the
// *_env reference fields (the secret stays out of the config file); a literal value
// is accepted but is redacted at every output boundary (its JSON key is in
// redact.secretKeyParts). See docs/DNS-DESIGN.md §4 and SECURITY.md §1/§6.
type DNSProviderSettings struct {
	Type     string `json:"type,omitempty"` // "" | "mock" | "cloudflare" | "adguard" | "pihole"
	Scope    string `json:"scope"`          // "internal" | "public"
	Zone     string `json:"zone"`           // DNS zone managed (defaults to top-level zone)
	EdgeAddr string `json:"edge_addr"`      // address records point at (the edge)
	Mock     bool   `json:"mock"`           // in-process fake (safe, no-infra)

	// Zones declares ALL the zones this one provider entry manages — the multi-zone
	// resolver shape said ONCE (one endpoint, one credential set, one instance label)
	// instead of a copy-pasted entry per zone that invites config drift. Wiring
	// expands it into one zone-confined driver instance per zone (the battle-tested
	// single-zone drivers are untouched), sharing what should be shared: the instance
	// label and, for pihole, the session channel (one login, not N). When the list
	// carries 2+ zones the zone is woven into each instance's display name
	// ("adguard[home]/zone-a") so plan/apply/audit labels never collide; `zones: [a]`
	// is byte-identical to `zone: a`. Setting BOTH Zone and Zones is a loud config
	// error at wiring — never a silent precedence guess.
	Zones []string `json:"zones,omitempty"`

	// Targets maps a RESIDENCY class (the operator-declared `expose --residency
	// <class>` / apply-file `residency:` key) to the address THIS provider instance
	// answers for hosts of that class — the per-host half of the reference
	// architecture's `target(class, vantage)` rule (docs/REFERENCE-ARCH-split-horizon.md
	// §2). The instance is the vantage, so each internal provider carries its OWN map:
	// e.g. the home (non-tunnel) resolver maps "vps" to the PUBLIC edge IP while the
	// vps (tunnel) resolver maps "vps" to the tunnel-direct address. edge_addr stays
	// the home-resident default (class unset), so configs without targets behave
	// byte-identically to before. Only internal resolver types (adguard/pihole) accept
	// it — wiring refuses it elsewhere rather than silently ignore config; a declared
	// class with no entry is refused loudly at plan time (never guessed).
	Targets map[string]string `json:"targets,omitempty"`

	// Instance is an OPTIONAL stable label distinguishing this provider from another of
	// the same type+scope+zone — the dual-resolver split-horizon case: two adguard
	// providers, scope "internal", same zone, DIFFERENT endpoint + vantage-correct
	// edge_addr (e.g. instance "home" → home resolver, instance "vps" → tunnel resolver).
	// It is woven into the provider's Name() so the two are distinguishable in every
	// plan/apply/verify/audit label (incl. the dns_coverage_parity finding) instead of
	// colliding as a bare "adguard". Empty is fine for a single instance. See
	// docs/REFERENCE-ARCH-split-horizon.md.
	Instance string `json:"instance,omitempty"`

	// DedicatedZone asserts crenel OWNS the entire zone (every record is crenel-managed).
	// It applies to the whole-zone-authoritative dnscontrol/cloudflare path: by default
	// (false) crenel REFUSES to push a zone that holds pre-existing records it does not
	// own — it would otherwise become authoritative over a shared production zone (the
	// lone-wildcard trap). Set true ONLY for a delegated, all-crenel zone (e.g.
	// edge.example.com). Ignored by the adguard provider (per-record, no whole-zone push)
	// and by surgical Cloudflare mode (also per-record). See docs/DNS-DESIGN.md.
	DedicatedZone bool `json:"dedicated_zone,omitempty"`

	// ApplyMode selects HOW the cloudflare provider applies changes:
	//   - "" / "whole-zone": the legacy dnscontrol whole-zone push (requires
	//     DedicatedZone for a non-empty zone — the destructive-push guard).
	//   - "surgical" / "record": the native Cloudflare REST API, per-record CRUD. It can
	//     safely manage one host inside a SHARED zone because it only ever touches records
	//     it CREATED (marked with an ownership comment) and default-denies on a foreign
	//     record at its name. Does NOT require DedicatedZone. See docs/DNS-DESIGN.md
	//     "Surgical (record-level) Cloudflare mode". Only meaningful for type "cloudflare".
	ApplyMode string `json:"apply_mode,omitempty"`
	// ZoneID optionally pins the Cloudflare zone id for surgical mode (skips the
	// GET /zones?name= lookup). Optional; resolved from Zone when empty.
	ZoneID string `json:"zone_id,omitempty"`
	// Proxied sets the Cloudflare orange-cloud state on records surgical mode CREATES
	// (default false = grey-cloud / DNS-only, the safe default). TTL sets their TTL in
	// seconds (0/1 = auto).
	Proxied bool `json:"proxied,omitempty"`
	TTL     int  `json:"ttl,omitempty"`

	// --- cloudflare (public) credentials ---
	// APITokenEnv names the env var holding the Cloudflare API token (preferred: the
	// token never lands on disk). APIToken is the literal fallback (redacted in output).
	APIToken    string `json:"api_token,omitempty"`
	APITokenEnv string `json:"api_token_env,omitempty"`

	// --- adguard / pihole (internal) credentials ---
	// Endpoint is the resolver's API base URL (adguard: the control API, e.g.
	// "http://10.0.0.53:3000"; pihole: the v6 web/API base, e.g. "http://10.0.0.54:8080").
	// adguard: Username + Password (or PasswordEnv) are the Basic-auth control
	// credentials. pihole: Password (or PasswordEnv) alone — v6 auth is a
	// session-by-password login (POST /api/auth), there is no username.
	Endpoint    string `json:"endpoint,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`
}

// Defaults returns baseline settings suitable for the bundled fixtures.
func Defaults() Settings {
	return Settings{
		AdminURL: "http://127.0.0.1:2019",
		Zone:     "example.com",
		Origins: map[string]string{
			"grafana": "10.0.0.5:3000",
			"photos":  "10.0.0.6:2342",
			"vault":   "10.0.0.7:8200",
		},
	}
}

// Load reads settings from a JSON or YAML file. A path of "" returns Defaults (the
// no-config demo/scaffold baseline, which includes EXAMPLE origins). A real config
// is decoded into a ZERO Settings — never merged UNDER Defaults — so the bundled demo
// origins (grafana/photos/vault) cannot leak into a user's config and surface as
// phantom entries (e.g. in `import --dry-run`). Only the connection scalars
// AdminURL/Zone backfill from Defaults when the user omits them; Origins (and every
// other map/slice) are exactly what the user wrote. The format is chosen by
// DecodeFile (extension, then a content sniff); the same struct decodes from JSON or
// YAML via the shared json: tags.
func Load(path string) (Settings, error) {
	if path == "" {
		return Defaults(), nil
	}
	var s Settings
	if err := DecodeFile(path, &s); err != nil {
		return s, fmt.Errorf("load settings: %w", err)
	}
	d := Defaults()
	if s.AdminURL == "" {
		s.AdminURL = d.AdminURL
	}
	if s.Zone == "" {
		s.Zone = d.Zone
	}
	return s, nil
}

// DecodeFile reads path and decodes it into v as JSON or YAML. The format is
// selected by extension (.yaml/.yml => YAML; .json => JSON); for any other
// extension it sniffs the content (a leading '{' or '[' => JSON, else YAML). Both
// paths target the same json: struct tags. This is what lets every Crenel config
// — settings AND the declarative apply file — be written in either format.
func DecodeFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if isYAML(path, b) {
		return yaml.Unmarshal(b, v)
	}
	return json.Unmarshal(b, v)
}

// isYAML decides the format for path/content: extension first, then a sniff.
func isYAML(path string, b []byte) bool {
	switch {
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		return true
	case strings.HasSuffix(path, ".json"):
		return false
	}
	t := bytes.TrimSpace(b)
	return len(t) == 0 || (t[0] != '{' && t[0] != '[')
}
