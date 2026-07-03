// Package traefik is a SECOND EdgeProvider adapter — for Traefik's file provider
// (dynamic-configuration file) — added to de-risk the EdgeProvider port: a port
// with only one implementation (Caddy) is fake agnosticism. Traefik is a "dumb
// data-plane" edge, and it fits the port cleanly; where it nonetheless STRAINS is
// documented in STRAIN.md and in the doc comments below.
//
// Shape contrast with the Caddy driver (this is the point of a second driver):
//   - Caddy is driven through an HTTP ADMIN API; a reload can silently no-op, so
//     read-back-verify guards a live mutation, and a wedged admin endpoint is a
//     real failure mode (HealthChecker exists for it).
//   - Traefik's file provider has NO admin API: the dynamic-config FILE *is* the
//     desired config, and Traefik hot-reloads it. Crenel mutates the file with an
//     additive read-modify-write (only ever touching crenel-* keys), so unmanaged
//     routers/services survive untouched. There is no admin endpoint to wedge, so
//     this driver deliberately does NOT implement ports.HealthChecker — proving
//     that capability is genuinely optional.
//
// Invariant (same as every EdgeProvider): this driver ALWAYS reports the catch-all
// default-deny truthfully. For Traefik the deny is the platform's NATIVE behavior —
// an unmatched host gets a 404 — so Apply renders NO explicit deny router (an older
// crenel did, but its empty-loadBalancer service was rejected by real Traefik and
// dropped the whole file: bench gap T3). The invariant is upheld by never writing a
// permissive catch-all and by ReadLiveState reporting DenyCatchAllPresent=false only
// when some router forwards ALL hosts to a real backend (a permissive catch-all).
package traefik

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// Driver implements ports.EdgeProvider against a Traefik dynamic-config file.
type Driver struct {
	path     string // path to the dynamic-config file the file provider watches
	resolver ports.OriginResolver
	// authMiddlewares maps a forward-auth policy NAME to the named Traefik middleware
	// to attach (e.g. "authelia" -> "authelia@file"). Missing entries fall back to the
	// default convention "<policy>@file". Injected at cmd from config.AuthPolicies.
	authMiddlewares map[string]string
	// apiURL is the Traefik HTTP API base (e.g. "http://127.0.0.1:8080"). When set, the
	// driver implements ports.RuntimeVerifier and CONFIRMS a write against the RUNNING
	// daemon's /api/http/routers — not crenel's own written file (bench gap T4/N2).
	// Empty => runtime verify reports Unavailable (honest, never a false "verified").
	apiURL string
	// verifyDeadline/verifyInterval bound the runtime-verify poll for the file
	// provider's asynchronous watcher reload. Defaulted in New; overridable in tests.
	verifyDeadline time.Duration
	verifyInterval time.Duration
}

// New builds a Traefik driver bound to the dynamic-config file at path.
func New(path string, resolver ports.OriginResolver, opts ...Option) *Driver {
	d := &Driver{
		path:           path,
		resolver:       resolver,
		verifyDeadline: 6 * time.Second,
		verifyInterval: 400 * time.Millisecond,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Option configures the Driver.
type Option func(*Driver)

// WithAuthMiddlewares injects the policy-name -> middleware map (from
// config.AuthPolicies). With no entry for a policy, crenel uses the default
// convention "<policy>@file".
func WithAuthMiddlewares(m map[string]string) Option {
	return func(d *Driver) { d.authMiddlewares = m }
}

// WithAPIURL wires the Traefik HTTP API base so writes are CONFIRMED against the
// running daemon (ports.RuntimeVerifier). Without it, runtime verify is Unavailable.
func WithAPIURL(url string) Option {
	return func(d *Driver) { d.apiURL = strings.TrimRight(url, "/") }
}

// traefikMiddleware returns the middleware name to attach for a policy (default
// convention "<policy>@file").
func (d *Driver) traefikMiddleware(policy string) string {
	if mw := d.authMiddlewares[policy]; mw != "" {
		return mw
	}
	return policy + "@file"
}

// authForRouter recognizes the forward-auth policy on a router from its
// middlewares. A crenel-MANAGED router carries exactly the auth middleware crenel
// set, so its first middleware maps back to the policy (configured reverse-map, or
// the "<policy>@file" convention inverse). An UNMANAGED router is best-effort: a
// middleware whose name contains "auth" surfaces as "(detected)" (read-only
// recognition), other middleware chains (e.g. secheaders) are not claimed as auth.
func (d *Driver) authForRouter(managed bool, r *router) string {
	if r == nil || len(r.Middlewares) == 0 {
		return ""
	}
	if managed {
		mw := r.Middlewares[0]
		if p := d.policyForMiddleware(mw); p != "" {
			return p
		}
		return strings.TrimSuffix(mw, "@file")
	}
	for _, mw := range r.Middlewares {
		if strings.Contains(strings.ToLower(mw), "auth") {
			return model.AuthDetected
		}
	}
	return ""
}

// policyForMiddleware reverse-maps a configured middleware name to its policy.
func (d *Driver) policyForMiddleware(mw string) string {
	for policy, m := range d.authMiddlewares {
		if m == mw {
			return policy
		}
	}
	return ""
}

func (d *Driver) Name() string { return "traefik" }

// Validate confirms the dynamic-config file exists and parses.
func (d *Driver) Validate(ctx context.Context) error {
	_, err := d.read()
	return err
}

// ReadLiveState reads and normalizes the dynamic-config file.
//
// LIVE-STATE CAVEAT (a real strain of the port for file-provider edges): the file
// is the DESIRED config handed to Traefik, not a direct read of Traefik's RUNNING
// state. If Traefik rejects a bad dynamic config it keeps serving the prior one,
// so file != running until the hot-reload succeeds. A production-grade driver
// would additionally read Traefik's read-only API (GET /api/http/routers) to
// confirm the running state — exactly the read-back-verify the Caddy admin API
// gives for free. Against the fake (a file), we treat file == live. See STRAIN.md.
func (d *Driver) ReadLiveState(ctx context.Context) (model.LiveEdgeState, error) {
	cfg, err := d.read()
	if err != nil {
		return model.LiveEdgeState{}, err
	}
	raw, _ := encode(cfg)
	return d.normalize(cfg, string(raw)), nil
}

// normalize walks the dynamic config into a LiveEdgeState.
//
// Default-deny model (mirrors Caddy's): Traefik denies any host matching no
// router via an implicit 404. So the structural default-deny holds UNLESS some
// router forwards traffic for ALL hosts — a permissive catch-all (HostRegexp /
// host-less rule) pointing at a real backend. The always-rendered crenel-deny
// router is a catch-all with NO upstream, so it denies and does not open the edge.
func (d *Driver) normalize(cfg dynamicConfig, raw string) model.LiveEdgeState {
	state := model.LiveEdgeState{Raw: raw}
	permissiveCatchAll := false

	// Deterministic order for stable Routes output.
	names := make([]string, 0, len(cfg.HTTP.Routers))
	for name := range cfg.HTTP.Routers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		r := cfg.HTTP.Routers[name]
		if r == nil {
			continue
		}
		svc := cfg.HTTP.Services[r.Service]
		hosts := parseHosts(r.Rule)
		if len(hosts) == 0 {
			// Host-less / catch-all rule. Only fail-open if it forwards somewhere.
			if isCatchAll(r.Rule) && svc.hasUpstream() {
				permissiveCatchAll = true
				continue
			}
			// A host-less rule that still FORWARDS traffic (has an upstream) but isn't a
			// recognized catch-all routes by path/header/etc. crenel cannot model as a
			// host — it could expose something crenel can't see, so declare it unknown
			// rather than drop it silently. A host-less rule with no upstream forwards
			// nothing (a benign empty/deny-like router, incl. crenel's own deny) and is
			// not flagged.
			if svc.hasUpstream() {
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: "http.routers." + name, Kind: model.UnknownMatcher,
					Reason:     fmt.Sprintf("router %q forwards traffic via a host-less rule crenel cannot model as a host", name),
					RawExcerpt: r.Rule,
				})
			}
			continue
		}
		// A host-matched router that is ALSO scoped by a non-host predicate (PathPrefix /
		// Path / Method / Headers / Query / …) cannot be represented at host granularity:
		// reading it as a plain host route would claim the WHOLE host is exposed (and could
		// merge two paths' distinct backends/auth into one). DECLARE it matcher_conditional
		// instead (register §4 — the Caddy path-matcher analogue). Full path-granular
		// MODELING is the P5 follow-on.
		if keys := nonHostPredicates(r.Rule); len(keys) > 0 {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: "http.routers." + name, Kind: model.UnknownMatcher,
				Reason: fmt.Sprintf("router %q matches %s but is also scoped by non-host predicate(s) crenel does not model (%s) — path/method/header-granular routing is not represented at host granularity",
					name, strings.Join(hosts, ", "), strings.Join(keys, ", ")),
				RawExcerpt: r.Rule,
			})
			continue
		}
		if !svc.hasUpstream() {
			// A router crenel can read the HOST(s) of but whose backend it cannot
			// resolve (the named service is absent or has no server URL — e.g. a
			// weighted/mirroring/dynamic service crenel does not model). DECLARE the
			// effective backend unknown rather than drop the route silently.
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: "http.routers." + name, Kind: model.UnknownBackend,
				Reason:     fmt.Sprintf("router %q matches %s but its service %q has no resolvable upstream", name, strings.Join(hosts, ", "), r.Service),
				RawExcerpt: r.Rule,
			})
			continue
		}
		addr := stripScheme(svc.firstUpstream())
		managed := strings.HasPrefix(name, managedPrefix) // crenel-* key ownership
		auth := d.authForRouter(managed, r)               // forward-auth middleware recognition
		for _, h := range hosts {
			state.Routes = append(state.Routes, model.Route{
				Host:      h,
				Managed:   managed,
				Ownership: model.OwnershipFromMarker(managed),
				Upstream:  model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: addr, ServerName: h, Auth: auth},
			})
		}
	}

	// TCP passthrough routers (ModeTCPPassthrough): HostSNI rule + a TCP service.
	if cfg.TCP != nil {
		tnames := make([]string, 0, len(cfg.TCP.Routers))
		for name := range cfg.TCP.Routers {
			tnames = append(tnames, name)
		}
		sort.Strings(tnames)
		for _, name := range tnames {
			r := cfg.TCP.Routers[name]
			if r == nil {
				continue
			}
			svc := cfg.TCP.Services[r.Service]
			addr := svc.firstAddress()
			if addr == "" {
				continue
			}
			managed := strings.HasPrefix(name, managedPrefix) // crenel-tcp-* is also crenel-*
			for _, h := range parseHostSNI(r.Rule) {
				state.Routes = append(state.Routes, model.Route{
					Host:      h,
					Managed:   managed,
					Ownership: model.OwnershipFromMarker(managed),
					Upstream: model.Upstream{
						Kind:           model.ForwardToOrigin,
						Mode:           model.ModeTCPPassthrough,
						Address:        addr,
						TLSPassthrough: true,
						ServerName:     h,
					},
				})
			}
		}
	}

	state.DenyCatchAllPresent = !permissiveCatchAll
	// Foreign-ownership detection (P2): a label/orchestrator-derived dynamic config
	// (routers with a `@docker`/`@swarm`/`@kubernetes*` provider suffix) is regenerated
	// from its source, so a crenel file edit would be overwritten. Mark the edge +
	// every route foreign-managed; crenel still READS it, but the gate refuses to
	// mutate it. See TOPOLOGY-RISK-REGISTER §3.2/§4.6.
	if g := detectGenerator(cfg); g != "" {
		state.Generator = g
		for i := range state.Routes {
			state.Routes[i].Ownership = model.OwnForeign
			state.Routes[i].Managed = false
		}
	}
	// Durability: Traefik's file provider IS the boot config — crenel does a
	// read-modify-write of the same file the server watches, so a mutation persists
	// across a restart with no separate step.
	state.Persistence = model.PersistDurableConfig
	return state
}

// Plan computes the ChangeSet to realize op against live (identical in shape to
// the Caddy driver — the port's Plan contract is edge-agnostic). It never sets
// NewPublic: that is computed by core (publicness depends on DNS scope).
func (d *Driver) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true // crenel-deny is always rendered

	// Mode check: this driver renders HTTP routers (ModeHTTPProxy) AND TCP/SNI
	// passthrough (ModeTCPPassthrough, via tcp.routers + HostSNI + tls.passthrough).
	// It is not an identity mesh, so it refuses mesh-grant loudly.
	if op.Mode != model.ModeHTTPProxy && op.Mode != model.ModeTCPPassthrough {
		return cs, fmt.Errorf("%w: traefik expresses http_proxy and tcp_passthrough (got %s) — "+
			"it is not an identity-mesh edge",
			model.ErrModeUnsupported, op.Mode)
	}

	switch op.Verb {
	case model.Expose:
		if op.Host == "" {
			return cs, fmt.Errorf("traefik plan: expose requires a host")
		}
		if live.HasHost(op.Host) {
			return cs, nil // already exposed => no-op
		}
		addr := op.To
		if addr == "" {
			resolved, err := d.resolver.Resolve(op.Service)
			if err != nil {
				return cs, fmt.Errorf("traefik plan: %w", err)
			}
			addr = resolved
		}
		up := model.Upstream{Kind: model.ForwardToOrigin, Mode: op.Mode, Address: addr, ServerName: op.Host, Auth: op.Auth}
		if op.Mode == model.ModeTCPPassthrough {
			up.TLSPassthrough = true
		}
		cs.Edge.AddRoutes = []model.Route{{Host: op.Host, Upstream: up}}
	case model.Unexpose:
		if op.Host == "" {
			return cs, fmt.Errorf("traefik plan: unexpose requires a host")
		}
		if !live.HasHost(op.Host) {
			return cs, nil // not exposed => no-op
		}
		cs.Edge.RemoveHosts = []string{op.Host}
	default:
		return cs, fmt.Errorf("traefik plan: unknown verb %q", op.Verb)
	}
	return cs, nil
}

// Apply realizes the edge change with an ADDITIVE read-modify-write of the
// dynamic-config file. It reads the current file, mutates ONLY crenel-* keys
// (adds/removes the managed router+service per host), always (re)writes the
// crenel-deny catch-all, and writes the file back. Every router/service Crenel
// does not manage is preserved byte-for-byte in structure.
//
// As with every EdgeProvider, a successful return is NOT proof: core
// read-back-verifies via a second ReadLiveState.
func (d *Driver) Apply(ctx context.Context, cs model.ChangeSet) error {
	cfg, err := d.read()
	if err != nil {
		return fmt.Errorf("traefik apply: read: %w", err)
	}
	if cfg.HTTP.Routers == nil {
		cfg.HTTP.Routers = map[string]*router{}
	}
	if cfg.HTTP.Services == nil {
		cfg.HTTP.Services = map[string]*service{}
	}

	// Removes BEFORE adds: a reconcile mode re-render carries the same host in both
	// RemoveHosts and AddRoutes (drop the wrong-mode router, then render the
	// canonical one). Removing first guarantees the add wins.
	for _, h := range cs.Edge.RemoveHosts {
		// A host may have been exposed in either tree; remove the crenel-managed
		// keys from both (idempotent).
		delete(cfg.HTTP.Routers, managedRouterID(h))
		delete(cfg.HTTP.Services, managedServiceID(h))
		if cfg.TCP != nil {
			delete(cfg.TCP.Routers, tcpRouterID(h))
			delete(cfg.TCP.Services, tcpServiceID(h))
		}
	}
	for _, r := range cs.Edge.AddRoutes {
		if r.Upstream.Mode == model.ModeTCPPassthrough {
			addTCPPassthrough(&cfg, r)
			continue
		}
		rt := &router{
			Rule:     fmt.Sprintf("Host(`%s`)", r.Host),
			Service:  managedServiceID(r.Host),
			Priority: routePriority,
		}
		// Attach the forward-auth middleware by reference (the operator owns the
		// middleware definition). Only crenel's own router is written.
		if policy := r.Upstream.Auth; policy != "" && policy != model.AuthNone {
			rt.Middlewares = []string{d.traefikMiddleware(policy)}
		}
		cfg.HTTP.Routers[managedRouterID(r.Host)] = rt
		cfg.HTTP.Services[managedServiceID(r.Host)] = &service{
			LoadBalancer: loadBalancer{Servers: []serverURL{{URL: withScheme(r.Upstream.Address)}}},
		}
	}

	removeStaleDeny(&cfg) // structural default-deny is Traefik's native 404; drop any stale crenel-deny

	return d.write(cfg)
}

// addTCPPassthrough inserts a crenel-managed TCP router (HostSNI + tls.passthrough)
// and its TCP service — Traefik forwards the raw TLS connection without terminating
// it. Only crenel-tcp-* keys are touched; unmanaged TCP routers are preserved.
func addTCPPassthrough(cfg *dynamicConfig, r model.Route) {
	if cfg.TCP == nil {
		cfg.TCP = &tcpConfig{}
	}
	if cfg.TCP.Routers == nil {
		cfg.TCP.Routers = map[string]*tcpRouter{}
	}
	if cfg.TCP.Services == nil {
		cfg.TCP.Services = map[string]*tcpService{}
	}
	cfg.TCP.Routers[tcpRouterID(r.Host)] = &tcpRouter{
		Rule:    fmt.Sprintf("HostSNI(`%s`)", r.Host),
		Service: tcpServiceID(r.Host),
		TLS:     &tcpTLS{Passthrough: true},
	}
	cfg.TCP.Services[tcpServiceID(r.Host)] = &tcpService{
		LoadBalancer: tcpLoadBalancer{Servers: []tcpServer{{Address: r.Upstream.Address}}},
	}
}

// removeStaleDeny deletes any crenel-deny router+service left by an OLDER crenel that
// emitted an explicit catch-all deny. Bench gap T3: that deny was a service with an
// EMPTY loadBalancer (`{"loadBalancer":{}}`), which real Traefik REJECTS outright
// ("loadBalancer cannot be a standalone element") — so the WHOLE file failed to load
// and nothing routed. The structural default-deny does not need an explicit router:
// Traefik returns 404 for any host matching no router, which IS default-deny. crenel's
// invariant is upheld by (a) never writing a permissive catch-all and (b) normalize
// reporting DenyCatchAllPresent=false if some OTHER router forwards all hosts. Applying
// the fixed binary over a previously-broken file heals it by removing the stale deny.
func removeStaleDeny(cfg *dynamicConfig) {
	delete(cfg.HTTP.Routers, denyKey)
	delete(cfg.HTTP.Services, denyKey)
}

// validate mirrors the Traefik dynamic-config CONSTRAINTS that crenel's output must
// satisfy so a real file provider accepts it — the lesson the bench taught: the
// faithful fake must REJECT what real Traefik rejects. Today it enforces the rule
// crenel actually violated (T3): every HTTP service's loadBalancer must carry at least
// one server (an empty `loadBalancer: {}` is not a valid standalone service). crenel
// runs it on every WRITE, so a render that would be rejected live fails loudly here
// instead of silently producing a file Traefik drops.
func validate(cfg dynamicConfig) error {
	names := make([]string, 0, len(cfg.HTTP.Services))
	for name := range cfg.HTTP.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := cfg.HTTP.Services[name]
		if svc == nil {
			continue
		}
		if len(svc.LoadBalancer.Servers) == 0 {
			return fmt.Errorf("invalid Traefik config: http service %q has a loadBalancer with no servers — "+
				"real Traefik rejects this (\"loadBalancer cannot be a standalone element\") and drops the whole file", name)
		}
	}
	return nil
}

// Adopt re-keys each host's EXISTING unmanaged router/service to the crenel-*
// namespace, in-place — preserving rule, tls, middlewares, priority, and
// entryPoints verbatim (a router's key is an identifier, not behaviour). Only
// ownership changes. Idempotent: a host already under a crenel-* key (or with no
// matching unmanaged HTTP router) is skipped. Implements ports.Adopter. See
// USABILITY-DESIGN.md §A.
func (d *Driver) Adopt(ctx context.Context, hosts []string) error {
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	cfg, err := d.read()
	if err != nil {
		return fmt.Errorf("traefik adopt: read: %w", err)
	}
	// Find, per requested host, the unmanaged router that matches it via Host().
	for name, r := range cfg.HTTP.Routers {
		if r == nil || strings.HasPrefix(name, managedPrefix) {
			continue // already crenel-owned
		}
		var match string
		for _, h := range parseHosts(r.Rule) {
			if want[h] {
				match = h
				break
			}
		}
		if match == "" {
			continue
		}
		// Re-key the router+service into the crenel-* namespace, preserving the
		// router body verbatim except its Service pointer (which must follow the
		// re-keyed service). Unmanaged routers for other hosts are left untouched.
		newRouter := managedRouterID(match)
		newService := managedServiceID(match)
		if svc, ok := cfg.HTTP.Services[r.Service]; ok {
			cfg.HTTP.Services[newService] = svc
			delete(cfg.HTTP.Services, r.Service)
		}
		r.Service = newService
		cfg.HTTP.Routers[newRouter] = r
		delete(cfg.HTTP.Routers, name)
	}
	return d.write(cfg)
}

func (d *Driver) read() (dynamicConfig, error) {
	b, err := os.ReadFile(d.path)
	if err != nil {
		// A not-yet-created dynamic-config file is the BOOTSTRAP case: crenel is
		// pointed at a path it will create on the first write (the Traefik file
		// provider is configured to watch it). Treat a missing file like an empty
		// one (decode already maps ""/"null" -> empty config) so the first expose
		// can initialize the file, instead of hard-erroring "no such file". This
		// matches the Caddy driver bootstrapping from an empty admin config.
		// (Surfaced by the live proving-ground bench, gap T2/N5.)
		if os.IsNotExist(err) {
			return dynamicConfig{}, nil
		}
		return dynamicConfig{}, fmt.Errorf("read dynamic-config %s: %w", d.path, err)
	}
	cfg, err := decode(b)
	if err != nil {
		return dynamicConfig{}, fmt.Errorf("parse dynamic-config %s: %w", d.path, err)
	}
	return cfg, nil
}

func (d *Driver) write(cfg dynamicConfig) error {
	if err := validate(cfg); err != nil {
		return err
	}
	b, err := encode(cfg)
	if err != nil {
		return fmt.Errorf("encode dynamic-config: %w", err)
	}
	if err := os.WriteFile(d.path, b, 0o644); err != nil {
		return fmt.Errorf("write dynamic-config %s: %w", d.path, err)
	}
	return nil
}
