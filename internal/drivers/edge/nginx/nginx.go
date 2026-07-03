// Package nginx is a FOURTH EdgeProvider adapter — for an nginx config file — added
// to further validate the EdgeProvider port's breadth: Caddy (admin API), Traefik
// (JSON dynamic-config file), and NetBird (identity mesh) were the first three;
// nginx is another "dumb data-plane" edge but with a third config SHAPE again — the
// nginx brace DSL, with COMMENT-MARKER ownership rather than @id or key-prefix.
//
// Shape contrast (the point of a fourth driver):
//   - Caddy: HTTP admin API, reload can silently no-op (read-back-verify), wedgeable.
//   - Traefik: JSON dynamic-config file, additive by key prefix; no admin to wedge.
//   - nginx: a text config the daemon reads on reload; crenel does an additive
//     read-modify-write that REGENERATES only its own marker-tagged server blocks
//     and the default-deny, preserving every unmanaged server block verbatim. Like
//     Traefik it has no admin endpoint to wedge, so it does NOT implement
//     ports.HealthChecker — re-confirming that capability is genuinely optional.
//
// Invariant (every EdgeProvider): this driver ALWAYS renders and reports the
// catch-all default-deny. Apply always writes a `default_server` that returns 444;
// ReadLiveState reports DenyCatchAllPresent truthfully (false only if some server
// block matches ALL hosts — default_server / server_name _ — AND forwards to a real
// backend, i.e. a permissive catch-all).
package nginx

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// Driver implements ports.EdgeProvider against an nginx config file.
type Driver struct {
	path     string // path to the nginx config file crenel manages
	resolver ports.OriginResolver
	// authRequests maps a forward-auth policy NAME to its auth_request URI (an
	// internal location the operator defines), e.g. "authelia" -> "/authelia".
	// Missing entries fall back to the default convention "/<policy>". Injected at
	// cmd from config.AuthPolicies.
	authRequests map[string]string
	// tls controls how crenel's own server blocks listen/terminate TLS. Zero value =
	// HTTP on :80 (always loads). Operator-provided certs upgrade to `listen 443 ssl`.
	tls tlsConfig
	// runtime, when set, lets the driver make a write LIVE and CONFIRM it against the
	// running daemon (bench gaps N1/N2/N3): test (nginx -t) + reload on Apply, and an
	// HTTP probe on VerifyRuntime. Unset => writes are inert and runtime verify reports
	// "unavailable" (honest, never a false "verified").
	runtime *runtimeConfig
	// verifyDeadline/verifyInterval bound the runtime-verify probe POLL. `nginx -s
	// reload` is graceful (old workers drain), so a probe fired immediately can race the
	// worker cutover; we poll briefly for the expected state. Defaulted in New.
	verifyDeadline time.Duration
	verifyInterval time.Duration
}

// runtimeConfig is the operator-owned recipe for reaching the running nginx: how to
// validate + reload its config, and an HTTP base to probe a host through it. Commands
// are run verbatim via os/exec (the operator's choice, e.g. a `docker exec ... nginx`
// invocation), mirroring how the Caddy transport runs operator-declared exec chains.
type runtimeConfig struct {
	TestCmd      []string // e.g. ["docker","exec","nginx","nginx","-t"]; empty => skip validate
	ReloadCmd    []string // e.g. ["docker","exec","nginx","nginx","-s","reload"]; empty => skip reload
	ProbeBaseURL string   // e.g. "http://127.0.0.1:8081"; empty => no HTTP confirmation
}

// New builds an nginx driver bound to the config file at path.
func New(path string, resolver ports.OriginResolver, opts ...Option) *Driver {
	d := &Driver{path: path, resolver: resolver, verifyDeadline: 4 * time.Second, verifyInterval: 300 * time.Millisecond}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Option configures the Driver.
type Option func(*Driver)

// WithAuthRequests injects the policy-name -> auth_request URI map (from
// config.AuthPolicies). With no entry for a policy, crenel uses the default
// convention "/<policy>".
func WithAuthRequests(m map[string]string) Option {
	return func(d *Driver) { d.authRequests = m }
}

// WithTLS configures crenel's blocks to terminate TLS with the operator's cert on
// the given port. Without it crenel serves HTTP on :80 (a valid, loadable config).
func WithTLS(port int, certPath, keyPath string) Option {
	return func(d *Driver) {
		d.tls = tlsConfig{Port: port, SSL: true, CertPath: certPath, KeyPath: keyPath}
	}
}

// WithListenPort overrides the HTTP listen port for crenel's blocks (default 80),
// without TLS. Used when the edge fronts plain HTTP on a non-standard port.
func WithListenPort(port int) Option {
	return func(d *Driver) { d.tls.Port = port }
}

// WithRuntime wires the running-daemon surface so writes go LIVE and can be CONFIRMED:
// testCmd/reloadCmd validate+reload nginx on Apply, probeBaseURL HTTP-probes a host on
// VerifyRuntime. Any empty field disables that step.
func WithRuntime(testCmd, reloadCmd []string, probeBaseURL string) Option {
	return func(d *Driver) {
		d.runtime = &runtimeConfig{TestCmd: testCmd, ReloadCmd: reloadCmd, ProbeBaseURL: probeBaseURL}
	}
}

// nginxAuthURI returns the auth_request URI to emit for a policy (default
// convention "/<policy>").
func (d *Driver) nginxAuthURI(policy string) string {
	if uri := d.authRequests[policy]; uri != "" {
		return uri
	}
	return "/" + policy
}

// policyForAuthURI reverse-maps an auth_request URI back to its policy name: a
// configured reverse-map match, else the "/<policy>" convention inverse (strip the
// leading slash). Returns "" for an empty URI.
func (d *Driver) policyForAuthURI(uri string) string {
	if uri == "" {
		return ""
	}
	for policy, u := range d.authRequests {
		if u == uri {
			return policy
		}
	}
	return strings.TrimPrefix(uri, "/")
}

func (d *Driver) Name() string { return "nginx" }

// Validate confirms the config file is readable (a not-yet-created file is the
// bootstrap case and is accepted — see read()).
func (d *Driver) Validate(ctx context.Context) error {
	_, err := os.ReadFile(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read nginx config %s: %w", d.path, err)
	}
	return nil
}

// ReadLiveState parses the config file and normalizes it.
//
// LIVE-STATE CAVEAT (same strain as Traefik's file provider): the file is the
// DESIRED config nginx reads on `nginx -s reload`, not a live read of the running
// process. A production-grade driver would also confirm via `nginx -t` / the stub
// status, or treat the file as authoritative only after a successful reload. Against
// the fake (a file), file == live.
func (d *Driver) ReadLiveState(ctx context.Context) (model.LiveEdgeState, error) {
	text, err := d.read()
	if err != nil {
		return model.LiveEdgeState{}, err
	}
	return d.normalize(text), nil
}

// normalize walks the parsed config into a LiveEdgeState.
func (d *Driver) normalize(text string) model.LiveEdgeState {
	state := model.LiveEdgeState{Raw: text}
	// Per-port default-deny model (bench gap N4): nginx serves an unmatched host from
	// the IMPLICIT default server — the first server block on that listen port — unless
	// an explicit non-forwarding default_server denies it. So default-deny is judged
	// PER PORT: a port that has a forwarding server but no denying default_server leaks
	// unmatched hosts to that forwarding server (what the bench saw: an unmatched host
	// returned 200 via the only :80 vhost while crenel wrongly claimed ENFORCED).
	forwardingPorts := map[int]bool{} // ports with a server that proxies traffic
	denyPorts := map[int]bool{}       // ports with a non-forwarding default_server (a deny)
	permissiveCatchAll := false       // an explicit default_server / server_name _ that FORWARDS
	for _, c := range parseChunks(text) {
		if !c.isServer {
			continue
		}
		if c.catchAll {
			// A catch-all server (default_server / server_name _). If it FORWARDS it is a
			// permissive catch-all (fail-open). If not, it is a deny default (e.g. crenel's
			// `return 444`) and certifies default-deny FOR ITS LISTEN PORT(S).
			if c.forwards {
				permissiveCatchAll = true
				for _, p := range portsOf(c) {
					forwardingPorts[p] = true
				}
			} else {
				for _, p := range portsOf(c) {
					denyPorts[p] = true
				}
			}
			continue
		}
		if c.host == "" {
			// No usable server_name and not a catch-all. If it nonetheless PROXIES
			// somewhere, it forwards traffic crenel cannot attribute to a host — a real
			// exposure blind spot — so declare it unknown rather than drop it silently.
			// A host-less block that forwards nothing (a redirect/static/return server)
			// exposes no backend, so it is left unflagged (avoids noise on common
			// HTTP→HTTPS redirect servers).
			if c.forwards {
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: "server (no server_name)", Kind: model.UnknownMatcher,
					Reason:     "server block proxies traffic but has no server_name crenel can attribute it to",
					RawExcerpt: boundedExcerpt(c.raw),
				})
			}
			continue
		}
		if !c.forwards {
			// A vhost crenel can see (server_name) but that does NOT reverse-proxy — it
			// serves content some way crenel does not model (static root, fastcgi,
			// return/redirect). DECLARE its effective exposure unknown rather than drop
			// it silently (detect-and-declare-unknown, register §4).
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: "server " + c.host, Kind: model.UnknownHandler,
				Reason:     fmt.Sprintf("server block for %s has no proxy_pass crenel can model (non-reverse-proxy vhost)", c.host),
				RawExcerpt: boundedExcerpt(c.raw),
			})
			continue
		}
		if c.pathScoped {
			// A vhost that routes by location PATH (several proxying locations, or a single
			// non-root one) cannot be represented at host granularity: reading it as
			// host->firstBackend would silently drop the other paths (and could merge two
			// paths' distinct backends/auth). DECLARE it matcher_conditional (register §4 —
			// the Caddy/Traefik path-matcher analogue). Full path-granular MODELING is P5.
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: "server " + c.host, Kind: model.UnknownMatcher,
				Reason: fmt.Sprintf("server block for %s routes by location path(s) crenel does not model (%s) — path-granular routing is not represented at host granularity",
					c.host, strings.Join(c.extraPaths, ", ")),
				RawExcerpt: boundedExcerpt(c.raw),
			})
			continue
		}
		// auth_request recognition: a crenel-managed block round-trips its policy via
		// the URI; an unmanaged block's auth_request surfaces as "(detected)".
		auth := ""
		if c.authURI != "" {
			if c.managed {
				auth = d.policyForAuthURI(c.authURI)
			} else {
				auth = model.AuthDetected
			}
		}
		for _, p := range portsOf(c) {
			forwardingPorts[p] = true // a host vhost that proxies on this port
		}
		state.Routes = append(state.Routes, model.Route{
			Host:      c.host,
			Managed:   c.managed, // the `# crenel-managed:` comment marker
			Ownership: model.OwnershipFromMarker(c.managed),
			Upstream: model.Upstream{
				Kind:       model.ForwardToOrigin,
				Mode:       model.ModeHTTPProxy,
				Address:    c.addr,
				ServerName: c.host,
				Auth:       auth,
			},
		})
	}
	// Default-deny is enforced iff (a) no permissive forwarding catch-all exists AND
	// (b) every port that serves traffic has a denying default_server covering it — so
	// no port leaks unmatched hosts to its implicit default server.
	state.DenyCatchAllPresent = !permissiveCatchAll
	for p := range forwardingPorts {
		if !denyPorts[p] {
			state.DenyCatchAllPresent = false
			break
		}
	}
	// Foreign-ownership detection (P2): if this config is generated by another tool
	// (e.g. Nginx Proxy Manager regenerating from its DB), mark the edge + every route
	// foreign-managed. crenel can still READ it (understanding ≠ ownership), but the
	// refuse-to-manage gate will block any mutation — a crenel edit would be reverted
	// on the generator's next save. See TOPOLOGY-RISK-REGISTER §3.3/§4.6.
	if g := detectGenerator(text); g != "" {
		state.Generator = g
		for i := range state.Routes {
			state.Routes[i].Ownership = model.OwnForeign
			state.Routes[i].Managed = false
		}
	}
	// Durability: nginx is a FILE provider — crenel writes the same config the server
	// boots from (read-modify-write of the managed file), so a mutation is already
	// durable across a restart with no separate persist step.
	state.Persistence = model.PersistDurableConfig
	return state
}

// Plan computes the ChangeSet to realize op against live — identical in shape to
// the Caddy/Traefik drivers (the port's Plan contract is edge-agnostic). It never
// sets NewPublic (core owns that). nginx here is an HTTP reverse-proxy edge; it
// refuses passthrough and mesh-grant LOUDLY rather than approximate. (SNI
// passthrough via nginx's stream/ssl_preread module is a plausible future
// capability-gated extension, mirroring the Caddy layer4 gate.)
func (d *Driver) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true // default-deny is always rendered

	if op.Mode != model.ModeHTTPProxy {
		return cs, fmt.Errorf("%w: nginx (this driver) terminates TLS and reverse-proxies http only (got %s) — "+
			"it does not render SNI passthrough (would need the stream/ssl_preread module) or identity-mesh grants",
			model.ErrModeUnsupported, op.Mode)
	}

	switch op.Verb {
	case model.Expose:
		if op.Host == "" {
			return cs, fmt.Errorf("nginx plan: expose requires a host")
		}
		if live.HasHost(op.Host) {
			return cs, nil // already exposed => no-op
		}
		addr := op.To
		if addr == "" {
			resolved, err := d.resolver.Resolve(op.Service)
			if err != nil {
				return cs, fmt.Errorf("nginx plan: %w", err)
			}
			addr = resolved
		}
		cs.Edge.AddRoutes = []model.Route{{
			Host: op.Host,
			Upstream: model.Upstream{
				Kind:       model.ForwardToOrigin,
				Mode:       model.ModeHTTPProxy,
				Address:    addr,
				ServerName: op.Host,
				Auth:       op.Auth,
			},
		}}
	case model.Unexpose:
		if op.Host == "" {
			return cs, fmt.Errorf("nginx plan: unexpose requires a host")
		}
		if !live.HasHost(op.Host) {
			return cs, nil // not exposed => no-op
		}
		cs.Edge.RemoveHosts = []string{op.Host}
	default:
		return cs, fmt.Errorf("nginx plan: unknown verb %q", op.Verb)
	}
	return cs, nil
}

// Apply realizes the edge change with an ADDITIVE read-modify-write of the config
// file: it parses the file, keeps every UNMANAGED chunk verbatim, rebuilds the set
// of crenel-managed server blocks (applying the add/remove), always (re)renders the
// default-deny, and writes the file back. Unmanaged server blocks (Authelia,
// other vhosts) survive byte-for-byte in structure.
//
// As with every EdgeProvider, a successful return is NOT proof: core
// read-back-verifies via a second ReadLiveState.
func (d *Driver) Apply(ctx context.Context, cs model.ChangeSet) error {
	text, err := d.read()
	if err != nil {
		return fmt.Errorf("nginx apply: read: %w", err)
	}
	chunks := parseChunks(text)

	var unmanaged []string
	managed := map[string]model.Route{}
	for _, c := range chunks {
		switch {
		case c.isServer && c.isDeny:
			// drop — re-rendered below
		case c.isServer && c.managed:
			if c.host != "" {
				// Carry the existing route's auth policy so a re-render of OTHER hosts
				// preserves this host's auth_request reference.
				managed[c.host] = model.Route{
					Host:     c.host,
					Upstream: model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: c.addr, ServerName: c.host, Auth: d.policyForAuthURI(c.authURI)},
				}
			}
		default:
			unmanaged = append(unmanaged, c.raw) // preserved verbatim
		}
	}

	// Removes before adds (a mode re-render carries the same host in both).
	for _, h := range cs.Edge.RemoveHosts {
		delete(managed, h)
	}
	for _, r := range cs.Edge.AddRoutes {
		managed[r.Host] = r
	}

	routes := make([]model.Route, 0, len(managed))
	for _, r := range managed {
		routes = append(routes, r)
	}
	if err := d.write(renderConfig(unmanaged, routes, d.nginxAuthURI, d.tls)); err != nil {
		return err
	}
	// Make the write LIVE (bench gap N3: a file write is INERT until nginx reloads).
	// Validate first so an invalid render (bench gap N1: the old `listen 443 ssl` with
	// no cert) FAILS Apply and rolls back, instead of silently leaving stale config.
	if d.runtime != nil {
		if out, err := d.runtime.run(ctx, d.runtime.TestCmd); err != nil {
			return fmt.Errorf("nginx apply: config test (nginx -t) failed — written config is invalid, NOT reloaded: %w%s", err, tail(out))
		}
		if _, err := d.runtime.run(ctx, d.runtime.ReloadCmd); err != nil {
			return fmt.Errorf("nginx apply: reload failed: %w", err)
		}
	}
	return nil
}

// denyProbeHost is a synthetic host that matches NO server_name, used to confirm the
// default-deny is live: a correctly-reloaded crenel config denies it (444/closed). The
// `.invalid` TLD (RFC 2606) is guaranteed never to be a real vhost.
const denyProbeHost = "crenel-runtime-verify.invalid"

// VerifyRuntime probes the RUNNING nginx (not crenel's written file) to confirm op's
// change is actually live, implementing ports.RuntimeVerifier (bench gap N2/T4). With a
// probe URL configured it HTTP-requests, THROUGH nginx: (1) each affected host — served
// after expose / denied after unexpose — and (2) a synthetic UNMATCHED host that must be
// DENIED. The deny probe does double duty: it verifies the default-deny invariant is
// live at runtime (bench gap N4), AND it discriminates the NEW config from a stale
// graceful-reload worker still running an old FAIL-OPEN config (where every host,
// including the one being exposed, answers 200 via an implicit default server — the race
// the bench caught). Without a runtime surface it reports Unavailable (honest, never a
// false "verified").
func (d *Driver) VerifyRuntime(ctx context.Context, op model.Op, ec model.EdgeChange) model.RuntimeVerification {
	if d.runtime == nil || d.runtime.ProbeBaseURL == "" {
		return model.RuntimeVerification{
			Status: model.RuntimeVerifyUnavailable,
			Detail: "no nginx runtime surface configured — set the edge's nginx reload+probe (test/reload command + probe URL) to confirm the daemon accepted the write and reloaded",
		}
	}
	// Build the probe checks: each affected host (served iff expose) + the deny probe.
	type check struct {
		host       string
		wantServed bool
	}
	var checks []check
	for _, h := range affectedHosts(ec) {
		checks = append(checks, check{host: h, wantServed: op.Verb == model.Expose})
	}
	checks = append(checks, check{host: denyProbeHost, wantServed: false})

	// `nginx -s reload` is GRACEFUL (old workers drain while new ones take over), so a
	// probe fired immediately can race the cutover. Poll each check for its EXPECTED
	// state rather than trusting the first probe; fail only if unconverged by deadline.
	interval := d.verifyInterval
	if interval <= 0 {
		interval = 300 * time.Millisecond
	}
	for _, c := range checks {
		var lastCode int
		var lastErr error
		converged := false
		for waited := time.Duration(0); ; waited += interval {
			served, code, err := d.runtime.probeHost(ctx, c.host)
			lastCode, lastErr = code, err
			if err == nil && served == c.wantServed {
				converged = true
				break
			}
			if waited >= d.verifyDeadline {
				break
			}
			select {
			case <-ctx.Done():
				return model.RuntimeVerification{Status: model.RuntimeVerifyFailed, Detail: fmt.Sprintf("context cancelled probing %s: %v", c.host, ctx.Err())}
			case <-time.After(interval):
			}
		}
		if !converged {
			return model.RuntimeVerification{Status: model.RuntimeVerifyFailed, Detail: probeFailDetail(c.host, c.wantServed, lastCode, lastErr)}
		}
	}
	return model.RuntimeVerification{
		Status: model.RuntimeVerifyConfirmed,
		Detail: fmt.Sprintf("nginx -t passed, reloaded, and probed the running daemon (routes + default-deny live for %s)", strings.Join(affectedHosts(ec), ", ")),
	}
}

// probeFailDetail renders a precise reason a runtime probe did not converge.
func probeFailDetail(host string, wantServed bool, code int, err error) string {
	if err != nil {
		return fmt.Sprintf("probe of %s failed: %v", host, err)
	}
	if host == denyProbeHost {
		return fmt.Sprintf("default-deny is NOT live — nginx served an unmatched host (HTTP %d) instead of denying it; the reload did not take effect or a permissive catch-all shadows the deny", code)
	}
	if wantServed {
		return fmt.Sprintf("nginx did not serve %s after reload (HTTP %d) — route not live", host, code)
	}
	return fmt.Sprintf("nginx still serves %s after unexpose (HTTP %d)", host, code)
}

// Adopt stamps the `# crenel-managed:` comment marker onto the EXISTING unmanaged
// server block for each host, in-place, preserving the block body verbatim — only
// ownership changes. Idempotent: a host already managed (or with no matching
// unmanaged block) is skipped. Unmanaged blocks for hosts not in the list are
// untouched. Implements ports.Adopter (brownfield import). See USABILITY-DESIGN.md §A.
func (d *Driver) Adopt(ctx context.Context, hosts []string) error {
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	text, err := d.read()
	if err != nil {
		return fmt.Errorf("nginx adopt: read: %w", err)
	}
	var b strings.Builder
	for i, raw := range splitTopLevel(text) {
		if i > 0 {
			b.WriteString("\n")
		}
		c := classify(raw)
		// Stamp only an UNMANAGED, non-deny server block whose host was requested.
		if c.isServer && !c.managed && !c.isDeny && c.host != "" && want[c.host] {
			b.WriteString(managedMarker + " " + c.host + "\n")
		}
		b.WriteString(strings.Trim(raw, "\n"))
		b.WriteString("\n")
	}
	return d.write(b.String())
}

func (d *Driver) read() (string, error) {
	b, err := os.ReadFile(d.path)
	if err != nil {
		// BOOTSTRAP: a missing config file is treated as empty so the first expose
		// can create it (write() below uses os.WriteFile, which creates the file),
		// rather than hard-erroring "no such file". An empty config parses to no
		// managed/unmanaged blocks; the first apply renders crenel's blocks + deny.
		// (Surfaced by the live proving-ground bench, gap T2/N5.)
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read nginx config %s: %w", d.path, err)
	}
	return string(b), nil
}

func (d *Driver) write(text string) error {
	if err := os.WriteFile(d.path, []byte(text), 0o644); err != nil {
		return fmt.Errorf("write nginx config %s: %w", d.path, err)
	}
	return nil
}
