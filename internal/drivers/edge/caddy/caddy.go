// Package caddy is an EdgeProvider adapter for the Caddy reverse proxy, driven
// through its admin API.
//
// Invariant: this driver ALWAYS renders and reports the catch-all default-deny.
// ReadLiveState sets DenyCatchAllPresent truthfully from the live config, and
// renderCaddyfile always emits the deny block, so Apply can never drop it.
//
// CRITICAL footgun modeled here: a 200 from POST /load is NOT proof the running
// config changed (Caddy can silently no-op a reload). Read-back verification is
// performed by core via a second ReadLiveState; this driver additionally
// re-reads inside Apply as a first line of defense.
package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/drivers/transport"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// Default per-operation timeouts. Reads are quick; WRITES (POST /load and every
// granular /config/ mutation) trigger a FULL Caddy reload that re-provisions all
// apps — on a Cloudflare DNS-01 build that re-reads the cert cache and can take
// tens of seconds — so the write budget is generous. Both are bounded: crenel
// must NEVER hang on a slow or wedged admin API (the failure that wedged the live
// edge and hung the prior session). See POSTMORTEM.md.
const (
	defaultReadTimeout   = 10 * time.Second
	defaultWriteTimeout  = 60 * time.Second
	defaultHealthTimeout = 5 * time.Second
)

// ErrAdminUnresponsive signals that an admin-API call exceeded its bounded
// timeout — the endpoint is slow or wedged (e.g. stuck mid-reload). Callers can
// test for it with IsUnresponsive to report cleanly and avoid piling more
// reloads onto a wedged admin server.
var ErrAdminUnresponsive = errors.New("caddy admin API unresponsive (bounded timeout exceeded)")

// IsUnresponsive reports whether err is (or wraps) ErrAdminUnresponsive.
func IsUnresponsive(err error) bool { return errors.Is(err, ErrAdminUnresponsive) }

// Driver implements ports.EdgeProvider against a Caddy admin API.
type Driver struct {
	server   string // managed server key, e.g. "srv0"
	resolver ports.OriginResolver
	hc       *http.Client    // applied to the default Direct transport (WithHTTPClient)
	xport    ports.Transport // HOW admin calls physically travel (default: Direct to admin_url)
	granular bool            // additive apply via structured admin API vs full POST /load
	layer4   bool            // edge has the caddy-l4 plugin: render ModeTCPPassthrough via it

	readTimeout  time.Duration // bound for GET /config/ (reads)
	writeTimeout time.Duration // bound for /load and granular /config/ mutations

	// persistPath, when set, enables on-disk persistence (ports.Persister): the
	// managed routes are additively mirrored into this Caddyfile after a verified
	// apply. caddyCLI is the injected validate/reload seam (default OSCaddyCLI).
	persistPath string
	caddyCLI    CaddyCLI

	// persistenceDeclared, when set, is an operator OVERRIDE of the edge's durability
	// posture (model.PersistenceModel) — e.g. "resume" to declare the control plane
	// boots with `--resume` (admin writes autosave), or "durable-file" to assert an
	// out-of-band persist. The admin API carries NO boot-source marker, so durability is
	// declared, never inferred; absent a declaration the driver defaults to durable-file
	// when a persist path is configured, else ephemeral-admin (the safe default). See
	// persistenceModel and model.PersistenceModel.
	persistenceDeclared model.PersistenceModel

	// configStore reads/writes the on-disk BOOT config for the durable reconciler
	// (default: local FS at persistPath; a remote ssh-exec edge injects a transport-
	// backed store). adapter is the `caddy adapt` cross-check seam (nil => skip the
	// re-adaptation read-back). Both are used only by the wildcard-site durable reconcile
	// (persist_caddyfile.go).
	configStore ConfigStore
	adapter     Adapter

	// authPolicies maps a forward-auth policy NAME to its Caddy reference (a Caddyfile
	// snippet to `import`, or a forward_auth endpoint). Empty/missing entries fall
	// back to the default convention (snippet == policy name). Injected at cmd from
	// config.AuthPolicies. See AUTH-DESIGN.md §2.
	authPolicies map[string]AuthRef

	// generator, when set, is an operator-DECLARED config generator that owns this
	// edge (e.g. "caddy-docker-proxy"). It is the robust fallback for a generator the
	// admin API carries no marker for: the operator tells crenel "this edge is owned
	// by X", so the refuse-to-manage gate engages edge-wide. See ReadLiveState.
	generator string
	// generatorConfigPath, when set, is a path to an on-disk config artifact crenel
	// scans to DETECT a generator (e.g. caddy-docker-proxy's `Caddyfile.autosave`).
	// The admin API itself carries no CDP marker (verified against CDP docs), so this
	// mounted-file signal is what makes auto-detection possible. See detectGeneratorFile.
	generatorConfigPath string
}

// AuthRef is the Caddy-side reference for one forward-auth policy. crenel emits only
// the reference; the operator owns the auth backend (its verify URI, headers, cookies).
// Three rendering inputs, each auth-by-reference:
//   - Import: a Caddyfile snippet name to `import` — the on-disk PERSISTENCE path only
//     (the admin API has no representation of a Caddyfile snippet).
//   - Handler: an operator-provided VERBATIM Caddy JSON handler object — the granular
//     admin-API path, purest by-reference (crenel inserts it unchanged, owning none of
//     the provider's internals). Recommended for reproducing a known-good block.
//   - ForwardAuth (+ VerifyURI, CopyHeaders): an authorizer endpoint crenel expands to
//     the CANONICAL reverse_proxy+handle_response gate Caddy's `forward_auth` directive
//     compiles to — the exact accepted shape the home edge uses. The verify URI and
//     copy-headers are operator-declared, not invented by crenel.
type AuthRef struct {
	Import      string          // Caddyfile snippet name (default: the policy name) — persistence path
	ForwardAuth string          // authorizer endpoint, e.g. "authelia:9080" — canonical-expansion granular path
	VerifyURI   string          // verify path incl. ?rd=…, e.g. "/api/verify?rd=https://auth.example.com"
	CopyHeaders []string        // auth headers copied on a 2xx (Remote-User, Remote-Groups, Remote-Name, Remote-Email)
	Handler     json.RawMessage // operator-provided VERBATIM handler JSON — purest by-reference escape hatch
}

// WithAuthPolicies injects the policy-name -> Caddy reference map (from
// config.AuthPolicies). With no entry for a policy, crenel uses the default
// convention: `import <policy>` (and snippet name == policy).
func WithAuthPolicies(m map[string]AuthRef) Option {
	return func(d *Driver) { d.authPolicies = m }
}

// authRef returns the Caddy reference for a policy, applying the default
// convention (snippet == policy) when nothing is configured.
func (d *Driver) authRef(policy string) AuthRef {
	ref := d.authPolicies[policy]
	if ref.Import == "" && ref.ForwardAuth == "" {
		ref.Import = policy
	}
	return ref
}

// authSnippet returns the Caddyfile snippet name to `import` for a policy (the
// on-disk persistence form). Defaults to the policy name.
func (d *Driver) authSnippet(policy string) string {
	if ref := d.authPolicies[policy]; ref.Import != "" {
		return ref.Import
	}
	return policy
}

// authMarker is crenel's policy-name MARKER handler: a `vars` handler carrying the
// policy. Real Caddy PRESERVES a vars handler's arbitrary keys on read-back (unlike a
// reverse_proxy's unknown fields, which it drops on normalize), so the policy NAME
// round-trips off a real edge — letting status/audit show "auth: <policy>" for a
// managed route rather than the lossy "(detected)". It is a valid, harmless handler
// (sets an unused request var); detectAuth recovers the name from it.
func authMarker(policy string) map[string]any {
	return map[string]any{"handler": handlerVars, "crenel_policy": policy}
}

// authGate returns the VALID Caddy forward-auth GATE handler for a policy, and whether
// one can be rendered on the granular admin-API path. Two by-reference shapes:
//   - VERBATIM (ref.Handler set): the operator's exact handler JSON inserted unchanged
//     (crenel owns NONE of the provider's internals — the purest by-reference).
//   - CANONICAL (ref.ForwardAuth set): crenel expands the operator-declared endpoint +
//     verify URI + copy-headers into the reverse_proxy+handle_response shape Caddy's
//     `forward_auth` directive compiles to (the exact accepted home-edge form).
//
// Returns ok=false for a snippet-only / default policy: the admin API has NO
// representation of a Caddyfile `import`, so the granular path cannot render valid JSON
// and Plan refuses loudly rather than emit a handler Caddy can't load (the bug the live
// trial caught). The snippet still renders on the on-disk persistence path.
func (d *Driver) authGate(policy string) (map[string]any, bool) {
	ref := d.authRef(policy)
	if len(ref.Handler) > 0 {
		var h map[string]any
		if json.Unmarshal(ref.Handler, &h) == nil && h["handler"] != nil {
			return h, true
		}
	}
	if ref.ForwardAuth != "" {
		return canonicalForwardAuth(ref), true
	}
	return nil, false
}

// canonicalForwardAuth renders the reverse_proxy+handle_response shape Caddy's
// `forward_auth <endpoint>` directive compiles to — the EXACT accepted form the real
// home edge uses (verified byte-for-byte against the live backup). The authorizer
// endpoint, verify URI, and copy-headers are all OPERATOR-DECLARED (via AuthRef), so the
// auth-by-reference boundary holds: crenel renders the operator's declared reference, it
// does not model Authelia's internals. On a 2xx from the authorizer the declared headers
// are copied into the request and the chain continues to the backend; any other status
// returns the authorizer's response (the 302 challenge) — reverse_proxy's handle_response
// default.
func canonicalForwardAuth(ref AuthRef) map[string]any {
	rewrite := map[string]any{"method": "GET"}
	if ref.VerifyURI != "" {
		rewrite["uri"] = ref.VerifyURI
	}
	// The leading empty `vars` route is part of Caddy's own forward_auth expansion.
	sub := []any{map[string]any{"handle": []any{map[string]any{"handler": handlerVars}}}}
	for _, hdr := range ref.CopyHeaders {
		sub = append(sub, copyHeaderDelete(hdr), copyHeaderSet(hdr))
	}
	return map[string]any{
		"handler":   handlerReverseProxy,
		"upstreams": []any{map[string]any{"dial": ref.ForwardAuth}},
		"rewrite":   rewrite,
		"headers": map[string]any{"request": map[string]any{"set": map[string]any{
			"X-Forwarded-Method": []any{"{http.request.method}"},
			"X-Forwarded-Uri":    []any{"{http.request.uri}"},
		}}},
		"handle_response": []any{map[string]any{
			"match":  map[string]any{"status_code": []any{2}},
			"routes": sub,
		}},
	}
}

// copyHeaderDelete / copyHeaderSet render one declared copy-header as Caddy's
// forward_auth `copy_headers` expansion does: first delete the inbound header, then set
// it from the authorizer's response header when that response header is non-empty.
func copyHeaderDelete(h string) map[string]any {
	return map[string]any{"handle": []any{map[string]any{
		"handler": handlerHeaders,
		"request": map[string]any{"delete": []any{h}},
	}}}
}

func copyHeaderSet(h string) map[string]any {
	upstreamVar := "{http.reverse_proxy.header." + h + "}"
	return map[string]any{
		"handle": []any{map[string]any{
			"handler": handlerHeaders,
			"request": map[string]any{"set": map[string]any{h: []any{upstreamVar}}},
		}},
		"match": []any{map[string]any{"not": []any{map[string]any{
			"vars": map[string]any{upstreamVar: []any{""}},
		}}}},
	}
}

// Option configures the Driver.
type Option func(*Driver)

// WithServer overrides the managed server key (default "srv0").
func WithServer(name string) Option { return func(d *Driver) { d.server = name } }

// WithHTTPClient overrides the HTTP client used by the default Direct transport
// (e.g. shorter timeouts in tests). Ignored when WithTransport injects a non-Direct
// transport (that transport owns its own client/channel).
func WithHTTPClient(hc *http.Client) Option { return func(d *Driver) { d.hc = hc } }

// WithTransport injects the channel the driver uses to reach the admin API,
// replacing the default Direct-HTTP-to-admin_url transport. This is how an edge is
// reached via ssh-exec (a nested-exec curl against a loopback admin) or an
// ssh-tunnel (a crenel-managed local forward) instead of a published HTTP endpoint.
// The driver makes the SAME admin calls; only how they travel changes. Wired at cmd.
func WithTransport(t ports.Transport) Option { return func(d *Driver) { d.xport = t } }

// WithGranularApply switches Apply from the full-config `POST /load` replace to
// ADDITIVE operations against Caddy's structured admin API: each exposed route
// is inserted individually (tagged with an @id) and removed by that @id. This
// is the production-safe mode — it never rewrites routes Crenel does not manage
// (Authelia snippets, TLS/cert config, other vendors' routes are untouched).
//
// Note: granular ops are ADDITIVE but NOT lighter than POST /load — Caddy
// regenerates and reloads the WHOLE config on every /config/ mutation. So each
// granular op is a full reload; crenel settles (re-checks health) between ops to
// avoid the back-to-back reload storm that wedged the live edge.
func WithGranularApply() Option { return func(d *Driver) { d.granular = true } }

// WithGenerator DECLARES that this Caddy edge is generated/owned by the named tool
// (e.g. "caddy-docker-proxy"). It is the operator's explicit hint for a generator the
// admin API carries no detectable marker for: with it set, normalize marks the edge +
// every route foreign so the refuse-to-manage gate blocks any mutation (a crenel edit
// would be reverted on the generator's next regeneration). Manage such an edge at its
// source (the Docker labels / the generator's own config).
func WithGenerator(name string) Option { return func(d *Driver) { d.generator = name } }

// WithGeneratorConfigPath points crenel at an on-disk config artifact to SCAN for a
// generator signature — specifically caddy-docker-proxy's `Caddyfile.autosave` (the
// generated Caddyfile CDP writes into Caddy's config dir). The admin API itself
// carries no CDP marker, so this mounted-file signal is what makes auto-detection
// possible. When the file is present and matches, the edge reads foreign (gate
// refuses). When absent/unreadable, detection simply does not fire — CDP routes then
// fall back to the P0 unknown net (read-only-safe, but mutable-looking; see DESIGN).
func WithGeneratorConfigPath(path string) Option {
	return func(d *Driver) { d.generatorConfigPath = path }
}

// WithLayer4 declares that this edge was built with the caddy-l4 plugin
// (github.com/mholt/caddy-l4), so Crenel can render ModeTCPPassthrough via the
// `layer4` app (SNI match → raw-TCP proxy, no TLS termination). It is a CAPABILITY
// gate: without it, Plan refuses passthrough LOUDLY rather than emit config a
// stock Caddy would reject. Passthrough rendering is additive (it touches only the
// crenel-l4 server's @id-tagged routes) and requires granular apply so it does not
// disturb the http routes / deny / TLS.
func WithLayer4() Option { return func(d *Driver) { d.layer4 = true } }

// WithTimeouts overrides the per-operation read and write timeouts. A zero value
// leaves the corresponding default in place. These bound EVERY admin call so the
// driver can never hang on a slow or wedged admin API.
func WithTimeouts(read, write time.Duration) Option {
	return func(d *Driver) {
		if read > 0 {
			d.readTimeout = read
		}
		if write > 0 {
			d.writeTimeout = write
		}
	}
}

// New builds a Caddy driver pointed at baseURL (e.g. "http://127.0.0.1:2019").
// By default it reaches that URL via a Direct (real-HTTP) transport — zero behavior
// change for any edge configured with just an admin_url. WithTransport overrides HOW
// the admin calls travel (ssh-exec / ssh-tunnel) without changing what they are.
func New(baseURL string, resolver ports.OriginResolver, opts ...Option) *Driver {
	d := &Driver{
		server:   defaultManagedServer,
		resolver: resolver,
		// No client-level Timeout: each call is bounded by a per-operation context
		// deadline (read/write/health) instead, so we get precise, classifiable
		// timeouts rather than one blunt cap.
		hc:           &http.Client{},
		readTimeout:  defaultReadTimeout,
		writeTimeout: defaultWriteTimeout,
	}
	for _, o := range opts {
		o(d)
	}
	// Default transport: Direct HTTP to baseURL (carrying any WithHTTPClient override).
	// An injected WithTransport wins. The per-op timeout + wedge classification stay in
	// doAdmin (above the transport), so they apply uniformly to every transport.
	if d.xport == nil {
		d.xport = transport.NewDirectWithClient(baseURL, d.hc)
	}
	return d
}

// healthTimeout is the bound for a quick liveness probe — short, but never longer
// than the read budget (so tiny test timeouts still apply).
func (d *Driver) healthTimeout() time.Duration {
	if d.readTimeout > 0 && d.readTimeout < defaultHealthTimeout {
		return d.readTimeout
	}
	return defaultHealthTimeout
}

func (d *Driver) Name() string { return "caddy" }

// Validate confirms the admin API is reachable and returns parseable config.
func (d *Driver) Validate(ctx context.Context) error {
	_, err := d.fetchConfig(ctx)
	return err
}

// Healthy performs a quick, tightly-bounded liveness probe of the admin API
// (GET /config/). It returns ErrAdminUnresponsive if the endpoint does not answer
// within the health budget — the signal that the admin server is wedged
// (e.g. stuck mid-reload). It satisfies ports.HealthChecker so core can decide
// NOT to fire compensating reloads into a wedged admin server.
func (d *Driver) Healthy(ctx context.Context) error {
	status, _, err := d.doAdmin(ctx, http.MethodGet, "/config/", "", nil, d.healthTimeout())
	if err != nil {
		return fmt.Errorf("caddy health probe: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("caddy health probe: GET /config/ returned %d", status)
	}
	return nil
}

// settle re-checks admin health AFTER a mutation. Every /config/ write triggers a
// full Caddy reload; firing the next one before the admin endpoint has recovered
// is exactly the back-to-back reload storm that wedged the live edge. settle also
// doubles as the post-apply health re-check.
func (d *Driver) settle(ctx context.Context) error { return d.Healthy(ctx) }

// ReadLiveState reads GET /config/ and normalizes it into LiveEdgeState. It
// always reports DenyCatchAllPresent based on what the live config actually
// contains.
func (d *Driver) ReadLiveState(ctx context.Context) (model.LiveEdgeState, error) {
	cfg, raw, err := d.fetchConfigRaw(ctx)
	if err != nil {
		return model.LiveEdgeState{}, err
	}
	state := normalize(cfg, d.server, raw)
	d.applyGeneratorOwnership(&state)
	state.Persistence = d.persistenceModel()
	return state, nil
}

// persistenceModel computes the edge's DECLARED durability posture (model.Persistence
// Model) — surfaced by status/audit and reported via ports.DurabilityReporter so the
// write path can warn on an ephemeral edge. The admin API exposes no boot-source marker
// (a `GET /config/` cannot reveal whether Caddy booted from a Caddyfile, a JSON file, or
// `--resume`), so the model is declared, never inferred from the wire:
//   - an explicit operator declaration (WithPersistenceModel) wins (e.g. "resume");
//   - else a configured durable persist path => durable-file (crenel reconciles the
//     on-disk boot config after each verified apply);
//   - else ephemeral-admin — the SAFE DEFAULT for a bare Caddy admin edge: admin-API
//     writes are in-memory and a restart drops them, and crenel must never assume durable.
func (d *Driver) persistenceModel() model.PersistenceModel {
	if d.persistenceDeclared != "" {
		return d.persistenceDeclared
	}
	if d.persistPath != "" {
		return model.PersistDurableFile
	}
	return model.PersistEphemeralAdmin
}

// PersistenceModel implements ports.DurabilityReporter: it declares whether a write to
// this edge survives a control-plane restart. core consults it on the write path to warn
// when a verified write lands on an ephemeral edge. Config-derived, cheap, never mutates.
func (d *Driver) PersistenceModel() model.PersistenceModel { return d.persistenceModel() }

// applyGeneratorOwnership marks the whole edge FOREIGN when a config generator is
// detected (caddy-docker-proxy via its on-disk autosave file, or an operator-declared
// generator). crenel can still READ the edge (understanding != ownership), but the
// refuse-to-manage gate then blocks any mutation — a crenel edit would be reverted on
// the generator's next regeneration (a Docker event / sync). Mirrors the nginx/Traefik
// P2 detectors; the difference is the SIGNAL: the Caddy admin API carries no CDP
// marker, so detection needs the mounted autosave file (or the declared hint).
func (d *Driver) applyGeneratorOwnership(state *model.LiveEdgeState) {
	g := d.detectGenerator()
	if g == "" {
		return
	}
	state.Generator = g
	for i := range state.Routes {
		state.Routes[i].Ownership = model.OwnForeign
		state.Routes[i].Managed = false
	}
}

// detectGenerator resolves the edge's config generator, if any: an operator-DECLARED
// generator (WithGenerator) takes precedence; otherwise crenel scans the configured
// on-disk artifact (WithGeneratorConfigPath) for a known signature. "" => no generator
// detected (a static, crenel-ownable edge — or one whose generator left no readable
// signal, still covered by the P0 unknown net).
func (d *Driver) detectGenerator() string {
	if d.generator != "" {
		return d.generator
	}
	if d.generatorConfigPath != "" {
		return detectGeneratorFile(d.generatorConfigPath)
	}
	return ""
}

// cdpAutosaveName is caddy-docker-proxy's generated-Caddyfile filename. CDP writes its
// label-derived config here in Caddy's config dir (typically
// /config/caddy/Caddyfile.autosave); the name is CDP-specific — stock Caddy autosaves
// JSON to `autosave.json`, never a `.autosave` Caddyfile. See README "Caddyfile.autosave".
const cdpAutosaveName = "Caddyfile.autosave"

// detectGeneratorFile scans an on-disk config artifact for a known generator
// signature. For caddy-docker-proxy the readable signal is its `Caddyfile.autosave`
// (by filename — CDP-specific — or a content marker). An unreadable/absent file yields
// "" (detection simply does not fire; the P0 unknown net still applies), never an
// error: a missing optional signal must not break a read.
func detectGeneratorFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if filepath.Base(path) == cdpAutosaveName || strings.Contains(string(b), "caddy-docker-proxy") {
		return "caddy-docker-proxy"
	}
	return ""
}

// normalize walks the http config into a LiveEdgeState, reading EVERY http.server
// (not just the configured one).
//
// Default-deny model: Caddy denies any host that matches NO route via an
// implicit 404. So the structural default-deny holds UNLESS some route forwards
// traffic for ANY host — i.e. a permissive host-less catch-all (a host-less
// reverse_proxy). An explicit host-less static_response deny is just a stricter
// form of the same default-deny and keeps it present. This is what lets a real
// edge that routes wildcard hosts (*.homelab.example) into subroutes — with no
// explicit catch-all — read correctly as default-deny SATISFIED, not fail-open.
//
// Nested subroutes: a real edge nests a wildcard host into a subroute that nests
// further (wildcard → subroute → per-host route → subroute → leaf reverse_proxy)
// down to the real per-host services. normalize RECURSES through those nested
// subroutes (collectLeaves) so status/audit/import see the ~25 real per-host
// services, not 2 opaque wildcards. The default-deny reading is unchanged: only a
// TOP-LEVEL host-less reverse_proxy is fail-open; a nested host-less reverse_proxy
// is scoped by the parent host matcher and inherits it as a leaf.
//
// Multi-server edges: Caddy's http app can hold SIBLING servers beside the
// configured one (e.g. a separate :80 listener). Reading only the configured key
// would make a route on a sibling server INVISIBLE — under-reporting exposure and
// possibly keeping default-deny falsely green (a MISREAD-by-omission). So normalize
// enumerates every sibling too: a sibling crenel can FULLY model has its leaf
// routes folded in (attributed via the route's host); a sibling that FORWARDS
// (reverse_proxy/subroute) but crenel cannot fully model is declared
// UnknownServerBlock (which downgrades default-deny to UNKNOWN); a benign
// non-forwarding sibling (a :80→:443 redirect, a pure static/file server) is left
// unflagged — the point is to catch hidden exposure, not amber-flag every helper
// listener. (crowdsec/tls/etc. are separate Caddy *apps*, not http.servers, so they
// are never seen here — the Config type only models the http and layer4 apps.)
func normalize(cfg Config, serverKey, raw string) model.LiveEdgeState {
	state := model.LiveEdgeState{Raw: raw}
	// Layer4 (SNI passthrough) routes are read FIRST and surfaced as
	// ModeTCPPassthrough routes, so status/audit/reconcile see them as live truth.
	// They live in a different app than http and never affect the http deny.
	appendLayer4Routes(&state, cfg)

	servers := cfg.Apps.HTTP.Servers

	// 1. The CONFIGURED (managed) server drives the structural default-deny: its
	//    routes are modeled per-host, and a permissive host-less catch-all THERE is
	//    fail-open. An l4-only edge (no managed http server) still has its implicit-404
	//    deny; otherwise (no managed server, no l4) the prior conservative reading holds
	//    (deny unconfirmed -> DenyMissing).
	denyPresent := false
	if srv, ok := servers[serverKey]; ok {
		routes, unparsed, permissive := normalizeServer(srv, serverKey)
		state.Routes = append(state.Routes, routes...)
		state.Unparsed = append(state.Unparsed, unparsed...)
		denyPresent = !permissive
	} else if cfg.Apps.Layer4 != nil {
		denyPresent = true
	}

	// 2. SIBLING http servers (every key except the configured one), in deterministic
	//    order. A route on a sibling is real exposure crenel would otherwise miss.
	for _, key := range siblingServerKeys(servers, serverKey) {
		srv := servers[key]
		if !serverForwards(srv) {
			continue // benign listener (redirect-only / static) — exposes nothing to model
		}
		routes, unparsed, permissive := normalizeServer(srv, key)
		if len(unparsed) == 0 && !permissive {
			// Fully modeled forwarding sibling: fold its leaf routes in (attributed to
			// that server by their host); status/audit now see those hosts.
			state.Routes = append(state.Routes, routes...)
			continue
		}
		// Forwarding but NOT fully modeled (an unmodeled handler, an undescended
		// subroute, or a permissive catch-all crenel cannot represent per-server):
		// declare the whole sibling server unknown. This downgrades default-deny to
		// UNKNOWN — a forwarding server crenel cannot fully see could itself be exposing
		// or fail-open.
		reason := fmt.Sprintf("sibling http server %q (listen %s) forwards traffic but crenel cannot fully model it",
			key, listenDesc(srv))
		if permissive {
			reason += " — it has a permissive host-less catch-all (fail-open for this listener)"
		} else {
			reason += fmt.Sprintf(" — %d route(s) not understood", len(unparsed))
		}
		state.Unparsed = append(state.Unparsed, model.Unparsed{
			Locator:    fmt.Sprintf("apps.http.servers.%s", key),
			Kind:       model.UnknownServerBlock,
			Reason:     reason,
			RawExcerpt: serverExcerpt(srv),
		})
	}

	state.DenyCatchAllPresent = denyPresent
	return state
}

// normalizeServer walks ONE http server's routes into (modeled routes, unparsed
// entries, permissiveCatchAll). It is the per-server core shared by the configured
// server and each sibling — extracted so multi-server enumeration reuses the exact
// same modeling (and thus the same detect-and-declare-unknown semantics).
func normalizeServer(srv Server, serverKey string) (routes []model.Route, unparsed []model.Unparsed, permissiveCatchAll bool) {
	for i, r := range srv.Routes {
		loc := fmt.Sprintf("apps.http.servers.%s.routes[%d]", serverKey, i)
		hosts, hasHost := r.hostMatches()
		if !hasHost {
			// TOP-LEVEL host-less route: matches every host. A host-less reverse_proxy
			// forwards ALL traffic regardless of host => the edge is fail-open. A
			// host-less deny (static_response) keeps the default-deny.
			if _, fwd := r.firstReverseProxyDial(); fwd {
				permissiveCatchAll = true
				continue
			}
			if r.hasDenyHandler() {
				continue // host-less deny — understood, keeps the default-deny
			}
			if subs, hasSub := r.subroutes(); hasSub {
				// A top-level host-less subroute. The CANONICAL Caddyfile default-deny
				// spelling — `:80 { respond 403 }` — adapts to exactly this: Caddy wraps
				// every site block's directives in a subroute, so the host-less catch-all
				// deny sits one level below the route. Descend to classify the leaves:
				//   - wraps ONLY denies  => understood; keeps the default-deny (the deny is
				//     just one subroute deep, same as a direct host-less static_response).
				//   - wraps a permissive forward => genuinely fail-open for every host;
				//     mark it permissive (DenyCatchAllPresent must read false).
				//   - anything else (a nested host route, a deeper subroute, an unmodeled
				//     handler) => still DECLARE it unparsed rather than guess — the
				//     detect-and-declare-unknown rule (register §4).
				// The in-repo fakes never caught this because JSON fixtures hand-wrote the
				// deny as a TOP-LEVEL static_response, a shape Caddy's adapter never emits;
				// the CT 120 proving-ground bench (a Caddyfile edge) surfaced it.
				switch denyOnly, permissive := classifyHostlessSubroute(subs); {
				case permissive:
					permissiveCatchAll = true
					continue
				case denyOnly:
					continue // host-less subroute wrapping only a deny — keeps the default-deny
				}
				unparsed = append(unparsed, model.Unparsed{
					Locator: loc, Kind: model.UnknownNestedRoute,
					Reason:     "top-level host-less subroute not descended (no host to attribute its leaves to)",
					RawExcerpt: r.excerpt(),
				})
				continue
			}
			// A host-less route with some other handler crenel does not model.
			unparsed = append(unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason:     "top-level host-less route with handler(s) crenel does not model: " + r.handlerNames(),
				RawExcerpt: r.excerpt(),
			})
			continue
		}
		// Host-scoped route: enumerate its leaf reverse-proxy targets for EACH host
		// it matches (one route may group many hosts onto one backend), descending
		// through any nested subroutes (per-host routing under a wildcard zone).
		for _, host := range hosts {
			collectLeaves(r, host, false, "", loc, &routes, &unparsed)
		}
	}
	return routes, unparsed, permissiveCatchAll
}

// classifyHostlessSubroute inspects the leaves of a TOP-LEVEL host-less subroute (the
// shape Caddy's Caddyfile adapter emits for a site block like `:80 { … }`) WITHOUT a
// host to attribute them to. It reports two mutually-informative signals:
//
//   - denyOnly: every child route is itself a host-less deny (a static_response with a
//     >=400 status or abort) and nothing else — so the subroute as a whole is exactly a
//     blanket default-deny, just nested one level. This is the canonical Caddyfile
//     default-deny `:80 { respond 403 }`.
//   - permissive: some child route forwards EVERY host (a host-less reverse_proxy), so
//     the subroute is genuinely fail-open and the edge must NOT read default-deny.
//
// When neither holds (a nested host matcher, a deeper subroute, or an unmodeled
// terminal), both are false and the caller declares the subroute unparsed — crenel
// surfaces what it cannot prove safe rather than guessing. The two signals are not both
// true: a single permissive forward anywhere makes the catch-all fail-open regardless of
// sibling denies.
func classifyHostlessSubroute(subs []JSONRoute) (denyOnly, permissive bool) {
	if len(subs) == 0 {
		return false, false
	}
	allDeny := true
	for _, sr := range subs {
		if _, hasHost := sr.hostMatches(); hasHost {
			// A nested host matcher is real per-host routing, not a blanket deny — leave it
			// to the detect-and-declare-unknown path (we have no host context here).
			return false, false
		}
		if _, fwd := sr.firstReverseProxyDial(); fwd {
			return false, true // host-less forward => fail-open for every host
		}
		if _, hasSub := sr.subroutes(); hasSub {
			return false, false // deeper nesting — don't guess, surface it
		}
		if !sr.hasDenyHandler() {
			allDeny = false // some other unmodeled handler — can't call it a clean deny
		}
	}
	return allDeny, false
}

// siblingServerKeys returns the http.server keys OTHER than the configured one, in
// deterministic (sorted) order so status/audit output is stable across the map's
// random iteration order.
func siblingServerKeys(servers map[string]Server, configured string) []string {
	keys := make([]string, 0, len(servers))
	for k := range servers {
		if k == configured {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// serverForwards reports whether a server FORWARDS traffic — has a reverse_proxy or
// subroute leaf anywhere in its route tree. This is the gate that separates a
// hidden-exposure sibling (worth surfacing) from a benign helper listener (a
// :80→:443 redirect via static_response, a pure file_server) that exposes nothing
// crenel needs to model. Only a forwarding-but-unmodeled sibling becomes an
// UnknownServerBlock — avoiding the cry-wolf of amber-flagging every redirect server.
func serverForwards(srv Server) bool {
	for _, r := range srv.Routes {
		if routeForwards(r) {
			return true
		}
	}
	return false
}

// routeForwards reports whether a route (recursively, through subroutes) forwards
// traffic. A reverse_proxy is forwarding; a subroute is a forwarding/routing
// construct (even an opaque one crenel cannot descend — it must not be dismissed as
// benign). static_response (deny/redirect) and file_server are NOT forwarding.
func routeForwards(r JSONRoute) bool {
	if _, ok := r.firstReverseProxyDial(); ok {
		return true
	}
	if _, ok := r.subroutes(); ok {
		return true
	}
	return false
}

// listenDesc renders a server's listen addresses for a human-readable reason,
// defaulting to "(default)" when the config omits them.
func listenDesc(srv Server) string {
	if len(srv.Listen) == 0 {
		return "(default)"
	}
	return strings.Join(srv.Listen, ",")
}

// serverExcerpt returns a bounded JSON snippet of a whole server for an
// UnknownServerBlock entry's RawExcerpt, so the operator can inspect the sibling
// crenel could not fully model without flooding status output.
func serverExcerpt(srv Server) string {
	b, err := json.Marshal(srv)
	if err != nil {
		return ""
	}
	const max = 240
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// collectLeaves appends one model.Route per leaf reverse_proxy reachable from a
// host-scoped route, recursing through nested subroute handlers. It carries down:
//   - host: the most specific host matcher seen so far (a nested per-host route's
//     own matcher overrides the wildcard above it);
//   - managed: whether any route in the chain carries Crenel's @id for this host
//     (so a nested per-host route crenel adopted reads back as managed);
//   - auth: a forward-auth handler seen at any level (the leaf inherits it).
//
// It returns resolved=true when the route is fully accounted for — a leaf was
// emitted, a deny was recognized, or a descended subroute resolved (even to denies
// only). If a subroute yields NOTHING crenel can account for (an opaque/empty shape),
// the route is DECLARED UNPARSED (UnknownNestedRoute) rather than silently dropped or
// faked as a single understood route — the detect-and-declare-unknown rule
// (register §4): an undescended subroute could itself nest a permissive catch-all, so
// crenel must surface it, not swallow it. A host-scoped route that forwards via an
// unmodeled terminal (no reverse_proxy, no subroute, not a deny) is likewise declared
// unparsed. A deny-ONLY subroute (a per-zone close with no backends) resolves cleanly
// and must NOT be flagged opaque — hence the resolved signal rather than a bare
// leaf-count check.
func collectLeaves(r JSONRoute, host string, managed bool, auth, loc string, out *[]model.Route, unparsed *[]model.Unparsed) (resolved bool) {
	managed = managed || r.ID == routeID(host)
	if a := r.detectAuth(); a != "" {
		auth = a
	}
	// A route gated by a NON-host matcher (path/method/header/query/…) is scoped beyond
	// what the host-granular model can represent. Reading it as a plain `host → backend`
	// route would silently claim the WHOLE host is exposed — and make the host inherit
	// one path's auth for all of them — a MISREAD-↓ that violates bounded honesty. DECLARE
	// it matcher_conditional instead (register §4): coverage counts it unparsed, deny
	// downgrades to UNKNOWN, and the excerpt shows the operator the real path/method scope.
	// The host-granular WRITE model cannot target a sub-path, so this is detect-and-declare,
	// not silent flattening; full path-granular MODELING is the P5 follow-on.
	if keys := r.extraMatcherKeys(); len(keys) > 0 {
		*unparsed = append(*unparsed, model.Unparsed{
			Locator: loc, Kind: model.UnknownMatcher,
			Reason: fmt.Sprintf("route for %s is scoped by non-host matcher(s) crenel does not model (%s) — path/method/header-granular routing is not represented at host granularity",
				host, strings.Join(keys, ", ")),
			RawExcerpt: r.excerpt(),
		})
		return false
	}
	if dial, ok := r.firstReverseProxyDial(); ok {
		*out = append(*out, model.Route{
			Host:      host,
			Managed:   managed,
			Ownership: model.OwnershipFromMarker(managed),
			Upstream: model.Upstream{
				Kind: model.ForwardToOrigin, Address: dial, ServerName: host, Auth: auth,
				// A backend reverse_proxy that dials its upstream over TLS reads back as
				// UpstreamTLS so a chain-forward's re-originated TLS hop round-trips and
				// verify can confirm it (TRIAL-FIX-4). A plain forward reads back false.
				UpstreamTLS: r.firstReverseProxyUpstreamTLS(),
			},
		})
		return true
	}
	subs, ok := r.subroutes()
	if !ok {
		if r.hasDenyHandler() {
			return true // per-host deny — understood (it closes this host, exposes nothing)
		}
		// A host-scoped route that neither forwards via reverse_proxy nor nests a
		// subroute — an unmodeled terminal (file_server, php_fastcgi, a map/vars-indirect
		// backend, …). Its effective exposure is unknown to crenel.
		*unparsed = append(*unparsed, model.Unparsed{
			Locator: loc, Kind: model.UnknownHandler,
			Reason:     fmt.Sprintf("route for %s has no reverse_proxy/subroute crenel can resolve (handlers: %s)", host, r.handlerNames()),
			RawExcerpt: r.excerpt(),
		})
		return false
	}
	anyResolved := false
	beforeU := len(*unparsed)
	for j, sr := range subs {
		childLoc := fmt.Sprintf("%s.handle[subroute].routes[%d]", loc, j)
		if childHosts, has := sr.hostMatches(); has {
			// A nested matcher narrows the wildcard to real per-host name(s); a single
			// route may group many hosts onto one handler — descend once per host so
			// every co-matched host is enumerated, not just the first.
			for _, childHost := range childHosts {
				if collectLeaves(sr, childHost, managed, auth, childLoc, out, unparsed) {
					anyResolved = true
				}
			}
		} else if collectLeaves(sr, host, managed, auth, childLoc, out, unparsed) {
			anyResolved = true
		}
	}
	if !anyResolved && len(*unparsed) == beforeU {
		// Opaque/empty subroute that yielded neither a resolved leaf/deny nor a nested
		// unparsed entry — surface it rather than swallow it.
		*unparsed = append(*unparsed, model.Unparsed{
			Locator: loc, Kind: model.UnknownNestedRoute,
			Reason:     fmt.Sprintf("subroute under %s yielded no resolvable leaf route", host),
			RawExcerpt: r.excerpt(),
		})
		return false
	}
	return true
}

// appendLayer4Routes surfaces SNI-passthrough routes from the caddy-l4 app as
// ModeTCPPassthrough routes on live state, so status/audit/reconcile see the
// passthrough exposures as live truth. Deterministic order for stable output.
func appendLayer4Routes(state *model.LiveEdgeState, cfg Config) {
	if cfg.Apps.Layer4 == nil {
		return
	}
	names := make([]string, 0, len(cfg.Apps.Layer4.Servers))
	for name := range cfg.Apps.Layer4.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range cfg.Apps.Layer4.Servers[name].Routes {
			host, dial, ok := r.firstSNIProxy()
			if !ok {
				continue
			}
			managed := r.ID == l4RouteID(host)
			state.Routes = append(state.Routes, model.Route{
				Host:      host,
				Managed:   managed,
				Ownership: model.OwnershipFromMarker(managed),
				Upstream: model.Upstream{
					Kind:           model.ForwardToOrigin,
					Mode:           model.ModeTCPPassthrough,
					Address:        dial,
					TLSPassthrough: true,
					ServerName:     host,
				},
			})
		}
	}
}

// Plan computes the ChangeSet to realize op against live. It resolves the
// service backend for Expose via the OriginResolver. It never mutates anything.
func (d *Driver) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	// The default-deny invariant: regardless of the op, the resulting config
	// will carry the catch-all deny.
	cs.Edge.DenyCatchAllWillBePresent = true

	// Mode check: by default Caddy terminates TLS and reverse-proxies (HTTP-proxy).
	// It expresses SNI PASSTHROUGH only when built with the caddy-l4 plugin
	// (WithLayer4) AND driven in additive granular mode (so the layer4 write does
	// not disturb the http routes). It never renders identity-mesh grants. Each
	// case it cannot express is refused LOUDLY, not approximated.
	switch op.Mode {
	case model.ModeHTTPProxy:
		// expressible
	case model.ModeTCPPassthrough:
		if !d.layer4 {
			return cs, fmt.Errorf("%w: caddy does not render SNI passthrough without the layer4 plugin — "+
				"build the edge with github.com/mholt/caddy-l4 and enable it (caddy_layer4 / WithLayer4)",
				model.ErrModeUnsupported)
		}
		if !d.granular {
			return cs, fmt.Errorf("%w: caddy layer4 passthrough requires additive granular apply (--granular) "+
				"so it does not disturb the http routes / deny / TLS", model.ErrModeUnsupported)
		}
	default:
		return cs, fmt.Errorf("%w: caddy expresses http_proxy (and tcp_passthrough with the layer4 plugin); "+
			"got %s — it does not render identity-mesh grants", model.ErrModeUnsupported, op.Mode)
	}

	// Auth is HTTP-only (refused for non-http modes upstream by model.ValidateAuth)
	// and — like layer4 passthrough — requires additive granular apply: full-load
	// renders crenel's whole config from its model and cannot carry the operator's
	// auth snippet, so crenel refuses LOUDLY rather than silently drop the policy.
	if op.HasAuthPolicy() && !d.granular {
		return cs, fmt.Errorf("caddy auth: attaching forward-auth policy %q requires additive granular apply (--granular) — "+
			"the full-load path cannot carry the operator's auth snippet", op.Auth)
	}
	// Granular auth must render to VALID admin-API JSON. A snippet-only / default policy
	// has no JSON representation (a Caddyfile `import` is not an admin-API construct), so
	// crenel refuses LOUDLY here rather than emit a handler Caddy can't load — the exact
	// failure the live cross-chain trial hit. The operator declares a renderable reference:
	// a verbatim handler blob (caddy_handler_json) or an authorizer endpoint
	// (caddy_forward_auth) crenel expands to the canonical gate.
	if op.HasAuthPolicy() && d.granular {
		if _, ok := d.authGate(op.Auth); !ok {
			return cs, fmt.Errorf("caddy auth: granular forward-auth for policy %q has no renderable Caddy reference — set "+
				"auth_policies.%s.caddy_handler_json (an operator-provided handler blob, the purest by-reference) or "+
				"auth_policies.%s.caddy_forward_auth (an authorizer endpoint crenel expands to the canonical "+
				"reverse_proxy+handle_response gate); the snippet `import` form renders only on the on-disk persistence path",
				op.Auth, op.Auth, op.Auth)
		}
	}

	switch op.Verb {
	case model.Expose:
		if op.Host == "" {
			return cs, fmt.Errorf("caddy plan: expose requires a host")
		}
		if live.HasHost(op.Host) {
			return cs, nil // already exposed => no-op
		}
		addr := op.To
		if addr == "" {
			resolved, err := d.resolver.Resolve(op.Service)
			if err != nil {
				return cs, fmt.Errorf("caddy plan: %w", err)
			}
			addr = resolved
		}
		cs.Edge.AddRoutes = []model.Route{{
			Host: op.Host,
			Upstream: model.Upstream{
				Kind:           model.ForwardToOrigin,
				Mode:           op.Mode,
				Address:        addr,
				ServerName:     op.Host,
				TLSPassthrough: op.Mode == model.ModeTCPPassthrough,
				Auth:           op.Auth,
			},
		}}
		// About-to-go-public highlight: this host becomes reachable iff the
		// deny is (and will remain) present, which it will.
		cs.NewPublic = []string{op.Host}
	case model.Unexpose:
		if op.Host == "" {
			return cs, fmt.Errorf("caddy plan: unexpose requires a host")
		}
		if !live.HasHost(op.Host) {
			return cs, nil // not exposed => no-op
		}
		cs.Edge.RemoveHosts = []string{op.Host}
	default:
		return cs, fmt.Errorf("caddy plan: unknown verb %q", op.Verb)
	}
	return cs, nil
}

// Apply renders the target Caddyfile and POSTs it to /load. It then re-reads to
// guard against a silent reload — but the authoritative read-back verification
// is done by core. Apply returning nil is NOT proof the change took effect.
func (d *Driver) Apply(ctx context.Context, cs model.ChangeSet) error {
	if d.granular {
		return d.applyGranular(ctx, cs)
	}
	cfg, raw, err := d.fetchConfigRaw(ctx)
	if err != nil {
		return fmt.Errorf("caddy apply: read live: %w", err)
	}
	live := normalize(cfg, d.server, raw)
	// SAFETY GATE: full-load is a full-config REPLACE rebuilt solely from the
	// understood, bare-reverse_proxy view (renderCaddyfile). Refuse it whenever live
	// holds something a full replace would SILENTLY lose rather than refuse — the
	// register's worst classes. See fullLoadSafe.
	if err := fullLoadSafe(live, cs.Edge); err != nil {
		return err
	}
	// MULTI-SERVER GATE: renderCaddyfile emits a SINGLE managed server. If live has a
	// forwarding sibling http server, normalize folded its routes into live.Routes —
	// a full replace would collapse them all onto the managed server (losing the
	// sibling's listen/structure) or, for an unparsed sibling, fullLoadSafe already
	// refused above. Refuse here so the fully-modeled-sibling case can't silently
	// restructure the edge; the additive granular path preserves each server.
	if err := multiServerFullLoadSafe(cfg, d.server); err != nil {
		return err
	}
	desired := targetRoutes(live, cs.Edge)
	body := renderCaddyfile(desired)

	if err := d.load(ctx, body); err != nil {
		return fmt.Errorf("caddy apply: load: %w", err)
	}
	// Post-apply health re-check: confirm the reload settled and the admin API is
	// responsive before returning (core then read-back-verifies).
	if err := d.settle(ctx); err != nil {
		return fmt.Errorf("caddy apply: post-load health: %w", err)
	}
	return nil
}

// fullLoadSafe refuses a full-config replace (POST /load) when live holds anything
// the full-load renderer cannot faithfully reproduce — which would be a SILENT loss,
// the exact opposite of detect-and-declare-unknown. renderCaddyfile emits only
// `host { reverse_proxy <addr> }` rebuilt SOLELY from live.Routes, so a full replace
// would:
//   - DROP every live.Unparsed construct (an unmodeled handler, an undescended
//     host-less subroute that could itself be a permissive catch-all) — and, by
//     erasing the evidence, falsely flip the read-back default-deny from UNKNOWN to
//     ENFORCED (register §4.4: a MISMANAGE that manufactures a false green);
//   - STRIP any forward-auth handler off a surviving route, turning a protected host
//     public-and-unprotected while read-back still passes (MISREAD-↓ by mutation);
//   - DROP a TCP-passthrough (layer4) route, which the http renderer cannot express.
//
// Full-load stays the simple greenfield / crenel-owned bootstrap path; a rich or
// brownfield edge must use --granular (additive admin-API ops that touch only
// crenel's own routes and carry auth/mode faithfully). Refusing loudly here is the
// structural guard the "greenfield-only" doc note previously left to the operator.
func fullLoadSafe(live model.LiveEdgeState, ec model.EdgeChange) error {
	if n := len(live.Unparsed); n > 0 {
		return fmt.Errorf("caddy apply: refusing full-config load on an edge with %d unparsed construct(s) — "+
			"a full replace would silently drop them and could falsely certify default-deny; use --granular (additive apply)", n)
	}
	removing := make(map[string]bool, len(ec.RemoveHosts))
	for _, h := range ec.RemoveHosts {
		removing[strings.ToLower(h)] = true
	}
	for _, r := range live.Routes {
		if removing[strings.ToLower(r.Host)] {
			continue // being removed anyway — not preserved, so nothing to lose
		}
		if hasRealAuth(r.Upstream.Auth) {
			return fmt.Errorf("caddy apply: refusing full-config load — route %s carries forward-auth (%s) that a full "+
				"replace would STRIP, leaving it public-unprotected; use --granular", r.Host, r.Upstream.Auth)
		}
		if r.Upstream.Mode == model.ModeTCPPassthrough {
			return fmt.Errorf("caddy apply: refusing full-config load — route %s is TCP passthrough (layer4) that the "+
				"http full-load renderer would drop; use --granular", r.Host)
		}
	}
	for _, r := range ec.AddRoutes {
		if hasRealAuth(r.Upstream.Auth) {
			return fmt.Errorf("caddy apply: exposing %s with forward-auth requires --granular "+
				"(the full-load renderer cannot carry the auth reference)", r.Host)
		}
	}
	return nil
}

// multiServerFullLoadSafe refuses a full-config replace when the edge has a
// FORWARDING sibling http server beside the configured one. The full-load renderer
// (renderCaddyfile) emits exactly one managed server, so collapsing a real
// multi-server edge into it would lose the sibling's own listener/structure — and,
// for a fully-modeled sibling whose routes normalize folded in, it would silently
// move those hosts onto the managed server. The additive granular path touches only
// crenel's own @id-tagged routes and leaves every server intact, so it is the safe
// path for a multi-server edge.
func multiServerFullLoadSafe(cfg Config, configured string) error {
	for _, key := range siblingServerKeys(cfg.Apps.HTTP.Servers, configured) {
		if serverForwards(cfg.Apps.HTTP.Servers[key]) {
			return fmt.Errorf("caddy apply: refusing full-config load — the edge has another forwarding http server %q "+
				"that a single-server full replace would collapse/restructure; use --granular (additive apply preserves every server)", key)
		}
	}
	return nil
}

// hasRealAuth reports whether an Upstream.Auth value names a forward-auth handler
// the full-load renderer would lose. "" (none attached) and the explicit "none"
// opt-out attach NO handler, so a bare reverse_proxy render is faithful for them;
// any other value (a policy name, or the recognized "(detected)" brownfield auth) is
// a real handler that a full replace would strip.
func hasRealAuth(auth string) bool { return auth != "" && auth != model.AuthNone }

// routeID returns the deterministic @id Crenel tags a managed route with, so it
// can be removed later without depending on route indices.
func routeID(host string) string { return "crenel-route-" + strings.ToLower(host) }

// Adopt stamps Crenel's @id onto the EXISTING unmanaged http route for each host,
// in-place, via PATCH — same match/handlers/backend, only the @id is added. It
// navigates the RAW config (not the typed view) so every field Crenel does not
// model is preserved verbatim; it touches exactly the one route per host and
// never the deny, TLS, or other routes. Idempotent: a host already carrying the
// crenel @id (or with no matching unmanaged route) is skipped. Implements
// ports.Adopter (brownfield import). See USABILITY-DESIGN.md §A.
func (d *Driver) Adopt(ctx context.Context, hosts []string) error {
	want := map[string]bool{}
	for _, h := range hosts {
		want[strings.ToLower(h)] = true
	}
	_, raw, err := d.fetchConfigRaw(ctx)
	if err != nil {
		return fmt.Errorf("caddy adopt: read live: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("caddy adopt: parse config: %w", err)
	}
	routes := rawRoutes(cfg, d.server)
	base := fmt.Sprintf("/config/apps/http/servers/%s/routes", d.server)
	return d.adoptWalk(ctx, routes, base, want)
}

// adoptWalk recursively stamps Crenel's @id onto each unmanaged route whose host
// matches a wanted host, descending through nested subroute handlers so a per-host
// route under a wildcard zone (wildcard → subroute → per-host route) is adoptable
// in place. routesPath is the admin-API path of the routes slice being walked. It
// PATCHes exactly the one matching route object per host (same match/handlers/
// backend, only @id added) — never the deny, TLS, or other routes — and settles
// between stamps to avoid a reload storm. Idempotent: a host already carrying the
// crenel @id is skipped.
func (d *Driver) adoptWalk(ctx context.Context, routes []any, routesPath string, want map[string]bool) error {
	for idx, rt := range routes {
		rm, ok := rt.(map[string]any)
		if !ok {
			continue
		}
		routePath := fmt.Sprintf("%s/%d", routesPath, idx)
		if host := rawRouteHost(rm); host != "" && want[strings.ToLower(host)] {
			if id, _ := rm["@id"].(string); id == routeID(host) {
				continue // already managed — idempotent
			}
			rm["@id"] = routeID(host)
			body, err := json.Marshal(rm)
			if err != nil {
				return fmt.Errorf("caddy adopt: marshal route %s: %w", host, err)
			}
			if err := d.adminWrite(ctx, http.MethodPatch, routePath, body); err != nil {
				return fmt.Errorf("caddy adopt: stamp %s: %w", host, err)
			}
			if err := d.settle(ctx); err != nil {
				return fmt.Errorf("caddy adopt: after stamp %s: %w", host, err)
			}
			continue // matched: don't descend further into this host's own subtree
		}
		// Not a wanted host: descend into any nested subroute handlers to reach the
		// per-host routes under a wildcard zone.
		handlers, _ := rm["handle"].([]any)
		for hidx, h := range handlers {
			hm, ok := h.(map[string]any)
			if !ok || hm["handler"] != handlerSubroute {
				continue
			}
			sub, _ := hm["routes"].([]any)
			if len(sub) == 0 {
				continue
			}
			subPath := fmt.Sprintf("%s/handle/%d/routes", routePath, hidx)
			if err := d.adoptWalk(ctx, sub, subPath, want); err != nil {
				return err
			}
		}
	}
	return nil
}

// rawRoutes returns the apps.http.servers.<srv>.routes array from a generic config
// map (nil if absent), so Adopt can address routes by index without re-marshaling
// the typed view (which would drop unmodeled fields).
func rawRoutes(cfg map[string]any, server string) []any {
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	srv, _ := servers[server].(map[string]any)
	routes, _ := srv["routes"].([]any)
	return routes
}

// rawRouteHost returns the first host in a raw route's match[].host, if any.
func rawRouteHost(rm map[string]any) string {
	matches, _ := rm["match"].([]any)
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hosts, _ := mm["host"].([]any)
		if len(hosts) > 0 {
			if h, ok := hosts[0].(string); ok {
				return h
			}
		}
	}
	return ""
}

// applyGranular realizes the edge change ADDITIVELY via the structured admin
// API. Adds insert a single tagged route at index 0 (so it precedes any trailing
// catch-all deny); removes delete by @id. Routes Crenel does not manage are
// never read, rewritten, or replaced.
func (d *Driver) applyGranular(ctx context.Context, cs model.ChangeSet) error {
	// MAKE-BEFORE-BREAK ordering. A route whose host is NOT also being removed is added
	// FIRST (a RENAME: bring the new host up before the old comes down — zero-downtime,
	// and if the add fails the old is never removed). Then removals. Then any route whose
	// host IS also in RemoveHosts is added LAST — the reconcile re-render case (same host
	// in both): the old @id must be deleted first so the fresh insert wins. So:
	//   add(new hosts) → remove(old hosts) → add(re-rendered same hosts)
	removing := make(map[string]bool, len(cs.Edge.RemoveHosts))
	for _, h := range cs.Edge.RemoveHosts {
		removing[strings.ToLower(h)] = true
	}
	var addFirst, addLast []model.Route
	for _, r := range cs.Edge.AddRoutes {
		if removing[strings.ToLower(r.Host)] {
			addLast = append(addLast, r)
		} else {
			addFirst = append(addFirst, r)
		}
	}

	for _, r := range addFirst {
		if err := d.insertOne(ctx, r); err != nil {
			return err
		}
	}
	// A removed host may live in the http tree, the layer4 (passthrough) tree, or both —
	// delete from each idempotently (a missing @id is a tolerated no-op).
	for _, h := range cs.Edge.RemoveHosts {
		if err := d.deleteRoute(ctx, h); err != nil {
			return fmt.Errorf("caddy apply (granular): delete %s: %w", h, err)
		}
		if d.layer4 {
			if err := d.deleteLayer4Route(ctx, h); err != nil {
				return fmt.Errorf("caddy apply (granular): delete l4 %s: %w", h, err)
			}
		}
		if err := d.settle(ctx); err != nil {
			return fmt.Errorf("caddy apply (granular): after delete %s: %w", h, err)
		}
	}
	for _, r := range addLast {
		if err := d.insertOne(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// insertOne inserts a single route (http or layer4 passthrough) and SETTLES — each
// insert is a full reload, so the admin endpoint must recover before the next mutation
// (never fire reloads back-to-back).
func (d *Driver) insertOne(ctx context.Context, r model.Route) error {
	var err error
	if r.Upstream.Mode == model.ModeTCPPassthrough {
		err = d.insertLayer4Route(ctx, r) // SNI passthrough via the layer4 app
	} else {
		err = d.insertRoute(ctx, r) // http reverse-proxy route
	}
	if err != nil {
		return fmt.Errorf("caddy apply (granular): insert %s: %w", r.Host, err)
	}
	if err := d.settle(ctx); err != nil {
		return fmt.Errorf("caddy apply (granular): after insert %s: %w", r.Host, err)
	}
	return nil
}

// insertRoute PUTs a single tagged http route at the front (index 0) of the routes
// array that OWNS this host's per-host routing — preceding any catch-all deny there
// so the exact-host match wins. On the real edge shape that array is the wildcard
// *.zone subroute (httpRouteInsertPath locates it); on a flat edge it is the managed
// server's top-level routes. This MIRRORS the read side (collectLeaves) so the route
// lands where status/audit enumerate it and unexpose/Adopt find it by @id.
func (d *Driver) insertRoute(ctx context.Context, r model.Route) error {
	// Auth reference (if any) is prepended BEFORE the backend reverse_proxy so the
	// forward-auth subrequest gates the route: [marker, gate, backend]. The gate is
	// VALID Caddy JSON (verbatim operator blob or canonical reverse_proxy+handle_response)
	// — never the synthetic {"handler":"forward_auth"} that no Caddy registers. The marker
	// round-trips the policy name on read-back.
	handlers := []any{}
	if policy := r.Upstream.Auth; policy != "" && policy != model.AuthNone {
		gate, ok := d.authGate(policy)
		if !ok {
			// Plan refuses this case up front; defensive guard so a misrouted call can
			// never emit a handler Caddy would reject.
			return fmt.Errorf("caddy auth: no renderable forward-auth gate for policy %q "+
				"(set auth_policies.%s.caddy_handler_json or caddy_forward_auth)", policy, policy)
		}
		handlers = append(handlers, authMarker(policy), gate)
	}
	backend := map[string]any{
		"handler":   handlerReverseProxy,
		"upstreams": []any{map[string]any{"dial": r.Upstream.Address}},
	}
	// Chain-forward to an HTTPS downstream (TRIAL-FIX-4): the front terminated the
	// client's TLS, so it must RE-ORIGINATE TLS to the downstream and preserve the Host,
	// else the downstream's TLS listener answers 400 "Client sent an HTTP request to an
	// HTTPS server" and its host matcher can't route. This mirrors the edge's OWN working
	// forward routes byte-for-byte: transport {protocol:http, tls:{insecure_skip_verify,
	// server_name:{http.request.host}}} + request Host set to {http.request.host}. The
	// {http.request.host} placeholder (not a literal FQDN) carries the matched host
	// through the wildcard so one rendering serves every forwarded host. A plain-HTTP
	// downstream leaves UpstreamTLS false and renders the bare reverse_proxy unchanged.
	if r.Upstream.UpstreamTLS {
		backend["transport"] = map[string]any{
			"protocol": "http",
			"tls": map[string]any{
				"insecure_skip_verify": true,
				"server_name":          requestHostPlaceholder,
			},
		}
		backend["headers"] = map[string]any{
			"request": map[string]any{
				"set": map[string]any{"Host": []any{requestHostPlaceholder}},
			},
		}
	}
	handlers = append(handlers, backend)
	route := map[string]any{
		"@id":    routeID(r.Host),
		"match":  []any{map[string]any{"host": []any{r.Host}}},
		"handle": handlers,
	}
	body, err := json.Marshal(route)
	if err != nil {
		return err
	}
	path, err := d.httpRouteInsertPath(ctx, r.Host)
	if err != nil {
		return err
	}
	return d.adminWrite(ctx, http.MethodPut, path, body)
}

// httpRouteInsertPath decides WHERE a per-host http route for host must be inserted so
// it lands where the read side (collectLeaves) enumerates per-host routes — and where
// unexpose/Adopt later find it by @id. The decision is PER-ZONE (how the host's OWN
// zone is shaped on this edge), not per-edge — a real edge can route some zones via
// wildcard subroutes and keep others flat:
//
//   - The host's zone is a WILDCARD SUBROUTE (a *.zone subroute COVERS the host — the
//     real home/front shape): insert at index 0 of that subroute
//     → …/routes/<w>/handle/<h>/routes/0. Mirrors collectLeaves.
//   - The host's zone is FLAT, or the edge is flat/greenfield: keep the historical
//     top-level index-0 insert → …/servers/<srv>/routes/0. "Flat zone" = the edge has a
//     flat top-level per-host route in the same zone (so the new host joins its flat
//     siblings), OR the edge has no wildcard subroutes at all, OR the managed server is
//     absent (path-creating PUT).
//   - REFUSE loudly when: more than one wildcard subroute covers the host's zone
//     (ambiguous), OR the edge IS subroute-structured but the host's zone is entirely
//     absent (no covering wildcard AND no flat sibling) — flat-inserting a stray
//     per-host route into a subroute-structured edge is the write-side defect the live
//     trial caught, so crenel declares it rather than silently misplacing the route.
func (d *Driver) httpRouteInsertPath(ctx context.Context, host string) (string, error) {
	flat := fmt.Sprintf("/config/apps/http/servers/%s/routes/0", d.server)
	cfg, err := d.fetchConfig(ctx)
	if err != nil {
		return "", err
	}
	srv, ok := cfg.Apps.HTTP.Servers[d.server]
	if !ok {
		return flat, nil // managed server absent: path-creating top-level PUT (greenfield)
	}

	anyWildcardSubroute := false
	flatSiblingInZone := false
	type insertLoc struct{ wIdx, hIdx int }
	var covering []insertLoc
	for i, rt := range srv.Routes {
		hIdx, isSub := rt.subrouteHandlerIndex()
		for _, m := range rt.Match {
			for _, hm := range m.Host {
				switch {
				case isWildcardHost(hm) && isSub:
					// A wildcard zone routed into a subroute — a nest target.
					anyWildcardSubroute = true
					if wildcardCovers(hm, host) {
						covering = append(covering, insertLoc{wIdx: i, hIdx: hIdx})
					}
				case !isWildcardHost(hm) && sameZone(hm, host):
					// A flat top-level per-host route in the host's OWN zone — evidence the
					// zone is represented FLAT on this edge (the new host joins it).
					flatSiblingInZone = true
				}
			}
		}
	}

	switch len(covering) {
	case 1:
		return fmt.Sprintf("/config/apps/http/servers/%s/routes/%d/handle/%d/routes/0",
			d.server, covering[0].wIdx, covering[0].hIdx), nil
	case 0:
		if !anyWildcardSubroute || flatSiblingInZone {
			return flat, nil // flat/greenfield edge, or the host's zone is flat here
		}
		return "", fmt.Errorf("caddy insert %s: this edge routes per-host services inside wildcard *.zone "+
			"subroutes, but neither a wildcard nor a flat route covers this host's zone — refusing to flat-insert "+
			"a stray per-host route into a subroute-structured edge (add the zone's wildcard subroute on the edge, "+
			"or expose this host on its flat zone)", host)
	default:
		return "", fmt.Errorf("caddy insert %s: %d wildcard subroutes cover this host's zone — ambiguous insert "+
			"point, refusing to guess which owns it", host, len(covering))
	}
}

// insertLayer4Route PUTs a single @id-tagged SNI-passthrough route at the front of
// the managed layer4 server. The route matches by tls.sni and proxies the raw TLS
// connection (no termination) to the backend. ADDITIVE: it touches only the
// crenel-l4 server and its @id-tagged routes — the http app (routes, deny, TLS) is
// never read or rewritten. Creating the layer4 server if absent mirrors Caddy's
// path-creating PUT semantics.
func (d *Driver) insertLayer4Route(ctx context.Context, r model.Route) error {
	route := map[string]any{
		"@id":   l4RouteID(r.Host),
		"match": []any{map[string]any{"tls": map[string]any{"sni": []any{r.Host}}}},
		"handle": []any{map[string]any{
			"handler":   handlerL4Proxy,
			"upstreams": []any{map[string]any{"dial": []any{r.Upstream.Address}}},
		}},
	}
	body, err := json.Marshal(route)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/config/apps/layer4/servers/%s/routes/0", defaultL4Server)
	return d.adminWrite(ctx, http.MethodPut, path, body)
}

// maxHostMatchDeletes bounds the host-match removal sweep (a host normally has exactly
// one route; the cap is a runaway guard, never reached in practice).
const maxHostMatchDeletes = 8

// deleteRoute removes the http route(s) for host. It first deletes by crenel's `@id`
// (`crenel-route-<host>`) — the route a granular insert tagged — then SWEEPS by host
// match to remove any remaining route for host that carries NO matching `@id`.
//
// The host-match sweep is what makes durable-edge UNEXPOSE work: after a durable persist
// reload, the live route is re-derived from the on-disk Caddyfile, which carries no JSON
// `@id` (a Caddyfile `handle` block has none), so the `/id/` delete above is a no-op and
// the route would survive — failing read-back-verify (the rollback the live durable-persist
// trial hit). Deleting by the route's config PATH instead removes it regardless of `@id`.
// It is scoped to the host crenel is unexposing (the gate already approved mutating it), so
// it never touches another host's route. If the route is still present after the bounded
// sweep, it errors — so the transaction's read-back-verify / rollback still catches a
// genuine failure rather than silently leaving a route up.
func (d *Driver) deleteRoute(ctx context.Context, host string) error {
	removed, err := d.deleteByID(ctx, routeID(host))
	if err != nil {
		return err
	}
	if removed {
		return nil // the @id-tagged route existed and was deleted — no read needed
	}
	// The @id delete found nothing (404). On a NON-durable edge that means the route is
	// genuinely absent (a fresh crenel route always carries the @id) — unchanged behavior,
	// and no structural read (so the never-hang wedge model is preserved). Only a
	// DURABLE-FILE edge produces an @id-LESS live route: the durable persist reload
	// re-derives it from the on-disk Caddyfile (no JSON @id). There, sweep by host match.
	if d.persistPath == "" {
		return nil
	}
	for i := 0; i < maxHostMatchDeletes; i++ {
		path, found, ferr := d.findHostRoutePath(ctx, host)
		if ferr != nil {
			return ferr
		}
		if !found {
			return nil
		}
		if derr := d.deleteByPath(ctx, path); derr != nil {
			return derr
		}
	}
	return fmt.Errorf("caddy delete %s: route still present after %d host-match deletes", host, maxHostMatchDeletes)
}

// findHostRoutePath returns the admin-API config PATH of the FIRST live route that serves
// host exactly — either a flat top-level per-host route, or a per-host route nested inside
// a covering wildcard `*.zone` subroute (where the real edges keep per-host routing). It
// NEVER returns the wildcard route itself (that would tear down the whole zone): a wildcard
// matcher is not an exact host. found=false when no such route exists.
func (d *Driver) findHostRoutePath(ctx context.Context, host string) (string, bool, error) {
	cfg, err := d.fetchConfig(ctx)
	if err != nil {
		return "", false, err
	}
	srv, ok := cfg.Apps.HTTP.Servers[d.server]
	if !ok {
		return "", false, nil
	}
	// 1. Flat top-level per-host route (exact host match, not a wildcard route).
	for i, rt := range srv.Routes {
		if routeHasExactHost(rt, host) {
			return fmt.Sprintf("/config/apps/http/servers/%s/routes/%d", d.server, i), true, nil
		}
	}
	// 2. Per-host route nested inside a covering wildcard subroute.
	for i, rt := range srv.Routes {
		hIdx, isSub := rt.subrouteHandlerIndex()
		if !isSub || !routeWildcardCovers(rt, host) {
			continue
		}
		for j, sub := range rt.Handle[hIdx].Routes {
			if routeHasExactHost(sub, host) {
				return fmt.Sprintf("/config/apps/http/servers/%s/routes/%d/handle/%d/routes/%d",
					d.server, i, hIdx, j), true, nil
			}
		}
	}
	return "", false, nil
}

// routeHasExactHost reports whether rt's matchers list host literally (not via a wildcard
// pattern). Case-insensitive.
func routeHasExactHost(rt JSONRoute, host string) bool {
	lh := strings.ToLower(host)
	for _, m := range rt.Match {
		for _, h := range m.Host {
			if !isWildcardHost(h) && strings.ToLower(h) == lh {
				return true
			}
		}
	}
	return false
}

// routeWildcardCovers reports whether rt is a wildcard route whose `*.zone` matcher covers
// host (so a per-host route for host would live inside its subroute).
func routeWildcardCovers(rt JSONRoute, host string) bool {
	for _, m := range rt.Match {
		for _, h := range m.Host {
			if isWildcardHost(h) && wildcardCovers(h, host) {
				return true
			}
		}
	}
	return false
}

// deleteByPath issues DELETE on a config PATH (e.g. a nested route index), treating a 404
// as already-absent (idempotent).
func (d *Driver) deleteByPath(ctx context.Context, path string) error {
	status, msg, err := d.doAdmin(ctx, http.MethodDelete, path, "", nil, d.writeTimeout)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("admin DELETE %s returned %d: %s", path, status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// deleteLayer4Route removes the managed layer4 (passthrough) route for host by its
// @id, idempotently.
func (d *Driver) deleteLayer4Route(ctx context.Context, host string) error {
	_, err := d.deleteByID(ctx, l4RouteID(host))
	return err
}

// deleteByID issues DELETE /id/<id>, treating a 404 (missing id) as already-absent
// (idempotent). It reports whether a route was actually removed (a 2xx) vs not found (a
// 404), so the caller can skip a redundant structural read when the @id delete sufficed.
func (d *Driver) deleteByID(ctx context.Context, id string) (removed bool, err error) {
	status, msg, err := d.doAdmin(ctx, http.MethodDelete, "/id/"+id, "", nil, d.writeTimeout)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil // already absent — idempotent
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("admin DELETE /id/%s returned %d: %s", id, status, strings.TrimSpace(string(msg)))
	}
	return true, nil
}

// adminWrite performs a structured admin-API mutation, bounded by the write
// timeout. As with /load, a 2xx is necessary but not sufficient — core
// read-back-verifies.
func (d *Driver) adminWrite(ctx context.Context, method, path string, body []byte) error {
	ct := ""
	if body != nil {
		ct = "application/json"
	}
	status, msg, err := d.doAdmin(ctx, method, path, ct, body, d.writeTimeout)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("admin %s %s returned %d: %s", method, path, status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// load POSTs a Caddyfile to /load, bounded by the write timeout. A non-2xx is an
// error; a 2xx is necessary but NOT sufficient (the silent-reload footgun) —
// hence read-back-verify.
func (d *Driver) load(ctx context.Context, caddyfile string) error {
	status, msg, err := d.doAdmin(ctx, http.MethodPost, "/load", "text/caddyfile", []byte(caddyfile), d.writeTimeout)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("admin /load returned %d: %s", status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (d *Driver) fetchConfig(ctx context.Context) (Config, error) {
	cfg, _, err := d.fetchConfigRaw(ctx)
	return cfg, err
}

func (d *Driver) fetchConfigRaw(ctx context.Context) (Config, string, error) {
	status, raw, err := d.doAdmin(ctx, http.MethodGet, "/config/", "", nil, d.readTimeout)
	if err != nil {
		return Config{}, "", fmt.Errorf("caddy admin GET /config/: %w", err)
	}
	if status != http.StatusOK {
		return Config{}, "", fmt.Errorf("caddy admin GET /config/ returned %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var cfg Config
	// An empty config ("null" or "") is valid: it just means nothing is loaded.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return Config{}, "", fmt.Errorf("caddy admin GET /config/: parse: %w", err)
		}
	}
	return cfg, string(raw), nil
}

// doAdmin issues a single admin-API request bounded by an explicit per-operation
// timeout derived from ctx, delegating the WIRE call to the configured transport
// (Direct / ssh-exec / ssh-tunnel). The timeout and the wedge classification live
// HERE, above the transport seam, so they apply uniformly however the call travels:
// a bounded-timeout failure (context deadline or a net timeout) is classified as
// ErrAdminUnresponsive with a recovery hint, so the driver reports a wedged admin
// API instead of hanging — and callers can branch on it (e.g. skip compensating
// reloads). The transport reads the full response body before returning.
func (d *Driver) doAdmin(ctx context.Context, method, path, contentType string, body []byte, timeout time.Duration) (int, []byte, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, msg, err := d.xport.Do(tctx, method, path, contentType, body)
	if err != nil {
		return 0, nil, d.classify(method, path, timeout, err)
	}
	return status, msg, nil
}

// classify turns a transport error into a clearer one: a bounded-timeout failure
// becomes ErrAdminUnresponsive (with a recovery hint); anything else is returned
// as-is.
func (d *Driver) classify(method, path string, timeout time.Duration, err error) error {
	var nerr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()) {
		return fmt.Errorf("%s %s: %w after %s: the admin API did not respond — it may be mid-reload or wedged. "+
			"If it stays unresponsive, recover the edge (e.g. `docker restart caddy-edge`), which reloads the "+
			"on-disk config and clears the wedge", method, path, ErrAdminUnresponsive, timeout)
	}
	return err
}
