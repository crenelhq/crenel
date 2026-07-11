package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// EdgeBinding binds a named edge in the topology to its provider and its
// projection predicate (M4). Fronts reports whether this edge is responsible for
// a given service — i.e. whether an Expose of that service should land here. A nil
// Fronts means "fronts everything" (the degenerate single-edge / back-compat
// case).
//
// Per-edge origins differ in the real world: the home edge proxies a LAN IP, the
// VPS edge proxies via Tailscale. That difference lives in each provider's own
// OriginResolver (injected at wiring); Fronts only decides PARTICIPATION, the
// resolver decides the ADDRESS.
type EdgeBinding struct {
	Name     string
	Provider ports.EdgeProvider
	Fronts   func(service string) bool

	// AuthDownstream marks this edge as the FRONT of an edge CHAIN: it fronts a
	// DOWNSTREAM edge that enforces forward-auth, so this edge legitimately carries
	// NO auth handler of its own. When set, core asserts "auth lives downstream" for
	// this edge's hosts — status labels them `auth: downstream` and audit SUPPRESSES
	// the public_without_auth warning (which would otherwise fire spuriously on a
	// front edge). It does NOT change routing or the default-deny; it is a posture
	// assertion about where auth is enforced in the chain. A genuine terminal edge
	// leaves this false so the warning still fires. See docs/internal/DESIGN.md "Chain topology".
	AuthDownstream bool

	// IngressKind DECLARES this edge's off-edge reachability mechanism (a tunnel /
	// overlay fronts it), when the operator knows it. It is the robust signal for the
	// axis-4 "exposed isn't a public port" gap: a cloudflared / Tailscale-funnel edge
	// is PUBLIC even though the local proxy may bind localhost, so reading only the
	// listener would MISREAD it internal. Empty => fall back to IngressConfigPath
	// detection, then to whatever the driver reported. See resolveIngressKind.
	IngressKind model.IngressKind
	// IngressConfigPath points crenel at a tunnel/overlay config file to SCAN for an
	// ingress signature (a cloudflared config.yml, a Tailscale serve.json). When the
	// file is present and recognized, the edge's IngressKind is detected; present but
	// unrecognized => IngressUnknown (declared external, mechanism undetermined),
	// never assumed internal. Empty => no file detection.
	IngressConfigPath string

	// DownstreamEdge marks this binding the FRONT of an edge CHAIN (P4): it names
	// another binding in the topology that this edge FORWARDS to. When set, core
	// FOLLOWS THROUGH each chain-forward route to the downstream edge to resolve the
	// host's real backend + observed auth (chain.go). Empty => not a chain front (the
	// ordinary terminal edge). Distinct from the parallel multi-edge "double-write":
	// a chain is sequential (front → downstream → origin), not peer edges.
	DownstreamEdge string
	// DownstreamAddress is the address (host or host:port) the front dials to reach
	// the downstream edge; a front leaf whose backend HOST matches it is a chain
	// forward, and any other leaf is a terminal origin the front serves itself. Empty
	// => every non-mesh data-plane route is treated as a forward (the "pure front"
	// case). Only consulted when DownstreamEdge is set.
	DownstreamAddress string
	// DownstreamScheme declares the scheme the front dials the downstream over:
	// "https" (re-originate TLS to a `:443` downstream, preserving Host) or "http"
	// (plain). Empty => INFER from DownstreamAddress (a `:443` dial is https). It
	// drives whether a synthesized chain-FORWARD route renders upstream TLS + Host —
	// the front-leg HTTPS gap the live cross-chain trial caught (TRIAL-FIX-4): a bare
	// HTTP forward to a `:443` downstream gets a 400. Only consulted when DownstreamEdge
	// is set. See chain_write.go forwardRoute and docs/internal/DESIGN.md "Transport / Connection".
	DownstreamScheme string
}

// resolveIngressKind returns the edge's effective ingress posture for status/audit:
// an operator-DECLARED kind wins; else a signature detected from the configured
// ingress file; else whatever the driver itself reported on live; else the
// generator rule below. "" (unset) means an ordinary public listener — no
// off-edge mechanism. Centralized so status and audit agree on one verdict per edge.
func (b EdgeBinding) resolveIngressKind(live model.LiveEdgeState) model.IngressKind {
	if b.IngressKind != "" {
		return b.IngressKind
	}
	if b.IngressConfigPath != "" {
		if k := detectIngressFile(b.IngressConfigPath); k != "" {
			return k
		}
	}
	if live.IngressKind != "" {
		return live.IngressKind
	}
	// Pangolin ⇒ overlay-ingress AUTO-DECLARATION (audit-any-edge §4.3, M-A4):
	// Pangolin's whole point is publishing resources over its WireGuard (newt)
	// tunnels, so a Pangolin-generated edge is externally fronted by an overlay
	// even when nothing was declared. Declared-not-observed on purpose: crenel
	// reads Traefik, not Pangolin's tunnel state — whether the overlay publishes
	// ADDITIONAL hostnames stays not-verifiable-here (the ingress_external finding
	// says so). An operator declaration above always wins ("unless declared
	// otherwise"), and never assumed-internal is the register's axis-4 rule.
	if live.Generator == "pangolin" {
		return model.IngressOverlay
	}
	return ""
}

// resolveIngressHosts recovers this edge's PER-HOST tunnel ingress mapping (the exact
// published hostnames + wildcard zones) when a tunnel config is configured and crenel can
// parse it — so audit resolves each host's external reachability by OBSERVATION instead of
// the coarse edge-level UNKNOWN. parsed=false (no config / unparseable / declared-only)
// keeps the safe coarse fallback; a mapping is never fabricated.
func (b EdgeBinding) resolveIngressHosts(live model.LiveEdgeState) (exact map[string]bool, wildcards []string, parsed bool) {
	if b.IngressConfigPath == "" {
		return nil, nil, false
	}
	return tunnelIngressHosts(b.IngressConfigPath)
}

// fronts reports whether the binding fronts service (nil predicate => yes).
func (b EdgeBinding) fronts(service string) bool {
	return b.Fronts == nil || b.Fronts(service)
}

// Engine wires one or more edges and zero or more DNS providers behind the
// vendor-agnostic verbs. It holds no persisted desired state.
type Engine struct {
	// Edges is the edge topology. A single-edge engine holds exactly one binding;
	// multi-edge (home + VPS double-write) holds several. core never imports a
	// driver — bindings are constructed at cmd.
	Edges []EdgeBinding
	DNS   []ports.DNSProvider
	// Zone is the DNS zone used to derive a host from a service name when the
	// caller does not supply an explicit host (e.g. "example.com").
	Zone string

	// Rollback enables compensating rollback when a multi-provider apply
	// partially fails or read-back verification fails (M1). Default true.
	Rollback bool

	// Force is the operator escape hatch for the refuse-to-manage ownership gate: it
	// permits mutating a route whose ownership is UNKNOWN (crenel could not determine
	// who owns it) when the operator has verified out-of-band that crenel may manage
	// it — load-bearing-on-the-human. It NEVER permits mutating a route/edge known to
	// be FOREIGN (generator-owned): that would be reverted, so there is no safe force.
	// Default false. See TOPOLOGY-RISK-REGISTER §4.5.
	Force bool

	// AllowUnverified is the operator escape hatch for the runtime-verify-honesty
	// gate (audit F2): a file-based edge (Traefik/nginx) with no runtime probe
	// configured can only confirm its OWN written file, never the running daemon.
	// Without this set, Apply/Rename/ApplyDeclarative REFUSE (rolling back the write)
	// when any participating edge comes back RuntimeVerifyUnavailable, rather than
	// let an unconfirmed write stand as a silent green. Default false — load-bearing-
	// on-the-human, same spirit as Force. See UnverifiedWriteError.
	AllowUnverified bool

	// ReadOnly declares this engine audit-only: every mutating verb (expose/unexpose/
	// apply/reconcile/import/rename/resume/ack/unack) refuses BEFORE planning with
	// ErrReadOnlyEngine, and no Persister/Adopter capability is ever invoked. Set from
	// settings `read_only: true` ("I only ever audit this edge"); the zero-config
	// audit-target mode forces it. It is the posture key for the foreign_managed_readonly
	// re-frame in Audit (§3.3 of the audit-any-edge design) — the downgrade is keyed
	// STRICTLY on this field so a writable engine's ownership warning never blunts
	// (risk A.7). Reads are untouched: audit was always read-only. Default false.
	ReadOnly bool

	// TargetMode declares this engine was synthesized from a positional audit
	// TARGET (`crenel audit <url|path>`, audit-any-edge §2) — one edge, no settings
	// topology, no DNS, no origins, ReadOnly forced. It only feeds the
	// AuditScope.TargetMode declaration (the "zero-config target" Scope line); it
	// gates no behavior of its own — the posture is carried by ReadOnly, which the
	// target bootstrap always sets alongside it. Default false.
	TargetMode bool

	// DeclaredInternal is the operator's explicit `--internal` declaration (risk
	// A.4, M-A6): "this edge is NOT internet-facing." It downgrades the
	// ASSUMPTION-derived public_without_auth warning (the no-DNS "edge route ⇒
	// public" boundary default) to an ok-severity `exposure_unscoped` finding —
	// declared, not observed, so the fact still prints, only the severity changes
	// (the --auth none pattern: a forced spoken choice, never a silent default).
	// It NEVER overrides OBSERVED public-ness (a tunnel-published host, or a host
	// covered by managed public DNS): a declaration cannot beat an observation.
	// cmd refuses the flag outright when a public DNS provider is configured — an
	// edge with managed public records is internet-facing by construction.
	// Default false.
	DeclaredInternal bool

	// InternalScope is the operator's per-SERVICE internal-only declaration for a
	// split-horizon topology (set at wiring from structured origins entries —
	// `{"addr": ..., "scope": "internal"}`): the named services are deliberately
	// NOT publicly reachable. Distinct from DeclaredInternal (a whole-EDGE audit
	// posture): this is a per-service demand gate PLUS a guarantee —
	//   - Plan/reconcile never demand (or create) a record for the service at a
	//     PUBLIC-scope DNS provider;
	//   - a chain FRONT edge is never asked to forward it (roleFor yields
	//     roleNone instead of roleForward, so the missing_route "half-present
	//     chain" demand cannot fire for it);
	//   - internal legs (internal DNS records, the downstream edge route) stay
	//     fully managed and verified, byte-identically to before;
	//   - audit ENFORCES the declaration: an internal-scope service that IS
	//     publicly reachable (explicit public DNS record, or a chain-front
	//     route/forward, or a tunnel-published host) is a CRITICAL finding —
	//     internal_scope_public_exposure. See docs/internal/DESIGN.md
	//     "Internal-scope services".
	// Keys use the same service keying as the origins maps / Fronts predicates
	// (bare name in the default zone, FQDN otherwise). Nil/empty = no internal-
	// scope services (byte-identical pre-feature behavior).
	InternalScope map[string]bool
}

// internalScoped reports whether service is declared internal-only. The key
// convention matches the origins maps (see InternalScope).
func (e *Engine) internalScoped(service string) bool { return e.InternalScope[service] }

// InternalScopedHost reports whether host belongs to an internal-only service —
// the display hook for status/HUD `[internal]` tagging (cmd) and any host-keyed
// caller. It maps the host back through the same serviceOf derivation the
// projection predicates use, so tagging and gating can never disagree.
func (e *Engine) InternalScopedHost(host string) bool {
	return e.internalScoped(e.serviceOf(host))
}

// New builds a single-edge Engine with compensating rollback enabled by default.
// The edge fronts everything (back-compat: behaves exactly as the pre-M4 engine).
func New(edge ports.EdgeProvider, zone string, dns ...ports.DNSProvider) *Engine {
	return NewMulti([]EdgeBinding{{Name: edge.Name(), Provider: edge}}, zone, dns...)
}

// NewMulti builds a multi-edge Engine. Each binding's Name defaults to its
// provider name when empty. Rollback is enabled by default.
func NewMulti(edges []EdgeBinding, zone string, dns ...ports.DNSProvider) *Engine {
	for i := range edges {
		if edges[i].Name == "" {
			edges[i].Name = edges[i].Provider.Name()
		}
	}
	return &Engine{Edges: edges, DNS: dns, Zone: zone, Rollback: true}
}

// binding returns the EdgeBinding with the given topology name.
func (e *Engine) binding(name string) (EdgeBinding, bool) {
	for _, b := range e.Edges {
		if b.Name == name {
			return b, true
		}
	}
	return EdgeBinding{}, false
}

// BuildOp constructs the transient Op for a verb+service. The host is derived as
// "<service>.<zone>" unless service already looks like an FQDN (contains a dot).
//
// The returned Op is the ONLY notion of desired state and is never persisted.
func (e *Engine) BuildOp(verb model.Verb, service string) model.Op {
	service = strings.TrimSpace(service)
	host := service
	if !strings.Contains(service, ".") && e.Zone != "" {
		host = service + "." + e.Zone
	}
	return model.Op{Verb: verb, Service: service, Host: host}
}

// ResolveOp is the MULTI-ZONE-aware front door for op construction (the CLI and
// the MCP write tools come through here). A full FQDN always works, verbatim.
// A BARE name resolves against the MANAGED zones (top-level Zone + every
// provider-declared zone):
//
//   - the top-level zone stays the DEFAULT derivation (decision: no behavior
//     change for any existing config) — a bare name with no contrary evidence
//     derives to "<service>.<Zone>" exactly as BuildOp always has;
//   - evidence that the name lives in a SPECIFIC zone is an edge with an
//     explicit origins map fronting either the bare name (⇒ the default zone —
//     bare keys have always meant "<service>.<Zone>") or the per-zone FQDN
//     "<service>.<z>" (the only way a non-default-zone service could be keyed
//     before zones-list);
//   - evidence for exactly ONE non-default zone (and none for the default)
//     redirects the bare name there — Service AND Host become the FQDN, so the
//     Fronts/origins lookups hit the key that actually exists;
//   - evidence under 2+ zones is REFUSED loudly, listing every candidate FQDN:
//     a bare name that exists in several zones must be said out loud.
//
// Engines whose every edge fronts-everything (nil predicate) carry no keying
// evidence at all and always take the default derivation — unchanged.
func (e *Engine) ResolveOp(verb model.Verb, service string) (model.Op, error) {
	service = strings.TrimSpace(service)
	if strings.Contains(service, ".") {
		// FQDN: verbatim, exactly like BuildOp. (It may still be a bare
		// multi-label service name; the zone routing treats it as a host either
		// way, which is the pre-zones contract.)
		return e.BuildOp(verb, service), nil
	}
	// Candidate zones with EVIDENCE, in stable managed-zone order (default first).
	var cands []string // the candidate HOSTS, one per evidenced zone
	defaultEvidence := e.Zone != "" && (e.explicitlyFronts(service) || e.explicitlyFronts(service+"."+e.Zone))
	if defaultEvidence {
		cands = append(cands, service+"."+e.Zone)
	}
	var nonDefault []string
	for _, z := range e.providerZones() {
		if strings.EqualFold(z, e.Zone) {
			continue
		}
		if e.explicitlyFronts(service + "." + z) {
			nonDefault = append(nonDefault, service+"."+z)
		}
	}
	cands = append(cands, nonDefault...)
	switch {
	case len(cands) >= 2:
		return model.Op{}, fmt.Errorf("bare service %q is ambiguous across managed zones — say the host out loud: %s", service, strings.Join(cands, " | "))
	case len(cands) == 1 && !defaultEvidence:
		// Uniquely known under one NON-default zone: resolve to that FQDN for
		// both Service and Host so the origins/Fronts key that exists is the
		// one every downstream lookup uses.
		return model.Op{Verb: verb, Service: cands[0], Host: cands[0]}, nil
	default:
		// Default-zone evidence, or no evidence anywhere: the classic derivation.
		return e.BuildOp(verb, service), nil
	}
}

// Plan computes the unified ChangeSet (every participating edge + DNS) for an op
// against live state. It FANS OUT across the edge topology (M4): for each edge
// that fronts the op's service it reads that edge's live state and plans against
// it, producing one EdgePlan per participating edge.
//
// PROJECTION: an edge participates iff it fronts the service. For Expose this
// means the route lands only on edges responsible for the service; an Expose that
// no edge fronts is an error (likely an unknown service). For Unexpose, a
// fronting edge that does not currently hold the host simply yields an empty
// change (the driver no-ops).
//
// cs.DNS is kept POSITIONALLY ALIGNED with e.DNS — one entry per provider, in
// provider order, including empty changes. Apply and the ordering logic rely on
// cs.DNS[i] belonging to e.DNS[i]; dropping empties here would misalign them.
func (e *Engine) Plan(ctx context.Context, op model.Op) (model.ChangeSet, error) {
	// Auth is HTTP-only: refuse a forward-auth policy on a passthrough/mesh exposure
	// loudly here, before any edge fan-out, so every path refuses identically.
	if err := model.ValidateAuth(op.Mode, op.Auth); err != nil {
		return model.ChangeSet{}, err
	}
	// Internal-scope vs an EXPLICIT public appointment: `--scope public` (or
	// `--dns public`) on a service declared internal-only is a direct
	// contradiction of the config — refused loudly here rather than silently
	// honoring either side. (An unset scope list is fine: the public providers
	// are simply skipped below, the declared posture.)
	if e.internalScoped(op.Service) {
		for _, sc := range op.Scopes {
			if sc == model.ScopePublic {
				return model.ChangeSet{}, fmt.Errorf("service %q is declared scope internal in origins — an explicit public DNS appointment contradicts it; change the declaration or drop --scope/--dns public", op.Service)
			}
		}
	}
	cs := model.ChangeSet{Op: op}
	participating := 0
	for _, b := range e.Edges {
		// Edge appointment (Op.Edges): restrict the fan-out to the named edge(s),
		// through the same predicate the declarative path uses for Exposure.Edges.
		if !edgeSelected(op.Edges, b.Name) {
			continue
		}
		role := e.roleFor(b, op.Service)
		if role == roleNone {
			continue
		}
		participating++
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return model.ChangeSet{}, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		// CHAIN-AWARE PROJECTION (P4-write): a TERMINAL edge plans the real route to its
		// resolved origin via its own driver (carrying op.Auth — auth lands where the host
		// is SERVED); a chain FRONT instead gets a synthesized FORWARD route to the
		// downstream edge (no auth). For a non-chain op every participant is terminal, so
		// this is identical to the pre-P4-write fan-out.
		var ec model.EdgeChange
		switch role {
		case roleTerminal:
			sub, err := b.Provider.Plan(op, live)
			if err != nil {
				return model.ChangeSet{}, fmt.Errorf("edge plan (%s): %w", b.Name, err)
			}
			ec = sub.Edge
		case roleForward:
			ec, err = b.planForward(op, live)
			if err != nil {
				return model.ChangeSet{}, fmt.Errorf("chain forward plan (%s): %w", b.Name, err)
			}
		}
		cs.Edges = append(cs.Edges, model.EdgePlan{
			Edge:   b.Name,
			Driver: b.Provider.Name(),
			Change: ec,
		})
	}
	if op.Verb == model.Expose && participating == 0 {
		if len(op.Edges) > 0 {
			return model.ChangeSet{}, fmt.Errorf("no configured edge in %v fronts service %q", op.Edges, op.Service)
		}
		return model.ChangeSet{}, fmt.Errorf("no configured edge fronts service %q", op.Service)
	}

	// Aggregate every DNS provider into the same ChangeSet, one per provider.
	// cs.DNS stays POSITIONALLY ALIGNED with e.DNS (see the doc comment): a DNS
	// scope NOT appointed by Op.Scopes contributes an EMPTY change in its slot
	// rather than being dropped — so `--scope internal` writes the internal record
	// and simply omits the public one (nothing "goes public"), without misaligning
	// the DNS slices Apply/verify index by position.
	for _, dp := range e.DNS {
		// Two independent skip predicates, composed (either leaves the positionally
		// aligned EMPTY change in this provider's slot):
		//  - scope appointment (Op.Scopes): `--scope internal` deliberately leaves
		//    the public provider alone;
		//  - zone routing (multi-zone): a provider whose declared zone does not
		//    cover the op's host is not asked for records at all — a zone-confined
		//    driver would refuse the out-of-zone write (its guard), and that refusal
		//    is the CORRECT posture in a two-zone topology, not an error;
		//  - internal-scope declaration: a service declared internal-only in origins
		//    NEVER gets a record at a public-scope provider — the standing,
		//    persisted twin of `--scope internal`, so the declared posture holds on
		//    every op without re-saying the flag.
		if !scopeSelected(op.Scopes, dp.Scope()) || !dnsCoversHost(dp, op.Host) ||
			(dp.Scope() == model.ScopePublic && e.internalScoped(op.Service)) {
			cs.DNS = append(cs.DNS, model.DNSChange{Scope: dp.Scope()})
			continue
		}
		// Residency gate (the residency selector, REFERENCE-ARCH §2): a non-default
		// residency class asks each INTERNAL provider for its own vantage-correct
		// target, so a participating internal provider that cannot resolve classes at
		// all must refuse LOUDLY here — silently writing its default edge_addr would
		// misdirect an entire vantage. Providers that DO resolve (ResidencyTargeter)
		// refuse an unknown class themselves inside DesiredRecords below; public
		// providers ignore residency by design (the public answer is class-invariant).
		if err := residencySupported(dp, op.Residency); err != nil {
			return model.ChangeSet{}, err
		}
		desired, err := dp.DesiredRecords(op)
		if err != nil {
			return model.ChangeSet{}, fmt.Errorf("dns %s desired records: %w", dp.Name(), err)
		}
		change, err := dp.Diff(ctx, op, desired)
		if err != nil {
			return model.ChangeSet{}, fmt.Errorf("dns %s diff: %w", dp.Name(), err)
		}
		cs.DNS = append(cs.DNS, change)
	}
	// NewPublic — the unified "about to go public" view — is a CORE concern, not a
	// per-edge-driver one: publicness depends on DNS scope, which the edge cannot
	// know. core recomputes it authoritatively here, overriding any provisional
	// value an edge driver set.
	cs.NewPublic = e.computeNewPublic(op, cs)
	return cs, nil
}

// computeNewPublic returns the hostnames this ChangeSet makes newly publicly
// reachable. "Public" means globally resolvable + reachable:
//   - When a public-scope DNS provider is managed, a host goes public when it
//     gains a public DNS record (it becomes resolvable from the whole internet).
//   - When no public DNS is managed, the edge IS the public boundary, so a host
//     gaining an edge route is the public exposure.
//
// Unexpose (decreasing exposure) never adds to NewPublic.
func (e *Engine) computeNewPublic(op model.Op, cs model.ChangeSet) []string {
	if op.Verb != model.Expose {
		return nil
	}
	hasPublicDNS := false
	for _, dp := range e.DNS {
		if dp.Scope() == model.ScopePublic {
			hasPublicDNS = true
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	if hasPublicDNS {
		for _, d := range cs.DNS {
			if d.Scope == model.ScopePublic {
				for _, rec := range d.Add {
					add(rec.Name)
				}
			}
		}
	} else {
		// No public DNS managed: the edge is the public boundary. A host goes
		// public when it gains a data-plane route (HTTP-proxy OR SNI passthrough) on
		// ANY edge — both expose the host to the world. A mesh-grant (identity-scoped)
		// exposure is the OPPOSITE of public, so it never counts.
		for _, ep := range cs.Edges {
			for _, r := range ep.Change.AddRoutes {
				if r.Upstream.Mode != model.ModeMeshGrant {
					add(r.Host)
				}
			}
		}
	}
	return out
}
