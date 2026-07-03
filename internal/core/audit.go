package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// wildcardRewrite is a wildcard DNS rewrite (pattern + answer value). Audit-internal:
// the parity check uses it to decide whether a wildcard on resolver R "covers" a host
// the other resolver only has as an explicit rewrite. See the dns_coverage_parity
// block in Audit for the value-mismatch caveat.
type wildcardRewrite struct {
	pattern string // lowercased, e.g. "*.homelab.example"
	value   string
}

// isWildcardName reports whether a DNS record name is a wildcard PATTERN (not a host).
// AdGuard's only documented wildcard form is a leading `*.` (single-label-prefix
// rewrite); the more permissive `Contains("*")` is the same answer for everything
// AdGuard returns, and is also conservative if a provider ever returns a different
// wildcard shape (it falls into the wildcard bucket rather than into explicit hosts).
func isWildcardName(name string) bool { return strings.Contains(name, "*") }

// wildcardBacksAnyExposed reports whether at least one exposed host falls under the
// wildcard pattern's zone. Used by `dns_without_edge_route`: a `*.zone` rewrite is a
// catch-all that backs ANY exposed host in .zone, so it's only "dangling" when nothing
// at all is exposed under its zone.
func wildcardBacksAnyExposed(pattern string, exposed map[string]bool) bool {
	pattern = strings.ToLower(pattern)
	if !strings.HasPrefix(pattern, "*.") {
		// An unusual wildcard shape we don't model (no `*.` prefix). Be conservative:
		// treat as not backing anything → existing dangling check still fires for it.
		return false
	}
	suffix := pattern[1:] // ".zone"
	for host := range exposed {
		if strings.HasSuffix(strings.ToLower(host), suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

// wildcardCovering returns the first wildcard in ws that covers host (and ok=true).
// Coverage = `*.zone` answers any name ending in `.zone` (suffix match; the audit
// purposely treats AdGuard's wildcard as suffix-covering, which is the SAFE side: if
// real DNS would resolve a host via the wildcard, the audit must consider it present).
func wildcardCovering(ws []wildcardRewrite, host string) (wildcardRewrite, bool) {
	h := strings.ToLower(host)
	for _, w := range ws {
		if !strings.HasPrefix(w.pattern, "*.") {
			continue
		}
		suffix := w.pattern[1:] // ".zone"
		// host must lie UNDER the wildcard zone (not be the apex itself).
		if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
			return w, true
		}
	}
	return wildcardRewrite{}, false
}

// boolSet builds a string-keyed bool set from any string-keyed map so we can reuse
// sortedKeys for deterministic iteration over either explicitValues or wildcardCovers.
func boolSet[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// sortedKeys returns the keys of a set in sorted order (deterministic output).
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Audit performs live-only invariant and cross-provider consistency checks. It
// reads, never writes, and never consults any stored desired state.
//
// Checks:
//   - default-deny invariant: the catch-all deny MUST be present on EVERY edge.
//   - cross-EDGE consistency (M4): a host exposed on one edge but missing from
//     another edge that ALSO fronts it (a half-applied double-write).
//   - cross-PROVIDER consistency: a public DNS record with no backing edge route
//     anywhere is a dangling exposure (critical); an exposed edge route with no
//     DNS record is exposed-but-unreachable-by-name (warning).
//   - (informational) count of exposed routes.
func (e *Engine) Audit(ctx context.Context) (AuditReport, error) {
	var rep AuditReport

	// Read every edge's live state once.
	type edgeLive struct {
		binding EdgeBinding
		hosts   map[string]bool
	}
	// ingressEdgePub holds an edge's RECOVERED tunnel ingress mapping (the exact published
	// hostnames), used after the read loop to flag a published host no edge serves.
	type ingressEdgePub struct {
		edge  string
		kind  model.IngressKind
		exact map[string]bool
	}
	var edges []edgeLive
	exposed := make(map[string]bool)                       // host exposed on ANY edge
	hostModes := make(map[string]map[model.RouteMode]bool) // host -> set of modes seen across edges
	hostAuth := make(map[string]bool)                      // host -> auth enforced (front OR observed downstream) on ANY edge
	hostAuthDownstream := make(map[string]bool)            // host -> auth ASSERTED downstream (unresolved/flag), not observed
	tunnelPublic := make(map[string]bool)                  // host -> OBSERVED publicly reachable via a tunnel's own ingress rules (P3)
	exposedOnPlainEdge := make(map[string]bool)            // host -> exposed on at least one edge WITHOUT parsed per-host ingress recovery (the "edge IS the public boundary" default applies)
	var tunnelEdges []ingressEdgePub                       // per-edge recovered tunnel mapping, for the dangling-route check
	totalRoutes := 0

	// Chain-aware (P4): read every edge once (shared with chain resolution) and resolve
	// each FRONT forward THROUGH to its downstream edge. A chain-target edge whose read
	// fails is tolerated (surfaced as edge_unreadable) instead of aborting.
	reads, err := e.readAll(ctx)
	if err != nil {
		return rep, err
	}
	cc := buildChainContext(reads)
	var chainResolved, chainUnresolved []string

	for _, b := range e.Edges {
		label := edgeLabel(b, len(e.Edges))
		rd := reads[b.Name]
		if rd.err != nil {
			// A chain-target edge crenel could not read: declare it UNKNOWN, never assume.
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "edge_unreadable",
				Message: fmt.Sprintf("%sedge could not be read (%v) — its routes and default-deny are UNKNOWN; any front edge forwarding here resolves 'downstream, not observed'",
					label, rd.err),
			})
			continue
		}
		live := rd.live
		hosts := make(map[string]bool, len(live.Routes))
		for _, r := range live.Routes {
			h := strings.ToLower(r.Host)
			hosts[h] = true
			exposed[h] = true
			if hostModes[h] == nil {
				hostModes[h] = map[model.RouteMode]bool{}
			}
			hostModes[h][r.Upstream.Mode] = true
			// Auth is resolved across the chain (P4): effectiveAuth returns a real/observed
			// policy (front auth or downstream-observed) => protected; model.AuthDownstream
			// for an UNRESOLVED forward or the legacy flag => asserted-not-observed
			// (suppressed-with-a-reason, never a silent drop); "" => no auth anywhere
			// (a downstream no-auth host is now correctly flagged, not blanket-suppressed).
			switch ea := cc.effectiveAuth(b, r); {
			case ea == model.AuthDownstream:
				hostAuthDownstream[h] = true
			case ea != "":
				hostAuth[h] = true
			}
			// Chain follow-through accounting: surface what was OBSERVED downstream vs.
			// declared unresolved, so the report is honest about chain coverage.
			if link := cc.resolveChain(b, r); link != nil {
				if link.Resolved {
					chainResolved = append(chainResolved, fmt.Sprintf("%s → %s:%s", r.Host, link.DownstreamEdge, link.DownstreamAddress))
				} else {
					chainUnresolved = append(chainUnresolved, fmt.Sprintf("%s (%s)", r.Host, link.Reason))
				}
			}

			// TLS/SNI consistency: an HTTP-proxy route's edge-served ServerName
			// (the cert host) should match the route host. A mismatch means the
			// edge would present a cert for a different name than requested.
			if r.Upstream.Mode == model.ModeHTTPProxy && r.Upstream.ServerName != "" &&
				!strings.EqualFold(r.Upstream.ServerName, r.Host) {
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "sni_host_mismatch",
					Message: fmt.Sprintf("%sroute %s serves SNI/cert name %q which does not match the host — TLS name mismatch",
						label, r.Host, r.Upstream.ServerName),
				})
			}
		}
		totalRoutes += len(live.Routes)
		edges = append(edges, edgeLive{binding: b, hosts: hosts})

		// Invariant 1 (per edge): catch-all default-deny — now TERNARY. A structural
		// default-deny "ENFORCED" claim is a statement about the ENTIRE config; it is
		// only sound if the entire config was parsed. So an ENFORCED claim requires
		// FullyParsed; with any unparsed routes the verdict DOWNGRADES to UNKNOWN (an
		// unparsed route could itself be a permissive catch-all). The hard invariant
		// becomes "deny is never FALSELY ENFORCED" — ENFORCED ⟹ FullyParsed. See
		// TOPOLOGY-RISK-REGISTER §4.4.
		switch live.DenyState() {
		case model.DenyEnforced:
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "ok",
				Code:     "deny_catchall_present",
				Message:  label + "default-deny holds: unmatched hosts get an implicit 404 (or explicit deny) — reachable only if explicitly routed",
			})
		case model.DenyUnknown:
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "deny_catchall_unknown",
				Message: fmt.Sprintf("%sdefault-deny is present but CANNOT be certified: %d route(s) not understood — an unparsed route could be a permissive catch-all, so deny is UNKNOWN, not ENFORCED",
					label, len(live.Unparsed)),
			})
		default: // model.DenyMissing
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "critical",
				Code:     "deny_catchall_missing",
				Message:  label + "FAIL-OPEN: a permissive host-less catch-all forwards unmatched hosts — anything is reachable regardless of explicit routes",
			})
		}

		// Coverage (detect-and-declare-unknown, register §4.3): when crenel could not
		// fully parse the config, EVERY other exposure/auth finding below is computed
		// over the UNDERSTOOD subset only — re-framed here so the report is honest.
		if len(live.Unparsed) > 0 {
			understood, total := live.Coverage()
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "coverage_incomplete",
				Message: fmt.Sprintf("%sread %d/%d routes — %d NOT UNDERSTOOD (%s) — exposure status INCOMPLETE; findings below cover the understood subset only",
					label, understood, total, len(live.Unparsed), unparsedLocators(live.Unparsed)),
			})
		}

		// Ownership (register §4.5): a route crenel cannot safely own — generated by
		// another tool (FOREIGN), or undetermined (UNKNOWN) — is mutation-blocked. The
		// audit surfaces it so the operator knows crenel will refuse to manage it.
		if live.Generator != "" {
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "ownership_unconfirmed",
				Message: fmt.Sprintf("%sedge is generated/owned by %s — crenel will NOT mutate it (an edit would be reverted on the next regeneration); manage it at the source",
					label, live.Generator),
			})
		} else if hosts := unconfirmedOwnershipHosts(live.Routes); len(hosts) > 0 {
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "ownership_unconfirmed",
				Message: fmt.Sprintf("%s%d route(s) have unconfirmed ownership (foreign/unknown) — crenel will refuse to mutate them: %s",
					label, len(hosts), strings.Join(hosts, ", ")),
			})
		}

		// Ingress (register §4.3): when reachability is decided OFF-edge (a tunnel/
		// overlay/CDN crenel cannot read), public/private status is determined somewhere
		// crenel cannot see — declared, never inferred from the local listener. The
		// posture is resolved from the edge's declared/detected ingress (P3), and the
		// finding fires for every EXTERNAL kind (tunnel/overlay/unknown), including the
		// declared-unknown case (externally fronted, mechanism undetermined).
		if ing := b.resolveIngressKind(live); ing.External() {
			detail := fmt.Sprintf("by %s", ing)
			if ing == model.IngressUnknown {
				detail = "by an EXTERNAL ingress crenel could not classify"
			}
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "ingress_external",
				Message: fmt.Sprintf("%sreachability for this edge's hosts is determined %s, not this edge's listener — "+
					"a host may be PUBLIC even if the local proxy binds localhost; public/private status is UNKNOWN to crenel",
					label, detail),
			})
			// Per-host recovery (P3 correctness): when crenel can read the tunnel's OWN
			// ingress rules, resolve each host's external reachability by OBSERVATION rather
			// than leaving the whole edge a coarse UNKNOWN. The published hosts crenel serves
			// are affirmatively PUBLIC (fed into public_without_auth); a published hostname no
			// edge serves is a DANGLING tunnel ingress (previously invisible). An unparseable
			// config recovers nothing and keeps only the coarse declaration above.
			parsedRecovery := false
			if exact, wildcards, parsed := b.resolveIngressHosts(live); parsed {
				parsedRecovery = true
				var observed []string
				for h := range hosts {
					if ingressPublishes(h, exact, wildcards) {
						tunnelPublic[h] = true
						observed = append(observed, h)
					}
				}
				sort.Strings(observed)
				if len(observed) > 0 {
					rep.Findings = append(rep.Findings, AuditFinding{
						Severity: "ok",
						Code:     "ingress_public_hosts",
						Message: fmt.Sprintf("%s%d host(s) OBSERVED publicly reachable via %s (recovered from its ingress rules): %s",
							label, len(observed), ing, strings.Join(observed, ", ")),
					})
				}
				tunnelEdges = append(tunnelEdges, ingressEdgePub{edge: b.Name, kind: ing, exact: exact})
			}
			// Edges WITHOUT parsed per-host recovery (declared-only / unparseable
			// external ingress) keep the conservative "the edge IS the public boundary"
			// default for THEIR hosts — public-via-this-edge stays exposed-by-default,
			// because crenel has no per-host evidence to do otherwise. Edges WITH
			// parsed recovery (cloudflared / Tailscale serve.json) opt OUT — the
			// recovery is authoritative for public-ness via this edge.
			if !parsedRecovery {
				for h := range hosts {
					exposedOnPlainEdge[h] = true
				}
			}
		} else {
			// Not externally fronted: the edge IS the local public boundary by
			// configuration, so all its hosts feed the conservative public default.
			for h := range hosts {
				exposedOnPlainEdge[h] = true
			}
		}

		// Durability (the persistence-model net): an EPHEMERAL edge — an admin-API edge
		// whose in-memory writes are not reconciled to the on-disk boot config — drops
		// crenel's managed routes on the next control-plane restart. The finding fires
		// only when crenel ACTUALLY has managed routes here (something a restart would
		// lose): a brownfield edge crenel merely reads has nothing ephemeral of its own
		// (the operator's own config persists their routes). It is the read-time analogue
		// of the write-path warning. See model.PersistenceModel.
		if live.Persistence.EphemeralWrites() {
			if n := crenelManagedRouteCount(live.Routes); n > 0 {
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "ephemeral_writes",
					Message: fmt.Sprintf("%s%d crenel-managed route(s) live on an EPHEMERAL edge (%s) — applied to the running admin API "+
						"but NOT to the on-disk config it boots from, so a control-plane restart DROPS them; configure a durable persist path",
						label, n, live.Persistence),
				})
			}
		}
	}

	// Chain follow-through (P4): one informational finding for the hosts crenel
	// OBSERVED through to their downstream destination, and one WARNING for the
	// forwards it could not resolve (downstream unreadable / not configured / a host
	// the downstream does not route). Surfacing both keeps the chain honest: a
	// resolved forward's auth is observed, an unresolved one is declared, never assumed.
	if len(chainResolved) > 0 {
		rep.Findings = append(rep.Findings, AuditFinding{
			Severity: "ok",
			Code:     "chain_resolved",
			Message: fmt.Sprintf("%d forwarded host(s) followed through to their downstream edge (real backend + observed auth): %s",
				len(chainResolved), strings.Join(chainResolved, ", ")),
		})
	}
	if len(chainUnresolved) > 0 {
		rep.Findings = append(rep.Findings, AuditFinding{
			Severity: "warning",
			Code:     "chain_unresolved",
			Message: fmt.Sprintf("%d forwarded host(s) could not be resolved downstream — destination/auth DECLARED 'downstream, not observed' (not assumed safe): %s",
				len(chainUnresolved), strings.Join(chainUnresolved, ", ")),
		})
	}

	// Dangling tunnel ingress (P3 correctness): a hostname a tunnel publishes to the
	// internet that NO edge serves — the request reaches the tunnel and 404s (or the rule
	// is stale). Previously invisible (crenel only flagged the edge external); now surfaced
	// by comparing the recovered ingress hostnames against the exposed set. Wildcards are
	// not flagged (they intentionally cover many unmanaged names).
	for _, te := range tunnelEdges {
		for _, host := range sortedKeys(te.exact) {
			if !exposed[strings.ToLower(host)] {
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "tunnel_route_without_edge",
					Message: fmt.Sprintf("%s publishes %s but no edge serves it — the tunnel exposes a hostname crenel has no route for (dangling/stale ingress)",
						te.kind, host),
				})
			}
		}
	}

	// Cross-EDGE consistency (M4): a host exposed somewhere but missing from
	// another edge that fronts its service is a half-applied double-write.
	if len(e.Edges) > 1 {
		for _, host := range sortedKeys(exposed) {
			service := e.serviceOf(host)
			for _, el := range edges {
				if el.binding.fronts(service) && !el.hosts[host] {
					rep.Findings = append(rep.Findings, AuditFinding{
						Severity: "warning",
						Code:     "edge_inconsistent_exposure",
						Message: fmt.Sprintf("host %s is exposed on another edge but MISSING from edge %q, which also fronts it — inconsistent double-write",
							host, el.binding.Name),
					})
				}
			}
		}
	}

	// Cross-edge MODE consistency (M6/M8): a host exposed with DIFFERENT modes on
	// different edges (e.g. HTTP-proxy on one, mesh-grant on another) has
	// inconsistent exposure semantics — almost certainly a misconfiguration.
	for _, host := range sortedKeys(exposed) {
		if len(hostModes[host]) > 1 {
			var modes []string
			for m := range hostModes[host] {
				modes = append(modes, m.String())
			}
			sort.Strings(modes)
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "edge_mode_mismatch",
				Message: fmt.Sprintf("host %s is exposed with conflicting modes across edges (%s) — inconsistent exposure semantics",
					host, strings.Join(modes, ", ")),
			})
		}
	}

	// isMeshGrant reports whether a host is exposed via an identity-mesh grant on
	// any edge (used to flag a misleading PUBLIC DNS record for it).
	isMeshGrant := func(host string) bool { return hostModes[host][model.ModeMeshGrant] }

	// dnsCovered tracks which exposed hosts have at least one DNS record, so we
	// can flag the reverse inconsistency (exposed but unreachable: no DNS).
	dnsCovered := make(map[string]bool)
	// publicDNSHosts tracks hosts with a PUBLIC-scope DNS record (globally
	// resolvable), and hasPublicDNS whether any public DNS provider is managed —
	// both feed the public-without-auth check below.
	publicDNSHosts := make(map[string]bool)
	hasPublicDNS := false
	for _, dp := range e.DNS {
		if dp.Scope() == model.ScopePublic {
			hasPublicDNS = true
		}
	}

	// internalCov captures each INTERNAL DNS provider's live records, split into
	// EXPLICIT host names (the "compare-as-a-host" set) and WILDCARD patterns (rewrites
	// like `*.zone` that ANSWER for any subdomain of zone, regardless of whether the
	// operator has an explicit entry for it). The split is what makes the parity check
	// wildcard-aware: a host h is PRESENT on a resolver if either its name is in the
	// explicit map OR some wildcard pattern there covers it — so a `*.homelab.example`
	// wildcard on home is NOT silently misread as "missing adguard.homelab.example" just
	// because home only has the wildcard entry and vps has the explicit one.
	type internalCov struct {
		name      string
		explicit  map[string]string  // explicit host (lowercased) → live value
		wildcards []wildcardRewrite // wildcard patterns, e.g. ("*.homelab.example" → IP)
	}
	var internalCovs []internalCov
	// allWildcards captures every wildcard rewrite across ALL DNS providers, used by
	// the dns_without_edge_route and edge_route_without_dns sibling checks to avoid
	// cry-wolfing on hosts the wildcard already backs/answers (mirrors the parity
	// check's wildcard-awareness; see also docs/DNS-DESIGN.md §12b.i).
	var allWildcards []wildcardRewrite

	// Cross-provider consistency: DNS records with no backing edge route.
	for _, dp := range e.DNS {
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			return rep, fmt.Errorf("read live dns (%s): %w", dp.Name(), err)
		}
		if dp.Scope() == model.ScopeInternal {
			cov := internalCov{name: dp.Name(), explicit: make(map[string]string, len(recs))}
			for _, rec := range recs {
				name := strings.ToLower(rec.Name)
				if isWildcardName(name) {
					cov.wildcards = append(cov.wildcards, wildcardRewrite{pattern: name, value: rec.Value})
				} else {
					cov.explicit[name] = rec.Value
				}
			}
			internalCovs = append(internalCovs, cov)
		}
		for _, rec := range recs {
			if isWildcardName(rec.Name) {
				allWildcards = append(allWildcards, wildcardRewrite{
					pattern: strings.ToLower(rec.Name),
					value:   rec.Value,
				})
			}
		}
		// Owned-record value drift: a provider that returns ONLY crenel-owned records (the
		// surgical Cloudflare marker boundary) can be value-checked for TARGET DRIFT — a
		// record crenel owns whose live value has diverged from what crenel would set is a
		// silent misdirect (right name, WRONG target) that the name-only checks below cannot
		// see. Marker-less providers (AdGuard) do not implement the capability, so this never
		// cries wolf on a legitimately-foreign rewrite. See ports.OwnedRecordReporter.
		ownsAll := false
		if r, ok := dp.(ports.OwnedRecordReporter); ok {
			ownsAll = r.OwnsAllLiveRecords()
		}
		for _, rec := range recs {
			dnsCovered[strings.ToLower(rec.Name)] = true
			host := strings.ToLower(rec.Name)
			if rec.Scope == model.ScopePublic {
				publicDNSHosts[host] = true
			}
			// Target drift on a crenel-OWNED record: its live value no longer matches the
			// value crenel would set (DesiredRecords). The name still resolves, so every
			// name-only check reads clean — but it points at the WRONG target (a public
			// record misdirects internet traffic → critical; an internal one → warning).
			if ownsAll {
				if desired, derr := dp.DesiredRecords(model.Op{Verb: model.Expose, Host: rec.Name}); derr == nil {
					for _, want := range desired {
						if strings.EqualFold(want.Name, rec.Name) && strings.EqualFold(want.Type, rec.Type) &&
							!strings.EqualFold(want.Value, rec.Value) {
							sev := "warning"
							if rec.Scope == model.ScopePublic {
								sev = "critical"
							}
							rep.Findings = append(rep.Findings, AuditFinding{
								Severity: sev,
								Code:     "dns_value_drift",
								Message: fmt.Sprintf("crenel-owned DNS record %s/%s points at %q but crenel's configured target is %q — the name resolves to the WRONG target; run reconcile to correct it",
									rec.Type, rec.Name, rec.Value, want.Value),
							})
						}
					}
				}
			}
			// A mesh-grant exposure is identity-scoped (private); a PUBLIC DNS
			// record for it advertises a globally-resolvable name that only mesh
			// peers can actually reach — misleading and a likely leak of intent.
			if rec.Scope == model.ScopePublic && isMeshGrant(host) {
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "public_dns_for_mesh_grant",
					Message: fmt.Sprintf("PUBLIC DNS record %s/%s names a MESH-GRANT (identity-scoped) host — it resolves globally but only mesh peers can reach it",
						rec.Type, rec.Name),
				})
			}
			// A wildcard rewrite (`*.zone`) is not a single host but a CATCH-ALL pattern:
			// it answers any name in .zone, so it's "backed" by ANY exposed host under
			// that zone. The dangling check applies only when the wildcard's zone has
			// nothing exposed at all (a real misdirect — the wildcard answers names crenel
			// cannot reach). For explicit records, the existing per-host check is unchanged.
			if isWildcardName(host) {
				if wildcardBacksAnyExposed(host, exposed) {
					continue
				}
				sev := "warning"
				msg := fmt.Sprintf("DNS wildcard %s/%s (%s) backs no exposed host under its zone — dangling pattern", rec.Type, rec.Name, rec.Scope)
				if rec.Scope == model.ScopePublic {
					sev = "critical"
					msg = fmt.Sprintf("PUBLIC DNS wildcard %s/%s answers names with NO backing edge route under its zone — points at the edge with nothing exposed", rec.Type, rec.Name)
				}
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: sev,
					Code:     "dns_without_edge_route",
					Message:  msg,
				})
				continue
			}
			if !exposed[host] {
				sev := "warning"
				msg := fmt.Sprintf("DNS record %s/%s (%s) has no backing edge route — dangling record", rec.Type, rec.Name, rec.Scope)
				if rec.Scope == model.ScopePublic {
					sev = "critical"
					msg = fmt.Sprintf("PUBLIC DNS record %s/%s resolves but has no backing edge route — points at the edge with nothing exposed", rec.Type, rec.Name)
				}
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: sev,
					Code:     "dns_without_edge_route",
					Message:  msg,
				})
			}
		}
	}

	// Cross-INSTANCE coverage parity (dual-resolver split-horizon): when two or more
	// INTERNAL DNS providers are managed — e.g. a home AdGuard answering non-tunnel
	// clients and a VPS AdGuard answering tunnel clients, one per vantage — they must
	// cover the SAME managed host set. Each may legitimately answer with a DIFFERENT,
	// vantage-correct target (so this check compares COVERAGE, never values), but a host
	// present on one resolver and MISSING from another is a silent, vantage-specific
	// drift: clients of the missing resolver get a different or absent answer for that
	// name (the live adguard.homelab.example case — see docs/REFERENCE-ARCH-split-horizon.md).
	// Default-deny posture: surfaced as a first-class finding, never inferred away. Two
	// same-scope providers SHOULD set distinct `instance` labels so present/missing name
	// the right resolver. (Same convention as the cross-EDGE edge_inconsistent_exposure
	// sibling: a WARNING, so it flips the report's OK() without failing CI as critical.)
	//
	// WILDCARD-AWARENESS (the cry-wolf fix on the bit-us case): coverage is checked
	// against EXPLICIT host names only — a wildcard rewrite like `*.homelab.example` is a
	// pattern, not a host, so it never enters the compared union as a literal. A host h
	// is treated as PRESENT on a resolver R if either (a) R has an explicit rewrite for
	// h, or (b) any wildcard pattern on R covers h (`*.zone` covers any name ending in
	// `.zone`). This kills the bit-us false positive where the audit flagged
	// `adguard.homelab.example` as drift even though home's `*.homelab.example` rewrite
	// already resolved it on the home vantage.
	//
	// VALUE-MISMATCH GUARD (the careful caveat — DO NOT hide a real drift): wildcard
	// SUBSTITUTION is only treated as parity-clean when the wildcard's answer value
	// matches at least one of the resolvers that hold an EXPLICIT entry for h. Otherwise
	// the wildcard answers the wrong target for h — explicit `host`→A on R1 vs covering
	// `*.zone`→B on R2 (B ≠ A) is silent misdirect for R2's clients, and the audit still
	// flags it (as `dns_coverage_parity` with a value-aware message). The pure vantage
	// case (two resolvers, two EXPLICIT entries with intentionally different vantage
	// targets, NO wildcard substitution) is unchanged and remains parity-clean.
	if len(internalCovs) >= 2 {
		union := map[string]bool{}
		for _, ic := range internalCovs {
			for h := range ic.explicit {
				union[h] = true
			}
		}
		for _, host := range sortedKeys(union) {
			var present, missing []string
			// wildcardCovers[ic.name] = wildcard pattern that covers host (only set when
			// the resolver has NO explicit entry for host but a wildcard there matches).
			wildcardCovers := map[string]wildcardRewrite{}
			explicitValues := map[string]string{} // resolvers with explicit h → their value
			for _, ic := range internalCovs {
				if v, ok := ic.explicit[host]; ok {
					present = append(present, ic.name)
					explicitValues[ic.name] = v
					continue
				}
				if w, ok := wildcardCovering(ic.wildcards, host); ok {
					present = append(present, ic.name)
					wildcardCovers[ic.name] = w
					continue
				}
				missing = append(missing, ic.name)
			}
			if len(missing) > 0 {
				sort.Strings(present)
				sort.Strings(missing)
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "dns_coverage_parity",
					Message: fmt.Sprintf("internal DNS coverage drift: host %s is present on [%s] but MISSING from [%s] — the split-horizon resolvers are out of coverage parity, so clients of the missing resolver get a different or absent answer for this name",
						host, strings.Join(present, ", "), strings.Join(missing, ", ")),
				})
				continue
			}
			// Every resolver covers host — but if any are covered ONLY by wildcard, that
			// wildcard's value must match an explicit value somewhere, else it's a silent
			// answer-the-wrong-target drift. Pure-explicit case (no wildcard substitution)
			// preserves the vantage rule: differing vantage-correct values are parity-clean.
			if len(wildcardCovers) == 0 || len(explicitValues) == 0 {
				continue
			}
			explicitSet := map[string]bool{}
			for _, v := range explicitValues {
				explicitSet[strings.ToLower(v)] = true
			}
			for _, resolver := range sortedKeys(boolSet(wildcardCovers)) {
				w := wildcardCovers[resolver]
				if explicitSet[strings.ToLower(w.value)] {
					continue
				}
				var explicitDescr []string
				for _, r := range sortedKeys(boolSet(explicitValues)) {
					explicitDescr = append(explicitDescr, fmt.Sprintf("%s=%s", r, explicitValues[r]))
				}
				rep.Findings = append(rep.Findings, AuditFinding{
					Severity: "warning",
					Code:     "dns_coverage_parity",
					Message: fmt.Sprintf("internal DNS coverage drift: host %s on [%s] is covered ONLY by wildcard %s → %q, but the explicit entry on the other resolver answers a DIFFERENT target (%s) — the wildcard substitution does not match, so clients of [%s] resolve %s to the wrong address",
						host, resolver, w.pattern, w.value, strings.Join(explicitDescr, ", "), resolver, host),
				})
			}
		}
	}

	// Reverse consistency (only meaningful when DNS is configured): a host exposed
	// on any edge with no DNS record pointing at it is exposed-but-unreachable.
	//
	// Wildcard-aware: a host is "reachable by name" if either an explicit DNS record
	// names it OR any wildcard rewrite covers it (`*.zone` answers any name in .zone).
	// This kills the cry-wolf on the AdGuard split-horizon shape where the zone has a
	// single `*.zone` rewrite acting as the resolver's catch-all and no explicit
	// per-host entries. The wildcard's value-correctness for any one host is a separate
	// concern (per-provider desired-vs-live / `dns_value_drift` for owned records).
	if len(e.DNS) > 0 {
		for _, host := range sortedKeys(exposed) {
			if dnsCovered[host] {
				continue
			}
			if _, ok := wildcardCovering(allWildcards, host); ok {
				continue
			}
			rep.Findings = append(rep.Findings, AuditFinding{
				Severity: "warning",
				Code:     "edge_route_without_dns",
				Message:  fmt.Sprintf("edge route %s has no DNS record — exposed but not reachable by name", host),
			})
		}
	}

	// Public-without-auth (the safety posture check): a host that is PUBLIC-scope
	// (a public DNS record, or — when no public DNS is managed — a non-mesh edge
	// route) but carries NO forward-auth policy is exposed to the world unprotected.
	// Flagged as a WARNING (never critical, so it never fails CI on its own): auth is
	// orthogonal to default-deny, so this is a posture signal, not an invariant
	// breach. Mesh-grant hosts are identity-enforced and never "public" — excluded.
	var downstreamSuppressed []string
	for _, host := range sortedKeys(exposed) {
		if isMeshGrant(host) || hostAuth[host] {
			continue
		}
		// The "edge IS the public boundary" default fires only for hosts on edges where
		// crenel actually has no per-host evidence — a plain (non-external) edge, or an
		// external edge whose per-host ingress rules could not be recovered. Hosts on
		// edges with PARSED per-host recovery (cloudflared / Tailscale serve.json) use
		// only the per-host evidence — exposedOnPlainEdge stays false so a tailnet-only
		// `Web` entry (no AllowFunnel) is NOT falsely claimed public. See ingress.go.
		public := exposedOnPlainEdge[host]
		if hasPublicDNS {
			public = publicDNSHosts[host]
		}
		// A host the tunnel's OWN ingress rules publish is PUBLIC by observation, even when
		// crenel manages public DNS that does not list it (the tunnel, not crenel's DNS, is
		// the public boundary) — additive, so it can only ADD a true-positive flag.
		if tunnelPublic[host] {
			public = true
		}
		if !public {
			continue
		}
		// Chain mitigation: a public host on a FRONT edge enforces auth one hop
		// downstream, so public_without_auth would be spurious here. Suppress it but
		// record it for an explicit informational finding (never a silent drop).
		if hostAuthDownstream[host] {
			downstreamSuppressed = append(downstreamSuppressed, host)
			continue
		}
		rep.Findings = append(rep.Findings, AuditFinding{
			Severity: "warning",
			Code:     "public_without_auth",
			Message: fmt.Sprintf("host %s is PUBLIC with no forward-auth policy — anyone on the internet can reach it; "+
				"attach an auth policy (expose --auth <policy>) or confirm it is intentionally open", host),
		})
	}
	if len(downstreamSuppressed) > 0 {
		rep.Findings = append(rep.Findings, AuditFinding{
			Severity: "ok",
			Code:     "auth_downstream",
			Message: fmt.Sprintf("%d public host(s) front a downstream edge that enforces auth (auth: downstream); "+
				"public_without_auth suppressed: %s", len(downstreamSuppressed), strings.Join(downstreamSuppressed, ", ")),
		})
	}

	rep.Findings = append(rep.Findings, AuditFinding{
		Severity: "ok",
		Code:     "exposed_count",
		Message:  fmt.Sprintf("%d host(s) exposed across %d edge(s)", len(exposed), len(e.Edges)),
	})
	return rep, nil
}

// unparsedLocators renders a bounded, comma-joined list of unparsed locators for a
// finding message (caps at a few so a heavily-unparsed edge doesn't flood output).
func unparsedLocators(us []model.Unparsed) string {
	const max = 4
	parts := make([]string, 0, len(us))
	for i, u := range us {
		if i >= max {
			parts = append(parts, fmt.Sprintf("…+%d more", len(us)-max))
			break
		}
		parts = append(parts, u.Locator)
	}
	return strings.Join(parts, ", ")
}

// crenelManagedRouteCount counts routes crenel physically wrote (OwnCrenel) — the
// routes whose durability is crenel's concern. On an ephemeral edge these are exactly
// what a control-plane restart would drop.
func crenelManagedRouteCount(routes []model.Route) int {
	n := 0
	for _, r := range routes {
		if r.Ownership == model.OwnCrenel || r.Managed {
			n++
		}
	}
	return n
}

// unconfirmedOwnershipHosts returns the sorted hosts of routes whose ownership is
// foreign or unknown (the mutation-blocked set), for the ownership_unconfirmed
// finding. Empty when every route is crenel/unmanaged (the safe-to-manage classes).
func unconfirmedOwnershipHosts(routes []model.Route) []string {
	var out []string
	for _, r := range routes {
		if r.Ownership == model.OwnForeign || r.Ownership == model.OwnUnknown {
			out = append(out, r.Host)
		}
	}
	sort.Strings(out)
	return out
}

// edgeLabel returns a per-edge prefix for audit messages — empty for a
// single-edge engine (keeps the original message text), "edge[name]: " otherwise.
func edgeLabel(b EdgeBinding, total int) string {
	if total <= 1 {
		return ""
	}
	return "edge[" + b.Name + "]: "
}

// serviceOf derives the logical service name from a host by stripping the zone
// suffix — the inverse of BuildOp's host derivation. Used by the cross-edge
// consistency check to ask each edge's Fronts predicate about a live host.
func (e *Engine) serviceOf(host string) string {
	if e.Zone != "" {
		if s := strings.TrimSuffix(host, "."+e.Zone); s != host {
			return s
		}
	}
	return host
}
