package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// DriftKind classifies one piece of drift reconcile fixes. Reconcile is the
// operator-grade "detect + fix ALL drift" verb: it converges every edge + DNS
// provider onto the CANONICAL currently-exposed set, which — in the live-state-
// authoritative no-SOT model — is derived FROM live (not from a stored desired
// state). See DESIGN.md "Reconcile" for the precise drift-vs-audit boundary.
type DriftKind string

const (
	// DriftMissingRoute: an edge fronts a managed service whose host is exposed on
	// another edge but MISSING here — a half-applied double-write. Fix: re-add.
	DriftMissingRoute DriftKind = "missing_route"
	// DriftModeMismatch: a host exposed with a mode different from the canonical
	// (primary-edge) mode. Fix: re-render it in the canonical mode.
	DriftModeMismatch DriftKind = "mode_mismatch"
	// DriftMissingDNS: a managed host is exposed on an edge but has no DNS record
	// in a managed scope. Fix: add the record.
	DriftMissingDNS DriftKind = "missing_dns_record"
	// DriftStaleDNS: a crenel-managed DNS record names a host exposed on NO edge —
	// a leftover from an interrupted unexpose. Fix: remove the record.
	DriftStaleDNS DriftKind = "stale_dns_record"
	// DriftValueDNS: a crenel-OWNED DNS record is present at the right name/type but its
	// VALUE has drifted from what crenel would set (it points at the WRONG target while
	// reading as "present"). Detected only on providers that prove their records are
	// crenel's (ports.OwnedRecordReporter) — never on a marker-less provider, where a
	// value mismatch may be a legitimately-foreign record. Fix: re-assert crenel's value.
	DriftValueDNS DriftKind = "wrong_dns_target"
)

// Drift is one detected divergence from the canonical exposed set.
type Drift struct {
	Kind   DriftKind
	Host   string
	Target string // edge name, or "<dns>/<scope>"
	Detail string
}

// ReconcilePlan is the computed reconciliation: the drift detected plus the
// corrective ChangeSet that converges the world. It NEVER references a route or
// DNS record outside crenel's managed domain (see managed-boundary note below).
type ReconcilePlan struct {
	Drift  []Drift
	Change model.ChangeSet
}

// Empty reports whether there is no drift to fix (a clean, already-consistent world).
func (p ReconcilePlan) Empty() bool { return len(p.Drift) == 0 }

// ReconcileConfirmFunc previews the reconcile plan before applying. Returning
// (true, nil) proceeds; (false, nil) aborts cleanly. Use AlwaysYesReconcile for --yes.
type ReconcileConfirmFunc func(ReconcilePlan) (bool, error)

// AlwaysYesReconcile approves a reconcile without prompting (for --yes).
func AlwaysYesReconcile(ReconcilePlan) (bool, error) { return true, nil }

// ReconcileReport is the result of a reconcile.
type ReconcileReport struct {
	Plan ReconcilePlan
	// Converged is true when there was no drift — a clean no-op.
	Converged bool
	Applied   bool
	Verify    []VerifyResult
	txnOutcome
}

// Verified reports whether every provider's read-back verification passed.
func (r ReconcileReport) Verified() bool {
	for _, v := range r.Verify {
		if !v.OK {
			return false
		}
	}
	return true
}

// canonicalState is the "should be true" snapshot derived from live: the set of
// managed exposed hosts and, per host, its canonical mode AND forward-auth (each the
// value it carries on the FIRST edge — in topology order — that exposes it; the
// primary-edge view). Auth is carried so reconcile re-adds / re-renders a managed
// route WITH its protection intact — dropping it would turn a protected host
// public-and-unprotected (a MISREAD-↓ by mutation) while read-back still passed.
type canonicalState struct {
	host map[string]string          // lower(host) -> display host
	mode map[string]model.RouteMode // lower(host) -> canonical mode
	auth map[string]string          // lower(host) -> canonical forward-auth policy ("" = none)
}

// Reconcile is the operator-grade detect-and-fix-ALL-drift verb. Unlike `resume`
// (which finishes ONE interrupted op) or `audit` (which only reports), reconcile
// makes every edge + DNS provider agree with the canonical currently-exposed set:
//   - re-adds managed routes missing from an edge that fronts them,
//   - re-renders routes whose mode drifted from the canonical (primary-edge) mode,
//   - adds missing managed DNS records and removes stale crenel-managed ones,
//
// all via the SAME all-or-nothing transaction + read-back-verify + wedge-safe
// rollback as Apply. It is preview-then-confirm like every mutating verb.
//
// MANAGED BOUNDARY (the load-bearing safety property): reconcile only ever touches
// hosts/records within crenel's managed domain — a host whose service is fronted by
// some edge (its origins-derived projection). Routes and DNS records outside that
// domain (Authelia, dashboards, other vendors, manually-created records) are NEVER
// read into the canonical set, so they are never added, removed, or re-rendered.
// Reconcile also never deletes an edge route outright (it only adds missing ones
// and re-renders modes), so it cannot tear down anything by mistake.
func (e *Engine) Reconcile(ctx context.Context, confirm ReconcileConfirmFunc) (ReconcileReport, error) {
	var rep ReconcileReport

	plan, canon, err := e.planReconcile(ctx)
	if err != nil {
		return rep, err
	}
	rep.Plan = plan
	if plan.Empty() {
		rep.Converged = true
		return rep, nil
	}

	// Refuse-to-manage gate (register §4.5): refuse before mutating a foreign/unknown
	// route or edge. Reconcile only ever ADDS/re-renders managed routes, but a mode
	// re-render touches an existing host, so the gate still applies.
	if err := e.gateOwnership(ctx, plan.Change); err != nil {
		return rep, err
	}

	ok, err := confirm(plan)
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, nil // declined; Applied stays false
	}

	// Re-snapshot each participating edge right before applying so the compensating
	// inverses are built against current live state (mirrors Apply).
	edgeSnaps := make(map[string]model.LiveEdgeState, len(plan.Change.Edges))
	for _, ep := range plan.Change.Edges {
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		snap, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return rep, fmt.Errorf("snapshot edge %s before reconcile: %w", ep.Edge, err)
		}
		edgeSnaps[ep.Edge] = snap
	}

	// Reuse the exact ordered, transactional step machinery as Apply. Reconcile
	// moves toward MORE consistency; ordering ascending (edges before public DNS)
	// keeps the add-direction safe and is harmless for the remove-stale-DNS steps
	// (their hosts are already unexposed).
	steps := e.buildSteps(ctx, model.Op{Verb: model.Expose}, plan.Change, edgeSnaps)
	var applied []compensator
	for _, st := range steps {
		if err := st.do(); err != nil {
			if st.edge != nil {
				probeEdge(ctx, st.edge, &rep.txnOutcome)
			}
			e.rollback(ctx, applied, &rep.txnOutcome)
			return rep, fmt.Errorf("reconcile apply %s: %w", st.name, err)
		}
		applied = append(applied, compensator{name: st.name, undo: st.undo, edge: st.edge})
	}
	rep.Applied = true

	// Read-back-verify convergence: every managed host the edge fronts is reachable
	// in its canonical mode, and every DNS add/remove actually took.
	rep.Verify = e.verifyReconcile(ctx, canon, plan.Change)
	if !rep.Verified() {
		e.rollback(ctx, applied, &rep.txnOutcome)
		var bad []string
		for _, v := range rep.Verify {
			if !v.OK {
				bad = append(bad, fmt.Sprintf("%s: %s", v.Provider, v.Detail))
			}
		}
		return rep, fmt.Errorf("reconcile read-back verification FAILED: %s", strings.Join(bad, "; "))
	}
	e.persistEdges(ctx, plan.Change.Edges, &rep.txnOutcome)
	return rep, nil
}

// DetectDrift is the read-only "detect" half of reconcile: it reads live across
// every edge + DNS provider and returns the divergence from the canonical exposed
// set WITHOUT mutating anything. It powers the `drift` verb (a CI/cron-friendly
// check) — where `audit` reports invariant/consistency findings, `drift` reports
// specifically what `reconcile` would change. An empty plan means fully converged.
func (e *Engine) DetectDrift(ctx context.Context) (ReconcilePlan, error) {
	plan, _, err := e.planReconcile(ctx)
	return plan, err
}

// planReconcile reads live across every edge + DNS provider, derives the canonical
// exposed set, and computes the corrective ChangeSet + drift list. It is the pure
// "detect" half — no mutation.
func (e *Engine) planReconcile(ctx context.Context) (ReconcilePlan, canonicalState, error) {
	canon := canonicalState{host: map[string]string{}, mode: map[string]model.RouteMode{}, auth: map[string]string{}}

	type edgeView struct {
		b    EdgeBinding
		live model.LiveEdgeState
	}
	var views []edgeView
	// canonTerminal[host] records that the canonical mode/auth for a host came from an
	// edge that SERVES it terminally — so a chain FRONT's forward relay (which carries
	// no auth) never sets the canonical auth, and the downstream/serving edge's auth
	// wins. Without it a chain reconcile would re-add the downstream route unprotected.
	canonTerminal := map[string]bool{}
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return ReconcilePlan{}, canon, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		views = append(views, edgeView{b: b, live: live})
		for _, r := range live.Routes {
			svc := e.serviceOf(r.Host)
			// MANAGED BOUNDARY: only hosts whose service some edge fronts are part of
			// crenel's domain. Everything else (unmanaged routes) is skipped here, so
			// reconcile can never propagate or alter it.
			if !e.anyFronts(svc) {
				continue
			}
			key := strings.ToLower(r.Host)
			canon.host[key] = r.Host
			// Canonical mode+auth come from the edge that SERVES the host terminally
			// (the FIRST such edge — the primary-edge view); in a chain that is the
			// downstream edge where auth lives, never the front's no-auth relay. A
			// host with no readable terminal edge falls back to the forward's values.
			terminal := e.roleFor(b, svc) == roleTerminal
			switch {
			case terminal && !canonTerminal[key]:
				canon.mode[key] = r.Upstream.Mode
				canon.auth[key] = r.Upstream.Auth
				canonTerminal[key] = true
			case !canonTerminal[key]:
				if _, seen := canon.mode[key]; !seen {
					canon.mode[key] = r.Upstream.Mode
					canon.auth[key] = r.Upstream.Auth
				}
			}
		}
	}

	var plan ReconcilePlan

	// --- EDGE drift: missing routes + mode mismatches, per participating edge. ---
	for _, v := range views {
		ec := model.EdgeChange{DenyCatchAllWillBePresent: true}
		for _, key := range sortedStrKeys(canon.host) {
			host := canon.host[key]
			svc := e.serviceOf(host)
			role := e.roleFor(v.b, svc)
			if role == roleNone {
				continue // this edge neither serves nor forwards the service
			}
			mode := canon.mode[key]
			cur, has := modeOf(v.live, host)
			switch {
			case !has:
				route, err := e.canonicalChainRoute(v.b, role, svc, host, mode, canon.auth[key])
				if err != nil {
					return ReconcilePlan{}, canon, err
				}
				ec.AddRoutes = append(ec.AddRoutes, route)
				detail := fmt.Sprintf("exposed elsewhere but missing from edge %q which also fronts %q", v.b.Name, svc)
				if role == roleForward {
					detail = fmt.Sprintf("half-present chain: edge %q forwards %q downstream but its forward route is missing", v.b.Name, svc)
				}
				plan.Drift = append(plan.Drift, Drift{
					Kind: DriftMissingRoute, Host: host, Target: v.b.Name, Detail: detail,
				})
			case cur != mode:
				route, err := e.canonicalChainRoute(v.b, role, svc, host, mode, canon.auth[key])
				if err != nil {
					return ReconcilePlan{}, canon, err
				}
				// Re-render: remove the wrong-mode route, then add the canonical one.
				// Drivers apply removes before adds, so this replaces it cleanly.
				ec.RemoveHosts = append(ec.RemoveHosts, host)
				ec.AddRoutes = append(ec.AddRoutes, route)
				plan.Drift = append(plan.Drift, Drift{
					Kind: DriftModeMismatch, Host: host, Target: v.b.Name,
					Detail: fmt.Sprintf("mode %s on edge %q differs from canonical %s", cur, v.b.Name, mode),
				})
			}
		}
		if !ec.Empty() {
			plan.Change.Edges = append(plan.Change.Edges, model.EdgePlan{
				Edge: v.b.Name, Driver: v.b.Provider.Name(), Change: ec,
			})
		}
	}

	// --- DNS drift: missing records + stale managed records, per provider. ---
	// plan.Change.DNS is kept POSITIONALLY ALIGNED with e.DNS (one entry each,
	// including empty changes) — buildSteps relies on this.
	for _, dp := range e.DNS {
		change := model.DNSChange{Scope: dp.Scope()}
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			return ReconcilePlan{}, canon, fmt.Errorf("read live dns (%s): %w", dp.Name(), err)
		}
		liveSet := recKeySet(recs)
		// liveByKey + ownsAll power VALUE-drift detection: a record present by name/type
		// but pointing at the WRONG target. We only correct it on a provider that PROVES
		// its live records are crenel's (ports.OwnedRecordReporter — the surgical Cloudflare
		// marker). On a marker-less provider (AdGuard) a value mismatch may be a legitimately-
		// foreign record, so reconcile leaves it untouched rather than clobber it.
		// liveWildcards captures `*.zone` catch-alls in live; both the missing and stale
		// checks are wildcard-aware (drift-sibling of the audit fix — #15/#16). See the
		// per-check comments below for the semantics.
		liveByKey := make(map[string]model.Record, len(recs))
		var liveWildcards []wildcardRewrite
		for _, r := range recs {
			liveByKey[r.Key()] = r
			if isWildcardName(r.Name) {
				liveWildcards = append(liveWildcards, wildcardRewrite{
					pattern: strings.ToLower(r.Name),
					value:   r.Value,
				})
			}
		}
		ownsAll := false
		if r, ok := dp.(ports.OwnedRecordReporter); ok {
			ownsAll = r.OwnsAllLiveRecords()
		}
		label := dp.Name() + "/" + string(dp.Scope())

		desiredSet := map[string]bool{}
		for _, key := range sortedStrKeys(canon.host) {
			host := canon.host[key]
			desired, err := dp.DesiredRecords(model.Op{Verb: model.Expose, Service: e.serviceOf(host), Host: host})
			if err != nil {
				return ReconcilePlan{}, canon, fmt.Errorf("dns %s desired records: %w", dp.Name(), err)
			}
			// The FULL canonical desired set is what crenel manages — carried on the change
			// so the driver's whole-zone-push ownership gate recognizes every managed
			// record (not just the missing ones it is adding now).
			change.Managed = append(change.Managed, desired...)
			for _, rec := range desired {
				desiredSet[rec.Key()] = true
				switch {
				case !liveSet[rec.Key()]:
					// Wildcard-awareness (drift-sibling of #15/#16): if a live wildcard
					// covers rec.Name AND already answers with the value crenel would set,
					// the host is not missing — the wildcard is the intentional coverage.
					// A VALUE mismatch under the wildcard still flags: the wildcard answers
					// the WRONG target, so an explicit record is genuinely needed to
					// override it (mirror of the audit's dns_coverage_parity value guard).
					if w, ok := wildcardCovering(liveWildcards, rec.Name); ok &&
						strings.EqualFold(strings.TrimSpace(w.value), strings.TrimSpace(rec.Value)) {
						break
					}
					change.Add = append(change.Add, rec)
					plan.Drift = append(plan.Drift, Drift{
						Kind: DriftMissingDNS, Host: host, Target: label,
						Detail: "exposed host is missing its DNS record",
					})
				case ownsAll:
					// Present by name/type: re-assert if the VALUE drifted. Without this,
					// reconcile would treat a wrong-target record as "converged" and leave it
					// silently misdirecting. The corrective Add becomes an UPDATE in the driver.
					if cur, ok := liveByKey[rec.Key()]; ok &&
						!strings.EqualFold(strings.TrimSpace(cur.Value), strings.TrimSpace(rec.Value)) {
						change.Add = append(change.Add, rec)
						plan.Drift = append(plan.Drift, Drift{
							Kind: DriftValueDNS, Host: host, Target: label,
							Detail: fmt.Sprintf("DNS record points at %q but should be %q", cur.Value, rec.Value),
						})
					}
				}
			}
		}
		// Stale: a managed record whose host is exposed on no edge.
		for _, r := range recs {
			// Wildcard-awareness (drift-sibling of #15/#16): never propose to REMOVE a
			// wildcard. Crenel does not own operator wildcards (the AdGuard driver's guard
			// refuses to emit one), and a `*.zone` that backs any exposed host is the
			// intentional catch-all. Prior behaviour would have deleted the load-bearing
			// `*.homelab.example` on the live home resolver — the exact bug this prevents.
			if isWildcardName(r.Name) {
				continue
			}
			if !e.anyFronts(e.serviceOf(r.Name)) {
				continue // unmanaged record — never touch
			}
			if canon.host[strings.ToLower(r.Name)] == "" && !desiredSet[r.Key()] {
				change.Remove = append(change.Remove, r)
				plan.Drift = append(plan.Drift, Drift{
					Kind: DriftStaleDNS, Host: r.Name, Target: label,
					Detail: "managed DNS record for a host exposed on no edge",
				})
			}
		}
		plan.Change.DNS = append(plan.Change.DNS, change)
	}

	return plan, canon, nil
}

// canonicalChainRoute renders the route an edge should hold for (service, host),
// honoring its chain ROLE: a TERMINAL edge renders the real route via its own driver
// (origin resolution + mode + auth); a chain FRONT renders the synthesized FORWARD
// route to the downstream edge (no auth — auth lives at the terminal edge). So a chain
// reconcile re-adds the correct SHAPE on each participant: a missing front forward is
// re-forwarded, a missing downstream route is re-served.
func (e *Engine) canonicalChainRoute(b EdgeBinding, role chainRole, service, host string, mode model.RouteMode, auth string) (model.Route, error) {
	if role == roleForward {
		return b.forwardRoute(host)
	}
	return e.canonicalRoute(b, service, host, mode, auth)
}

// canonicalRoute asks the edge's own Plan to render the route for (service, host)
// in the canonical mode AND forward-auth. Using the driver's Plan reuses its
// per-edge origin resolution (home → LAN, VPS → Tailscale), its mode capability,
// and its auth rendering — so if a driver cannot express the canonical mode (e.g.
// Caddy + TCP passthrough without layer4) or auth, reconcile fails LOUDLY here
// instead of approximating or silently dropping protection.
func (e *Engine) canonicalRoute(b EdgeBinding, service, host string, mode model.RouteMode, auth string) (model.Route, error) {
	op := model.Op{Verb: model.Expose, Service: service, Host: host, Mode: mode, Auth: auth}
	// Plan against an empty live so the driver emits exactly one AddRoute.
	cs, err := b.Provider.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err != nil {
		return model.Route{}, fmt.Errorf("reconcile: edge %q cannot render %s for %s: %w", b.Name, mode, host, err)
	}
	if len(cs.Edge.AddRoutes) != 1 {
		return model.Route{}, fmt.Errorf("reconcile: edge %q planned %d routes for %s (want 1)", b.Name, len(cs.Edge.AddRoutes), host)
	}
	return cs.Edge.AddRoutes[0], nil
}

// verifyReconcile re-reads every provider and asserts convergence to the canonical
// state: each edge holds (reachable, in canonical mode) every managed host it
// fronts with the deny present; each DNS provider's adds are present and removes
// absent.
func (e *Engine) verifyReconcile(ctx context.Context, canon canonicalState, cs model.ChangeSet) []VerifyResult {
	var out []VerifyResult

	for _, b := range e.Edges {
		label := "edge[" + b.Name + "·" + b.Provider.Name() + "]"
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: reReadFailedDetail(err)})
			continue
		}
		if !live.DenyCatchAllPresent {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: "catch-all default-deny missing after reconcile"})
			continue
		}
		ok, detail := true, "consistent with the canonical exposed set"
		for _, key := range sortedStrKeys(canon.host) {
			host := canon.host[key]
			if e.roleFor(b, e.serviceOf(host)) == roleNone {
				continue // neither serves nor forwards this host
			}
			if !live.Reachable(host) {
				ok, detail = false, fmt.Sprintf("%s expected reachable but is not", host)
				break
			}
			if m, has := modeOf(live, host); !has || m != canon.mode[key] {
				ok, detail = false, fmt.Sprintf("%s expected mode %s but found %s", host, canon.mode[key], m)
				break
			}
		}
		// Read-back the forward-auth of the routes reconcile actually ADDED/RE-RENDERED
		// on THIS edge: a converged route must not have silently lost its protection
		// (register: never drop protection by mutation). Scoped to touched routes only —
		// reconcile does not reconcile pre-existing cross-edge auth differences, so it
		// must not fail verification over one it left alone.
		if ok {
			for _, want := range addedRoutesForEdge(cs, b.Name) {
				if a, has := authOf(live, want.Host); !has || a != want.Upstream.Auth {
					ok, detail = false, fmt.Sprintf("%s expected auth %q after re-render but found %q", want.Host, want.Upstream.Auth, a)
					break
				}
			}
		}
		out = append(out, VerifyResult{Provider: label, OK: ok, Detail: detail})
	}

	for i, dp := range e.DNS {
		label := dp.Name() + "/" + string(dp.Scope())
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: reReadFailedDetail(err)})
			continue
		}
		liveSet := recKeySet(recs)
		ok, detail := true, "records consistent"
		if i < len(cs.DNS) {
			for _, add := range cs.DNS[i].Add {
				if !liveSet[add.Key()] {
					ok, detail = false, fmt.Sprintf("record %s expected present but missing", add.Key())
					break
				}
			}
			if ok {
				for _, rm := range cs.DNS[i].Remove {
					if liveSet[rm.Key()] {
						ok, detail = false, fmt.Sprintf("record %s expected absent but still present", rm.Key())
						break
					}
				}
			}
		}
		out = append(out, VerifyResult{Provider: label, OK: ok, Detail: detail})
	}
	return out
}

// anyFronts reports whether any edge in the topology fronts service — i.e. whether
// the service is within crenel's managed domain.
func (e *Engine) anyFronts(service string) bool {
	for _, b := range e.Edges {
		if b.fronts(service) {
			return true
		}
	}
	return false
}

// modeOf returns the realized mode of host in live, if exposed.
func modeOf(live model.LiveEdgeState, host string) (model.RouteMode, bool) {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Upstream.Mode, true
		}
	}
	return "", false
}

// addedRoutesForEdge returns the routes a ChangeSet adds (or re-renders) on the
// named edge — the routes whose auth a reconcile read-back should re-assert.
func addedRoutesForEdge(cs model.ChangeSet, edge string) []model.Route {
	for _, ep := range cs.Edges {
		if ep.Edge == edge {
			return ep.Change.AddRoutes
		}
	}
	return nil
}

// authOf returns the realized forward-auth policy of host in live, if exposed.
func authOf(live model.LiveEdgeState, host string) (string, bool) {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Upstream.Auth, true
		}
	}
	return "", false
}

// sortedStrKeys returns the keys of a string-valued map in sorted order.
func sortedStrKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// recKeySet indexes records by Key() for fast presence checks.
func recKeySet(recs []model.Record) map[string]bool {
	m := make(map[string]bool, len(recs))
	for _, r := range recs {
		m[r.Key()] = true
	}
	return m
}
