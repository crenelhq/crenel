package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
	"github.com/crenelhq/crenel/internal/redact"
)

// reReadFailedDetail formats a read-back-verify failure detail, REDACTING any
// secret-shaped bytes a provider/admin-API error may echo (a DNS tool's combined
// stdout+stderr, an admin-API error body). Redaction is at the CONSTRUCTION boundary
// so even a programmatic caller (e.g. the read-only MCP server) never receives raw
// secret-bearing output — honoring the SECURITY.md §6 error-boundary invariant.
func reReadFailedDetail(err error) string {
	return redact.Snippet(fmt.Sprintf("re-read failed: %v", err))
}

// ConfirmFunc is called with the computed ChangeSet before applying. Returning
// (true, nil) proceeds; (false, nil) aborts cleanly. Use AlwaysYes for --yes.
type ConfirmFunc func(model.ChangeSet) (bool, error)

// AlwaysYes is a ConfirmFunc that approves without prompting (for --yes).
func AlwaysYes(model.ChangeSet) (bool, error) { return true, nil }

// UnverifiedWriteError is returned by Apply/Rename/ApplyDeclarative when every
// provider's artifact re-read matched (Verified() is true) but at least one
// file-based edge (Traefik/nginx) had no runtime probe configured, so the write
// could NOT be confirmed against the running daemon — RuntimeVerifyUnavailable
// (audit F2). The write is rolled back rather than left standing as an unconfirmed
// "green". Providers names the affected edges. Retry with Engine.AllowUnverified
// = true (the CLI's --allow-unverified, or an interactive accept) to proceed
// anyway, or configure a runtime probe on the affected driver(s).
type UnverifiedWriteError struct {
	Providers []string
}

func (e *UnverifiedWriteError) Error() string {
	return fmt.Sprintf("runtime verify unavailable for %s — write rolled back; pass --allow-unverified "+
		"to accept an unconfirmed write, or configure a runtime probe on the affected driver",
		strings.Join(e.Providers, ", "))
}

// gateRuntimeVerify enforces bounded honesty (audit F2): when any result in verify
// is a file-driver write whose daemon could not be confirmed, refuse — rolling back
// applied — unless the operator has explicitly accepted that via Engine.
// AllowUnverified. Never silently green. Returns nil when there is nothing to gate
// (fully verified, or already accepted).
func (e *Engine) gateRuntimeVerify(ctx context.Context, verify []VerifyResult, applied []compensator, rep *txnOutcome) error {
	if e.AllowUnverified {
		return nil
	}
	unconfirmed := runtimeUnconfirmedResults(verify)
	if len(unconfirmed) == 0 {
		return nil
	}
	e.rollback(ctx, applied, rep)
	names := make([]string, len(unconfirmed))
	for i, v := range unconfirmed {
		names[i] = v.Provider
	}
	return &UnverifiedWriteError{Providers: names}
}

// Apply runs the full mutating flow for an op:
//
//	plan -> confirm -> apply -> READ-BACK-VERIFY each provider -> report
//
// Read-back verification is the load-bearing step: a provider reporting success
// (e.g. a Caddy admin 200) is NOT trusted. We re-read live state and assert the
// world actually matches the intent. This is what catches the silent-reload
// footgun.
func (e *Engine) Apply(ctx context.Context, op model.Op, confirm ConfirmFunc) (ApplyReport, error) {
	cs, err := e.Plan(ctx, op)
	if err != nil {
		return ApplyReport{Op: op}, err
	}
	return e.applyPlanned(ctx, op, cs, confirm)
}

// applyPlanned runs the confirm → apply → read-back-verify → (rollback) flow for a
// ChangeSet already computed by Plan. Apply and Resume share it so the remaining
// delta of an interrupted apply is completed by exactly the same transactional
// machinery.
func (e *Engine) applyPlanned(ctx context.Context, op model.Op, cs model.ChangeSet, confirm ConfirmFunc) (ApplyReport, error) {
	rep := ApplyReport{Op: op}
	rep.NewPublic = cs.NewPublic

	if cs.Empty() {
		rep.NoOp = true
		return rep, nil
	}

	// Refuse-to-manage gate (register §4.5): before touching any driver, refuse a
	// mutation of a foreign/unknown-owned route or edge. --yes never bypasses this.
	if err := e.gateOwnership(ctx, cs); err != nil {
		return rep, err
	}

	ok, err := confirm(cs)
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, nil // declined; Applied stays false
	}

	// Snapshot each participating edge's live state BEFORE applying so we can build
	// a compensating (inverse) change per edge if we need to roll back (M1/M4).
	edgeSnaps := make(map[string]model.LiveEdgeState, len(cs.Edges))
	for _, ep := range cs.Edges {
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		snap, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return rep, fmt.Errorf("snapshot edge %s before apply: %w", ep.Edge, err)
		}
		edgeSnaps[ep.Edge] = snap
	}

	// Build the apply steps and ORDER them by exposure rank + direction (M3/M4):
	//
	//   increasing exposure (Expose):   ALL edges → internal-DNS → public-DNS
	//   decreasing exposure (Unexpose): public-DNS → internal-DNS → ALL edges
	//
	// The principle: when making something MORE reachable, bring up every edge
	// route before announcing the name to the world (announce LAST); when making it
	// LESS reachable, stop announcing to the world FIRST, then tear the routes down.
	// All edges share the edge rank, so they all precede public-DNS on expose and
	// all follow it on unexpose. See DESIGN.md.
	steps := e.buildSteps(ctx, op, cs, edgeSnaps)

	// applied holds compensators in apply order; rollback runs them in reverse.
	// This is the ALL-OR-NOTHING cross-edge + DNS transaction: any step failing
	// rolls back every step already applied (every edge + DNS), in reverse.
	var applied []compensator
	for _, st := range steps {
		if err := st.do(); err != nil {
			// A step may have failed because an edge admin API wedged. Probe THAT
			// edge's health so the report reflects an unresponsive edge (and the CLI
			// can print the recovery hint) before attempting any rollback.
			if st.edge != nil {
				probeEdge(ctx, st.edge, &rep.txnOutcome)
			}
			e.rollback(ctx, applied, &rep.txnOutcome)
			return rep, fmt.Errorf("apply %s: %w", st.name, err)
		}
		applied = append(applied, compensator{name: st.name, undo: st.undo, edge: st.edge})
	}
	rep.Applied = true

	// --- READ-BACK-VERIFY ---
	rep.Verify = e.verify(ctx, op, cs)
	if !rep.Verified() {
		// Apply reported success but reality disagrees. Roll back what we did.
		e.rollback(ctx, applied, &rep.txnOutcome)
		var bad []string
		for _, v := range rep.Verify {
			if !v.OK {
				bad = append(bad, fmt.Sprintf("%s: %s", v.Provider, v.Detail))
			}
		}
		return rep, fmt.Errorf("read-back verification FAILED (provider reported success but live state did not change): %s", strings.Join(bad, "; "))
	}
	if err := e.gateRuntimeVerify(ctx, rep.Verify, applied, &rep.txnOutcome); err != nil {
		return rep, err
	}
	// Durability: persist the managed routes on any on-disk-persisting edge
	// (best-effort; a failure is a warning, not a rollback).
	e.persistEdges(ctx, cs.Edges, &rep.txnOutcome)
	return rep, nil
}

// persistEdges asks every PARTICIPATING edge that implements ports.Persister to
// durably persist its managed routes (e.g. write the on-disk Caddyfile), and DECLARES
// any edge whose writes are EPHEMERAL (applied to a running admin API but not the
// on-disk boot config). It is called AFTER a verified apply, and is best-effort: a
// failure (or an ephemeral declaration) is recorded as a warning on rep, never a
// rollback — the running state is already correct and verified; only its durability
// across a restart is in question. Each participating edge is persisted at most once
// (debounced by the driver into a single reload).
func (e *Engine) persistEdges(ctx context.Context, edges []model.EdgePlan, rep *txnOutcome) {
	seen := map[string]bool{}
	for _, ep := range edges {
		if seen[ep.Edge] {
			continue
		}
		seen[ep.Edge] = true
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		if p, ok := b.Provider.(ports.Persister); ok {
			if err := p.Persist(ctx); err != nil {
				rep.PersistWarnings = append(rep.PersistWarnings,
					fmt.Sprintf("edge[%s·%s]: %v", ep.Edge, b.Provider.Name(), err))
			}
		}
		// Durability declaration: if this edge actually took a change AND its persistence
		// model says writes are ephemeral (an admin-API edge with no durable path / a
		// declared unknown), warn that the verified write will NOT survive a restart. This
		// is the write-time analogue of the audit `ephemeral_writes` finding; it fires
		// even for a no-op Persister (a bare Caddy admin Persist returns nil) because the
		// durability gap is the model, not a Persist error.
		if dr, ok := b.Provider.(ports.DurabilityReporter); ok && !ep.Change.Empty() {
			if m := dr.PersistenceModel(); m.EphemeralWrites() {
				rep.PersistWarnings = append(rep.PersistWarnings,
					fmt.Sprintf("edge[%s·%s]: write applied + verified LIVE but this edge is EPHEMERAL (%s) — "+
						"it will NOT survive a control-plane restart; configure a durable persist path",
						ep.Edge, b.Provider.Name(), m))
			}
		}
	}
}

// compensator is an undo action for one already-applied provider. edge is set
// (non-nil) for an edge compensator so rollback can probe THAT edge's health
// before firing a compensating reload into it.
type compensator struct {
	name string
	undo func() error
	edge ports.EdgeProvider
}

// applyStep is one provider's apply, with its compensating inverse and an
// exposure rank used to order steps relative to one another. edge is set for an
// edge step (nil for DNS), used to probe the right edge's health on failure.
type applyStep struct {
	name  string
	rank  int                // exposure rank: edge < internal-DNS < public-DNS
	depth int                // chain depth (edge steps only): deeper = more internal
	edge  ports.EdgeProvider // non-nil for an edge step
	do    func() error       // apply this provider's change
	undo  func() error       // compensating inverse (built against the pre-apply snapshot)
}

// Exposure ranks. Lower = closer to the data plane / less globally discoverable;
// higher = more globally public. Expose applies low→high (announce to the world
// last); Unexpose applies high→low (stop announcing to the world first). ALL edges
// share rankEdge, so on expose every edge precedes public-DNS, and on unexpose
// public-DNS precedes every edge.
const (
	rankEdge        = 0 // the route itself: reachable if you can find the edge
	rankInternalDNS = 1 // discoverable on the internal network
	rankPublicDNS   = 2 // discoverable from the entire internet
)

// dnsRank maps a DNS provider's scope to its exposure rank.
func dnsRank(scope model.Scope) int {
	if scope == model.ScopePublic {
		return rankPublicDNS
	}
	return rankInternalDNS
}

// buildSteps assembles the ordered, non-empty apply steps for cs across ALL
// participating edges + DNS providers. The slice is sorted by exposure rank in
// the direction the op moves exposure (ascending for Expose, descending for
// Unexpose). Sorting is stable, so equal-rank steps (e.g. all edges) keep their
// wiring order.
func (e *Engine) buildSteps(ctx context.Context, op model.Op, cs model.ChangeSet, edgeSnaps map[string]model.LiveEdgeState) []applyStep {
	var steps []applyStep

	// Chain depth refines the edge rank: a chain DOWNSTREAM edge is deeper (more
	// internal) than its FRONT, so on expose it is brought up first and on unexpose
	// torn down last. Depth is 0 everywhere in a non-chain topology (no reordering).
	depth := e.chainDepth()

	for _, ep := range cs.Edges {
		if ep.Change.Empty() {
			continue
		}
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		ep := ep
		prov := b.Provider
		fwd := model.ChangeSet{Op: op, Edge: ep.Change}
		inv := model.ChangeSet{Op: op, Edge: invertEdge(ep.Change, edgeSnaps[ep.Edge])}
		steps = append(steps, applyStep{
			name:  "edge[" + ep.Edge + "·" + ep.Driver + "]",
			rank:  rankEdge,
			depth: depth[ep.Edge],
			edge:  prov,
			do:    func() error { return prov.Apply(ctx, fwd) },
			undo:  func() error { return prov.Apply(ctx, inv) },
		})
	}

	for i, dp := range e.DNS {
		if i >= len(cs.DNS) || cs.DNS[i].Empty() {
			continue
		}
		dp := dp
		change := cs.DNS[i]
		inv := invertDNS(change)
		steps = append(steps, applyStep{
			name: dp.Name() + "/" + string(dp.Scope()),
			rank: dnsRank(dp.Scope()),
			do:   func() error { return dp.Apply(ctx, change) },
			undo: func() error { return dp.Apply(ctx, inv) },
		})
	}

	ascending := op.Verb == model.Expose
	sort.SliceStable(steps, func(i, j int) bool {
		if steps[i].rank != steps[j].rank {
			if ascending {
				return steps[i].rank < steps[j].rank
			}
			return steps[i].rank > steps[j].rank
		}
		// Same exposure rank (e.g. all edges): order by chain DEPTH. On expose apply
		// the deeper (downstream) edge first; on unexpose the shallower (front) first.
		// Peer edges in a parallel multi-edge double-write share depth 0, so the stable
		// sort keeps their wiring order — unchanged from before.
		if ascending {
			return steps[i].depth > steps[j].depth
		}
		return steps[i].depth < steps[j].depth
	})
	return steps
}

// rollback runs compensators in reverse order, recording status on rep. It is a
// no-op when rollback is disabled or nothing was applied.
//
// Wedge safety (PER EDGE for M4): a compensating edge change is itself a full
// reload. If a given edge's control plane is wedged, firing another reload into it
// would only deepen the wedge (and hang on a bounded timeout). So for each edge
// compensator we probe THAT edge's health; if it is unresponsive we SKIP just that
// edge's compensator (and surface a recovery hint) while still rolling back every
// other edge and all DNS. One wedged edge never blocks unwinding the rest.
func (e *Engine) rollback(ctx context.Context, applied []compensator, rep *txnOutcome) {
	if !e.Rollback || len(applied) == 0 {
		return
	}
	rep.RolledBack = true

	// Cache per-edge wedge status so we probe each edge at most once.
	wedged := map[ports.EdgeProvider]bool{}
	isWedged := func(p ports.EdgeProvider) bool {
		if v, seen := wedged[p]; seen {
			return v
		}
		v := probeEdge(ctx, p, rep)
		wedged[p] = v
		return v
	}

	for i := len(applied) - 1; i >= 0; i-- {
		c := applied[i]
		if c.edge != nil && isWedged(c.edge) {
			rep.RollbackErrors = append(rep.RollbackErrors,
				fmt.Sprintf("%s: skipped (edge admin API unresponsive)", c.name))
			continue
		}
		if err := c.undo(); err != nil {
			rep.RollbackErrors = append(rep.RollbackErrors,
				fmt.Sprintf("%s: %v", c.name, err))
		}
	}
}

// probeEdge checks a specific edge provider's health (when it supports
// HealthChecker) and, if it is wedged/slow, records EdgeUnresponsive + a
// RecoveryHint on rep. Returns whether that edge is wedged. Safe to call more than
// once (the hint is only set the first time).
func probeEdge(ctx context.Context, prov ports.EdgeProvider, rep *txnOutcome) bool {
	hc, ok := prov.(ports.HealthChecker)
	if !ok {
		return false
	}
	if err := hc.Healthy(ctx); err == nil {
		return false
	}
	rep.EdgeUnresponsive = true
	if rep.RecoveryHint == "" {
		rep.RecoveryHint = "an edge admin API is unresponsive — recover the edge (e.g. restart Caddy, " +
			"which reloads the on-disk config and clears the wedge), then re-run crenel to reconcile."
	}
	return true
}

// invertEdge builds the compensating edge change that undoes ec, using the
// pre-apply snapshot to recover the prior upstreams of removed routes.
func invertEdge(ec model.EdgeChange, snapshot model.LiveEdgeState) model.EdgeChange {
	inv := model.EdgeChange{DenyCatchAllWillBePresent: true}
	// Undo additions by removing them.
	for _, r := range ec.AddRoutes {
		inv.RemoveHosts = append(inv.RemoveHosts, r.Host)
	}
	// Undo removals by re-adding the prior route from the snapshot.
	for _, h := range ec.RemoveHosts {
		for _, sr := range snapshot.Routes {
			if sr.Host == h {
				inv.AddRoutes = append(inv.AddRoutes, sr)
				break
			}
		}
	}
	return inv
}

// invertDNS builds the compensating DNS change (swap add/remove).
func invertDNS(dc model.DNSChange) model.DNSChange {
	// Carry Managed through so the rollback's apply-time ownership gate uses the same
	// managed set as the forward change (else it would refuse the compensating push).
	return model.DNSChange{Scope: dc.Scope, Add: dc.Remove, Remove: dc.Add, Managed: dc.Managed}
}

// verify re-reads each participating provider's live state and checks it matches
// op's intent. Every edge that took part in the change is re-read: the default-deny
// invariant must hold on each, and the host expectation (reachable after expose,
// absent after unexpose) is checked per edge.
func (e *Engine) verify(ctx context.Context, op model.Op, cs model.ChangeSet) []VerifyResult {
	var out []VerifyResult

	// Edge verification — one result per participating edge.
	for _, ep := range cs.Edges {
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		label := "edge[" + ep.Edge + "·" + ep.Driver + "]"
		live, err := b.Provider.ReadLiveState(ctx)
		switch {
		case err != nil:
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: reReadFailedDetail(err)})
		case !live.DenyCatchAllPresent:
			// The default-deny invariant must hold after any apply.
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: "catch-all default-deny missing after apply"})
		default:
			// A rename verifies BOTH transitions on this edge (new present, old absent);
			// other verbs verify their single op host. Both then share the auth + TLS
			// read-backs below over this edge's AddRoutes.
			var res VerifyResult
			if op.Verb == model.Rename {
				res = verifyEdgeRename(label, live, ep.Change)
			} else {
				res = verifyEdgeHost(label, live, op)
			}
			// Auth read-back (closes the consolidation-pass auth-verify gap): a route this
			// edge ADDED must read back carrying the forward-auth policy it was planned with.
			// In a chain this is what proves the policy actually landed at the DOWNSTREAM
			// edge that serves the host (the front's forward route carries none); generally
			// it catches any render that silently dropped or failed to attach auth.
			if res.OK {
				if d := verifyEdgeAuth(live, ep.Change.AddRoutes); d != "" {
					res = VerifyResult{Provider: label, OK: false, Detail: d}
				}
			}
			// Upstream-TLS read-back (TRIAL-FIX-4): a chain-FORWARD planned to dial an
			// HTTPS downstream must read back carrying the upstream TLS transport, else a
			// render that dropped it (bare HTTP to a :443 listener) reads back green and
			// then 400s at request time. This is the front-leg analogue of the auth check.
			if res.OK {
				if d := verifyEdgeForwardTLS(live, ep.Change.AddRoutes); d != "" {
					res = VerifyResult{Provider: label, OK: false, Detail: d}
				}
			}
			// RUNTIME verify (gap T4/N2): everything above re-read crenel's OWN written
			// file for a file driver — hollow. If the driver declares it (ports.
			// RuntimeVerifier), probe the actual daemon. Confirmed earns "verified LIVE";
			// Failed flips this result to not-OK (the false green the bench caught becomes
			// a real rollback); Unavailable keeps the write but blocks a "verified" claim.
			if res.OK {
				if rv, ok := b.Provider.(ports.RuntimeVerifier); ok {
					v := rv.VerifyRuntime(ctx, op, ep.Change)
					res.RuntimeChecked = true
					res.Runtime = v.Status
					res.RuntimeDetail = v.Detail
					if v.Status == model.RuntimeVerifyFailed {
						res.OK = false
						res.Detail = "runtime verify FAILED — " + v.Detail
					}
				}
			}
			out = append(out, res)
		}
	}

	// DNS verification — one result per provider, labelled by scope so internal
	// and public read-backs are distinguishable.
	for _, dp := range e.DNS {
		name := dp.Name() + "/" + string(dp.Scope())
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			out = append(out, VerifyResult{Provider: name, OK: false, Detail: reReadFailedDetail(err)})
			continue
		}
		desired, _ := dp.DesiredRecords(op)
		out = append(out, verifyDNS(name, op, desired, recs))
	}
	return out
}

// verifyEdgeAuth asserts every route this edge ADDED carries, on read-back, the auth
// policy it was planned with — so a render that silently dropped (or failed to attach)
// a forward-auth policy fails verification instead of reading back green. Mesh grants
// are identity-enforced (no forward-auth handler to observe) and skipped. Returns an
// empty string when every added route's auth matches its plan.
func verifyEdgeAuth(live model.LiveEdgeState, added []model.Route) string {
	for _, want := range added {
		if want.Upstream.Mode == model.ModeMeshGrant {
			continue
		}
		got, has := authOf(live, want.Host)
		if !has {
			return fmt.Sprintf("%s expected present for auth read-back but route is absent", want.Host)
		}
		// AuthNone ("none") is the explicit opt-out: it renders NO handler, so it reads
		// back as "" — both mean "no forward-auth attached" and must compare equal. A
		// REAL policy must match exactly.
		if normalizeAuthPresence(got) != normalizeAuthPresence(want.Upstream.Auth) {
			return fmt.Sprintf("%s expected auth %q after apply but found %q", want.Host, want.Upstream.Auth, got)
		}
	}
	return ""
}

// verifyEdgeForwardTLS asserts every route this edge ADDED that was PLANNED to dial an
// HTTPS upstream (a chain-forward to a `:443` downstream) reads back carrying the upstream
// TLS transport — so a render that silently dropped it fails verification instead of
// reading back green and then returning 400 "Client sent an HTTP request to an HTTPS
// server" at request time (the front-leg gap the live cross-chain trial caught,
// TRIAL-FIX-4). A route planned WITHOUT upstream TLS is unconstrained here. Returns an
// empty string when every TLS-planned forward read back with its TLS hop intact.
func verifyEdgeForwardTLS(live model.LiveEdgeState, added []model.Route) string {
	for _, want := range added {
		if !want.Upstream.UpstreamTLS {
			continue
		}
		got, has := upstreamTLSOf(live, want.Host)
		if !has {
			return fmt.Sprintf("%s expected present for upstream-TLS read-back but route is absent", want.Host)
		}
		if !got {
			return fmt.Sprintf("%s expected upstream TLS (HTTPS downstream) after apply but read back plain HTTP", want.Host)
		}
	}
	return ""
}

// upstreamTLSOf returns whether the live route for host dials its upstream over TLS.
func upstreamTLSOf(live model.LiveEdgeState, host string) (bool, bool) {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Upstream.UpstreamTLS, true
		}
	}
	return false, false
}

// normalizeAuthPresence collapses the two "no policy attached" values ("" and the
// explicit AuthNone opt-out) to one, so the auth read-back compares the PRESENCE of a
// real policy, not the intent marker the operator typed.
func normalizeAuthPresence(a string) string {
	if a == model.AuthNone {
		return ""
	}
	return a
}

func verifyEdgeHost(provider string, live model.LiveEdgeState, op model.Op) VerifyResult {
	switch op.Verb {
	case model.Expose:
		if live.Reachable(op.Host) {
			return VerifyResult{Provider: provider, OK: true, Detail: fmt.Sprintf("%s is now reachable", op.Host)}
		}
		return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("%s expected reachable but is not", op.Host)}
	case model.Unexpose:
		if !live.HasHost(op.Host) {
			return VerifyResult{Provider: provider, OK: true, Detail: fmt.Sprintf("%s is no longer exposed", op.Host)}
		}
		return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("%s expected removed but route still present", op.Host)}
	default:
		return VerifyResult{Provider: provider, OK: false, Detail: "unknown verb"}
	}
}

// verifyEdgeRename read-back-verifies a rename on one edge: every added (new) host is
// reachable AND every removed (old) host is absent. Both halves must hold or the rename
// transaction rolls back as a unit.
func verifyEdgeRename(provider string, live model.LiveEdgeState, ec model.EdgeChange) VerifyResult {
	for _, r := range ec.AddRoutes {
		if !live.Reachable(r.Host) {
			return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("renamed-to %s expected reachable but is not", r.Host)}
		}
	}
	for _, h := range ec.RemoveHosts {
		if live.HasHost(h) {
			return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("renamed-from %s expected removed but still present", h)}
		}
	}
	from, to := "", ""
	if len(ec.RemoveHosts) > 0 {
		from = ec.RemoveHosts[0]
	}
	if len(ec.AddRoutes) > 0 {
		to = ec.AddRoutes[0].Host
	}
	return VerifyResult{Provider: provider, OK: true, Detail: fmt.Sprintf("renamed %s → %s", from, to)}
}

func verifyDNS(provider string, op model.Op, desired, live []model.Record) VerifyResult {
	liveByKey := make(map[string]model.Record, len(live))
	for _, r := range live {
		liveByKey[r.Key()] = r
	}
	switch op.Verb {
	case model.Expose:
		// Value-AWARE: present-by-name is not enough — the live VALUE must match the
		// desired one, so a record left pointing at a stale/wrong address can never read
		// back green (defense in depth for the value-update path).
		for _, d := range desired {
			cur, ok := liveByKey[d.Key()]
			if !ok {
				return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("record %s expected present but missing", d.Key())}
			}
			if !strings.EqualFold(strings.TrimSpace(cur.Value), strings.TrimSpace(d.Value)) {
				return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("record %s present but value %q != expected %q", d.Key(), cur.Value, d.Value)}
			}
		}
		return VerifyResult{Provider: provider, OK: true, Detail: "records present"}
	case model.Unexpose:
		for _, d := range desired {
			if _, ok := liveByKey[d.Key()]; ok {
				return VerifyResult{Provider: provider, OK: false, Detail: fmt.Sprintf("record %s expected absent but still present", d.Key())}
			}
		}
		return VerifyResult{Provider: provider, OK: true, Detail: "records absent"}
	default:
		return VerifyResult{Provider: provider, OK: false, Detail: "unknown verb"}
	}
}
