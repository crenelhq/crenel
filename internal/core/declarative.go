package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// declarative.go implements `crenel apply <file>` — kubectl-style declarative
// exposure. It diffs a file's desired EXPOSURES set against LIVE, previews
// ("about to go public" highlighted), and applies all-or-nothing with read-back
// verify. It is a point-in-time ASSERTION (live stays the truth), NOT a watched
// mirror, and it holds NO stored desired state: the file is intent only for the
// duration of this call. See USABILITY-DESIGN.md §C.

// Exposure is one desired exposure from an apply file. Host may be omitted (then
// derived from Service + zone). Edges/Scopes optionally restrict where it lands;
// empty means "every edge that fronts the service" / "every configured scope".
type Exposure struct {
	Host    string          `json:"host,omitempty"`
	Service string          `json:"service"`
	Mode    model.RouteMode `json:"mode,omitempty"`
	// Auth names a forward-auth policy to attach (see AUTH-DESIGN.md). "" =
	// unspecified, "none" = explicit opt-out, else a named policy. A public host
	// with auth unspecified is refused by the CLI guardrail.
	Auth   string        `json:"auth,omitempty"`
	Edges  []string      `json:"edges,omitempty"`
	Scopes []model.Scope `json:"dns,omitempty"`
}

// DeclarativeOptions tunes apply. Adopt brings matching present-but-unmanaged
// hosts under management inline (instead of refusing them); Prune unexposes
// crenel-OWNED hosts absent from the file (never unmanaged ones).
type DeclarativeOptions struct {
	Adopt bool
	Prune bool
}

// DeclarativePlan is the previewed diff of the file vs live.
type DeclarativePlan struct {
	Change    model.ChangeSet
	NewPublic []string
	Adopt     []AdoptCandidate // present-unmanaged + matching: adopted inline (with --adopt)
	Prune     []string         // owned hosts absent from the file (with --prune)
	Blocked   []ImportConflict // present-unmanaged hosts that block apply (no --adopt, or true conflict)
}

// Empty reports whether applying the file would change nothing.
func (p DeclarativePlan) Empty() bool {
	return p.Change.Empty() && len(p.Adopt) == 0 && len(p.Prune) == 0
}

// DeclarativeReport is the outcome of an apply.
type DeclarativeReport struct {
	Plan    DeclarativePlan
	Applied bool
	Verify  []VerifyResult
	txnOutcome
}

// Verified reports whether every provider's read-back verification passed.
func (r DeclarativeReport) Verified() bool {
	for _, v := range r.Verify {
		if !v.OK {
			return false
		}
	}
	return true
}

// PlanDeclarative computes the diff of the desired exposures vs live WITHOUT
// mutating anything (powers the preview and `apply --dry-run`).
func (e *Engine) PlanDeclarative(ctx context.Context, exposures []Exposure, opts DeclarativeOptions) (DeclarativePlan, error) {
	return e.planDeclarative(ctx, exposures, opts)
}

// ApplyDeclarative converges the managed set to the file: preview → confirm →
// (adopt inline) → all-or-nothing apply → read-back-verify, reusing the same
// transactional step machinery as Apply/Reconcile. Blocked hosts (present-
// unmanaged without --adopt, or true conflicts) abort BEFORE any mutation.
func (e *Engine) ApplyDeclarative(ctx context.Context, exposures []Exposure, opts DeclarativeOptions, confirm ConfirmFunc) (DeclarativeReport, error) {
	var rep DeclarativeReport
	plan, err := e.planDeclarative(ctx, exposures, opts)
	if err != nil {
		return rep, err
	}
	rep.Plan = plan

	if len(plan.Blocked) > 0 {
		var hosts []string
		for _, b := range plan.Blocked {
			hosts = append(hosts, fmt.Sprintf("%s (%s)", b.Host, b.Reason))
		}
		return rep, fmt.Errorf("apply blocked: %d host(s) exist unmanaged or conflict — run `crenel import` first, or apply --adopt: %s",
			len(plan.Blocked), strings.Join(hosts, ", "))
	}
	if plan.Empty() {
		rep.Applied = false
		return rep, nil // nothing to do
	}

	// Refuse-to-manage gate (register §4.5): refuse before mutating a foreign/unknown
	// route or edge. (Foreign/unknown present-unmanaged hosts are already classified
	// as Blocked by planDeclarative, so adoption never stamps them either.)
	if err := e.gateOwnership(ctx, plan.Change); err != nil {
		return rep, err
	}

	ok, err := confirm(declarativeChangeForConfirm(plan))
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, nil // declined
	}

	// Adopt matching present-unmanaged hosts inline FIRST (additive, behavior-
	// preserving) so they become managed no-ops before the transaction.
	if len(plan.Adopt) > 0 {
		if err := e.adoptInline(ctx, plan.Adopt); err != nil {
			return rep, fmt.Errorf("apply --adopt: %w", err)
		}
	}

	// Re-snapshot each participating edge right before applying so the compensating
	// inverses are built against current live state (mirrors Apply/Reconcile).
	edgeSnaps := make(map[string]model.LiveEdgeState, len(plan.Change.Edges))
	for _, ep := range plan.Change.Edges {
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

	// Declarative apply moves exposure UP (asserting a desired set), so order
	// ascending like Expose: every edge route is brought up before public DNS is
	// announced. Prune removes fold into edge RemoveHosts (drivers remove before
	// add) and DNS Remove (applied alongside each provider's change).
	steps := e.buildSteps(ctx, model.Op{Verb: model.Expose}, plan.Change, edgeSnaps)
	var applied []compensator
	for _, st := range steps {
		if err := st.do(); err != nil {
			if st.edge != nil {
				probeEdge(ctx, st.edge, &rep.txnOutcome)
			}
			e.rollback(ctx, applied, &rep.txnOutcome)
			return rep, fmt.Errorf("apply %s: %w", st.name, err)
		}
		applied = append(applied, compensator{name: st.name, undo: st.undo, edge: st.edge})
	}
	rep.Applied = true

	rep.Verify = e.verifyDeclarative(ctx, plan)
	if !rep.Verified() {
		e.rollback(ctx, applied, &rep.txnOutcome)
		var bad []string
		for _, v := range rep.Verify {
			if !v.OK {
				bad = append(bad, fmt.Sprintf("%s: %s", v.Provider, v.Detail))
			}
		}
		return rep, fmt.Errorf("apply read-back verification FAILED: %s", strings.Join(bad, "; "))
	}
	e.persistEdges(ctx, plan.Change.Edges, &rep.txnOutcome)
	return rep, nil
}

// desiredRoute pairs a desired host with the mode it should carry on an edge.
type desiredRoute struct {
	host string
	mode model.RouteMode
}

// planDeclarative reads live once per edge, then for each desired exposure decides
// per target edge whether it is already satisfied, adoptable, blocked, or needs a
// new route; aggregates DNS adds; and (with --prune) schedules owned hosts absent
// from the file for removal.
func (e *Engine) planDeclarative(ctx context.Context, exposures []Exposure, opts DeclarativeOptions) (DeclarativePlan, error) {
	var plan DeclarativePlan

	lives := map[string]model.LiveEdgeState{}
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return plan, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		lives[b.Name] = live
	}

	// desiredByEdge[edge] = set of desired (host, mode) on that edge; used by prune
	// and verify. edgeChanges[edge] accumulates the additive route changes.
	desiredByEdge := map[string][]desiredRoute{}
	edgeChanges := map[string]*model.EdgeChange{}
	desiredHosts := map[string]bool{} // lower(host) anywhere — for DNS + prune

	for _, ex := range exposures {
		host := e.exposureHost(ex)
		if host == "" {
			return plan, fmt.Errorf("apply: exposure for service %q has no host and no zone to derive one", ex.Service)
		}
		// Auth is HTTP-only: refuse a policy on a passthrough/mesh exposure loudly.
		if err := model.ValidateAuth(ex.Mode, ex.Auth); err != nil {
			return plan, fmt.Errorf("apply: exposure %s: %w", host, err)
		}
		desiredHosts[strings.ToLower(host)] = true
		for _, b := range e.targetEdges(ex) {
			live := lives[b.Name]
			desiredByEdge[b.Name] = append(desiredByEdge[b.Name], desiredRoute{host: host, mode: ex.Mode})

			if live.HasHost(host) {
				if managedRoute(live, host) {
					continue // already managed + present => satisfied
				}
				// Present but FOREIGN/UNKNOWN-owned: never adopt or mutate it (register
				// §4.5) — block regardless of --adopt (the marker would be regenerated
				// away, or ownership is unverified).
				if own := ownershipOf(live, host); own == model.OwnForeign || own == model.OwnUnknown {
					reason, detail := "ownership_unknown", "ownership could not be determined — refusing to adopt; verify ownership out-of-band"
					if own == model.OwnForeign {
						reason, detail = "foreign_managed", "route is generator-owned — a crenel edit/marker would be reverted; manage it at the source"
					}
					plan.Blocked = append(plan.Blocked, ImportConflict{
						Edge: b.Name, Driver: b.Provider.Name(), Host: host, Service: ex.Service,
						Reason: reason, Detail: detail,
					})
					continue
				}
				// Present but UNMANAGED: adopt inline (if --adopt and origin matches)
				// or block. Reuse the import classification.
				want, err := e.desiredAddr(b, ex.Service, host)
				if err != nil {
					plan.Blocked = append(plan.Blocked, ImportConflict{
						Edge: b.Name, Driver: b.Provider.Name(), Host: host, Service: ex.Service,
						Reason: "unresolvable", Detail: err.Error(),
					})
					continue
				}
				liveAddr := addrOf(live, host)
				if liveAddr != want {
					plan.Blocked = append(plan.Blocked, ImportConflict{
						Edge: b.Name, Driver: b.Provider.Name(), Host: host, Service: ex.Service,
						Reason: "origin_mismatch",
						Detail: fmt.Sprintf("live backend %s differs from configured %s", liveAddr, want),
					})
					continue
				}
				if !opts.Adopt {
					plan.Blocked = append(plan.Blocked, ImportConflict{
						Edge: b.Name, Driver: b.Provider.Name(), Host: host, Service: ex.Service,
						Reason: "exists_unmanaged",
						Detail: "matches the file but is unmanaged — run `crenel import` or apply --adopt",
					})
					continue
				}
				plan.Adopt = append(plan.Adopt, AdoptCandidate{
					Edge: b.Name, Driver: b.Provider.Name(), Host: host, Service: ex.Service,
					Address: liveAddr, Mode: ex.Mode,
				})
				continue // adoption makes it satisfied; no AddRoute needed
			}

			// Not present: plan the expose route via the driver (per-edge resolver +
			// mode capability — a driver that cannot express the mode fails loudly here).
			op := model.Op{Verb: model.Expose, Service: ex.Service, Host: host, Mode: ex.Mode, Auth: ex.Auth}
			cs, err := b.Provider.Plan(op, live)
			if err != nil {
				return plan, fmt.Errorf("apply: edge %q cannot plan %s: %w", b.Name, host, err)
			}
			ec := edgeChanges[b.Name]
			if ec == nil {
				ec = &model.EdgeChange{DenyCatchAllWillBePresent: true}
				edgeChanges[b.Name] = ec
			}
			ec.AddRoutes = append(ec.AddRoutes, cs.Edge.AddRoutes...)
		}
	}

	// --- Prune: owned hosts present on an edge but absent from the desired set. ---
	if opts.Prune {
		for _, b := range e.Edges {
			live := lives[b.Name]
			for _, r := range live.Routes {
				if !r.Managed {
					continue // never prune an unmanaged route
				}
				if desiredHosts[strings.ToLower(r.Host)] {
					continue // still desired
				}
				ec := edgeChanges[b.Name]
				if ec == nil {
					ec = &model.EdgeChange{DenyCatchAllWillBePresent: true}
					edgeChanges[b.Name] = ec
				}
				ec.RemoveHosts = append(ec.RemoveHosts, r.Host)
				plan.Prune = append(plan.Prune, r.Host)
			}
		}
	}

	// Materialize edge changes in topology order.
	for _, b := range e.Edges {
		if ec := edgeChanges[b.Name]; ec != nil && !ec.Empty() {
			plan.Change.Edges = append(plan.Change.Edges, model.EdgePlan{
				Edge: b.Name, Driver: b.Provider.Name(), Change: *ec,
			})
		}
	}

	// --- DNS: one change per provider (positionally aligned with e.DNS). ---
	for _, dp := range e.DNS {
		change := model.DNSChange{Scope: dp.Scope()}
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			return plan, fmt.Errorf("read live dns (%s): %w", dp.Name(), err)
		}
		liveSet := recKeySet(recs)
		desiredSet := map[string]bool{}
		// Adds: a desired host (whose exposure includes this scope) lacking its record.
		for _, ex := range exposures {
			if !scopeWanted(ex, dp.Scope()) {
				continue
			}
			host := e.exposureHost(ex)
			desired, err := dp.DesiredRecords(model.Op{Verb: model.Expose, Service: ex.Service, Host: host})
			if err != nil {
				return plan, fmt.Errorf("dns %s desired records: %w", dp.Name(), err)
			}
			// The full desired set is crenel's managed records — carried on the change so
			// the driver's whole-zone-push ownership gate recognizes every managed record.
			change.Managed = append(change.Managed, desired...)
			for _, rec := range desired {
				desiredSet[rec.Key()] = true
				if !liveSet[rec.Key()] {
					change.Add = append(change.Add, rec)
				}
			}
		}
		// Prune: managed records for hosts no longer desired (owned-domain only).
		if opts.Prune {
			for _, r := range recs {
				if !e.anyFronts(e.serviceOf(r.Name)) {
					continue // unmanaged record — never touch
				}
				if !desiredHosts[strings.ToLower(r.Name)] && !desiredSet[r.Key()] {
					change.Remove = append(change.Remove, r)
				}
			}
		}
		plan.Change.DNS = append(plan.Change.DNS, change)
	}

	plan.NewPublic = e.declarativeNewPublic(plan)
	sort.Strings(plan.Prune)
	return plan, nil
}

// adoptInline stamps ownership on each adopt candidate via its edge's Adopter.
func (e *Engine) adoptInline(ctx context.Context, cands []AdoptCandidate) error {
	byEdge := map[string][]string{}
	for _, c := range cands {
		byEdge[c.Edge] = append(byEdge[c.Edge], c.Host)
	}
	for _, b := range e.Edges {
		hosts := byEdge[b.Name]
		if len(hosts) == 0 {
			continue
		}
		ad, ok := b.Provider.(interface {
			Adopt(context.Context, []string) error
		})
		if !ok {
			return fmt.Errorf("edge %q (%s) does not support adoption", b.Name, b.Provider.Name())
		}
		if err := ad.Adopt(ctx, hosts); err != nil {
			return fmt.Errorf("adopt on edge %q: %w", b.Name, err)
		}
	}
	return nil
}

// exposureHost returns the exposure's explicit host or derives it from service+zone.
func (e *Engine) exposureHost(ex Exposure) string {
	if ex.Host != "" {
		return ex.Host
	}
	return e.BuildOp(model.Expose, ex.Service).Host
}

// targetEdges returns the bindings an exposure lands on: the named subset that
// also fronts the service, or (when no edges are named) every binding that fronts it.
func (e *Engine) targetEdges(ex Exposure) []EdgeBinding {
	named := map[string]bool{}
	for _, n := range ex.Edges {
		named[n] = true
	}
	var out []EdgeBinding
	for _, b := range e.Edges {
		if len(named) > 0 && !named[b.Name] {
			continue
		}
		if !b.fronts(ex.Service) {
			continue
		}
		out = append(out, b)
	}
	return out
}

// scopeWanted reports whether an exposure includes the given DNS scope (empty
// Scopes means every configured scope).
func scopeWanted(ex Exposure, scope model.Scope) bool {
	if len(ex.Scopes) == 0 {
		return true
	}
	for _, s := range ex.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// declarativeNewPublic computes which hosts this apply makes newly public: those
// gaining a public DNS record when public DNS is managed, else those gaining a
// non-mesh edge route (mirrors computeNewPublic).
func (e *Engine) declarativeNewPublic(plan DeclarativePlan) []string {
	hasPublicDNS := false
	for _, dp := range e.DNS {
		if dp.Scope() == model.ScopePublic {
			hasPublicDNS = true
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h == "" || seen[strings.ToLower(h)] {
			return
		}
		seen[strings.ToLower(h)] = true
		out = append(out, h)
	}
	if hasPublicDNS {
		for _, d := range plan.Change.DNS {
			if d.Scope == model.ScopePublic {
				for _, rec := range d.Add {
					add(rec.Name)
				}
			}
		}
	} else {
		for _, ep := range plan.Change.Edges {
			for _, r := range ep.Change.AddRoutes {
				if r.Upstream.Mode != model.ModeMeshGrant {
					add(r.Host)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// verifyDeclarative re-reads each edge + DNS provider and asserts convergence to
// the file: every desired host reachable in its mode, the deny present, pruned
// hosts absent, and DNS adds present / removes absent.
func (e *Engine) verifyDeclarative(ctx context.Context, plan DeclarativePlan) []VerifyResult {
	var out []VerifyResult

	pruned := map[string]bool{}
	for _, h := range plan.Prune {
		pruned[strings.ToLower(h)] = true
	}
	// Desired (host, mode) per edge, recomputed from the change + live so verify is
	// independent of the apply path.
	for _, b := range e.Edges {
		label := "edge[" + b.Name + "·" + b.Provider.Name() + "]"
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: reReadFailedDetail(err)})
			continue
		}
		if !live.DenyCatchAllPresent {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: "catch-all default-deny missing after apply"})
			continue
		}
		ok, detail := true, "consistent with the desired exposures"
		for _, h := range plan.desiredHostsOnEdge(b.Name) {
			if pruned[strings.ToLower(h)] {
				continue
			}
			if !live.Reachable(h) {
				ok, detail = false, fmt.Sprintf("%s expected reachable but is not", h)
				break
			}
		}
		if ok {
			for _, h := range plan.Prune {
				if live.HasHost(h) {
					ok, detail = false, fmt.Sprintf("%s expected pruned but still present", h)
					break
				}
			}
		}
		// Auth + upstream-TLS read-back on the routes this apply ADDED — parity with the
		// primary expose path's verify() (closes the consolidation-pass auth-verify gap on
		// the declarative path). Without this a render that attached the route but SILENTLY
		// dropped its forward-auth policy (or a chain-forward's upstream TLS) would read back
		// reachable and verify GREEN, publishing the host unprotected / 400-ing at request
		// time. Asserted only over AddRoutes (adoption preserves existing auth verbatim).
		if ok {
			added := plan.addRoutesOnEdge(b.Name)
			if d := verifyEdgeAuth(live, added); d != "" {
				ok, detail = false, d
			} else if d := verifyEdgeForwardTLS(live, added); d != "" {
				ok, detail = false, d
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
		if i < len(plan.Change.DNS) {
			for _, add := range plan.Change.DNS[i].Add {
				if !liveSet[add.Key()] {
					ok, detail = false, fmt.Sprintf("record %s expected present but missing", add.Key())
					break
				}
			}
			if ok {
				for _, rm := range plan.Change.DNS[i].Remove {
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

// desiredHostsOnEdge returns the desired hostnames that should be reachable on the
// named edge (from the change's AddRoutes plus any already-satisfied hosts are not
// re-listed here; verify only asserts the routes this apply touched plus adoptions
// via reachability). For simplicity it derives from the planned AddRoutes.
func (p DeclarativePlan) desiredHostsOnEdge(edge string) []string {
	var out []string
	for _, ep := range p.Change.Edges {
		if ep.Edge != edge {
			continue
		}
		for _, r := range ep.Change.AddRoutes {
			out = append(out, r.Host)
		}
	}
	for _, a := range p.Adopt {
		if a.Edge == edge {
			out = append(out, a.Host)
		}
	}
	return out
}

// addRoutesOnEdge returns the routes this plan ADDS on the named edge (carrying their
// planned auth/upstream-TLS intent) — the set the auth + upstream-TLS read-backs assert
// against. Adoptions are excluded: they preserve an existing route's auth verbatim and
// carry no planned policy to re-assert.
func (p DeclarativePlan) addRoutesOnEdge(edge string) []model.Route {
	var out []model.Route
	for _, ep := range p.Change.Edges {
		if ep.Edge != edge {
			continue
		}
		out = append(out, ep.Change.AddRoutes...)
	}
	return out
}

// declarativeChangeForConfirm packages the plan's change with its NewPublic for
// the confirm prompt (so the CLI's printChangeSet highlights "about to go public").
func declarativeChangeForConfirm(plan DeclarativePlan) model.ChangeSet {
	cs := plan.Change
	cs.NewPublic = plan.NewPublic
	return cs
}

// addrOf returns the live backend address of host, if present.
func addrOf(live model.LiveEdgeState, host string) string {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Upstream.Address
		}
	}
	return ""
}
