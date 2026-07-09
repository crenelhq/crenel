package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// import.go implements `crenel import` — ADOPTION of a pre-existing (brownfield)
// setup. It scans live, finds UNMANAGED routes that fall within Crenel's managed
// domain and match their configured origin, and stamps each driver's ownership
// marker IN-PLACE so the imperative verbs / reconcile / apply can manage them
// afterwards. It never changes runtime behavior and never touches anything
// outside the managed domain. See docs/internal/USABILITY-DESIGN.md §A.

// AdoptCandidate is one unmanaged-but-matching route Crenel would bring under
// management (stamp its ownership marker) without changing behavior.
type AdoptCandidate struct {
	Edge    string          `json:"edge"`
	Driver  string          `json:"driver"`
	Host    string          `json:"host"`
	Service string          `json:"service"`
	Address string          `json:"address"` // the live backend (preserved as-is)
	Mode    model.RouteMode `json:"mode"`
}

// ImportConflict is a host in the managed domain that is present but exposed
// DIFFERENTLY than configured (different backend, or a shape Crenel cannot model
// as a flat host→backend route). Crenel refuses to adopt it — adoption must not
// change behavior — and reports it for the operator to resolve explicitly.
type ImportConflict struct {
	Edge    string `json:"edge"`
	Driver  string `json:"driver"`
	Host    string `json:"host"`
	Service string `json:"service"`
	Reason  string `json:"reason"` // "origin_mismatch" | "driver_unsupported"
	Detail  string `json:"detail"`
}

// ImportPlan is the previewed result of an import scan.
type ImportPlan struct {
	Adopt          []AdoptCandidate `json:"adopt"`
	Conflicts      []ImportConflict `json:"conflicts"`
	AlreadyManaged []string         `json:"already_managed"`
}

// Empty reports whether there is nothing to adopt (a clean already-managed world).
func (p ImportPlan) Empty() bool { return len(p.Adopt) == 0 }

// ImportConfirmFunc previews the import plan before adopting. (true,nil) proceeds;
// (false,nil) aborts cleanly. Use AlwaysYesImport for --yes.
type ImportConfirmFunc func(ImportPlan) (bool, error)

// AlwaysYesImport approves an import without prompting (for --yes).
func AlwaysYesImport(ImportPlan) (bool, error) { return true, nil }

// ImportReport is the outcome of an import.
type ImportReport struct {
	Plan    ImportPlan
	Adopted bool
	Verify  []VerifyResult
}

// Verified reports whether every adopted host read back as managed + unchanged.
func (r ImportReport) Verified() bool {
	for _, v := range r.Verify {
		if !v.OK {
			return false
		}
	}
	return true
}

// DetectImport is the read-only scan half of import: it reports what `import`
// would adopt without mutating anything. Powers `import --dry-run` and the preview.
func (e *Engine) DetectImport(ctx context.Context) (ImportPlan, error) {
	return e.planImport(ctx)
}

// Import scans live, previews the adoption, and (on confirm) stamps ownership
// markers in-place, then read-back-verifies each adopted host is now managed and
// still reachable (behavior unchanged). Preview-then-confirm like every mutating
// verb (honors --yes). Adoption is purely additive: it can never take anything
// down or expose anything new.
func (e *Engine) Import(ctx context.Context, confirm ImportConfirmFunc) (ImportReport, error) {
	var rep ImportReport
	// Read-only posture: refuse before planning (DetectImport stays available — it reads).
	if err := e.gateReadOnly("import"); err != nil {
		return rep, err
	}
	plan, err := e.planImport(ctx)
	if err != nil {
		return rep, err
	}
	rep.Plan = plan
	if plan.Empty() {
		return rep, nil // nothing to adopt; Adopted stays false
	}

	ok, err := confirm(plan)
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, nil // declined
	}

	// Group adoptions by edge, then ask each edge's Adopter to stamp them.
	byEdge := map[string][]string{}
	for _, c := range plan.Adopt {
		byEdge[c.Edge] = append(byEdge[c.Edge], c.Host)
	}
	for _, b := range e.Edges {
		hosts := byEdge[b.Name]
		if len(hosts) == 0 {
			continue
		}
		ad, ok := b.Provider.(ports.Adopter)
		if !ok {
			return rep, fmt.Errorf("import: edge %q (%s) does not support adoption", b.Name, b.Provider.Name())
		}
		if err := ad.Adopt(ctx, hosts); err != nil {
			return rep, fmt.Errorf("import: adopt on edge %q: %w", b.Name, err)
		}
	}
	rep.Adopted = true

	rep.Verify = e.verifyImport(ctx, plan)
	if !rep.Verified() {
		var bad []string
		for _, v := range rep.Verify {
			if !v.OK {
				bad = append(bad, fmt.Sprintf("%s: %s", v.Provider, v.Detail))
			}
		}
		return rep, fmt.Errorf("import read-back verification FAILED: %s", strings.Join(bad, "; "))
	}
	return rep, nil
}

// planImport reads live across every edge and classifies each in-domain route as
// already-managed, adoptable (origin matches), or a conflict. Pure (no mutation).
func (e *Engine) planImport(ctx context.Context) (ImportPlan, error) {
	var plan ImportPlan
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return ImportPlan{}, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		_, isAdopter := b.Provider.(ports.Adopter)
		for _, r := range live.Routes {
			svc := e.serviceOf(r.Host)
			// MANAGED DOMAIN: only routes whose service THIS edge fronts are eligible.
			// Everything else (Authelia, dashboards, wildcard subroutes for a service
			// not in origins) is outside the domain and never shown or touched.
			if !b.fronts(svc) {
				continue
			}
			if r.Managed {
				plan.AlreadyManaged = append(plan.AlreadyManaged, r.Host)
				continue
			}
			// Refuse to stamp a marker onto a route crenel cannot safely own: a
			// generator-owned (FOREIGN) block would have the marker regenerated away
			// (adopting it is itself a MISMANAGE), and an UNKNOWN-owned block must not be
			// touched blind. Surface as a conflict instead of adopting (register §4.5).
			if r.Ownership == model.OwnForeign || r.Ownership == model.OwnUnknown {
				reason, detail := "ownership_unknown", "ownership could not be determined — refusing to stamp a marker (run with verified ownership)"
				if r.Ownership == model.OwnForeign {
					src := live.Generator
					if src == "" {
						src = "another tool"
					}
					reason = "foreign_managed"
					detail = fmt.Sprintf("route is owned by %s — a stamped marker would be regenerated away; manage it at the source", src)
				}
				plan.Conflicts = append(plan.Conflicts, ImportConflict{
					Edge: b.Name, Driver: b.Provider.Name(), Host: r.Host, Service: svc,
					Reason: reason, Detail: detail,
				})
				continue
			}
			// The configured backend for this (service, host) on this edge, via the
			// driver's own resolver. A resolve failure means the edge has no origin for
			// the service — it cannot manage it, so it is effectively outside the domain.
			want, err := e.desiredAddr(b, svc, r.Host)
			if err != nil {
				continue
			}
			if !isAdopter {
				plan.Conflicts = append(plan.Conflicts, ImportConflict{
					Edge: b.Name, Driver: b.Provider.Name(), Host: r.Host, Service: svc,
					Reason: "driver_unsupported",
					Detail: "edge driver cannot stamp ownership (no adoption support)",
				})
				continue
			}
			if r.Upstream.Address != want {
				plan.Conflicts = append(plan.Conflicts, ImportConflict{
					Edge: b.Name, Driver: b.Provider.Name(), Host: r.Host, Service: svc,
					Reason: "origin_mismatch",
					Detail: fmt.Sprintf("live backend %s differs from configured %s — not adopting (would change behavior)", r.Upstream.Address, want),
				})
				continue
			}
			plan.Adopt = append(plan.Adopt, AdoptCandidate{
				Edge: b.Name, Driver: b.Provider.Name(), Host: r.Host, Service: svc,
				Address: r.Upstream.Address, Mode: r.Upstream.Mode,
			})
		}
	}
	sort.Strings(plan.AlreadyManaged)
	return plan, nil
}

// desiredAddr asks the edge's own Plan to resolve the configured backend for
// (service, host) — reusing the driver's per-edge OriginResolver — by planning a
// throwaway HTTP-proxy expose against an empty live. Mode is irrelevant to the
// resolved address, so http_proxy is used to avoid a mode-capability refusal.
func (e *Engine) desiredAddr(b EdgeBinding, service, host string) (string, error) {
	op := model.Op{Verb: model.Expose, Service: service, Host: host, Mode: model.ModeHTTPProxy}
	cs, err := b.Provider.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err != nil {
		return "", err
	}
	if len(cs.Edge.AddRoutes) != 1 {
		return "", fmt.Errorf("expected 1 planned route, got %d", len(cs.Edge.AddRoutes))
	}
	return cs.Edge.AddRoutes[0].Upstream.Address, nil
}

// verifyImport re-reads each edge and asserts every adopted host is now Managed
// AND still reachable (deny present, route present) — ownership changed, behavior
// did not.
func (e *Engine) verifyImport(ctx context.Context, plan ImportPlan) []VerifyResult {
	adoptedByEdge := map[string][]string{}
	for _, c := range plan.Adopt {
		adoptedByEdge[c.Edge] = append(adoptedByEdge[c.Edge], c.Host)
	}
	var out []VerifyResult
	for _, b := range e.Edges {
		hosts := adoptedByEdge[b.Name]
		if len(hosts) == 0 {
			continue
		}
		label := "edge[" + b.Name + "·" + b.Provider.Name() + "]"
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: reReadFailedDetail(err)})
			continue
		}
		if !live.DenyCatchAllPresent {
			out = append(out, VerifyResult{Provider: label, OK: false, Detail: "catch-all default-deny missing after adopt"})
			continue
		}
		ok, detail := true, fmt.Sprintf("%d host(s) now managed, behavior unchanged", len(hosts))
		for _, h := range hosts {
			if !managedRoute(live, h) {
				ok, detail = false, fmt.Sprintf("%s expected managed after adopt but is not", h)
				break
			}
			if !live.Reachable(h) {
				ok, detail = false, fmt.Sprintf("%s reachability changed by adopt (regression)", h)
				break
			}
		}
		out = append(out, VerifyResult{Provider: label, OK: ok, Detail: detail})
	}
	return out
}

// managedRoute reports whether host is present in live AND carries the ownership
// marker (Managed).
func managedRoute(live model.LiveEdgeState, host string) bool {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Managed
		}
	}
	return false
}
