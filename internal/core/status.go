package core

import (
	"context"
	"fmt"

	"github.com/crenelhq/crenel/internal/model"
)

// Status reads live edge (and DNS) state and returns what is exposed right now.
// It is strictly read-only — it never mutates and never consults any stored
// desired state (there is none).
//
// Chain-aware (P4): a FRONT edge's forwarded routes are FOLLOWED THROUGH to their
// downstream edge so status shows each host's REAL downstream destination + the auth
// OBSERVED there (or an honest "downstream, not observed" when the downstream is
// unreadable). All edges are read once via readAll so the downstream is read exactly
// once; a chain-target edge that cannot be read degrades to a DECLARED-UNKNOWN row
// rather than aborting the whole status.
func (e *Engine) Status(ctx context.Context) (StatusReport, error) {
	var rep StatusReport
	reads, err := e.readAll(ctx)
	if err != nil {
		return StatusReport{}, err
	}
	cc := buildChainContext(reads)
	for _, b := range e.Edges {
		rd := reads[b.Name]
		if rd.err != nil {
			// A chain-target edge crenel could not read: surface a DECLARED-UNKNOWN row
			// (deny UNKNOWN, coverage 0/1) — never a silent drop and never a false green.
			rep.Edges = append(rep.Edges, EdgeStatus{
				Name:                b.Name,
				Driver:              b.Provider.Name(),
				DenyCatchAllPresent: true, // present+unparsed => DenyUnknown (honest: we did not read it)
				Unparsed: []model.Unparsed{{
					Locator: "edge",
					Kind:    model.UnknownServerBlock,
					Reason:  "edge could not be read: " + rd.err.Error(),
				}},
				IngressKind: b.IngressKind,
			})
			continue
		}
		live := rd.live
		rep.Edges = append(rep.Edges, EdgeStatus{
			Name:                b.Name,
			Driver:              b.Provider.Name(),
			Routes:              annotateChain(cc, b, live.Routes),
			DenyCatchAllPresent: live.DenyCatchAllPresent,
			Unparsed:            live.Unparsed,
			Generator:           live.Generator,
			IngressKind:         b.resolveIngressKind(live),
			Persistence:         live.Persistence,
		})
	}
	for _, dp := range e.DNS {
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			return StatusReport{}, fmt.Errorf("read live dns (%s): %w", dp.Name(), err)
		}
		rep.DNS = append(rep.DNS, ScopeRecords{
			Provider: dp.Name(),
			Scope:    dp.Scope(),
			Records:  recs,
		})
	}
	return rep, nil
}

// annotateChain returns DISPLAY copies of routes with chain follow-through overlaid
// (P4): a chain-forward route gets its resolved model.ChainLink attached (real
// downstream destination + observed auth, or an unresolved Reason) and its display
// auth set to the OBSERVED downstream auth; a real front auth is preserved; the
// legacy auth_downstream label still applies on a flag-only front edge. For an
// ordinary terminal edge (no chain, no flag) it returns the routes unchanged. The
// freshly-read live state is never mutated — the overlay is on a copy.
func annotateChain(cc chainContext, b EdgeBinding, routes []model.Route) []model.Route {
	if !b.isChainFront() && !b.AuthDownstream {
		return routes
	}
	out := make([]model.Route, len(routes))
	copy(out, routes)
	for i := range out {
		if link := cc.resolveChain(b, out[i]); link != nil {
			out[i].Chain = link
		}
		out[i].Upstream.Auth = cc.effectiveAuth(b, out[i])
	}
	return out
}
