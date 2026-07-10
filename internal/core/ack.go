package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// Ack stamps the operator's crenel-ack:<reason> marker (docs/design/ack-marker.md)
// onto host's declared-unknown route, on whichever participating edge fronts
// it, then READ-BACK-VERIFIES the route now reads acknowledged_unknown — never
// a silent claim. Refuses if no participating edge implements ports.Acker (see
// the per-driver support table in the design doc) or none has a matching
// declared-unknown route for host.
func (e *Engine) Ack(ctx context.Context, host, reason string) error {
	// Read-only posture: the ack marker is a live-config WRITE, so it refuses too.
	if err := e.gateReadOnly("ack"); err != nil {
		return err
	}
	if ok, failures := e.ackUnackOnEdges(func(acker ports.Acker) error { return acker.Ack(ctx, host, reason) }); !ok {
		// Every participating edge failed (or none participates). Surface each
		// edge's REAL error — the live @id-collision bug was invisible behind the
		// old generic message, which implied the host simply didn't exist.
		return fmt.Errorf("ack %s: no participating edge could ack a route for this host (see docs/design/ack-marker.md for the manual marker shape per driver)%s", host, joinEdgeFailures(failures))
	}
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			continue
		}
		for _, u := range live.Unparsed {
			if u.Kind == model.UnknownAcknowledged && strings.Contains(strings.ToLower(u.Reason), strings.ToLower(reason)) {
				return nil
			}
		}
	}
	return fmt.Errorf("ack %s: wrote the marker but the read-back did not confirm acknowledged_unknown", host)
}

// Unack removes the crenel-ack marker from host's route on every participating
// edge that implements ports.Acker, reverting it to whatever Unparsed kind it
// would otherwise classify as, then read-back-verifies no acknowledged entry
// for host remains. A no-op (not an error) if host was not currently ack'd on
// any edge.
func (e *Engine) Unack(ctx context.Context, host string) error {
	// Read-only posture: removing the marker is a write like stamping it.
	if err := e.gateReadOnly("unack"); err != nil {
		return err
	}
	if ok, failures := e.ackUnackOnEdges(func(acker ports.Acker) error { return acker.Unack(ctx, host) }); !ok {
		// Same surfacing rule as Ack: when NOTHING succeeded, the operator gets
		// every edge's actual error, not a generic shrug.
		return fmt.Errorf("unack %s: no participating edge could unack a route for this host%s", host, joinEdgeFailures(failures))
	}
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			continue
		}
		for _, u := range live.Unparsed {
			if u.Kind == model.UnknownAcknowledged && strings.Contains(u.RawExcerpt, host) {
				return fmt.Errorf("unack %s: removed the marker but the read-back still shows it acknowledged", host)
			}
		}
	}
	return nil
}

// ackUnackOnEdges runs op against every participating edge that implements
// ports.Acker, tolerating a per-edge error as long as SOME edge accepted the
// operation (multi-edge topologies front a host on only one of several edges,
// so a "no route found for this host" from the others is expected). Returns
// whether at least one edge accepted, plus every edge's failure LABELED with
// its edge name — the callers surface those only when ok is false, so the real
// driver error (e.g. Caddy's duplicate-@id rejection) is never swallowed
// behind the generic "no participating edge" message, while the tolerated
// not-found-on-this-edge case stays a non-error whenever another edge succeeds.
func (e *Engine) ackUnackOnEdges(op func(ports.Acker) error) (ok bool, failures []string) {
	for _, b := range e.Edges {
		acker, isAcker := b.Provider.(ports.Acker)
		if !isAcker {
			continue
		}
		if err := op(acker); err != nil {
			failures = append(failures, fmt.Sprintf("edge %s: %v", b.Name, err))
		} else {
			ok = true
		}
	}
	return ok, failures
}

// joinEdgeFailures renders the per-edge failure list as an indented block for
// the all-edges-failed error message; empty (no Acker edges at all, or none
// errored) renders nothing so the base message stands alone.
func joinEdgeFailures(failures []string) string {
	if len(failures) == 0 {
		return ""
	}
	return ":\n  " + strings.Join(failures, "\n  ")
}
