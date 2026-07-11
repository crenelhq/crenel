package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// This file is the core surface behind `crenel triage` and `crenel ack --route`:
// enumerating every route crenel could NOT understand (the exact set audit's
// coverage_incomplete finding counts) and acknowledging one by its STRUCTURAL
// PATH — the Unparsed.Locator — for the routes host-addressed Ack cannot reach
// (no recoverable host). Same posture as Ack: a live-config WRITE, gated by
// read-only, never a silent claim (read-back-verified against the locator).

// TriageItem is one not-understood route surfaced to the operator: which edge
// declared it, the full Unparsed evidence (locator, kind, reason, bounded raw
// excerpt), and whether that edge can ack it by structural path.
type TriageItem struct {
	Edge     string
	Unparsed model.Unparsed
	// RouteAckable reports whether the item's edge implements
	// ports.LocatorAcker — i.e. AckRoute(edge, locator, …) can land. Edges
	// without the capability still SURFACE their unknowns (bounded honesty:
	// triage never hides what it cannot fix), the prompt just cannot [a]ck them.
	RouteAckable bool
}

// NotUnderstood reads live state and returns every REAL unknown (Unparsed
// entries excluding operator-acknowledged ones — the same splitAcknowledged
// partition audit's deny/coverage findings use, so triage's worklist is
// exactly what audit counts against default-deny). edgeName filters to one
// edge; "" means all. Deterministic: engine edge order, then driver-reported
// entry order.
func (e *Engine) NotUnderstood(ctx context.Context, edgeName string) ([]TriageItem, error) {
	var items []TriageItem
	matched := false
	for _, b := range e.Edges {
		if edgeName != "" && b.Name != edgeName {
			continue
		}
		matched = true
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return nil, fmt.Errorf("read edge %s: %w", b.Name, err)
		}
		realUnknown, _ := splitAcknowledged(live.Unparsed)
		_, ackable := b.Provider.(ports.LocatorAcker)
		for _, u := range realUnknown {
			items = append(items, TriageItem{Edge: b.Name, Unparsed: u, RouteAckable: ackable})
		}
	}
	if edgeName != "" && !matched {
		return nil, fmt.Errorf("no edge named %q (configured edges: %s)", edgeName, e.edgeNames())
	}
	return items, nil
}

// AckRoute stamps the crenel-ack marker onto the route at locator (structural
// path, model.Unparsed.Locator) on the named edge — or, when edgeName is "",
// on whichever LocatorAcker edge resolves the locator (multi-edge tolerance,
// mirroring ackUnackOnEdges: a locator minted by one edge is a not-found on
// the others). Then READ-BACK-VERIFIES the entry at that locator now reads
// acknowledged_unknown — never a silent claim.
func (e *Engine) AckRoute(ctx context.Context, edgeName, locator, reason string) error {
	// Read-only posture: the ack marker is a live-config WRITE, so it refuses too.
	if err := e.gateReadOnly("ack"); err != nil {
		return err
	}
	ok, failures := e.onLocatorAckers(edgeName, func(la ports.LocatorAcker) error {
		return la.AckLocator(ctx, locator, reason)
	})
	if !ok {
		return fmt.Errorf("ack --route %s: no participating edge could ack this route (path-addressed ack needs a driver with the LocatorAcker capability — Caddy today)%s",
			locator, joinEdgeFailures(failures))
	}
	// Read-back verify: the SAME locator must now classify acknowledged.
	for _, b := range e.Edges {
		if edgeName != "" && b.Name != edgeName {
			continue
		}
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			continue
		}
		for _, u := range live.Unparsed {
			if u.Kind == model.UnknownAcknowledged && u.Locator == locator {
				return nil
			}
		}
	}
	return fmt.Errorf("ack --route %s: wrote the marker but the read-back did not confirm acknowledged_unknown at this locator", locator)
}

// UnackRoute removes the crenel-ack marker from the route at locator (the
// undo of AckRoute), read-back-verifying no acknowledged entry remains at
// that locator. A no-op (not an error) if the route was not currently ack'd.
func (e *Engine) UnackRoute(ctx context.Context, edgeName, locator string) error {
	// Read-only posture: removing the marker is a write like stamping it.
	if err := e.gateReadOnly("unack"); err != nil {
		return err
	}
	ok, failures := e.onLocatorAckers(edgeName, func(la ports.LocatorAcker) error {
		return la.UnackLocator(ctx, locator)
	})
	if !ok {
		return fmt.Errorf("unack --route %s: no participating edge could unack this route%s", locator, joinEdgeFailures(failures))
	}
	for _, b := range e.Edges {
		if edgeName != "" && b.Name != edgeName {
			continue
		}
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			continue
		}
		for _, u := range live.Unparsed {
			if u.Kind == model.UnknownAcknowledged && u.Locator == locator {
				return fmt.Errorf("unack --route %s: removed the marker but the read-back still shows it acknowledged", locator)
			}
		}
	}
	return nil
}

// RouteJSON returns the full raw JSON of the route at locator from the first
// edge that can resolve it — the triage [o]pen-full-JSON evidence view. An
// edge without the capability, or one where the locator does not resolve, is
// skipped; every failure is surfaced when none succeeds.
func (e *Engine) RouteJSON(ctx context.Context, edgeName, locator string) (string, error) {
	var failures []string
	for _, b := range e.Edges {
		if edgeName != "" && b.Name != edgeName {
			continue
		}
		la, ok := b.Provider.(ports.LocatorAcker)
		if !ok {
			continue
		}
		s, err := la.RouteRawJSON(ctx, locator)
		if err != nil {
			failures = append(failures, fmt.Sprintf("edge %s: %v", b.Name, err))
			continue
		}
		return s, nil
	}
	return "", fmt.Errorf("route json %s: no edge could resolve this locator%s", locator, joinEdgeFailures(failures))
}

// onLocatorAckers runs op against every LocatorAcker edge (optionally filtered
// to one name), with the same at-least-one-accepted tolerance as
// ackUnackOnEdges: multi-edge topologies mint a locator on exactly one edge,
// so "does not resolve here" from the others is expected — but when NOTHING
// succeeded every edge's real error is surfaced, never a generic shrug.
func (e *Engine) onLocatorAckers(edgeName string, op func(ports.LocatorAcker) error) (ok bool, failures []string) {
	for _, b := range e.Edges {
		if edgeName != "" && b.Name != edgeName {
			continue
		}
		la, isLA := b.Provider.(ports.LocatorAcker)
		if !isLA {
			continue
		}
		if err := op(la); err != nil {
			failures = append(failures, fmt.Sprintf("edge %s: %v", b.Name, err))
		} else {
			ok = true
		}
	}
	return ok, failures
}

// edgeNames renders the configured edge names for a not-found error message.
func (e *Engine) edgeNames() string {
	names := make([]string, 0, len(e.Edges))
	for _, b := range e.Edges {
		names = append(names, b.Name)
	}
	return strings.Join(names, ", ")
}
