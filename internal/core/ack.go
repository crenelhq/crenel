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
	if !e.ackUnackOnEdges(func(acker ports.Acker) error { return acker.Ack(ctx, host, reason) }) {
		return fmt.Errorf("ack %s: no participating edge could ack a route for this host (see docs/design/ack-marker.md for the manual marker shape per driver)", host)
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
	if !e.ackUnackOnEdges(func(acker ports.Acker) error { return acker.Unack(ctx, host) }) {
		return fmt.Errorf("unack %s: no participating edge could unack a route for this host", host)
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
// ports.Acker, tolerating a "no matching route on this edge" error from any
// individual edge (multi-edge topologies front a host on only one of several
// edges). Returns whether at least one edge accepted the operation.
func (e *Engine) ackUnackOnEdges(op func(ports.Acker) error) bool {
	ok := false
	for _, b := range e.Edges {
		acker, isAcker := b.Provider.(ports.Acker)
		if !isAcker {
			continue
		}
		if err := op(acker); err == nil {
			ok = true
		}
	}
	return ok
}
