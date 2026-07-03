package core

import (
	"context"

	"github.com/crenelhq/crenel/internal/model"
)

// ResumeReport is the result of a resume: a diagnosis of which providers were
// already in the intended state vs. which still needed completing, plus the result
// of completing the remaining delta.
type ResumeReport struct {
	Op model.Op
	// Already names the providers already in the op's intended state (nothing to
	// do for them). Pending names those that still needed the change applied.
	Already []string
	Pending []string
	// NothingToDo is true when the whole intended state is already realized — the
	// world is consistent and there is nothing to resume.
	NothingToDo bool
	// Apply is the result of completing the remaining delta (zero when NothingToDo).
	Apply ApplyReport
}

// Resume re-drives an interrupted / partially-applied op from LIVE state. Because
// Crenel keeps no stored desired state, "resume" means: read live across every
// edge + DNS provider, recompute the REMAINING delta toward the op's intended
// state, and complete it with the same all-or-nothing transaction as Apply (so a
// failure mid-completion rolls the just-applied portion back cleanly). Providers
// already in the intended state are diagnosed as done and left untouched.
//
// This works precisely because every provider's Plan is a delta-against-live: a
// half-applied double-write (exposed on one edge, not another) yields an empty
// change for the done edge and a real change for the pending one.
func (e *Engine) Resume(ctx context.Context, op model.Op, confirm ConfirmFunc) (ResumeReport, error) {
	rr := ResumeReport{Op: op}

	cs, err := e.Plan(ctx, op)
	if err != nil {
		return rr, err
	}

	// Diagnose per-provider: an empty change means that provider already matches
	// the intended state (done); a non-empty change means it still needs work.
	for _, ep := range cs.Edges {
		label := "edge[" + ep.Edge + "·" + ep.Driver + "]"
		if ep.Change.Empty() {
			rr.Already = append(rr.Already, label)
		} else {
			rr.Pending = append(rr.Pending, label)
		}
	}
	for i, dp := range e.DNS {
		label := dp.Name() + "/" + string(dp.Scope())
		if i < len(cs.DNS) && !cs.DNS[i].Empty() {
			rr.Pending = append(rr.Pending, label)
		} else {
			rr.Already = append(rr.Already, label)
		}
	}

	if cs.Empty() {
		rr.NothingToDo = true
		return rr, nil
	}

	rep, err := e.applyPlanned(ctx, op, cs, confirm)
	rr.Apply = rep
	return rr, err
}
