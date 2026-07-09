package core

import (
	"context"
	"errors"
	"fmt"
)

// ErrReadOnlyEngine classifies the read-only posture's refusal: this engine was
// constructed to AUDIT a topology, never to mutate it (settings `read_only: true`
// today; the zero-config audit-target mode forces it). Every mutating verb refuses
// with this sentinel BEFORE planning — no driver Plan/Apply, no Persister/Adopter
// capability is ever invoked. Distinct from ErrRefuseToManage (per-route/edge
// OWNERSHIP, decided from live state): read-only is a property of the ENGINE the
// operator chose, so there is no --force/--yes escape — remove `read_only` to manage.
// Callers/tests classify it with errors.Is.
var ErrReadOnlyEngine = errors.New("read-only engine: refusing to mutate")

// gateReadOnly is the belt half of the read-only posture (belt-and-braces, §3.2 of
// the audit-any-edge design): each mutating verb calls it first, before any plan.
// The braces half is structural: a consumer that only ever needs reads holds the
// narrow ReadOnlyEngine interface below, so mutation is unreachable BY TYPE there.
func (e *Engine) gateReadOnly(verb string) error {
	if !e.ReadOnly {
		return nil
	}
	return fmt.Errorf("%w: %s is a mutating verb and this engine is READ-ONLY "+
		"(`read_only: true` in settings, or an audit-target invocation) — crenel audits this "+
		"topology and will not plan or apply writes here; remove `read_only` to manage it", ErrReadOnlyEngine, verb)
}

// ReadOnlyEngine is the narrow read-only capability surface: the three live read
// paths and nothing else. It mirrors the MCP server's read-only-by-construction
// claim (docs/AUDIT.md §6): a consumer that holds ONLY this interface — the serve
// dashboard's posture, and the audit-target mode's engine handle — literally cannot
// reach a mutating method; the Go type system, not a runtime check, forbids it.
// *Engine satisfies it.
type ReadOnlyEngine interface {
	Status(ctx context.Context) (StatusReport, error)
	Audit(ctx context.Context) (AuditReport, error)
	DetectDrift(ctx context.Context) (ReconcilePlan, error)
}

// Compile-time assertion that the real engine is a valid read-only engine. This
// does NOT widen any consumer's view — a holder's field stays the narrow interface.
var _ ReadOnlyEngine = (*Engine)(nil)
