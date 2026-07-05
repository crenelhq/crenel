package core_test

import (
	"context"
	"errors"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// rvEdge is a FILE-style edge: its ReadLiveState reflects an in-memory "file" that
// Apply mutates, so the artifact re-read ALWAYS "matches intent" (the hollow-verify
// shape the bench caught — gap T4/N2). It also implements ports.RuntimeVerifier with a
// configurable status, so these tests exercise how core folds the runtime tri-state
// into the ApplyReport.
type rvEdge struct {
	live    model.LiveEdgeState
	origin  string
	runtime model.RuntimeVerifyStatus
}

func (e *rvEdge) Name() string                   { return "rv" }
func (e *rvEdge) Validate(context.Context) error { return nil }
func (e *rvEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	cp := e.live
	cp.Routes = append([]model.Route(nil), e.live.Routes...)
	return cp, nil
}

func (e *rvEdge) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true
	switch op.Verb {
	case model.Expose:
		if !live.HasHost(op.Host) {
			cs.Edge.AddRoutes = []model.Route{{Host: op.Host, Upstream: model.Upstream{
				Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: e.origin, ServerName: op.Host}}}
		}
	case model.Unexpose:
		if live.HasHost(op.Host) {
			cs.Edge.RemoveHosts = []string{op.Host}
		}
	}
	return cs, nil
}

func (e *rvEdge) Apply(_ context.Context, cs model.ChangeSet) error {
	for _, h := range cs.Edge.RemoveHosts {
		var kept []model.Route
		for _, r := range e.live.Routes {
			if r.Host != h {
				kept = append(kept, r)
			}
		}
		e.live.Routes = kept
	}
	for _, r := range cs.Edge.AddRoutes {
		r.Managed, r.Ownership = true, model.OwnCrenel
		e.live.Routes = append(e.live.Routes, r)
	}
	e.live.DenyCatchAllPresent = true
	return nil
}

func (e *rvEdge) VerifyRuntime(context.Context, model.Op, model.EdgeChange) model.RuntimeVerification {
	return model.RuntimeVerification{Status: e.runtime, Detail: "test runtime probe"}
}

// TestEngine_RuntimeConfirmedIsFullyVerified: a file edge whose daemon CONFIRMS the
// change earns FullyVerified (a true "verified LIVE").
func TestEngine_RuntimeConfirmedIsFullyVerified(t *testing.T) {
	edge := &rvEdge{live: model.LiveEdgeState{DenyCatchAllPresent: true}, origin: "10.0.0.1:80", runtime: model.RuntimeVerifyConfirmed}
	eng := core.New(edge, "example.com")
	rep, err := eng.Apply(context.Background(), eng.BuildOp(model.Expose, "svc"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !rep.FullyVerified() {
		t.Errorf("runtime-confirmed apply must be FullyVerified, got verify=%+v", rep.Verify)
	}
}

// TestEngine_RuntimeUnavailableRefusedWithoutAllowUnverified: a file edge with NO
// runtime surface can only re-read its OWN written file — never proof the running
// daemon picked it up. Without the explicit AllowUnverified escape hatch (audit
// F2), Apply must REFUSE (rolling back the write) rather than let an unconfirmed
// write stand as a silent green.
func TestEngine_RuntimeUnavailableRefusedWithoutAllowUnverified(t *testing.T) {
	edge := &rvEdge{live: model.LiveEdgeState{DenyCatchAllPresent: true}, origin: "10.0.0.1:80", runtime: model.RuntimeVerifyUnavailable}
	eng := core.New(edge, "example.com")
	_, err := eng.Apply(context.Background(), eng.BuildOp(model.Expose, "svc"), core.AlwaysYes)
	var uerr *core.UnverifiedWriteError
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *core.UnverifiedWriteError, got %v", err)
	}
	if edge.live.HasHost("svc.example.com") {
		t.Error("the unconfirmed write should have been rolled back")
	}
}

// TestEngine_RuntimeUnavailableAllowedWithFlag: with AllowUnverified set (the
// --allow-unverified escape hatch, or an interactive accept), the write stands —
// Verified (written + re-read OK) but NOT FullyVerified — the report must say
// "written; runtime verify unavailable", never "verified".
func TestEngine_RuntimeUnavailableAllowedWithFlag(t *testing.T) {
	edge := &rvEdge{live: model.LiveEdgeState{DenyCatchAllPresent: true}, origin: "10.0.0.1:80", runtime: model.RuntimeVerifyUnavailable}
	eng := core.New(edge, "example.com")
	eng.AllowUnverified = true
	rep, err := eng.Apply(context.Background(), eng.BuildOp(model.Expose, "svc"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !rep.Verified() {
		t.Error("the write happened + re-read OK, so Verified() should be true")
	}
	if rep.FullyVerified() {
		t.Error("no runtime confirmation => must NOT be FullyVerified (no false green)")
	}
	if got := rep.RuntimeUnconfirmed(); len(got) != 1 {
		t.Errorf("expected 1 runtime-unconfirmed result, got %d", len(got))
	}
}

// TestEngine_RuntimeFailedRollsBack: a file edge whose daemon CONTRADICTS the change
// (rejected config / route not live — the exact false green the bench caught) fails
// verification and rolls back, instead of printing a green.
func TestEngine_RuntimeFailedRollsBack(t *testing.T) {
	edge := &rvEdge{live: model.LiveEdgeState{DenyCatchAllPresent: true}, origin: "10.0.0.1:80", runtime: model.RuntimeVerifyFailed}
	eng := core.New(edge, "example.com")
	rep, err := eng.Apply(context.Background(), eng.BuildOp(model.Expose, "svc"), core.AlwaysYes)
	if err == nil {
		t.Fatal("a runtime-FAILED apply must return an error (rolled back), not succeed")
	}
	if rep.Verified() {
		t.Error("a runtime-failed apply must not read as verified")
	}
	// The compensating rollback removed the route from the in-memory file.
	if edge.live.HasHost("svc.example.com") {
		t.Error("rollback should have removed the route after a failed runtime verify")
	}
}
