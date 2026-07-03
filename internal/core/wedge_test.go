package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// wedgedEdge is a test double whose admin control plane is "wedged": writes fail
// (or succeed) as configured, and the health probe reports unresponsive. It lets
// us assert core's wedge-safety policy precisely: never fire a compensating
// reload into a wedged edge, and surface a recovery hint.
type wedgedEdge struct {
	live       model.LiveEdgeState
	applyErr   error // returned by Apply
	healthErr  error // returned by Healthy
	applyCalls int   // total Apply invocations (the original + any rollback)
}

func (w *wedgedEdge) Name() string                       { return "caddy" }
func (w *wedgedEdge) Validate(ctx context.Context) error { return nil }
func (w *wedgedEdge) Healthy(ctx context.Context) error  { return w.healthErr }
func (w *wedgedEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return w.live, nil
}

func (w *wedgedEdge) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true
	if op.Verb == model.Expose && !live.HasHost(op.Host) {
		cs.Edge.AddRoutes = []model.Route{{
			Host:     op.Host,
			Upstream: model.Upstream{Kind: model.ForwardToOrigin, Address: "127.0.0.1:9999", ServerName: op.Host},
		}}
		cs.NewPublic = []string{op.Host}
	}
	return cs, nil
}

func (w *wedgedEdge) Apply(ctx context.Context, cs model.ChangeSet) error {
	w.applyCalls++
	return w.applyErr
}

// TestApply_EdgeApplyWedged_ClassifiedNoHang: the edge apply fails because the
// admin API is wedged. core must return the unresponsive error and flag the edge
// as unresponsive with a recovery hint — and must not have hung.
func TestApply_EdgeApplyWedged_ClassifiedNoHang(t *testing.T) {
	we := &wedgedEdge{
		live:      model.LiveEdgeState{DenyCatchAllPresent: true},
		applyErr:  caddy.ErrAdminUnresponsive,
		healthErr: caddy.ErrAdminUnresponsive,
	}
	e := core.New(we, "example.com")
	op := e.BuildOp(model.Expose, "photos")

	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected an error from a wedged edge apply")
	}
	if !caddy.IsUnresponsive(err) {
		t.Fatalf("expected the error to wrap ErrAdminUnresponsive, got: %v", err)
	}
	if !rep.EdgeUnresponsive {
		t.Error("report should flag EdgeUnresponsive")
	}
	if rep.RecoveryHint == "" {
		t.Error("report should carry a RecoveryHint for the operator")
	}
	if we.applyCalls != 1 {
		t.Errorf("expected exactly 1 Apply (no compensating reload), got %d", we.applyCalls)
	}
}

// TestApply_RollbackSkipsWedgedEdge is the headline wedge-safety test: the edge
// apply SUCCEEDS but read-back verification fails, so rollback is triggered — and
// the edge is now wedged. core must SKIP the compensating edge reload (which
// would only deepen the wedge) rather than firing it, and report how to recover.
func TestApply_RollbackSkipsWedgedEdge(t *testing.T) {
	we := &wedgedEdge{
		// Deny present but host never appears => expose verification fails =>
		// rollback path. Health reports wedged.
		live:      model.LiveEdgeState{DenyCatchAllPresent: true},
		applyErr:  nil,
		healthErr: caddy.ErrAdminUnresponsive,
	}
	e := core.New(we, "example.com")
	op := e.BuildOp(model.Expose, "photos")

	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected verification to fail")
	}
	if !rep.RolledBack {
		t.Error("expected RolledBack=true")
	}
	if !rep.EdgeUnresponsive {
		t.Error("expected EdgeUnresponsive=true (health probe found the edge wedged)")
	}
	if rep.RecoveryHint == "" {
		t.Error("expected a RecoveryHint")
	}
	// The crucial assertion: Apply was called ONCE (the original). The rollback
	// must NOT have called Apply again — no compensating reload into a wedged edge.
	if we.applyCalls != 1 {
		t.Errorf("rollback fired a compensating reload into a wedged edge: applyCalls=%d, want 1", we.applyCalls)
	}
	var skipped bool
	for _, re := range rep.RollbackErrors {
		if re == "edge[caddy·caddy]: skipped (edge admin API unresponsive)" {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("expected a 'skipped (edge unresponsive)' rollback note, got: %v", rep.RollbackErrors)
	}
}

// TestApply_RealDriverHangingFake_NoHang is an end-to-end guard: the real Caddy
// driver against a hanging fake admin API, through core.Apply, must return a
// bounded, classified error instead of hanging.
func TestApply_RealDriverHangingFake_NoHang(t *testing.T) {
	cf := caddyfake.New()
	defer cf.Close()
	cf.SeedCaddyfile(seedGrafana)
	cf.WriteDelay = time.Hour // every mutation wedges; reads still work (Plan/snapshot)

	res := static.New(map[string]string{"photos": "10.0.0.6:2342"})
	edge := caddy.New(cf.URL(), res,
		caddy.WithGranularApply(),
		caddy.WithTimeouts(300*time.Millisecond, 400*time.Millisecond))
	e := core.New(edge, "example.com")
	op := e.BuildOp(model.Expose, "photos")

	done := make(chan error, 1)
	go func() { _, err := e.Apply(context.Background(), op, core.AlwaysYes); done <- err }()
	select {
	case err := <-done:
		if err == nil || !caddy.IsUnresponsive(err) {
			t.Fatalf("expected a bounded ErrAdminUnresponsive, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("core.Apply HUNG against a wedged admin API")
	}
}
