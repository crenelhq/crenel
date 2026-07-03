package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

const seedGrafana = "grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n"

// only returns the single edge's status (most tests are single-edge).
func only(st core.StatusReport) core.EdgeStatus {
	if len(st.Edges) == 0 {
		return core.EdgeStatus{}
	}
	return st.Edges[0]
}

func newEngine(t *testing.T, fake *caddyfake.Fake) *core.Engine {
	t.Helper()
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	return core.New(edge, "example.com")
}

func TestApply_ExposeVerifies(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	e := newEngine(t, fake)

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	if len(rep.NewPublic) != 1 || rep.NewPublic[0] != "photos.example.com" {
		t.Errorf("expected NewPublic, got %v", rep.NewPublic)
	}
}

// TestApply_SilentReloadFootgunDetected is THE key test: the fake returns 200
// from /load but does not change the running config. The engine must detect via
// read-back verification that the change did not take, and return an error.
func TestApply_SilentReloadFootgunDetected(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	fake.SilentReload = true // 200 OK but no actual change
	e := newEngine(t, fake)

	op := e.BuildOp(model.Expose, "photos")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err == nil {
		t.Fatal("expected read-back verification to FAIL on silent reload, got nil error")
	}
	if !strings.Contains(err.Error(), "read-back verification FAILED") {
		t.Errorf("expected read-back failure error, got: %v", err)
	}
	if rep.Verified() {
		t.Error("report should show verification did not pass")
	}
}

func TestApply_DeclineDoesNothing(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	e := newEngine(t, fake)

	op := e.BuildOp(model.Expose, "photos")
	decline := func(model.ChangeSet) (bool, error) { return false, nil }
	rep, err := e.Apply(context.Background(), op, decline)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Applied {
		t.Error("declined op must not be applied")
	}
	if len(fake.Loads) != 0 {
		t.Error("declined op must not POST /load")
	}
}

func TestApply_NoOpWhenAlreadyExposed(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	e := newEngine(t, fake)

	op := e.BuildOp(model.Expose, "grafana") // already exposed
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NoOp || rep.Applied {
		t.Errorf("expected no-op, got %+v", rep)
	}
}

// TestApply_UnexposeNeverLeavesHostReachable verifies the structural default-deny
// end to end: after unexposing the only host, nothing is reachable but the deny
// remains present.
func TestApply_UnexposeNeverLeavesHostReachable(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile(seedGrafana)
	e := newEngine(t, fake)

	op := e.BuildOp(model.Unexpose, "grafana")
	rep, err := e.Apply(context.Background(), op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !rep.Verified() {
		t.Fatal("unexpose should verify")
	}

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(only(st).Routes) != 0 {
		t.Errorf("expected nothing exposed, got %v", only(st).Routes)
	}
	if !only(st).DenyCatchAllPresent {
		t.Error("default-deny must remain present after removing the last route")
	}
}
