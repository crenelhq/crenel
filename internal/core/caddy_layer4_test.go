package core_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestCore_CaddyLayer4Passthrough proves SNI passthrough now renders on the Caddy
// edge (via the layer4 app) THROUGH the engine — the same intent (ModeTCPPassthrough)
// that M9 made real on Traefik now works on Caddy too. core is unchanged: it plans,
// applies, and read-back-verifies the passthrough exposure exactly as for http.
func TestCore_CaddyLayer4Passthrough(t *testing.T) {
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	res := static.New(map[string]string{"db": "10.0.0.7:5432"})
	edge := caddy.New(cf.URL(), res, caddy.WithGranularApply(), caddy.WithLayer4())
	e := core.New(edge, "example.com")
	ctx := context.Background()

	op := e.BuildOp(model.Expose, "db")
	op.Mode = model.ModeTCPPassthrough

	// The passthrough exposure IS publicly reachable (no public DNS managed here),
	// so it must show up in NewPublic.
	cs, err := e.Plan(ctx, op)
	if err != nil {
		t.Fatalf("plan passthrough: %v", err)
	}
	if len(cs.NewPublic) != 1 || cs.NewPublic[0] != "db.example.com" {
		t.Errorf("a passthrough exposure should be flagged about-to-go-public, got %v", cs.NewPublic)
	}

	rep, err := e.Apply(ctx, op, core.AlwaysYes)
	if err != nil {
		t.Fatalf("apply passthrough through core: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("passthrough should read-back-verify, got %+v", rep.Verify)
	}

	st, _ := e.Status(ctx)
	found := false
	for _, r := range st.Edges[0].Routes {
		if r.Host == "db.example.com" && r.Upstream.Mode == model.ModeTCPPassthrough {
			found = true
		}
	}
	if !found {
		t.Error("status should show db as a passthrough route after the engine apply")
	}

	// Unexpose through the engine removes it and verifies, deny intact.
	un := e.BuildOp(model.Unexpose, "db")
	un.Mode = model.ModeTCPPassthrough
	repU, err := e.Apply(ctx, un, core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose passthrough: %v", err)
	}
	if !repU.Verified() {
		t.Fatalf("unexpose should verify, got %+v", repU.Verify)
	}
	stF, _ := e.Status(ctx)
	if !stF.Edges[0].DenyCatchAllPresent {
		t.Error("deny must remain present after passthrough unexpose")
	}
	for _, r := range stF.Edges[0].Routes {
		if r.Host == "db.example.com" {
			t.Error("db passthrough route should be gone after unexpose")
		}
	}
}
