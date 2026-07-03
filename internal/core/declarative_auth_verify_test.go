package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// TestApplyDeclarative_FailsWhenAuthSilentlyDropped closes the consolidation-pass
// auth-verify gap on the DECLARATIVE (apply <file>) path. The primary expose path and
// reconcile already re-assert that every added route reads back carrying its planned
// forward-auth (verifyEdgeAuth); verifyDeclarative did not — it asserted only
// reachability + deny + prune. So a render/edge that attached the route but SILENTLY
// dropped the auth policy would read back "reachable", verify GREEN, and publish the
// host UNPROTECTED — the exact MISREAD the auth read-back exists to prevent, just on a
// different write path.
//
// The faithful double is memEdge with dropAuthHost: it applies the route but strips the
// auth on read-back (a render that failed to attach the policy). With auth: authelia in
// the file, the declarative apply MUST fail verification and roll the route back, not
// report success.
func TestApplyDeclarative_FailsWhenAuthSilentlyDropped(t *testing.T) {
	ctx := context.Background()
	home := &memEdge{
		name:         "home",
		origins:      map[string]string{"vault": "10.0.0.7:8200"},
		live:         &model.LiveEdgeState{DenyCatchAllPresent: true},
		dropAuthHost: "vault.homelab.example", // the edge silently loses the auth policy
	}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example")

	exposures := []core.Exposure{{Service: "vault", Auth: "authelia"}}
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes)

	if err == nil {
		t.Fatalf("declarative apply must FAIL: vault was published with auth dropped but verify passed (rep=%+v)", rep)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "auth") {
		t.Errorf("the failure must name the auth read-back, got %v", err)
	}
	if rep.Verified() {
		t.Errorf("rep must not report verified when auth was dropped: %+v", rep.Verify)
	}
	// All-or-nothing: the unprotected route must be rolled back, not left serving.
	live, _ := home.ReadLiveState(ctx)
	if live.HasHost("vault.homelab.example") {
		t.Errorf("the unprotected vault route must be rolled back, but it is still present: %+v", live.Routes)
	}
}

// TestApplyDeclarative_PassesWhenAuthLandsCorrectly is the GREEN control: the SAME
// declarative apply with auth attached correctly (no drop) converges and verifies, so
// the new auth read-back does not cry wolf on a faithful render.
func TestApplyDeclarative_PassesWhenAuthLandsCorrectly(t *testing.T) {
	ctx := context.Background()
	home := &memEdge{
		name:    "home",
		origins: map[string]string{"vault": "10.0.0.7:8200"},
		live:    &model.LiveEdgeState{DenyCatchAllPresent: true},
	}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example")

	exposures := []core.Exposure{{Service: "vault", Auth: "authelia"}}
	rep, err := e.ApplyDeclarative(ctx, exposures, core.DeclarativeOptions{}, core.AlwaysYes)
	if err != nil {
		t.Fatalf("faithful apply must succeed, got %v (%+v)", err, rep.Verify)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("apply should converge+verify, got %+v", rep)
	}
	live, _ := home.ReadLiveState(ctx)
	var got string
	var has bool
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, "vault.homelab.example") {
			got, has = r.Upstream.Auth, true
		}
	}
	if !has || got != "authelia" {
		t.Errorf("vault must read back carrying auth=authelia, got %q (has=%v)", got, has)
	}
}
