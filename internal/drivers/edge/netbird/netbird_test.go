package netbird

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

func tempGrants(t *testing.T, seed string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReadLiveState_MeshIsDefaultDeny: a mesh is default-deny by construction, and
// grants surface read-only with a visibly non-HTTP pseudo-address.
func TestReadLiveState_MeshIsDefaultDeny(t *testing.T) {
	path := tempGrants(t, `{"grants":[{"host":"vault.example.com","group":"admins"}]}`)
	d := New(path)
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("a mesh must read as default-deny (no grant => no access)")
	}
	if !live.HasHost("vault.example.com") {
		t.Errorf("grant should surface as a route, got %v", live.Hosts())
	}
	if live.Routes[0].Upstream.Address != "mesh-grant:admins" {
		t.Errorf("grant address should make the transport/identity collapse visible, got %q",
			live.Routes[0].Upstream.Address)
	}
}

// TestPlan_ErrorsLoudlyOnHTTPProxy: the default HTTP-proxy intent is refused
// loudly (classified), not approximated.
func TestPlan_ErrorsLoudlyOnHTTPProxy(t *testing.T) {
	d := New(tempGrants(t, `{}`))
	live, _ := d.ReadLiveState(context.Background())
	op := model.Op{Verb: model.Expose, Service: "vault", Host: "vault.example.com"} // default mode = HTTP proxy
	_, err := d.Plan(op, live)
	if err == nil {
		t.Fatal("expected a loud refusal, got nil")
	}
	if !IsUnsupported(err) {
		t.Fatalf("error should classify as model.ErrModeUnsupported, got: %v", err)
	}
	if !strings.Contains(err.Error(), "identity-mesh") || !strings.Contains(err.Error(), "ACL grant") {
		t.Errorf("refusal should explain WHY (identity-mesh / ACL grant), got: %v", err)
	}
}

// TestMeshGrant_PlanApplyRoundTrip: in its NATIVE ModeMeshGrant, the driver plans
// and applies a real grant (and removes it on unexpose).
func TestMeshGrant_PlanApplyRoundTrip(t *testing.T) {
	path := tempGrants(t, `{}`)
	d := New(path)
	ctx := context.Background()

	// expose --mode mesh_grant --param group=admins vault
	op := model.Op{Verb: model.Expose, Service: "vault", Host: "vault.example.com",
		Mode: model.ModeMeshGrant, Params: map[string]string{"group": "admins"}}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatalf("native mesh-grant plan should succeed, got: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 || cs.Edge.AddRoutes[0].Upstream.Mode != model.ModeMeshGrant {
		t.Fatalf("expected one mesh-grant add, got %+v", cs.Edge)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	live2, _ := d.ReadLiveState(ctx)
	if !live2.HasHost("vault.example.com") || !live2.DenyCatchAllPresent {
		t.Errorf("grant should be live + mesh default-deny holds, got %+v", live2)
	}
	if live2.Routes[0].Upstream.Address != "mesh-grant:admins" {
		t.Errorf("grant should record the group, got %q", live2.Routes[0].Upstream.Address)
	}

	// missing group => clear error.
	bad := model.Op{Verb: model.Expose, Host: "x.example.com", Mode: model.ModeMeshGrant}
	if _, err := d.Plan(bad, live2); err == nil || !strings.Contains(err.Error(), "group") {
		t.Errorf("mesh-grant without a group should error clearly, got: %v", err)
	}

	// unexpose removes the grant.
	un := model.Op{Verb: model.Unexpose, Host: "vault.example.com", Mode: model.ModeMeshGrant}
	csu, _ := d.Plan(un, live2)
	if err := d.Apply(ctx, csu); err != nil {
		t.Fatal(err)
	}
	live3, _ := d.ReadLiveState(ctx)
	if live3.HasHost("vault.example.com") {
		t.Error("grant should be removed after unexpose")
	}
}
