package core_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/netbird"
	"github.com/crenelhq/crenel/internal/model"
)

// TestCore_NetbirdEdgeReadsButRefusesMutation proves the port's LIMIT is handled
// honestly through core: a mesh edge's read-only verbs work (status sees the mesh
// as default-deny with its grants), but a mutating expose is refused LOUDLY rather
// than approximated — the design's "error loudly on inexpressible intents".
func TestCore_NetbirdEdgeReadsButRefusesMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(path, []byte(`{"grants":[{"host":"vault.example.com","group":"admins"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := core.New(netbird.New(path), "example.com")
	ctx := context.Background()

	// READ works: status sees the mesh (default-deny + the grant as a route).
	st, err := e.Status(ctx)
	if err != nil {
		t.Fatalf("status over a mesh edge should work, got: %v", err)
	}
	if len(st.Edges) != 1 || !only(st).DenyCatchAllPresent {
		t.Fatalf("mesh must read default-deny, got %+v", st.Edges)
	}
	if len(only(st).Routes) != 1 || only(st).Routes[0].Host != "vault.example.com" {
		t.Errorf("status should surface the grant, got %+v", only(st).Routes)
	}

	// MUTATE is refused loudly: expose errors with ErrIntentUnsupported.
	_, err = e.Apply(ctx, e.BuildOp(model.Expose, "vault"), core.AlwaysYes)
	if err == nil {
		t.Fatal("expose over a mesh edge must error loudly, got nil")
	}
	if !netbird.IsUnsupported(err) {
		t.Errorf("error should classify as ErrIntentUnsupported, got: %v", err)
	}
}
