package nginx_test

import (
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/nginx"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestPlan_ExposeWithTo_NginxOverridesResolver: same guarantee as caddy/traefik.
func TestPlan_ExposeWithTo_NginxOverridesResolver(t *testing.T) {
	empty := static.New(map[string]string{})
	p := filepath.Join(t.TempDir(), "nginx.conf")
	d := nginx.New(p, empty)
	live := model.LiveEdgeState{DenyCatchAllPresent: true}
	cs, err := d.Plan(model.Op{
		Verb:    model.Expose,
		Service: "immich",
		Host:    "photos.example.com",
		To:      "10.0.0.99:2283",
	}, live)
	if err != nil {
		t.Fatalf("nginx Plan(--to) must succeed for a service NOT in origins: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 {
		t.Fatalf("expected one add-route, got %+v", cs.Edge.AddRoutes)
	}
	if got, want := cs.Edge.AddRoutes[0].Upstream.Address, "10.0.0.99:2283"; got != want {
		t.Errorf("nginx upstream address = %q, want %q", got, want)
	}
}
