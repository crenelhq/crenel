package traefik

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresRouterWithoutBackend proves Traefik's normalize DECLARES a
// router whose host(s) it can read but whose service it cannot resolve to an
// upstream — rather than silently dropping it (detect-and-declare-unknown). The
// always-present deny router (host-less, no upstream) is NOT flagged.
func TestNormalize_DeclaresRouterWithoutBackend(t *testing.T) {
	// app.example.com routes to a service with no server URL (e.g. a weighted/dynamic
	// service crenel does not model). grafana is a normal resolvable route.
	seed := `{
      "http": {
        "routers": {
          "crenel-grafana.example.com": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "crenel-grafana.example.com"},
          "app": {"rule": "Host(` + "`app.example.com`" + `)", "service": "app-weighted"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "crenel-grafana.example.com": {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}},
          "app-weighted": {"loadBalancer": {"servers": []}},
          "crenel-deny": {"loadBalancer": {}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.HasHost("grafana.example.com") || len(live.Routes) != 1 {
		t.Fatalf("only the resolvable grafana route should enumerate, got %v", live.Hosts())
	}
	if len(live.Unparsed) != 1 || live.Unparsed[0].Kind != model.UnknownBackend {
		t.Fatalf("expected one backend_indirect unparsed entry for app.example.com, got %+v", live.Unparsed)
	}
	if !live.DenyCatchAllPresent {
		t.Error("deny router present + no permissive catch-all => DenyCatchAllPresent")
	}
	if live.DenyState() != model.DenyUnknown {
		t.Errorf("unparsed router must downgrade deny to UNKNOWN, got %q", live.DenyState())
	}
}
