package traefik

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DetectsDockerLabelsForeign proves P2 generator detection for
// Traefik: a router carrying a provider suffix (`@docker`) marks a label-derived
// config FOREIGN-managed, so the gate refuses to mutate it (a file edit would be
// overwritten when the docker provider re-syncs).
func TestNormalize_DetectsDockerLabelsForeign(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "grafana@docker": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "grafana@docker"}
        },
        "services": {
          "grafana@docker": {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "traefik-docker-labels" {
		t.Fatalf("expected traefik-docker-labels detection, got %q", live.Generator)
	}
	if !live.HasHost("grafana.example.com") {
		t.Fatalf("the route should still be READ, got %v", live.Hosts())
	}
	for _, r := range live.Routes {
		if r.Ownership != model.OwnForeign || r.Managed {
			t.Errorf("a generator-owned route must be foreign + unmanaged, got %+v", r)
		}
	}
}

// TestNormalize_DetectsPangolinForeign proves P2 generator detection for Pangolin
// (fosrl/pangolin): a Traefik dynamic config whose routers attach Pangolin's access
// plugin middleware `badger` is recognized as Pangolin-generated and marked FOREIGN.
// Pangolin regenerates this config from its database (served via the HTTP provider),
// so a crenel file edit would be overwritten — the gate must refuse to mutate it.
func TestNormalize_DetectsPangolinForeign(t *testing.T) {
	// A Pangolin-shaped config: a resource router with the badger middleware + its
	// service. The `@http` provider suffix is how Pangolin's HTTP-provider config
	// surfaces; the badger middleware is the distinguishing signal.
	seed := `{
      "http": {
        "routers": {
          "resource-7@http": {
            "rule": "Host(` + "`app.example.com`" + `)",
            "service": "service-7@http",
            "middlewares": ["badger@http"]
          }
        },
        "services": {
          "service-7@http": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8080"}]}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "pangolin" {
		t.Fatalf("expected pangolin detection, got %q", live.Generator)
	}
	if !live.HasHost("app.example.com") {
		t.Fatalf("the route should still be READ (understanding != ownership), got %v", live.Hosts())
	}
	for _, r := range live.Routes {
		if r.Ownership != model.OwnForeign || r.Managed {
			t.Errorf("a Pangolin-owned route must be foreign + unmanaged, got %+v", r)
		}
	}
}

// TestNormalize_NoPangolinForOrdinaryMiddleware guards against false positives: an
// ordinary router with a hand-written middleware (e.g. a compress or a crenel auth
// reference) is NOT mistaken for Pangolin — only the specific `badger` plugin fires.
func TestNormalize_NoPangolinForOrdinaryMiddleware(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "crenel-app.example.com": {
            "rule": "Host(` + "`app.example.com`" + `)",
            "service": "crenel-app.example.com",
            "middlewares": ["compress@file", "authelia@file"]
          }
        },
        "services": {
          "crenel-app.example.com": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8080"}]}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "" {
		t.Errorf("an ordinary middleware must NOT trigger Pangolin detection, got %q", live.Generator)
	}
}

// TestNormalize_NoGeneratorForFileConfig guards against false positives: a static
// file-provider config (crenel-* + plain router names, no provider suffix) is NOT
// flagged as generator-owned.
func TestNormalize_NoGeneratorForFileConfig(t *testing.T) {
	d := newDriver(tempConfig(t, fixture(t)))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "" {
		t.Errorf("a file-provider config must NOT be flagged generator-owned, got %q", live.Generator)
	}
}
