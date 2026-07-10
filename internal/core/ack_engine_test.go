package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// TestEngine_AckUnackRoundTrip proves Engine.Ack/Unack (the ports.Acker fan-out
// + read-back-verify) work end to end against a real driver, and that Ack
// refuses cleanly when no host matches on any edge.
func TestEngine_AckUnackRoundTrip(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"host": ["app.example.com"], "path": ["/api/hawser"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.9:8080"}]}]
            },
            {"handle": [{"handler": "static_response", "status_code": 403}]}
          ]
        }
      }
    }
  }
}`); err != nil {
		t.Fatal(err)
	}
	e := core.New(caddy.New(fake.URL(), static.New(map[string]string{"app": "10.0.0.9:8080"})), "example.com")
	ctx := context.Background()

	if err := e.Ack(ctx, "app.example.com", "hawser-tailnet-agents"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Edges) != 1 || len(st.Edges[0].Acknowledged()) != 1 {
		t.Fatalf("expected 1 acknowledged entry after Ack, got %+v", st.Edges)
	}
	if !st.Edges[0].FullyParsed() || st.Edges[0].DenyState() != "enforced" {
		t.Errorf("an acked-only edge must certify ENFORCED, got FullyParsed=%v DenyState=%v",
			st.Edges[0].FullyParsed(), st.Edges[0].DenyState())
	}

	if err := e.Unack(ctx, "app.example.com"); err != nil {
		t.Fatalf("Unack: %v", err)
	}
	st, err = e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Edges[0].Acknowledged()) != 0 {
		t.Errorf("expected 0 acknowledged entries after Unack, got %+v", st.Edges[0].Unparsed)
	}

	if err := e.Ack(ctx, "nope.example.com", "no-such-host"); err == nil {
		t.Error("Ack on a host that matches nothing anywhere must return an error")
	}
}

// TestEngine_AckTwoHostsSameReason is the @id-collision regression (found live:
// acking a second host with a reason slug already used on another host was
// rejected by Caddy's admin API, because the bare crenel-ack:<reason> marker is
// an @id and @ids are GLOBALLY unique). The marker is now host-qualified
// (crenel-ack:<host>:<reason>), so both acks must succeed — the fake enforces
// real Caddy's global-uniqueness rule, so this test fails on the bare form.
func TestEngine_AckTwoHostsSameReason(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"host": ["agent-vault.example.com"], "path": ["/api/auth"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.9:8080"}]}]
            },
            {
              "match": [{"host": ["secrets.example.com"], "path": ["/api/auth"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.10:8200"}]}]
            },
            {"handle": [{"handler": "static_response", "status_code": 403}]}
          ]
        }
      }
    }
  }
}`); err != nil {
		t.Fatal(err)
	}
	e := core.New(caddy.New(fake.URL(), static.New(map[string]string{
		"agent-vault": "10.0.0.9:8080", "secrets": "10.0.0.10:8200",
	})), "example.com")
	ctx := context.Background()

	// The SAME reason slug on two different hosts — the live failure sequence.
	if err := e.Ack(ctx, "agent-vault.example.com", "api-path-auth-bypass"); err != nil {
		t.Fatalf("first ack: %v", err)
	}
	if err := e.Ack(ctx, "secrets.example.com", "api-path-auth-bypass"); err != nil {
		t.Fatalf("second ack with the same reason slug must not collide on @id: %v", err)
	}
	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(st.Edges[0].Acknowledged()); got != 2 {
		t.Fatalf("expected both hosts acknowledged, got %d: %+v", got, st.Edges[0].Unparsed)
	}
}

// TestEngine_AckAllEdgesFail_SurfacesDriverError proves the all-edges-failed
// error carries each edge's REAL driver error, edge-labeled — the live @id
// collision was invisible behind the old generic message, which implied the
// host/route simply didn't exist.
func TestEngine_AckAllEdgesFail_SurfacesDriverError(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
    {"handle":[{"handler":"static_response","status_code":403}]}
  ]}}}}}`); err != nil {
		t.Fatal(err)
	}
	e := core.New(caddy.New(fake.URL(), static.New(map[string]string{})), "example.com")

	err := e.Ack(context.Background(), "nope.example.com", "whatever")
	if err == nil {
		t.Fatal("ack of a host no edge fronts must fail")
	}
	// The generic line survives, but the per-edge driver error is appended.
	if !strings.Contains(err.Error(), "no participating edge could ack") {
		t.Errorf("error should keep the summary line, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no route found for this host") {
		t.Errorf("error must surface the driver's actual failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "edge ") {
		t.Errorf("per-edge failures must be edge-labeled, got: %v", err)
	}
}

// TestEngine_AckMultiEdgeToleratesNotFound proves multi-edge tolerance still
// holds after the error-surfacing change: a host fronted by only ONE of two
// edges acks successfully — the other edge's "no route found" is tolerated,
// not fatal, and not surfaced.
func TestEngine_AckMultiEdgeToleratesNotFound(t *testing.T) {
	empty := caddyfake.New()
	defer empty.Close()
	if err := empty.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
    {"handle":[{"handler":"static_response","status_code":403}]}
  ]}}}}}`); err != nil {
		t.Fatal(err)
	}
	fronting := caddyfake.New()
	defer fronting.Close()
	if err := fronting.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
    {"match":[{"host":["app.example.com"],"path":["/api"]}],
     "handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:8080"}]}]},
    {"handle":[{"handler":"static_response","status_code":403}]}
  ]}}}}}`); err != nil {
		t.Fatal(err)
	}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: caddy.New(empty.URL(), static.New(map[string]string{}))},
		{Name: "home", Provider: caddy.New(fronting.URL(), static.New(map[string]string{"app": "10.0.0.9:8080"}))},
	}, "example.com")

	if err := e.Ack(context.Background(), "app.example.com", "carveout"); err != nil {
		t.Fatalf("one edge fronting the host is enough — the other's not-found must be tolerated: %v", err)
	}
}
