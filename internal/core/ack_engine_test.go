package core_test

import (
	"context"
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
