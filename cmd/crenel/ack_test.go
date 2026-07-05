package main

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// TestCLI_AckUnack proves the `ack`/`unack` verbs work end to end through
// dispatch: `ack` without --reason is refused; with --reason it stamps the
// marker and status then reports it as ACK, not a blocking unknown; `unack`
// reverts it.
func TestCLI_AckUnack(t *testing.T) {
	f := caddyfake.New()
	t.Cleanup(f.Close)
	if err := f.SeedJSON(`{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"host": ["grafana.example.com"], "path": ["/admin"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5:3000"}]}]
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
	c, out := newTestCLI(t, f, true, "")

	if err := c.dispatch(context.Background(), "ack", []string{"grafana.example.com"}); err == nil {
		t.Fatal("ack without --reason must be refused")
	}

	c.gf.reason = "brownfield-carveout"
	if err := c.dispatch(context.Background(), "ack", []string{"grafana.example.com"}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if !strings.Contains(out.String(), "acknowledged: grafana.example.com") {
		t.Errorf("expected an acknowledgment confirmation, got: %s", out.String())
	}

	out.Reset()
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "ACK") || !strings.Contains(s, "brownfield-carveout") {
		t.Errorf("status should show the ACK state with its reason:\n%s", s)
	}
	if strings.Contains(s, "Default-deny catch-all: UNKNOWN") {
		t.Errorf("an edge with only an acknowledged unknown must certify ENFORCED:\n%s", s)
	}

	out.Reset()
	if err := c.dispatch(context.Background(), "unack", []string{"grafana.example.com"}); err != nil {
		t.Fatalf("unack: %v", err)
	}
	out.Reset()
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s = out.String()
	if strings.Contains(s, "ACK") {
		t.Errorf("unack should have removed the ACK state:\n%s", s)
	}
	if !strings.Contains(s, "Default-deny catch-all: UNKNOWN") {
		t.Errorf("after unack the path-scoped route is a real unknown again, deny should read UNKNOWN:\n%s", s)
	}
}
