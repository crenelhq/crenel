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

// TestCLI_AckRefusesSlashForm: docs/design/ack-marker.md §4b sketches `ack
// <host>[/<path>]`, but the implementation is host-only first-match — a slash
// argument used to silently fail host matching and die with the generic "no
// participating edge" error. The cmd layer must refuse it loudly instead,
// naming the workaround (ack the bare host) and the doc section.
func TestCLI_AckRefusesSlashForm(t *testing.T) {
	f := caddyfake.New()
	t.Cleanup(f.Close)
	if err := f.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
    {"match":[{"host":["secrets.example.com"],"path":["/api"]}],
     "handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:8200"}]}]},
    {"handle":[{"handler":"static_response","status_code":403}]}
  ]}}}}}`); err != nil {
		t.Fatal(err)
	}
	c, _ := newTestCLI(t, f, true, "")
	c.gf.reason = "x"

	err := c.dispatch(context.Background(), "ack", []string{"secrets.example.com/api"})
	if err == nil {
		t.Fatal("slash-form ack target must be refused")
	}
	if !strings.Contains(err.Error(), "path-scoped ack targeting is not yet implemented") {
		t.Errorf("refusal must say path targeting is unimplemented, got: %v", err)
	}
	if !strings.Contains(err.Error(), "ack the bare host") {
		t.Errorf("refusal must name the workaround, got: %v", err)
	}
}
