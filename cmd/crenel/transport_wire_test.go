package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/transport"
)

// TestBuildTransport_Selection covers the wiring choice: absent/direct => the driver's
// default Direct (nil), ssh-exec/ssh-tunnel => the concrete transport, misconfig =>
// a clear error. This is the back-compat anchor: an edge with no transport block is
// reached exactly as before.
func TestBuildTransport_Selection(t *testing.T) {
	w := &wiring{cleanup: func() {}}

	// nil / direct / "" => no override (driver builds Direct to admin_url).
	for _, ts := range []*config.TransportSettings{nil, {Type: "direct"}, {Type: ""}} {
		got, err := buildTransport(ts, w)
		if err != nil || got != nil {
			t.Fatalf("buildTransport(%v) = (%v, %v); want (nil, nil)", ts, got, err)
		}
	}

	// ssh-exec.
	x, err := buildTransport(&config.TransportSettings{Type: "ssh-exec", Command: []string{"sh"}, AdminURL: "http://127.0.0.1:2019"}, w)
	if err != nil {
		t.Fatalf("ssh-exec: %v", err)
	}
	if _, ok := x.(*transport.SSHExec); !ok {
		t.Fatalf("ssh-exec built %T, want *transport.SSHExec", x)
	}

	// ssh-exec without a command is refused.
	if _, err := buildTransport(&config.TransportSettings{Type: "ssh-exec"}, w); err == nil {
		t.Fatal("ssh-exec with no command should error")
	}

	// ssh-tunnel registers a cleanup (Close).
	tw := &wiring{cleanup: func() {}}
	tx, err := buildTransport(&config.TransportSettings{Type: "ssh-tunnel", SSHTarget: "root@h", LocalPort: 12019}, tw)
	if err != nil {
		t.Fatalf("ssh-tunnel: %v", err)
	}
	if _, ok := tx.(*transport.SSHTunnel); !ok {
		t.Fatalf("ssh-tunnel built %T, want *transport.SSHTunnel", tx)
	}
	tw.cleanup() // must not panic (Close on an unopened tunnel is a no-op)

	// Unknown type.
	if _, err := buildTransport(&config.TransportSettings{Type: "carrier-pigeon"}, w); err == nil {
		t.Fatal("unknown transport type should error")
	}
}

// TestTransport_DecodesFromConfig proves the `transport` block round-trips through the
// config decoder onto an edge (JSON), so an operator config wires it.
func TestTransport_DecodesFromConfig(t *testing.T) {
	const doc = `{
      "zone": "homelab.example",
      "edges": [
        {"name":"home","driver":"caddy","admin_url":"http://127.0.0.1:2019",
         "origins":{"x":"10.0.0.1:80"},
         "transport":{"type":"ssh-exec",
           "command":["ssh","root@ml350","pct","exec","113","--","docker","exec","-i","caddy","sh"],
           "admin_url":"http://127.0.0.1:2019"}}
      ]
    }`
	dir := t.TempDir()
	path := dir + "/c.json"
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ts := s.Edges[0].Transport
	if ts == nil || ts.Type != "ssh-exec" || len(ts.Command) != 11 || ts.Command[0] != "ssh" {
		t.Fatalf("transport did not decode as expected: %+v", ts)
	}
}

// TestBuild_SSHExecEdge_ReadsThroughRealSh is the end-to-end wiring proof: a config
// with an ssh-exec edge (real local `sh`) pointed at an in-process caddy fake reads
// live state THROUGH the transport — config -> wire -> driver -> ssh-exec -> admin.
// No published port, no live infra. Skips if sh/curl/base64 are unavailable.
func TestBuild_SSHExecEdge_ReadsThroughRealSh(t *testing.T) {
	if !shCapableMain(t) {
		t.Skip("sh/curl/base64 not available — skipping the real-exec wiring test")
	}
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")

	s := config.Settings{
		Zone: "example.com",
		Edges: []config.EdgeSettings{{
			Name:     "home",
			Driver:   "caddy",
			AdminURL: "http://127.0.0.1:1", // ignored: the transport routes the call
			Origins:  map[string]string{"grafana": "10.0.0.5:3000"},
			Transport: &config.TransportSettings{
				Type:     "ssh-exec",
				Command:  []string{"sh"}, // innermost shell, reads the script from stdin
				AdminURL: fake.URL(),     // admin as seen from the far end
			},
		}},
	}
	w, err := build(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer w.cleanup()

	out := &bytes.Buffer{}
	c := &cli{engine: w.engine, gf: &globalFlags{}, out: out, errOut: out, in: strings.NewReader("")}
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatalf("status over ssh-exec: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "grafana.example.com") || !strings.Contains(got, "ENFORCED") {
		t.Errorf("status read over ssh-exec missing expectations:\n%s", got)
	}
}

func shCapableMain(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		return false
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return false
	}
	o, err := exec.Command("sh", "-c", "printf aGk= | base64 -d").Output()
	return err == nil && string(o) == "hi"
}
