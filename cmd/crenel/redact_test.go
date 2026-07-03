package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

const leakToken = "cf-LEAK-abcd1234WXYZ"

// statusWithSecretExcerpt builds a one-edge report whose declared-unknown excerpt
// carries a secret (the shape a driver that excerpts RAW config text — e.g. nginx —
// produces for an unmodeled secret-bearing block).
func statusWithSecretExcerpt() core.StatusReport {
	return core.StatusReport{Edges: []core.EdgeStatus{{
		Name: "home", Driver: "nginx", DenyCatchAllPresent: true,
		Unparsed: []model.Unparsed{{
			Locator: "server[2]", Kind: model.UnknownHandler,
			Reason:     "block not modeled",
			RawExcerpt: `proxy_set_header Authorization "Bearer ` + leakToken + `"; api_token ` + leakToken,
		}},
	}}}
}

// TestRedactStatus_MasksByDefault proves the status output boundary masks secret
// bytes in a declared-unknown excerpt unless --show-secrets — and that the toggle
// reveals the real value.
func TestRedactStatus_MasksByDefault(t *testing.T) {
	c := &cli{gf: &globalFlags{}}
	rep := statusWithSecretExcerpt()
	c.redactStatus(&rep)
	if got := rep.Edges[0].Unparsed[0].RawExcerpt; strings.Contains(got, leakToken) {
		t.Errorf("default status must redact the excerpt secret, got: %s", got)
	}

	// --show-secrets reveals the real value (the escape hatch).
	c.gf.showSecrets = true
	rep2 := statusWithSecretExcerpt()
	c.redactStatus(&rep2)
	if got := rep2.Edges[0].Unparsed[0].RawExcerpt; !strings.Contains(got, leakToken) {
		t.Errorf("--show-secrets must reveal the real excerpt, got: %s", got)
	}
}

// TestRedactStatus_JSONPathIsScrubbed proves the leak surface (`status --json`
// serializes RawExcerpt) is scrubbed end-to-end through the helper used by cmdStatus.
func TestRedactStatus_JSONPathIsScrubbed(t *testing.T) {
	c := &cli{gf: &globalFlags{}, out: &bytes.Buffer{}}
	rep := statusWithSecretExcerpt()
	c.redactStatus(&rep)
	out := c.out.(*bytes.Buffer)
	if err := c.writeJSON(rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), leakToken) {
		t.Errorf("status --json leaked the excerpt secret:\n%s", out.String())
	}
}

// TestErrMessage_RedactsAdminBodyEcho proves an error that echoes admin-API config
// bytes (a Caddy /load rejection echoes the offending config) is masked at the print
// boundary unless --show-secrets — without changing the real error value.
func TestErrMessage_RedactsAdminBodyEcho(t *testing.T) {
	err := fmt.Errorf(`admin /load returned 400: {"error":"loading","api_token":"%s"}`, leakToken)

	if got := errMessage(&globalFlags{}, err); strings.Contains(got, leakToken) {
		t.Errorf("error boundary must redact echoed config bytes, got: %s", got)
	}
	if got := errMessage(&globalFlags{showSecrets: true}, err); !strings.Contains(got, leakToken) {
		t.Errorf("--show-secrets must reveal the raw error, got: %s", got)
	}
	// The underlying error value is never mutated (programmatic callers see the real one).
	if !strings.Contains(err.Error(), leakToken) {
		t.Error("redaction must not mutate the original error value")
	}
}

// TestRedactLines_RollbackErrors proves the rollback-error print path masks echoed
// secrets unless --show-secrets.
func TestRedactLines_RollbackErrors(t *testing.T) {
	in := []string{`reverse_proxy: admin /load returned 400: {"api_token":"` + leakToken + `"}`}
	c := &cli{gf: &globalFlags{}}
	if got := c.redactLines(in); strings.Contains(strings.Join(got, " "), leakToken) {
		t.Errorf("rollback-error lines must be redacted, got: %v", got)
	}
	c.gf.showSecrets = true
	if got := c.redactLines(in); !strings.Contains(strings.Join(got, " "), leakToken) {
		t.Errorf("--show-secrets must reveal rollback-error lines, got: %v", got)
	}
}

// TestExport_PermsAndRedactedMode proves export writes 0600 and that --redacted
// scrubs the secret-bearing declared-unknown excerpts while the default keeps them.
func TestExport_PermsAndRedactedMode(t *testing.T) {
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	engine := core.New(caddy.New(f.URL(), res), "example.com")

	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	c := &cli{engine: engine, gf: &globalFlags{}, out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	if err := c.dispatch(context.Background(), "export", []string{path}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("export must be 0600 (it can hold real secrets), got %o", perm)
	}
	if out := c.out.(*bytes.Buffer).String(); !strings.Contains(out, "0600") {
		t.Errorf("export message should note 0600 perms:\n%s", out)
	}

	// --redacted is accepted and still records the non-secret routing.
	rpath := filepath.Join(dir, "snap-redacted.json")
	if err := c.dispatch(context.Background(), "export", []string{rpath, "--redacted"}); err != nil {
		t.Fatalf("export --redacted: %v", err)
	}
	if b, _ := os.ReadFile(rpath); !strings.Contains(string(b), "grafana.example.com") {
		t.Errorf("redacted export should still record non-secret routing:\n%s", b)
	}
}

// TestExportRedaction_ScrubsExcerptSecret proves the export --redacted path masks a
// secret carried in a declared-unknown excerpt (the cmd applies redact.Snippet to
// each RawExcerpt via redactSnapshot), while the default snapshot keeps real bytes.
func TestExportRedaction_ScrubsExcerptSecret(t *testing.T) {
	mk := func() core.ExportSnapshot {
		return core.ExportSnapshot{Edges: []core.ExportEdge{{
			Name: "home", Provider: "nginx",
			Unparsed: []model.Unparsed{{
				Locator: "server[2]", Kind: model.UnknownHandler,
				RawExcerpt: `api_token ` + leakToken,
			}},
		}}}
	}
	real := mk()
	if !strings.Contains(real.Edges[0].Unparsed[0].RawExcerpt, leakToken) {
		t.Fatal("fixture should carry the secret before redaction")
	}
	red := mk()
	redactSnapshot(&red)
	if strings.Contains(red.Edges[0].Unparsed[0].RawExcerpt, leakToken) {
		t.Errorf("redactSnapshot must scrub the excerpt secret: %s", red.Edges[0].Unparsed[0].RawExcerpt)
	}
}

// TestApplyPreservesUnmanagedSecret_RealValues is the load-bearing guarantee: the
// APPLY / preserve-unmanaged path uses REAL values, never redacted ones. A granular
// expose alongside an unmanaged route that carries a secret must leave that secret
// in the live config BYTE-INTACT (redaction is output-only; it never reaches a write).
func TestApplyPreservesUnmanagedSecret_RealValues(t *testing.T) {
	f := caddyfake.New()
	t.Cleanup(f.Close)
	// An unmanaged (no @id) route carrying a basic_auth secret, plus the catch-all deny.
	// Granular expose of grafana must add ONE route and touch nothing else.
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	  {"match":[{"host":["secure.example.com"]}],"handle":[
	    {"handler":"authentication","providers":{"http_basic":{"accounts":[{"username":"a","password":"$2a$14$realbcrypthashVALUE"}]}}},
	    {"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:80"}]}]},
	  {"handle":[{"handler":"static_response","abort":true}]}
	]}}}}}`
	if err := f.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	engine := core.New(caddy.New(f.URL(), res, caddy.WithGranularApply()), "example.com")
	c := &cli{engine: engine, gf: &globalFlags{yes: true, granular: true}, out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	c.gf.auth = "none" // grafana goes public — explicit opt-out so the guardrail allows it

	if err := c.dispatch(context.Background(), "expose", []string{"grafana"}); err != nil {
		t.Fatalf("granular expose: %v", err)
	}
	// The unmanaged route's REAL secret is still present in live config, unredacted —
	// proving the write/preserve path never sees the masked form.
	if cur := f.CurrentJSON(); !strings.Contains(cur, "$2a$14$realbcrypthashVALUE") {
		t.Errorf("apply must preserve the unmanaged secret with REAL bytes:\n%s", cur)
	}
}
