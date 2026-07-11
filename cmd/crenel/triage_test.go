package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// triageSeed is the brownfield first-audit shape the triage verb exists for:
// a path-scoped host route, a HOST-LESS unmodeled handler route (no host to
// hand `crenel ack <host>` — structural path is its only address), and the
// trailing catch-all deny. Two real unknowns; deny reads UNKNOWN until both
// are understood or acknowledged.
const triageSeed = `{
  "apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
    {"match": [{"host": ["grafana.example.com"], "path": ["/admin"]}],
     "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5:3000"}]}]},
    {"handle": [{"handler": "file_server"}]},
    {"handle": [{"handler": "static_response", "status_code": 403}]}
  ]}}}}
}`

const (
	triageLocTop      = "apps.http.servers.srv0.routes[0]"
	triageLocHostless = "apps.http.servers.srv0.routes[1]"
)

// newTriageCLI builds a CLI over a seeded fake with the interactive-stdin
// seam forced on and the given operator keystrokes scripted. This is the
// prompt seam: triage reads from c.in / writes to c.out like every other
// prompt in the CLI, so tests script it with a plain reader.
func newTriageCLI(t *testing.T, script string) (*cli, *bytes.Buffer, *caddyfake.Fake) {
	t.Helper()
	f := caddyfake.New()
	t.Cleanup(f.Close)
	if err := f.SeedJSON(triageSeed); err != nil {
		t.Fatal(err)
	}
	c, out := newTestCLI(t, f, true, script)
	c.stdinTTY = func() bool { return true }
	return c, out, f
}

// TestCLI_TriageEnumerationMatchesAudit: triage's worklist is exactly the
// not-understood set audit counts — both locators surface, in order, with the
// same count the coverage finding reports; an all-skip run writes nothing.
func TestCLI_TriageEnumerationMatchesAudit(t *testing.T) {
	c, out, _ := newTriageCLI(t, "s\ns\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "2 route(s) not understood") {
		t.Errorf("triage should announce the audit's not-understood count:\n%s", s)
	}
	for _, loc := range []string{triageLocTop, triageLocHostless} {
		if !strings.Contains(s, loc) {
			t.Errorf("triage should show a card for %s:\n%s", loc, s)
		}
	}
	if !strings.Contains(s, "0 acked, 2 skipped") {
		t.Errorf("all-skip summary expected:\n%s", s)
	}
	// Audit agrees nothing changed: deny still UNKNOWN.
	out.Reset()
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Default-deny catch-all: UNKNOWN") {
		t.Errorf("skipping must not weaken anything:\n%s", out.String())
	}
}

// TestCLI_TriageAcksEndToEnd: acking both routes (including the HOST-LESS one)
// through the guided flow lands read-back-verified markers; audit stops
// counting them and default-deny certifies ENFORCED, with the routes still
// listed as ACK — never hidden.
func TestCLI_TriageAcksEndToEnd(t *testing.T) {
	// Card 1: [a] + reason. Card 2: [a] + reason.
	c, out, _ := newTriageCLI(t, "a\npath-scoped-admin\na\nhostless-carveout\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "2 acked, 0 skipped") {
		t.Errorf("both routes should be acked:\n%s", s)
	}
	if !strings.Contains(s, "read-back verified") {
		t.Errorf("each ack must report its read-back verification:\n%s", s)
	}
	if !strings.Contains(s, "audit will no longer count not-understood routes here") {
		t.Errorf("summary should say what audit will now report:\n%s", s)
	}
	out.Reset()
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s = out.String()
	if !strings.Contains(s, "Default-deny catch-all: ENFORCED") {
		t.Errorf("with every unknown acknowledged, deny must certify ENFORCED:\n%s", s)
	}
	if !strings.Contains(s, "ACK") || !strings.Contains(s, "hostless-carveout") {
		t.Errorf("acked routes must stay visible as ACK with their reasons:\n%s", s)
	}
}

// TestCLI_TriageNonTTYRefusal: triage is interactive by contract; a piped
// stdin is refused with the scriptable equivalent named.
func TestCLI_TriageNonTTYRefusal(t *testing.T) {
	c, _, _ := newTriageCLI(t, "")
	c.stdinTTY = func() bool { return false }
	err := c.dispatch(context.Background(), "triage", nil)
	if err == nil {
		t.Fatal("triage on a non-TTY stdin must refuse")
	}
	if !strings.Contains(err.Error(), "not a terminal") || !strings.Contains(err.Error(), "ack --route") {
		t.Errorf("refusal must name the non-interactive equivalent, got: %v", err)
	}
}

// TestCLI_TriageReasonValidation: a reason with spaces/uppercase (which the
// marker grammar cannot round-trip) is re-prompted, not stamped; an empty
// reason cancels back to the card menu.
func TestCLI_TriageReasonValidation(t *testing.T) {
	// Card 1: [a], bad reason, then a valid one. Card 2: [a], 'q' at the reason
	// prompt (cancel — an EMPTY line now accepts the suggested default), then [s]kip.
	c, out, _ := newTriageCLI(t, "a\nBad Reason!\nok-slug\na\nq\ns\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, `invalid reason "Bad Reason!"`) {
		t.Errorf("bad slug must be rejected with the grammar named:\n%s", s)
	}
	if !strings.Contains(s, "1 acked, 1 skipped") {
		t.Errorf("valid retry should ack card 1; cancelled card 2 skipped:\n%s", s)
	}
}

// TestCLI_TriageQuitKeepsAcks: [q] mid-flow leaves everything already acked
// in place and says so; the untouched route is still a real unknown after.
func TestCLI_TriageQuitKeepsAcks(t *testing.T) {
	c, out, _ := newTriageCLI(t, "a\nfirst-one\nq\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "everything already acked stays acked") {
		t.Errorf("[q] must state that prior acks persist:\n%s", s)
	}
	if !strings.Contains(s, "audit will still report 1 route(s) not understood") {
		t.Errorf("summary must report the remaining unknown:\n%s", s)
	}
	out.Reset()
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s = out.String()
	if !strings.Contains(s, "first-one") {
		t.Errorf("the pre-quit ack must have landed:\n%s", s)
	}
	if !strings.Contains(s, "Default-deny catch-all: UNKNOWN") {
		t.Errorf("one real unknown remains, deny stays UNKNOWN:\n%s", s)
	}
}

// TestCLI_TriageDryRun walks the full flow but writes nothing: the ack is
// reported as would-run (with the exact non-interactive command), and audit
// still counts both unknowns afterwards.
func TestCLI_TriageDryRun(t *testing.T) {
	c, out, _ := newTriageCLI(t, "a\nwould-be\ns\n")
	if err := c.dispatch(context.Background(), "triage", []string{"--dry-run"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "dry-run: would run `crenel ack --route") {
		t.Errorf("dry-run must print the equivalent scriptable command:\n%s", s)
	}
	if !strings.Contains(s, "audit will still report 2 route(s) not understood") {
		t.Errorf("dry-run must leave the live config untouched:\n%s", s)
	}
}

// TestCLI_TriageOpenFullJSON: the [o] action prints the FULL raw route JSON
// (beyond the read-time bounded excerpt) and the card shows what crenel DID
// understand about the route.
func TestCLI_TriageOpenFullJSON(t *testing.T) {
	c, out, _ := newTriageCLI(t, "o\ns\ns\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "reverse_proxy") || !strings.Contains(s, "10.0.0.5:3000") {
		t.Errorf("[o] should show the full route JSON:\n%s", s)
	}
	if !strings.Contains(s, "understood: host matcher grafana.example.com") {
		t.Errorf("card should surface the recovered host matcher:\n%s", s)
	}
	if !strings.Contains(s, "handler(s): reverse_proxy") {
		t.Errorf("card should surface the handler types:\n%s", s)
	}
}

// TestCLI_TriageEdgeFilterUnknownEdge: --edge with a name that isn't
// configured errors instead of silently triaging nothing.
func TestCLI_TriageEdgeFilterUnknownEdge(t *testing.T) {
	c, _, _ := newTriageCLI(t, "")
	err := c.dispatch(context.Background(), "triage", []string{"--edge", "nope"})
	if err == nil || !strings.Contains(err.Error(), `no edge named "nope"`) {
		t.Errorf("unknown --edge must error with the configured names, got: %v", err)
	}
}

// TestCLI_AckByRoute_Hostless is the NON-INTERACTIVE equivalent triage wraps:
// `ack --route '<locator>' --reason <slug>` acks the host-less route (which
// `ack <host>` can never address), read-back-verified; `unack --route`
// reverts it. Reason grammar is enforced up front.
func TestCLI_AckByRoute_Hostless(t *testing.T) {
	c, out, _ := newTriageCLI(t, "")
	ctx := context.Background()

	// Reason grammar: refused before any write.
	c.gf.route = triageLocHostless
	c.gf.reason = "Not A Slug"
	if err := c.dispatch(ctx, "ack", nil); err == nil || !strings.Contains(err.Error(), "invalid --reason") {
		t.Fatalf("bad reason slug must be refused, got: %v", err)
	}

	c.gf.reason = "hostless-carveout"
	if err := c.dispatch(ctx, "ack", nil); err != nil {
		t.Fatalf("ack --route: %v", err)
	}
	if !strings.Contains(out.String(), "acknowledged: "+triageLocHostless) {
		t.Errorf("expected a locator acknowledgment, got:\n%s", out.String())
	}
	out.Reset()
	if err := c.dispatch(ctx, "status", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hostless-carveout") {
		t.Errorf("status should list the path-acked route as ACK:\n%s", out.String())
	}

	// Undo by the same address.
	out.Reset()
	if err := c.dispatch(ctx, "unack", nil); err != nil {
		t.Fatalf("unack --route: %v", err)
	}
	out.Reset()
	if err := c.dispatch(ctx, "status", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "hostless-carveout") {
		t.Errorf("unack --route should have removed the marker:\n%s", out.String())
	}
}

// TestCLI_AckByRoute_BareHostRegression: the pre-existing HOST-addressed ack
// path is untouched by the --route extension — a bare-host ack still lands
// and parses (including alongside a path-addressed ack in the same config).
func TestCLI_AckByRoute_BareHostRegression(t *testing.T) {
	c, out, _ := newTriageCLI(t, "")
	ctx := context.Background()

	// Path-ack the host-less route first…
	c.gf.route = triageLocHostless
	c.gf.reason = "hostless-carveout"
	if err := c.dispatch(ctx, "ack", nil); err != nil {
		t.Fatalf("ack --route: %v", err)
	}
	// …then a bare-host ack of the path-scoped route, exactly as before.
	c.gf.route = ""
	c.gf.reason = "brownfield-carveout"
	if err := c.dispatch(ctx, "ack", []string{"grafana.example.com"}); err != nil {
		t.Fatalf("bare-host ack must keep working: %v", err)
	}
	out.Reset()
	if err := c.dispatch(ctx, "status", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"brownfield-carveout", "hostless-carveout", "Default-deny catch-all: ENFORCED"} {
		if !strings.Contains(s, want) {
			t.Errorf("status missing %q — both marker forms must coexist and parse:\n%s", want, s)
		}
	}
}

// TestCLI_TriageNilStdinNoPanic: the PRODUCTION cli constructors never set the
// c.in test seam — it stays nil and prompts must fall back to os.Stdin. The
// v0.5.2 live debut panicked here (nil dereference on the first keystroke read)
// because only scripted readers had ever exercised the prompt loop. Under `go
// test` os.Stdin is typically /dev/null, so the fallback reads EOF: the run
// must surface that as an ordinary error (or an EOF-terminated clean pass),
// NEVER a panic.
func TestCLI_TriageNilStdinNoPanic(t *testing.T) {
	c, _, _ := newTriageCLI(t, "")
	c.in = nil // the production shape: no seam wired
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("triage with nil c.in must not panic (production cli shape): %v", r)
		}
	}()
	_ = c.dispatch(context.Background(), "triage", nil)
}

// TestCLI_TriageSuggestedReasonDefault: an empty line at the reason prompt
// accepts the evidence-derived suggestion (host first label + kind slug) —
// the operator is never left inventing a format from a blank line. The
// suggestion must be shown in the prompt and the landed marker must carry it.
func TestCLI_TriageSuggestedReasonDefault(t *testing.T) {
	c, out, _ := newTriageCLI(t, "a\n\ns\n")
	if err := c.dispatch(context.Background(), "triage", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "[enter = ") {
		t.Errorf("reason prompt should display the suggested default:\n%s", s)
	}
	if !strings.Contains(s, "1 acked, 1 skipped") {
		t.Errorf("empty line should accept the suggestion and ack card 1:\n%s", s)
	}
	if !strings.Contains(s, "acked (read-back verified)") {
		t.Errorf("suggested-reason ack must still read-back verify:\n%s", s)
	}
}
