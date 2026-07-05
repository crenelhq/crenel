package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// newTestCLI builds a cli wired to a fake seeded with grafana, returning the cli
// plus a buffer capturing stdout.
func newTestCLI(t *testing.T, fake *caddyfake.Fake, yes bool, stdin string) (*cli, *bytes.Buffer) {
	t.Helper()
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	edge := caddy.New(fake.URL(), res)
	engine := core.New(edge, "example.com")
	out := &bytes.Buffer{}
	return &cli{
		engine: engine,
		gf:     &globalFlags{yes: yes},
		out:    out,
		errOut: out,
		in:     strings.NewReader(stdin),
	}, out
}

func seedFake(t *testing.T) *caddyfake.Fake {
	t.Helper()
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	return f
}

func TestCLI_Status(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	// Fully-parsed edge => default-deny reads ENFORCED (the ternary's green state).
	if !strings.Contains(s, "grafana.example.com") || !strings.Contains(s, "Default-deny catch-all: ENFORCED") {
		t.Errorf("status output missing expectations:\n%s", s)
	}
}

// TestCLI_StatusHUDBanner forces the full HUD banner (no TTY needed via --hud)
// and asserts the branded surface is wired to real status data.
func TestCLI_StatusHUDBanner(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	if err := c.dispatch(context.Background(), "status", []string{"--hud"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"CORE MATRIX", "EXPOSED", "DEFAULT-DENY", "DRIFT", "EDGES", "grafana.example.com"} {
		if !strings.Contains(s, want) {
			t.Errorf("HUD status missing %q:\n%s", want, s)
		}
	}
	if !strings.ContainsRune(s, '█') {
		t.Errorf("HUD status should include the block wordmark:\n%s", s)
	}
}

// TestCLI_StatusDefaultNoBannerWhenPiped asserts the scriptable default: with no
// TTY (the test's zero-value cli), status prints only the detail listing.
func TestCLI_StatusDefaultNoBannerWhenPiped(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, "CORE MATRIX") || strings.Contains(s, "EXPOSED") {
		t.Errorf("piped status must not draw the branded header:\n%s", s)
	}
	if !strings.Contains(s, "grafana.example.com") {
		t.Errorf("piped status must still print the detail listing:\n%s", s)
	}
}

// TestCLI_StatusHeaderColorGating asserts color appears on a TTY and the HUD
// degrades to plain ASCII when color is disabled.
func TestCLI_StatusHeaderColorGating(t *testing.T) {
	// TTY + color: compact header is drawn and colored.
	c, out := newTestCLI(t, seedFake(t), false, "")
	c.tty, c.color = true, true
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "\x1b[") || !strings.Contains(s, "EXPOSED") {
		t.Errorf("TTY status header should be colored and include EXPOSED:\n%s", s)
	}

	// HUD requested but color disabled: no ANSI at all (plain fallback).
	c2, out2 := newTestCLI(t, seedFake(t), false, "")
	c2.color = false
	if err := c2.dispatch(context.Background(), "status", []string{"--hud"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2.String(), "\x1b[") {
		t.Errorf("color disabled must emit no ANSI:\n%q", out2.String())
	}
}

// TestCLI_StatusPlainSuppressesBanner asserts --plain wins even on a TTY.
func TestCLI_StatusPlainSuppressesBanner(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	c.tty, c.color = true, true
	if err := c.dispatch(context.Background(), "status", []string{"--plain"}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); strings.Contains(s, "CORE MATRIX") || strings.Contains(s, "EXPOSED") {
		t.Errorf("--plain must suppress the branded header:\n%s", s)
	}
}

func TestPrintLanding(t *testing.T) {
	var b bytes.Buffer
	printLanding(&b, false)
	s := b.String()
	if !strings.ContainsRune(s, '█') {
		t.Errorf("landing should include the block wordmark:\n%s", s)
	}
	if !strings.Contains(s, "status") {
		t.Errorf("landing should list commands:\n%s", s)
	}
	if strings.Contains(s, "\x1b[") {
		t.Errorf("plain landing should contain no ANSI:\n%q", s)
	}
}

func TestCLI_PreviewHighlightsNewPublic(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	if err := c.dispatch(context.Background(), "preview", []string{"expose", "photos"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ABOUT TO GO PUBLIC") {
		t.Errorf("preview should highlight new public exposure:\n%s", out.String())
	}
}

func TestCLI_ExposeWithYes(t *testing.T) {
	fake := seedFake(t)
	c, out := newTestCLI(t, fake, true, "")
	c.gf.auth = "none" // explicit opt-out: publishing photos unprotected on purpose
	if err := c.dispatch(context.Background(), "expose", []string{"photos"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("expose should verify:\n%s", out.String())
	}
}

func TestCLI_ConfirmPromptDeclines(t *testing.T) {
	fake := seedFake(t)
	c, out := newTestCLI(t, fake, false, "n\n") // answer "no"
	c.gf.auth = "none"                          // explicit opt-out so the guardrail lets the prompt run
	if err := c.dispatch(context.Background(), "expose", []string{"photos"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "aborted") {
		t.Errorf("declining should abort:\n%s", out.String())
	}
	if len(fake.Loads) != 0 {
		t.Error("decline must not POST /load")
	}
}

// TestCLI_ExposePublicWithoutAuthRefused proves the SAFETY GUARDRAIL: exposing a
// host that goes PUBLIC with no auth is refused (even with --yes), and nothing is
// applied — the operator must make an explicit choice.
func TestCLI_ExposePublicWithoutAuthRefused(t *testing.T) {
	fake := seedFake(t)
	c, _ := newTestCLI(t, fake, true, "") // --yes must NOT bypass the guardrail
	err := c.dispatch(context.Background(), "expose", []string{"photos"})
	if err == nil || !strings.Contains(err.Error(), "PUBLIC with no auth") {
		t.Fatalf("public expose with no auth must be refused, got %v", err)
	}
	if len(fake.Loads) != 0 {
		t.Error("a refused expose must not POST /load")
	}
}

// TestCLI_ApplyPublicWithoutAuthRefused proves the same guardrail on declarative
// apply, and that `auth: none` in the file is the explicit opt-out that allows it.
func TestCLI_ApplyPublicWithoutAuthRefused(t *testing.T) {
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	c, _ := newTestCLI(t, f, true, "")

	dir := t.TempDir()
	exp := filepath.Join(dir, "exposures.yaml")
	if err := os.WriteFile(exp, []byte("zone: example.com\nexposures:\n  - service: photos\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := c.cmdApply(context.Background(), []string{exp})
	if err == nil || !strings.Contains(err.Error(), "PUBLIC with no auth") {
		t.Fatalf("declarative public apply with no auth must be refused, got %v", err)
	}
	if len(f.Loads) != 0 {
		t.Error("a refused apply must not mutate the edge")
	}

	// With an explicit `auth: none`, the apply proceeds and verifies.
	exp2 := filepath.Join(dir, "exposures-none.yaml")
	if err := os.WriteFile(exp2, []byte("zone: example.com\nexposures:\n  - service: photos\n    auth: none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	c.out, c.errOut = out, out
	if err := c.cmdApply(context.Background(), []string{exp2}); err != nil {
		t.Fatalf("explicit auth: none should be allowed: %v", err)
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("apply with auth: none should verify:\n%s", out.String())
	}
}

func TestCLI_AuditCriticalReturnsError(t *testing.T) {
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(":443 {\n\treverse_proxy 10.9.9.9:80\n}\n") // host-less catch-all = fail-open
	c, _ := newTestCLI(t, fake, false, "")
	c.engine = func() *core.Engine {
		res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
		return core.New(caddy.New(fake.URL(), res), "example.com")
	}()
	err := c.dispatch(context.Background(), "audit", nil)
	if err == nil {
		t.Error("audit with missing deny should return an error")
	}
}

func TestCLI_Export(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	c, _ := newTestCLI(t, seedFake(t), false, "")
	if err := c.dispatch(context.Background(), "export", []string{path}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "grafana.example.com") {
		t.Errorf("export missing route: %s", b)
	}
}

// TestRun_EndToEndWithFakeSeed exercises the real run() entry point + wiring,
// using --fake-seed to spin up an in-process fake (the safe demo path).
func TestRun_EndToEndWithFakeSeed(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.caddyfile")
	if err := os.WriteFile(seed, []byte(":443 {\n\trespond 403\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"--fake-seed", seed, "status"})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

// TestAbsorbPostVerbFlags proves global flags placed AFTER the verb are honored
// (Go's flag package stops at the first positional, so without this the README's
// `import --yes` / `expose <svc> --auth none` would silently no-op). Verb-local and
// unknown flags must be left in place for the verb handler.
// TestCLI_ChainStatusFollowsThrough is the END-TO-END P4 demo: a two-edge chain
// (the bundled fixtures) where the VPS front forwards to the home edge. status must
// FOLLOW THROUGH — showing each forwarded host's real downstream backend + observed
// auth — and audit must resolve protection by OBSERVATION (vault protected, books
// open). Both edges are in-process fakes wired via build() from the settings shape.
func TestCLI_ChainStatusFollowsThrough(t *testing.T) {
	s := config.Settings{
		Zone: "homelab.example",
		Edges: []config.EdgeSettings{
			{Name: "vps", Driver: "caddy", FakeSeed: filepath.Join("..", "..", "examples", "seed-chain-front.json"),
				GranularApply: true, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13", Origins: map[string]string{}},
			{Name: "home", Driver: "caddy", FakeSeed: filepath.Join("..", "..", "examples", "seed-chain-home.json"),
				GranularApply: true, Origins: map[string]string{}},
		},
	}
	w, err := build(s)
	if err != nil {
		t.Fatalf("build chain engine: %v", err)
	}
	defer w.cleanup()

	out := &bytes.Buffer{}
	c := &cli{engine: w.engine, gf: &globalFlags{}, out: out, errOut: out, in: strings.NewReader("")}

	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Fatalf("status: %v", err)
	}
	s1 := out.String()
	// Follow-through: the front's vault forward resolves to the REAL home backend +
	// observed auth, not the opaque downstream-edge address.
	if !strings.Contains(s1, "vault.homelab.example") || !strings.Contains(s1, "→ home:10.0.0.7:8200") {
		t.Errorf("status should follow vault through to its real downstream backend:\n%s", s1)
	}
	if !strings.Contains(s1, "→ home:10.0.0.9:80") {
		t.Errorf("status should follow books through to its real downstream backend:\n%s", s1)
	}

	// Audit: vault is protected by observation (not flagged); books/git are open and
	// flagged; the report stays non-critical (warnings only).
	out.Reset()
	if err := c.dispatch(context.Background(), "audit", nil); err != nil {
		t.Fatalf("audit should not error on a warning-only chain: %v", err)
	}
	s2 := out.String()
	if strings.Contains(s2, "vault.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("vault is Authelia-protected downstream (observed) — must not be flagged:\n%s", s2)
	}
	if !strings.Contains(s2, "books.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("books is open downstream — must be flagged public_without_auth:\n%s", s2)
	}
	if !strings.Contains(s2, "followed through") {
		t.Errorf("audit should report chain follow-through (chain_resolved):\n%s", s2)
	}
}

func TestAbsorbPostVerbFlags(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		want     []string
		check    func(*globalFlags) bool
		checkMsg string
	}{
		{
			name:     "bool yes after positional",
			args:     []string{"grafana", "--yes"},
			want:     []string{"grafana"},
			check:    func(g *globalFlags) bool { return g.yes },
			checkMsg: "yes should be set",
		},
		{
			name:     "auth value space-separated",
			args:     []string{"grafana", "--auth", "none"},
			want:     []string{"grafana"},
			check:    func(g *globalFlags) bool { return g.auth == "none" },
			checkMsg: "auth should be none",
		},
		{
			name:     "auth value equals form",
			args:     []string{"grafana", "--auth=authelia", "-yes"},
			want:     []string{"grafana"},
			check:    func(g *globalFlags) bool { return g.auth == "authelia" && g.yes },
			checkMsg: "auth=authelia and yes",
		},
		{
			name:     "verb-local flags pass through untouched",
			args:     []string{"file.yaml", "--dry-run", "--adopt", "--prune", "--json"},
			want:     []string{"file.yaml", "--dry-run", "--adopt", "--prune"},
			check:    func(g *globalFlags) bool { return g.jsonOut },
			checkMsg: "json absorbed, verb-local left",
		},
		{
			name:     "repeatable param",
			args:     []string{"svc", "--param", "group=admins", "--mode", "mesh"},
			want:     []string{"svc"},
			check:    func(g *globalFlags) bool { return len(g.params) == 1 && g.params[0] == "group=admins" && g.mode == "mesh" },
			checkMsg: "param + mode absorbed",
		},
		{
			name:     "bool allow-unverified after positional",
			args:     []string{"grafana", "--allow-unverified"},
			want:     []string{"grafana"},
			check:    func(g *globalFlags) bool { return g.allowUnverified },
			checkMsg: "allow-unverified should be set",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gf := &globalFlags{}
			got, err := absorbPostVerbFlags(gf, tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("remaining args = %v, want %v", got, tc.want)
			}
			if !tc.check(gf) {
				t.Errorf("%s; gf=%+v", tc.checkMsg, gf)
			}
		})
	}

	// A value flag missing its value is a clean error, not a silent drop.
	if _, err := absorbPostVerbFlags(&globalFlags{}, []string{"svc", "--auth"}); err == nil {
		t.Error("trailing value flag with no value should error")
	}
}

// TestRun_PostVerbFlagsEndToEnd proves the run() entry path honors post-verb global
// flags (the README's documented form) all the way through wiring. It uses a case
// whose OUTCOME flips on whether the flags are honored: exposing a public host with
// no auth is refused (exit 1), but a post-verb `--auth none --yes` makes it the
// explicit, applied choice (exit 0). If the absorber were absent, both flags would
// be dropped and the command would be refused.
func TestRun_PostVerbFlagsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.caddyfile")
	if err := os.WriteFile(seed, []byte(":443 {\n\trespond 403\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Without an explicit auth choice, the public-without-auth guardrail refuses.
	if code := run([]string{"--fake-seed", seed, "--zone", "example.com", "expose", "photos"}); code == 0 {
		t.Error("expose of a public host with no auth should be refused (exit non-zero)")
	}
	// A fresh fake (in-process state is per-run); post-verb `--auth none --yes` is the
	// explicit opt-out + skip-confirm, so the apply proceeds and verifies.
	if code := run([]string{"--fake-seed", seed, "--zone", "example.com", "expose", "photos", "--auth", "none", "--yes"}); code != 0 {
		t.Errorf("post-verb `--auth none --yes` should be honored and apply, got exit %d", code)
	}
}

func TestDefaults_Sane(t *testing.T) {
	d := config.Defaults()
	if d.Zone == "" || d.AdminURL == "" || len(d.Origins) == 0 {
		t.Errorf("defaults look unpopulated: %+v", d)
	}
}

// TestCLI_Init scaffolds starter files and confirms they parse back as settings.
func TestCLI_Init(t *testing.T) {
	dir := t.TempDir()
	c, out := newTestCLI(t, seedFake(t), false, "")
	if err := c.cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"crenel.settings.yaml", "crenel.exposures.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("init should have written %s: %v", name, err)
		}
	}
	if !strings.Contains(out.String(), "Next steps") {
		t.Error("init should print next steps")
	}
	// The scaffolded settings must decode (proving the YAML path end-to-end).
	var s config.Settings
	if err := config.DecodeFile(filepath.Join(dir, "crenel.settings.yaml"), &s); err != nil {
		t.Fatalf("scaffolded settings should decode: %v", err)
	}
	if s.EdgeDriver != "caddy" || s.Origins["grafana"] == "" {
		t.Fatalf("scaffolded settings wrong: %+v", s)
	}
	// init must refuse to overwrite.
	if err := c.cmdInit([]string{dir}); err == nil {
		t.Fatal("init should refuse to overwrite existing files")
	}
}

// TestCLI_ImportDryRun: a fake seeded with an UNMANAGED grafana (matching origin)
// is reported adoptable, and --dry-run exits non-zero.
func TestCLI_ImportDryRun(t *testing.T) {
	c, out := newTestCLI(t, seedFake(t), false, "")
	err := c.cmdImport(context.Background(), []string{"--dry-run"})
	if err == nil {
		t.Fatal("import --dry-run should exit non-zero when something is adoptable")
	}
	if !strings.Contains(out.String(), "adopt") || !strings.Contains(out.String(), "grafana.example.com") {
		t.Errorf("import preview should list grafana as adoptable:\n%s", out.String())
	}
}

// TestCLI_ApplyDryRun: a declarative apply file previews the diff with the public
// highlight, decoding the exposures file as YAML.
func TestCLI_ApplyDryRun(t *testing.T) {
	// Empty edge so photos is a fresh expose (about to go public).
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	c, out := newTestCLI(t, f, false, "")

	dir := t.TempDir()
	exp := filepath.Join(dir, "exposures.yaml")
	if err := os.WriteFile(exp, []byte("zone: example.com\nexposures:\n  - service: photos\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.cmdApply(context.Background(), []string{exp, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "photos.example.com") || !strings.Contains(s, "ABOUT TO GO PUBLIC") {
		t.Errorf("apply dry-run should preview the new public exposure:\n%s", s)
	}
}

// TestConfirmUnverifiedOverride covers the F2 gate's "(or interactive confirm)"
// alternative to --allow-unverified (see core.UnverifiedWriteError):
//   - a different error never prompts / never accepts;
//   - --yes means non-interactive, so it refuses even a y answer waiting on stdin;
//   - interactively, "y"/"yes" accepts and anything else (including EOF) refuses.
func TestConfirmUnverifiedOverride(t *testing.T) {
	uerr := &core.UnverifiedWriteError{Providers: []string{"edge[vps·traefik]"}}
	cases := []struct {
		name  string
		err   error
		yes   bool
		stdin string
		want  bool
	}{
		{name: "unrelated error never accepts", err: fmt.Errorf("boom"), stdin: "y\n", want: false},
		{name: "--yes refuses without prompting", err: uerr, yes: true, stdin: "y\n", want: false},
		{name: "interactive y accepts", err: uerr, stdin: "y\n", want: true},
		{name: "interactive yes accepts", err: uerr, stdin: "yes\n", want: true},
		{name: "interactive blank refuses", err: uerr, stdin: "\n", want: false},
		{name: "interactive EOF refuses", err: uerr, stdin: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			c := &cli{gf: &globalFlags{yes: tc.yes}, out: out, in: strings.NewReader(tc.stdin)}
			if got := c.confirmUnverifiedOverride(tc.err); got != tc.want {
				t.Errorf("confirmUnverifiedOverride() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestUsage_DocumentsAckUnack is a regression guard: ack/unack were wired into
// dispatch() but initially left out of `crenel help` — caught during a live
// production dogfood (2026-07-05). Both verbs, and the --reason flag ack
// requires, must appear in the usage text.
func TestUsage_DocumentsAckUnack(t *testing.T) {
	out := &bytes.Buffer{}
	writeUsage(out)
	s := out.String()
	for _, want := range []string{"ack <host>", "unack <host>", "-reason"} {
		if !strings.Contains(s, want) {
			t.Errorf("usage text should document %q, got:\n%s", want, s)
		}
	}
}
