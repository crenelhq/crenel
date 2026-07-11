package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// nopConn is a stand-in net.Conn returned by the dial stub — Close is the
// only method guardToReachable calls.
type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// newExposeToCLI builds a cli backed by a fake caddy edge and a REAL on-disk
// settings file — the fixture the persistence path needs to write into.
// origins is intentionally EMPTY: the whole point of --to is that a service
// need not be pre-declared before `expose`.
func newExposeToCLI(t *testing.T, fake *caddyfake.Fake, settingsBody string) (*cli, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(p, []byte(settingsBody), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	res := static.New(s.Origins.Addrs()) // may be empty — --to is the point
	edge := caddy.New(fake.URL(), res)
	engine := core.New(edge, "example.com")
	out := &bytes.Buffer{}
	return &cli{
		engine:       engine,
		gf:           &globalFlags{yes: true},
		settings:     s,
		settingsPath: p,
		out:          out,
		errOut:       out,
		in:           strings.NewReader(""),
	}, out, p
}

func seedEmptyDenyFake(t *testing.T) *caddyfake.Fake {
	t.Helper()
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	return f
}

// TestCLI_ExposeWithTo_WritesRouteAndPersistsOrigin: the hero-command
// contract. `crenel expose immich --to immich:2283 --auth none` on a config
// with an EMPTY origins map must (a) land the live route with the --to
// backend and (b) persist the origins entry so drift/audit stay coherent.
func TestCLI_ExposeWithTo_WritesRouteAndPersistsOrigin(t *testing.T) {
	// The pre-flight probe is exercised by TestCLI_ExposeWithTo_AbortsOnUnreachableBackend
	// (see expose_to_validate_test.go). Here we stub it OK so this test stays focused on the
	// route+persist path — swapping the stub keeps the test hermetic (no real dial).
	withDialTo(t, func(string, time.Duration) (net.Conn, error) { return &nopConn{}, nil })

	fake := seedEmptyDenyFake(t)
	c, out, p := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.auth = "none" // explicit publish-unprotected — clears the public-auth guardrail
	c.gf.to = "10.0.0.99:2283"

	if err := c.dispatch(context.Background(), "expose", []string{"immich"}); err != nil {
		t.Fatalf("expose --to should succeed for an undeclared service, got %v: out=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("expose should verify (read-back OK):\n%s", out.String())
	}
	if !strings.Contains(out.String(), "persisted origin: immich -> 10.0.0.99:2283") {
		t.Errorf("expected the persistence trace in output:\n%s", out.String())
	}
	// Coherence check: origins now contains immich, so a fresh Load sees it —
	// which is what makes subsequent status/audit/drift/reconcile coherent.
	got, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origins["immich"].Addr != "10.0.0.99:2283" {
		t.Errorf("origins not persisted; got %v", got.Origins)
	}
}

// TestCLI_ExposeWithTo_StillRefusesPublicWithoutAuth: --to must NOT be an
// end-run around the safety guardrail. A public host with no --auth is
// still refused (and no origins entry is persisted).
func TestCLI_ExposeWithTo_StillRefusesPublicWithoutAuth(t *testing.T) {
	fake := seedEmptyDenyFake(t)
	c, _, p := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.to = "10.0.0.99:2283" // NO --auth

	err := c.dispatch(context.Background(), "expose", []string{"immich"})
	if err == nil || !strings.Contains(err.Error(), "PUBLIC with no auth") {
		t.Fatalf("--to must NOT bypass the public-auth guardrail; got %v", err)
	}
	if len(fake.Loads) != 0 {
		t.Error("a refused expose must not POST /load")
	}
	// Persistence must not run when apply is refused — otherwise origins would
	// name a service that has no live route.
	got, _ := config.Load(p)
	if _, has := got.Origins["immich"]; has {
		t.Errorf("origins must NOT be persisted when apply is refused; got %v", got.Origins)
	}
}

// TestCLI_ExposeWithoutTo_UnchangedPreDeclaredPath: the existing UX (a
// pre-declared origin in the map, no --to) must keep working with no changes.
func TestCLI_ExposeWithoutTo_UnchangedPreDeclaredPath(t *testing.T) {
	fake := seedEmptyDenyFake(t)
	c, out, _ := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{"photos":"10.0.0.6:2342"}}`)
	c.gf.auth = "none"
	// no c.gf.to
	if err := c.dispatch(context.Background(), "expose", []string{"photos"}); err != nil {
		t.Fatalf("pre-declared expose must still work, got %v: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("expose should verify:\n%s", out.String())
	}
	if strings.Contains(out.String(), "persisted origin") {
		t.Error("without --to, expose must NOT print a persistence trace")
	}
}

// TestCLI_PreviewWithTo_ReflectsBackend: preview is the read-only look at the
// planned change. It must show the --to backend on the planned route (proof
// the flag flows into buildOp → Plan, not just Apply).
func TestCLI_PreviewWithTo_ReflectsBackend(t *testing.T) {
	fake := seedEmptyDenyFake(t)
	c, out, p := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.to = "10.0.0.99:2283"
	c.gf.jsonOut = true // JSON is easy to grep for the backend

	if err := c.dispatch(context.Background(), "preview", []string{"expose", "immich"}); err != nil {
		t.Fatalf("preview --to should succeed, got %v", err)
	}
	if !strings.Contains(out.String(), "10.0.0.99:2283") {
		t.Errorf("preview JSON should include the --to backend on the planned route:\n%s", out.String())
	}
	// Preview must NEVER persist (it is read-only).
	got, _ := config.Load(p)
	if _, has := got.Origins["immich"]; has {
		t.Errorf("preview must NEVER persist origins; got %v", got.Origins)
	}
}

// TestCLI_ExposeWithTo_RefusesMultiEdge: a multi-edge topology is refused
// with a clear message before any apply runs — origins live per-edge there
// and the CLI cannot unambiguously pick one.
func TestCLI_ExposeWithTo_RefusesMultiEdge(t *testing.T) {
	fake := seedEmptyDenyFake(t)
	c, _, _ := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","edges":[{"name":"home","driver":"caddy","origins":{}}]}`)
	c.gf.auth = "none"
	c.gf.to = "10.0.0.99:2283"

	err := c.dispatch(context.Background(), "expose", []string{"immich"})
	if err == nil {
		t.Fatal("multi-edge + --to must be refused")
	}
	if !strings.Contains(err.Error(), "multi-edge") {
		t.Errorf("error should name the multi-edge case, got %v", err)
	}
	if len(fake.Loads) != 0 {
		t.Error("multi-edge + --to must refuse BEFORE apply")
	}
}

// TestAbsorbPostVerbFlags_To: the user-natural post-verb ordering
// (`expose immich --to immich:2283 --auth authelia`) must work — Go's flag
// package stops at the first positional, so the CLI absorbs recognized
// globals after the verb. --to must be one of them; both spellings work.
func TestAbsorbPostVerbFlags_To(t *testing.T) {
	gf := &globalFlags{}
	rest, err := absorbPostVerbFlags(gf, []string{"immich", "--to", "immich:2283", "--auth", "authelia"})
	if err != nil {
		t.Fatal(err)
	}
	if gf.to != "immich:2283" {
		t.Errorf("--to not absorbed: %q", gf.to)
	}
	if gf.auth != "authelia" {
		t.Errorf("--auth still absorbed alongside --to: %q", gf.auth)
	}
	if len(rest) != 1 || rest[0] != "immich" {
		t.Errorf("positional lost: %v", rest)
	}

	gf2 := &globalFlags{}
	if _, err := absorbPostVerbFlags(gf2, []string{"immich", "--upstream=immich:2283"}); err != nil {
		t.Fatal(err)
	}
	if gf2.to != "immich:2283" {
		t.Errorf("--upstream alias not absorbed: %q", gf2.to)
	}
}
