package caddy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresPathGranularRoutes proves crenel does not SILENTLY read a
// route gated by a non-host matcher (path / method / header / …) as a plain host
// route. The Caddy matcher decoder historically modeled only `host`, so a route
// matched on `host + path` decoded as a bare host match and was emitted as a
// confident `host → backend` route — the path constraint dropped. That is a
// MISREAD-↓ that violates bounded honesty: a host split across `/admin/*` (an auth'd
// admin backend) and `/*` (a public backend) read as ONE fully-exposed host, so
// auth/exposure answers for that host were wrong.
//
// The fixture mirrors that real shape: `app.example.com` is split across two PATH
// routes and `api.example.com` is gated by a METHOD matcher; a clean host route
// (grafana) and the catch-all deny sit alongside. After the fix each non-host-matched
// FORWARDING route is DECLARED `matcher_conditional` (path-granular routing is not
// represented at host granularity) rather than enumerated as a host route, so deny
// DOWNGRADES to UNKNOWN — never falsely ENFORCED over routes crenel could not fully read.
func TestNormalize_DeclaresPathGranularRoutes(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/path-granular-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{
		"grafana": "10.0.0.5:3000", "app": "10.0.0.9:8080", "api": "10.0.0.10:9000",
	}))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The plain host route is still enumerated.
	if !live.HasHost("grafana.example.com") {
		t.Fatalf("the plain-host grafana route must be enumerated; got %v", live.Hosts())
	}
	// The path/method-scoped routes must NOT be read as plain host routes — that was the
	// silent misread. Reading app.example.com as a simple reachable host claims the WHOLE
	// host is exposed when only specific paths are.
	if live.HasHost("app.example.com") {
		t.Errorf("a path-scoped route must NOT be read as a plain host route, but app.example.com is enumerated as one: %v", live.Hosts())
	}
	if live.HasHost("api.example.com") {
		t.Errorf("a method-scoped route must NOT be read as a plain host route, but api.example.com is enumerated as one: %v", live.Hosts())
	}
	if len(live.Routes) != 1 {
		t.Errorf("exactly one understood (plain-host) route expected, got %d: %v", len(live.Routes), live.Hosts())
	}

	// Three matcher_conditional declarations: two path routes + one method route.
	var matcherUnparsed []model.Unparsed
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			matcherUnparsed = append(matcherUnparsed, u)
		}
		if u.Locator == "" || u.Reason == "" {
			t.Errorf("every unparsed entry must carry a locator + reason: %+v", u)
		}
	}
	if len(matcherUnparsed) != 3 {
		t.Fatalf("expected 3 matcher_conditional declarations (2 path + 1 method), got %d: %+v", len(matcherUnparsed), live.Unparsed)
	}
	// The reason must name the offending matcher key so the operator can see WHY.
	var sawPath, sawMethod bool
	for _, u := range matcherUnparsed {
		if strings.Contains(u.Reason, "path") {
			sawPath = true
		}
		if strings.Contains(u.Reason, "method") {
			sawMethod = true
		}
	}
	if !sawPath || !sawMethod {
		t.Errorf("matcher_conditional reasons must name the matcher key (path/method); got %+v", matcherUnparsed)
	}

	// Coverage + deny verdict: present but NOT fully parsed => UNKNOWN, never ENFORCED.
	understood, total := live.Coverage()
	if understood != 1 || total != 4 {
		t.Errorf("coverage should be 1/4 (1 understood + 3 declared), got %d/%d", understood, total)
	}
	if live.FullyParsed() {
		t.Error("config has path/method-scoped routes crenel cannot model; FullyParsed must be false")
	}
	if !live.DenyCatchAllPresent {
		t.Error("a status_code-403 catch-all is present => DenyCatchAllPresent should be true")
	}
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("deny must DOWNGRADE to UNKNOWN with path-granular routes, got %q", got)
	}
}

// TestNormalize_PlainHostRoutesUnaffectedByMatcherCheck locks the no-cry-wolf side:
// crenel's OWN routes and ordinary host-only routes carry only a `host` matcher, so the
// matcher_conditional declaration must NEVER fire for them. The existing fully-parsed
// nested fixture (all host-matched, wildcard → subroute → per-host) must still read at
// FULL coverage with deny ENFORCED.
func TestNormalize_PlainHostRoutesUnaffectedByMatcherCheck(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/nested-subroute-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), nestedResolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			t.Errorf("a host-only edge must not raise matcher_conditional (cry-wolf): %+v", u)
		}
	}
	if !live.FullyParsed() {
		t.Errorf("host-only nested fixture must read at full coverage, got unparsed: %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("fully-parsed host-only edge must read deny ENFORCED, got %q", got)
	}
}
