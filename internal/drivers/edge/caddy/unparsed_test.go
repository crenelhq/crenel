package caddy_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresUnparsedHandlers proves the detect-and-declare-unknown net:
// normalize EMITS an Unparsed entry for every shape it cannot model (an unmodeled
// terminal handler, a subroute whose leaf is unmodeled, a top-level host-less
// subroute it will not descend) instead of silently dropping it — while still
// enumerating the one route it DOES understand and keeping the default-deny reading.
func TestNormalize_DeclaresUnparsedHandlers(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(mustRead(t, "testdata/unparseable-prod.json")); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), static.New(map[string]string{"grafana": "100.100.0.5:3000"}))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The one modeled route is enumerated (and reads as crenel-owned).
	if !live.HasHost("grafana.homelab.example") {
		t.Fatalf("the modeled grafana route must be enumerated; got %v", live.Hosts())
	}
	if len(live.Routes) != 1 {
		t.Errorf("exactly one understood route expected, got %d: %v", len(live.Routes), live.Hosts())
	}

	// Three unparsed entries: file_server terminal, vars-only subroute leaf, and the
	// top-level host-less subroute (not descended).
	if len(live.Unparsed) != 3 {
		t.Fatalf("expected 3 unparsed entries, got %d: %+v", len(live.Unparsed), live.Unparsed)
	}
	kinds := map[model.UnknownKind]int{}
	for _, u := range live.Unparsed {
		kinds[u.Kind]++
		if u.Locator == "" || u.Reason == "" {
			t.Errorf("every unparsed entry must carry a locator + reason: %+v", u)
		}
	}
	if kinds[model.UnknownHandler] != 2 {
		t.Errorf("expected 2 handler_unrecognized entries (file_server + vars leaf), got %d (%+v)", kinds[model.UnknownHandler], live.Unparsed)
	}
	if kinds[model.UnknownNestedRoute] != 1 {
		t.Errorf("expected 1 subroute_not_descended entry (the host-less subroute), got %d (%+v)", kinds[model.UnknownNestedRoute], live.Unparsed)
	}

	// Coverage + deny verdict: present but NOT fully parsed => UNKNOWN, never ENFORCED.
	understood, total := live.Coverage()
	if understood != 1 || total != 4 {
		t.Errorf("coverage should be 1/4, got %d/%d", understood, total)
	}
	if live.FullyParsed() {
		t.Error("config has unparsed routes; FullyParsed must be false")
	}
	if !live.DenyCatchAllPresent {
		t.Error("no top-level host-less reverse_proxy => DenyCatchAllPresent should be true")
	}
	if got := live.DenyState(); got != model.DenyUnknown {
		t.Errorf("deny must DOWNGRADE to UNKNOWN with unparsed routes, got %q", got)
	}
}

// TestNormalize_FullyParsedFixtureHasNoUnparsed locks the regression guarantee that
// the recursion + auth work still reads the real nested edge at FULL coverage — no
// Unparsed entries, deny ENFORCED — so the existing trial fixtures are unaffected.
func TestNormalize_FullyParsedFixtureHasNoUnparsed(t *testing.T) {
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
	if !live.FullyParsed() {
		t.Errorf("nested fixture must read at full coverage, got unparsed: %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("fully-parsed nested edge must read deny ENFORCED, got %q", got)
	}
}
