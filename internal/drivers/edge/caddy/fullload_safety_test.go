package caddy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// TestFullLoad_RefusesWhenUnparsed proves the F1 guard: a full-config replace is
// REFUSED on an edge holding an unparsed construct, because rebuilding solely from
// the understood routes would silently DROP it and falsely flip default-deny from
// UNKNOWN to ENFORCED (register §4.4). The refusal leaves the live config untouched.
func TestFullLoad_RefusesWhenUnparsed(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// A file_server terminal is an unmodeled handler => normalize emits Unparsed.
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["files.example.com"]}],"handle":[{"handler":"file_server","root":"/srv"}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver()) // NOT granular => full-load path
	ctx := context.Background()

	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if live.FullyParsed() {
		t.Fatal("precondition: seed should produce an unparsed construct")
	}

	// Exposing an UNRELATED host via full-load must refuse rather than clobber.
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Apply(ctx, cs)
	if err == nil || !strings.Contains(err.Error(), "unparsed") {
		t.Fatalf("full-load apply on an unparsed edge must refuse, got %v", err)
	}
	// The file_server route must still be present (nothing was clobbered).
	if got := fake.CurrentJSON(); !strings.Contains(got, "file_server") {
		t.Errorf("a refused full-load must not mutate live; file_server gone:\n%s", got)
	}
}

// TestFullLoad_RefusesWhenAuthPresent proves the F2 guard: a full-config replace is
// REFUSED when a surviving route carries forward-auth, because the bare-reverse_proxy
// renderer would STRIP it (leaving the host public-unprotected) while read-back still
// passes green. The auth handler must survive the refusal.
func TestFullLoad_RefusesWhenAuthPresent(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["secure.example.com"]}],"handle":[
			{"handler":"authentication","providers":{"http_basic":{}}},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.8:80"}]}
		]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver()) // full-load path
	ctx := context.Background()

	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Apply(ctx, cs)
	if err == nil || !strings.Contains(err.Error(), "forward-auth") {
		t.Fatalf("full-load apply that would strip auth must refuse, got %v", err)
	}
	if got := fake.CurrentJSON(); !strings.Contains(got, "authentication") {
		t.Errorf("a refused full-load must not strip the auth handler:\n%s", got)
	}
}

// TestFullLoad_AllowsCleanGreenfield proves the guard does NOT over-refuse: a
// fully-parsed edge of clean reverse_proxy routes with no auth (the greenfield case
// full-load is designed for) still applies normally.
func TestFullLoad_AllowsCleanGreenfield(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	d := caddy.New(fake.URL(), resolver()) // full-load path
	ctx := context.Background()

	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("clean greenfield full-load should apply, got %v", err)
	}
	after, _ := d.ReadLiveState(ctx)
	if !after.Reachable("photos.example.com") || !after.Reachable("grafana.example.com") {
		t.Errorf("both hosts should be reachable after a clean full-load apply")
	}
}
