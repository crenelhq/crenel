package caddy_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// These tests mirror the shape of the maintainer's REAL VPS edge (the 2026-06-27 read-only
// v0.1.0 trial surfaced both gaps below):
//
//	*.homelab.example  -> subroute
//	  ├─ vault.homelab.example           -> subroute -> [crowdsec, reverse_proxy]   (per-host backend)
//	  ├─ [auth, books, git, …]          -> subroute -> [crowdsec, reverse_proxy]   (ONE route, MANY hosts → home edge)
//	  └─ (host-less)                    -> subroute -> static_response{abort:true} (the per-zone deny)
//
// Two real misreads it exposed:
//  1. a single route grouping many hosts read as ONLY its first host — the rest were
//     silently dropped (~21 of ~30 services invisible);
//  2. the per-zone catch-all `{"handler":"static_response","abort":true}` (no
//     status_code) read as an unmodeled handler → default-deny falsely UNKNOWN.

// TestNormalize_GroupedMultiHostRoute_EnumeratesEveryHost proves fix #1: a single
// Caddy route matching N hosts yields N reachable services, not just the first.
func TestNormalize_GroupedMultiHostRoute_EnumeratesEveryHost(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// One wildcard zone: a per-host backend (vault), a GROUPED route fronting four
	// hosts onto one downstream dial, and an abort catch-all.
	seed := `{"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{"match": [{"host": ["*.homelab.example"]}], "handle": [{"handler": "subroute", "routes": [{"match": [{"host": ["vault.homelab.example"]}], "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "crowdsec"}, {"handler": "reverse_proxy", "upstreams": [{"dial": "172.18.0.5:80"}]}]}]}]}, {"match": [{"host": ["auth.homelab.example", "git.homelab.example", "photos.homelab.example", "jellyfin.homelab.example"]}], "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "crowdsec"}, {"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.13:443"}]}]}]}]}, {"handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "static_response", "abort": true}]}]}]}]}]}]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Every grouped host must be visible — none silently dropped.
	for _, h := range []string{
		"vault.homelab.example",
		"auth.homelab.example", "git.homelab.example",
		"photos.homelab.example", "jellyfin.homelab.example",
	} {
		if !live.HasHost(h) {
			t.Errorf("host %q must be enumerated; got %v", h, live.Hosts())
		}
	}
	// 1 per-host backend + 4 grouped hosts = 5 routes (the abort deny adds none).
	if got := len(live.Routes); got != 5 {
		t.Errorf("want 5 enumerated routes (1 vault + 4 grouped), got %d: %v", got, live.Hosts())
	}
	// The four grouped hosts share the one downstream dial.
	for _, r := range live.Routes {
		switch r.Host {
		case "auth.homelab.example", "git.homelab.example", "photos.homelab.example", "jellyfin.homelab.example":
			if r.Upstream.Address != "10.0.0.13:443" {
				t.Errorf("grouped host %q should dial 10.0.0.13:443, got %q", r.Host, r.Upstream.Address)
			}
		}
	}
}

// TestNormalize_AbortStaticResponse_RecognizedAsDeny proves fix #2: an
// `abort:true` static_response (no status_code) is a deny, so the config parses
// fully and default-deny reads ENFORCED — not a false UNKNOWN from an "unmodeled
// handler".
func TestNormalize_AbortStaticResponse_RecognizedAsDeny(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{"match": [{"host": ["*.homelab.example"]}], "handle": [{"handler": "subroute", "routes": [{"match": [{"host": ["vault.homelab.example"]}], "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "172.18.0.5:80"}]}]}, {"handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "static_response", "abort": true}]}]}]}]}]}]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !live.FullyParsed() {
		t.Errorf("abort static_response must parse as a deny, not Unparsed; got %+v", live.Unparsed)
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("default-deny should read ENFORCED once the abort deny is understood, got %q", got)
	}
	if !live.HasHost("vault.homelab.example") {
		t.Errorf("the real backend must still be enumerated; got %v", live.Hosts())
	}
}

// TestNormalize_MultiHostTopLevel_EnumeratesEveryHost proves the multi-host fix
// also applies to a flat (non-nested) config where a top-level route groups hosts.
func TestNormalize_MultiHostTopLevel_EnumeratesEveryHost(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{"match": [{"host": ["a.example.com", "b.example.com", "c.example.com"]}], "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.9:80"}]}]}, {"handle": [{"handler": "static_response", "status_code": 403}]}]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := caddy.New(fake.URL(), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if !live.HasHost(h) {
			t.Errorf("top-level grouped host %q must be enumerated; got %v", h, live.Hosts())
		}
	}
	if got := len(live.Routes); got != 3 {
		t.Errorf("want 3 routes (one per grouped host), got %d: %v", got, live.Hosts())
	}
	if got := live.DenyState(); got != model.DenyEnforced {
		t.Errorf("deny should be ENFORCED (explicit 403 catch-all, fully parsed), got %q", got)
	}
}
