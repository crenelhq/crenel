package core_test

// chain_wildcard_forward_test.go proves the chain-forward presence checks are
// WILDCARD-AWARE (the third instance of the wildcard-vs-presence cry-wolf, after the
// internal DNS parity fix and the public-DNS coverage fix — same matching rule,
// wildcardPatternCovers). The mirrored production shape: a FRONT edge ("vps") whose
// live routes hold one zone-wide WILDCARD forward (`*.zone → downstream:443`, exactly
// the literal `*.zone` leaf the caddy reader surfaces for a wildcard site block with
// no nested per-host matchers) plus its own terminal VPS-local route; a DOWNSTREAM
// edge ("home") fronting host "ha" in its origins projection. Before the fix, drift
// cried wolf per host: `missing_route ha.<zone> @ vps — half-present chain …` and
// reconcile planned a redundant explicit forward the wildcard already carries.

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// wildRoute is the FRONT edge's zone-wide wildcard forward exactly as the caddy
// reader surfaces it in live reads: a literal `*.zone` leaf route whose backend
// dials the downstream edge (or, in the negative tests, somewhere else).
func wildRoute(pattern, dial string) model.Route {
	return model.Route{Host: pattern, Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: dial, ServerName: pattern, UpstreamTLS: true}}
}

// wildcardChainEngine mirrors the production wiring: the front's downstream_address
// is the BARE host (no port) while the wildcard dials host:443 — chainForward's
// dialHost matching is port-insensitive, so the classification must still hold.
func wildcardChainEngine(front, home *memEdge) *core.Engine {
	return core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: frontsFor(front.origins), DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example")
}

// prodFront builds the front edge: one terminal VPS-local route (the front serves it
// itself, behind auth) plus — when extra routes are given — the wildcard forward(s).
func prodFront(extra ...model.Route) *memEdge {
	routes := append([]model.Route{{Host: "status.homelab.example", Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: "127.0.0.2:9090",
		ServerName: "status.homelab.example", Auth: "authelia"}}}, extra...)
	return &memEdge{name: "vps", origins: map[string]string{"status": "127.0.0.2:9090"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: routes}}
}

// prodHome builds the downstream edge fronting "ha" (in its origins projection map)
// with its terminal route present and auth enforced there — the healthy downstream.
func prodHome() *memEdge {
	return &memEdge{name: "home", origins: map[string]string{"ha": "10.0.0.5:8123"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
			downRoute("ha.homelab.example", "10.0.0.5:8123", "authelia"),
		}}}
}

// TestChainWildcardForward_DriftAndAuditClean: the healthy prod shape — the wildcard
// forward already carries every covered host downstream — must be drift-clean AND
// audit-clean (no warning/critical findings; in particular no half-present
// missing_route and no chain_unresolved cry-wolf on the wildcard relay).
func TestChainWildcardForward_DriftAndAuditClean(t *testing.T) {
	front := prodFront(wildRoute("*.homelab.example", "10.0.0.13:443"))
	e := wildcardChainEngine(front, prodHome())
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("wildcard forward already carries the host downstream — drift must be clean, got %+v", plan.Drift)
	}

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var relay bool
	for _, f := range rep.Findings {
		if f.Severity != "ok" {
			t.Errorf("audit must be clean on the healthy wildcard chain, got %s finding %s: %s", f.Severity, f.Code, f.Message)
		}
		// The zone relay is accounted as chain follow-through, not dangling.
		if f.Code == "chain_resolved" && strings.Contains(f.Message, "wildcard relay") {
			relay = true
		}
	}
	if !relay {
		t.Errorf("audit should account the wildcard forward as a resolved zone relay, got %+v", rep.Findings)
	}
}

// TestChainWildcardForward_WrongDialStillFlags: a covering wildcard that dials
// somewhere OTHER than the downstream edge is NOT satisfaction — the host would be
// answered at the front but sent to the wrong place. Drift must still flag the
// missing forward, with a detail NAMING the wildcard and where it actually dials,
// and reconcile must add the explicit override forward.
func TestChainWildcardForward_WrongDialStillFlags(t *testing.T) {
	front := prodFront(wildRoute("*.homelab.example", "203.0.113.99:443")) // NOT the downstream
	e := wildcardChainEngine(front, prodHome())
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !chainDrift(plan, core.DriftMissingRoute, "vps") {
		t.Fatalf("wrong-dial wildcard must not satisfy the forward's presence, got %+v", plan.Drift)
	}
	var detail string
	for _, d := range plan.Drift {
		if d.Kind == core.DriftMissingRoute && d.Target == "vps" {
			detail = d.Detail
		}
	}
	for _, must := range []string{"*.homelab.example", "203.0.113.99:443", "10.0.0.13"} {
		if !strings.Contains(detail, must) {
			t.Errorf("drift detail must name the wildcard and its actual dial (missing %q): %s", must, detail)
		}
	}

	// Reconcile adds the explicit per-host override forward (which wins over the
	// wildcard at the edge) and verifies cleanly.
	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified, got %+v\n%+v", rep, rep.Verify)
	}
	fv, ok := liveRoute(*front.live, "ha.homelab.example")
	if !ok || fv.Upstream.Address != "10.0.0.13" || fv.Upstream.Auth != "" {
		t.Errorf("explicit override forward should be added (dial downstream, no auth), got %+v", fv)
	}
}

// TestChainWildcardForward_NoWildcardStillFlags: with NO covering wildcard and no
// explicit forward, the half-present chain still flags exactly as before and
// reconcile's corrective Add is unchanged — wildcard-awareness is a targeted
// satisfaction rule, never a blanket suppression of the chain presence check.
func TestChainWildcardForward_NoWildcardStillFlags(t *testing.T) {
	front := prodFront() // terminal local only — nothing forwards the zone
	e := wildcardChainEngine(front, prodHome())
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !chainDrift(plan, core.DriftMissingRoute, "vps") {
		t.Fatalf("missing forward with no covering wildcard must still flag, got %+v", plan.Drift)
	}
	for _, d := range plan.Drift {
		if d.Kind == core.DriftMissingRoute && d.Target == "vps" {
			if !strings.Contains(d.Detail, "half-present chain") || strings.Contains(d.Detail, "wildcard") {
				t.Errorf("plain half-present detail expected (no wildcard note), got %s", d.Detail)
			}
		}
	}

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied + verified, got %+v\n%+v", rep, rep.Verify)
	}
	if _, ok := liveRoute(*front.live, "ha.homelab.example"); !ok {
		t.Errorf("corrective Add for a genuinely-missing forward must be unchanged, routes: %+v", front.live.Routes)
	}
}

// TestChainWildcardForward_ExplicitForwardStillSatisfies: an explicit per-host
// forward (no wildcard at all) satisfies presence exactly as today.
func TestChainWildcardForward_ExplicitForwardStillSatisfies(t *testing.T) {
	front := prodFront(fwdRoute("ha.homelab.example", "10.0.0.13:443"))
	e := wildcardChainEngine(front, prodHome())

	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("explicit per-host forward must satisfy presence, got %+v", plan.Drift)
	}
}
