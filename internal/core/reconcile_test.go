package core_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// driftKinds returns the multiset of drift kinds in a plan, for assertions.
func driftCount(rep core.ReconcileReport, kind core.DriftKind) int {
	n := 0
	for _, d := range rep.Plan.Drift {
		if d.Kind == kind {
			n++
		}
	}
	return n
}

// TestReconcile_ConvergesMultiEdgeDrift builds a multi-edge world drifted SEVERAL
// ways at once and proves a single reconcile converges all of it:
//   - grafana exposed on home (caddy) but MISSING from vps (traefik), which also
//     fronts it           => missing_route
//   - api exposed HTTP on home but as TCP-PASSTHROUGH on vps (mode drift from the
//     canonical primary-edge mode)        => mode_mismatch
//   - grafana + api exposed but with no DNS record       => missing_dns_record (x2)
//   - a managed DNS record for photos, which is exposed on NO edge => stale_dns_record
func TestReconcile_ConvergesMultiEdgeDrift(t *testing.T) {
	ctx := context.Background()

	// home: caddy, fronts grafana/api/photos; has grafana + api exposed (HTTP).
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n" +
		"api.example.com {\n\treverse_proxy 10.0.0.8:8080\n}\n:443 {\n\trespond 403\n}\n")
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000", "api": "10.0.0.8:8080", "photos": "10.0.0.6:2342"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	// vps: traefik, fronts grafana/api; has api exposed as TCP passthrough only.
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	seedVPS := `{
	  "tcp": {
	    "routers":  {"crenel-tcp-api.example.com": {"rule": "HostSNI(` + "`api.example.com`" + `)", "service": "crenel-tcp-api.example.com", "tls": {"passthrough": true}}},
	    "services": {"crenel-tcp-api.example.com": {"loadBalancer": {"servers": [{"address": "100.100.0.8:8080"}]}}}
	  }
	}`
	if err := os.WriteFile(path, []byte(seedVPS), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000", "api": "100.100.0.8:8080"}
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	// internal DNS seeded with a stale record (photos exposed on no edge).
	sh := dnscontrolfake.New("example.com", model.Record{Name: "photos.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal})
	dns := dnscontrol.New(dnscontrol.Config{ZoneName: "example.com", Scope: model.ScopeInternal, EdgeAddr: "10.0.0.1", Shell: sh})

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com", dns)

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if rep.Converged {
		t.Fatal("there WAS drift; reconcile should not report converged")
	}
	if !rep.Verified() {
		t.Fatalf("reconcile should verify after converging, got %+v", rep.Verify)
	}

	// Drift detected: exactly the shapes we engineered.
	if got := driftCount(rep, core.DriftMissingRoute); got != 1 {
		t.Errorf("want 1 missing_route (grafana on vps), got %d", got)
	}
	if got := driftCount(rep, core.DriftModeMismatch); got != 1 {
		t.Errorf("want 1 mode_mismatch (api on vps), got %d", got)
	}
	if got := driftCount(rep, core.DriftMissingDNS); got != 2 {
		t.Errorf("want 2 missing_dns_record (grafana, api), got %d", got)
	}
	if got := driftCount(rep, core.DriftStaleDNS); got != 1 {
		t.Errorf("want 1 stale_dns_record (photos), got %d", got)
	}

	// Post-state: vps now exposes grafana AND api, api re-rendered as HTTP-proxy
	// (the canonical primary-edge mode), the passthrough gone.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		if es.Name != "vps" {
			continue
		}
		var hasGrafana, apiHTTP bool
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				hasGrafana = true
			}
			if r.Host == "api.example.com" {
				apiHTTP = r.Upstream.Mode == model.ModeHTTPProxy
			}
		}
		if !hasGrafana {
			t.Error("vps should expose grafana after reconcile (missing route re-added)")
		}
		if !apiHTTP {
			t.Error("vps api should be re-rendered as HTTP-proxy after reconcile (mode converged)")
		}
	}

	// DNS converged: grafana + api present, stale photos removed.
	live, _ := dns.LiveRecords(ctx)
	names := map[string]bool{}
	for _, r := range live {
		names[r.Name] = true
	}
	if !names["grafana.example.com"] || !names["api.example.com"] {
		t.Errorf("DNS should now have grafana + api records, got %v", names)
	}
	if names["photos.example.com"] {
		t.Error("stale photos DNS record should have been removed")
	}

	// A SECOND reconcile is now a clean no-op (idempotent convergence).
	rep2, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.Converged {
		t.Errorf("second reconcile should be a clean no-op, got drift %+v", rep2.Plan.Drift)
	}
}

// TestDetectDrift_ReadOnly: the drift verb reports divergence from the canonical
// set WITHOUT mutating anything, and an already-consistent world reports none.
func TestDetectDrift_ReadOnly(t *testing.T) {
	ctx := context.Background()

	// home (caddy) exposes grafana; vps (traefik) also fronts it but is empty.
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(seedGrafana)
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("drift should be detected (grafana missing on vps)")
	}
	if len(plan.Drift) != 1 || plan.Drift[0].Kind != core.DriftMissingRoute {
		t.Errorf("expected one missing_route drift, got %+v", plan.Drift)
	}

	// Read-only: vps must NOT have been mutated by the detection.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		if es.Name == "vps" && len(es.Routes) != 0 {
			t.Errorf("drift detection must not mutate vps, got routes %+v", es.Routes)
		}
	}

	// After converging, drift reports nothing.
	if _, err := e.Reconcile(ctx, core.AlwaysYesReconcile); err != nil {
		t.Fatal(err)
	}
	plan2, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !plan2.Empty() {
		t.Errorf("a converged world should report no drift, got %+v", plan2.Drift)
	}
}

// TestReconcile_CleanWorldIsNoOp: an already-consistent multi-edge world reconciles
// to a clean no-op without touching anything.
func TestReconcile_CleanWorldIsNoOp(t *testing.T) {
	e, _, _ := heteroEngine(t)
	ctx := context.Background()
	// Bring the world to a consistent state (grafana on both edges).
	if _, err := e.Apply(ctx, e.BuildOp(model.Expose, "grafana"), core.AlwaysYes); err != nil {
		t.Fatal(err)
	}
	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Converged {
		t.Errorf("expected converged no-op, got drift %+v", rep.Plan.Drift)
	}
	if rep.Applied {
		t.Error("a no-op reconcile must not apply anything")
	}
}

// TestReconcile_RollsBackOnFailure: reconcile applies a missing route to one edge
// successfully, then the next edge's apply fails — the whole transaction rolls
// back, reverting the edge it already fixed. No partial convergence is left.
func TestReconcile_RollsBackOnFailure(t *testing.T) {
	ctx := context.Background()

	// vps (traefik) already exposes grafana => grafana is in the canonical set.
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vpsDriver := traefik.New(path, static.New(vpsOrigins))
	// Pre-expose grafana on vps directly via the driver.
	if err := vpsDriver.Apply(ctx, model.ChangeSet{Edge: model.EdgeChange{
		AddRoutes: []model.Route{{Host: "grafana.example.com", Upstream: model.Upstream{Address: "100.100.0.5:3000"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	vps := core.EdgeBinding{Name: "vps", Provider: vpsDriver, Fronts: frontsFor(vpsOrigins)}

	// home (caddy) fronts grafana but is EMPTY => missing route => reconcile will
	// apply it (and succeed).
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile(":443 {\n\trespond 403\n}\n")
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	// bad edge fronts grafana, is missing it, and its Apply always fails.
	bad := core.EdgeBinding{Name: "bad", Provider: failOnApply{live: model.LiveEdgeState{DenyCatchAllPresent: true}}, Fronts: func(string) bool { return true }}

	// Order matters: vps (no change) , home (change succeeds) , bad (change fails).
	e := core.NewMulti([]core.EdgeBinding{vps, home, bad}, "example.com")

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err == nil {
		t.Fatal("expected reconcile to fail on the bad edge")
	}
	if !rep.RolledBack {
		t.Error("expected RolledBack=true")
	}
	if len(rep.RollbackErrors) != 0 {
		t.Errorf("home rollback should succeed cleanly, got %v", rep.RollbackErrors)
	}

	// home (which reconcile fixed) must be reverted; vps (untouched) keeps grafana.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		has := false
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				has = true
			}
		}
		switch es.Name {
		case "home":
			if has {
				t.Error("home must be rolled back to empty after the bad edge failed")
			}
		case "vps":
			if !has {
				t.Error("vps (untouched) must still expose grafana")
			}
		}
	}
}

// TestReconcile_ReAddsRouteWithAuth proves the F3 fix: when reconcile re-adds a
// managed route that is missing from an edge that also fronts it, it carries the
// route's forward-auth from the primary edge — it must NOT drop protection and leave
// the re-added host public-and-unprotected (a MISREAD-↓ by mutation).
func TestReconcile_ReAddsRouteWithAuth(t *testing.T) {
	ctx := context.Background()
	policies := map[string]caddy.AuthRef{"authelia": {ForwardAuth: "authelia:9080", VerifyURI: "/api/verify?rd=https://auth.example.com"}}

	// home (caddy, granular): grafana already crenel-managed BEHIND a forward_auth
	// reference (policy=authelia).
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	if err := cf.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"@id":"crenel-route-grafana.example.com","match":[{"host":["grafana.example.com"]}],"handle":[
			{"handler":"forward_auth","crenel_policy":"authelia","upstreams":[{"dial":"authelia:9080"}]},
			{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`); err != nil {
		t.Fatal(err)
	}
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home",
		Provider: caddy.New(cf.URL(), static.New(homeOrigins), caddy.WithGranularApply(), caddy.WithAuthPolicies(policies)),
		Fronts:   frontsFor(homeOrigins)}

	// vps (caddy, granular): also fronts grafana, currently empty (only the deny).
	vf := caddyfake.New()
	t.Cleanup(vf.Close)
	if err := vf.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vps := core.EdgeBinding{Name: "vps",
		Provider: caddy.New(vf.URL(), static.New(vpsOrigins), caddy.WithGranularApply(), caddy.WithAuthPolicies(policies)),
		Fronts:   frontsFor(vpsOrigins)}

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("reconcile read-back should verify (incl. auth): %+v", rep.Verify)
	}

	// vps must now serve grafana WITH the auth policy carried over — not unprotected.
	st, _ := e.Status(ctx)
	var found bool
	for _, es := range st.Edges {
		if es.Name != "vps" {
			continue
		}
		for _, r := range es.Routes {
			if r.Host == "grafana.example.com" {
				found = true
				if r.Upstream.Auth != "authelia" {
					t.Errorf("re-added grafana on vps must carry auth=authelia, got %q (F3: protection dropped)", r.Upstream.Auth)
				}
			}
		}
	}
	if !found {
		t.Fatal("reconcile should have re-added grafana on vps")
	}
}

// TestReconcile_NeverTouchesUnmanagedRoutes: a route whose service NO edge fronts
// (an unmanaged route, e.g. Authelia) is never pulled into the canonical set, so
// reconcile neither propagates it to other edges nor reports drift for it.
func TestReconcile_NeverTouchesUnmanagedRoutes(t *testing.T) {
	ctx := context.Background()

	// home (caddy) exposes grafana (managed) AND authelia (UNMANAGED — not in any
	// edge's origins).
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n" +
		"authelia.example.com {\n\treverse_proxy 10.0.0.9:9091\n}\n:443 {\n\trespond 403\n}\n")
	homeOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(cf.URL(), static.New(homeOrigins)), Fronts: frontsFor(homeOrigins)}

	// vps (traefik) ALSO fronts grafana but not authelia; currently empty.
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	vpsOrigins := map[string]string{"grafana": "100.100.0.5:3000"}
	vps := core.EdgeBinding{Name: "vps", Provider: traefik.New(path, static.New(vpsOrigins)), Fronts: frontsFor(vpsOrigins)}

	e := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")

	rep, err := e.Reconcile(ctx, core.AlwaysYesReconcile)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	// The ONLY drift is grafana missing on vps — authelia is never considered.
	if len(rep.Plan.Drift) != 1 || rep.Plan.Drift[0].Host != "grafana.example.com" {
		t.Fatalf("reconcile should only act on managed grafana, got drift %+v", rep.Plan.Drift)
	}
	// vps must NOT have gained authelia.
	st, _ := e.Status(ctx)
	for _, es := range st.Edges {
		if es.Name != "vps" {
			continue
		}
		for _, r := range es.Routes {
			if r.Host == "authelia.example.com" {
				t.Error("reconcile propagated an UNMANAGED route to vps — must never happen")
			}
		}
	}
	// home still serves authelia, untouched.
	for _, es := range st.Edges {
		if es.Name != "home" {
			continue
		}
		found := false
		for _, r := range es.Routes {
			if r.Host == "authelia.example.com" {
				found = true
			}
		}
		if !found {
			t.Error("home's unmanaged authelia route must be left intact")
		}
	}
}
