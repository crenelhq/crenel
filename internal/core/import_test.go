package core_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/nginx"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestImport_AdoptsBrownfieldAcrossDrivers builds a pre-existing setup the way an
// operator actually has it — hand-written, UNMANAGED routes for the exact hosts
// crenel is configured to front — and proves `import`:
//   - adopts an unmanaged-but-matching route in-place on EACH driver shape,
//   - leaves an out-of-domain vhost (Authelia) completely untouched,
//   - flags an origin mismatch as a conflict (does NOT adopt it),
//   - is idempotent (a second import finds everything already managed),
//   - and CLOSES THE LIFECYCLE GAP: a host that could not be unexposed before
//     adoption (delete-by-marker no-ops) unexposes cleanly afterwards.
func TestImport_AdoptsBrownfieldAcrossDrivers(t *testing.T) {
	ctx := context.Background()

	// caddy edge: an unmanaged grafana route (matches origin) + an unmanaged
	// Authelia vhost (NOT in origins → out of domain) + the deny.
	cf := caddyfake.New()
	t.Cleanup(cf.Close)
	cf.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["grafana.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"match":[{"host":["auth.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:9091"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`)
	caddyOrigins := map[string]string{"grafana": "10.0.0.5:3000"}
	caddyEdge := core.EdgeBinding{
		Name:     "caddy",
		Provider: caddy.New(cf.URL(), static.New(caddyOrigins), caddy.WithGranularApply()),
		Fronts:   frontsFor(caddyOrigins),
	}

	// traefik edge: an unmanaged photos router (matches) + an unmanaged "vault"
	// router whose backend DIFFERS from the configured origin (conflict).
	tdir := t.TempDir()
	tpath := filepath.Join(tdir, "dynamic.json")
	mustWrite(t, tpath, `{"http":{
		"routers":{
			"photos-router":{"rule":"Host(`+"`"+`photos.example.com`+"`"+`)","service":"photos-svc"},
			"vault-router":{"rule":"Host(`+"`"+`vault.example.com`+"`"+`)","service":"vault-svc"}
		},
		"services":{
			"photos-svc":{"loadBalancer":{"servers":[{"url":"http://10.0.0.6:2342"}]}},
			"vault-svc":{"loadBalancer":{"servers":[{"url":"http://10.0.0.99:8200"}]}}
		}
	}}`)
	traefikOrigins := map[string]string{"photos": "10.0.0.6:2342", "vault": "10.0.0.7:8200"}
	traefikEdge := core.EdgeBinding{
		Name:     "traefik",
		Provider: traefik.New(tpath, static.New(traefikOrigins)),
		Fronts:   frontsFor(traefikOrigins),
	}

	// nginx edge: an unmanaged status vhost (matches) preserved verbatim, plus a deny
	// default_server on the SAME :443 — so the brownfield is genuinely default-deny
	// (without it, status.example.com is nginx's implicit default server for :443 and
	// unmatched hosts leak to it: bench gap N4). Adopt stamps the marker without adding
	// a deny (it must not change behavior), so the brownfield must already deny.
	ndir := t.TempDir()
	npath := filepath.Join(ndir, "nginx.conf")
	mustWrite(t, npath, "server {\n    listen 443 ssl;\n    server_name status.example.com;\n    location / {\n        proxy_pass http://10.0.0.10:8080;\n    }\n}\n\nserver {\n    listen 443 ssl default_server;\n    server_name _;\n    return 444;\n}\n")
	nginxOrigins := map[string]string{"status": "10.0.0.10:8080"}
	nginxEdge := core.EdgeBinding{
		Name:     "nginx",
		Provider: nginx.New(npath, static.New(nginxOrigins)),
		Fronts:   frontsFor(nginxOrigins),
	}

	e := core.NewMulti([]core.EdgeBinding{caddyEdge, traefikEdge, nginxEdge}, "example.com")

	// --- scan: 3 adoptable, 1 conflict, Authelia untouched (not even shown). ---
	plan, err := e.DetectImport(ctx)
	if err != nil {
		t.Fatalf("DetectImport: %v", err)
	}
	if len(plan.Adopt) != 3 {
		t.Fatalf("want 3 adoptable, got %d: %+v", len(plan.Adopt), plan.Adopt)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Host != "vault.example.com" || plan.Conflicts[0].Reason != "origin_mismatch" {
		t.Fatalf("want 1 vault origin_mismatch conflict, got %+v", plan.Conflicts)
	}
	for _, a := range plan.Adopt {
		if a.Host == "auth.example.com" {
			t.Fatal("Authelia vhost is out of domain and must NEVER be an adoption candidate")
		}
	}

	// --- adopt ---
	rep, err := e.Import(ctx, core.AlwaysYesImport)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !rep.Adopted || !rep.Verified() {
		t.Fatalf("import should adopt + verify, got adopted=%v verify=%+v", rep.Adopted, rep.Verify)
	}

	// The Authelia route must survive byte-for-byte unmanaged (untouched).
	caddyLive, _ := caddyEdge.Provider.ReadLiveState(ctx)
	assertRoute(t, caddyLive, "auth.example.com", false /*managed*/, "10.0.0.9:9091")
	assertRoute(t, caddyLive, "grafana.example.com", true /*managed now*/, "10.0.0.5:3000")
	if !caddyLive.DenyCatchAllPresent {
		t.Fatal("deny must remain present after adopt")
	}

	// nginx: the adopted block keeps its verbatim body + is now managed.
	nginxLive, _ := nginxEdge.Provider.ReadLiveState(ctx)
	assertRoute(t, nginxLive, "status.example.com", true, "10.0.0.10:8080")

	// --- idempotent: a second scan finds nothing to adopt. ---
	plan2, err := e.DetectImport(ctx)
	if err != nil {
		t.Fatalf("DetectImport #2: %v", err)
	}
	if !plan2.Empty() {
		t.Fatalf("second import should be a no-op, got %+v", plan2.Adopt)
	}

	// --- the closed lifecycle gap: grafana now unexposes CLEANLY (before adoption
	// the delete-by-@id would have no-op'd and read-back would FAIL). ---
	ur, err := e.Apply(ctx, e.BuildOp(model.Unexpose, "grafana"), core.AlwaysYes)
	if err != nil {
		t.Fatalf("unexpose after adopt should succeed, got %v (%+v)", err, ur.Verify)
	}
	after, _ := caddyEdge.Provider.ReadLiveState(ctx)
	if after.HasHost("grafana.example.com") {
		t.Fatal("grafana should be gone after unexpose of an adopted route")
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertRoute(t *testing.T, live model.LiveEdgeState, host string, managed bool, addr string) {
	t.Helper()
	for _, r := range live.Routes {
		if r.Host == host {
			if r.Managed != managed {
				t.Fatalf("%s: want managed=%v, got %v", host, managed, r.Managed)
			}
			if addr != "" && r.Upstream.Address != addr {
				t.Fatalf("%s: want addr %s, got %s (behavior must be unchanged)", host, addr, r.Upstream.Address)
			}
			return
		}
	}
	t.Fatalf("route %s not found in live state", host)
}
