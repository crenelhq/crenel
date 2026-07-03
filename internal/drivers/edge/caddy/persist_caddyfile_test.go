package caddy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// This file is the durable WILDCARD-SITE reconciler's test. It is an INTERNAL test
// (package caddy) so the faithful fake adapter can reuse the same parse primitives a real
// `caddy adapt` exercises (findSiteBlock/parseHandles) — modelling, faithfully, that
// adapting the candidate Caddyfile reproduces the live managed routes.

// --- faithful fake adapter -------------------------------------------------

// caddyfileAdapter is a FAITHFUL fake of `caddy adapt` for the home-edge subset: it
// walks every site block's @host/handle pairs (operator AND crenel) into the admin-JSON
// per-host route shape the driver's normalize reads — reverse_proxy dial, an `import`
// rendered as the crenel auth marker (so auth reads ENFORCED), and the upstream-TLS
// transport. drop names a host to OMIT (a FAITHLESS variant, to prove the re-adaptation
// read-back refuses an on-disk config that would reload to a different state).
type caddyfileAdapter struct {
	server string
	drop   string
}

func (a caddyfileAdapter) Adapt(_ context.Context, configBytes []byte) ([]byte, error) {
	text := string(configBytes)
	var routes []any
	for _, addr := range siteAddresses(text) {
		ac := addr
		site, ok := findSiteBlock(text, func(s string) bool { return s == ac })
		if !ok {
			continue
		}
		for _, r := range parseHandles(text[site.bodyStart:site.bodyEnd]) {
			if a.drop != "" && strings.EqualFold(r.Host, a.drop) {
				continue
			}
			handle := []any{}
			if r.Upstream.Auth != "" { // an `import <policy>` => auth enforced
				handle = append(handle, map[string]any{"handler": "vars", "crenel_policy": r.Upstream.Auth})
			}
			rp := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": r.Upstream.Address}}}
			if r.Upstream.UpstreamTLS {
				rp["transport"] = map[string]any{"protocol": "http", "tls": map[string]any{"insecure_skip_verify": true}}
			}
			handle = append(handle, rp)
			routes = append(routes, map[string]any{
				"match":  []any{map[string]any{"host": []any{r.Host}}},
				"handle": handle,
			})
		}
	}
	routes = append(routes, map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}}})
	doc := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		a.server: map[string]any{"listen": []any{":443"}, "routes": routes}}}}}
	return json.Marshal(doc)
}

// --- fake validate/reload CLI ----------------------------------------------

type fakeReloadCLI struct {
	validated, reloaded int
	failValidate        bool
}

func (c *fakeReloadCLI) Validate(context.Context, string) error {
	c.validated++
	if c.failValidate {
		return errCLIValidate
	}
	return nil
}
func (c *fakeReloadCLI) Reload(context.Context, string) error { c.reloaded++; return nil }

var errCLIValidate = &cliErr{"simulated invalid Caddyfile"}

type cliErr struct{ s string }

func (e *cliErr) Error() string { return e.s }

// --- fixtures --------------------------------------------------------------

// operatorWildcardCaddyfile mirrors the real home edge: a global block, an (authelia)
// snippet, and a `*.homelab.example` wildcard site with a tls block + one operator handle
// (@git). crenel has no region yet.
const operatorWildcardCaddyfile = `{
	email a@b.com
}
(authelia) {
	forward_auth authelia:9080 {
		uri /api/verify?rd=https://auth.homelab.example
	}
}
*.homelab.example {
	tls {
		dns cloudflare {env.CF_TOKEN}
		resolvers 1.1.1.1
	}
	@git host git.homelab.example
	handle @git {
		reverse_proxy 10.0.0.13:3030
	}
}
`

// liveWithManaged seeds the fake admin with two crenel-MANAGED routes under the wildcard
// (files plain, home authelia-protected) plus the unmanaged operator git route + deny.
const liveWithManaged = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
 {"@id":"crenel-route-files.homelab.example","match":[{"host":["files.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"filebrowser:80"}]}]},
 {"@id":"crenel-route-home.homelab.example","match":[{"host":["home.homelab.example"]}],"handle":[{"handler":"vars","crenel_policy":"authelia"},{"handler":"reverse_proxy","upstreams":[{"dial":"homepage:3000"}]}]},
 {"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]},
 {"handle":[{"handler":"static_response","status_code":403}]}
]}}}}}`

func writeBoot(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func driverFor(t *testing.T, liveJSON, bootPath string, cli CaddyCLI, ad Adapter) *Driver {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	if err := fake.SeedJSON(liveJSON); err != nil {
		t.Fatal(err)
	}
	res := static.New(map[string]string{})
	return New(fake.URL(), res, WithGranularApply(), WithPersistPath(bootPath), WithCaddyCLI(cli), WithAdapter(ad))
}

// TestPersistInSite_ReconcilesIntoWildcard is the flagship: a crenel-managed expose is
// durably persisted as a per-host handle INSIDE the covering wildcard site (inheriting
// its TLS), the operator's own config is preserved byte-for-byte, NO shadowing top-level
// site is created, and the re-adaptation read-back proves a restart reproduces live.
func TestPersistInSite_ReconcilesIntoWildcard(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile)
	cli := &fakeReloadCLI{}
	d := driverFor(t, liveWithManaged, boot, cli, caddyfileAdapter{server: "srv0"})

	if err := d.Persist(context.Background()); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got, _ := os.ReadFile(boot)
	out := string(got)

	// Operator config preserved verbatim.
	for _, must := range []string{"email a@b.com", "(authelia) {", "dns cloudflare {env.CF_TOKEN}", "@git host git.homelab.example", "reverse_proxy 10.0.0.13:3030"} {
		if !strings.Contains(out, must) {
			t.Fatalf("operator content %q lost:\n%s", must, out)
		}
	}
	// Managed handles landed INSIDE the wildcard (region present, both hosts), home with auth.
	if !strings.Contains(out, "# crenel-managed-begin") {
		t.Fatalf("no crenel region:\n%s", out)
	}
	site, ok := findSiteBlock(out, func(a string) bool { return a == "*.homelab.example" })
	if !ok {
		t.Fatal("wildcard site vanished")
	}
	body := out[site.bodyStart:site.bodyEnd]
	if !strings.Contains(body, "# crenel-managed-begin") {
		t.Fatalf("crenel region must be INSIDE the wildcard site, not elsewhere:\n%s", out)
	}
	if !strings.Contains(body, "host files.homelab.example") || !strings.Contains(body, "reverse_proxy filebrowser:80") {
		t.Fatalf("files handle missing from wildcard region:\n%s", body)
	}
	if !strings.Contains(body, "host home.homelab.example") || !strings.Contains(body, "import authelia") {
		t.Fatalf("home handle (with import authelia) missing:\n%s", body)
	}
	// The shadowing hazard the flat persister would create MUST NOT appear: no top-level
	// `files.homelab.example {` site (which would bypass the wildcard's TLS).
	if strings.Contains(out, "\nfiles.homelab.example {") {
		t.Fatalf("must NOT create a shadowing top-level site:\n%s", out)
	}
	// Validated once, reloaded once (debounced).
	if cli.validated != 1 || cli.reloaded != 1 {
		t.Fatalf("want 1 validate + 1 reload, got %d/%d", cli.validated, cli.reloaded)
	}

	// Idempotent: a second persist replaces the region cleanly (exactly one region).
	if err := d.Persist(context.Background()); err != nil {
		t.Fatalf("re-persist: %v", err)
	}
	out2, _ := os.ReadFile(boot)
	if n := strings.Count(string(out2), "# crenel-managed-begin"); n != 1 {
		t.Fatalf("want exactly 1 region after re-persist, got %d:\n%s", n, out2)
	}
}

// TestPersistInSite_FaithlessAdaptRefusesAndRestores proves the re-adaptation read-back:
// if `caddy adapt` of the candidate does NOT reproduce a managed host (here the adapter
// drops files), persist REFUSES — the boot file is left UNTOUCHED and no reload fires.
// This is the no-second-SOT guarantee: crenel never commits a Caddyfile that would reload
// to a different state than is live.
func TestPersistInSite_FaithlessAdaptRefusesAndRestores(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile)
	cli := &fakeReloadCLI{}
	d := driverFor(t, liveWithManaged, boot, cli, caddyfileAdapter{server: "srv0", drop: "files.homelab.example"})

	err := d.Persist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "re-adaptation read-back") {
		t.Fatalf("expected a re-adaptation refusal, got: %v", err)
	}
	out, _ := os.ReadFile(boot)
	if string(out) != operatorWildcardCaddyfile {
		t.Fatalf("boot file must be UNTOUCHED on refusal, got:\n%s", out)
	}
	if cli.reloaded != 0 {
		t.Fatal("must NOT reload after a refused re-adaptation")
	}
}

// TestPersistInSite_UnexposeClearsRegion proves an unexpose (no managed routes left)
// CLEARS crenel's in-site region while preserving the operator's handles.
func TestPersistInSite_UnexposeClearsRegion(t *testing.T) {
	// Boot file that already has a crenel region (as if a prior expose persisted).
	withRegion := strings.Replace(operatorWildcardCaddyfile,
		"\t@git host git.homelab.example\n\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n",
		"\t@git host git.homelab.example\n\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n"+
			"\t"+persistBegin+"\n\t@crenel_files_homelab_example host files.homelab.example\n\thandle @crenel_files_homelab_example {\n\t\treverse_proxy filebrowser:80\n\t}\n\t"+persistEnd+"\n", 1)
	boot := writeBoot(t, withRegion)
	cli := &fakeReloadCLI{}
	// Live state has NO crenel-managed routes (only the unmanaged operator git + deny).
	liveNoManaged := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	d := driverFor(t, liveNoManaged, boot, cli, caddyfileAdapter{server: "srv0"})

	if err := d.Persist(context.Background()); err != nil {
		t.Fatalf("persist (unexpose): %v", err)
	}
	out, _ := os.ReadFile(boot)
	if strings.Contains(string(out), "# crenel-managed-begin") {
		t.Fatalf("region must be cleared on unexpose:\n%s", out)
	}
	if !strings.Contains(string(out), "@git host git.homelab.example") {
		t.Fatalf("operator git handle must be preserved:\n%s", out)
	}
}

// TestPersistInSite_MultiHostKeepsPriorRegionHost is the live-faithful reproduction of the
// rename-demo finding (TRIAL-FIX-DURABLE-2). The boot Caddyfile already holds a crenel
// region for `aaa` (a prior durable expose, now @id-LESS after its reload). A SECOND
// durable host `bbb` (freshly @id-tagged) is persisted. Before the fix, the persist mirror
// = @id-only = {bbb}, so it would drop `aaa` and the no-drift-loss gate REFUSES (the exact
// demo refusal). After the fix, the mirror = {aaa (region), bbb (@id)}, so BOTH survive.
func TestPersistInSite_MultiHostKeepsPriorRegionHost(t *testing.T) {
	bootWithA := strings.Replace(operatorWildcardCaddyfile,
		"\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n",
		"\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n"+
			"\t"+persistBegin+"\n\t@crenel_aaa_homelab_example host aaa.homelab.example\n\thandle @crenel_aaa_homelab_example {\n\t\treverse_proxy aaa-backend:1\n\t}\n\t"+persistEnd+"\n", 1)
	boot := writeBoot(t, bootWithA)
	cli := &fakeReloadCLI{}
	// Live: git (operator), aaa (region-derived, NO @id), bbb (freshly @id-tagged).
	live := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"match":[{"host":["*.homelab.example"]}],"terminal":true,"handle":[{"handler":"subroute","routes":[
	   {"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]}]}]},
	   {"match":[{"host":["aaa.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"aaa-backend:1"}]}]}]}]},
	   {"@id":"crenel-route-bbb.homelab.example","match":[{"host":["bbb.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"bbb-backend:2"}]}]}
	 ]}]},
	 {"handle":[{"handler":"static_response","abort":true}]}
	]}}}}}`
	d := driverFor(t, live, boot, cli, caddyfileAdapter{server: "srv0"})

	if err := d.Persist(context.Background()); err != nil {
		t.Fatalf("persist must keep the prior region host (no drift refusal): %v", err)
	}
	out, _ := os.ReadFile(boot)
	for _, must := range []string{"host aaa.homelab.example", "reverse_proxy aaa-backend:1", "host bbb.homelab.example", "reverse_proxy bbb-backend:2"} {
		if !strings.Contains(string(out), must) {
			t.Fatalf("region must hold BOTH durable hosts, missing %q:\n%s", must, out)
		}
	}
	if cli.reloaded != 1 {
		t.Fatalf("want exactly one reload, got %d", cli.reloaded)
	}
}

// TestPersistInSite_DriftLossRefused proves the no-drift-loss gate (safe-by-construction
// durability): a host that is LIVE but NOT reproduced by the boot Caddyfile (an admin-only
// route — drift) would be DROPPED by the durable reload, so persist REFUSES — even though
// the managed host the op is persisting adapts back fine. The boot file is left untouched.
func TestPersistInSite_DriftLossRefused(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile) // operator Caddyfile knows @git only
	cli := &fakeReloadCLI{}
	// Live admin: git (operator, in the Caddyfile), files (crenel-managed, @id), and
	// `drifted` (operator route present ONLY in the live admin — NOT in the Caddyfile).
	liveWithDrift := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"match":[{"host":["*.homelab.example"]}],"terminal":true,"handle":[{"handler":"subroute","routes":[
	   {"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]}]}]},
	   {"match":[{"host":["drifted.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:80"}]}]}]}]},
	   {"@id":"crenel-route-files.homelab.example","match":[{"host":["files.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"filebrowser:80"}]}]}
	 ]}]},
	 {"handle":[{"handler":"static_response","abort":true}]}
	]}}}}}`
	d := driverFor(t, liveWithDrift, boot, cli, caddyfileAdapter{server: "srv0"})

	err := d.Persist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "DRIFT") {
		t.Fatalf("expected an on-disk drift refusal, got: %v", err)
	}
	if !strings.Contains(err.Error(), "drifted.homelab.example") {
		t.Errorf("the refusal should name the dropped host, got: %v", err)
	}
	out, _ := os.ReadFile(boot)
	if string(out) != operatorWildcardCaddyfile {
		t.Fatalf("boot file must be UNTOUCHED on a drift refusal")
	}
	if cli.reloaded != 0 {
		t.Fatal("must NOT reload when drift would drop a live route")
	}
}

// TestPersistInSite_OperatorOwnedHostRefused proves the refuse-to-shadow gate: if the
// operator already handles a host inside the wildcard, crenel will NOT add a shadowed
// duplicate — it declares the conflict (adopt via import instead).
func TestPersistInSite_OperatorOwnedHostRefused(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile) // operator owns @git
	cli := &fakeReloadCLI{}
	// Live state: a crenel-managed route for git.homelab.example (the operator-owned host).
	liveGitManaged := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"@id":"crenel-route-git.homelab.example","match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	d := driverFor(t, liveGitManaged, boot, cli, caddyfileAdapter{server: "srv0"})

	err := d.Persist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "operator block") {
		t.Fatalf("expected an operator-owned-host refusal, got: %v", err)
	}
	if cli.reloaded != 0 {
		t.Fatal("must not reload on a refused conflict")
	}
}
