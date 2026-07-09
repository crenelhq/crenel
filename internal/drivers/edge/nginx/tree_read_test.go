package nginx

// tree_read_test.go — M-A3 milestone tests, hermetic against the CHECKED-IN
// fixture tree (testdata/npm-tree), captured from a real jc21/nginx-proxy-manager
// container (design §9 decision 7): three proxy hosts — app (plain), grafana
// (access-list basic auth), chat (websockets + a custom /api location) — plus the
// "444" default_host. Tests that need a mutated tree copy it to a temp dir first;
// the fixture itself is never written.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

const npmFixture = "testdata/npm-tree"

func readTree(t *testing.T, root string) model.LiveEdgeState {
	t.Helper()
	st, err := NewTreeReader(root).ReadLiveState(context.Background())
	if err != nil {
		t.Fatalf("ReadLiveState(%s): %v", root, err)
	}
	return st
}

// copyTree clones the fixture into a temp dir so a test can mutate it.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func routeByHost(st model.LiveEdgeState, host string) (model.Route, bool) {
	for _, r := range st.Routes {
		if r.Host == host {
			return r, true
		}
	}
	return model.Route{}, false
}

func unparsedContaining(st model.LiveEdgeState, substr string) bool {
	for _, u := range st.Unparsed {
		if strings.Contains(u.Locator+" "+u.Reason, substr) {
			return true
		}
	}
	return false
}

// TestNPMTree_Fixture is the milestone's core assertion set over the real
// captured tree: generator detected edge-wide, every proxy_host enumerated (the
// plain and auth hosts as routes, the custom-location host DECLARED), the deny
// verdict decided against NPM's real "444" default_host, access-list auth
// surfacing as AuthDetected (never public_without_auth's trigger state).
func TestNPMTree_Fixture(t *testing.T) {
	st := readTree(t, npmFixture)

	// Generator: the whole tree is NPM's output — foreign edge-wide, every route
	// foreign per M-A1 ownership semantics.
	if st.Generator != "nginx-proxy-manager" {
		t.Fatalf("generator = %q, want nginx-proxy-manager", st.Generator)
	}
	for _, r := range st.Routes {
		if r.Ownership != model.OwnForeign || r.Managed {
			t.Errorf("route %s: ownership=%v managed=%v, want foreign/unmanaged", r.Host, r.Ownership, r.Managed)
		}
	}

	// Every proxy_host enumerated: 1.conf and 2.conf are routes; 3.conf (custom
	// location = path-granular) is DECLARED, never silently misread as host->first
	// backend, and never dropped.
	app, ok := routeByHost(st, "app.homelab.example")
	if !ok {
		t.Fatal("app.homelab.example not enumerated")
	}
	if app.Upstream.Address != "10.0.0.5:3000" {
		t.Errorf("app backend = %q, want 10.0.0.5:3000 (from NPM's set-variables + proxy.conf idiom)", app.Upstream.Address)
	}
	if app.Upstream.Auth != "" {
		t.Errorf("app auth = %q, want none", app.Upstream.Auth)
	}

	// Access-list host: NPM renders auth_basic + auth_basic_user_file — must read
	// as AuthDetected (recognized-but-unnamed), NOT as public-without-auth.
	grafana, ok := routeByHost(st, "grafana.homelab.example")
	if !ok {
		t.Fatal("grafana.homelab.example not enumerated")
	}
	if grafana.Upstream.Auth != model.AuthDetected {
		t.Errorf("grafana auth = %q, want %q (access list = basic auth at the edge)", grafana.Upstream.Auth, model.AuthDetected)
	}

	// Custom-location host: declared unknown (matcher_conditional path), and its
	// declaration must name both proxying paths so nothing was silently merged.
	if _, ok := routeByHost(st, "chat.homelab.example"); ok {
		t.Error("chat.homelab.example must NOT be a host-granular route (it routes by path)")
	}
	if !unparsedContaining(st, "chat.homelab.example") {
		t.Errorf("chat.homelab.example must be DECLARED unparsed, got %+v", st.Unparsed)
	}

	// Deny verdict, decided against NPM's real default server: the fixture's
	// default_host/site.conf is `listen 80 default;` + `return 444` — a
	// non-forwarding catch-all on the same port the proxy hosts forward on, so the
	// structural deny is PRESENT. The ternary is UNKNOWN (not ENFORCED): the
	// declared chat host means the config was not fully parsed, and ENFORCED ⟹
	// FullyParsed is the hard invariant.
	if !st.DenyCatchAllPresent {
		t.Error("DenyCatchAllPresent = false, want true (NPM 444 default_host denies port 80)")
	}
	if got := st.DenyState(); got != model.DenyUnknown {
		t.Errorf("DenyState = %v, want DenyUnknown (declared unknowns forbid ENFORCED)", got)
	}

	// The NPM stock template includes (conf.d/include/*) are positively recognized
	// — they must NOT flood Unparsed (else every NPM audit would read as
	// coverage-incomplete for fixed template plumbing).
	if unparsedContaining(st, "conf.d/include/") {
		t.Errorf("stock NPM template includes must be understood, got %+v", st.Unparsed)
	}
	// The in-root custom wildcard include matches nothing on a stock install —
	// understood-empty (nginx semantics), not declared.
	if unparsedContaining(st, "server_proxy") {
		t.Errorf("empty wildcard custom include must be understood, got %+v", st.Unparsed)
	}
}

// TestNPMTree_NoDefaultHost: with NPM's "Default Site" setting untouched there is
// NO default server in the tree — the real catch-all lives in the container's
// /etc/nginx/conf.d/default.conf, which a tree audit does not read. That absence
// must be DECLARED (deny UNKNOWN), never guessed ENFORCED and never read as
// fail-open (both are unproven).
func TestNPMTree_NoDefaultHost(t *testing.T) {
	dir := copyTree(t, npmFixture)
	if err := os.RemoveAll(filepath.Join(dir, "default_host")); err != nil {
		t.Fatal(err)
	}
	st := readTree(t, dir)
	if !unparsedContaining(st, "default server") {
		t.Fatalf("missing default server must be DECLARED, got %+v", st.Unparsed)
	}
	if got := st.DenyState(); got != model.DenyUnknown {
		t.Errorf("DenyState = %v, want DenyUnknown (catch-all outside the tree was not read)", got)
	}
}

// TestNPMTree_ForeignInclude: an include pointing OUTSIDE the tree root (e.g. an
// operator's advanced_config pulling from /etc/nginx) is DECLARED Unparsed —
// never silently skipped (the P0 rule) — and its presence downgrades deny.
func TestNPMTree_ForeignInclude(t *testing.T) {
	dir := copyTree(t, npmFixture)
	p := filepath.Join(dir, "proxy_host", "1.conf")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(b), "server {", "server {\n  include /etc/nginx/snippets/evil.conf;", 1)
	if err := os.WriteFile(p, []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}
	st := readTree(t, dir)
	if !unparsedContaining(st, "/etc/nginx/snippets/evil.conf") {
		t.Fatalf("foreign include must be DECLARED Unparsed, got %+v", st.Unparsed)
	}
	// The host still enumerates (the include did not eat the server block).
	if _, ok := routeByHost(st, "app.homelab.example"); !ok {
		t.Error("app.homelab.example must still be enumerated alongside the declared include")
	}
}

// TestNPMTree_InRootIncludeFollowed: an include that resolves INSIDE the tree
// root is FOLLOWED — here the custom snippet include every NPM proxy_host carries
// (`include /data/nginx/custom/server_proxy[.]conf;`) gains a real file whose
// auth_basic must then surface on the host. Following is observable, not assumed.
func TestNPMTree_InRootIncludeFollowed(t *testing.T) {
	dir := copyTree(t, npmFixture)
	if err := os.MkdirAll(filepath.Join(dir, "custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	snippet := "auth_basic \"custom snippet\";\nauth_basic_user_file /data/access/9;\n"
	if err := os.WriteFile(filepath.Join(dir, "custom", "server_proxy.conf"), []byte(snippet), 0o644); err != nil {
		t.Fatal(err)
	}
	st := readTree(t, dir)
	app, ok := routeByHost(st, "app.homelab.example")
	if !ok {
		t.Fatal("app.homelab.example not enumerated")
	}
	if app.Upstream.Auth != model.AuthDetected {
		t.Errorf("app auth = %q, want %q — the in-root include was not followed", app.Upstream.Auth, model.AuthDetected)
	}
}

// TestNPMTree_AdversarialDeleteConf is the milestone's RED test: deleting one
// .conf from a copy of the tree must VISIBLY change the audit's inputs — the
// host disappears from the route set AND the evidence substrate count shrinks.
// A reader that silently kept a cached/partial view would fail both assertions.
func TestNPMTree_AdversarialDeleteConf(t *testing.T) {
	dir := copyTree(t, npmFixture)
	full := readTree(t, dir)
	evFull := NewTreeReader(dir).ReadEvidence()
	if _, ok := routeByHost(full, "grafana.homelab.example"); !ok {
		t.Fatal("precondition: grafana.homelab.example enumerated in the full tree")
	}

	if err := os.Remove(filepath.Join(dir, "proxy_host", "2.conf")); err != nil {
		t.Fatal(err)
	}
	shrunk := readTree(t, dir)
	evShrunk := NewTreeReader(dir).ReadEvidence()

	if _, ok := routeByHost(shrunk, "grafana.homelab.example"); ok {
		t.Error("deleted proxy_host still enumerated — stale read")
	}
	if len(shrunk.Routes) >= len(full.Routes) {
		t.Errorf("route count did not shrink: %d -> %d", len(full.Routes), len(shrunk.Routes))
	}
	if evFull.Source == evShrunk.Source {
		t.Errorf("evidence substrate must name the (changed) file count: %q == %q — the shrink is invisible in the report", evFull.Source, evShrunk.Source)
	}
	if !strings.Contains(evFull.Source, "4 config file(s)") || !strings.Contains(evShrunk.Source, "3 config file(s)") {
		t.Errorf("evidence sources = %q / %q, want explicit 4-vs-3 file counts", evFull.Source, evShrunk.Source)
	}
}

// TestNPMTree_ReadOnlyAndEvidence: the reader is structurally read-only (Plan and
// Apply refuse — belt; the target engine adds the type braces) and reports CONFIG
// evidence with a non-zero newest mtime for the A.2 staleness hint.
func TestNPMTree_ReadOnlyAndEvidence(t *testing.T) {
	r := NewTreeReader(npmFixture)
	if _, err := r.Plan(model.Op{Verb: model.Expose, Host: "x.homelab.example", Mode: model.ModeHTTPProxy}, model.LiveEdgeState{}); err == nil {
		t.Error("Plan must refuse on the NPM tree reader")
	}
	if err := r.Apply(context.Background(), model.ChangeSet{}); err == nil {
		t.Error("Apply must refuse on the NPM tree reader")
	}
	ev := r.ReadEvidence()
	if ev.Kind != model.EvidenceConfig {
		t.Errorf("evidence kind = %q, want config", ev.Kind)
	}
	if ev.ModTime.IsZero() {
		t.Error("evidence ModTime must carry the newest file mtime (staleness hint)")
	}
	if !strings.Contains(ev.Source, npmFixture) {
		t.Errorf("evidence source must name the substrate root, got %q", ev.Source)
	}
	if err := r.Validate(context.Background()); err != nil {
		t.Errorf("Validate on the fixture: %v", err)
	}
	if SniffNPMTree(t.TempDir()) {
		t.Error("SniffNPMTree must NOT match an empty directory (positive signature only)")
	}
}
