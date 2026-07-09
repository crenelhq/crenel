package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// seedTargetFake starts a caddyfake seeded with one exposed host plus the
// canonical hostless deny — the clean zero-config demo shape.
func seedTargetFake(t *testing.T) *caddyfake.Fake {
	t.Helper()
	f := caddyfake.New()
	t.Cleanup(f.Close)
	f.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	return f
}

func writeTargetFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSniffTarget_Table is the A.5 sniffer table: a target is wired ONLY on a
// positive signature; everything ambiguous/unrecognized errors (refused loudly
// upstream with exit 2, never guessed).
func TestSniffTarget_Table(t *testing.T) {
	fake := seedTargetFake(t)
	notCaddy := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notCaddy.Close)
	htmlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html>hi</html>"))
	}))
	t.Cleanup(htmlSrv.Close)

	caddyfilePath := writeTargetFile(t, "Caddyfile", "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n")
	nginxPath := writeTargetFile(t, "nginx.conf", "server {\n\tlisten 443 ssl;\n\tserver_name app.example.com;\n}\n")
	yamlPath := writeTargetFile(t, "dynamic.yml", "http:\n  routers:\n    app:\n      rule: Host(`app.example.com`)\n")
	jsonPath := writeTargetFile(t, "config.json", `{"apps":{"http":{"servers":{}}}}`)

	cases := []struct {
		name     string
		arg      string
		wantKind string // "" => must be refused
	}{
		{"caddy admin URL", fake.URL(), targetCaddyAdmin},
		{"non-caddy URL (404 on /config/)", notCaddy.URL, ""},
		{"non-caddy URL (HTML body)", htmlSrv.URL, ""},
		{"caddyfile path", caddyfilePath, targetCaddyfile},
		{"nginx conf", nginxPath, ""},
		{"traefik yaml", yamlPath, ""},
		{"caddy JSON config file", jsonPath, ""},
		{"missing path", filepath.Join(t.TempDir(), "nope"), ""},
		{"directory", t.TempDir(), ""},
	}
	for _, tc := range cases {
		st, err := sniffTarget(tc.arg)
		if tc.wantKind == "" {
			if err == nil {
				t.Errorf("%s: must be REFUSED, got kind %q", tc.name, st.kind)
			}
			continue
		}
		if err != nil || st.kind != tc.wantKind {
			t.Errorf("%s: want kind %q, got %q err %v", tc.name, tc.wantKind, st.kind, err)
		}
	}
}

// TestAuditTarget_AdminURL_EndToEnd drives the whole zero-config flow against the
// caddyfake: sniff → synthesized read-only engine → ordinary audit, RUNTIME
// evidence in the Scope block, exit 0 on the deny-clean edge.
func TestAuditTarget_AdminURL_EndToEnd(t *testing.T) {
	fake := seedTargetFake(t)
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fake.URL(), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"READ-ONLY EXPOSURE AUDIT (zero-config target)",
		"Target: caddy admin API @ " + fake.URL(),
		"evidence: RUNTIME",
		"Scope: zero-config target — one edge, no settings topology",
		"Scope: no DNS providers configured",
		"Scope: edge[caddy] evidence: runtime",
		"default-deny holds",
		"1 host(s) exposed",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	// A CONFIG-only caveat must NOT appear on a RUNTIME target.
	if strings.Contains(s, "evidence is CONFIG") {
		t.Errorf("RUNTIME target must not carry the config_evidence_only finding:\n%s", s)
	}
}

// TestAuditTarget_OnlyPastedTargetContacted is risk A.6 made executable: every
// request the whole flow (sniff + audit) makes goes to the pasted URL, and every
// one of them is GET /config/ — the documented, only probe.
func TestAuditTarget_OnlyPastedTargetContacted(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}`))
	}))
	t.Cleanup(srv.Close)

	var out, errOut bytes.Buffer
	if code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, srv.URL, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, req := range seen {
		if req != "GET /config/" {
			t.Errorf("unexpected request %q — only GET /config/ to the pasted target is permitted (risk A.6)", req)
		}
	}
}

// TestAuditTarget_CaddyfileFixture audits the checked-in unmodeled-directive
// fixture end-to-end: CONFIG evidence + the config_evidence_only caveat with the
// mtime staleness hint, the declared unknown driving coverage_incomplete, and the
// deny ternary at UNKNOWN — never an empty-but-green report on a partial parse.
func TestAuditTarget_CaddyfileFixture(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, filepath.Join("..", "..", "examples", "seed-audit-unmodeled.caddyfile"), &out, &errOut)
	if code != 0 { // warnings do not flip the exit code; only criticals do (cmdAudit parity)
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"Target: Caddyfile",
		"evidence: CONFIG",
		"Scope: edge[caddy] evidence: config",
		"evidence is CONFIG",   // the standing config_evidence_only finding
		"config last modified", // the A.2 staleness hint
		"NOT UNDERSTOOD",       // coverage_incomplete over the php_fastcgi site
		"CANNOT be certified",  // deny_catchall_unknown
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

// TestAuditTarget_AmbiguousRefusalExit2 wires the refusal through run(): an
// unrecognized file target exits 2 (distinct from audit findings' exit 1), with
// nothing audited.
func TestAuditTarget_AmbiguousRefusalExit2(t *testing.T) {
	nginxPath := writeTargetFile(t, "nginx.conf", "server {\n\tlisten 443 ssl;\n}\n")
	if code := run([]string{"audit", nginxPath, "--assume-public-boundary"}); code != 2 {
		t.Errorf("ambiguous target must exit 2 (loud refusal, nothing audited), got %d", code)
	}
}

// TestAuditTarget_WildcardFixtureWarnsUnprotectedPublic: the wildcard fixture's
// unprotected host fires public_without_auth (no DNS → the edge is the public
// boundary), while the forward_auth-protected host does not.
func TestAuditTarget_WildcardFixtureWarnsUnprotectedPublic(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, filepath.Join("..", "..", "examples", "seed-audit-wildcard.caddyfile"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "photos.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("unprotected host must fire public_without_auth:\n%s", s)
	}
	if strings.Contains(s, "grafana.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("forward_auth-protected host must NOT fire public_without_auth:\n%s", s)
	}
	if !strings.Contains(s, "default-deny holds") {
		t.Errorf("fully-parsed fixture must certify the deny:\n%s", s)
	}
}

// TestSniffTarget_NPMTreeDirectory extends the A.5 sniffer table to directories
// (M-A3): only the NPM layout signature (proxy_host/*.conf) matches; a directory
// of generic nginx confs — or an empty one — stays a loud refusal.
func TestSniffTarget_NPMTreeDirectory(t *testing.T) {
	npmDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(npmDir, "proxy_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(npmDir, "proxy_host", "1.conf"), []byte("server {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := sniffTarget(npmDir)
	if err != nil || st.kind != targetNPMTree {
		t.Errorf("NPM-shaped dir: want kind %q, got %q err %v", targetNPMTree, st.kind, err)
	}

	genericDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(genericDir, "site.conf"), []byte("server {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, err := sniffTarget(genericDir); err == nil {
		t.Errorf("generic conf dir must be REFUSED (no positive signature), got kind %q", st.kind)
	}
}

// TestAuditTarget_NPMTreeFixture audits the checked-in NPM tree end-to-end:
// CONFIG evidence naming the substrate read (risk A.1) with the mtime staleness
// hint (A.2), foreign_managed_readonly at ok severity (design §9 decision 2 —
// exit stays 0 for the edge being an NPM edge), the access-list host NOT firing
// public_without_auth, the custom-location host driving coverage_incomplete, and
// the deny ternary at UNKNOWN.
func TestAuditTarget_NPMTreeFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "drivers", "edge", "nginx", "testdata", "npm-tree")
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fixture, &out, &errOut)
	if code != 0 { // warnings do not flip the exit code; only criticals do
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"Target: NPM tree",
		"evidence: CONFIG",
		"Scope: edge[nginx] evidence: config",
		"4 config file(s) under",                 // the substrate read, named (A.1)
		"config last modified",                   // the A.2 staleness hint
		"generated/owned by nginx-proxy-manager", // foreign_managed_readonly (ok)
		"audited read-only",
		"NOT UNDERSTOOD",                                     // coverage_incomplete over the custom-location host
		"CANNOT be certified",                                // deny_catchall_unknown (declared unknowns present)
		"app.homelab.example is PUBLIC with no forward-auth", // the plain host
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	// The access-list (basic-auth) host must NOT read as unprotected-public.
	if strings.Contains(s, "grafana.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("access-list host must carry AuthDetected, not public_without_auth:\n%s", s)
	}
	// Read-only posture: the foreign edge prints at OK severity, not WARNING.
	if strings.Contains(s, "[WARNING] edge is generated/owned") {
		t.Errorf("foreign_managed_readonly must be ok-severity in target mode:\n%s", s)
	}
}
