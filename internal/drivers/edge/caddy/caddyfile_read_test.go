package caddy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// writeCaddyfile drops content into a temp file and returns its path.
func writeCaddyfile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readState(t *testing.T, content string) model.LiveEdgeState {
	t.Helper()
	fr := NewFileReader(writeCaddyfile(t, content))
	st, err := fr.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func routeByHost(st model.LiveEdgeState, host string) (model.Route, bool) {
	for _, r := range st.Routes {
		if strings.EqualFold(r.Host, host) {
			return r, true
		}
	}
	return model.Route{}, false
}

// TestCaddyfileRead_WildcardFixture reads the checked-in real-shape wildcard
// fixture (per-host handles inside a wildcard site, a forward_auth snippet
// imported by one host, canonical `:80 { respond 403 }` deny) and asserts the
// M-A2 read contract: every handle host enumerated, auth recovered through the
// snippet import, fully parsed, deny ENFORCED.
func TestCaddyfileRead_WildcardFixture(t *testing.T) {
	fr := NewFileReader(filepath.Join("..", "..", "..", "..", "examples", "seed-audit-wildcard.caddyfile"))
	if err := fr.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := fr.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 2 {
		t.Fatalf("want 2 routes, got %+v", st.Routes)
	}
	g, ok := routeByHost(st, "grafana.homelab.example")
	if !ok || g.Upstream.Address != "10.0.0.5:3000" {
		t.Fatalf("grafana route missing/wrong: %+v", st.Routes)
	}
	if g.Upstream.Auth != model.AuthDetected {
		t.Errorf("forward_auth via imported snippet must read back as auth %q, got %q", model.AuthDetected, g.Upstream.Auth)
	}
	p, ok := routeByHost(st, "photos.homelab.example")
	if !ok || p.Upstream.Auth != "" {
		t.Errorf("photos must be unprotected (no auth), got %+v", p)
	}
	if !st.FullyParsed() {
		t.Errorf("fixture is fully modelable; unparsed: %+v", st.Unparsed)
	}
	if st.DenyState() != model.DenyEnforced {
		t.Errorf("fully-parsed file with a :80 respond-403 catch-all must read deny ENFORCED, got %s", st.DenyState())
	}
	if st.Persistence != model.PersistDurableConfig {
		t.Errorf("a Caddyfile IS the boot config — persistence must be durable-config, got %s", st.Persistence)
	}
}

// TestCaddyfileRead_UnmodeledFixture asserts the detect-and-declare-unknown
// contract on the checked-in fixture: the php_fastcgi site is DECLARED unparsed
// (never dropped) and the deny ternary downgrades to UNKNOWN — ENFORCED requires
// FullyParsed, exactly as on the admin path (register §4.4).
func TestCaddyfileRead_UnmodeledFixture(t *testing.T) {
	fr := NewFileReader(filepath.Join("..", "..", "..", "..", "examples", "seed-audit-unmodeled.caddyfile"))
	st, err := fr.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routeByHost(st, "grafana.example.com"); !ok {
		t.Fatalf("modeled site must still be read: %+v", st.Routes)
	}
	if len(st.Unparsed) == 0 {
		t.Fatal("php_fastcgi must be DECLARED unparsed, got none")
	}
	found := false
	for _, u := range st.Unparsed {
		if strings.Contains(u.Reason, "php_fastcgi") && u.Kind == model.UnknownHandler {
			found = true
		}
	}
	if !found {
		t.Errorf("unparsed entry must name the unmodeled directive: %+v", st.Unparsed)
	}
	if st.DenyState() != model.DenyUnknown {
		t.Errorf("deny must downgrade to UNKNOWN with an unmodeled directive present, got %s", st.DenyState())
	}
}

// TestCaddyfileRead_PermissiveCatchAllIsFailOpen: a host-less site that FORWARDS
// is the fail-open shape — deny must read MISSING, mirroring the admin driver's
// permissive host-less catch-all model.
func TestCaddyfileRead_PermissiveCatchAllIsFailOpen(t *testing.T) {
	st := readState(t, ":443 {\n\treverse_proxy 10.0.0.9:80\n}\n")
	if st.DenyCatchAllPresent {
		t.Fatal("a forwarding host-less catch-all must read fail-open (deny NOT present)")
	}
	if st.DenyState() != model.DenyMissing {
		t.Errorf("want DenyMissing, got %s", st.DenyState())
	}
}

// TestCaddyfileRead_ImplicitDenyHolds: a plain host site with NO explicit
// catch-all still reads deny present — Caddy's implicit 404 for unmatched hosts
// is the structural deny (same model as the admin path).
func TestCaddyfileRead_ImplicitDenyHolds(t *testing.T) {
	st := readState(t, "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n")
	if st.DenyState() != model.DenyEnforced {
		t.Errorf("fully-parsed host-only file must read deny ENFORCED (implicit 404), got %s", st.DenyState())
	}
}

// TestCaddyfileRead_UnresolvableImportDeclared: an `import` of a name not defined
// as a snippet in THIS file has an unknowable routing/auth effect — it must be
// DECLARED, never best-fit as auth (risk A.5 applied at directive granularity).
func TestCaddyfileRead_UnresolvableImportDeclared(t *testing.T) {
	st := readState(t, "app.example.com {\n\timport somewhere-else\n\treverse_proxy 10.0.0.5:3000\n}\n")
	if len(st.Unparsed) != 1 || !strings.Contains(st.Unparsed[0].Reason, "somewhere-else") {
		t.Fatalf("unresolvable import must be declared unknown: %+v", st.Unparsed)
	}
	if r, ok := routeByHost(st, "app.example.com"); !ok || r.Upstream.Auth != "" {
		t.Errorf("the import must NOT be guessed as an auth policy: %+v", st.Routes)
	}
	if st.DenyState() != model.DenyUnknown {
		t.Errorf("declared unknown must downgrade deny to UNKNOWN, got %s", st.DenyState())
	}
}

// TestCaddyfileRead_CrenelHandleReadsManaged: crenel's own on-disk marker
// (@crenel_<host> handle, the durable persist form) round-trips as Managed/
// OwnCrenel; an operator handle stays unmanaged.
func TestCaddyfileRead_CrenelHandleReadsManaged(t *testing.T) {
	st := readState(t, "*.home.example {\n"+
		"\t@crenel_app_home_example host app.home.example\n"+
		"\thandle @crenel_app_home_example {\n\t\treverse_proxy 10.0.0.7:8080\n\t}\n"+
		"\t@ops host ops.home.example\n"+
		"\thandle @ops {\n\t\treverse_proxy 10.0.0.8:9090\n\t}\n"+
		"}\n")
	app, ok := routeByHost(st, "app.home.example")
	if !ok || !app.Managed || app.Ownership != model.OwnCrenel {
		t.Errorf("@crenel_ handle must read managed/OwnCrenel: %+v", app)
	}
	ops, ok := routeByHost(st, "ops.home.example")
	if !ok || ops.Managed || ops.Ownership != model.OwnUnmanaged {
		t.Errorf("operator handle must read unmanaged: %+v", ops)
	}
}

// TestCaddyfileRead_MatcherScopedProxyDeclared: a reverse_proxy gated by a path
// matcher is path-granular routing the host model cannot represent — declared
// matcher_conditional, mirroring the admin driver.
func TestCaddyfileRead_MatcherScopedProxyDeclared(t *testing.T) {
	st := readState(t, "app.example.com {\n\treverse_proxy /api/* 10.0.0.5:3000\n}\n")
	if len(st.Unparsed) == 0 || st.Unparsed[0].Kind != model.UnknownMatcher {
		t.Fatalf("matcher-scoped proxy must be declared %s: %+v", model.UnknownMatcher, st.Unparsed)
	}
	if len(st.Routes) != 0 {
		t.Errorf("a path-scoped proxy must not be flattened into a whole-host route: %+v", st.Routes)
	}
}

// TestCaddyfileRead_ReadOnlyByConstruction: Plan and Apply refuse — a Caddyfile
// is a read source, never a write target (no validate/reload channel to verify).
func TestCaddyfileRead_ReadOnlyByConstruction(t *testing.T) {
	fr := NewFileReader(writeCaddyfile(t, "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n"))
	if _, err := fr.Plan(model.Op{Verb: model.Expose, Host: "x.example.com", Service: "x"}, model.LiveEdgeState{}); err == nil ||
		!strings.Contains(err.Error(), "READ-ONLY") {
		t.Errorf("Plan must refuse loudly, got %v", err)
	}
	if err := fr.Apply(context.Background(), model.ChangeSet{}); err == nil || !strings.Contains(err.Error(), "READ-ONLY") {
		t.Errorf("Apply must refuse loudly, got %v", err)
	}
}

// TestCaddyfileRead_Evidence: the adapter declares CONFIG evidence with the file's
// mtime (the A.2 staleness hint input) and the path as Source.
func TestCaddyfileRead_Evidence(t *testing.T) {
	p := writeCaddyfile(t, "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n")
	ev := NewFileReader(p).ReadEvidence()
	if ev.Kind != model.EvidenceConfig || ev.Source != p || ev.ModTime.IsZero() {
		t.Errorf("want CONFIG evidence with source+mtime, got %+v", ev)
	}
}

// TestSniffCaddyfile_PositiveSignatureOnly is the A.5 table: only a genuine
// Caddyfile matches; nginx brace DSL, Traefik YAML, JSON configs, and prose all
// FAIL the sniff (they must be refused upstream, never best-fit parsed).
func TestSniffCaddyfile_PositiveSignatureOnly(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"caddyfile host site", "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n", true},
		{"caddyfile port site", ":443 {\n\trespond 403\n}\n", true},
		{"caddyfile wildcard + global block", "{\n\temail a@b.c\n}\n*.home.example {\n\treverse_proxy 10.0.0.5:3000\n}\n", true},
		{"nginx brace DSL", "server {\n\tlisten 443 ssl;\n\tserver_name app.example.com;\n\tlocation / { proxy_pass http://10.0.0.5:3000; }\n}\n", false},
		{"traefik yaml", "http:\n  routers:\n    app:\n      rule: Host(`app.example.com`)\n", false},
		{"caddy JSON config", `{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}`, false},
		{"prose", "this is not a proxy config at all\n", false},
		{"unbalanced braces", "app.example.com {\n\treverse_proxy 10.0.0.5:3000\n", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := SniffCaddyfile([]byte(tc.content)); got != tc.want {
			t.Errorf("%s: SniffCaddyfile = %v, want %v", tc.name, got, tc.want)
		}
	}
}
