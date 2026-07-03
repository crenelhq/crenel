package core_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// ingressEngine builds a single-edge engine over a stub edge with the given binding
// ingress posture, so the tests exercise the core overlay (resolveIngressKind) +
// status/audit surfacing without any driver.
func ingressEngine(t *testing.T, kind model.IngressKind, configPath string) *core.Engine {
	t.Helper()
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("app.example.com")},
	}}
	return core.NewMulti([]core.EdgeBinding{{
		Name:              "home",
		Provider:          edge,
		IngressKind:       kind,
		IngressConfigPath: configPath,
	}}, "example.com")
}

// TestIngress_DeclaredTunnelSurfaces proves an operator-DECLARED tunnel ingress is
// surfaced: status carries IngressKind=tunnel and audit fires ingress_external — the
// host is PUBLIC via the tunnel even though the local proxy may bind localhost, so
// crenel must not read it as a plain internal listener.
func TestIngress_DeclaredTunnelSurfaces(t *testing.T) {
	e := ingressEngine(t, model.IngressTunnel, "")
	ctx := context.Background()

	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Edges[0].IngressKind != model.IngressTunnel {
		t.Errorf("status should carry the declared ingress kind, got %q", st.Edges[0].IngressKind)
	}

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "ingress_external"); !ok || f.Severity != "warning" {
		t.Errorf("a declared tunnel must fire ingress_external, got %+v", rep.Findings)
	}
}

// TestIngress_DetectsCloudflaredFromConfig proves file-based detection: pointed at a
// cloudflared config.yml, crenel detects a TUNNEL ingress and surfaces it.
func TestIngress_DetectsCloudflaredFromConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	cloudflared := "tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef\n" +
		"credentials-file: /etc/cloudflared/6ff42ae2.json\n" +
		"ingress:\n" +
		"  - hostname: app.example.com\n" +
		"    service: http://localhost:3000\n" +
		"  - service: http_status:404\n"
	if err := os.WriteFile(cfgPath, []byte(cloudflared), 0o644); err != nil {
		t.Fatal(err)
	}
	e := ingressEngine(t, "", cfgPath)
	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Edges[0].IngressKind != model.IngressTunnel {
		t.Fatalf("cloudflared config should detect a tunnel, got %q", st.Edges[0].IngressKind)
	}
}

// TestIngress_DetectsTailscaleServeFromConfig proves a Tailscale serve/funnel
// ServeConfig (serve.json with AllowFunnel) is detected as OVERLAY ingress.
func TestIngress_DetectsTailscaleServeFromConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "serve.json")
	serve := `{"TCP":{"443":{"HTTPS":true}},"Web":{"app.example.com:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},"AllowFunnel":{"app.example.com:443":true}}`
	if err := os.WriteFile(cfgPath, []byte(serve), 0o644); err != nil {
		t.Fatal(err)
	}
	e := ingressEngine(t, "", cfgPath)
	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Edges[0].IngressKind != model.IngressOverlay {
		t.Fatalf("tailscale serve config should detect an overlay, got %q", st.Edges[0].IngressKind)
	}
}

// TestIngress_UnrecognizedFileDeclaresUnknown proves the load-bearing safety rule:
// when an ingress config is PRESENT but crenel cannot classify the mechanism, it
// DECLARES UNKNOWN (externally fronted, mechanism undetermined) rather than assume
// the edge is internal — and the audit surfaces it as an external-ingress warning.
func TestIngress_UnrecognizedFileDeclaresUnknown(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "mystery-ingress.conf")
	if err := os.WriteFile(cfgPath, []byte("some: opaque\nproxy: front\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := ingressEngine(t, "", cfgPath)
	ctx := context.Background()

	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Edges[0].IngressKind != model.IngressUnknown {
		t.Fatalf("an unrecognized ingress file must DECLARE UNKNOWN, not assume internal; got %q", st.Edges[0].IngressKind)
	}
	if !st.Edges[0].IngressKind.External() {
		t.Errorf("IngressUnknown must count as External (off-edge reachability)")
	}

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "ingress_external")
	if !ok || !strings.Contains(f.Message, "could not classify") {
		t.Errorf("unknown ingress must surface as an external-ingress warning, got %+v", rep.Findings)
	}
}

// TestIngress_NoIngressIsClean proves the no-false-positive case: an edge with no
// ingress posture (a plain public listener) carries no IngressKind and fires no
// ingress_external finding — surfacing only fires for genuine off-edge ingress.
func TestIngress_NoIngressIsClean(t *testing.T) {
	e := ingressEngine(t, "", "")
	ctx := context.Background()

	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Edges[0].IngressKind.External() {
		t.Errorf("a plain edge must not be flagged external, got %q", st.Edges[0].IngressKind)
	}

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "ingress_external"); ok {
		t.Errorf("no ingress posture => no ingress_external finding, got %+v", rep.Findings)
	}
}

// TestIngress_MissingFileMakesNoClaim proves an absent/unreadable ingress path is a
// tolerated no-op (no claim) — a missing optional signal must neither error nor
// fabricate an external posture.
func TestIngress_MissingFileMakesNoClaim(t *testing.T) {
	e := ingressEngine(t, "", "/nonexistent/ingress.yml")
	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatalf("a missing ingress file must not error a read, got %v", err)
	}
	if st.Edges[0].IngressKind.External() {
		t.Errorf("an absent file must make no external claim, got %q", st.Edges[0].IngressKind)
	}
}
