package main

// target_ma56_test.go covers the final audit-any-edge slices:
//
// M-A5 — the caddy-docker-proxy DIRECTORY target: the Caddyfile.autosave layout
// signature (positive, never best-fit — a dir carrying BOTH the NPM and cdp
// signatures is refused as genuinely ambiguous), the fixture audit (foreign cdp
// edge-wide + CONFIG evidence + config_evidence_only), and the admin-URL honesty
// line ("generator detection unavailable" — the admin API carries no CDP marker,
// §4.1: declared, never implied hand-written).
//
// M-A6 — the forced boundary declaration (--assume-public-boundary / --internal,
// §9 decision 5: the --auth none pattern) and the opt-in --probe RUNTIME upgrade
// (risk A.6 made executable: probe OFF opens zero sockets beyond the pasted
// target; probe ON makes exactly the one documented GET /config/ to the
// config-DECLARED admin address).
//
// The cdp fixture (internal/drivers/edge/caddy/testdata/cdp-tree) was captured
// from a real lucaslorentz/caddy-docker-proxy container (CT120, 2026-07-09):
// three whoami containers labeled caddy=<host> / caddy.reverse_proxy={{upstreams 80}},
// one with caddy.forward_auth labels — checked in verbatim (born clean:
// homelab.example hosts, RFC1918 upstreams).

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

const cdpFixtureDir = "../../internal/drivers/edge/caddy/testdata/cdp-tree"

// --- M-A6: the forced boundary declaration ---

// TestAuditTarget_RefusesWithoutBoundaryFlag: with no DNS topology crenel cannot
// know whether the target edge is the public boundary — a zero-config audit
// REFUSES (exit 2, nothing audited, no socket opened) until the operator says
// the boundary out loud, naming BOTH flags.
func TestAuditTarget_RefusesWithoutBoundaryFlag(t *testing.T) {
	// A recording server proves the refusal happens BEFORE any probe of the target.
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)

	var out, errOut bytes.Buffer
	if code := runAuditTarget(&globalFlags{}, srv.URL, &out, &errOut); code != 2 {
		t.Fatalf("boundary-less zero-config audit must exit 2, got %d\nstderr: %s", code, errOut.String())
	}
	s := errOut.String()
	for _, want := range []string{"--assume-public-boundary", "--internal", "refuses to guess"} {
		if !strings.Contains(s, want) {
			t.Errorf("refusal must explain %q:\n%s", want, s)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("refusal must fire before any target probe, got %d request(s)", hits)
	}
}

// TestAuditTarget_RefusalThroughRun wires the refusal through run(): the exact
// UX a new user hits typing `crenel audit <url>` with no boundary flag.
func TestAuditTarget_RefusalThroughRun(t *testing.T) {
	fake := seedTargetFake(t)
	if code := run([]string{"audit", fake.URL()}); code != 2 {
		t.Errorf("run() without a boundary flag must exit 2, got %d", code)
	}
	if code := run([]string{"audit", fake.URL(), "--assume-public-boundary"}); code != 0 {
		t.Errorf("run() with --assume-public-boundary must exit 0 on the clean fake, got %d", code)
	}
}

// TestAuditTarget_BothBoundaryFlagsContradict: saying both boundaries is a
// contradiction, refused loudly (exit 2), never resolved by precedence.
func TestAuditTarget_BothBoundaryFlagsContradict(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{internalScope: true, assumePublicBoundary: true}, "http://127.0.0.1:1", &out, &errOut)
	if code != 2 {
		t.Fatalf("contradictory boundary flags must exit 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "contradict") {
		t.Errorf("contradiction must be named:\n%s", errOut.String())
	}
}

// TestAuditTarget_InternalDowngradesPublicWithoutAuth: --internal downgrades the
// assumption-derived public_without_auth to the ok-severity exposure_unscoped —
// the fact still prints (declared, not observed), the exit stays clean, and the
// Scope block declares the downgrade.
func TestAuditTarget_InternalDowngradesPublicWithoutAuth(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{internalScope: true},
		filepath.Join("..", "..", "examples", "seed-audit-wildcard.caddyfile"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	if strings.Contains(s, "PUBLIC with no forward-auth") {
		t.Errorf("--internal must downgrade public_without_auth:\n%s", s)
	}
	for _, want := range []string{
		"exposure is unscoped (declared, not observed)", // the ok-severity re-frame, never a silent drop
		"photos.homelab.example",                        // the would-have-warned host still named
		"Scope: edge DECLARED internal (--internal)",    // the scope declaration
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	// The downgraded finding must be ok severity (exit already proved no warning
	// flipped OK(), but assert the mark too).
	if !strings.Contains(s, "[OK] host photos.homelab.example carries no forward-auth policy") {
		t.Errorf("exposure_unscoped must print at ok severity:\n%s", s)
	}
}

// stubPublicDNS is a minimal public-scope DNS provider for the settings-topology
// contradiction test — never called beyond Name/Scope.
type stubPublicDNS struct{}

func (stubPublicDNS) Name() string       { return "cloudflare" }
func (stubPublicDNS) Scope() model.Scope { return model.ScopePublic }
func (stubPublicDNS) DesiredRecords(model.Op) ([]model.Record, error) {
	return nil, nil
}
func (stubPublicDNS) Diff(context.Context, model.Op, []model.Record) (model.DNSChange, error) {
	return model.DNSChange{}, nil
}
func (stubPublicDNS) Apply(context.Context, model.DNSChange) error { return nil }
func (stubPublicDNS) LiveRecords(context.Context) ([]model.Record, error) {
	return nil, nil
}

var _ ports.DNSProvider = stubPublicDNS{}

// TestCmdAudit_InternalContradictsPublicDNS: in a settings topology that MANAGES
// public DNS, the edge is internet-facing by construction — --internal is refused
// as a contradiction, never silently blunting public_without_auth (M-A6).
func TestCmdAudit_InternalContradictsPublicDNS(t *testing.T) {
	fake := seedFake(t)
	engine := core.New(caddy.New(fake.URL(), static.New(nil)), "example.com", stubPublicDNS{})
	out := &bytes.Buffer{}
	c := &cli{engine: engine, gf: &globalFlags{internalScope: true}, out: out, errOut: out}
	err := c.dispatch(context.Background(), "audit", nil)
	if err == nil || !strings.Contains(err.Error(), "contradicts") || !strings.Contains(err.Error(), "cloudflare") {
		t.Fatalf("--internal with public DNS must be refused as a contradiction naming the provider, got: %v", err)
	}
	if engine.DeclaredInternal {
		t.Error("refused --internal must not leak into the engine posture")
	}
}

// TestCmdAudit_InternalHonoredWithoutPublicDNS: a settings topology with NO
// public DNS provider may be declared internal — the downgrade applies exactly as
// in target mode.
func TestCmdAudit_InternalHonoredWithoutPublicDNS(t *testing.T) {
	fake := seedFake(t) // grafana exposed with no auth — would fire public_without_auth
	engine := core.New(caddy.New(fake.URL(), static.New(nil)), "example.com")
	out := &bytes.Buffer{}
	c := &cli{engine: engine, gf: &globalFlags{internalScope: true}, out: out, errOut: out}
	if err := c.dispatch(context.Background(), "audit", nil); err != nil {
		t.Fatalf("audit: %v\n%s", err, out.String())
	}
	s := out.String()
	if strings.Contains(s, "PUBLIC with no forward-auth") {
		t.Errorf("--internal must downgrade public_without_auth:\n%s", s)
	}
	if !strings.Contains(s, "exposure is unscoped (declared, not observed)") {
		t.Errorf("downgrade must still print the fact:\n%s", s)
	}
}

// --- M-A5: the cdp directory target ---

// TestSniffTarget_CDPDirectory extends the A.5 sniffer table to the cdp layout:
// Caddyfile.autosave is the positive signature; a dir carrying BOTH the NPM and
// cdp signatures is genuinely ambiguous and refused — precedence is never ranked.
func TestSniffTarget_CDPDirectory(t *testing.T) {
	st, err := sniffTarget(cdpFixtureDir)
	if err != nil || st.kind != targetCDPDir {
		t.Errorf("cdp fixture dir: want kind %q, got %q err %v", targetCDPDir, st.kind, err)
	}

	// Both signatures in one dir: refuse as ambiguous, naming both.
	both := t.TempDir()
	if err := os.MkdirAll(filepath.Join(both, "proxy_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(both, "proxy_host", "1.conf"), []byte("server {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(both, "Caddyfile.autosave"), []byte("a.example.com {\n\treverse_proxy 10.0.0.1:80\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = sniffTarget(both)
	if err == nil {
		t.Fatal("dir with BOTH the NPM and cdp signatures must be refused as ambiguous")
	}
	for _, want := range []string{"TWO directory signatures", "proxy_host", "Caddyfile.autosave"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ambiguity refusal must name %q, got: %v", want, err)
		}
	}
}

// TestAuditTarget_CDPTreeFixture audits the captured cdp autosave end-to-end:
// foreign(caddy-docker-proxy) edge-wide at ok severity (read-only posture),
// CONFIG evidence + the config_evidence_only caveat, the forward_auth-labeled
// host NOT firing public_without_auth while the plain hosts do, deny ENFORCED
// (CDP emits per-host sites, no permissive catch-all), exit 0.
func TestAuditTarget_CDPTreeFixture(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, cdpFixtureDir, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"Target: caddy-docker-proxy dir",
		"evidence: CONFIG",
		"Scope: edge[caddy] evidence: config",
		"evidence is CONFIG",                    // config_evidence_only
		"config last modified",                  // the A.2 staleness hint
		"generated/owned by caddy-docker-proxy", // foreign_managed_readonly
		"audited read-only",
		"3 host(s) exposed",
		"grafana.homelab.example is PUBLIC with no forward-auth",
		"photos.homelab.example is PUBLIC with no forward-auth",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "notes.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("forward_auth-labeled host must NOT fire public_without_auth:\n%s", s)
	}
	if strings.Contains(s, "[WARNING] edge is generated/owned") {
		t.Errorf("foreign_managed_readonly must be ok-severity in target mode:\n%s", s)
	}
}

// TestAuditTarget_AdminURL_GeneratorHonestyLine: an admin-URL-only target cannot
// detect caddy-docker-proxy (the admin API carries no CDP marker) — the scope
// header DECLARES that reduction instead of implying the edge is hand-written
// (§4.1, M-A5).
func TestAuditTarget_AdminURL_GeneratorHonestyLine(t *testing.T) {
	fake := seedTargetFake(t)
	var out, errOut bytes.Buffer
	if code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fake.URL(), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "generator detection unavailable over the Caddy admin API") {
		t.Errorf("admin-URL target must declare generator detection unavailable:\n%s", out.String())
	}
}

// --- M-A6: --probe ---

// TestAuditTarget_ProbeOff_NoSocketsBeyondTarget extends the A.6 recording tests
// to CONFIG targets: with --probe OFF, a Caddyfile audit whose config DECLARES an
// admin address opens ZERO sockets — not even to that declared address — and the
// report says what would have been probeable.
func TestAuditTarget_ProbeOff_NoSocketsBeyondTarget(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Write([]byte(`{"apps":{}}`))
	}))
	t.Cleanup(admin.Close)

	cf := writeTargetFile(t, "Caddyfile", fmt.Sprintf("{\n\tadmin %s\n}\napp.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n",
		strings.TrimPrefix(admin.URL, "http://")))
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, cf, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("probe OFF must open zero sockets beyond the pasted target, got %d request(s) to the declared admin address (risk A.6)", hits)
	}
	s := out.String()
	if !strings.Contains(s, "Probe: off — pass --probe") || !strings.Contains(s, "GET /config/") {
		t.Errorf("probe-off report must say what would have been probeable (and the exact request):\n%s", s)
	}
	if !strings.Contains(s, "evidence: CONFIG") {
		t.Errorf("evidence must remain CONFIG with probe off:\n%s", s)
	}
}

// TestAuditTarget_ProbeUpgradesCaddyfileToRuntime: --probe GETs /config/ at the
// config-DECLARED admin address; on the positive Caddy signature the audit reads
// the RUNNING process — evidence upgrades CONFIG → RUNTIME, declared in both the
// target header and the Scope block.
func TestAuditTarget_ProbeUpgradesCaddyfileToRuntime(t *testing.T) {
	fake := seedTargetFake(t)
	cf := writeTargetFile(t, "Caddyfile", fmt.Sprintf("{\n\tadmin %s\n}\napp.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n",
		strings.TrimPrefix(fake.URL(), "http://")))
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true, probe: true}, cf, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"evidence: RUNTIME (probed)",
		"evidence upgraded CONFIG → RUNTIME",
		"Scope: edge[caddy] evidence: runtime",
		"grafana.example.com", // the RUNNING process's route, not the file's
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "evidence is CONFIG") {
		t.Errorf("upgraded audit must not carry the config_evidence_only caveat:\n%s", s)
	}
}

// TestAuditTarget_ProbeFailureStaysConfig: --probe against an unreachable admin
// address fails LOUDLY into the report and the audit proceeds on CONFIG evidence
// — a failed probe never blocks the file audit and never fakes an upgrade.
func TestAuditTarget_ProbeFailureStaysConfig(t *testing.T) {
	cf := writeTargetFile(t, "Caddyfile", "{\n\tadmin 127.0.0.1:1\n}\napp.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n")
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true, probe: true}, cf, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "Probe: FAILED") || !strings.Contains(s, "evidence remains CONFIG") {
		t.Errorf("failed probe must be declared and evidence stay CONFIG:\n%s", s)
	}
	if !strings.Contains(s, "evidence: CONFIG") || strings.Contains(s, "RUNTIME (probed)") {
		t.Errorf("failed probe must not upgrade evidence:\n%s", s)
	}
}

// TestAuditTarget_ProbeNPMTreeDeclaresNoAPI: nginx has no admin API — --probe on
// an NPM tree declares that honestly instead of inventing a probe.
func TestAuditTarget_ProbeNPMTreeDeclaresNoAPI(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "drivers", "edge", "nginx", "testdata", "npm-tree")
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true, probe: true}, fixture, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "no runtime API exists for an NPM tree") {
		t.Errorf("--probe on an NPM tree must declare no API exists:\n%s", out.String())
	}
}

// TestAuditTarget_ProbeCDPKeepsGeneratorDetection: a probed cdp dir audits the
// RUNNING process but keeps its generator detection via the autosave-path hint
// (the admin API alone carries no CDP marker) — foreign never silently becomes
// unmanaged on the upgrade path.
func TestAuditTarget_ProbeCDPKeepsGeneratorDetection(t *testing.T) {
	fake := seedTargetFake(t)
	dir := t.TempDir()
	autosave := fmt.Sprintf("{\n\tadmin %s\n}\ngrafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n",
		strings.TrimPrefix(fake.URL(), "http://"))
	if err := os.WriteFile(filepath.Join(dir, "Caddyfile.autosave"), []byte(autosave), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true, probe: true}, dir, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"evidence upgraded CONFIG → RUNTIME",
		"generated/owned by caddy-docker-proxy", // detection survives the engine swap
		"Scope: edge[caddy] evidence: runtime",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}
