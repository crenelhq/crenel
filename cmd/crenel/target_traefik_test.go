package main

// target_traefik_test.go extends the zero-config target tests for M-A4: the
// Traefik API sniff (positive signature, Caddy-vs-Traefik never decided by
// elimination), the end-to-end audit against traefikapifake serving the real
// captured payloads, and the A.6 network contract over the two-probe sniff.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/traefik/traefikapifake"
)

func startTraefikFake(t *testing.T, capture string) *traefikapifake.Fake {
	t.Helper()
	f, err := traefikapifake.NewFromDir(filepath.Join("..", "..", "internal", "drivers", "edge", "traefik", "testdata", capture))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

// TestSniffTarget_TraefikAPI extends the A.5 sniffer table: the Traefik API
// matches on its positive /api/version signature; a generic app answering JSON
// at /api/version (no Version/Codename shape) stays a loud refusal — neither
// Caddy nor Traefik is ever inferred by elimination.
func TestSniffTarget_TraefikAPI(t *testing.T) {
	traefikFake := startTraefikFake(t, "api-docker")
	caddyFake := seedTargetFake(t)

	// A JSON API that is NOT Traefik: 200 on /api/version but the wrong shape.
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":"2.0","service":"someapp"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(impostor.Close)

	cases := []struct {
		name     string
		arg      string
		wantKind string // "" => must be refused
	}{
		{"traefik API URL", traefikFake.URL(), targetTraefikAPI},
		{"caddy admin URL still sniffs caddy", caddyFake.URL(), targetCaddyAdmin},
		{"JSON impostor at /api/version", impostor.URL, ""},
	}
	for _, tc := range cases {
		st, err := sniffTarget(tc.arg)
		if tc.wantKind == "" {
			if err == nil {
				t.Errorf("%s: must be REFUSED, got kind %q", tc.name, st.kind)
			} else if !strings.Contains(err.Error(), "/config/") || !strings.Contains(err.Error(), "/api/version") {
				t.Errorf("%s: refusal must enumerate BOTH probes tried, got: %v", tc.name, err)
			}
			continue
		}
		if err != nil || st.kind != tc.wantKind {
			t.Errorf("%s: want kind %q, got %q err %v", tc.name, tc.wantKind, st.kind, err)
		}
	}
}

// TestAuditTarget_TraefikAPI_Pangolin drives the whole zero-config flow against
// the captured Pangolin payload: RUNTIME evidence, foreign_managed_readonly at
// ok severity (a Pangolin edge being a Pangolin edge must not page), badger ⇒
// AuthDetected keeping the resource hosts out of public_without_auth, the
// overlay-ingress auto-declaration surfacing as ingress_external, the
// conditional dashboard routers driving coverage_incomplete + deny UNKNOWN, and
// exit 0 (warnings only — same contract as every zero-config audit).
func TestAuditTarget_TraefikAPI_Pangolin(t *testing.T) {
	fake := startTraefikFake(t, "api-pangolin")
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fake.URL(), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"READ-ONLY EXPOSURE AUDIT (zero-config target)",
		"Target: traefik API @ " + fake.URL(),
		"evidence: RUNTIME",
		"Scope: edge[traefik] evidence: runtime",
		"generated/owned by pangolin", // foreign_managed_readonly (ok severity)
		"audited read-only",
		"reachability for this edge's hosts is determined by overlay", // §4.3 auto-declaration
		"NOT UNDERSTOOD",                                              // coverage_incomplete over the conditional routers
		"CANNOT be certified",                                         // deny_catchall_unknown
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	// badger-guarded resources must NOT read unprotected-public.
	for _, host := range []string{"vault.homelab.example", "notes.homelab.example"} {
		if strings.Contains(s, host+" is PUBLIC with no forward-auth") {
			t.Errorf("badger-guarded host %s must not fire public_without_auth:\n%s", host, s)
		}
	}
	// Read-only posture: the foreign edge prints at OK severity, not WARNING (A.7).
	if strings.Contains(s, "[WARNING] edge is generated/owned") {
		t.Errorf("foreign_managed_readonly must be ok-severity in target mode:\n%s", s)
	}
	// RUNTIME read: the A.1 "audit the API instead" pointer must NOT fire here —
	// this IS the API.
	if strings.Contains(s, "audit the API instead") {
		t.Errorf("pangolin_http_provider must not fire on a RUNTIME (API) read:\n%s", s)
	}
}

// TestAuditTarget_TraefikAPI_DockerLabels: the docker-labels capture reads as a
// foreign traefik-docker-labels edge; the unprotected labeled host fires
// public_without_auth while the forwardauth-guarded one does not.
func TestAuditTarget_TraefikAPI_DockerLabels(t *testing.T) {
	fake := startTraefikFake(t, "api-docker")
	var out, errOut bytes.Buffer
	code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fake.URL(), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, errOut.String(), out.String())
	}
	s := out.String()
	for _, want := range []string{
		"generated/owned by traefik-docker-labels",
		"notes.homelab.example is PUBLIC with no forward-auth",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "grafana.homelab.example is PUBLIC with no forward-auth") {
		t.Errorf("forwardauth-guarded host must NOT fire public_without_auth:\n%s", s)
	}
}

// TestAuditTarget_TraefikAPI_OnlyPastedTargetContacted is risk A.6 for the M-A4
// path: the whole flow (two-probe sniff + API read) contacts ONLY the pasted
// target, with GETs to exactly the documented endpoints and nothing else.
func TestAuditTarget_TraefikAPI_OnlyPastedTargetContacted(t *testing.T) {
	fake := startTraefikFake(t, "api-pangolin")
	var out, errOut bytes.Buffer
	if code := runAuditTarget(&globalFlags{assumePublicBoundary: true}, fake.URL(), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	allowed := map[string]bool{
		"GET /config/":              true, // the Caddy probe (404s here; that 404 routes us to the Traefik probe)
		"GET /api/version":          true, // the Traefik signature probe
		"GET /api/http/routers":     true,
		"GET /api/http/services":    true,
		"GET /api/http/middlewares": true,
		"GET /api/tcp/routers":      true,
		"GET /api/tcp/services":     true,
	}
	reqs := fake.Requests()
	if len(reqs) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, req := range reqs {
		if !allowed[req] {
			t.Errorf("undocumented request %q — only the documented probes/reads against the pasted target are permitted (risk A.6)", req)
		}
	}
}
