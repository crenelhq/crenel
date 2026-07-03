package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// dashboardForTest builds a dashboard wired to a real engine over a fake Caddy
// seeded with one exposed host + a default-deny — the same faithful-fake path the
// CLI tests use, so the web view is exercised against real status output.
func dashboardForTest(t *testing.T) *dashboard {
	t.Helper()
	f := seedFake(t)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	edge := caddy.New(f.URL(), res)
	return &dashboard{engine: core.New(edge, "example.com"), refresh: 5}
}

func TestDashboard_HUDRendersLiveStatus(t *testing.T) {
	d := dashboardForTest(t)
	srv := httptest.NewServer(d.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/hud.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /hud.svg status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
	body := readAll(t, resp)
	// The HUD must carry the real exposure state: the panel, the exposed host, and
	// a certifiable default-deny (the seeded edge is fully parsed -> ENFORCED).
	for _, want := range []string{"CORE MATRIX", "EXPOSED", "DEFAULT-DENY", "ENFORCED"} {
		if !strings.Contains(body, want) {
			t.Errorf("HUD SVG missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "FAIL-OPEN") {
		t.Errorf("seeded edge has a default-deny; HUD should not read FAIL-OPEN:\n%s", body)
	}
}

func TestDashboard_IndexEmbedsHUD(t *testing.T) {
	d := dashboardForTest(t)
	srv := httptest.NewServer(d.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, "/hud.svg") {
		t.Errorf("index should embed /hud.svg:\n%s", body)
	}
	if !strings.Contains(body, "read-only") {
		t.Errorf("index should advertise the read-only posture:\n%s", body)
	}
}

// TestDashboard_RejectsMutatingMethods is the load-bearing safety test: the
// dashboard is read-only BY CONSTRUCTION — any non-GET method is 405 on every
// route, so no web request can ever drive a mutation.
func TestDashboard_RejectsMutatingMethods(t *testing.T) {
	d := dashboardForTest(t)
	srv := httptest.NewServer(d.handler())
	defer srv.Close()

	for _, path := range []string{"/", "/hud.svg", "/healthz"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			req, _ := http.NewRequest(method, srv.URL+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405 (read-only dashboard)", method, path, resp.StatusCode)
			}
		}
	}
}

func TestDashboard_HealthOK(t *testing.T) {
	d := dashboardForTest(t)
	srv := httptest.NewServer(d.handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", resp.StatusCode)
	}
}

// errEngine is a statusSource whose reads always fail, to exercise the degraded
// "edge unreachable" path.
type errEngine struct{}

func (errEngine) Status(context.Context) (core.StatusReport, error) {
	return core.StatusReport{}, errors.New("dial tcp 127.0.0.1:2019: connection refused")
}
func (errEngine) DetectDrift(context.Context) (core.ReconcilePlan, error) {
	return core.ReconcilePlan{}, errors.New("unreachable")
}

func TestDashboard_DegradesWhenEdgeUnreachable(t *testing.T) {
	d := &dashboard{engine: errEngine{}, refresh: 5}
	srv := httptest.NewServer(d.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/hud.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Degraded, but still 200 so a poller keeps retrying — and honest: it must show
	// UNREACHABLE, never a green ENFORCED it could not certify.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("degraded /hud.svg = %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "EDGE UNREACHABLE") {
		t.Errorf("degraded HUD should say EDGE UNREACHABLE:\n%s", body)
	}
	if strings.Contains(body, "ENFORCED") {
		t.Errorf("degraded HUD must not claim ENFORCED:\n%s", body)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
