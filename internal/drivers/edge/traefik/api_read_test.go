package traefik

// api_read_test.go exercises the M-A4 Traefik API read source against
// traefikapifake serving the CAPTURED payloads (testdata/api-pangolin and
// api-docker — real Traefik v3.6 answers; see the fixture-provenance note in
// api_read.go). The assertions pin the milestone's contract: badger ⇒ pangolin,
// provider docker ⇒ labels, foreign edge-wide, routes enumerated with typed auth
// detection, conditional rules declared (never misread), RUNTIME evidence, and
// mutation refused structurally.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/traefik/traefikapifake"
	"github.com/crenelhq/crenel/internal/model"
)

func startFake(t *testing.T, capture string) *traefikapifake.Fake {
	t.Helper()
	f, err := traefikapifake.NewFromDir(filepath.Join("testdata", capture))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func routeByHost(routes []model.Route, host string) *model.Route {
	for i := range routes {
		if routes[i].Host == host {
			return &routes[i]
		}
	}
	return nil
}

// TestAPIRead_PangolinCapture: the Pangolin payload (badger@http middleware on
// every generated router) reads as a FOREIGN pangolin edge; the resource hosts
// carry AuthDetected from the typed badger middleware; the dashboard's own
// conditional routers (`Host && [!]PathPrefix(/api/v1)`) are DECLARED, never
// flattened into a whole-host claim.
func TestAPIRead_PangolinCapture(t *testing.T) {
	f := startFake(t, "api-pangolin")
	r := NewAPIReader(f.URL())
	live, err := r.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "pangolin" {
		t.Fatalf("generator = %q, want pangolin (badger middleware signature)", live.Generator)
	}
	for _, host := range []string{"vault.homelab.example", "notes.homelab.example", "pangolin.homelab.example"} {
		rt := routeByHost(live.Routes, host)
		if rt == nil {
			t.Fatalf("host %s not enumerated; routes: %+v", host, live.Routes)
		}
		if rt.Ownership != model.OwnForeign || rt.Managed {
			t.Errorf("%s: ownership %q managed=%v — a generator edge is foreign edge-wide", host, rt.Ownership, rt.Managed)
		}
	}
	// Pangolin publishes each resource via TWO routers (the web->https redirect
	// and the websecure badger-guarded one); both are enumerated honestly, and
	// the badger-guarded one carries AuthDetected — which is what protects the
	// host in core's any-route-authed model.
	authed := false
	for _, rt := range live.Routes {
		if rt.Host == "vault.homelab.example" && rt.Upstream.Auth == model.AuthDetected {
			authed = true
		}
	}
	if !authed {
		t.Errorf("no vault route carries AuthDetected (badger middleware); routes: %+v", live.Routes)
	}
	// Upstream address from the HTTP-provider service (10.0.0.7:8200 in capture).
	if rt := routeByHost(live.Routes, "vault.homelab.example"); rt.Upstream.Address != "10.0.0.7:8200" {
		t.Errorf("vault upstream = %q, want 10.0.0.7:8200", rt.Upstream.Address)
	}
	// Pangolin's own dashboard is served by FOUR routers; the two conditional
	// ones (PathPrefix / negated PathPrefix) must be declared matcher-conditional.
	var conditional int
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher && strings.Contains(u.Reason, "non-host predicate") {
			conditional++
		}
	}
	if conditional != 2 {
		t.Errorf("declared %d conditional routers, want 2 (next-router, api-router); unparsed: %+v", conditional, live.Unparsed)
	}
	// Deny: Traefik's API reports no explicit catch-all; nothing in the capture
	// forwards all hosts, so the structural deny (native 404) stands — core's
	// ternary still downgrades ENFORCED->UNKNOWN because of the declared unknowns.
	if !live.DenyCatchAllPresent {
		t.Error("no permissive catch-all in the capture — DenyCatchAllPresent must hold")
	}
	if live.DenyState() != model.DenyUnknown {
		t.Errorf("deny state = %v, want UNKNOWN (declared conditional routers block certification)", live.DenyState())
	}
}

// TestAPIRead_DockerLabelsCapture: the docker-provider payload reads as a
// FOREIGN traefik-docker-labels edge; the forwardauth-typed middleware yields
// AuthDetected on exactly the router that references it; the PathPrefix-scoped
// router is declared, and Traefik's own internal plumbing (api/dashboard) is
// benign — not a route, not an unknown, not a permissive catch-all.
func TestAPIRead_DockerLabelsCapture(t *testing.T) {
	f := startFake(t, "api-docker")
	r := NewAPIReader(f.URL())
	live, err := r.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.Generator != "traefik-docker-labels" {
		t.Fatalf("generator = %q, want traefik-docker-labels (provider field)", live.Generator)
	}
	grafana := routeByHost(live.Routes, "grafana.homelab.example")
	notes := routeByHost(live.Routes, "notes.homelab.example")
	if grafana == nil || notes == nil {
		t.Fatalf("labeled hosts not enumerated; routes: %+v", live.Routes)
	}
	if grafana.Upstream.Auth != model.AuthDetected {
		t.Errorf("grafana auth = %q, want AuthDetected (typed forwardauth middleware)", grafana.Upstream.Auth)
	}
	if notes.Upstream.Auth != "" {
		t.Errorf("notes auth = %q, want none — auth must never be invented", notes.Upstream.Auth)
	}
	if grafana.Ownership != model.OwnForeign {
		t.Errorf("grafana ownership = %q, want foreign (label-generated)", grafana.Ownership)
	}
	// api.homelab.example is scoped by PathPrefix(`/v1`): declared, not a route.
	if rt := routeByHost(live.Routes, "api.homelab.example"); rt != nil {
		t.Errorf("path-scoped router must NOT read as a whole-host route: %+v", rt)
	}
	found := false
	for _, u := range live.Unparsed {
		if strings.Contains(u.Locator, "apionly@docker") && u.Kind == model.UnknownMatcher {
			found = true
		}
		// Internal plumbing must not leak into unknowns: it has no upstream and no host.
		if strings.Contains(u.Locator, "@internal") {
			t.Errorf("internal router leaked into unknowns: %+v", u)
		}
	}
	if !found {
		t.Errorf("apionly@docker (Host && PathPrefix) must be declared matcher-conditional; unparsed: %+v", live.Unparsed)
	}
	if !live.DenyCatchAllPresent {
		t.Error("dashboard@internal (PathPrefix(`/`), no upstream) must not read as a permissive catch-all")
	}
}

// TestAPIRead_MutationRefusedStructurally: the API read source refuses Plan and
// Apply loudly — read-only by construction (belt; the zero-config target adds
// the core.ReadOnlyEngine braces on top).
func TestAPIRead_MutationRefusedStructurally(t *testing.T) {
	f := startFake(t, "api-pangolin")
	r := NewAPIReader(f.URL())
	if _, err := r.Plan(model.Op{Verb: model.Expose, Host: "x.homelab.example", Mode: model.ModeHTTPProxy}, model.LiveEdgeState{}); err == nil || !strings.Contains(err.Error(), "READ-ONLY") {
		t.Errorf("Plan must refuse loudly, got %v", err)
	}
	if err := r.Apply(context.Background(), model.ChangeSet{}); err == nil || !strings.Contains(err.Error(), "READ-ONLY") {
		t.Errorf("Apply must refuse loudly, got %v", err)
	}
	// And the refusals must not have written anything: every recorded request is a GET.
	for _, req := range f.Requests() {
		if !strings.HasPrefix(req, "GET ") {
			t.Errorf("non-GET request recorded: %s", req)
		}
	}
}

// TestAPIRead_EvidenceRuntime: the reader declares RUNTIME evidence naming the
// API — the strongest read kind; never CONFIG, never a staleness mtime.
func TestAPIRead_EvidenceRuntime(t *testing.T) {
	r := NewAPIReader("http://127.0.0.1:9")
	ev := r.ReadEvidence()
	if ev.Kind != model.EvidenceRuntime || !strings.Contains(ev.Source, "Traefik API") || !ev.ModTime.IsZero() {
		t.Errorf("evidence = %+v, want RUNTIME naming the Traefik API with zero mtime", ev)
	}
}

// TestAPIRead_ValidateSignature: Validate answers the Traefik version signature
// against the fake and fails against a dead port (bounded, never hangs).
func TestAPIRead_ValidateSignature(t *testing.T) {
	f := startFake(t, "api-docker")
	if err := NewAPIReader(f.URL()).Validate(context.Background()); err != nil {
		t.Errorf("Validate against the fake: %v", err)
	}
	if err := NewAPIReader("http://127.0.0.1:9").Validate(context.Background()); err == nil {
		t.Error("Validate against a dead port must fail")
	}
}
