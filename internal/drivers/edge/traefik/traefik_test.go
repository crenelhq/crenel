package traefik

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// TestPlan_RefusesMeshGrant: Traefik renders HTTP + TCP-passthrough; it is not an
// identity mesh, so it refuses mesh-grant loudly.
func TestPlan_RefusesMeshGrant(t *testing.T) {
	d := newDriver(tempConfig(t, `{}`))
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Mode: model.ModeMeshGrant}
	_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
	if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
		t.Errorf("mesh_grant should be refused with ErrModeUnsupported, got: %v", err)
	}
}

// TestTCPPassthrough_RoundTrip: in ModeTCPPassthrough the driver renders a TCP
// router (HostSNI + tls.passthrough) and a TCP service, reads it back as a
// passthrough route, and removes it on unexpose — additively (HTTP deny preserved).
func TestTCPPassthrough_RoundTrip(t *testing.T) {
	path := tempConfig(t, fixture(t)) // has an unmanaged authelia HTTP router
	d := newDriver(path)
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "photos", Host: "stream.example.com", Mode: model.ModeTCPPassthrough}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatalf("passthrough plan should succeed, got: %v", err)
	}
	if len(cs.Edge.AddRoutes) != 1 || cs.Edge.AddRoutes[0].Upstream.Mode != model.ModeTCPPassthrough {
		t.Fatalf("expected a passthrough add, got %+v", cs.Edge)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	cfg := readBack(t, path)
	tr := cfg.TCP.Routers["crenel-tcp-stream.example.com"]
	if tr == nil || tr.TLS == nil || !tr.TLS.Passthrough || tr.Rule != "HostSNI(`stream.example.com`)" {
		t.Errorf("expected a HostSNI passthrough TCP router, got %+v", tr)
	}
	if svc := cfg.TCP.Services["crenel-tcp-stream.example.com"]; svc == nil || svc.firstAddress() != "10.0.0.6:2342" {
		t.Errorf("TCP service should point at the resolved origin (host:port), got %+v", svc)
	}
	// Unmanaged HTTP authelia router survives. crenel writes NO explicit deny router
	// (bench gap T3: the deny is Traefik's native 404); DenyCatchAllPresent is asserted
	// via read-back below.
	if cfg.HTTP.Routers["authelia"] == nil {
		t.Error("HTTP unmanaged router must survive a TCP-passthrough apply")
	}
	if cfg.HTTP.Routers[denyKey] != nil {
		t.Error("crenel must NOT write an explicit deny router (invalid for real Traefik) — deny is the native 404")
	}

	// Read-back surfaces it as a passthrough route.
	live2, _ := d.ReadLiveState(ctx)
	if !live2.Reachable("stream.example.com") {
		t.Error("passthrough host should be reachable + deny present")
	}
	for _, r := range live2.Routes {
		if r.Host == "stream.example.com" && (r.Upstream.Mode != model.ModeTCPPassthrough || !r.Upstream.TLSPassthrough) {
			t.Errorf("read-back should mark the route as TCP passthrough, got %+v", r.Upstream)
		}
	}

	// Unexpose removes the TCP router+service.
	un := model.Op{Verb: model.Unexpose, Host: "stream.example.com", Mode: model.ModeTCPPassthrough}
	live3, _ := d.ReadLiveState(ctx)
	csu, _ := d.Plan(un, live3)
	if err := d.Apply(ctx, csu); err != nil {
		t.Fatal(err)
	}
	cfg2 := readBack(t, path)
	// After removing the only TCP route, the tcp element is omitted entirely (nil on
	// read-back) — required so Traefik doesn't reject an empty `tcp` standalone element
	// (bench gap T6). Either nil tcp or an absent router satisfies "removed".
	if cfg2.TCP != nil && cfg2.TCP.Routers["crenel-tcp-stream.example.com"] != nil {
		t.Error("unexpose must remove the TCP passthrough router")
	}
}

func tempConfig(t *testing.T, seed string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic.json")
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/rich-prod.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newDriver(path string, opts ...Option) *Driver {
	res := static.New(map[string]string{
		"grafana": "10.0.0.5:3000",
		"photos":  "10.0.0.6:2342",
	})
	return New(path, res, opts...)
}

// TestNormalize_DefaultDenyImplicit: a Host()-scoped config (no permissive
// catch-all) reads as default-deny SATISFIED, with the two host routes surfaced.
func TestNormalize_DefaultDenyImplicit(t *testing.T) {
	d := newDriver(tempConfig(t, fixture(t)))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !live.DenyCatchAllPresent {
		t.Error("Host()-scoped routers => implicit 404 default-deny should hold")
	}
	if !live.HasHost("auth.example.com") || !live.HasHost("grafana.example.com") {
		t.Errorf("expected both host routes, got %v", live.Hosts())
	}
	if !live.Reachable("grafana.example.com") {
		t.Error("grafana should be reachable (route + deny present)")
	}
}

// TestNormalize_FailOpenWhenPermissiveCatchAll: a router that forwards ALL hosts
// to a real backend defeats the default-deny — DenyCatchAllPresent must be false.
func TestNormalize_FailOpenWhenPermissiveCatchAll(t *testing.T) {
	seed := `{"http":{"routers":{
		"catchall":{"rule":"HostRegexp(` + "`^.+$`" + `)","service":"sink"}
	},"services":{
		"sink":{"loadBalancer":{"servers":[{"url":"http://10.0.0.99:80"}]}}
	}}}`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.DenyCatchAllPresent {
		t.Error("a permissive forwarding catch-all must read as FAIL-OPEN")
	}
}

// TestApply_AdditiveExposePreservesUnmanaged is the headline additivity proof
// (the Traefik analogue of the Caddy granular test): exposing a host adds ONLY
// the crenel-* router/service (+ the deny) and leaves every unmanaged router and
// service untouched.
func TestApply_AdditiveExposePreservesUnmanaged(t *testing.T) {
	path := tempConfig(t, fixture(t))
	d := newDriver(path)
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	cfg := readBack(t, path)

	// Unmanaged routers survive, fields intact.
	auth := cfg.HTTP.Routers["authelia"]
	if auth == nil || auth.Rule != "Host(`auth.example.com`)" || len(auth.Middlewares) != 1 ||
		auth.Middlewares[0] != "authelia-forward" || auth.TLS == nil || auth.TLS.CertResolver != "cloudflare" {
		t.Errorf("unmanaged authelia router was altered: %+v", auth)
	}
	if cfg.HTTP.Routers["dashboard"] == nil || cfg.HTTP.Services["authelia-svc"] == nil ||
		cfg.HTTP.Services["grafana-svc"] == nil {
		t.Error("unmanaged dashboard/services must survive")
	}
	// The managed route was added.
	if cfg.HTTP.Routers["crenel-photos.example.com"] == nil {
		t.Error("crenel-managed router for photos must be added")
	}
	if svc := cfg.HTTP.Services["crenel-photos.example.com"]; svc == nil || svc.firstUpstream() != "http://10.0.0.6:2342" {
		t.Errorf("crenel service should point at the resolved origin, got %+v", svc)
	}
	// The structural deny is Traefik's native 404 — crenel writes NO explicit deny
	// router (bench gap T3). Its absence is asserted; the deny is verified via the
	// read-back's DenyCatchAllPresent below.
	if cfg.HTTP.Routers[denyKey] != nil {
		t.Error("crenel must NOT write an explicit crenel-deny router — real Traefik rejects its empty loadBalancer")
	}
	// And the written config must be VALID for a real Traefik file provider.
	if err := validate(cfg); err != nil {
		t.Errorf("written config must be valid Traefik: %v", err)
	}

	// Read-back through the driver: photos reachable, deny holds (via native 404).
	live2, _ := d.ReadLiveState(ctx)
	if !live2.Reachable("photos.example.com") || !live2.DenyCatchAllPresent {
		t.Errorf("after expose, photos must be reachable and deny present: %+v", live2)
	}

	// Now unexpose: only the crenel route is removed; unmanaged survive; deny stays.
	op2 := model.Op{Verb: model.Unexpose, Service: "photos", Host: "photos.example.com"}
	live3, _ := d.ReadLiveState(ctx)
	cs2, _ := d.Plan(op2, live3)
	if err := d.Apply(ctx, cs2); err != nil {
		t.Fatal(err)
	}
	cfg2 := readBack(t, path)
	if cfg2.HTTP.Routers["crenel-photos.example.com"] != nil || cfg2.HTTP.Services["crenel-photos.example.com"] != nil {
		t.Error("unexpose must remove the crenel route+service")
	}
	if cfg2.HTTP.Routers["authelia"] == nil || cfg2.HTTP.Routers["dashboard"] == nil {
		t.Error("unmanaged routers must survive unexpose")
	}
	// Default-deny still holds after unexpose — via the native 404, asserted on read-back.
	live4, _ := d.ReadLiveState(ctx)
	if !live4.DenyCatchAllPresent {
		t.Error("default-deny must remain present after removing a route")
	}
	if err := validate(cfg2); err != nil {
		t.Errorf("config after unexpose must be valid Traefik: %v", err)
	}
}

// TestApply_StructuralDenyOnEmptyEdge: even applying to a config with no routes, the
// structural default-deny holds (Traefik's native 404) and DenyCatchAllPresent is true.
func TestApply_StructuralDenyOnEmptyEdge(t *testing.T) {
	path := tempConfig(t, `{}`)
	d := newDriver(path)
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(op, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	op2 := model.Op{Verb: model.Unexpose, Service: "grafana", Host: "grafana.example.com"}
	live2, _ := d.ReadLiveState(ctx)
	cs2, _ := d.Plan(op2, live2)
	if err := d.Apply(ctx, cs2); err != nil {
		t.Fatal(err)
	}
	live3, _ := d.ReadLiveState(ctx)
	if !live3.DenyCatchAllPresent || len(live3.Routes) != 0 {
		t.Errorf("empty edge must still carry the deny and expose nothing: %+v", live3)
	}
}

func readBack(t *testing.T, path string) dynamicConfig {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg dynamicConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("read-back parse: %v", err)
	}
	return cfg
}

// TestAdopt_RekeysPreservingMiddlewaresAndTLS proves Traefik adoption re-keys an
// unmanaged router/service into the crenel-* namespace while preserving the
// router's middlewares, tls, and priority verbatim (ownership changes, behavior
// does not). Idempotent on a second run.
func TestAdopt_RekeysPreservingMiddlewaresAndTLS(t *testing.T) {
	ctx := context.Background()
	seed := `{"http":{
		"routers":{"grafana-r":{"rule":"Host(` + "`grafana.example.com`" + `)","service":"grafana-s","priority":42,"middlewares":["secheaders"],"tls":{"certResolver":"cloudflare"}}},
		"services":{"grafana-s":{"loadBalancer":{"servers":[{"url":"http://10.0.0.5:3000"}]}}}
	}}`
	path := tempConfig(t, seed)
	d := newDriver(path)

	// Before: surfaced as UNMANAGED.
	live, _ := d.ReadLiveState(ctx)
	if managedOf(live, "grafana.example.com") {
		t.Fatal("hand-written router must read as unmanaged before adopt")
	}

	if err := d.Adopt(ctx, []string{"grafana.example.com"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	cfg := readBack(t, path)
	r := cfg.HTTP.Routers["crenel-grafana.example.com"]
	if r == nil {
		t.Fatal("router should be re-keyed to crenel-grafana.example.com")
	}
	if cfg.HTTP.Routers["grafana-r"] != nil {
		t.Fatal("old unmanaged router key must be gone")
	}
	if r.Priority != 42 || r.TLS == nil || r.TLS.CertResolver != "cloudflare" {
		t.Fatalf("adopt must preserve priority/tls verbatim, got %+v / %+v", r, r.TLS)
	}
	if len(r.Middlewares) != 1 || r.Middlewares[0] != "secheaders" {
		t.Fatalf("adopt must preserve middlewares verbatim, got %v", r.Middlewares)
	}
	if r.Service != "crenel-grafana.example.com" || cfg.HTTP.Services["crenel-grafana.example.com"] == nil {
		t.Fatalf("service must be re-keyed and referenced, got service=%q", r.Service)
	}

	// Now surfaced as MANAGED, same backend.
	live2, _ := d.ReadLiveState(ctx)
	if !managedOf(live2, "grafana.example.com") {
		t.Fatal("adopted router must read as managed")
	}

	// Idempotent.
	if err := d.Adopt(ctx, []string{"grafana.example.com"}); err != nil {
		t.Fatalf("second adopt should be a no-op, got %v", err)
	}
}

func managedOf(live model.LiveEdgeState, host string) bool {
	for _, r := range live.Routes {
		if r.Host == host {
			return r.Managed
		}
	}
	return false
}

// TestReadLiveState_MissingFileBootstraps: pointing the driver at a not-yet-created
// dynamic-config path is the BOOTSTRAP case (crenel will create the file the Traefik
// file provider watches). ReadLiveState must NOT hard-error "no such file"; it reads
// as an empty edge, and the first expose initializes the file with the route + deny.
// Regression for proving-ground gap T2 (live: expose aborted on a missing file).
func TestReadLiveState_MissingFileBootstraps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	d := newDriver(path)
	ctx := context.Background()

	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatalf("missing file must read as empty edge, not error: %v", err)
	}
	if len(live.Routes) != 0 {
		t.Errorf("missing file must expose nothing, got %+v", live.Routes)
	}

	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("first expose must bootstrap the file: %v", err)
	}
	after, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatalf("read after bootstrap: %v", err)
	}
	if !after.DenyCatchAllPresent {
		t.Error("deny must be present after bootstrapping from a missing file")
	}
	if !after.Reachable("grafana.example.com") {
		t.Error("grafana should be reachable after bootstrap expose")
	}
}

// --- proving-ground gap fixes: T3 (valid output), T4/N2 (runtime verify) ---

// TestValidate_RejectsEmptyLoadBalancer encodes bench gap T3: a service with an empty
// loadBalancer (the shape crenel's old deny emitted) is INVALID for a real Traefik file
// provider ("loadBalancer cannot be a standalone element"). The faithful fake must now
// reject what real Traefik rejects, so write() refuses it.
func TestValidate_RejectsEmptyLoadBalancer(t *testing.T) {
	bad := dynamicConfig{HTTP: httpConfig{
		Routers:  map[string]*router{"crenel-deny": {Rule: "HostRegexp(`^.+$`)", Service: "crenel-deny", Priority: 1}},
		Services: map[string]*service{"crenel-deny": {LoadBalancer: loadBalancer{Servers: nil}}},
	}}
	if err := validate(bad); err == nil {
		t.Error("a service with an empty loadBalancer must be rejected (real Traefik drops the whole file)")
	}
	// And write() must refuse to emit it.
	d := newDriver(tempConfig(t, `{}`))
	if err := d.write(bad); err == nil {
		t.Error("write() must refuse an invalid Traefik config")
	}
}

// TestApply_HealsStaleInvalidDeny: applying over a file left broken by an OLDER crenel
// (an explicit crenel-deny with an empty loadBalancer) REMOVES the stale deny and writes
// a VALID file — so the fixed binary self-heals a previously-rejected config.
func TestApply_HealsStaleInvalidDeny(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "authelia": {"rule": "Host(` + "`auth.example.com`" + `)", "service": "authelia-svc"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "authelia-svc": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:9091"}]}},
          "crenel-deny": {"loadBalancer": {}}
        }
      }
    }`
	path := tempConfig(t, seed)
	d := newDriver(path)
	ctx := context.Background()
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("apply must heal the stale deny, not fail: %v", err)
	}
	cfg := readBack(t, path)
	if cfg.HTTP.Routers["crenel-deny"] != nil || cfg.HTTP.Services["crenel-deny"] != nil {
		t.Error("stale invalid crenel-deny must be removed")
	}
	if err := validate(cfg); err != nil {
		t.Errorf("healed config must be valid Traefik: %v", err)
	}
	if cfg.HTTP.Routers["authelia"] == nil {
		t.Error("unmanaged authelia must survive the heal")
	}
}

// fakeTraefikAPI serves /api/http/routers from a fixed set, mimicking the running
// daemon's runtime view (the @file suffix and "enabled" status included).
func fakeTraefikAPI(t *testing.T, routers []apiRouter) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/http/routers" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(routers)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestVerifyRuntime_UnavailableWithoutAPI: no api_url => Unavailable (never false green).
func TestVerifyRuntime_UnavailableWithoutAPI(t *testing.T) {
	d := newDriver("/unused")
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyUnavailable {
		t.Errorf("no api_url => Unavailable, got %s (%s)", v.Status, v.Detail)
	}
}

// TestVerifyRuntime_ConfirmsViaAPI: the running daemon LISTS crenel's enabled router =>
// Confirmed (a true runtime verify against the daemon, not crenel's file).
func TestVerifyRuntime_ConfirmsViaAPI(t *testing.T) {
	url := fakeTraefikAPI(t, []apiRouter{
		{Name: "crenel-x.example.com@file", Rule: "Host(`x.example.com`)", Status: "enabled"},
	})
	d := newDriver("/unused", WithAPIURL(url))
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyConfirmed {
		t.Errorf("daemon lists the enabled router => Confirmed, got %s (%s)", v.Status, v.Detail)
	}
}

// TestVerifyRuntime_FailsWhenRouterAbsent: the daemon does NOT list the router (e.g. it
// rejected the file — the exact T3 false-green the bench caught) => Failed, not green.
func TestVerifyRuntime_FailsWhenRouterAbsent(t *testing.T) {
	url := fakeTraefikAPI(t, []apiRouter{
		{Name: "authelia@file", Rule: "Host(`auth.example.com`)", Status: "enabled"},
	})
	d := newDriver("/unused", WithAPIURL(url))
	d.verifyDeadline = 0 // single-shot: don't wait the full poll window for the negative case
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyFailed {
		t.Errorf("daemon does not list the router => Failed, got %s (%s)", v.Status, v.Detail)
	}
}

// TestEncode_EmptyConfigIsValidEmptyDoc: an emptied config serializes to {} — NOT
// {"http":{}} — because real Traefik rejects the standalone-element form and then
// silently retains the old routes (bench gap T6).
func TestEncode_EmptyConfigIsValidEmptyDoc(t *testing.T) {
	b, err := encode(dynamicConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(b)); s != "{}" {
		t.Errorf("empty config must encode to {} (real Traefik rejects an empty http element), got: %s", s)
	}
}

// TestApply_UnexposeLastRouteLeavesValidEmptyDoc: removing the LAST managed route must
// leave a file Traefik accepts (so the removal actually takes effect), not a rejected
// empty-http element that lingers the route (bench gap T6).
func TestApply_UnexposeLastRouteLeavesValidEmptyDoc(t *testing.T) {
	path := tempConfig(t, `{}`)
	d := newDriver(path)
	ctx := context.Background()
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	live2, _ := d.ReadLiveState(ctx)
	cs2, _ := d.Plan(model.Op{Verb: model.Unexpose, Service: "grafana", Host: "grafana.example.com"}, live2)
	if err := d.Apply(ctx, cs2); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"http"`) {
		t.Errorf("after removing the last route the file must carry no empty http element (T6), got: %s", raw)
	}
	// And it must still decode + read back as an empty, default-deny edge.
	after, _ := d.ReadLiveState(ctx)
	if len(after.Routes) != 0 || !after.DenyCatchAllPresent {
		t.Errorf("emptied edge must read back with no routes + deny present, got %+v", after)
	}
}
