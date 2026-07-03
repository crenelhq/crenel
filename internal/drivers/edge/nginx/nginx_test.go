package nginx

import (
	"context"
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

func resolver() *static.Resolver {
	return static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
}

func tempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "edge.conf")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// richFixture is a config with an UNMANAGED auth vhost (Authelia) crenel must never
// touch, plus a hand-written upstream directive, and a permissive nothing.
const richFixture = `# operator-owned nginx config

upstream authelia_backend {
    server 10.0.0.9:9091;
}

server {
    listen 443 ssl;
    server_name auth.example.com;
    location / {
        proxy_pass http://authelia_backend;
    }
}
`

// TestReadLiveState_ImplicitDefaultLeaksIsNotDeny: a brownfield with a single
// forwarding vhost and NO denying default_server is NOT default-deny — nginx serves an
// unmatched host from the IMPLICIT default server (the first server on the port). This
// is bench gap N4: crenel previously claimed ENFORCED here while a real nginx returned
// the vhost's backend for ANY host. crenel must now report it honestly (false), still
// surfacing the vhost it read.
func TestReadLiveState_ImplicitDefaultLeaksIsNotDeny(t *testing.T) {
	d := New(tempConfig(t, richFixture), resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.DenyCatchAllPresent {
		t.Error("a :443 vhost with no denying default_server leaks unmatched hosts via nginx's implicit default server => default-deny is NOT enforced")
	}
	if !live.HasHost("auth.example.com") {
		t.Errorf("should still surface the unmanaged auth vhost, got %v", live.Hosts())
	}
}

// TestReadLiveState_PermissiveCatchAllIsFailOpen: a default_server that proxies all
// hosts to a backend is a permissive catch-all => fail-open.
func TestReadLiveState_PermissiveCatchAllIsFailOpen(t *testing.T) {
	failopen := `server {
    listen 443 ssl default_server;
    server_name _;
    location / {
        proxy_pass http://10.0.0.1:8080;
    }
}
`
	d := New(tempConfig(t, failopen), resolver())
	live, _ := d.ReadLiveState(context.Background())
	if live.DenyCatchAllPresent {
		t.Error("a forwarding default_server is a permissive catch-all => fail-open")
	}
}

// TestPlan_RefusesNonHTTPModes: nginx (this driver) is an HTTP reverse-proxy edge;
// passthrough + mesh are refused loudly.
func TestPlan_RefusesNonHTTPModes(t *testing.T) {
	d := New("/unused", resolver())
	for _, m := range []model.RouteMode{model.ModeTCPPassthrough, model.ModeMeshGrant} {
		op := model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com", Mode: m}
		_, err := d.Plan(op, model.LiveEdgeState{DenyCatchAllPresent: true})
		if err == nil || !errors.Is(err, model.ErrModeUnsupported) {
			t.Errorf("mode %s should be refused with ErrModeUnsupported, got: %v", m, err)
		}
	}
}

// TestApply_AdditiveExposePreservesUnmanaged: exposing a service ADDS only a
// crenel-managed server block + the deny; the unmanaged Authelia vhost and the
// hand-written upstream survive. Unexpose removes only the crenel block. The driver is
// configured WithTLS on :443 to MATCH the brownfield's listen port, so the deny's
// default_server covers the same port the Authelia vhost serves (bench gap N4: a
// port-mismatched deny would leave :443 leaking via its implicit default server).
func TestApply_AdditiveExposePreservesUnmanaged(t *testing.T) {
	path := tempConfig(t, richFixture)
	d := New(path, resolver(), WithTLS(443, "/etc/ssl/edge.crt", "/etc/ssl/edge.key"))
	ctx := context.Background()

	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	out := readFile(t, path)
	// Unmanaged content survives.
	if !strings.Contains(out, "upstream authelia_backend") || !strings.Contains(out, "auth.example.com") {
		t.Errorf("unmanaged blocks must be preserved, got:\n%s", out)
	}
	// crenel block added with its marker + proxy_pass.
	if !strings.Contains(out, managedMarker+" grafana.example.com") || !strings.Contains(out, "proxy_pass http://10.0.0.5:3000;") {
		t.Errorf("crenel-managed grafana block should be present, got:\n%s", out)
	}
	// Default-deny rendered on the matching :443 port.
	if !strings.Contains(out, "listen 443 ssl default_server;") || !strings.Contains(out, "return 444;") {
		t.Errorf("default-deny block must be rendered on the managed port, got:\n%s", out)
	}
	// VALIDITY (bench gap N1): every `ssl` listener crenel emits MUST carry a cert, or
	// real nginx refuses the file. No bare `listen 443 ssl;` without ssl_certificate.
	if strings.Contains(out, "ssl") && !strings.Contains(out, "ssl_certificate /etc/ssl/edge.crt;") {
		t.Errorf("an ssl listener must carry ssl_certificate (else nginx -t fails), got:\n%s", out)
	}

	// Read-back: grafana + auth exposed, deny present (deny on :443 covers the :443 vhost).
	after, _ := d.ReadLiveState(ctx)
	if !after.Reachable("grafana.example.com") {
		t.Error("grafana should be reachable after expose")
	}
	if !after.HasHost("auth.example.com") {
		t.Error("unmanaged auth vhost must still be present")
	}

	// Unexpose removes only the crenel block.
	csU, _ := d.Plan(model.Op{Verb: model.Unexpose, Service: "grafana", Host: "grafana.example.com"}, after)
	if err := d.Apply(ctx, csU); err != nil {
		t.Fatal(err)
	}
	final := readFile(t, path)
	if strings.Contains(final, "grafana.example.com") {
		t.Error("crenel grafana block should be gone after unexpose")
	}
	if !strings.Contains(final, "auth.example.com") {
		t.Error("unmanaged auth vhost must survive unexpose")
	}
}

// TestApply_EmptyConfigGetsDeny: applying to an empty file still renders the
// structural default-deny (the invariant holds from a greenfield start).
func TestApply_EmptyConfigGetsDeny(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver())
	ctx := context.Background()
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	after, _ := d.ReadLiveState(ctx)
	if !after.DenyCatchAllPresent {
		t.Error("deny must be present even when starting from an empty config")
	}
	if !after.Reachable("photos.example.com") {
		t.Error("photos should be reachable after expose")
	}
}

// TestAdopt_StampsMarkerPreservingBodyVerbatim proves nginx adoption inserts the
// `# crenel-managed:` marker above an existing unmanaged server block WITHOUT
// touching the block body (a custom directive survives), leaves an out-of-list
// block alone, and is idempotent.
func TestAdopt_StampsMarkerPreservingBodyVerbatim(t *testing.T) {
	ctx := context.Background()
	body := `server {
    listen 443 ssl;
    server_name status.example.com;
    client_max_body_size 200m;
    location / {
        proxy_pass http://10.0.0.10:8080;
    }
}

server {
    listen 443 ssl;
    server_name other.example.com;
    location / {
        proxy_pass http://10.0.0.20:9090;
    }
}
`
	path := tempConfig(t, body)
	d := New(path, static.New(map[string]string{"status": "10.0.0.10:8080"}))

	live, _ := d.ReadLiveState(ctx)
	for _, r := range live.Routes {
		if r.Host == "status.example.com" && r.Managed {
			t.Fatal("hand-written block must read as unmanaged before adopt")
		}
	}

	if err := d.Adopt(ctx, []string{"status.example.com"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	out := readFile(t, path)
	if !strings.Contains(out, managedMarker+" status.example.com") {
		t.Fatalf("marker not stamped:\n%s", out)
	}
	if !strings.Contains(out, "client_max_body_size 200m;") {
		t.Fatalf("custom directive must survive adoption verbatim:\n%s", out)
	}
	// The other block must remain UNMANAGED (not in the adopt list).
	if strings.Contains(out, managedMarker+" other.example.com") {
		t.Fatalf("an unlisted block must not be adopted:\n%s", out)
	}

	live2, _ := d.ReadLiveState(ctx)
	got := false
	for _, r := range live2.Routes {
		if r.Host == "status.example.com" {
			got = r.Managed
			if r.Upstream.Address != "10.0.0.10:8080" {
				t.Fatalf("backend changed by adopt: %s", r.Upstream.Address)
			}
		}
	}
	if !got {
		t.Fatal("status block must read as managed after adopt")
	}

	// Idempotent: a second adopt does not add a second marker.
	if err := d.Adopt(ctx, []string{"status.example.com"}); err != nil {
		t.Fatalf("second adopt: %v", err)
	}
	if n := strings.Count(readFile(t, path), managedMarker+" status.example.com"); n != 1 {
		t.Fatalf("idempotency: want exactly 1 marker, got %d", n)
	}
}

// TestReadLiveState_MissingFileBootstraps: a not-yet-created nginx config path is the
// BOOTSTRAP case — ReadLiveState reads it as empty (not an error), and the first
// expose creates the file (write() uses os.WriteFile). Regression for proving-ground
// gap N5 (live: expose aborted "no such file or directory" on a missing path).
func TestReadLiveState_MissingFileBootstraps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.conf")
	d := New(path, resolver())
	ctx := context.Background()

	if err := d.Validate(ctx); err != nil {
		t.Fatalf("Validate must accept a not-yet-created file (bootstrap): %v", err)
	}
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		t.Fatalf("missing file must read as empty edge, not error: %v", err)
	}
	if len(live.Routes) != 0 {
		t.Errorf("missing file must expose nothing, got %+v", live.Routes)
	}

	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatalf("first expose must bootstrap the file: %v", err)
	}
	after, _ := d.ReadLiveState(ctx)
	if !after.DenyCatchAllPresent {
		t.Error("deny must be present after bootstrapping from a missing file")
	}
	if !after.Reachable("photos.example.com") {
		t.Error("photos should be reachable after bootstrap expose")
	}
}

// --- proving-ground gap fixes: N1 (valid output), N4 (implicit-default), N3/N2 (runtime) ---

// TestRender_DefaultIsValidHTTP: with no TLS configured crenel emits `listen 80;`
// (HTTP) with NO `ssl` — a config a real nginx LOADS. Bench gap N1: the old hardcoded
// `listen 443 ssl;` had no ssl_certificate and made `nginx -t` fail, so the write never
// reloaded. The deny default_server sits on the same :80.
func TestRender_DefaultIsValidHTTP(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver())
	ctx := context.Background()
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	out := readFile(t, path)
	if strings.Contains(out, "ssl") {
		t.Errorf("default render must be plain HTTP (no ssl without a cert), got:\n%s", out)
	}
	if !strings.Contains(out, "listen 80;") || !strings.Contains(out, "listen 80 default_server;") {
		t.Errorf("managed block + deny must listen on :80, got:\n%s", out)
	}
}

// TestNormalize_DenyOnWrongPortDoesNotCertify: a deny default_server on :443 does NOT
// certify default-deny for a vhost serving on :80 (bench gap N4 — the exact false-green
// the bench caught: crenel's deny was on :443 while traffic was :80).
func TestNormalize_DenyOnWrongPortDoesNotCertify(t *testing.T) {
	cfg := `server {
    listen 80;
    server_name app.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}
# crenel-deny: default-deny catch-all
server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}
`
	d := New(tempConfig(t, cfg), resolver())
	live, _ := d.ReadLiveState(context.Background())
	if live.DenyCatchAllPresent {
		t.Error(":80 has a forwarding vhost but the only deny default_server is on :443 — :80 leaks via its implicit default => NOT default-deny")
	}
}

// TestNormalize_DenyOnMatchingPortCertifies: deny default_server on the SAME port as the
// forwarding vhost certifies default-deny (the post-fix render shape).
func TestNormalize_DenyOnMatchingPortCertifies(t *testing.T) {
	cfg := `server {
    listen 80;
    server_name app.example.com;
    location / {
        proxy_pass http://10.0.0.5:3000;
    }
}
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
`
	d := New(tempConfig(t, cfg), resolver())
	live, _ := d.ReadLiveState(context.Background())
	if !live.DenyCatchAllPresent {
		t.Error("a deny default_server on the same :80 as the vhost must certify default-deny")
	}
}

// TestVerifyRuntime_UnavailableWithoutSurface: with no runtime configured, VerifyRuntime
// reports UNAVAILABLE — never a confirmed/false green (bench gap N2/T4).
func TestVerifyRuntime_UnavailableWithoutSurface(t *testing.T) {
	d := New("/unused", resolver())
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyUnavailable {
		t.Errorf("no runtime surface => Unavailable, got %s (%s)", v.Status, v.Detail)
	}
}

// servingExcept returns a handler that answers 200 for every host EXCEPT the named ones,
// whose connections it closes (mimicking nginx's `return 444` deny). It lets a fake
// daemon model "this host is served, that one is denied".
func servingExcept(deny ...string) http.HandlerFunc {
	denied := map[string]bool{}
	for _, h := range deny {
		denied[h] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if denied[r.Host] {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					_ = c.Close()
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// TestVerifyRuntime_ConfirmsServedExpose: a running daemon that SERVES the host AND denies
// an unmatched host confirms an expose against the real surface (not crenel's file).
func TestVerifyRuntime_ConfirmsServedExpose(t *testing.T) {
	srv := httptest.NewServer(servingExcept(denyProbeHost)) // serves x, denies the synthetic probe
	defer srv.Close()
	d := New("/unused", resolver(), WithRuntime([]string{"true"}, []string{"true"}, srv.URL))
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyConfirmed {
		t.Errorf("daemon serves the host + denies unmatched => Confirmed, got %s (%s)", v.Status, v.Detail)
	}
}

// TestVerifyRuntime_FailsWhenDenyNotLive: a daemon that serves the exposed host but ALSO
// serves an unmatched host (default-deny NOT live — bench gap N4, and the fail-open
// stale-worker race) must FAIL, not confirm. This is the discriminator the bench needed.
func TestVerifyRuntime_FailsWhenDenyNotLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // serves EVERYTHING, including unmatched hosts (fail-open)
	}))
	defer srv.Close()
	d := New("/unused", resolver(), WithRuntime([]string{"true"}, []string{"true"}, srv.URL))
	d.verifyDeadline = 0
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Expose, Host: "x.example.com"},
		model.EdgeChange{AddRoutes: []model.Route{{Host: "x.example.com"}}})
	if v.Status != model.RuntimeVerifyFailed {
		t.Errorf("fail-open daemon (unmatched host served) => Failed, got %s (%s)", v.Status, v.Detail)
	}
	if !strings.Contains(v.Detail, "default-deny is NOT live") {
		t.Errorf("failure should name the live default-deny gap, got: %s", v.Detail)
	}
}

// TestVerifyRuntime_FailsWhenStillServedAfterUnexpose: if the daemon STILL serves a host
// after an unexpose, runtime verify FAILS — the would-be false green becomes a real red.
func TestVerifyRuntime_FailsWhenStillServedAfterUnexpose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // still serving — the unexpose did not take effect
	}))
	defer srv.Close()
	d := New("/unused", resolver(), WithRuntime([]string{"true"}, []string{"true"}, srv.URL))
	d.verifyDeadline = 0 // single-shot: don't wait the full poll window for the negative case
	v := d.VerifyRuntime(context.Background(), model.Op{Verb: model.Unexpose, Host: "x.example.com"},
		model.EdgeChange{RemoveHosts: []string{"x.example.com"}})
	if v.Status != model.RuntimeVerifyFailed {
		t.Errorf("daemon still serves the host after unexpose => Failed, got %s (%s)", v.Status, v.Detail)
	}
}

// TestApply_RejectsConfigThatFailsNginxTest: an Apply whose `nginx -t` fails returns an
// error (so core rolls back) — crenel never leaves an invalid config "applied" (gap N1).
func TestApply_RejectsConfigThatFailsNginxTest(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver(), WithRuntime([]string{"false"}, []string{"true"}, "")) // `false` => nginx -t fails
	ctx := context.Background()
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(model.Op{Verb: model.Expose, Service: "photos", Host: "photos.example.com"}, live)
	if err := d.Apply(ctx, cs); err == nil {
		t.Error("Apply must fail when nginx -t rejects the written config")
	}
}
