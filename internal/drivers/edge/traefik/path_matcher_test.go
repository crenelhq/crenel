package traefik

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestNormalize_DeclaresPathScopedRouters proves Traefik's normalize does not SILENTLY
// read a router gated by a non-host predicate (PathPrefix / Path / Method / Headers / …)
// as a plain host route. parseHosts extracts the Host(`…`) matcher and the host branch
// emitted one route per host — IGNORING any `&& PathPrefix(…)` / `&& Method(…)` in the
// same rule. So `app.example.com` split across `/api` and `/` (different backends) read
// as ONE fully-exposed host, and a method-scoped router read as exposing every method —
// a MISREAD-↓ that violates bounded honesty (the Caddy path-matcher analogue).
//
// After the fix each host-matched router that ALSO carries a non-host predicate is
// DECLARED matcher_conditional (naming the predicate) rather than enumerated as a host
// route, so deny downgrades to UNKNOWN.
func TestNormalize_DeclaresPathScopedRouters(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "crenel-grafana.example.com": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "svc-grafana"},
          "app-api":  {"rule": "Host(` + "`app.example.com`" + `) && PathPrefix(` + "`/api`" + `)", "service": "svc-app-api"},
          "app-root": {"rule": "Host(` + "`app.example.com`" + `) && PathPrefix(` + "`/`" + `)", "service": "svc-app-root"},
          "api-ro":   {"rule": "Host(` + "`api.example.com`" + `) && Method(` + "`GET`" + `)", "service": "svc-api"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "svc-grafana":  {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}},
          "svc-app-api":  {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8443"}]}},
          "svc-app-root": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:8080"}]}},
          "svc-api":      {"loadBalancer": {"servers": [{"url": "http://10.0.0.10:9000"}]}},
          "crenel-deny":  {"loadBalancer": {}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Only the plain-host grafana route enumerates; the path/method-scoped routers do NOT.
	if !live.HasHost("grafana.example.com") || len(live.Routes) != 1 {
		t.Fatalf("only the plain-host grafana route should enumerate, got %v", live.Hosts())
	}
	if live.HasHost("app.example.com") {
		t.Errorf("a path-scoped router must NOT read as a plain host route, but app.example.com enumerated: %v", live.Hosts())
	}
	if live.HasHost("api.example.com") {
		t.Errorf("a method-scoped router must NOT read as a plain host route, but api.example.com enumerated: %v", live.Hosts())
	}

	// Three matcher_conditional declarations: two PathPrefix routers + one Method router.
	var conds []model.Unparsed
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			conds = append(conds, u)
		}
	}
	if len(conds) != 3 {
		t.Fatalf("expected 3 matcher_conditional declarations (2 path + 1 method), got %d: %+v", len(conds), live.Unparsed)
	}
	var sawPath, sawMethod bool
	for _, u := range conds {
		if strings.Contains(u.Reason, "PathPrefix") {
			sawPath = true
		}
		if strings.Contains(u.Reason, "Method") {
			sawMethod = true
		}
	}
	if !sawPath || !sawMethod {
		t.Errorf("declaration reasons must name the predicate (PathPrefix/Method); got %+v", conds)
	}

	if !live.DenyCatchAllPresent {
		t.Error("deny router present + no permissive catch-all => DenyCatchAllPresent")
	}
	if live.DenyState() != model.DenyUnknown {
		t.Errorf("path/method-scoped routers must downgrade deny to UNKNOWN, got %q", live.DenyState())
	}
}

// TestNormalize_PlainHostRouterUnaffected locks the no-cry-wolf side: an ordinary
// Host(`…`) router (and crenel's own host-only managed render) must NOT raise
// matcher_conditional, and the deny's HostRegexp is host-family (not a non-host predicate).
func TestNormalize_PlainHostRouterUnaffected(t *testing.T) {
	seed := `{
      "http": {
        "routers": {
          "crenel-grafana.example.com": {"rule": "Host(` + "`grafana.example.com`" + `)", "service": "svc-grafana"},
          "crenel-deny": {"rule": "HostRegexp(` + "`^.+$`" + `)", "service": "crenel-deny", "priority": 1}
        },
        "services": {
          "svc-grafana": {"loadBalancer": {"servers": [{"url": "http://10.0.0.5:3000"}]}},
          "crenel-deny": {"loadBalancer": {}}
        }
      }
    }`
	d := newDriver(tempConfig(t, seed))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range live.Unparsed {
		if u.Kind == model.UnknownMatcher {
			t.Errorf("a host-only edge must not raise matcher_conditional (cry-wolf): %+v", u)
		}
	}
	if !live.FullyParsed() || live.DenyState() != model.DenyEnforced {
		t.Errorf("host-only edge must read fully-parsed + deny ENFORCED, got unparsed=%+v deny=%q", live.Unparsed, live.DenyState())
	}
}
