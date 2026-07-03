package traefik

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

func authDriver(path string, middlewares map[string]string) *Driver {
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000", "photos": "10.0.0.6:2342"})
	return New(path, res, WithAuthMiddlewares(middlewares))
}

// TestAuth_AttachesMiddlewareByReference proves a crenel-managed expose with a
// forward-auth policy attaches the named middleware to ITS router only, and the
// policy round-trips on read-back.
func TestAuth_AttachesMiddlewareByReference(t *testing.T) {
	path := tempConfig(t, `{}`)
	d := authDriver(path, map[string]string{"authelia": "authelia@file"})
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(ctx)
	cs, err := d.Plan(op, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}

	cfg := readBack(t, path)
	r := cfg.HTTP.Routers["crenel-grafana.example.com"]
	if r == nil || len(r.Middlewares) != 1 || r.Middlewares[0] != "authelia@file" {
		t.Fatalf("managed router should carry the auth middleware, got %+v", r)
	}
	// The deny router must NOT carry auth.
	if deny := cfg.HTTP.Routers[denyKey]; deny != nil && len(deny.Middlewares) != 0 {
		t.Errorf("deny router must not be given auth, got %+v", deny)
	}

	after, _ := d.ReadLiveState(ctx)
	r2 := routeFor(after, "grafana.example.com")
	if r2 == nil || r2.Upstream.Auth != "authelia" {
		t.Fatalf("auth policy should round-trip, got %+v", r2)
	}
}

// TestAuth_DefaultMiddlewareConvention: with no auth_policies config, crenel uses
// the "<policy>@file" convention and still round-trips the policy name.
func TestAuth_DefaultMiddlewareConvention(t *testing.T) {
	path := tempConfig(t, `{}`)
	d := authDriver(path, nil)
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(op, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	cfg := readBack(t, path)
	if r := cfg.HTTP.Routers["crenel-grafana.example.com"]; r == nil || r.Middlewares[0] != "authelia@file" {
		t.Fatalf("default convention should be authelia@file, got %+v", r)
	}
	after, _ := d.ReadLiveState(ctx)
	if r := routeFor(after, "grafana.example.com"); r == nil || r.Upstream.Auth != "authelia" {
		t.Fatalf("convention middleware should reverse to the policy, got %+v", r)
	}
}

// TestAuth_RecognizesBrownfieldMiddleware: an UNMANAGED router with an auth-ish
// middleware surfaces as "(detected)" (recognition), while a non-auth middleware
// chain is NOT falsely claimed as auth.
func TestAuth_RecognizesBrownfieldMiddleware(t *testing.T) {
	seed := `{"http":{
		"routers":{
			"authelia":{"rule":"Host(` + "`auth.example.com`" + `)","service":"authelia-svc","middlewares":["authelia-forward"]},
			"plain":{"rule":"Host(` + "`plain.example.com`" + `)","service":"plain-svc","middlewares":["secheaders"]}
		},
		"services":{
			"authelia-svc":{"loadBalancer":{"servers":[{"url":"http://10.0.0.9:9091"}]}},
			"plain-svc":{"loadBalancer":{"servers":[{"url":"http://10.0.0.3:80"}]}}
		}
	}}`
	path := tempConfig(t, seed)
	d := authDriver(path, nil)
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := routeFor(live, "auth.example.com"); r == nil || r.Upstream.Auth != model.AuthDetected {
		t.Fatalf("auth-ish middleware should be recognized, got %+v", r)
	}
	if r := routeFor(live, "plain.example.com"); r == nil || r.Upstream.Auth != "" {
		t.Fatalf("a non-auth middleware must not be claimed as auth, got %+v", r)
	}
}

func routeFor(live model.LiveEdgeState, host string) *model.Route {
	for i := range live.Routes {
		if live.Routes[i].Host == host {
			return &live.Routes[i]
		}
	}
	return nil
}
