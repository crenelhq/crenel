package nginx

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestAuth_RendersAuthRequestByReference proves a crenel-managed expose with a
// forward-auth policy emits an `auth_request <uri>;` reference inside location /,
// and the policy round-trips on read-back.
func TestAuth_RendersAuthRequestByReference(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver(), WithAuthRequests(map[string]string{"authelia": "/authelia"}))
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

	out := readFile(t, path)
	if !strings.Contains(out, "auth_request /authelia;") {
		t.Fatalf("rendered config should reference auth_request:\n%s", out)
	}
	// auth_request must sit inside the managed server's location /, before proxy_pass.
	if !strings.Contains(out, "auth_request /authelia;\n        proxy_pass") {
		t.Errorf("auth_request should precede proxy_pass in location /:\n%s", out)
	}

	after, _ := d.ReadLiveState(ctx)
	r := routeFor(after, "grafana.example.com")
	if r == nil || r.Upstream.Auth != "authelia" {
		t.Fatalf("auth policy should round-trip, got %+v", r)
	}
	if !after.DenyCatchAllPresent {
		t.Error("default-deny must still hold")
	}
}

// TestAuth_DefaultURIConvention: with no auth_requests config, crenel uses the
// "/<policy>" convention and round-trips the policy name.
func TestAuth_DefaultURIConvention(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver()) // no WithAuthRequests
	ctx := context.Background()

	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com", Auth: "authelia"}
	live, _ := d.ReadLiveState(ctx)
	cs, _ := d.Plan(op, live)
	if err := d.Apply(ctx, cs); err != nil {
		t.Fatal(err)
	}
	if out := readFile(t, path); !strings.Contains(out, "auth_request /authelia;") {
		t.Fatalf("default convention should be /authelia:\n%s", out)
	}
	after, _ := d.ReadLiveState(ctx)
	if r := routeFor(after, "grafana.example.com"); r == nil || r.Upstream.Auth != "authelia" {
		t.Fatalf("convention URI should reverse to the policy, got %+v", r)
	}
}

// TestAuth_PreservedAcrossUnrelatedReRender proves that re-rendering (a second
// expose of a DIFFERENT host) preserves an existing managed host's auth_request.
func TestAuth_PreservedAcrossUnrelatedReRender(t *testing.T) {
	path := tempConfig(t, "")
	d := New(path, resolver(), WithAuthRequests(map[string]string{"authelia": "/authelia"}))
	ctx := context.Background()

	expose := func(host, service, auth string) {
		op := model.Op{Verb: model.Expose, Service: service, Host: host, Auth: auth}
		live, _ := d.ReadLiveState(ctx)
		cs, err := d.Plan(op, live)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Apply(ctx, cs); err != nil {
			t.Fatal(err)
		}
	}
	expose("grafana.example.com", "grafana", "authelia")
	expose("photos.example.com", "photos", "") // no auth on this one

	out := readFile(t, path)
	if !strings.Contains(out, "auth_request /authelia;") {
		t.Fatalf("grafana's auth_request must survive a re-render for photos:\n%s", out)
	}
	after, _ := d.ReadLiveState(ctx)
	if r := routeFor(after, "grafana.example.com"); r == nil || r.Upstream.Auth != "authelia" {
		t.Errorf("grafana should still carry auth, got %+v", r)
	}
	if r := routeFor(after, "photos.example.com"); r == nil || r.Upstream.Auth != "" {
		t.Errorf("photos should have no auth, got %+v", r)
	}
}

// TestAuth_RecognizesBrownfieldAuthRequest: an UNMANAGED server block with an
// auth_request surfaces as "(detected)".
func TestAuth_RecognizesBrownfieldAuthRequest(t *testing.T) {
	seed := `# operator-owned
server {
    listen 443 ssl;
    server_name secure.example.com;
    location / {
        auth_request /verify;
        proxy_pass http://10.0.0.8:80;
    }
}
`
	path := tempConfig(t, seed)
	d := New(path, resolver())
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := routeFor(live, "secure.example.com"); r == nil || r.Upstream.Auth != model.AuthDetected {
		t.Fatalf("brownfield auth_request should be recognized, got %+v", r)
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
