package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// TestChain_FrontEdgeSuppressesPublicWithoutAuth proves the chain mitigation: a
// FRONT edge (AuthDownstream) carries no auth of its own because auth is enforced
// one hop downstream, so audit must NOT fire public_without_auth for its hosts —
// instead it emits an informational auth_downstream finding. A genuine TERMINAL
// edge with the same hosts still warns.
func TestChain_FrontEdgeSuppressesPublicWithoutAuth(t *testing.T) {
	live := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		httpRoute("vault.example.com"),
		httpRoute("git.example.com"),
	}}

	// Front edge: auth lives downstream -> suppressed.
	front := stubEdge{name: "caddy", live: live}
	eFront := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: front, AuthDownstream: true}}, "example.com")
	rep, err := eFront.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("front edge (auth downstream) must NOT warn public_without_auth:\n%+v", rep.Findings)
	}
	f, ok := findCode(rep, "auth_downstream")
	if !ok || f.Severity != "ok" {
		t.Fatalf("expected an informational auth_downstream finding, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "vault.example.com") || !strings.Contains(f.Message, "git.example.com") {
		t.Errorf("auth_downstream finding should name the suppressed hosts, got %q", f.Message)
	}

	// Terminal edge: same hosts, no downstream assertion -> the warning fires.
	term := stubEdge{name: "caddy", live: live}
	eTerm := core.NewMulti([]core.EdgeBinding{{Name: "edge", Provider: term}}, "example.com")
	repT, err := eTerm.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(repT, "public_without_auth"); !ok {
		t.Errorf("terminal edge with public no-auth hosts MUST still warn public_without_auth:\n%+v", repT.Findings)
	}
	if _, ok := findCode(repT, "auth_downstream"); ok {
		t.Errorf("terminal edge must not emit auth_downstream:\n%+v", repT.Findings)
	}
}

// TestChain_RealAuthStillBeatsDownstream proves a real auth reference read from a
// front edge wins over the downstream label (a host genuinely gated at the front
// edge is reported with its real policy, not "downstream"), and is never warned.
func TestChain_RealAuthAndStatusLabel(t *testing.T) {
	withAuth := httpRoute("authd.example.com")
	withAuth.Upstream.Auth = "authelia"
	live := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		withAuth,
		httpRoute("plain.example.com"),
	}}
	front := stubEdge{name: "caddy", live: live}
	e := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: front, AuthDownstream: true}}, "example.com")

	// status: the no-auth host is labeled downstream; the real-auth host keeps its
	// policy; neither is mutated in live (the overlay is display-only on a copy).
	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range st.Edges[0].Routes {
		got[r.Host] = r.Upstream.Auth
	}
	if got["plain.example.com"] != model.AuthDownstream {
		t.Errorf("plain host should be labeled %q, got %q", model.AuthDownstream, got["plain.example.com"])
	}
	if got["authd.example.com"] != "authelia" {
		t.Errorf("real-auth host should keep its policy, got %q", got["authd.example.com"])
	}

	// audit: neither host warns (one real auth, one downstream).
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("no host should warn public_without_auth here:\n%+v", rep.Findings)
	}
}

// TestChain_DownstreamDoesNotMaskMeshOrDeny proves the chain label is scoped: it
// never annotates a mesh-grant route (identity-enforced, never public) and never
// affects the default-deny invariant.
func TestChain_DownstreamScoped(t *testing.T) {
	mesh := model.Route{Host: "m.example.com", Upstream: model.Upstream{Mode: model.ModeMeshGrant, Address: "mesh-grant:admins"}}
	live := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{mesh}}
	front := stubEdge{name: "caddy", live: live}
	e := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: front, AuthDownstream: true}}, "example.com")

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a := st.Edges[0].Routes[0].Upstream.Auth; a != "" {
		t.Errorf("mesh-grant route must not be labeled downstream, got %q", a)
	}
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "auth_downstream"); ok {
		t.Errorf("a mesh-only front edge has no public host to suppress:\n%+v", rep.Findings)
	}
}
