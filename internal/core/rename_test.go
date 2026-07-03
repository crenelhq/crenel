package core_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

func renameEdge(t *testing.T, fake *caddyfake.Fake, opts ...caddy.Option) *core.Engine {
	t.Helper()
	res := static.New(map[string]string{})
	o := append([]caddy.Option{caddy.WithGranularApply()}, opts...)
	return core.New(caddy.New(fake.URL(), res, o...), "example.com")
}

// seedRoute is a single crenel-managed http route + a deny, for the rename tests.
const seedPlainOld = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
 {"@id":"crenel-route-old.example.com","match":[{"host":["old.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
 {"handle":[{"handler":"static_response","status_code":403}]}
]}}}}}`

// TestRename_MovesPlainHostAtomically is the core proof: rename copies the source route's
// backend to the new host and removes the old, as one verified transaction.
func TestRename_MovesPlainHostAtomically(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(seedPlainOld); err != nil {
		t.Fatal(err)
	}
	e := renameEdge(t, fake)
	ctx := context.Background()

	rep, err := e.Rename(ctx, "old.example.com", "new.example.com", core.AlwaysYes)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if !rep.Applied || !rep.Verified() {
		t.Fatalf("expected applied+verified, got %+v", rep)
	}
	st, _ := e.Status(ctx)
	es := only(st)
	var newR, oldR *model.Route
	for i := range es.Routes {
		switch es.Routes[i].Host {
		case "new.example.com":
			newR = &es.Routes[i]
		case "old.example.com":
			oldR = &es.Routes[i]
		}
	}
	if oldR != nil {
		t.Fatalf("old host must be gone after rename, still present")
	}
	if newR == nil {
		t.Fatalf("new host must be present after rename; hosts: %v", es.Routes)
	}
	if newR.Upstream.Address != "10.0.0.5:3000" {
		t.Fatalf("new host must copy the source backend, got %q", newR.Upstream.Address)
	}
}

// TestRename_CopiesAuthPolicy proves the ergonomic win: the source route's auth policy is
// carried to the new host (the operator does not re-specify it).
func TestRename_CopiesAuthPolicy(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	// Source carries a crenel auth marker (policy "authelia") + the backend.
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"@id":"crenel-route-old.example.com","match":[{"host":["old.example.com"]}],"handle":[{"handler":"vars","crenel_policy":"authelia"},{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	authRef := caddy.WithAuthPolicies(map[string]caddy.AuthRef{"authelia": {
		ForwardAuth: "authelia:9080",
		VerifyURI:   "/api/verify?rd=https://auth.example.com",
		CopyHeaders: []string{"Remote-User"},
	}})
	e := renameEdge(t, fake, authRef)
	ctx := context.Background()

	rep, err := e.Rename(ctx, "old.example.com", "new.example.com", core.AlwaysYes)
	if err != nil {
		t.Fatalf("rename (auth): %v", err)
	}
	if !rep.Verified() {
		t.Fatalf("expected verified, got %+v", rep)
	}
	st, _ := e.Status(ctx)
	for _, r := range only(st).Routes {
		if r.Host == "new.example.com" {
			if r.Upstream.Auth == "" || r.Upstream.Auth == model.AuthNone {
				t.Fatalf("renamed host must carry the copied auth policy, got %q", r.Upstream.Auth)
			}
			return
		}
	}
	t.Fatal("new host not found after auth-copy rename")
}

// TestRename_RefusesWhenNewExists: no silent overwrite of an existing host.
func TestRename_RefusesWhenNewExists(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"@id":"crenel-route-old.example.com","match":[{"host":["old.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
	 {"@id":"crenel-route-new.example.com","match":[{"host":["new.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:3000"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	e := renameEdge(t, fake)
	_, err := e.Rename(context.Background(), "old.example.com", "new.example.com", core.AlwaysYes)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refusal that new host exists, got: %v", err)
	}
}

// TestRename_RefusesWhenOldAbsent: nothing to rename.
func TestRename_RefusesWhenOldAbsent(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(seedPlainOld); err != nil {
		t.Fatal(err)
	}
	e := renameEdge(t, fake)
	_, err := e.Rename(context.Background(), "absent.example.com", "new.example.com", core.AlwaysYes)
	if err == nil || !strings.Contains(err.Error(), "not exposed") {
		t.Fatalf("expected refusal that old host is absent, got: %v", err)
	}
}

// TestRename_RefusesForeignSource: the refuse-to-manage gate blocks renaming a route owned
// by a config generator (a crenel edit would be reverted at the source).
func TestRename_RefusesForeignSource(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{{
			Host:      "old.example.com",
			Ownership: model.OwnForeign,
			Upstream:  model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "old.example.com"},
		}},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	_, err := e.Rename(context.Background(), "old.example.com", "new.example.com", core.AlwaysYes)
	if err == nil || !errors.Is(err, core.ErrRefuseToManage) {
		t.Fatalf("expected refuse-to-manage on a foreign source, got: %v", err)
	}
}
