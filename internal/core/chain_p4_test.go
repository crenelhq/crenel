package core_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// fwdRoute is a FRONT-edge route whose backend dials the downstream edge's address
// (so chain resolution recognizes it as a forward, not a terminal origin).
func fwdRoute(host, downstreamAddr string) model.Route {
	return model.Route{Host: host, Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: downstreamAddr, ServerName: host}}
}

// downRoute is a DOWNSTREAM-edge per-host route to a real backend, optionally with a
// forward-auth policy enforced there.
func downRoute(host, backend, auth string) model.Route {
	return model.Route{Host: host, Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: backend, ServerName: host, Auth: auth}}
}

// errEdge is an edge whose live read always fails — used to prove a chain-target's
// read failure degrades to "downstream, not observed" instead of aborting.
type errEdge struct{ name string }

func (e errEdge) Name() string                   { return e.name }
func (e errEdge) Validate(context.Context) error { return nil }
func (e errEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return model.LiveEdgeState{}, fmt.Errorf("admin API unreachable")
}
func (e errEdge) Plan(op model.Op, _ model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{Op: op}, nil
}
func (e errEdge) Apply(context.Context, model.ChangeSet) error { return nil }

func statusEdge(rep core.StatusReport, name string) (core.EdgeStatus, bool) {
	for _, es := range rep.Edges {
		if es.Name == name {
			return es, true
		}
	}
	return core.EdgeStatus{}, false
}

func routeByHost(es core.EdgeStatus, host string) (model.Route, bool) {
	for _, r := range es.Routes {
		if strings.EqualFold(r.Host, host) {
			return r, true
		}
	}
	return model.Route{}, false
}

// chainEngine builds the canonical two-edge chain: a VPS front forwarding everything
// to a downstream HOME edge whose per-host routes carry the REAL backends + auth.
// Mirrors the maintainer's shape: a downstream Authelia-protected host + a downstream no-auth host.
func chainEngine(front, home model.LiveEdgeState) *core.Engine {
	return core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: stubEdge{name: "caddy", live: front}, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: stubEdge{name: "caddy", live: home}},
	}, "homelab.example")
}

// TestChainP4_StatusFollowsThrough proves the front edge's forwarded hosts are
// resolved THROUGH to their real downstream destination + the auth OBSERVED there.
func TestChainP4_StatusFollowsThrough(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("vault.homelab.example", "10.0.0.13:443"),
		fwdRoute("books.homelab.example", "10.0.0.13:443"),
	}}
	home := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		downRoute("vault.homelab.example", "10.0.0.7:8200", "authelia"),
		downRoute("books.homelab.example", "10.0.0.9:80", ""), // no auth downstream
	}}
	e := chainEngine(front, home)

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vps, ok := statusEdge(st, "vps")
	if !ok {
		t.Fatal("vps edge missing from status")
	}

	vault, ok := routeByHost(vps, "vault.homelab.example")
	if !ok {
		t.Fatal("vault route missing")
	}
	if vault.Chain == nil || !vault.Chain.Resolved {
		t.Fatalf("vault should resolve through the chain, got %+v", vault.Chain)
	}
	if vault.Chain.DownstreamEdge != "home" || vault.Chain.DownstreamAddress != "10.0.0.7:8200" {
		t.Errorf("vault chain destination wrong: %+v", vault.Chain)
	}
	if vault.Chain.DownstreamAuth != "authelia" {
		t.Errorf("vault downstream auth should be observed as authelia, got %q", vault.Chain.DownstreamAuth)
	}
	if vault.Upstream.Auth != "authelia" {
		t.Errorf("vault display auth should be the observed downstream policy, got %q", vault.Upstream.Auth)
	}

	books, _ := routeByHost(vps, "books.homelab.example")
	if books.Chain == nil || !books.Chain.Resolved {
		t.Fatalf("books should resolve through the chain, got %+v", books.Chain)
	}
	if books.Chain.DownstreamAddress != "10.0.0.9:80" {
		t.Errorf("books downstream backend wrong: %+v", books.Chain)
	}
	if books.Chain.DownstreamAuth != "" || books.Upstream.Auth != "" {
		t.Errorf("books has NO auth downstream — must read as unprotected, got chain=%q display=%q",
			books.Chain.DownstreamAuth, books.Upstream.Auth)
	}

	// The freshly-read live state must NOT be mutated by the display overlay: the home
	// edge's own row still shows its real terminal backends + auth.
	homeEdge, _ := statusEdge(st, "home")
	hv, _ := routeByHost(homeEdge, "vault.homelab.example")
	if hv.Chain != nil {
		t.Errorf("downstream edge's own route must not carry a ChainLink, got %+v", hv.Chain)
	}
	if hv.Upstream.Auth != "authelia" {
		t.Errorf("home vault should keep its real auth, got %q", hv.Upstream.Auth)
	}
}

// TestChainP4_AuditResolvesAuthByObservation proves audit resolves
// public_without_auth by OBSERVATION across the chain — NOT by blanket suppression.
// The front carries NO auth_downstream flag, yet the downstream-Authelia host is not
// flagged (observed protected) while the downstream-no-auth host IS flagged.
func TestChainP4_AuditResolvesAuthByObservation(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("vault.homelab.example", "10.0.0.13:443"),
		fwdRoute("books.homelab.example", "10.0.0.13:443"),
	}}
	home := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		downRoute("vault.homelab.example", "10.0.0.7:8200", "authelia"),
		downRoute("books.homelab.example", "10.0.0.9:80", ""),
	}}
	e := chainEngine(front, home) // note: NO AuthDownstream flag on the front

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The protected host must NOT be flagged; the unprotected one MUST be.
	for _, f := range rep.Findings {
		if f.Code == "public_without_auth" && strings.Contains(f.Message, "vault.homelab.example") {
			t.Errorf("vault is protected downstream (observed) — must NOT be flagged: %q", f.Message)
		}
	}
	var booksFlagged bool
	for _, f := range rep.Findings {
		if f.Code == "public_without_auth" && strings.Contains(f.Message, "books.homelab.example") {
			booksFlagged = true
		}
	}
	if !booksFlagged {
		t.Errorf("books has no auth anywhere on the chain — MUST be flagged public_without_auth:\n%+v", rep.Findings)
	}
	// Observation, not blanket suppression: the auth_downstream (flag) finding must NOT
	// appear, and the chain follow-through must be reported as resolved.
	if _, ok := findCode(rep, "auth_downstream"); ok {
		t.Errorf("protection was resolved by OBSERVATION — the blanket auth_downstream finding must not fire:\n%+v", rep.Findings)
	}
	f, ok := findCode(rep, "chain_resolved")
	if !ok || f.Severity != "ok" {
		t.Fatalf("expected an informational chain_resolved finding, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "vault.homelab.example") || !strings.Contains(f.Message, "10.0.0.7:8200") {
		t.Errorf("chain_resolved should name the followed-through destination, got %q", f.Message)
	}
}

// TestChainP4_AuditUnreadableDownstreamFallsBack proves that when the downstream edge
// is unreadable the forwards FALL BACK to the auth_downstream assertion (suppress, not
// flag) but are honestly DECLARED unresolved (chain_unresolved + edge_unreadable),
// never a silent misread.
func TestChainP4_AuditUnreadableDownstreamFallsBack(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("vault.homelab.example", "10.0.0.13:443"),
	}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: stubEdge{name: "caddy", live: front}, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: errEdge{name: "caddy"}},
	}, "homelab.example")

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatalf("audit must not abort on an unreadable chain target: %v", err)
	}
	if _, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("an unresolved forward asserts downstream auth — must NOT flag public_without_auth:\n%+v", rep.Findings)
	}
	if f, ok := findCode(rep, "chain_unresolved"); !ok || f.Severity != "warning" {
		t.Fatalf("expected a chain_unresolved warning, got %+v", rep.Findings)
	}
	if f, ok := findCode(rep, "edge_unreadable"); !ok || f.Severity != "warning" {
		t.Fatalf("expected an edge_unreadable warning for the home edge, got %+v", rep.Findings)
	}
}

// TestChainP4_DownstreamNotConfigured: a front naming a downstream edge absent from
// the topology declares the forwards unresolved (never assumed safe).
func TestChainP4_DownstreamNotConfigured(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("vault.homelab.example", "10.0.0.13:443"),
	}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: stubEdge{name: "caddy", live: front}, DownstreamEdge: "ghost", DownstreamAddress: "10.0.0.13"},
	}, "homelab.example")

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vps, _ := statusEdge(st, "vps")
	vault, _ := routeByHost(vps, "vault.homelab.example")
	if vault.Chain == nil || vault.Chain.Resolved {
		t.Fatalf("vault should be UNRESOLVED (ghost downstream), got %+v", vault.Chain)
	}
	if !strings.Contains(vault.Chain.Reason, "not configured") {
		t.Errorf("reason should explain the downstream is not configured, got %q", vault.Chain.Reason)
	}
	if vault.Upstream.Auth != model.AuthDownstream {
		t.Errorf("unresolved forward should fall back to the downstream assertion, got %q", vault.Upstream.Auth)
	}
}

// TestChainP4_DownstreamNotRouted: a readable downstream that does NOT route the host
// (a dangling forward) declares it unresolved, not silently protected.
func TestChainP4_DownstreamNotRouted(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("ghosthost.homelab.example", "10.0.0.13:443"),
	}}
	home := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		downRoute("other.homelab.example", "10.0.0.7:8200", "authelia"),
	}}
	e := chainEngine(front, home)

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vps, _ := statusEdge(st, "vps")
	gh, _ := routeByHost(vps, "ghosthost.homelab.example")
	if gh.Chain == nil || gh.Chain.Resolved {
		t.Fatalf("dangling forward should be UNRESOLVED, got %+v", gh.Chain)
	}
	if !strings.Contains(gh.Chain.Reason, "not routed") {
		t.Errorf("reason should explain the host is not routed downstream, got %q", gh.Chain.Reason)
	}
}

// TestChainP4_DownstreamUnreadable: a chain-target edge whose read FAILS does not
// abort status — the front declares its forwards "downstream, not observed" and the
// target edge surfaces as a DECLARED-UNKNOWN row (deny UNKNOWN), never a misread.
func TestChainP4_DownstreamUnreadable(t *testing.T) {
	front := model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
		fwdRoute("vault.homelab.example", "10.0.0.13:443"),
	}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: stubEdge{name: "caddy", live: front}, DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: errEdge{name: "caddy"}},
	}, "homelab.example")

	st, err := e.Status(context.Background())
	if err != nil {
		t.Fatalf("status must not abort on an unreadable chain target, got %v", err)
	}
	vps, _ := statusEdge(st, "vps")
	vault, _ := routeByHost(vps, "vault.homelab.example")
	if vault.Chain == nil || vault.Chain.Resolved {
		t.Fatalf("vault should be UNRESOLVED (downstream unreadable), got %+v", vault.Chain)
	}
	if !strings.Contains(vault.Chain.Reason, "could not be read") {
		t.Errorf("reason should explain the downstream was unreadable, got %q", vault.Chain.Reason)
	}
	homeEdge, ok := statusEdge(st, "home")
	if !ok {
		t.Fatal("unreadable home edge should still surface as a row")
	}
	if homeEdge.DenyState() != model.DenyUnknown {
		t.Errorf("unreadable edge deny should be UNKNOWN (declared), got %s", homeEdge.DenyState())
	}
	if homeEdge.FullyParsed() {
		t.Errorf("unreadable edge must not read as fully parsed")
	}
}
