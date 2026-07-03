package model_test

import (
	"errors"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

func liveWith(deny bool, hosts ...string) model.LiveEdgeState {
	s := model.LiveEdgeState{DenyCatchAllPresent: deny}
	for _, h := range hosts {
		s.Routes = append(s.Routes, model.Route{Host: h, Upstream: model.Upstream{Address: "x"}})
	}
	return s
}

func TestReachable_StructuralDefaultDeny(t *testing.T) {
	// A host is reachable IFF it is explicitly exposed AND the catch-all deny
	// is present. This is the core safety property.
	s := liveWith(true, "a.example.com")

	if !s.Reachable("a.example.com") {
		t.Error("exposed host with deny present should be reachable")
	}
	if !s.Reachable("A.EXAMPLE.COM") {
		t.Error("reachability should be case-insensitive")
	}
	// Negative: an un-exposed host is NEVER reachable.
	if s.Reachable("b.example.com") {
		t.Error("un-exposed host must never be reachable")
	}

	// If the deny vanished, reachability semantics flip to fail-open — but our
	// model reports unreachable for explicit hosts too, forcing audit to flag
	// the missing deny rather than silently trusting routes.
	noDeny := liveWith(false, "a.example.com")
	if noDeny.Reachable("a.example.com") {
		t.Error("with deny missing, Reachable must be false (fail-closed reporting)")
	}
}

func TestChangeSetEmpty(t *testing.T) {
	if !(model.ChangeSet{}).Empty() {
		t.Error("zero ChangeSet should be empty")
	}
	cs := model.ChangeSet{Edge: model.EdgeChange{AddRoutes: []model.Route{{Host: "h"}}}}
	if cs.Empty() {
		t.Error("ChangeSet with an add should not be empty")
	}
	cs2 := model.ChangeSet{DNS: []model.DNSChange{{Add: []model.Record{{Name: "x"}}}}}
	if cs2.Empty() {
		t.Error("ChangeSet with a DNS add should not be empty")
	}
}

func TestRecordKey(t *testing.T) {
	r := model.Record{Name: "Grafana", Type: "A", Value: "1.2.3.4", Scope: model.ScopeInternal}
	if r.Key() != "internal/A/grafana" {
		t.Errorf("unexpected key %q", r.Key())
	}
}

func TestValidateAuth_HTTPOnly(t *testing.T) {
	cases := []struct {
		name    string
		mode    model.RouteMode
		auth    string
		wantErr bool
	}{
		{"http+policy ok", model.ModeHTTPProxy, "authelia", false},
		{"http+none ok", model.ModeHTTPProxy, model.AuthNone, false},
		{"http+empty ok", model.ModeHTTPProxy, "", false},
		{"passthrough+empty ok", model.ModeTCPPassthrough, "", false},
		{"passthrough+none ok", model.ModeTCPPassthrough, model.AuthNone, false},
		{"passthrough+policy refused", model.ModeTCPPassthrough, "authelia", true},
		{"mesh+policy refused", model.ModeMeshGrant, "authelia", true},
		{"mesh+none ok", model.ModeMeshGrant, model.AuthNone, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := model.ValidateAuth(c.mode, c.auth)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, model.ErrAuthUnsupportedForMode) {
					t.Fatalf("error must wrap ErrAuthUnsupportedForMode, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOp_HasAuthPolicy(t *testing.T) {
	if (model.Op{Auth: ""}).HasAuthPolicy() {
		t.Error("empty auth is not a policy")
	}
	if (model.Op{Auth: model.AuthNone}).HasAuthPolicy() {
		t.Error("explicit none is not a policy")
	}
	if !(model.Op{Auth: "authelia"}).HasAuthPolicy() {
		t.Error("a named policy is a policy")
	}
}
