package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// zones_interface_test.go — the multi-zone INTERFACE layer (`zones:` list):
// bare-name host derivation across ALL managed zones (ResolveOp) and the
// evidence-gated serviceOf strip. The zone ROUTING mechanism itself is proven
// by dns_multizone_test.go; these tests prove the operator-facing naming rules
// layered on top of it.

// zonesTestEngine wires two stub edges (explicit Fronts predicates — the
// origins-keying EVIDENCE ResolveOp/serviceOf reason over) plus zone-declaring
// DNS providers for zoneA (the top-level default) and zoneB.
func zonesTestEngine(fronts1, fronts2 map[string]bool, live1, live2 []model.Route) *core.Engine {
	e1 := stubEdge{name: "one", live: model.LiveEdgeState{DenyCatchAllPresent: true, Routes: live1}}
	e2 := stubEdge{name: "two", live: model.LiveEdgeState{DenyCatchAllPresent: true, Routes: live2}}
	pred := func(m map[string]bool) func(string) bool {
		if m == nil {
			return nil // fronts-everything: carries no keying evidence
		}
		return func(s string) bool { return m[s] }
	}
	dns := []ports.DNSProvider{
		&zonedStubDNS{stubDNS: stubDNS{name: "resolver-a", scope: model.ScopeInternal}, zone: zoneA},
		&zonedStubDNS{stubDNS: stubDNS{name: "resolver-b", scope: model.ScopeInternal}, zone: zoneB},
	}
	return core.NewMulti([]core.EdgeBinding{
		{Name: "one", Provider: e1, Fronts: pred(fronts1)},
		{Name: "two", Provider: e2, Fronts: pred(fronts2)},
	}, zoneA, dns...)
}

// A full FQDN always works verbatim — in ANY managed zone, no derivation.
func TestResolveOp_FQDNPassthrough(t *testing.T) {
	e := zonesTestEngine(map[string]bool{}, map[string]bool{}, nil, nil)
	op, err := e.ResolveOp(model.Expose, "auth."+zoneB)
	if err != nil {
		t.Fatal(err)
	}
	if op.Host != "auth."+zoneB || op.Service != "auth."+zoneB {
		t.Errorf("FQDN must pass through verbatim, got service=%q host=%q", op.Service, op.Host)
	}
}

// A bare name with no contrary evidence keeps the CLASSIC default-zone
// derivation — byte-identical to BuildOp for every existing config, including
// engines whose edges front everything (nil predicate = no evidence at all).
func TestResolveOp_BareDefaultDerivationUnchanged(t *testing.T) {
	for name, e := range map[string]*core.Engine{
		"no evidence anywhere":  zonesTestEngine(map[string]bool{}, map[string]bool{}, nil, nil),
		"fronts-everything":     zonesTestEngine(nil, nil, nil, nil),
		"bare key evidence":     zonesTestEngine(map[string]bool{"grafana": true}, map[string]bool{}, nil, nil),
		"default FQDN evidence": zonesTestEngine(map[string]bool{"grafana." + zoneA: true}, map[string]bool{}, nil, nil),
	} {
		op, err := e.ResolveOp(model.Expose, "grafana")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := e.BuildOp(model.Expose, "grafana")
		if op.Service != want.Service || op.Host != want.Host {
			t.Errorf("%s: bare default derivation changed: got %+v want %+v", name, op, want)
		}
	}
}

// A bare name known ONLY under a non-default managed zone (its origins entry is
// keyed by that zone's FQDN) resolves there — Service AND Host become the FQDN
// so every downstream Fronts/origins lookup hits the key that actually exists.
func TestResolveOp_BareUniqueNonDefaultZoneResolves(t *testing.T) {
	e := zonesTestEngine(map[string]bool{"auth." + zoneB: true}, map[string]bool{}, nil, nil)
	op, err := e.ResolveOp(model.Expose, "auth")
	if err != nil {
		t.Fatal(err)
	}
	if op.Service != "auth."+zoneB || op.Host != "auth."+zoneB {
		t.Errorf("unique non-default-zone bare name must resolve to its FQDN, got service=%q host=%q", op.Service, op.Host)
	}
}

// A bare name with evidence under TWO managed zones is REFUSED loudly, listing
// every candidate FQDN — the operator must say the host out loud.
func TestResolveOp_BareAmbiguousAcrossZonesRefused(t *testing.T) {
	e := zonesTestEngine(map[string]bool{"auth": true, "auth." + zoneB: true}, map[string]bool{}, nil, nil)
	_, err := e.ResolveOp(model.Expose, "auth")
	if err == nil {
		t.Fatal("ambiguous bare name must refuse")
	}
	for _, want := range []string{"ambiguous", "auth." + zoneA, "auth." + zoneB} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must name the candidates (%q missing): %v", want, err)
		}
	}
}

// serviceOf strips a PROVIDER-managed zone suffix only with evidence that the
// bare name is how the operator keys the service. Observable through the
// cross-edge consistency audit: a zoneB host live on edge one and missing from
// edge two — which fronts the service under its BARE key — must now flag the
// half-applied double-write. (The FQDN-keyed shape is byte-identical to before:
// dns_multizone_test.go keeps proving it.)
func TestServiceOf_BareKeyedNonDefaultZoneHostIsRecognized(t *testing.T) {
	host := "auth." + zoneB
	e := zonesTestEngine(
		map[string]bool{"auth": true}, map[string]bool{"auth": true},
		[]model.Route{httpRoute(host)}, nil, // live on edge one, missing from edge two
	)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_inconsistent_exposure")
	if !ok || !strings.Contains(f.Message, host) {
		t.Errorf("bare-keyed zoneB host must be mapped to its service across edges; findings: %+v", rep.Findings)
	}
}
