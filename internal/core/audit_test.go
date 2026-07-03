package core_test

import (
	"context"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// stubDNS is an in-test DNSProvider used to exercise cross-provider audit.
type stubDNS struct {
	name  string
	scope model.Scope
	live  []model.Record
}

func (s *stubDNS) Name() string       { return s.name }
func (s *stubDNS) Scope() model.Scope { return s.scope }
func (s *stubDNS) DesiredRecords(op model.Op) ([]model.Record, error) {
	return []model.Record{{Name: op.Host, Type: "A", Value: "1.2.3.4", Scope: s.scope}}, nil
}
func (s *stubDNS) Diff(context.Context, model.Op, []model.Record) (model.DNSChange, error) {
	return model.DNSChange{Scope: s.scope}, nil
}
func (s *stubDNS) Apply(context.Context, model.DNSChange) error { return nil }
func (s *stubDNS) LiveRecords(context.Context) ([]model.Record, error) {
	return s.live, nil
}

// stubEdge is a fixed-live-state edge double for crafting precise audit inputs
// (specific modes / SNI) that the real normalizers wouldn't naturally produce.
type stubEdge struct {
	name string
	live model.LiveEdgeState
}

func (s stubEdge) Name() string                   { return s.name }
func (s stubEdge) Validate(context.Context) error { return nil }
func (s stubEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return s.live, nil
}
func (s stubEdge) Plan(op model.Op, _ model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{Op: op}, nil
}
func (s stubEdge) Apply(context.Context, model.ChangeSet) error { return nil }

func httpRoute(host string) model.Route {
	return model.Route{Host: host, Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: host}}
}

func TestAudit_SNIHostMismatchIsWarning(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "a.example.com", Upstream: model.Upstream{
			Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "wrong.example.com"}}},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "sni_host_mismatch"); !ok || f.Severity != "warning" {
		t.Errorf("expected SNI mismatch warning, got %+v", rep.Findings)
	}
}

func TestAudit_EdgeModeMismatchIsWarning(t *testing.T) {
	home := stubEdge{name: "caddy", live: model.LiveEdgeState{DenyCatchAllPresent: true,
		Routes: []model.Route{httpRoute("x.example.com")}}}
	mesh := stubEdge{name: "netbird", live: model.LiveEdgeState{DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "x.example.com", Upstream: model.Upstream{Mode: model.ModeMeshGrant, Address: "mesh-grant:admins"}}}}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: home}, {Name: "vps", Provider: mesh}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "edge_mode_mismatch"); !ok || f.Severity != "warning" {
		t.Errorf("expected cross-edge mode mismatch warning, got %+v", rep.Findings)
	}
}

func TestAudit_PublicDNSForMeshGrantIsWarning(t *testing.T) {
	mesh := stubEdge{name: "netbird", live: model.LiveEdgeState{DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "vault.example.com", Upstream: model.Upstream{Mode: model.ModeMeshGrant, Address: "mesh-grant:admins"}}}}}
	dns := &stubDNS{name: "dnscontrol", scope: model.ScopePublic, live: []model.Record{
		{Name: "vault.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: mesh}}, "example.com", dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "public_dns_for_mesh_grant"); !ok || f.Severity != "warning" {
		t.Errorf("expected public-DNS-for-mesh-grant warning, got %+v", rep.Findings)
	}
}

func auditEngine(t *testing.T, seed string, dns ...*stubDNS) *core.Engine {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile(seed)
	res := static.New(map[string]string{"grafana": "10.0.0.5:3000"})
	edge := caddy.New(fake.URL(), res)
	var dps []ports.DNSProvider
	for _, d := range dns {
		dps = append(dps, d)
	}
	return core.New(edge, "example.com", dps...)
}

func findCode(r core.AuditReport, code string) (core.AuditFinding, bool) {
	for _, f := range r.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return core.AuditFinding{}, false
}

func TestAudit_DenyPresentIsOK(t *testing.T) {
	e := auditEngine(t, seedGrafana)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "deny_catchall_present"); !ok || f.Severity != "ok" {
		t.Errorf("expected deny present OK, got %+v", rep.Findings)
	}
	if rep.HasCritical() {
		t.Error("healthy config should have no critical findings")
	}
}

func TestAudit_FailOpenCatchAllIsCritical(t *testing.T) {
	// A host-less reverse_proxy forwards every host => genuinely fail-open.
	e := auditEngine(t, ":443 {\n\treverse_proxy 10.9.9.9:80\n}\n")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "deny_catchall_missing")
	if !ok || f.Severity != "critical" {
		t.Errorf("expected fail-open critical finding, got %+v", rep.Findings)
	}
	if !rep.HasCritical() {
		t.Error("expected HasCritical true")
	}
}

func TestAudit_ImplicitDenyIsOK(t *testing.T) {
	// Only a host-scoped route, no explicit catch-all: default-deny via 404.
	e := auditEngine(t, "grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "deny_catchall_present"); !ok || f.Severity != "ok" {
		t.Errorf("host-scoped-only edge should audit OK (implicit deny), got %+v", rep.Findings)
	}
	if rep.HasCritical() {
		t.Error("must not be critical")
	}
}

func TestAudit_DanglingPublicDNSIsCritical(t *testing.T) {
	// A public DNS record whose host has no backing edge route.
	dns := &stubDNS{name: "dnscontrol", scope: model.ScopePublic, live: []model.Record{
		{Name: "ghost.example.com", Type: "A", Value: "1.2.3.4", Scope: model.ScopePublic},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_without_edge_route")
	if !ok || f.Severity != "critical" {
		t.Errorf("expected dangling public DNS critical, got %+v", rep.Findings)
	}
}

func TestAudit_ExposedRouteWithoutDNSIsWarning(t *testing.T) {
	// grafana is exposed on the edge but DNS has no record for it.
	dns := &stubDNS{name: "dnscontrol", scope: model.ScopeInternal, live: nil}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "edge_route_without_dns")
	if !ok || f.Severity != "warning" {
		t.Errorf("expected exposed-without-DNS warning, got %+v", rep.Findings)
	}
}

func TestAudit_NoDNSConfiguredSkipsReverseCheck(t *testing.T) {
	// With no DNS provider, the reverse check must not fire (would be noise).
	e := auditEngine(t, seedGrafana)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "edge_route_without_dns"); ok {
		t.Error("reverse check should not run without DNS configured")
	}
}

// TestAudit_SplitHorizonTwoProviders exercises the M3 shape: internal AND public
// DNS providers wired at once. A host exposed at the edge AND backed in both scopes
// is clean; a public-only dangling record is still surfaced as critical.
func TestAudit_SplitHorizonTwoProviders(t *testing.T) {
	internal := &stubDNS{name: "dnscontrol", scope: model.ScopeInternal, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal},
	}}
	public := &stubDNS{name: "dnscontrol", scope: model.ScopePublic, live: []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic},
		{Name: "ghost.example.com", Type: "A", Value: "203.0.113.9", Scope: model.ScopePublic},
	}}
	e := auditEngine(t, seedGrafana, internal, public)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// grafana is fully backed (edge + both scopes) => no exposed-without-DNS noise.
	if _, ok := findCode(rep, "edge_route_without_dns"); ok {
		t.Errorf("grafana is backed in both scopes; no reverse warning expected: %+v", rep.Findings)
	}
	// The public-only ghost record has no backing edge route => critical.
	f, ok := findCode(rep, "dns_without_edge_route")
	if !ok || f.Severity != "critical" {
		t.Errorf("expected dangling public ghost record critical, got %+v", rep.Findings)
	}
}

func TestAudit_InternalDanglingDNSIsWarning(t *testing.T) {
	dns := &stubDNS{name: "dnscontrol", scope: model.ScopeInternal, live: []model.Record{
		{Name: "ghost.example.com", Type: "A", Value: "10.0.0.9", Scope: model.ScopeInternal},
	}}
	e := auditEngine(t, seedGrafana, dns)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_without_edge_route")
	if !ok || f.Severity != "warning" {
		t.Errorf("expected dangling internal DNS warning, got %+v", rep.Findings)
	}
}

// TestAudit_PublicWithoutAuthIsWarning: a host exposed at the edge with no public
// DNS managed (the edge IS the public boundary) and no forward-auth policy is
// flagged as a public_without_auth WARNING (never critical).
func TestAudit_PublicWithoutAuthIsWarning(t *testing.T) {
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{httpRoute("grafana.example.com")}, // Auth == ""
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "public_without_auth")
	if !ok || f.Severity != "warning" {
		t.Errorf("expected public_without_auth warning, got %+v", rep.Findings)
	}
	if rep.HasCritical() {
		t.Error("public-without-auth must not be critical")
	}
}

// TestAudit_AuthProtectedNoWarning: a public host that carries a forward-auth
// policy is NOT flagged.
func TestAudit_AuthProtectedNoWarning(t *testing.T) {
	protected := httpRoute("grafana.example.com")
	protected.Upstream.Auth = "authelia"
	edge := stubEdge{name: "caddy", live: model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes:              []model.Route{protected},
	}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "home", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("an auth-protected host must not be flagged:\n%+v", rep.Findings)
	}
}

// TestAudit_MeshGrantNotFlaggedForAuth: a mesh-grant host is identity-enforced and
// never "public", so it is excluded from the public-without-auth check.
func TestAudit_MeshGrantNotFlaggedForAuth(t *testing.T) {
	mesh := stubEdge{name: "netbird", live: model.LiveEdgeState{DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "vault.example.com", Upstream: model.Upstream{Mode: model.ModeMeshGrant, Address: "mesh-grant:admins"}}}}}
	e := core.NewMulti([]core.EdgeBinding{{Name: "vps", Provider: mesh}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findCode(rep, "public_without_auth"); ok {
		t.Errorf("a mesh-grant host must not be flagged public_without_auth:\n%+v", rep.Findings)
	}
}
