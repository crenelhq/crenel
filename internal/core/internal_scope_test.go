package core_test

// internal_scope_test.go proves the INTERNAL-SCOPE service declaration
// (split-horizon topologies, docs/internal/DESIGN.md "Internal-scope services").
// The mirrored production shape throughout: a chain FRONT edge ("vps", the public
// ingress) forwarding to a DOWNSTREAM edge ("home") that terminally fronts an
// internal-only service ("ha"); an INTERNAL DNS resolver that answers the host
// and a PUBLIC DNS provider that must NEVER carry it. Before this feature the
// only way to express "internal-only" was leaving the service OUT of origins —
// unmanaged and unverified; declaring it instead made drift demand a forward on
// the chain front (missing_route "half-present chain") and a public DNS record.
// These tests pin every demand gate AND the audit guarantee that enforces the
// declaration.

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// scopeDNS is a minimal in-memory DNSProvider whose Diff actually reports the
// adds (unlike stubDNS's empty Diff) so Plan-level DNS-leg assertions are real.
type scopeDNS struct {
	name  string
	scope model.Scope
	addr  string // the answer value DesiredRecords emits
	live  []model.Record
}

func (s *scopeDNS) Name() string       { return s.name }
func (s *scopeDNS) Scope() model.Scope { return s.scope }
func (s *scopeDNS) DesiredRecords(op model.Op) ([]model.Record, error) {
	return []model.Record{{Name: op.Host, Type: "A", Value: s.addr, Scope: s.scope}}, nil
}
func (s *scopeDNS) Diff(_ context.Context, op model.Op, desired []model.Record) (model.DNSChange, error) {
	ch := model.DNSChange{Scope: s.scope}
	if op.Verb == model.Expose {
		for _, d := range desired {
			present := false
			for _, l := range s.live {
				if l.Key() == d.Key() {
					present = true
				}
			}
			if !present {
				ch.Add = append(ch.Add, d)
			}
		}
	}
	return ch, nil
}
func (s *scopeDNS) Apply(_ context.Context, ch model.DNSChange) error {
	s.live = append(s.live, ch.Add...)
	return nil
}
func (s *scopeDNS) LiveRecords(context.Context) ([]model.Record, error) { return s.live, nil }

// downRouteAuth is the downstream edge's terminal route for host, auth-protected —
// the healthy home shape (auth lives where the host is served).
func downRouteAuth(host, addr string) model.Route {
	return model.Route{Host: host, Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: addr, ServerName: host, Auth: "authelia"}}
}

// internalScopeChain wires the prod shape: front "vps" (chain front toward
// "home", carrying the given front routes) and home terminally fronting "ha"
// with its route live, plus the given DNS providers. The engine declares "ha"
// internal-scope — the feature under test.
func internalScopeChain(frontRoutes []model.Route, dns ...ports.DNSProvider) *core.Engine {
	front := &memEdge{name: "vps", origins: map[string]string{},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: frontRoutes}}
	home := &memEdge{name: "home", origins: map[string]string{"ha": "10.0.0.19:8123"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true, Routes: []model.Route{
			downRouteAuth("ha.homelab.example", "10.0.0.19:8123"),
		}}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: frontsFor(front.origins), DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example", dns...)
	e.InternalScope = map[string]bool{"ha": true}
	return e
}

// internalDNSWithHA is the internal resolver already answering the host (the
// converged internal leg) and an EMPTY public provider (the posture to keep).
func internalDNSWithHA() (*scopeDNS, *scopeDNS) {
	internal := &scopeDNS{name: "adguard", scope: model.ScopeInternal, addr: "10.0.0.2",
		live: []model.Record{{Name: "ha.homelab.example", Type: "A", Value: "10.0.0.2", Scope: model.ScopeInternal}}}
	public := &scopeDNS{name: "cloudflare", scope: model.ScopePublic, addr: "203.0.113.10"}
	return internal, public
}

func badFindings(rep core.AuditReport) []core.AuditFinding {
	var out []core.AuditFinding
	for _, f := range rep.Findings {
		if f.Severity != "ok" {
			out = append(out, f)
		}
	}
	return out
}

func findingsByCode(rep core.AuditReport, code string) []core.AuditFinding {
	var out []core.AuditFinding
	for _, f := range rep.Findings {
		if f.Code == code {
			out = append(out, f)
		}
	}
	return out
}

// TestInternalScope_ChainCleanDriftAndAudit is the headline prod case: the
// declared internal service exists ONLY on the downstream edge + internal DNS,
// the chain front does NOT forward it and public DNS has no record — exactly
// the intended split-horizon posture. Drift must be clean (no half-present
// chain missing_route on the front, no missing public DNS record) and audit
// must be clean (the declaration is satisfied).
func TestInternalScope_ChainCleanDriftAndAudit(t *testing.T) {
	internal, public := internalDNSWithHA()
	e := internalScopeChain(nil, internal, public)
	ctx := context.Background()

	plan, err := e.DetectDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("declared internal service must generate no front/public demands — drift must be clean, got %+v", plan.Drift)
	}

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad := badFindings(rep); len(bad) > 0 {
		t.Fatalf("audit must be clean on the satisfied internal-scope posture, got %+v", bad)
	}
}

// TestInternalScope_UndeclaredRegression proves the gates are the DECLARATION's
// doing: the identical topology without the internal-scope declaration must
// flag both the half-present chain forward on the front AND the missing public
// DNS record — today's behavior, byte-identical.
func TestInternalScope_UndeclaredRegression(t *testing.T) {
	internal, public := internalDNSWithHA()
	e := internalScopeChain(nil, internal, public)
	e.InternalScope = nil // withdraw the declaration

	plan, err := e.DetectDrift(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var missingRoute, missingDNS bool
	for _, d := range plan.Drift {
		if d.Kind == core.DriftMissingRoute && d.Target == "vps" {
			missingRoute = true
		}
		if d.Kind == core.DriftMissingDNS && strings.Contains(d.Target, "cloudflare") {
			missingDNS = true
		}
	}
	if !missingRoute || !missingDNS {
		t.Fatalf("without the declaration the front forward AND public record must be demanded (missingRoute=%v missingDNS=%v): %+v",
			missingRoute, missingDNS, plan.Drift)
	}
}

// TestInternalScope_FrontForwardIsCritical: the GUARANTEE. The chain front DOES
// carry an explicit route/forward for the internal host — the public ingress
// relays it. Audit must raise the critical internal_scope_public_exposure
// finding, naming the edge and saying what to do.
func TestInternalScope_FrontForwardIsCritical(t *testing.T) {
	internal, public := internalDNSWithHA()
	fwd := model.Route{Host: "ha.homelab.example", Upstream: model.Upstream{
		Kind: model.DirectBackend, Mode: model.ModeHTTPProxy, Address: "10.0.0.13:443",
		ServerName: "ha.homelab.example", UpstreamTLS: true}}
	e := internalScopeChain([]model.Route{fwd}, internal, public)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByCode(rep, "internal_scope_public_exposure")
	if len(fs) != 1 || fs[0].Severity != "critical" {
		t.Fatalf("front forward of an internal-scope host must be one critical finding, got %+v", rep.Findings)
	}
	for _, must := range []string{"ha.homelab.example", "vps", "remove the front route"} {
		if !strings.Contains(fs[0].Message, must) {
			t.Errorf("finding must contain %q, got %q", must, fs[0].Message)
		}
	}
}

// TestInternalScope_ExplicitPublicDNSIsCritical: an explicit public DNS record
// for the internal host (owned or foreign — someone published this exact name)
// is always critical, independent of any route.
func TestInternalScope_ExplicitPublicDNSIsCritical(t *testing.T) {
	internal, public := internalDNSWithHA()
	public.live = []model.Record{{Name: "ha.homelab.example", Type: "A", Value: "203.0.113.10", Scope: model.ScopePublic}}
	e := internalScopeChain(nil, internal, public)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByCode(rep, "internal_scope_public_exposure")
	if len(fs) != 1 || fs[0].Severity != "critical" {
		t.Fatalf("explicit public DNS record for an internal-scope host must be one critical finding, got %+v", rep.Findings)
	}
	if !strings.Contains(fs[0].Message, "PUBLIC DNS record") || !strings.Contains(fs[0].Message, "remove the public record") {
		t.Errorf("finding must name the record and the fix, got %q", fs[0].Message)
	}
}

// TestInternalScope_PublicWildcardOnlyIsNoFinding pins the documented design
// decision: a zone-wide public wildcard (`*.zone`) covers EVERY internal host
// by construction — in the maintainer's architecture that coverage is
// unavoidable — and with NO public route the name resolves to an edge that
// default-denies it: unreachable in practice, so no finding (a permanent
// cry-wolf would train the operator to ignore the audit).
func TestInternalScope_PublicWildcardOnlyIsNoFinding(t *testing.T) {
	internal, public := internalDNSWithHA()
	public.live = []model.Record{{Name: "*.homelab.example", Type: "A", Value: "203.0.113.10", Scope: model.ScopePublic}}
	e := internalScopeChain(nil, internal, public)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fs := findingsByCode(rep, "internal_scope_public_exposure"); len(fs) > 0 {
		t.Fatalf("wildcard-only public coverage with no public route must not flag, got %+v", fs)
	}
	if fs := findingsByCode(rep, "internal_scope_wildcard_covered"); len(fs) > 0 {
		t.Fatalf("wildcard-only public coverage with no public route must not raise the combination note, got %+v", fs)
	}
}

// TestInternalScope_WildcardDNSPlusWildcardForwardIsWarning: the COMBINATION is
// real reachability — the public wildcard resolves the name AND the front's
// covering wildcard forward relays it downstream — so the lower-severity
// combination note fires (warning, not critical: each half alone is a normal
// architectural shape).
func TestInternalScope_WildcardDNSPlusWildcardForwardIsWarning(t *testing.T) {
	internal, public := internalDNSWithHA()
	public.live = []model.Record{{Name: "*.homelab.example", Type: "A", Value: "203.0.113.10", Scope: model.ScopePublic}}
	wild := model.Route{Host: "*.homelab.example", Upstream: model.Upstream{
		Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: "10.0.0.13:443",
		ServerName: "*.homelab.example", UpstreamTLS: true}}
	e := internalScopeChain([]model.Route{wild}, internal, public)

	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fs := findingsByCode(rep, "internal_scope_public_exposure"); len(fs) > 0 {
		t.Fatalf("wildcard+wildcard is the WARNING note, never critical, got %+v", fs)
	}
	fs := findingsByCode(rep, "internal_scope_wildcard_covered")
	if len(fs) != 1 || fs[0].Severity != "warning" {
		t.Fatalf("public wildcard + covering wildcard forward must be one warning note, got %+v", rep.Findings)
	}
}

// TestInternalScope_PlanWritesOnlyInternalLegs: an expose of the declared
// internal service plans the downstream edge route + the internal DNS record
// and NOTHING else — no front forward EdgePlan, and an EMPTY (alignment-
// preserving) public DNS slot.
func TestInternalScope_PlanWritesOnlyInternalLegs(t *testing.T) {
	internal := &scopeDNS{name: "adguard", scope: model.ScopeInternal, addr: "10.0.0.2"}
	public := &scopeDNS{name: "cloudflare", scope: model.ScopePublic, addr: "203.0.113.10"}
	// Start the home edge WITHOUT the route so the expose has work to plan.
	front := &memEdge{name: "vps", origins: map[string]string{},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true}}
	home := &memEdge{name: "home", origins: map[string]string{"ha": "10.0.0.19:8123"},
		live: &model.LiveEdgeState{DenyCatchAllPresent: true}}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "vps", Provider: front, Fronts: frontsFor(front.origins), DownstreamEdge: "home", DownstreamAddress: "10.0.0.13"},
		{Name: "home", Provider: home, Fronts: frontsFor(home.origins)},
	}, "homelab.example", internal, public)
	e.InternalScope = map[string]bool{"ha": true}

	cs, err := e.Plan(context.Background(), e.BuildOp(model.Expose, "ha"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edges) != 1 || cs.Edges[0].Edge != "home" {
		t.Fatalf("only the downstream edge may participate (no front forward), got %+v", cs.Edges)
	}
	if len(cs.DNS) != 2 {
		t.Fatalf("DNS slots must stay positionally aligned, got %d", len(cs.DNS))
	}
	if len(cs.DNS[0].Add) == 0 {
		t.Errorf("internal DNS leg must be planned, got %+v", cs.DNS[0])
	}
	if len(cs.DNS[1].Add) != 0 {
		t.Errorf("public DNS leg must be EMPTY for an internal-scope service, got %+v", cs.DNS[1])
	}
	if len(cs.NewPublic) != 0 {
		t.Errorf("nothing goes public, got NewPublic=%v", cs.NewPublic)
	}
}

// TestInternalScope_ExplicitPublicScopeRefused: `--scope public` on a declared
// internal service directly contradicts the config and must refuse loudly —
// never silently honor either side.
func TestInternalScope_ExplicitPublicScopeRefused(t *testing.T) {
	internal, public := internalDNSWithHA()
	e := internalScopeChain(nil, internal, public)
	op := e.BuildOp(model.Expose, "ha")
	op.Scopes = []model.Scope{model.ScopePublic}
	if _, err := e.Plan(context.Background(), op); err == nil || !strings.Contains(err.Error(), "declared scope internal") {
		t.Fatalf("explicit public appointment of an internal-scope service must refuse loudly, got %v", err)
	}
}
