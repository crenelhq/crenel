package core

// audit_pangolin_test.go pins risk A.1 (M-A4): a NON-runtime read of a
// Pangolin-detected edge — the dynamic-config FILE, when Pangolin actually
// serves routes to Traefik over the HTTP provider — must emit the "audit the
// API instead" pointer, because the file may be a SUBSET of what the running
// edge exposes. RED-style: the file-driver case was written to fail before the
// finding existed. A RUNTIME (Traefik API) read must NOT fire it.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/model"
)

// pangolinFileEngine builds a read-only engine over the traefik FILE driver
// pointed at the captured Pangolin dynamic config (the file Pangolin's own
// compose feeds Traefik's file provider — its badger middleware fires the
// pangolin detector from the file exactly as from the API).
func pangolinFileEngine(t *testing.T) *Engine {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "drivers", "edge", "traefik", "testdata", "pangolin-dynamic.yml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dynamic_config.yml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(traefik.New(path, nil), "")
	e.ReadOnly = true
	return e
}

// TestAuditPangolinFileTarget_PointsAtAPI (risk A.1): the file read detects
// pangolin and the audit says, loudly and as a WARNING, that the config is
// partly served over the HTTP provider — audit the API instead.
func TestAuditPangolinFileTarget_PointsAtAPI(t *testing.T) {
	rep, err := pangolinFileEngine(t).Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found *AuditFinding
	for i := range rep.Findings {
		if rep.Findings[i].Code == "pangolin_http_provider" {
			found = &rep.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("file read of a Pangolin-detected config must emit pangolin_http_provider; findings: %+v", rep.Findings)
	}
	if found.Severity != "warning" {
		t.Errorf("severity = %q, want warning — partial-coverage complacency is the re-armed MISREAD", found.Severity)
	}
	for _, want := range []string{"HTTP provider", "audit the API instead"} {
		if !strings.Contains(found.Message, want) {
			t.Errorf("finding message missing %q: %s", want, found.Message)
		}
	}
}

// runtimePangolinEdge fakes a RUNTIME-evidence provider whose live state is
// pangolin-generated — the A.1 finding must key on evidence, not on generator
// alone (the Traefik API read IS the whole running truth).
type runtimePangolinEdge struct{}

func (runtimePangolinEdge) Name() string                   { return "traefik" }
func (runtimePangolinEdge) Validate(context.Context) error { return nil }
func (runtimePangolinEdge) Plan(model.Op, model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{}, nil
}
func (runtimePangolinEdge) Apply(context.Context, model.ChangeSet) error { return nil }
func (runtimePangolinEdge) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	return model.LiveEdgeState{
		Generator:           "pangolin",
		DenyCatchAllPresent: true,
		Routes: []model.Route{{
			Host: "vault.homelab.example", Ownership: model.OwnForeign,
			Upstream: model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: "10.0.0.7:8200", Auth: model.AuthDetected},
		}},
	}, nil
}
func (runtimePangolinEdge) ReadEvidence() model.ReadEvidence {
	return model.ReadEvidence{Kind: model.EvidenceRuntime, Source: "http://127.0.0.1:8080 (Traefik API)"}
}

// TestAuditPangolinRuntimeRead_NoAPIPointer: a RUNTIME read never fires A.1 —
// and the §4.3 overlay auto-declaration DOES fire (ingress_external), since a
// Pangolin edge is overlay-fronted unless the operator declares otherwise.
func TestAuditPangolinRuntimeRead_NoAPIPointer(t *testing.T) {
	e := New(runtimePangolinEdge{}, "")
	e.ReadOnly = true
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var sawIngress bool
	for _, f := range rep.Findings {
		if f.Code == "pangolin_http_provider" {
			t.Errorf("RUNTIME evidence must suppress the A.1 pointer: %+v", f)
		}
		if f.Code == "ingress_external" && strings.Contains(f.Message, "overlay") {
			sawIngress = true
		}
	}
	if !sawIngress {
		t.Errorf("pangolin generator must auto-declare overlay ingress (§4.3); findings: %+v", rep.Findings)
	}
}
