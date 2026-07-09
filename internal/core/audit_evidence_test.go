package core_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// evidenceEdge wraps the audit stub with a declared read-evidence kind
// (ports.EvidenceReporter) — the M-A2 capability under test.
type evidenceEdge struct {
	stubEdge
	ev model.ReadEvidence
}

func (e evidenceEdge) ReadEvidence() model.ReadEvidence { return e.ev }

func cleanLive() model.LiveEdgeState {
	return model.LiveEdgeState{
		DenyCatchAllPresent: true,
		Routes: []model.Route{{Host: "app.example.com", Upstream: model.Upstream{
			Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "app.example.com", Auth: "authelia"}}},
	}
}

// TestAudit_ConfigEvidenceFindingAndScope: a CONFIG-evidence edge populates
// AuditScope.Evidence AND emits the standing config_evidence_only finding — ok
// severity (the operator CHOSE a file target; it never flips the exit code),
// naming the source and carrying the mtime staleness hint (risk A.2).
func TestAudit_ConfigEvidenceFindingAndScope(t *testing.T) {
	edge := evidenceEdge{
		stubEdge: stubEdge{name: "caddy", live: cleanLive()},
		ev: model.ReadEvidence{
			Kind:    model.EvidenceConfig,
			Source:  "/etc/caddy/Caddyfile",
			ModTime: time.Now().Add(-41 * 24 * time.Hour),
		},
	}
	e := core.NewMulti([]core.EdgeBinding{{Name: "edge", Provider: edge}}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Scope.Evidence["edge"]; got != model.EvidenceConfig {
		t.Errorf("Scope.Evidence must carry the declared kind, got %q", got)
	}
	f, ok := findCode(rep, "config_evidence_only")
	if !ok || f.Severity != "ok" {
		t.Fatalf("CONFIG evidence must emit the ok-severity standing finding, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "/etc/caddy/Caddyfile") || !strings.Contains(f.Message, "not the running daemon") {
		t.Errorf("the finding must name the source and the daemon-vs-file gap, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "config last modified 41 days ago") {
		t.Errorf("the finding must carry the mtime staleness hint, got %q", f.Message)
	}
	if !rep.OK() {
		t.Errorf("config_evidence_only must not flip OK()/exit on an otherwise-clean edge: %+v", rep.Findings)
	}
}

// TestAudit_RuntimeEvidenceScopedNotFlagged: RUNTIME evidence lands in the Scope
// map but emits NO caveat finding (the running process IS the strongest read),
// and an edge with no EvidenceReporter stays unclassified — never upgraded.
func TestAudit_RuntimeEvidenceScopedNotFlagged(t *testing.T) {
	runtimeEdge := evidenceEdge{
		stubEdge: stubEdge{name: "caddy", live: cleanLive()},
		ev:       model.ReadEvidence{Kind: model.EvidenceRuntime, Source: "http://127.0.0.1:2019"},
	}
	plain := stubEdge{name: "plain", live: cleanLive()}
	e := core.NewMulti([]core.EdgeBinding{
		{Name: "rt", Provider: runtimeEdge},
		{Name: "unclassified", Provider: plain},
	}, "example.com")
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Scope.Evidence["rt"]; got != model.EvidenceRuntime {
		t.Errorf("runtime edge must be scoped RUNTIME, got %q", got)
	}
	if _, ok := rep.Scope.Evidence["unclassified"]; ok {
		t.Errorf("an edge without the capability must stay unclassified, got %+v", rep.Scope.Evidence)
	}
	if _, ok := findCode(rep, "config_evidence_only"); ok {
		t.Errorf("RUNTIME evidence must not emit the CONFIG caveat: %+v", rep.Findings)
	}
}
