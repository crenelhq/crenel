// Package core is the vendor-agnostic engine: status, preview, apply, audit,
// export. It depends only on internal/model and internal/ports — NEVER on a
// driver package. Concrete drivers are injected at cmd (the composition root).
package core

import "github.com/crenelhq/crenel/internal/model"

// StatusReport is the result of a read-only status query. With M4 it carries one
// EdgeStatus per edge in the topology (a single-edge engine reports exactly one).
type StatusReport struct {
	Edges []EdgeStatus
	DNS   []ScopeRecords
}

// EdgeStatus is one edge's live snapshot for status reporting.
type EdgeStatus struct {
	Name                string        `json:"name"`   // topology name, e.g. "home", "vps"
	Driver              string        `json:"driver"` // provider name, e.g. "caddy", "traefik"
	Routes              []model.Route `json:"routes"`
	DenyCatchAllPresent bool          `json:"deny_catchall_present"`
	// Unparsed is everything the driver SAW but could not fully understand on this
	// edge — first-class coverage output, never a silent drop (register §4).
	Unparsed []model.Unparsed `json:"unparsed,omitempty"`
	// Generator names a config generator that owns this edge ("" = none), and
	// IngressKind names an off-edge reachability mechanism ("" = a public port).
	Generator   string            `json:"generator,omitempty"`
	IngressKind model.IngressKind `json:"ingress_kind,omitempty"`
	// Persistence DECLARES whether a write to this edge survives a control-plane
	// restart (model.PersistenceModel) — durable-config (file provider), durable-file
	// (admin edge reconciled to disk), resume, or ephemeral-admin (admin-only, lost on
	// restart). "" = not classified (a mesh edge). Surfaced as the status DURABILITY
	// line; the write path warns when it is EphemeralWrites.
	Persistence model.PersistenceModel `json:"persistence,omitempty"`
}

// Coverage reports understood vs total routes on this edge (total = understood +
// unparsed), so status can print "read N/M routes".
func (es EdgeStatus) Coverage() (understood, total int) {
	return len(es.Routes), len(es.Routes) + len(es.Unparsed)
}

// FullyParsed reports whether crenel understood this edge's entire config,
// treating an operator-ACKNOWLEDGED unknown as resolved — see
// model.LiveEdgeState.FullyParsed.
func (es EdgeStatus) FullyParsed() bool {
	for _, u := range es.Unparsed {
		if u.Kind != model.UnknownAcknowledged {
			return false
		}
	}
	return true
}

// Acknowledged returns the Unparsed entries the operator has explicitly
// acknowledged (crenel-ack marker) — surfaced by status/audit as their own
// "ACK" state, never hidden. See docs/design/ack-marker.md.
func (es EdgeStatus) Acknowledged() []model.Unparsed {
	var out []model.Unparsed
	for _, u := range es.Unparsed {
		if u.Kind == model.UnknownAcknowledged {
			out = append(out, u)
		}
	}
	return out
}

// DenyState returns the ternary default-deny verdict for this edge (mirrors
// model.LiveEdgeState.DenyState): ENFORCED only when present AND fully parsed.
func (es EdgeStatus) DenyState() model.DenyState {
	if !es.DenyCatchAllPresent {
		return model.DenyMissing
	}
	if !es.FullyParsed() {
		return model.DenyUnknown
	}
	return model.DenyEnforced
}

// ScopeRecords groups live DNS records by provider/scope for status & audit.
type ScopeRecords struct {
	Provider string
	Scope    model.Scope
	Records  []model.Record
}

// AuditFinding is a single invariant or consistency result.
type AuditFinding struct {
	Severity string // "critical" | "warning" | "ok"
	Code     string // machine code, e.g. "deny_catchall_missing"
	Message  string
}

// AuditScope is the audit's first-class "what was NOT evaluated" declaration
// (audit-any-edge §3.4). Several checks silently change meaning with the wiring —
// no DNS providers means public-ness falls back to the conservative "edge route ⇒
// public" boundary default, and parity/dangling-DNS checks don't run; no chain
// topology means downstream edges are not followed. Declaring the reduction is the
// same honesty move as the coverage line. Rendered as the `Scope:` header lines in
// the text report and carried in --json.
type AuditScope struct {
	// TargetMode: a zero-config positional-target audit (one synthesized edge, no
	// settings topology). Always false until the target bootstrap ships (M-A2+).
	TargetMode bool
	// DNSEvaluated: DNS providers were configured and consulted. false ⇒ public-ness
	// used the conservative edge-boundary default; split-horizon/dangling/parity
	// checks were NOT evaluated.
	DNSEvaluated bool
	// ChainDepth is the deepest configured chain follow-through (0 ⇒ no downstream
	// edge was followed).
	ChainDepth int
	// Evidence declares, per edge, WHAT the read observed (running process vs a
	// file on disk vs an operator assertion). Populated when drivers report a
	// read-evidence kind (M-A2+); empty means unclassified, never claimed RUNTIME.
	Evidence map[string]model.EvidenceKind
}

// AuditReport is the result of a live-only audit.
type AuditReport struct {
	// Scope declares what this audit could and could not evaluate — it carries no
	// severity and never affects OK()/exit codes; it bounds the claim the findings
	// make.
	Scope    AuditScope
	Findings []AuditFinding
}

// OK reports whether the audit found no critical or warning findings.
func (a AuditReport) OK() bool {
	for _, f := range a.Findings {
		if f.Severity == "critical" || f.Severity == "warning" {
			return false
		}
	}
	return true
}

// HasCritical reports whether any finding is critical.
func (a AuditReport) HasCritical() bool {
	for _, f := range a.Findings {
		if f.Severity == "critical" {
			return true
		}
	}
	return false
}

// VerifyResult records one provider's read-back verification outcome.
//
// Two layers fold here. Detail/OK come from the ARTIFACT re-read (ReadLiveState matched
// intent). RuntimeChecked/Runtime come from a file driver's RUNTIME probe of the actual
// daemon (ports.RuntimeVerifier): for a file edge the re-read alone is hollow (it
// re-reads crenel's own written file), so the runtime status is what decides whether the
// report may say "verified". Caddy reads its live admin API, so it does not set
// RuntimeChecked and its re-read IS the verify.
type VerifyResult struct {
	Provider string
	OK       bool
	Detail   string
	// RuntimeChecked is true when this edge is a file driver whose daemon was probed.
	// When false, Detail/OK are authoritative as before (e.g. Caddy's live admin read).
	RuntimeChecked bool
	// Runtime is the daemon-probe status (only meaningful when RuntimeChecked): a
	// Failed status forces OK=false upstream; Unavailable keeps OK=true but blocks a
	// "verified" report.
	Runtime model.RuntimeVerifyStatus
	// RuntimeDetail describes what the daemon probe checked, or why it was unavailable.
	RuntimeDetail string
}

// RuntimeUnconfirmed reports whether this result was a file-driver write whose daemon
// could NOT be confirmed (no runtime surface configured). It is OK (the file was
// written) but must NOT be reported as "verified".
func (v VerifyResult) RuntimeUnconfirmed() bool {
	return v.RuntimeChecked && v.Runtime == model.RuntimeVerifyUnavailable
}

// fullyVerified reports whether every result in verify passed AND none is a
// file-driver write whose daemon could not be confirmed. Shared by ApplyReport
// and DeclarativeReport.
func fullyVerified(verify []VerifyResult) bool {
	for _, v := range verify {
		if !v.OK || v.RuntimeUnconfirmed() {
			return false
		}
	}
	return true
}

// runtimeUnconfirmedResults returns the OK results in verify whose daemon could
// not be confirmed. Shared by ApplyReport and DeclarativeReport.
func runtimeUnconfirmedResults(verify []VerifyResult) []VerifyResult {
	var out []VerifyResult
	for _, v := range verify {
		if v.RuntimeUnconfirmed() {
			out = append(out, v)
		}
	}
	return out
}

// txnOutcome holds the rollback / wedge-safety status shared by every
// transactional mutating operation (Apply, Reconcile). It is embedded so its
// fields promote unchanged onto the containing report (and serialize flat).
type txnOutcome struct {
	// RolledBack is true if a partial apply or failed verification triggered
	// compensating rollback of the providers already applied (M1).
	RolledBack bool
	// RollbackErrors holds any errors encountered while rolling back. A
	// non-empty slice means the system may be in an inconsistent state and
	// needs manual attention.
	RollbackErrors []string

	// EdgeUnresponsive is true if the edge control plane was found wedged/slow
	// (its admin API did not answer within the bounded timeout) during apply or
	// rollback. When set, edge rollback is SKIPPED to avoid worsening the wedge.
	EdgeUnresponsive bool
	// RecoveryHint, when non-empty, tells the operator how to recover (e.g. a
	// manual edge restart) after an unresponsive-edge outcome.
	RecoveryHint string

	// PersistWarnings holds non-fatal on-disk persistence failures (a Persister
	// edge's Persist returned an error AFTER a verified apply). The running state is
	// already correct and verified; only its durability across a restart is in
	// question, so a persist failure is a WARNING, not a rollback. See
	// docs/internal/USABILITY-DESIGN.md §B.
	PersistWarnings []string
}

// ApplyReport is the result of a mutating apply (expose/unexpose/set).
type ApplyReport struct {
	Op        model.Op
	Applied   bool // false if the user declined or it was a no-op
	NoOp      bool
	Verify    []VerifyResult
	NewPublic []string
	txnOutcome
}

// Verified reports whether every provider's read-back verification passed (the write
// took effect — no rollback). It does NOT by itself license a "verified" report: a file
// edge can be OK-but-runtime-unconfirmed (file written, daemon not probeable). Use
// FullyVerified for the "may we say verified?" question.
func (r ApplyReport) Verified() bool {
	for _, v := range r.Verify {
		if !v.OK {
			return false
		}
	}
	return true
}

// FullyVerified reports whether the apply may HONESTLY claim "verified": every result
// passed AND none was a file-driver write whose daemon could not be confirmed. When this
// is false but Verified() is true, the write stands but at least one edge is only
// "written; runtime verify unavailable" — surfaced by RuntimeUnconfirmed().
func (r ApplyReport) FullyVerified() bool { return fullyVerified(r.Verify) }

// RuntimeUnconfirmed returns the OK results whose daemon could not be confirmed (file
// written, no runtime surface configured) — what the CLI lists when it must say
// "written; runtime verify unavailable" instead of "verified".
func (r ApplyReport) RuntimeUnconfirmed() []VerifyResult { return runtimeUnconfirmedResults(r.Verify) }
