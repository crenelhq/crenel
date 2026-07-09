package model

import "time"

// EvidenceKind classifies WHAT a read-only audit actually observed for an edge —
// the read-side extension of the RuntimeVerifyStatus vocabulary ("verified" means
// read-back-after-write, so a pure read must not use the word; it declares its
// evidence instead). Ordered strongest to weakest; a kind is DECLARED by the read
// path, never inferred upward: a file read stays CONFIG even when the daemon is
// probably fine.
type EvidenceKind string

const (
	// EvidenceRuntime: the RUNNING process reported this state (Caddy admin API,
	// Traefik API) — the strongest read evidence.
	EvidenceRuntime EvidenceKind = "runtime"
	// EvidenceConfig: a file/tree on disk declared this state; the daemon may
	// differ (unloaded edit, failed reload) — the daemon-vs-file gap must be
	// surfaced, never papered over.
	EvidenceConfig EvidenceKind = "config"
	// EvidenceDeclared: asserted by the operator/config, observed by nothing
	// (ingress_kind, the auth_downstream fallback).
	EvidenceDeclared EvidenceKind = "declared"
)

// ReadEvidence is a driver's declaration of WHAT its ReadLiveState observed —
// reported via ports.EvidenceReporter and folded into AuditScope.Evidence. It is
// config-derived and cheap: the driver knows at construction whether it reads a
// running process or a file; it never upgrades itself (a file read stays CONFIG
// even when the daemon is probably fine — the A.2 staleness risk is the point).
type ReadEvidence struct {
	Kind EvidenceKind
	// Source names what was read — the admin URL for RUNTIME, the file path for
	// CONFIG — so the report can say exactly which substrate the claim rests on.
	Source string
	// ModTime is the newest mtime of the file(s) read (CONFIG only; zero when
	// unknown / not applicable). It feeds the audit's staleness HINT ("config last
	// modified 41 days ago") — evidence the operator weighs, never a verdict.
	ModTime time.Time
}
