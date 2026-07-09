package model

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
