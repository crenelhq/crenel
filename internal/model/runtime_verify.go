package model

// RuntimeVerifyStatus is the outcome of probing a file-based edge's RUNNING daemon
// (not crenel's written config artifact) to confirm an applied change actually took
// effect. It exists because a file driver's ReadLiveState re-reads the file crenel
// just WROTE — which always "matches intent" regardless of whether the daemon
// accepted the config. A true verify must ask the daemon, not the file.
type RuntimeVerifyStatus int

const (
	// RuntimeVerifyConfirmed: the running daemon was queried and CONFIRMS the change
	// (Traefik's API lists the router; nginx -t passed, reloaded, and the host probes
	// as expected). This is the only status that earns a "verified LIVE" report.
	RuntimeVerifyConfirmed RuntimeVerifyStatus = iota
	// RuntimeVerifyFailed: the running daemon was queried and CONTRADICTS the change —
	// it rejected the config, or the route is not actually live. This is the false
	// green the bench caught (crenel printed "verified" while Traefik had rejected the
	// whole file); it now fails verification and rolls back.
	RuntimeVerifyFailed
	// RuntimeVerifyUnavailable: no runtime surface is configured for this edge (no
	// Traefik API URL; no nginx reload/probe command), so the file was WRITTEN but the
	// daemon could not be queried. Honest non-green: the report says "written; runtime
	// verify unavailable", never "verified".
	RuntimeVerifyUnavailable
)

func (s RuntimeVerifyStatus) String() string {
	switch s {
	case RuntimeVerifyConfirmed:
		return "confirmed"
	case RuntimeVerifyFailed:
		return "failed"
	case RuntimeVerifyUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// RuntimeVerification is a file driver's report on probing its running daemon. core
// folds it into the per-edge read-back result: Failed flips the result to not-OK
// (rollback), Unavailable keeps the write but downgrades the report wording from
// "verified" to "written; runtime verify unavailable", Confirmed earns "verified LIVE".
type RuntimeVerification struct {
	Status RuntimeVerifyStatus
	// Detail is a human-readable account of what was checked (or why it could not be):
	// e.g. "traefik API lists router crenel-foo@file (enabled)" or "no traefik api_url
	// configured — set edge.traefik_api_url to confirm routes against the running daemon".
	Detail string
}
