// Package ports defines the interfaces (ports) that drivers (adapters) implement.
//
// core depends on these interfaces; concrete drivers are wired in at cmd. Neither
// core nor ports import any driver package.
package ports

import (
	"context"

	"github.com/crenelhq/crenel/internal/model"
)

// EdgeProvider models a reverse-proxy edge (e.g. Caddy).
//
// HARD INVARIANT every implementation must satisfy: it ALWAYS renders and
// reports the catch-all default-deny on live state. A host is reachable iff an
// explicit Expose added a route for it. ReadLiveState must therefore set
// LiveEdgeState.DenyCatchAllPresent truthfully, and Apply must never produce a
// config that drops the catch-all deny.
type EdgeProvider interface {
	// Name identifies the driver, e.g. "caddy".
	Name() string

	// ReadLiveState reads the edge's current running config and normalizes it.
	ReadLiveState(ctx context.Context) (model.LiveEdgeState, error)

	// Validate checks the edge is reachable and healthy enough to plan against.
	Validate(ctx context.Context) error

	// Plan computes the ChangeSet to realize op against the given live state.
	// It does not mutate anything.
	Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error)

	// Apply realizes the edge half of a ChangeSet. A successful return is NOT
	// proof the change took effect — callers must read-back-verify.
	Apply(ctx context.Context, cs model.ChangeSet) error
}

// Transport is the pluggable CHANNEL an admin-API edge driver uses to physically
// reach its control plane — decoupled from the EdgeProvider, which knows the API
// SHAPE (paths, bodies, status semantics). The EdgeProvider answers "what API does
// this edge speak"; the Transport answers "HOW do I reach it" (real HTTP to an
// admin_url, an ssh-exec curl against a loopback admin, a crenel-managed ssh
// tunnel). Only admin-API drivers (Caddy) consume a Transport; file-based drivers
// (Traefik/nginx) and the mesh driver do not.
//
// Unlike the other ports, Transport is consumed by a DRIVER, not by core — it is an
// infra concern wired at cmd. core/model never import it.
type Transport interface {
	// Do issues ONE admin request and returns the HTTP status, the response body,
	// and a transport error. A nil error with a non-2xx status means "the admin was
	// reached and answered <status>" — the driver interprets the status. A non-nil
	// error means NO HTTP response could be obtained at all (the channel failed).
	//
	// Do MUST honor ctx's deadline/cancellation and never outlive it: every admin
	// call is bounded by the driver's read/write timeout, and the never-hang lesson
	// (POSTMORTEM.md) applies to EVERY transport. On a deadline it returns an error
	// that wraps context.DeadlineExceeded (or a net.Error reporting Timeout), so the
	// driver classifies it as a wedged admin (ErrAdminUnresponsive) uniformly,
	// regardless of which transport carried the call. A 2xx is necessary but never
	// sufficient — the driver still read-back-verifies.
	Do(ctx context.Context, method, path, contentType string, body []byte) (status int, respBody []byte, err error)
}

// DNSProvider models a DNS reconciliation backend (e.g. dnscontrol). Each
// provider instance is bound to a single scope (internal or public).
type DNSProvider interface {
	Name() string
	Scope() model.Scope

	// DesiredRecords returns the records this op concerns for this provider's
	// scope (verb-agnostic: the A record(s) for the op's host). Used for display
	// and read-back verification (present after expose, absent after unexpose).
	DesiredRecords(op model.Op) ([]model.Record, error)

	// Diff computes the change needed to realize op against live records. The op
	// carries the verb so the provider knows whether desired records should be
	// added (expose) or removed (unexpose).
	Diff(ctx context.Context, op model.Op, desired []model.Record) (model.DNSChange, error)

	// Apply realizes a DNSChange. Like the edge, success is not proof; callers
	// read-back-verify where the provider supports it.
	Apply(ctx context.Context, change model.DNSChange) error

	// LiveRecords reads the records currently managed in this scope (used by
	// status, audit cross-provider consistency, and read-back verification).
	LiveRecords(ctx context.Context) ([]model.Record, error)
}

// OwnedRecordReporter is an OPTIONAL DNSProvider capability: it declares that LiveRecords
// returns ONLY crenel-owned records (e.g. the surgical Cloudflare driver filters to records
// carrying its `managed-by:crenel` marker). core/audit uses it to value-check those records
// for TARGET DRIFT — a record crenel OWNS whose live value no longer matches what crenel
// would set (DesiredRecords) is a SILENT MISDIRECT: the name resolves to the WRONG target
// while the name-only consistency checks otherwise read clean.
//
// It is deliberately NOT applied to providers that cannot distinguish their own records from
// the operator's — an AdGuard rewrite carries no ownership marker, so a value check there
// would cry wolf on every legitimately-foreign rewrite (the homelab's vault/notify/etc. point
// at a different vantage target ON PURPOSE). A provider without a provable ownership marker
// simply does not implement this, and audit skips the value check for it.
type OwnedRecordReporter interface {
	// OwnsAllLiveRecords reports whether LiveRecords returns ONLY crenel-owned records.
	OwnsAllLiveRecords() bool
}

// CoverageReporter is an OPTIONAL DNSProvider capability: a READ-ONLY view of ALL
// records in the provider's zone — crenel-owned AND foreign, including operator
// wildcards — for PRESENCE/COVERAGE checks only.
//
// Why it exists: a marker-filtered provider (the surgical Cloudflare driver) keeps
// LiveRecords scoped to crenel-OWNED records — the correct boundary for everything
// that feeds mutation and ownership reasoning. But presence is a property of the
// ZONE, not of crenel's footprint: an operator's UNOWNED `*.zone` wildcard already
// answers every exposed host under the zone, and a coverage check that cannot see it
// flags a permanent `missing_dns_record` per host — the public-scope cry-wolf
// sibling of the internal wildcard-awareness fix (audit's dns_coverage_parity /
// dns_without_edge_route / edge_route_without_dns wildcard treatment).
//
// HARD SEPARATION (the load-bearing safety property): CoverageRecords may be
// consumed ONLY by presence/coverage checks — "is this name already answered, and by
// what value?". It must NEVER feed a mutation, an ownership decision, or an
// owned-record value-drift check; those stay marker-gated on LiveRecords +
// OwnedRecordReporter. Coverage may READ foreign records; crenel still never
// TOUCHES them.
//
// Providers whose LiveRecords is already zone-complete (AdGuard/Pi-hole: filtered
// by zone but NOT by ownership — they have no ownership marker to filter on) gain
// nothing from implementing it; core falls back to LiveRecords for them, which
// preserves their behavior byte-identically.
type CoverageReporter interface {
	// CoverageRecords reads ALL records currently present in the provider's zone
	// (owned + foreign, explicit + wildcard). Read-only; never mutates.
	CoverageRecords(ctx context.Context) ([]model.Record, error)
}

// ZoneReporter is an OPTIONAL DNSProvider capability: it declares the single DNS zone
// this provider instance is confined to (e.g. "homelab.example"). core uses it to route
// each host to ONLY the providers whose zone covers it — the multi-zone edge case: one
// edge serving hosts under two apexes ("homelab.example" + "smallbiz.example"), with
// separate provider entries per zone. Without it, every plan/reconcile fan-out would ask
// EVERY provider for EVERY host, and a zone-confined driver (AdGuard/Pi-hole/Cloudflare)
// would correctly refuse the out-of-zone write — turning a legitimate two-zone config
// into a hard error. Audit likewise uses it to group coverage-parity comparisons by
// zone (two resolvers of DIFFERENT zones must never be compared against each other).
//
// A provider that does not implement it — or reports "" — is treated as covering every
// host (back-compat: the pre-multi-zone behavior, and the honest default for a provider
// whose confinement core cannot see).
type ZoneReporter interface {
	// ManagedZone returns the zone this provider is confined to ("" = unconfined).
	// Config-derived, cheap, never mutates.
	ManagedZone() string
}

// ResidencyTargeter is an OPTIONAL DNSProvider capability: it declares that this
// provider can resolve a host's RESIDENCY class (model.Op.Residency; the reference
// architecture's `target(class, vantage)` rule, docs/REFERENCE-ARCH-split-horizon.md
// §2) to ITS OWN vantage-correct answer — a per-provider `targets` map layered over
// the single default edge_addr. This is what turns the per-PROVIDER target divergence
// the dual-resolver split already supports into per-HOST divergence: for an
// edge-resident host the home (non-tunnel) resolver answers the PUBLIC edge while the
// tunnel resolver answers tunnel-direct, and each instance resolves the class against
// only its own map.
//
// The contract is refuse-loudly, never guess: a class the provider has no target for
// MUST return an error (core surfaces it at plan time, before any write), and core
// REFUSES a non-default residency op on any INTERNAL provider that does not implement
// this capability at all — a provider that cannot express the class must never
// silently fall back to its default target and misdirect a vantage. PUBLIC providers
// do not implement it: the public answer is the public edge for every class (the §2
// table's Cloudflare column is constant).
type ResidencyTargeter interface {
	// ResidencyTarget resolves a residency class to this provider's answer address.
	// "" (the home-resident default) returns the configured edge_addr; an unknown
	// class returns a loud, instance-naming error. Config-derived, never mutates.
	ResidencyTarget(class string) (string, error)
}

// OriginResolver maps a logical service name to a backend address.
type OriginResolver interface {
	Resolve(serviceName string) (string, error)
}

// Adopter is an OPTIONAL capability an EdgeProvider may implement: stamping
// Crenel's ownership marker onto an EXISTING unmanaged route in-place, so a
// hand-built brownfield route comes under management WITHOUT changing runtime
// behavior. `crenel import` uses it to bring a pre-existing setup under
// management idempotently. Drivers that have no ownership marker (e.g. an
// identity mesh) simply do not implement it.
type Adopter interface {
	// Adopt stamps the ownership marker onto the existing route for each host —
	// same backend, same behavior, only ownership changes. It MUST:
	//   - be idempotent: a host already managed (or absent) is a tolerated no-op;
	//   - never touch any block it does not own for a host outside the list;
	//   - never alter the route's backend, mode, or the default-deny.
	// A successful return is not proof — callers read-back-verify that the route
	// is now Managed and behaviour is unchanged.
	Adopt(ctx context.Context, hosts []string) error
}

// Acker is an OPTIONAL capability an EdgeProvider may implement: stamping (or
// removing) the operator's crenel-ack:<reason> marker onto an EXISTING
// declared-unknown route in-place — the `crenel ack`/`unack` verbs (see
// docs/design/ack-marker.md). It generalizes Adopter's pattern (a marker
// written into the live config itself, no sidecar store) to a different
// question: not "is this crenel's to manage" but "has the operator
// acknowledged this unknown." Drivers with no per-route marker/comment/field
// slot (e.g. AdGuard's rewrite API) simply do not implement it.
type Acker interface {
	// Ack stamps the marker onto the FIRST route matching host that crenel would
	// otherwise declare unknown — same backend, same behavior, only the marker
	// changes. It MUST be idempotent (already-acked with the same reason is a
	// tolerated no-op) and never touch a route it fully understands or one
	// belonging to a different host. Returns an error if no matching
	// declared-unknown route is found.
	Ack(ctx context.Context, host, reason string) error
	// Unack removes the marker from host's route, reverting it to whatever
	// Unparsed kind it would otherwise classify as. A no-op if the route is not
	// currently ack'd.
	Unack(ctx context.Context, host string) error
}

// LocatorAcker is an OPTIONAL capability an EdgeProvider may implement,
// EXTENDING Acker's host addressing to STRUCTURAL-PATH addressing: acking a
// declared-unknown route by the exact Locator its Unparsed entry reports
// (e.g. "apps.http.servers.srv0.routes[1].handle[subroute].routes[5]").
// Needed because an unparsed route may have NO recoverable host to hand to
// Acker.Ack (a top-level host-less route with an unmodeled handler is the
// canonical case) — the locator is then the ONLY address crenel has for it.
// The marker stays within the crenel-ack:<qualifier>:<reason> @id convention
// (docs/design/ack-marker.md): the qualifier is a sanitized form of the
// locator, so two path-acked routes never collide on a global @id index and
// ParseAckMarker classifies the route acknowledged on the next read.
// `crenel triage` and `crenel ack --route` are the consumers.
type LocatorAcker interface {
	// AckLocator stamps the marker onto the route AT locator — same
	// match/handlers/backend, only the marker changes. Idempotent (an exact
	// re-ack is a tolerated no-op); refuses a crenel-managed route (that @id
	// means ownership, not acknowledgment) and a locator that does not resolve
	// to a route in the live config.
	AckLocator(ctx context.Context, locator, reason string) error
	// UnackLocator removes any crenel-ack marker from the route at locator.
	// A no-op if the route is not currently ack'd.
	UnackLocator(ctx context.Context, locator string) error
	// RouteRawJSON returns the FULL pretty-printed raw JSON of the route at
	// locator, for the operator to inspect during triage (Unparsed.RawExcerpt
	// is bounded at read time; this is the unbounded evidence view).
	RouteRawJSON(ctx context.Context, locator string) (string, error)
}

// Persister is an OPTIONAL capability an EdgeProvider may implement: writing the
// current crenel-managed routes to DURABLE storage (e.g. an on-disk Caddyfile)
// so they survive a control-plane restart. core calls it AFTER a successful,
// read-back-verified apply. Drivers whose mutations already persist (a config
// file, a DNS provider) do not implement it; only the in-memory Caddy admin API
// needs it. See docs/internal/USABILITY-DESIGN.md §B.
type Persister interface {
	// Persist writes crenel-managed live routes to durable storage additively
	// (rewriting only crenel-managed blocks), validating before and reloading at
	// most once (debounced). It is best-effort durability, NOT part of the apply
	// transaction: a failure is a warning, not a rollback (the running state is
	// already correct and verified).
	Persist(ctx context.Context) error
}

// DurabilityReporter is an OPTIONAL capability an EdgeProvider may implement: it
// declares the edge's PersistenceModel — whether a write that was applied + verified
// LIVE actually SURVIVES a control-plane restart. core uses it on the write path to
// WARN when a verified write lands on an EPHEMERAL edge (admin-API only, no durable
// path), so the operator is never silently left with a change a restart will drop. An
// edge that does not implement it is treated as durable (a file provider whose write IS
// the boot config) — no warning. See model.PersistenceModel and docs/internal/DESIGN.md "Durability".
type DurabilityReporter interface {
	// PersistenceModel returns the edge's declared durability posture. It is config-
	// derived (the admin API carries no boot-source marker), cheap, and never mutates.
	PersistenceModel() model.PersistenceModel
}

// RuntimeVerifier is an OPTIONAL capability a FILE-based EdgeProvider implements to
// declare that its ReadLiveState reads a WRITTEN ARTIFACT (the config file it just
// wrote), NOT the running daemon — so core must not treat a passing ReadLiveState
// re-read as proof the daemon accepted the change. It provides a probe of the RUNNING
// daemon's runtime surface: Traefik's HTTP API, or nginx -t + reload + an HTTP probe.
//
// A driver whose ReadLiveState is ALREADY runtime-authoritative (Caddy reads its live
// admin API) does NOT implement this — core then trusts the re-read as a true verify.
// The PRESENCE of this interface is the driver's declaration "my re-read is the file,
// not the daemon; use my runtime probe instead." This is what prevents a file driver's
// hollow re-read from printing a false "verified" (the headline bench gap T4/N2).
//
// core calls VerifyRuntime AFTER the artifact re-read passes (so the file is known to
// carry crenel's intent). The returned status decides the outcome:
//   - RuntimeVerifyFailed      -> the read-back result flips to NOT-OK -> rollback.
//   - RuntimeVerifyUnavailable -> the write stands, but the report says "written;
//     runtime verify unavailable" (NEVER "verified").
//   - RuntimeVerifyConfirmed   -> "verified LIVE (daemon confirmed)".
//
// VerifyRuntime MUST honor ctx's deadline and never hang (the never-hang lesson applies
// to every daemon probe). It is a READ probe: any state-changing step a daemon needs to
// go live (e.g. nginx -s reload) belongs in the driver's Apply, not here.
type RuntimeVerifier interface {
	VerifyRuntime(ctx context.Context, op model.Op, ec model.EdgeChange) model.RuntimeVerification
}

// EvidenceReporter is an OPTIONAL capability an EdgeProvider may implement: it
// DECLARES what its ReadLiveState actually observes — the running process (RUNTIME:
// Caddy admin API, Traefik API) or a file/tree on disk (CONFIG: a Caddyfile, an
// nginx tree). "Verified" in crenel means read-back-after-write; a pure read has no
// write to verify, so instead every audited edge carries its evidence kind
// (audit-any-edge §5). core folds it into AuditScope.Evidence and emits the standing
// config_evidence_only finding (+ mtime staleness hint) for CONFIG edges — what stops
// a stale file from producing a confident wrong answer (risk A.2). A provider that
// does not implement it is simply UNCLASSIFIED — never assumed RUNTIME.
type EvidenceReporter interface {
	// ReadEvidence is config-derived (the driver knows its substrate at
	// construction), cheap, and never mutates or opens a connection.
	ReadEvidence() model.ReadEvidence
}

// HealthChecker is an OPTIONAL capability a provider may implement: a quick,
// bounded liveness probe of its control plane. core uses it to avoid firing
// compensating reloads into a wedged edge during rollback (which would worsen the
// wedge). Providers that cannot cheaply probe simply do not implement it.
type HealthChecker interface {
	// Healthy returns nil if the control plane is responsive, or an error
	// (ideally a recognisable "unresponsive" error) if it is not.
	Healthy(ctx context.Context) error
}
