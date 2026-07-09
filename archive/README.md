# Archive

Superseded / point-in-time material, kept for the audit trail rather than deleted.
Nothing here is required to build, test, or understand current Crenel — start at the
root [`README.md`](../README.md), [`docs/WHAT-CRENEL-DOES.md`](../docs/WHAT-CRENEL-DOES.md),
and [`STATE-OF-CRENEL.md`](../STATE-OF-CRENEL.md) instead.

> **Anonymized for publication.** These documents record live work against the
> maintainer's real infrastructure. Hostnames, zones, addresses, and host identifiers
> have been consistently pseudonymized (`homelab.example`, `smallbiz.example`,
> RFC 5737/1918 ranges, generic host labels); commands, configs, and results are
> otherwise verbatim. Byte-for-byte originals are retained privately.

- **`incident-2026-06-27/`** — the 2026-06-27 Caddy-wedge postmortem + goroutine-dump
  root-cause diagnostics. The bug is fixed (shipped in v0.2.0); kept in case the failure
  mode ever recurs.
- **`trials/plans/`** — dated pre-trial plans for one-off live trials. Each has a
  corresponding write-up in `trials/results/` (or the root `TRIAL-RECORD-*.md`) that
  supersedes it.
- **`trials/results/`** — dated write-ups of individual live trials (2026-06-27 →
  2026-06-29) against real infrastructure, each already folded into
  `STATE-OF-CRENEL.md` and `../docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md`, which
  is the current consolidated proof record.
- **`outputs/`** — a pre-launch checklist snapshot, superseded by `STATE-OF-CRENEL.md`'s
  own backlog section.
- **`diag-artifacts/`** — raw goroutine/log captures from the 2026-06-27 incident,
  companion to `incident-2026-06-27/`.
- **`BUILD_LOG.md`** — the frozen per-increment development narrative (M0 → v0.3.1).
  Release-level history continues in the root [`CHANGELOG.md`](../CHANGELOG.md).
- **`CONTEXT.md`** — historical maintainer-continuity notes (conventions, roadmap
  snapshots) from the pre-launch build.
- **`PROVING-GROUND.md`** — the maintainer's standing live bench (real Caddy / Traefik /
  nginx / Authentik) used for the trial-before-merge cadence described in
  [`CONTRIBUTING.md`](../CONTRIBUTING.md).
