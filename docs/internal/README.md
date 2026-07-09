# Internal docs

Maintainer/design docs — not needed to build, run, or use Crenel day to day. If
you're a user, start at the root [`README.md`](../../README.md) instead.

Suggested reading order:

1. [`DESIGN.md`](DESIGN.md) — the architecture: the two load-bearing invariants
   (live-state-authoritative, structural default-deny), the driver model, and
   how each verb (expose/unexpose/import/apply/audit/verify) behaves.
2. [`TOPOLOGY-RISK-REGISTER.md`](TOPOLOGY-RISK-REGISTER.md) — a forward-looking
   enumeration of real-world reverse-proxy/edge/auth topologies Crenel will meet
   in the wild, and an honest classification of how it behaves on each.
3. [`STRAIN.md`](STRAIN.md) — where the `EdgeProvider` port strains, written
   while adding the second driver (Traefik) to test whether the abstraction
   holds or is fake agnosticism.
4. [`AUTH-DESIGN.md`](AUTH-DESIGN.md) — the forward-auth-by-reference design
   note: Crenel attaches an auth policy by reference and never embeds the auth
   provider's internals.
5. [`USABILITY-DESIGN.md`](USABILITY-DESIGN.md) — the brownfield-usability
   design note covering ownership/adoption (`import`), persistence, and
   declarative `apply`.
6. [`BUNDLE-DESIGN.md`](BUNDLE-DESIGN.md) — design-only proposal for a turnkey
   Crenel "bundle" distribution (nothing built yet at time of writing).
7. [`TRIAL-RECORD-live-proofs-2026-06-30.md`](TRIAL-RECORD-live-proofs-2026-06-30.md)
   — the operator-record write-up of the 2026-06-30 live proofs (shared-zone
   Cloudflare, dual-AdGuard parity, full-chain expose) that closed punch-list
   items without their own standalone trial-result doc.
8. [`DEPLOY-VPS.md`](DEPLOY-VPS.md) — the runbook for running Crenel directly
   on the VPS edge host, against its loopback-only admin API.
9. [`TEASER-TIMELINE.md`](TEASER-TIMELINE.md) — the living plan/timeline for
   Crenel's capability teaser reel (fake-names-only demo-recording discipline).
