# Open-core boundary

Crenel is **open-core**. This document draws the line explicitly: what is
Apache-2.0 core (now), what could live in a separately-licensed enterprise
directory (later), and the design rule that keeps the seam clean enough that the
core stands on its own.

This is a *boundary policy*, not a roadmap. The core is intended to be a
complete, genuinely useful tool with no enterprise directory present at all.

## The principle

> The Apache-2.0 **core is the whole product for an individual operator.** The
> open-core line never removes capability from the core to upsell it. The
> enterprise seam adds *organizational* concerns (multi-operator, attestation,
> retention) on top of a core that is already correct and complete on its own.

If a feature is needed to safely answer **"what is exposed right now, and is
default-deny actually enforced"** for one operator on their own infra, it belongs
in the core. Full stop.

## What is Apache-2.0 core (today)

Everything in this repository is Apache-2.0 (see [`LICENSE`](../LICENSE)). That
includes, and will keep including:

- The CLI and every verb: `status`, `audit`, `drift`, `reconcile`, `expose` /
  `unexpose`, `set`, `rename`, `import`, `apply`, `resume`, `export`.
- The hexagonal core: `internal/core` (preview/apply/audit/status engine),
  `internal/model` (pure domain types), `internal/ports` (the interfaces).
- All four driver families: reverse-proxy edges (**Caddy / Traefik / nginx**) and
  the identity mesh (**NetBird**), DNS via **dnscontrol** (split-horizon
  internal + public), and origin resolution.
- The three load-bearing invariants: **live-state-authoritative**,
  **structural default-deny**, and **bounded honesty** (detect-and-declare-unknown,
  refuse-to-manage foreign/unknown routes).
- `read-back-verify` on every mutating path, the Caddyfile persistence path, the
  branded `internal/ui` (wordmark + status HUD), and the full faithful-fake test
  suite.

The core is not crippleware. It is the heart of the project (a FOSS operator
CLI), and it is meant to be excellent by itself.

## What could be enterprise (later, separately licensed)

A future top-level directory (e.g. `enterprise/`) under a **separate, non-Apache
license** could add concerns that only matter once *multiple people in an
organization* depend on the edge. Candidates (**none built, none promised**):

- **Compliance / audit ledger.** An append-only, signed record of every
  apply/expose/unexpose across time and operators: "who exposed what, when, with
  whose approval, and what the read-back proved." The core verifies *now*; this
  would retain and attest *over time* for audits (SOC 2 / change-management).
- **Multi-operator & policy.** RBAC, approval gates ("a second operator must
  confirm a new public host"), org-wide exposure policy, fleet rollups across
  many edges.
- **Integrations of an organizational nature.** SSO for the (future) dashboard,
  ticketing/SIEM export, long-term drift history and alerting.

These sit *on top of* the core through the existing ports. They consume core's
verified results; they do not replace or fork its logic.

## The design rule that protects the seam

The boundary is not just policy. It is enforced by the architecture, so the core
can never quietly grow a dependency on proprietary code:

- `internal/core` and `internal/model` **never import a driver package.**
- Drivers depend only on `internal/model` and `internal/ports`.
- Concrete drivers (and, later, any enterprise driver/decorator) are wired in
  **exclusively at `cmd/crenel`**, the composition root.
- A unit test (`internal/core/deps_test.go`) asserts this import graph, so the
  rule cannot silently rot.

Because everything attaches at `cmd` through `EdgeProvider` / `DNSProvider` /
`OriginResolver` (and could attach through a future `LedgerProvider` port), an
enterprise build is *additive wiring*, not a patch to core. The Apache core
compiles, tests, and ships with nothing enterprise present. See
[`DESIGN.md`](../DESIGN.md) for the full hexagonal architecture.

## Licensing & contributions across the boundary

- The **core** is Apache-2.0. Contributions to it are welcome and stay Apache-2.0.
- The reason the project asks contributors to accept a **CLA** in addition to the
  per-commit **DCO** is precisely this boundary: the CLA grants the maintainer the
  latitude to offer the project (including building a separately-licensed
  enterprise layer that links the Apache core) without having to re-contact every
  past contributor. The DCO certifies provenance; the CLA grants licensing
  latitude. See [`CLA.md`](../CLA.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- **No-VC by intent.** The project is built to be a sustainable, operator-first
  FOSS tool, not a growth-funded land-grab. Open-core (core free forever +
  optional enterprise for organizations) is the sustainability model, chosen so
  the core never has to be compromised to satisfy outside investors.

## Naming & trademark note

The open-core boundary, the CLA's relicensing grant, and the trademark posture
(name/wordmark reserved; nominative use fine, see [`NOTICE`](../NOTICE)) are
documented here alongside the naming.
