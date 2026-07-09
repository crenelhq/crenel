# Crenel — Launch-Readiness Checklist

> The honest "what's done / what's left" before a public FOSS launch. Treats the
> docs the same way the code treats the edge: **never silently wrong**. If an item
> says "DONE", that's verifiable from the repo right now; if it says "TBD" the
> blocking work is named. Last updated 2026-06-30 against `develop` HEAD `e3597de`
> (post-PR-#17 capstone).

This list is **the launch-side companion** to `STATE-OF-CRENEL.md` §6.z bucket C.
The correctness phase (§5i, PRs #11–#17) is complete and offline-provable.

---

## A. Code / correctness

| Item | Status | Notes |
|---|---|---|
| `make check` green + race-clean uncached on `develop` | ✅ DONE | 17 test packages OK, 5 with no test files, 498 test functions |
| Offline-provable silently-wrong gaps closed | ✅ DONE | PRs #11–#17 capstone; STATE §5i |
| Documented limits visible in the README | ✅ DONE | "Documented limits (honest)" section, this pass |
| `STATE-OF-CRENEL.md` reflects merged state through #17 | ✅ DONE | this pass |
| `docs/REFERENCE-ARCH-split-horizon.md` accurate to current build | ✅ DONE | this pass — §5 table updated; dual-AdGuard + wildcard awareness + Tailscale funnel marked BUILT |

## B. License, NOTICE, governance

| Item | Status | Notes |
|---|---|---|
| `LICENSE` (Apache-2.0) | ✅ present | repo root |
| `NOTICE` | ✅ present | repo root; carries the "Crenel is a working name" note + trademark line |
| `DCO.txt` (Developer Certificate of Origin v1.1) | ✅ present | repo root |
| `CLA.md` (one-time CLA, dual sign-off model) | ✅ present, **template state** | per its own front-matter: "Status: prepared, not yet activated… legal-entity name, contact address, and the final project name are filled in at activation" |
| `CODE_OF_CONDUCT.md` | ❌ TBD | Apache projects typically ship the Contributor Covenant v2.1 verbatim; add before the first external contribution |
| `SECURITY.md` (responsible disclosure contact) | ✅ present | confirm `security@<final-domain>` once domain is set |
| `CONTRIBUTING.md` (testing bar, faithful-fake rule, trial cadence) | ✅ present | references DCO + CLA + LICENSE; project-status banner says "pre-public-launch, solo maintainer" |
| `docs/OPEN-CORE.md` (the open-core boundary, enforced in code) | ✅ present | core never imports a driver; enforced by package layout |

## C. Project identity

| Item | Status | Notes |
|---|---|---|
| Working name "Crenel" + rationale documented | ✅ DONE | README + NOTICE — "rename is one find/replace; see internal/config/naming.go" |
| Final name decision | ❌ TBD | the rename is mechanical; the *decision* is what's outstanding |
| Domain registrations | ❌ TBD | confirm `crenel.sh` (already used as the live-trial dedicated zone, so the operator already controls it) AND the final org's primary domain |
| GitHub org `crenelhq` | ❌ TBD — **NOT VERIFIED FROM THIS REPO.** The go.mod module path is `github.com/crenelhq/crenel`, which assumes the org exists. The repo itself currently lives on the self-hosted Forgejo at `10.0.0.13:3030/nate/crenel`. Status of the `crenelhq` GitHub org and the upstream `crenelhq/crenel` repo needs to be checked outside this session before launch. |
| Wordmark + brand assets | ✅ DONE | `docs/brand/` — wordmark light/dark SVG, status HUD SVG; `BRANDING.md` defines the semantic-color rule |

## D. Package-name reservations

Crenel is a **single static Go binary** distributed by `go install` + `make release`
artifacts. The set of ecosystems where a name reservation is correctness-relevant is
narrower than the generic "npm/PyPI/crates" checklist suggests.

| Registry | Applicable? | Status | Notes |
|---|---|---|---|
| Go module path (`github.com/crenelhq/crenel`) | ✅ yes (this IS how `go install` works) | depends on the GitHub org / repo decision in §C | the module path IS the package coordinate in Go |
| GitHub `crenelhq` org + `crenel` repo | ✅ yes | TBD — see §C | the public-facing repo is the package |
| Docker Hub `crenelhq/crenel` (for the bundle image / a CLI image) | ⚠️ optional | TBD | useful if the `bundle/` docker-compose stack ships a published image (today the bundle builds locally) |
| GitHub Container Registry `ghcr.io/crenelhq/crenel` | ⚠️ optional | TBD | same as Docker Hub |
| Homebrew tap | ⚠️ optional | TBD | not blocking — `go install` is the primary path |
| npm | ❌ N/A | — | not a JS project, no npm consumer |
| PyPI | ❌ N/A | — | not a Python project |
| crates.io | ❌ N/A | — | not a Rust project |

**Recommendation:** reserve the Go module path / GitHub org / repo first (load-bearing).
Docker Hub + ghcr are nice-to-have once the bundle ships an image. Reserving npm / PyPI /
crates would be defensive cybersquatting against name collision, not functional.

## E. Live-trial gates (before any public claim of a capability)

Each of these is the SEPARATE LIVE GATE for a built-and-tested capability. The build
is done offline; the gate is a one-shot live verification, recorded byte-for-byte.

| Trial | Status | Gate document |
|---|---|---|
| Caddy admin-API live read on home edge | ✅ DONE | (verified during earlier passes; ssh-exec transport) |
| Surgical Cloudflare on dedicated `crenel.sh` zone | ✅ DONE | live-proven 2026-06-30, see STATE §0a |
| Cloudflare DNS hardening (TTL + proxied fidelity, idempotency, rollback) on `crenel.sh` | ✅ DONE | live-proven 2026-06-30, see STATE §0a |
| Durable Caddyfile persist (the home wildcard-site reconciler) | ⚠️ separately gated | `TRIAL-PLAN-durable-persist.md` |
| Cross-chain coordinated WRITE on the real home + VPS chain | ⚠️ separately gated | mentioned in STATE §5d; trial-plan TBD |
| Dual-AdGuard split-horizon, vantage-correct targets | ⚠️ separately gated | trial-plan TBD; described in `docs/REFERENCE-ARCH-split-horizon.md` §5 |
| Surgical Cloudflare on the **shared** `homelab.example` zone | ⚠️ separately gated | needs `Zone:DNS:Edit` token scoped to that zone + the maintainer's explicit go |
| Tailscale serve.json WRITE (the read side already shipped in PR #17) | ❌ TBD — write path not built | the audit / status read path is now per-host wildcard-aware, but `tailscale serve` writes are not yet implemented |

## F. Release / packaging

| Item | Status | Notes |
|---|---|---|
| Versioned release tags exist | ✅ DONE | `v0.3.0`, `v0.3.1`, `v0.3.2` (see `git tag`) |
| `make release` cross-compiles linux/{amd64,arm64} + darwin/{amd64,arm64} | ✅ DONE | README documented |
| Static / zero-dependency binary | ✅ DONE | stdlib-only; no cgo |
| `CHANGELOG.md` (or similar) | ⚠️ partial | release notes live as files in the tree; consolidating a single `CHANGELOG.md` would help launch discoverability |
| Signed releases | ❌ TBD | not blocking for v0.4.0; useful before v1.0 |

## G. Docs surface

| Doc | Audience | Status |
|---|---|---|
| `README.md` | first-touch | ✅ DONE this pass — capabilities + documented limits |
| `STATE-OF-CRENEL.md` | maintainer + serious evaluator | ✅ DONE this pass — current truth through #17 |
| `DESIGN.md` | architecture | ✅ present |
| `docs/DNS-DESIGN.md` | DNS driver design | ✅ present, includes §12b.i wildcard-awareness + §12b.ii sibling wildcard-awareness |
| `docs/REFERENCE-ARCH-split-horizon.md` | preferred-method walkthrough | ✅ DONE this pass — §5 table updated |
| `docs/OPEN-CORE.md` | governance | ✅ present |
| `SECURITY.md` | threat model + secret redaction | ✅ present |
| `AUTH-DESIGN.md` / `USABILITY-DESIGN.md` / `BRANDING.md` | feature/visual | ✅ present |
| `TOPOLOGY-RISK-REGISTER.md` | long-tail safety spec | ✅ present |
| `BUILD_LOG.md` | per-increment narrative | ✅ present |
| `CONTRIBUTING.md` | external contributors | ✅ present |

---

## Honest gating summary

**Blocking before a public FOSS launch:**

1. **Final-name decision + GitHub org `crenelhq` + upstream `crenelhq/crenel` repo created.** This is THE load-bearing TBD — the rename in code is one find/replace, but the go.mod path + import paths assume `github.com/crenelhq/crenel` exists on github.com.
2. **`CODE_OF_CONDUCT.md`** (Contributor Covenant v2.1 verbatim is the standard pick).
3. **CLA activation** — fill in legal-entity name, contact, final project name; the template is ready.
4. **`SECURITY.md` disclosure contact** finalized to the chosen domain.

**Not blocking but worth doing before v0.4.0:**

5. Consolidated `CHANGELOG.md` at repo root (today each tag has its own notes file).
6. Docker Hub / ghcr image publish for the `bundle/` stack.

**Not blocking; do at v1.0:**

7. Signed release artifacts.
8. The live trials still gated (durable-persist, cross-chain, dual-AdGuard, surgical-CF-on-shared-zone).

**Explicitly NOT on the critical path:** npm / PyPI / crates registrations — not a JS / Python / Rust project. The Go module path is what `go install` needs.
