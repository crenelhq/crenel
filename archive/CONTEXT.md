# crenel — Project Context & Continuity

> **ARCHIVED (2026-07-02).** Historical maintainer-continuity notes, kept for the audit
> trail; identifiers anonymized for publication. Start at the root `README.md` instead.
>
> Quick-start for any agent picking up crenel. For the technical state map see **STATE-OF-CRENEL.md**; for history see **BUILD_LOG.md** and the `TRIAL-RESULT-*.md` docs. This file captures the **decisions, conventions, and roadmap** that aren't obvious from the code.

## What crenel is
A vendor-agnostic, **live-state-authoritative** control plane (Go CLI) for split-horizon edge exposure. It sits above your existing reverse-proxy edge + DNS + overlay and drives them; reimplements nothing. One-liner: *one file/command declares what's public → edge allowlist + internal split-horizon DNS + public DNS, default-deny, with plan/apply preview.* Core promise: **never silently wrong** (read-back-verify against the running daemon; declare-unknown rather than guess).

## Brand decisions (LOCKED 2026-06-29)
- **Name: `crenel`** — /ˈkrɛn.əl/ ("CREN-uhl, like fennel"). Rejected the "CRENL" vowel-drop; kept the real word for the metaphor (a crenel = the deliberate gap in a default-deny battlement). Phonetics go in the **README**, NOT the banner.
- **Taglines:** hero = `Every edge in atomic agreement. Verified.`; technical strapline = `EDGES · DEFAULT-DENY ENFORCED · SOURCE OF TRUTH · EXPOSED` (crenel's own status-bar voice).
- **Banner / mark:** the pagga-style wordmark with the distinctive **big lowercase `n`** (non-negotiable — it's the mark's symmetry). NO drop-shadow (depth comes from character texture). Chosen theme = **"the wall"**: a crenellated battlement where each gap is a live exposed host colored by state (🟢 verified / 🟠 about-to-go-public / 🔴 fail-open). The banner is a LIVE security-posture readout. Radium green (#00FF66) on near-black. The CORE MATRIX `status --hud` panel is the other key brand surface.
- **Domains: SECURED** `crenel.sh` (since 2026-07-03 the single canonical domain: site + email + install) plus a defensive secondary, on Porkbun (2yr, auto-renew/lock/privacy). TAKEN/route-around: `crenel.io`+`.app` (squatter), `crenel.com` (HugeDomains ~$8.5k), `crenel.org`. Still to grab (free): `crenelhq` GitHub org + npm/PyPI/crates/Homebrew name reservations.
- **Trademark:** self-search clear — no live CRENEL mark in software (classes 9/42); the one live CRENEL mark is EuroChem fertilizer (class 1). A registered mark later would give UDRP leverage to reclaim squatted domains. Optional, file around launch (ideally with an attorney).

## What's built & PROVEN LIVE (v0.3.0, on develop)
4 edge drivers (Caddy/Traefik/nginx/NetBird) — Caddy + Traefik + nginx all bench-validated with real runtime verify. Verbs: status/audit/drift/reconcile + expose/unexpose/set/rename/import/resume/export. Multi-edge atomic coordination with all-or-nothing rollback. A `serve` read-only HUD dashboard, a read-only `crenel mcp` server, and a v0 bundle (`docker compose up`). **Five clean live production trials:** the 302 cross-chain auth write, the durable home-edge persist cycle, the two-verb + one-command rename, the cross-vendor Caddy+Traefik atomic+rollback, and the **first real managed durable expose on the home edge** (`crenel-demo.homelab.example`, left up). Every trial left production byte-for-byte as found.

## Conventions (how to work on crenel)
- **Ultracode / max effort** for code sessions (the maintainer's standing preference).
- **Faithful fakes**: test doubles must reject what the real system rejects. Live testing repeatedly caught bugs fakes couldn't — hence the standing proving-ground bench.
- **Trial-before-merge** for anything touching a real edge: backup + sha anchors, read-back-verify, byte-for-byte restore as abort-only fallback, sole executor, no fan-out on live infra.
- **Worktree isolation** for parallel code agents on this repo (don't switch branches in the shared main checkout).
- **Source control = the maintainer's self-hosted git remote** (private), not GitHub. Push via a GIT_ASKPASS helper; never embed the token.
- **Demo/teaser assets:** human-typing cadence (jittered keystrokes + pauses, demo-magic style), FAKE hostnames only (never the operator's real domains) — see TEASER-TIMELINE.md.

## Key infra
- **Proving ground:** the bench host `crenel-proving` @ 10.0.0.20 (Proxmox `proxmox`) — standing real Caddy/Traefik/nginx/Authentik for live bench-testing (see PROVING-GROUND.md).
- **Real edges:** VPS front (Caddy admin, read-only crenel v0.3.0 installed) + home edge (10.0.0.13, Caddy; write-enabled crenel installed, durable persist on).

## Roadmap / what's next
1. Bake the chosen "wall" banner theme into `internal/ui` (live-wired), confirm via real-binary capture.
2. Consolidate staged branches onto develop: `feat/public-launch-prep` (Apache/CLA/README/brand), `feat/crenel-mcp` (read-only MCP). (Also pending: `feat/bundle-v0`, `feat/bundle-design`, the brand-banner branch.)
3. **DNS for real** (the marquee feature): wire live Cloudflare + AdGuard providers and bench-prove — upgrades the tagline from "every edge" to "every layer." (Today DNS is built but mock-only — renders to a fake provider, never run live.)
4. Bundle v0.1 (durable-persist on by default), NetBird real-API driver.
5. Brand grabs (crenelhq org + package names), then public repo + release.

## Strategy
FOSS operator CLI is the heart (Headscale-style ceiling, no-VC). The **bundle** is an on-ramp/distribution mode (crenel = brain, best-of-breed = swappable batteries), NOT a reimplementation and NOT a single-stack appliance — that cross-stack coordination is the moat vs Pangolin. Apache-2.0 core + CLA/DCO before first external PR.
