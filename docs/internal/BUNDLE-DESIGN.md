# Crenel Bundle — Design Doc

> **Status:** DESIGN ONLY. Nothing built yet. This doc proposes the shape of Crenel's
> turnkey "bundle" distribution and tees up the open decisions for the maintainer. No appliance
> code is part of this change.
>
> Companions: **DESIGN.md** (architecture + invariants), **STATE-OF-CRENEL.md** (true
> current state + backlog), **docs/OPEN-CORE.md** (the licensing seam), **README.md**.
>
> _Branch `feat/bundle-design` off `develop`. 2026-06-28._

---

## 0. The decision (frame everything around this)

The bundle is a **distribution / on-ramp MODE — not a new identity.**

Crenel stays exactly what it is: the **live-state-authoritative, bounded-honesty,
multi-vendor coordination BRAIN** that works across whatever edge / DNS / overlay the
operator already runs. The bundle ships **opinionated-but-swappable batteries** (a
default edge + DNS + overlay) pre-wired to Crenel, so a newcomer gets *one command → a
working default-deny split-horizon edge, batteries included* — while the **same Crenel
binary** still points at an existing BYO stack with zero bundled pieces.

Two hard "nots", load-bearing:

- **We reimplement no data plane.** No homegrown proxy, DNS server, or overlay. The
  bundle *composes* best-in-class FOSS components Crenel already drives.
- **We do not build a hosted SaaS.** The bundle is something the operator runs on their
  own box. (A managed offering is explicitly out of scope; the open-core seam in §5
  keeps that option closed-by-default and clean if it ever opens.)

**Why this is the whole game (the anti-Pangolin thesis).** Pangolin (Fossorial, YC 2025,
~19k★) is the fast incumbent in the self-hosted tunneled-reverse-proxy appliance space.
It is **one opinionated stack — Traefik + WireGuard + a dashboard — adopted wholesale.**
Adopt it and you live inside its stack; leave it and you leave everything.

Crenel's structural differentiator is the **cross-stack control plane**: it coordinates
over Caddy **and** Traefik **and** nginx, on-prem **and** VPS, **atomically**, with
read-back-verify and "never silently wrong." The bundle must *keep* that — it is the
moat. The bundle is "here's a great default stack to start from," and because Crenel's
architecture is driver-agnostic (§3), **every battery is swappable for what you already
run.** Pangolin can't offer that without ceasing to be Pangolin; for Crenel it falls out
of the architecture for free.

One line:

> **Crenel** — the control plane for your self-hosted edge. *Batteries included, none
> required.* One command brings up a default-deny, split-horizon edge; the same binary
> drives the Caddy / Traefik / nginx / DNS / overlay stack you already have.

---

## 1. v0 — the smallest turnkey "entire service" that proves the value

**Recommendation: ship v0 as edge-only, Caddy + Crenel + the web HUD, via one
`docker compose up`.** This is the smallest artifact that delivers the felt experience
("I typed one command and got a working, *honest* default-deny edge I can drive") without
Crenel having to vouch for anything not yet live-proven.

### What v0 is

```
docker compose up         →   a working default-deny edge, controlled by crenel verbs,
                              zero assembly, with a live "what's exposed right now" view.
```

| Component | Role in v0 | Why this one |
|---|---|---|
| **Crenel** | the brain; config baked for the bundled topology | the product |
| **Caddy** | the bundled edge data plane | the **only** edge Crenel has proven end-to-end on a live edge — granular apply, durable persist, the literal `302` chain write (STATE §5b/§5d/§5g). Structural default-deny is real here. |
| **Web HUD** | read-only "what's exposed right now" as a browser view | `internal/ui` **already renders `StatusHUDSVG(HUDModel)`** — v0 wraps it in a ~50-line static handler + a JSON poll of `status --json`. Near-zero new surface. |

The newcomer's first five minutes:

```bash
git clone … && cd crenel/bundle
docker compose up -d
open http://localhost:8080          # the HUD: EXPOSED 0 · DEFAULT-DENY ENFORCED
crenel expose whoami --auth none    # one verb; read-back-verified
# HUD flips to EXPOSED 1 (public) — amber, because no auth, on purpose
```

### Why edge-only, why Caddy-only, for v0

- **It proves the thesis with the strongest evidence.** Caddy is the one edge with live
  trial receipts. v0 must not ship a claim Crenel can't stand behind on day one.
- **The "entire service" feeling comes from `compose up` + the HUD, not from breadth.**
  A working default-deny edge you can *see* and *drive* is the demo. DNS/overlay add
  reach, not the core "aha."
- **It is honest about its own boundary.** v0 is "a great Caddy edge, batteries
  included." The swappability (§3) and the rest of the stack (§2) are *advertised as the
  roadmap*, not faked into v0.

### v0 explicitly includes / excludes

- **In:** Crenel + Caddy + web HUD; a baked compose topology (loopback-only Caddy admin,
  per SECURITY.md's loopback-first transport model — Crenel reaches it in-network, never
  a published admin port); a `whoami`/demo upstream so `expose` does something visible; a
  scaffolded `crenel.settings` pointed at the bundled Caddy; `granular_apply: true` and
  `caddy_persist` wired so writes survive `docker restart` out of the box.
- **Out (deferred to §2):** bundled DNS, bundled overlay, any non-Caddy edge as a
  *default*, a write-capable dashboard.

**One open call for the maintainer (see §7):** v0 = edge-only (recommended) vs. v0 = edge + internal
DNS. Including AdGuard in v0 tells the full split-horizon story sooner but doubles the
"does the default-deny claim hold" surface on day one. I lean edge-only.

---

## 2. Phased roadmap — v0 → fuller bundle

Each tier is honest about its dependency: **a battery only becomes a bundled default once
Crenel's driver for it is live-validated.** Until then it ships as a *documented swap-in*,
not a default. (See §4 for the gating rule.)

| Tier | Adds | Story it unlocks | Depends on |
|---|---|---|---|
| **v0** | Crenel + **Caddy** + web HUD | "one command → a working, honest default-deny edge you can drive + see" | Caddy driver (proven live ✔) |
| **v1 — split-horizon (internal)** | + **AdGuard Home** as internal DNS | "expose photos" now also publishes the *internal* name; LAN clients resolve split-horizon | dnscontrol driver scoped internal (built); AdGuard provider wiring validated on the bench |
| **v2 — split-horizon (public)** | + **Cloudflare via dnscontrol** for public DNS | the **full split-horizon**: one verb sets internal + public names with exposure-rank ordering (public last) | dnscontrol public scope (built); a real Cloudflare credential path |
| **v3 — reachability default** | + an **overlay/tunnel default** for origin/tunnel ingress (Tailscale **/** Headscale **/** NetBird — assess below) | "expose from a box with no public IP" — the Pangolin core use case, but cross-stack | the chosen overlay's ingress modeled per-host (cloudflared per-host is done, STATE §5h; Tailscale serve.json per-host is the documented follow-on) |

### v3 overlay assessment (the one genuinely open battery)

The overlay is where the bundle most directly answers Pangolin's "tunnel from anywhere"
pitch, and it's the least-settled choice. Crenel already has a **NetBird** mesh driver
(reads; refuses HTTP mutation loudly — STATE M5) and models cloudflared/Tailscale ingress
posture (P3 + §5h).

| Option | Fit for a *bundled default* | Notes |
|---|---|---|
| **Headscale** | **Recommended default to target.** | Self-hosted Tailscale control plane — the **"Headscale-style ceiling"** is already Crenel's stated posture (FOSS, self-hosted, no SaaS dependency). Keeps the bundle fully self-hostable. Crenel models the Tailscale data plane already; gap is Headscale control-plane wiring + per-host serve.json recovery. |
| **Tailscale (SaaS control plane)** | Best UX, **violates self-hostable-by-default.** | Easiest onboarding, but introduces a hosted dependency the no-SaaS posture rejects as a *default*. Ship as a documented swap-in for users who want it. |
| **NetBird** | Already a driver; mesh-grant model. | Strongest if the bundle leans identity-mesh (WireGuard ACLs) rather than tunneled-reverse-proxy. Reads today; mutation is refused — would need write support before it's a *default*. |

**Recommendation:** target **Headscale** as the bundled overlay default (matches the
self-hosted ceiling), with **Tailscale** and **NetBird** as first-class swap-ins. Flag
for the maintainer (§7) — this is a real fork in positioning.

---

## 3. Swappable batteries — the mechanism (the moat, made concrete)

The whole anti-Pangolin claim rests on this section being *mechanically true*, not
aspirational. It is — because **the bundle's "default" is nothing more than a default
value in Crenel's existing driver/config selection.** Swapping a battery is editing
config + swapping a compose service; **Crenel's core does not change.**

### Why it falls out of the architecture we already have

Crenel is hexagonal: `internal/core` and `internal/model` **never import a driver**;
every concrete driver is wired **only at `cmd/crenel`** through the ports
`EdgeProvider` / `DNSProvider` / `OriginResolver` / `Transport`. A `deps_test.go`
asserts this import graph (OPEN-CORE.md). The driver in use is selected by config
(`edge_driver`, `dns_*`, `transport`, `auth_policies`). **The bundle picks the
defaults; it does not hardcode them.**

So a "battery" is just: *(bundled compose service) + (a default in the scaffolded
`crenel.settings`) + (the matching Crenel driver, which already exists).*

### The swaps, concretely

| Swap | What the user changes | What Crenel does | Driver status |
|---|---|---|---|
| **Caddy → Traefik** | compose service + `edge_driver: traefik` + admin/file path | same verbs; Traefik file-provider driver renders the route + middleware-by-reference auth | built; **gated** (§4) — live-validate on the bench first |
| **Caddy → nginx** | compose service + `edge_driver: nginx` | same verbs; nginx driver writes a `# crenel-managed` block, `auth_request` auth | built; **gated** (§4) |
| **AdGuard → Pi-hole** | compose service + DNS provider config | DNS verbs unchanged (dnscontrol abstracts the provider) | dnscontrol-dependent; validate provider |
| **Cloudflare → other public DNS** | dnscontrol creds/provider | unchanged | dnscontrol-dependent |
| **Headscale → Tailscale / NetBird** | compose service + overlay config | ingress/origin resolution per the overlay driver | per §2 (NetBird reads today; write gated) |
| **Bundled edge → BYO edge (no bundle at all)** | point `crenel.settings` at the existing edge; bring up *zero* bundled services | this is just crenel-the-CLI — the original product | proven |

**The key property:** the last row is not a special mode. **"BYO stack" and "bundled
stack" are the same binary reading different config.** That is precisely what a
single-stack appliance (Pangolin) structurally cannot say, and it is why the bundle keeps
the differentiator instead of becoming an appliance.

### How the bundle expresses defaults without forking config

Recommended: the bundle ships a **compose file + a scaffolded `crenel.settings`** whose
values are the opinionated defaults (Caddy edge, loopback admin via in-network transport,
granular + persist on). Swapping = editing those values and the corresponding compose
service. No bundle-specific code path in Crenel; the bundle is *data + composition*, which
keeps the core honest and the seam (§5) clean.

---

## 4. Honest gating — what the bundle may and may not claim

**The rule:** the bundle ships as a *bundled default* only what Crenel has **live-proven**;
everything else ships as a **documented swap-in** with its real status stated. The bundle
must **never** claim multi-vendor breadth that the drivers haven't earned on the bench.

| Claim | Allowed in the bundle? |
|---|---|
| "v0 gives you a working default-deny **Caddy** edge, durable, read-back-verified" | **Yes** — live-proven (STATE §5b/§5d/§5g, real `302`). |
| "Swap to **Traefik/nginx** with one config change" | **Yes, as a swap-in** — *and only after* each is live-validated on the proving ground (see archive/PROVING-GROUND.md). Until then the doc/README says "Caddy is the proven default; Traefik/nginx drivers are built and pass faithful-fake suites, live-validation in progress." |
| "Crenel coordinates **across** Caddy + Traefik + nginx atomically" | **Yes as the architectural claim** (it's the design + tested against faithful fakes), **but** the *bundle's* turnkey promise stays Caddy-first until the file drivers clear the bench. |
| "Bundled DNS / overlay split-horizon works turnkey" | **Not until v1/v2/v3** ship with their providers validated. Roadmap, not v0 claim. |

**Why this matters specifically here:** the bundle is a newcomer's *first* contact with
Crenel. A bundle that defaults to an unproven edge and reads back green on a config it
silently mismodeled would violate the bounded-honesty invariant *at the worst possible
moment* (first impression). The file-driver fixes are in flight (STATE §5h closed the
read-side path-granular misreads across all three drivers; the write/live-validation tail
remains). **v0 defaults to Caddy precisely to avoid making a breadth claim Crenel can't
yet stand behind live.** Breadth is the *advertised trajectory*, proven one driver at a
time on the bench, then promoted from swap-in → default.

---

## 5. FOSS + open-core boundary for the bundle

**The bundle is FOSS, Apache-2.0, end to end.** It changes nothing about the open-core
line in `docs/OPEN-CORE.md`; it lives entirely on the **core** side.

- **The bundle is composition + config, not capability.** It bundles Crenel (Apache) +
  upstream FOSS components (each under its own OSI license) + a compose file + scaffolded
  settings + the web-HUD handler. None of it gates a core capability behind a paywall —
  "what's exposed, is default-deny enforced" stays 100% free, which is the open-core
  principle.
- **No new dependency on proprietary code.** The web HUD wraps the *existing* Apache
  `internal/ui`. The bundle introduces no `enterprise/` import; the `deps_test.go` import
  graph is untouched.
- **Where a future paid/managed seam *could* sit — without violating no-VC.** Same place
  OPEN-CORE.md already reserves: *organizational* concerns layered on the bundle through
  ports, never removing core capability. For the bundle specifically:
  - a **fleet/multi-operator dashboard** over many bundled edges (the single-edge HUD
    stays free);
  - an **append-only compliance ledger** of every apply across the fleet;
  - **approval gates** ("second operator confirms a new public host") in the dashboard.
  
  These attach via a future `LedgerProvider`-style port at `cmd`, consume core's verified
  results, and never fork core logic. **No-VC intact:** core + bundle are free forever;
  the only far-side-of-the-line thing is org tooling, and it's optional.
- **What the bundle must *not* become:** a hosted SaaS, or a "free tier" that withholds a
  safety capability. Both would violate the principle that the Apache core is the whole
  product for one operator.

---

## 6. Naming & positioning

**Recommendation: it's all just "Crenel."** The bundle is not a separate product with a
separate name — that would undercut the "one brain, batteries optional" framing.

- **The CLI** is `crenel`.
- **The bundle** is *"Crenel, batteries included"* — a distribution, surfaced as e.g. a
  `bundle/` directory / a compose file / a `docker compose up`, not a renamed artifact.
- **The HUD web view** is just "the Crenel status view," served by the bundle.

One-line pitch (repeat of §0, this is the canonical form):

> **Crenel** — the control plane for your self-hosted edge. *Batteries included, none
> required.*

Positioning against Pangolin, in one breath: *"Pangolin is a stack you adopt. Crenel is
the control plane for the stack you already run — and if you don't have one yet, one
command gives you a great default. Either way it's the same binary, and every piece is
swappable."*

(Trademark/naming posture is unchanged and rename-safe per NOTICE / OPEN-CORE.md §"Naming
& trademark" — none of this depends on the final name.)

---

## 7. Open decisions — teed up for the maintainer

| # | Decision | Options | My lean |
|---|---|---|---|
| **D1** | **v0 scope** | (a) edge-only · (b) edge + internal DNS (AdGuard) | **(a) edge-only.** Smallest honest artifact; DNS is v1. Including DNS doubles the day-one default-deny surface. |
| **D2** | **Default overlay (v3)** | Headscale · Tailscale (SaaS) · NetBird | **Headscale** as the default-to-target (matches the self-hosted ceiling); Tailscale + NetBird as swap-ins. Real positioning fork. |
| **D3** | **Packaging** | compose-first · Nix · both | **compose-first** for v0 (lowest friction, matches the homelab audience). Nix as a later additive packaging, not v0. |
| **D4** | **Dashboard scope** | read-only HUD web view (v0) · write-capable dashboard (later, possibly the open-core fleet seam) | **read-only HUD in v0** (reuses `internal/ui`, near-zero surface, can't violate default-deny). Write-capable/multi-edge dashboard is the natural enterprise-seam candidate (§5), deferred. |
| **D5** | **Bundled upstream pinning** | pin exact upstream versions · track latest | Pin in v0 for reproducibility; the faithful-fake bar means a driver is only validated against the versions it was tested on. |

### Recommended path, in one paragraph

Ship **v0 = `docker compose up` → Crenel + Caddy + a read-only web HUD**: a working,
durable, read-back-verified default-deny edge with zero assembly, defaulting to the one
edge Crenel has live-proven. Advertise the **swap-in matrix** (§3) and the **v1→v3
roadmap** (DNS split-horizon → overlay) as the trajectory, promoting each non-Caddy
battery from *documented swap-in* to *bundled default* only after it clears the proving-ground
bench (§4). Keep it **all FOSS / all "Crenel"** (§5/§6). The moat — cross-stack,
atomic, never-silently-wrong coordination — is preserved precisely because the bundle is
**data + composition over the existing driver-agnostic core**, not a new single-stack
appliance.

**Open calls that change the build:** D1 (v0 includes DNS or not) and D2 (overlay
default). The rest have safe defaults above and can proceed without blocking.
