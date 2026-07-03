# Crenel — Teaser Reel Timeline

The plan for Crenel's full-capability teaser reel. This is a **living document**:
every error-test / live trial on the bench going forward doubles as demo-footage
capture (see *Capture-as-we-test*, below), so the teaser builds incrementally instead
of being shot in one heroic session.

**Hard rule — FAKE NAMES ONLY.** Nothing personal (no `homelab.example`, no real backends,
no real DNS) ever appears in a shareable frame. Every asset is recorded against the
anonymous `example.com` / `acme.test` scheme below, on a throwaway bench, restored
byte-for-byte afterwards.

Brand surface: the tech-noir terminal look (radium-green `#00FF66` on near-black,
the crenellated `CRENEL` wordmark, the `CORE MATRIX` HUD). Palette + semantics in
[`BRANDING.md`](BRANDING.md). Capture stack: **asciinema 3** (`--headless
--window-size`) → **agg** (`--theme dracula`), GIF + optional MP4.

---

## Delivered so far

| Asset | What it shows | Bench |
|---|---|---|
| `crenel-bootup-branding.gif` | `status --banner` → wordmark + live CORE MATRIX HUD + per-edge detail | in-process fake Caddy (`fake_seed`), fake hosts |
| `crenel-capability-reel.gif` / `.mp4` | the 6-beat narrative below (teaser seed) | **real Caddy 2.8 + real Traefik 3.1**, fake hosts |

The capability reel is the **seed** — the shot list below is the full cut it grows into.

---

## Shot list — Crenel's marquee capabilities

Ordered as a narrative. Each beat is one (or a few) self-proving commands; Crenel's
own output is the proof (preview → apply → read-back → verify all happen in-process).

1. **Default-deny is the ground state.** `crenel status --hud` on a fresh edge —
   `DEFAULT-DENY ENFORCED`, nothing exposed. *The wall is solid; you cut the gaps.*
2. **Preview before you touch the edge.** `crenel expose app.example.com` (preview) —
   the cross-vendor plan + `default-deny will remain present on every edge: true` +
   the amber `⚠ ABOUT TO GO PUBLIC` warning. *No surprise writes.*
3. **One-command expose, read-back verified.** `crenel expose app.example.com --yes` —
   `read-back ✓` on each edge + `runtime: traefik API confirms` + `verified: live state
   matches intent`. *It didn't just write — it re-read the live edge and confirmed.*
4. **Cross-vendor multi-edge, atomic.** The same expose landing on a **heterogeneous
   Caddy + Traefik** pair from one `edges[]` config — both verified, all-or-nothing.
   *Every edge in atomic agreement, across different vendors.*
5. **The one-command rename.** `crenel rename app.example.com web.example.com --yes` —
   make-before-break, copies the source route's exact backend/mode/auth, read-back
   verified on both edges, rolled back as a unit. *Move a host like it's one word.*
6. **Atomic rollback on partial failure.** A coordinated expose where one edge can't
   accept the change (a misconfigured origin the daemon rejects) → `ROLLED BACK`,
   `EXIT=1`, the other edge **not left half-applied**, an honest reason. *Move together
   or not at all.*
7. **Drift → reconcile.** Hand-edit the edge out from under Crenel; `crenel drift`
   reports the divergence (exit non-zero, CI-friendly); `crenel reconcile` converges
   every edge + DNS back to the canonical set. *Live state is the source of truth, and
   Crenel pulls it back.*
8. **Never silently wrong.** The honesty beats, shown deliberately: a partially-parsed
   edge reads `Default-deny: UNKNOWN` (not a false green); an ephemeral admin-API edge
   warns a write won't survive a restart; an unverifiable runtime reports `UNAVAILABLE`,
   never `verified`. *Crenel would rather say "I don't know" than lie.*
9. **The HUD / dashboard.** `crenel status --hud` (terminal) and `crenel serve` (the
   read-only SVG dashboard — wordmark + CORE MATRIX over HTTP, auto-refreshing, never
   mutates). *The same live truth, two surfaces.*
10. **Closing card.** Wordmark + tagline. *Crenel — vendor-agnostic, live-state-
    authoritative control of what your edge exposes.*

Scale to the cut: a 30-second teaser is beats 1·3·4·6·9; the full reel runs all ten.

---

## Fake-hostname scheme (consistent anonymous brand)

**Never** use real names. Two interchangeable anonymous brands; pick one per clip and
stay consistent within it.

| Service | Brand A — `example.com` | Brand B — `acme.test` |
|---|---|---|
| Web app | `app.example.com` | `app.acme.test` |
| Secrets / vault | `vault.example.com` | `vault.acme.test` |
| Metrics | `grafana.example.com` → `metrics.example.com` | `grafana.acme.test` |
| Auth (brownfield) | `auth.example.com` | `auth.acme.test` |
| Internal-only | `internal.example.com` | `internal.acme.test` |

Backends are RFC-1918 / TEST-NET placeholders (`10.0.0.0/8`, `10.20.0.0/16`) — never a
real IP. `example.com` / `.test` are reserved (RFC 2606 / 6761), so a frame can never
imply a real, resolvable target. **Forbidden in any shareable frame:** `homelab.example`,
real public IPs, real backend ports tied to a real service, anything from a real
`settings.json`.

---

## The bench (reproducible, isolated, restorable)

Two ways to drive footage; both are fully isolated and leave no trace.

**A — in-process fake (no daemons).** `examples/demo/settings-demo.json` seeds an
in-process fake Caddy from `examples/demo/seed-demo-caddy.json`. Zero infra, instant,
perfect for the **boot-up / HUD** clips. Used for `crenel-bootup-branding.gif`.

**B — real cross-vendor bench (the proving pair).** Real `caddy` (admin API
`127.0.0.1:2019`) + real `traefik` (file provider + API `127.0.0.1:8099`), both fed
fake hosts. This is what gives the authentic **green double read-back + `traefik API
confirms`** and the **real runtime-verify rollback**. Recipe (matches the
proving-ground trial, reproduced locally for `crenel-capability-reel.gif`):

- `caddy run` from a JSON config (admin + `automatic_https: disable` + a `static_response 403`
  catch-all + one brownfield `auth` route) — JSON boot reads cleanly as
  `DEFAULT-DENY ENFORCED` (a Caddyfile boot adapts the deny into a host-less subroute
  that currently displays `UNKNOWN` — the known `feat/caddy-hostless-subroute-deny`
  finding; avoid it for clean footage).
- `traefik --providers.file.filename=<crenel.json> --providers.file.watch` +
  `--entrypoints.traefik.address=:8099` (the API; `:8080` may be taken). Crenel reads
  AND writes that one JSON file; the watch reload is what `traefik API confirms` probes.
- Crenel `edges[]`: edge A `driver: caddy` (`admin_url`), edge B `driver: traefik`
  (`traefik_config_path` + `traefik_api_url`). Both `origins` carry every demo service
  so an expose projects onto BOTH.
- **Rollback induction:** point the Traefik edge's origin for the doomed service at an
  invalid target (e.g. `"bad host:8200"` — a space). It passes Crenel's `validate()`
  (the loadBalancer has a server) but the **real daemon rejects** it, so runtime-verify
  sees the router never go `enabled` → the transaction fails → BOTH edges roll back.
- **Durability presentation:** a bare admin-API Caddy edge is `ephemeral-admin` and
  honestly warns on every write. For clean footage, give edge A a `caddy_persist_path`
  (durable-file) so the warning is replaced by a short positive durability line.

**Discipline (every session):** back up before, abort-only-on-fail, restore byte-for-byte
after, kill the throwaway daemons. The bench is disposable; production is never touched.

---

## Capture-as-we-test (the standing workflow)

Going forward, **error-testing and live trials on the bench ARE demo capture.** When a
trial drives a real Crenel behavior worth proving (a new driver, a rollback, a drift
fix, an honesty beat), record it on fake names while it runs:

1. Bring up bench A or B with the fake-hostname scheme above.
2. `asciinema rec --headless --window-size 96x30 -c "bash drive-<beat>.sh" out.cast`
   (set `TERM=xterm-256color`, `CLICOLOR_FORCE=1`).
3. `agg --theme dracula --font-size 20 --idle-time-limit 3 out.cast out.gif`
   (`--idle-time-limit` ≥ your deliberate hold so paced pauses aren't clipped).
4. Sanity-check a few frames; drop the `.cast` + `.gif` next to this file's asset table.
5. Tear the bench down and restore.

Each captured beat slots into the shot list above. The teaser is never a from-scratch
shoot — it's the accumulated, already-verified footage, cut together.
