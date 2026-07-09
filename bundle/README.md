# Crenel, batteries included (bundle v0)

> **One command → a working default-deny edge you can see and drive.**
>
> This is the turnkey distribution of Crenel: `docker compose up` brings up the
> bundled **Caddy** edge (the proven Crenel driver, structural default-deny baked
> in), **Crenel** (the brain, pre-wired to drive that Caddy), a read-only **status
> dashboard**, and a tiny **demo** upstream so an `expose` has something real to
> show. Zero assembly.
>
> Crenel is not an appliance. It's the control plane. The same binary drives the
> Caddy / Traefik / nginx / DNS stack you *already* run (point its config at your
> edge and bring up none of these services). The bundle is just a great default to
> start from. See `../../docs/internal/BUNDLE-DESIGN.md`.

## What's in v0 (and what's deliberately not)

| In v0 | Not in v0 (roadmap) |
|---|---|
| Bundled **Caddy** edge, default-deny, loopback admin | Traefik / nginx as bundled defaults (swap-in once bench-validated) |
| **Crenel** driving it via the admin API | Internal split-horizon **DNS** (AdGuard), tier v1 |
| **Read-only web HUD** (`crenel serve`) | Public **DNS** (Cloudflare/dnscontrol), tier v2 |
| A **demo** upstream to expose | **Overlay** (Headscale/Tailscale/NetBird), tier v3 |

v0 is Caddy-only on purpose: Caddy is the one edge Crenel has proven end-to-end on
real infrastructure. The breadth is real in the architecture and arrives one
bench-validated driver at a time, never claimed before it's proven. (Honest
gating: `../docs/internal/BUNDLE-DESIGN.md` §4.)

## Quickstart

Requires Docker + the Compose plugin. From this directory:

```bash
# 1. Bring up the entire service (build crenel + start Caddy + demo).
docker compose up -d --build

# 2. Open the read-only dashboard: the live answer to "what's exposed right now".
open http://localhost:8080          # EXPOSED 0 · DEFAULT-DENY ENFORCED

# 3. Confirm the edge is closed by default (nothing exposed -> the catch-all denies).
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: demo.crenel.test' http://localhost:8088
#   -> 403   (default-deny: no route exists yet)

# 4. Drive it: ONE command exposes the demo through the edge (writes stay on the CLI).
docker compose exec keep crenel expose demo --auth none
#   crenel: read-live -> plan -> apply -> READ-BACK-VERIFY. The dashboard flips to
#   EXPOSED 1 (public, amber: published with no auth, on purpose).

# 5. It now serves: the host crenel just opened reaches the demo upstream.
curl -s -H 'Host: demo.crenel.test' http://localhost:8088 | head -3
#   -> whoami output (Hostname/IP/headers)

# 6. Close it again, atomically.
docker compose exec keep crenel unexpose demo
#   -> dashboard back to EXPOSED 0 · DEFAULT-DENY ENFORCED; step 5 returns 403 again.

# Tear down.
docker compose down
```

`crenel status` from the CLI shows the same state as the dashboard (they share one
model builder):

```bash
docker compose exec keep crenel status --hud
```

## How it fits together

```
            :8088  ─────────────►  caddy (:80)  ──route──►  demo (:80)
  (Host: demo.crenel.test)            │  ▲
                                      │  │ admin API @ 127.0.0.1:2019 (loopback only)
            :8080  ─────────────►  crenel (shares caddy's netns)
       (read-only dashboard)          └── drives Caddy; reads it back live
```

- **The admin API is never published.** Crenel shares Caddy's network namespace
  (`network_mode: "service:caddy"`), so it reaches `127.0.0.1:2019` while that port
  is exposed on *no* network interface. That's the loopback-first model from `SECURITY.md`.
- **The dashboard is read-only by construction.** `crenel serve` answers only GET;
  any mutating method is `405`. Writes happen exclusively on the CLI.
- **Default-deny is structural.** `caddy/Caddyfile` ends in a catch-all `403`;
  a host is reachable only after Crenel inserts an explicit route ahead of it.

## Files

```
bundle/
├── README.md            # this file
├── docker-compose.yml   # caddy + crenel + demo (project name: crenel-bundle)
├── Dockerfile           # static, zero-dep crenel binary (built from repo root)
├── caddy/
│   └── Caddyfile        # loopback admin + structural default-deny
└── crenel/
    └── settings.json    # baked config: points crenel at the bundled Caddy
```

## Pointing Crenel at YOUR existing edge instead

Bring up *none* of these services. Install the `crenel` binary (`make install` from
the repo root) and point it at your real Caddy/Traefik/nginx with your own settings
file. Same verbs, same read-back-verify, same default-deny invariant; the bundle
was only ever a convenient default. That's the difference between a control plane
and an appliance.
