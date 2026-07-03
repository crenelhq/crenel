# Bundle v0 — live validation evidence

The v0 bundle was stood up as a **real compose stack** on the standing proving-ground
(Docker 29.6.1), in an **isolated project** (`crenel-bundle`, its own network, host
ports remapped to 18080/18088 so it never touched the bench's running
caddy/nginx/traefik/authentik), exercised end-to-end, and **torn down clean**.

This is the v0 analogue of the repo's `TRIAL-RESULT-*.md` cadence: the unit suite
proves the handler against faithful fakes; this proves the *whole turnkey
experience* against real Docker + real Caddy + a real upstream.

## What ran

`docker compose up -d --build` → built the static Crenel binary (**9.68 MB** image
on alpine), started Caddy (healthy via loopback admin), demo (`traefik/whoami`), and
Crenel (sharing Caddy's netns, running the read-only dashboard).

| Step | Command (abridged) | Result |
|---|---|---|
| 1. up | `docker compose up -d --build` | caddy **healthy**, Crenel + demo **up** |
| 2. before | `curl -H 'Host: demo.crenel.test' caddy:80` | **HTTP 403** (structural default-deny) |
| 3. read | `crenel status --plain` | `Default-deny: ENFORCED`, `Exposed: (nothing)` |
| 4. **expose** | `crenel expose demo --auth none --yes` | `applied … read-back ✓ … verified: live state matches intent` |
| 5. after | `crenel status --plain` | `Exposed (1): demo.crenel.test -> demo:80`, deny still `ENFORCED` |
| 6. serves | `curl -H 'Host: demo.crenel.test' caddy:80` | **whoami output** (HTTP 200) |
| 7. HUD | `curl caddy:8080/hud.svg` | `EXPOSED 1 host (1 public)`, `ENFORCED` |
| 7b. read-only | `curl -X POST caddy:8080/hud.svg` | **HTTP 405** (read-only by construction) |
| 8. unexpose | `crenel unexpose demo --yes` | `read-back ✓ … no longer exposed`; edge back to **403** |
| 9. published | `wget 127.0.0.1:18080/healthz` | `ok` (the port a browser hits) |
| 10. down | `docker compose down -v` + image rm | all crenel-bundle containers/network/image gone; **bench untouched** |

## What this proves about v0

- **One command → a working default-deny edge.** `compose up` yields a closed edge
  (403 on everything) with Crenel already driving it — zero assembly.
- **Drive it in one command.** `crenel expose demo --auth none` lands the route,
  read-back-verifies it, and the edge immediately serves the upstream.
- **The HUD is the live answer.** The read-only web view reflects the exact same
  state as `crenel status` (one shared model builder), and physically refuses
  mutation (405 on non-GET).
- **The loopback-first model holds in miniature.** Caddy's admin API was reachable
  by Crenel (shared netns) while published on **no** network interface.

## One honest finding (informs the docs)

The bundled Caddy boots from a Caddyfile but Crenel writes via the **admin API**, so
v0 writes are **ephemeral-admin** — Crenel says so loudly on every write:

> ⚠ persist (durability) warning: … write applied + verified LIVE but this edge is
> EPHEMERAL (ephemeral-admin) — it will NOT survive a control-plane restart …

For v0 (a demo/on-ramp) this is correct and honestly surfaced — but a newcomer who
restarts the stack loses their exposures. **v0.1 should bake the durable
wildcard-site persist path** (mount the Caddyfile writable + set `caddy_persist`) so
`expose` survives `docker compose restart`. Tracked as a v0.1 refinement below.
