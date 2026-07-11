# Running Crenel as a container

The published image is `ghcr.io/crenelhq/crenel` (multi-arch, linux/amd64 +
linux/arm64, pushed on every release tag). It is the crenel binary on alpine —
a shell and CA roots, nothing else. For the batteries-included demo (Caddy +
crenel + dashboard in one `compose up`) see [`../bundle/`](../bundle/); this
doc is the reference topology for running crenel against an edge **you**
already run in compose.

## Zero-config audit (no install at all)

```bash
docker run --rm -v ./Caddyfile:/Caddyfile:ro ghcr.io/crenelhq/crenel \
  audit /Caddyfile --assume-public-boundary
```

## The sidecar pattern (recommended)

Caddy's admin API is plaintext and unauthenticated — it must stay
loopback-only, never a published port. The sidecar makes that free: crenel
shares the caddy service's network namespace (`network_mode: "service:caddy"`),
so `http://127.0.0.1:2019` inside crenel IS caddy's loopback admin. No exec
transport, no tunnel, no exposed admin.

```yaml
services:
  caddy:
    image: caddy:2-alpine
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    ports:
      - "443:443"

  crenel:
    image: ghcr.io/crenelhq/crenel
    network_mode: "service:caddy"   # reach the loopback-only admin directly
    env_file: crenel.env            # DNS creds etc. (never in the compose file)
    volumes:
      - ./crenel/settings.json:/etc/crenel/settings.json:ro
    environment:
      CRENEL_CONFIG: /etc/crenel/settings.json
    command: ["serve", "--addr", ":8080", "--refresh", "5"]  # read-only HUD

volumes:
  caddy-data:
```

Drive writes from the host: `docker compose exec crenel crenel expose demo`.
Settings are the usual file (`admin_url: "http://127.0.0.1:2019"`, zone
`homelab.example`, your origins) — no `transport` block needed.

**This is ephemeral-admin by default, and crenel says so.** Admin-API writes
live in caddy's memory; a `docker compose restart caddy` reloads the ro-mounted
Caddyfile and drops them. `status` prints the `Durability:` line, `audit`
raises `ephemeral_writes`, and every write records a `PersistWarning`. Fine
for audit/status/drift; for durable writes, read on.

## Durable persist in this topology

The durable reconciler (see `docs/internal/DESIGN.md` "Durability") needs two
channels: a **file channel** to the boot Caddyfile and a **caddy channel**
where a caddy binary runs `validate`/`reload`/`adapt`. In the sidecar:

- **File channel:** mount the Caddyfile **rw into the crenel container** (it
  can stay `:ro` in the caddy container — caddy only reads it at boot/reload).
  With a local mount, `caddy_persist.file_command` stays empty.
- **Caddy channel:** the crenel image ships **no caddy binary and no docker
  CLI**, so out of the box there is no caddy channel. What works **today**,
  with today's code, is option (a): mount the docker socket and exec into the
  caddy container. That needs the docker CLI, so build a two-line derived image:

```dockerfile
FROM ghcr.io/crenelhq/crenel
RUN apk add --no-cache docker-cli
```

```yaml
  crenel:
    build: ./crenel                 # the derived image above
    network_mode: "service:caddy"
    env_file: crenel.env
    volumes:
      - ./crenel/settings.json:/etc/crenel/settings.json:ro
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:rw   # file channel (rw HERE)
      - /var/run/docker.sock:/var/run/docker.sock   # caddy channel
```

```json
"caddy_persist": {
  "boot_path": "/etc/caddy/Caddyfile",
  "caddy_command": ["docker", "exec", "-i", "caddy", "sh"],
  "adapter": "caddyfile",
  "verify_adapt": true
}
```

The edge now declares `durable-file`: every verified write is reconciled into
the on-disk Caddyfile, validated and adapt-cross-checked by the **running
caddy's own binary** (no version skew), and survives a restart.

**Tradeoffs, honestly:**

- **(a) docker socket (above — recommended, works today).** The socket is
  root-equivalent on the host: anything that owns the crenel container owns
  the machine. Acceptable when crenel is *the* control plane on a box you
  control; scope it with a socket proxy if that bothers you (it should at
  least give you pause).
- **(b) bake `caddy` into a derived crenel image.** No socket — but now the
  validating/adapting binary can skew from the running caddy's version, which
  quietly weakens the "a restart reproduces exactly this" proof. If you go
  this way, pin both images to the same caddy release.
- **(c) flat persist without the caddy channel — does not exist.** The flat
  persister (`caddy_persist_path`) still shells out to a local `caddy` for
  validate + reload; there is no validate-free persist mode, by design (an
  unvalidated candidate never touches the boot file). Without a caddy channel
  the honest state is ephemeral-admin, loudly declared — not a silent maybe.

## Drift checks from the host

```bash
# crontab on the docker host — nightly drift, notify only on drift/failure
0 3 * * * cd /opt/stacks/edge && docker compose exec -T crenel crenel drift \
  || curl -s -d "crenel drift check failed or found drift" https://ntfy.example/edge
```

## What does NOT work containerized

- **Host paths you didn't mount.** `crenel audit ./Caddyfile`, backups,
  exports — the container sees only its volumes. Mount what you point at.
- **Auditing a host-level (non-compose) caddy/nginx from a bridge network.**
  Its loopback admin at the host's `127.0.0.1:2019` is not your container's
  loopback. Use `network_mode: host`, or keep that edge driven by a host
  crenel binary — the same settings file works for both.
- **ssh-exec / ssh-tunnel transports** need an ssh client and keys the image
  does not carry. Driving *remote* edges is the host binary's job; the
  container is the sidecar for the edge it lives next to.
- **`crenel mcp`** is stdio — your MCP client must be able to spawn
  `docker compose exec -i crenel crenel mcp`, which most can, but the agent
  then only reaches what this container reaches.
