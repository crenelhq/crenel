<p align="center">
  <img src="docs/brand/crenel-mark.svg" alt="Crenel" width="96">
</p>

# Crenel

[![CI](https://github.com/crenelhq/crenel/actions/workflows/ci.yml/badge.svg)](https://github.com/crenelhq/crenel/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Crenel is a zero-dependency CLI that keeps a split-horizon homelab honest.**
One command exposes a service locally or publicly — across Caddy, AdGuard, and
Cloudflare in one atomic step — then **re-reads the live edge to prove the change
actually landed**. Nothing is reachable unless you explicitly opened it, and
`audit`/`drift` can prove that at any moment.

```bash
crenel expose photos --to immich:2283 --auth authelia
# → proxy route on every edge, internal DNS rewrite, public DNS record,
#   auth gate — previewed, applied atomically, then VERIFIED by read-back.
crenel status     # what is exposed RIGHT NOW (live state, nothing stored)
crenel drift      # CI-friendly: exits non-zero if reality disagrees
```

<p align="center">
  <img src="docs/brand/crenel-demo.gif" alt="crenel demo: expose, verify, drift, unexpose" width="760">
</p>

## Is Crenel for you?

Be honest with yourself first — most people don't need it:

- **You just want to expose services to the internet?** Use
  [Pangolin](https://github.com/fosrl/pangolin) or Cloudflare Tunnel. They're
  excellent, and Crenel doesn't compete with them.
- **Every device you care about can run a mesh client?** Tailscale Serve/Funnel
  or NetBird's public/private service toggle already give you one-switch
  exposure. Take the simpler stack.

Crenel is for the setup those tools structurally can't cover — **split-horizon
on your own domain**: clientless LAN devices (TVs, IoT, guests) resolving
`app.your.domain` to a *local* proxy at LAN speed, the same name resolving
publicly through a hardened edge, AdGuard doing your filtering, and you owning
every hop. That topology means one logical change touches four or five systems
— proxy routes, internal DNS rewrites, public DNS records, auth gates — and
keeping them agreeing by hand is exactly where silent drift and accidental
exposure live. Crenel makes that one verified command.

|  | By hand | Terraform-style IaC | Pangolin / tunnel appliance | NetBird services | **Crenel** |
|---|---|---|---|---|---|
| Reverse-proxy routes | manual edits | ✅ | ✅ (replaces your proxy) | ✅ (its own proxy) | ✅ drives *your* proxy |
| Public DNS records | manual | ✅ | wildcard once | manual CNAME | ✅ |
| Split-horizon LAN DNS (clientless devices) | manual | rare/roll-your-own | ❌ | ❌ (mesh-only) | ✅ AdGuard rewrites |
| Local ↔ public toggle per service | ❌ | ❌ | partial | ✅ (mesh = "local") | ✅ |
| **Verified against live state** | ❌ | ❌ (state file drifts) | ❌ | ❌ | ✅ read-back, every write |
| Default-deny proven, not assumed | ❌ | ❌ | ❌ | ❌ | ✅ `audit` / `drift` |
| Keeps your existing stack | — | ✅ | ❌ greenfield | ❌ replaces mesh+proxy | ✅ removable anytime |

Remove Crenel tomorrow and your infrastructure keeps running untouched — it's a
control plane over the tools you already trust, not another proxy or tunnel.

## What works with what

The architecture is vendor-agnostic (ports-and-adapters; a new driver is a
contribution, not a rewrite), but honesty about the *implemented* surface:

| Driver | Read / status | Write (expose etc.) | Verify (read-back) | Notes |
|---|---|---|---|---|
| **Caddy** | ✅ admin API | ✅ + durable Caddyfile persist | ✅ | first-class path; `ack`/`unack` supported |
| **Traefik** | ✅ file provider | ✅ file only | ⚠️ file re-read; runtime probe opt-in | write refused without probe URL unless `--allow-unverified` |
| **nginx** | ✅ file | ✅ file only | ⚠️ same as Traefik | managed-block re-render fidelity documented |
| **Cloudflare DNS** | ✅ | ✅ surgical (shared zones) or whole-zone (dedicated) | ✅ | ownership marker `managed-by:crenel` |
| **AdGuard Home** | ✅ rewrites | ✅ (dual-instance aware) | ✅ presence | value-drift detection deliberately opt-out (see limits) |
| **Pi-hole (v6)** | ✅ Local DNS host entries | ✅ (dual-instance aware, session auth) | ✅ presence | IP targets only (no CNAME); wildcards refused (they live in dnsmasq confs, outside the API); same marker-less value-drift opt-out as AdGuard |
| **Tailscale** | ✅ serve.json read | 🚧 planned | — | write path unbuilt/untrialed |
| **NetBird** | ✅ read-only | — by design | — | mesh grants surfaced, never driven |
| **Auth (forward-auth)** | — | ✅ by reference (Authelia, any) | ✅ | you own the auth config; Crenel renders the reference |

One edge can serve hosts under **several apex zones** (say, `*.homelab.example`
and `*.smallbiz.example` on one Caddy): a provider covering several apexes lists
them once — `zones: ["homelab.example", "smallbiz.example"]` — one block per
resolver box. Crenel routes every host only to the providers whose zone covers
it: zone-confined resolvers never see an out-of-zone write, coverage parity is
compared per zone (never across zones), a host no provider's zone covers is
declared honestly rather than flagged as a missing record, and a bare service
name that could live under two zones is refused with the candidate FQDNs
(say the host out loud).

## Why trust it with your edge

- **Zero dependencies.** `go.mod` has no `require` block — Go standard library
  only. The entire supply chain in your trust boundary is the Go toolchain. The
  drivers speak plain `net/http` to Caddy/Cloudflare/AdGuard; you can read all
  of it in an afternoon, and it will still build years from now.
- **Live state is the only truth.** No stored desired state, no state file to
  drift. Every mutating verb runs `read-live → plan → apply → read-back-verify`;
  an admin-API `200` is never accepted as proof.
- **Structural default-deny.** A host is reachable *iff* an explicit expose
  added it — a hard driver invariant, and `audit` proves it against live state.
- **Bounded honesty.** Config Crenel can't fully parse becomes a *declared
  unknown* — counted in `status`/`audit`, never silently green. Routes owned by
  another generator (NPM, Pangolin, caddy-docker-proxy) are detected and
  **refused**, not clobbered.
- **Atomic across the chain.** A coordinated write across two edges + two DNS
  planes either fully lands or fully rolls back — proven live (see below).
- Publishing a host **public with no auth** is refused unless you say
  `--auth none` out loud, and `audit` flags any `public_without_auth` host.

## Install

```bash
go install github.com/crenelhq/crenel/cmd/crenel@latest
```

Or grab a static binary for linux/darwin (amd64/arm64) from
[Releases](https://github.com/crenelhq/crenel/releases) — zero-dependency,
verify by SHA256. From a clone: `make build` (host platform) or `make release`
(cross-compile to `./dist`).

Or run the container image — audit an edge with nothing installed:

```bash
docker run --rm -v ./Caddyfile:/Caddyfile:ro ghcr.io/crenelhq/crenel \
  audit /Caddyfile --assume-public-boundary
```

Images are published on release tags (multi-arch, linux amd64/arm64). For
running crenel itself as a compose sidecar — including making writes survive a
restart — see [docs/CONTAINER.md](docs/CONTAINER.md).

**Installed? The first ten minutes, in order:** (1) point `crenel audit` at the
edge you already run — read-only, no config, next section; (2) `crenel init
--xdg` to scaffold a config crenel auto-discovers; (3) fill it in —
[`examples/config.example.yaml`](examples/config.example.yaml) is the
commented canonical starter, and [`examples/README.md`](examples/README.md)
maps every example to a topology; (4) `crenel status` to see your live edge;
(5) your first `crenel expose`.

## Audit any edge in 30 seconds

Point `crenel audit` at the edge you already run — no settings file, read-only,
nothing written. Say the boundary out loud (`--assume-public-boundary` for an
internet-facing edge, `--internal` for a LAN-only one) and crenel reports what
is exposed, whether default-deny is structural, and where auth is missing:

```bash
crenel audit ./Caddyfile --assume-public-boundary
crenel audit http://localhost:2019 --assume-public-boundary
crenel audit /path/to/npm/data/nginx --assume-public-boundary
crenel audit http://traefik:8080 --assume-public-boundary
```

- `./Caddyfile` — parses the file on disk (CONFIG evidence; add `--probe` to
  cross-check the running process via its admin API).
- `http://localhost:2019` — reads the running Caddy's admin API (RUNTIME
  evidence — the process itself, not a file).
- `/path/to/npm/data/nginx` — reads an Nginx Proxy Manager data dir
  (`proxy_host/*.conf` tree), detects the NPM generator, audits it read-only.
- `http://traefik:8080` — reads Traefik's API (Pangolin and docker-labels
  setups included); generator detected, routes enumerated, writes refused.

A directory containing `Caddyfile.autosave` audits a caddy-docker-proxy edge
the same way. Only the URL you paste is ever contacted; anything beyond it is
opt-in via `--probe`. Foreign edges exit 0 when otherwise clean — cron it.

When the audit has earned some trust, the next step is a config so crenel can
*manage* the edge: `crenel init --xdg` scaffolds one (see
["Daily driver"](#daily-driver-config-discovery--a-secrets-file) below), or
adopt in place per the quickstart two sections down.

## Quickstart: batteries included (one command)

No edge yet? The [`bundle/`](bundle/README.md) brings up a working default-deny
Caddy edge + Crenel + a read-only dashboard + a demo upstream:

```bash
cd bundle && docker compose up -d
# unmatched host -> 403 (default-deny); then:
docker compose exec keep crenel expose demo --auth none   # read-back ✓
# demo host now serves 200; the HUD shows it. `unexpose` puts it back to 403.
```

## Quickstart: adopt the setup you already run

Point Crenel at your existing hand-built edge; it adopts in place (ownership
markers only, zero behavior change) and exposing becomes one command:

```bash
crenel init                       # scaffolds settings + declarative exposures file
CFG="-config crenel.settings.yaml"
# (or `crenel init --xdg` for a config crenel finds without any flag — then drop
#  $CFG below. Filling it in: examples/config.example.yaml is the commented
#  canonical starter; examples/README.md maps every example to a topology.)

crenel $CFG status                # what's exposed RIGHT NOW, live
crenel $CFG import --dry-run      # preview what crenel would adopt
crenel $CFG import                # adopt in place, idempotently
crenel $CFG drift                 # consistency check; non-zero exit on drift

# imperative — one host; --to TCP-probes the backend before writing any route:
crenel $CFG expose grafana --to grafana:3000 --auth authelia
crenel $CFG expose status --auth none          # public with no auth = explicit

# declarative — converge to a file, kubectl-style:
crenel $CFG apply crenel.exposures.yaml --dry-run
```

Internal-only, or just one edge — inline, no apply file:

```bash
crenel $CFG expose ha --to 10.0.0.19:8123 --scope internal --auth none
# internal DNS record + edge route only. NO public/Cloudflare record, so nothing
# "goes public" and no auth is forced. Reachable only where an internal name
# resolves (split-horizon DNS). Drop --scope for the full public chain.

crenel $CFG expose grafana --to grafana:3000 --auth authelia --edges home
# appoint the route to just the `home` edge (of a multi-edge home+vps topology).
```

`--scope internal|public|both` is the ergonomic bundle (it's sugar over `--dns`);
`--edges <a,b>` picks which edges serve the route; `--dns internal|public|both` is
the granular DNS half. All three also work on `unexpose`/`set`. This is the inline
twin of an apply file's `dns:`/`edges:` fields — same mechanism, one command. See
[`docs/design/expose-scope-flags.md`](docs/design/expose-scope-flags.md).

Internal-only can also be **declared once in the config** instead of re-said per
command: an origins entry may be the structured form `ha: {addr, scope: internal}`
(JSON; block-map in YAML) — plain-string entries keep today's semantics exactly.
A declared internal service stays fully managed and verified on its internal legs
(downstream edge route + internal DNS), but crenel never demands or creates a
public DNS record for it and never asks a chain-front edge to forward it — and
**audit enforces the declaration**: an internal-scope service that *is* publicly
reachable (an explicit public DNS record, a chain-front route, a tunnel ingress
rule) is a critical `internal_scope_public_exposure` finding. `expose <svc> --to
<addr> --scope internal` persists this form automatically, and `status` tags such
hosts `[internal]`. See `docs/internal/DESIGN.md` "Internal-scope services".

A host that doesn't live at home gets a **residency class**: `expose vault
--residency vps` (or `residency: vps` in an apply file) makes each internal
resolver answer with its *own* vantage-correct address for that host, from a
per-provider `targets:` map in settings (e.g. the home resolver answers the
public edge IP, the tunnel-side resolver answers the tunnel-direct address).
A class no resolver has a target for is **refused at plan time**, naming the
instance and the class — never silently answered with the default. Class unset
(the common home-resident case) behaves exactly as before. See
[`docs/DNS-DESIGN.md`](docs/DNS-DESIGN.md) §14 and the reference architecture's
target rule.

Caddy edges: set `caddy_persist_path` so exposures survive a container restart —
Crenel writes between `# crenel-managed-begin/end` markers, validates, reloads,
and preserves the rest of your Caddyfile byte-for-byte.

**First audit says "N route(s) not understood — deny UNKNOWN"?** That is normal
on a hand-built Caddyfile: run **`crenel triage`**. It walks each not-understood
route interactively — edge, structural path, what crenel *did* understand, the
raw route JSON — and lets you acknowledge each with a reason. Acks are stamped
in the live config (the `crenel-ack` marker,
[`docs/design/ack-marker.md`](docs/design/ack-marker.md)) and read-back-verified;
acknowledged routes stop blocking default-deny but stay visible as ACK. The
scriptable equivalents are `crenel ack <host> --reason <slug>` and — for routes
with no recoverable host — `crenel ack --route '<locator>' --reason <slug>`,
targeting the structural path the audit prints.

Auth is **forward-auth by reference**: an exposure carries `auth: authelia` and
Crenel renders the per-edge reference (Caddy `forward_auth`, Traefik middleware,
nginx `auth_request`); *you* own the actual auth config. See
[`docs/internal/AUTH-DESIGN.md`](docs/internal/AUTH-DESIGN.md).

**No infrastructure at all?** Every flow runs against bundled in-process fakes:

```bash
go build -o bin/crenel ./cmd/crenel
./bin/crenel -config examples/settings-brownfield.json status
```

## Daily driver: config discovery + a secrets file

Typing `-config` on every invocation gets old. Crenel resolves its config in
this order — first hit wins:

1. `-config <path>` flag
2. `CRENEL_CONFIG` env var
3. `$XDG_CONFIG_HOME/crenel/{config.json,config.yaml,config.yml}`
4. `~/.config/crenel/` (same names)
5. bare defaults (no file)

So put a config at the XDG path once and every `crenel status` / `drift` /
`expose` after that just works. `init --xdg` scaffolds it:

```bash
crenel init --xdg
# writes ~/.config/crenel/config.yaml        (auto-discovered)
#        ~/.config/crenel/crenel.exposures.yaml
#        ~/.config/crenel/crenel.env         (0600 secrets stub)
```

Secrets never go in the config file. The config names an env var (the `*_env`
convention — `password_env: ADGUARD_PASSWORD`, `api_token_env:
CLOUDFLARE_API_TOKEN`) and the value lives in `crenel.env`, mode 0600. Load it
in your shell:

```bash
# ~/.bashrc
set -a; . ~/.config/crenel/crenel.env; set +a
```

or, for units and timers:

```ini
EnvironmentFile=%h/.config/crenel/crenel.env
```

`drift` exits non-zero when live state diverges from the canonical set, so a
cron line with an [ntfy](https://ntfy.sh) push is all the monitoring it needs:

```
*/30 * * * * crenel drift || curl -s -d "edge drift detected" ntfy.sh/your-topic
```

Optional, if you check the HUD a lot:

```bash
alias hud="crenel status --hud"
```

Config-free verbs (`version`, `help`, `init`, `banner`, `audit <target>`) skip
discovery entirely — they must work on a box whose discovered config points at
unreachable providers. A discovered-but-invalid file errors loudly; it never
silently falls back to defaults.

## MCP server: let an agent drive it (read-only by default)

`crenel mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio, so an LLM agent can query your edge live: `crenel_status`,
`crenel_audit`, `crenel_drift`. Read-only **by construction** — the server holds
the engine only through the narrow read interface, so a mutating call is
unrepresentable, not merely refused. Opt-in `crenel mcp --write` adds a
**two-phase gated** write pair (`crenel_plan` -> `crenel_apply` with a
content-hash plan id), with every CLI guardrail intact. See
[`docs/MCP.md`](docs/MCP.md); [`docs/mcp/mcp.json`](docs/mcp/mcp.json) is a
ready `mcpServers` snippet and [`docs/mcp/SKILL.md`](docs/mcp/SKILL.md) teaches
an agent the safety contract.

## Proven, not promised

Beyond the hermetic suite (**788 test functions, race-clean, 18 packages**,
under the rule *a fake may only accept what the real edge accepts*), the claims
that matter were exercised against real production edges — the maintainer's own
homelab + VPS — each run recorded and reverted byte-for-byte (hostnames
anonymized to `homelab.example` in the write-ups):

| Claim | Proven live | Record |
|---|---|---|
| One-command rename survives `docker restart` | 2026-06-28 | [trial](docs/internal/trials/TRIAL-RESULT-rename-onecommand-2026-06-28.md) |
| Durable persist into an existing wildcard site | 2026-06-28 | [trial](docs/internal/trials/TRIAL-RESULT-durable-persist-2026-06-28.md) |
| Cross-edge atomic rollback (zero changes on failure) | 2026-06-28 | [trial](docs/internal/trials/TRIAL-RESULT-chain-write-2026-06-28.md) |
| Surgical Cloudflare write on a *shared* production zone | 2026-06-30 | [record](docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md) |
| Full chain — 2 edges + 2 AdGuards + Cloudflare, one command | 2026-06-30 | [record](docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md) |
| Dual-AdGuard split-horizon parity audit catches real divergence | 2026-06-30 | [record](docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md) |
| Independent third-party audit (no critical/high findings) | 2026-07-03 | [audit](docs/audits/independent-audit-2026-07-03.md) |

Notably, the first live cross-chain write **aborted atomically with zero changes
applied** when it surfaced a renderer bug the fake-based suite structurally
couldn't catch — which is the whole argument for read-back verification.

## Documented limits (honest)

What Crenel *can't* do is stated as loudly as what it can:

- **Marker-less AdGuard/Pi-hole value drift isn't detected.** AdGuard rewrites
  and Pi-hole host entries carry no metadata field, so Crenel can't distinguish
  a foreign entry from a stale one of its own; value-checking would cry wolf on
  your intentional entries.
  Presence is verified; value drift detection is deliberately scoped to
  providers with ownership markers (Cloudflare surgical).
- **Path-granular routing is detected, not modeled.** A route scoped by
  path/method/header matchers is declared `matcher_conditional` and forces
  default-deny to UNKNOWN — never silently misread — but Crenel can't yet write
  per-path backends or auth.
- **Tailscale serve write support is unbuilt** (read/classification works;
  tailnet-only hosts are no longer falsely flagged public).
- **Whole-zone Cloudflare push requires a dedicated zone**; shared zones use
  surgical mode, which refuses to touch any record it doesn't own.

Full current state — what's built, live-proven, and open — is maintained in
[`STATE-OF-CRENEL.md`](docs/STATE-OF-CRENEL.md). Design docs live in
[`docs/internal/`](docs/internal/); the plain-English explainer is
[`docs/WHAT-CRENEL-DOES.md`](docs/WHAT-CRENEL-DOES.md); the split-horizon
reference architecture is
[`docs/REFERENCE-ARCH-split-horizon.md`](docs/REFERENCE-ARCH-split-horizon.md).

## Name

A *crenel* (/ˈkrɛn.əl/) is the gap in a castle battlement — the deliberate
opening you choose to expose. Run `crenel banner` for the battlement HUD drawn
from your live hosts.

## License & contributing

Apache-2.0 ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)). The Apache core is the
whole product for an individual operator; see
[`docs/OPEN-CORE.md`](docs/OPEN-CORE.md) for the boundary. External PRs are
welcome under **DCO** (per-commit sign-off, [`DCO.txt`](DCO.txt)) — build/test
flow and the faithful-fake testing bar are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Crenel never touches real infrastructure
in this repo's tests; everything runs against in-repo fakes.

Built with the assistance of [Claude Code](https://claude.com/claude-code).
