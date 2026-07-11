# Examples: which file is yours?

This directory holds two very different kinds of file, and telling them apart
matters:

- **Configs you copy** — settings files (`config.example.yaml`,
  `settings-*.json/yaml`) that show how to describe a topology to crenel.
  Ordered below from the common case to the exotic.
- **Seed fixtures** (`seed-*`, plus `Caddyfile.base` and the `demo/` dir) — NOT
  configs. They are fake edge states the settings files (and the test suite /
  recorded demos) load via `fake_seed`, so every example runs against an
  in-process fake and never touches real infrastructure. You don't edit these;
  you only ever point a `fake_seed:` line at one.

## Start here

| File | Who it's for |
|---|---|
| **[`config.example.yaml`](config.example.yaml)** | **Everyone's starting point.** One Caddy at home + optional split-horizon DNS (AdGuard internal, Cloudflare public) + an Authelia auth policy, heavily commented, every value a placeholder. Copy it to `~/.config/crenel/config.yaml`, substitute your values, delete what you don't use. |
| [`exposures.yaml`](exposures.yaml) | The matching declarative apply file: list what should be exposed, `crenel apply` converges live to it. |
| [`settings-apply.yaml`](settings-apply.yaml) | Minimal YAML settings against a fake edge — proves YAML settings work; try `apply` with zero infrastructure. |

## Walkthrough recipes (prose, not configs)

| File | Scenario |
|---|---|
| [`caddy-cloudflare-authelia.md`](caddy-cloudflare-authelia.md) | You run Caddy + Cloudflare + Authelia (the common privacy stack) and want to expose one new service on it. |
| [`adguard-cloudflare.md`](adguard-cloudflare.md) | Split-horizon DNS: AdGuard answers your LAN, Cloudflare answers the internet, one `expose` keeps both in sync. |
| [`DEMO-chain-write.md`](DEMO-chain-write.md) | Captured transcript of a coordinated two-edge chain write (what the transaction output looks like). |

## Configs by topology, common → exotic

Every one of these runs against a fake (`fake_seed`) or a throwaway path — safe
to try verbatim.

| File | You have… |
|---|---|
| [`settings-dns.json`](settings-dns.json) | One Caddy + internal & public DNS (mock providers — the no-infra shape of `config.example.yaml`). |
| [`settings-dns-split.json`](settings-dns-split.json) | Same, with a split-horizon flavor: internal answers differ from public, and one origin shows the structured internal-only form (`scope: internal`). |
| [`settings-brownfield.json`](settings-brownfield.json) | An existing hand-built Caddy you want crenel to **adopt** (`import`) without changing behavior. |
| [`settings-caddy-persist.json`](settings-caddy-persist.json) | A Caddy whose admin-API writes must **survive a restart** (on-disk Caddyfile mirror). |
| [`settings-selftest.json`](settings-selftest.json) | A rich production-shaped edge to run the self-test exposure cycle against. |
| [`settings-traefik.json`](settings-traefik.json) | Traefik (file provider) instead of Caddy. |
| [`settings-nginx.json`](settings-nginx.json) | nginx instead of Caddy (additive read-modify-write of your conf). |
| [`settings-netbird.json`](settings-netbird.json) | A NetBird mesh: read-only grant surfacing. |
| [`settings-caddy-layer4.json`](settings-caddy-layer4.json) | TCP/SNI passthrough via Caddy's layer4 plugin (`--mode passthrough`). |
| [`settings-dual-adguard.json`](settings-dual-adguard.json) | **Two** internal AdGuard resolvers (home + VPS vantage) — the split-horizon reference shape (`docs/REFERENCE-ARCH-split-horizon.md`). |
| [`settings-multiedge.json`](settings-multiedge.json) | Two peer edges (home + VPS) that both serve routes — parallel double-write. |
| [`settings-chain-frontedge.json`](settings-chain-frontedge.json) | A VPS **front** edge forwarding to a home edge, auth enforced downstream (read/audit view). |
| [`settings-chain-p4.json`](settings-chain-p4.json) | The chain with **follow-through**: status/audit resolve each forwarded host to its real downstream backend + observed auth. |
| [`settings-chain-write.json`](settings-chain-write.json) | The chain with coordinated **writes**: one `expose` lands front + downstream + DNS as one all-or-nothing transaction. |
| [`settings-multizone-residency.json`](settings-multizone-residency.json) | One edge serving several apex zones + per-host residency classes (vantage-divergent DNS answers). |
| [`settings-transport-sshexec.json`](settings-transport-sshexec.json) | A loopback-only Caddy admin you can only reach by SSH — the `ssh-exec` transport (no port, no tunnel). |
| [`settings-durable-home.json`](settings-durable-home.json) | The two-channel containerized home edge: durable persist where the Caddyfile lives on one host and `caddy` runs in a container. |
| [`vps-config.json`](vps-config.json) | A hardened VPS front-edge config (see `docs/internal/DEPLOY-VPS.md`). |

## Seed fixtures (referenced by the configs, tests, and docs — not configs)

`seed-empty.caddyfile`, `seed-grafana.caddyfile`, `seed-brownfield-caddy.json`,
`seed-rich-prod.json`, `seed-subroute-prod.json`, `seed-nested-subroute-prod.json`,
`seed-failopen.json`, `seed-chain-front.json`, `seed-chain-home.json`,
`seed-chain-write-edge.json`, `seed-traefik.json`, `seed-netbird-grants.json`,
`seed-nginx.conf`, `seed-audit-unmodeled.caddyfile`, `seed-audit-wildcard.caddyfile`.

Plus: [`Caddyfile.base`](Caddyfile.base) (an operator-style base Caddyfile for
the persist demos) and [`demo/`](demo/) (scripts + seeds behind the recorded
README demo — not a starting point).
