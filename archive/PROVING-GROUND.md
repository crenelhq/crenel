# Crenel proving ground (live multi-backend bench)

> **ARCHIVED (2026-07-02).** Internal bench documentation, kept because
> `CONTRIBUTING.md`'s trial-before-merge cadence references how live validation is
> done. Identifiers anonymized for publication.

A **standing** Proxmox LXC that runs REAL Traefik, nginx, Caddy, and Authentik so
crenel's edge drivers can be bench-tested against live systems — not just the faithful
in-repo fakes. It exists because live testing on Caddy alone caught three real bugs the
fakes structurally couldn't, so the not-yet-live-proven drivers (Traefik, nginx,
NetBird) needed the same treatment before any public multi-backend claim.

## The CT

| | |
|---|---|
| Proxmox node | `pve1` (10.0.0.10, Tailscale 100.100.0.7) — `ssh root@pve1` |
| CT ID / host | **120** / `crenel-proving` |
| IP | **10.0.0.20/24** (octet convention: CTID−100) |
| OS | Debian 13 unprivileged, `nesting=1,keyctl=1` (Docker-in-LXC) |
| Resources | 4 cores / 6 GiB RAM / 2 GiB swap / 24 GiB on `local-nvme` |
| Enter | `ssh root@pve1 'pct exec 120 -- bash'` |

### Isolation
- **Real guarantee:** every bench daemon binds to `127.0.0.1` inside the CT, and crenel
  is only ever pointed at in-CT `localhost` endpoints / paths — never the production
  Caddy edge, DNS, or Authelia. crenel cannot reach prod because it is never given prod
  endpoints.
- **Defense-in-depth:** an in-guest nftables egress DROP (`/etc/nftables.conf`, table
  `inet crenel_guard`) blocks outbound to `10.0.0.13` (prod Caddy/the home-edge host) and
  `10.0.0.16` (AdGuard/a disposable host); general internet egress stays open for image/apt pulls.
  The Proxmox datacenter firewall is disabled cluster-wide; enabling it for one guest
  rule was rejected as a risky cluster-wide toggle, so the block lives inside the CT.

## Layout — `/opt/crenel-bench/`

```
bin/crenel            cross-compiled linux/amd64 crenel (develop @ 7db759a)
bin/crenel-fixed      build of feat/proving-ground-bootstrap-fix (bootstrap fix)
traefik/              docker-compose (traefik:v3.1 + whoami); file provider watches dynamic/
  dynamic/operator.yml   brownfield routers, authored as real Traefik YAML
nginx/                docker-compose (nginx:1.27 + whoami); conf.d/crenel.conf is crenel-managed
caddy/                docker-compose (caddy:2 + whoami); admin API on 127.0.0.1:2019
authentik/            docker-compose (server+worker+postgres+redis), 2024.12.3, :9000
```

Ports (all `127.0.0.1`): Traefik web `8000` / api `8080`; nginx `8081`; Caddy http
`8082` / admin `2019`; Authentik `9000`.

## Re-running the bench

```bash
ssh root@pve1 'pct exec 120 -- bash -lc "
  cd /opt/crenel-bench/<driver> && docker compose up -d   # ensure the stack is up
  /opt/crenel-bench/bin/crenel -config settings*.json status --plain
"'
```

Per-driver `settings*.json` already exist under each stack dir. Writes are gated; use
`--auth none` (public, no gate) or `--auth <policy>` and `--yes`. For Caddy, granular
(additive) apply needs `-granular` **before** the verb. The per-stack scratch scripts
used to drive each trial (`*-test.sh`, `*-gate.sh`) are kept in the CT for replay.

## What the bench found (summary; full log in the trial report)

| Driver | Read | Write round-trip | Verdict |
|---|---|---|---|
| **Caddy** | ✅ live admin API | ✅ verified vs live runtime | live-faithful (control) |
| **Traefik** | ❌ JSON-only decode can't read real YAML | ❌ emits invalid `loadBalancer:{}`, Traefik rejects whole file | gaps T1–T4 |
| **nginx** | ✅ regex parser | ❌ `listen 443 ssl` w/o cert → `nginx -t` fails; no reload trigger | gaps N1–N5 |
| **Authentik** | n/a (auth provider) | ✅ Caddy gate render/detect/enforce against non-Authelia | provider-agnostic ✔ |
| **NetBird** | ✅ JSON grant file | ✅ file round-trip | file-only; no live mgmt-API integration (deferred) |

The single root cause behind the worst gaps (T4 / N2): the file drivers "read-back-verify"
by re-reading the artifact they just wrote, so they report success even when the daemon
rejected the config. The Caddy driver verifies against the live admin API and therefore
cannot.

## CRITICAL gaps burned down (branch `feat/proving-ground-bootstrap-fix`, live-validated)

All fixes verified against the bench host's real Traefik/nginx, RED→GREEN with the fakes upgraded
to reject what the real daemons reject. **Not merged.**

| Gap | Fix | Live proof on the bench host |
|---|---|---|
| **T4/N2** hollow verify | `ports.RuntimeVerifier`: file drivers probe the DAEMON (Traefik API / nginx -t+reload+HTTP probe), not their own file. Tri-state Confirmed / Failed→rollback / Unavailable→"written, not verified". Never a false green. | "verified LIVE (daemon confirmed)" via API/probe; "written; runtime verify unavailable" without a surface |
| **T3** invalid Traefik deny | drop the explicit deny (Traefik's native 404 IS default-deny); `validate()` rejects an empty loadBalancer | file accepted, route serves HTTP 200, no rejection in logs |
| **T6** empty-doc rejected | `encode()` emits `{}` (not `{"http":{}}`) when emptied | unexpose leaves `{}`, route 404s (actually removed) |
| **N1** invalid nginx ssl | default valid `listen 80;`; `WithTLS` adds cert for `listen 443 ssl` | `nginx -t` passes, reload succeeds |
| **N4** false default-deny | per-port implicit-default-server model; deny renders on the managed port | unmatched host denied (444); status ENFORCED matches reality; brownfield reads honestly FAIL-OPEN |
| **N3** inert writes | Apply runs operator-declared nginx -t + reload | route live with no manual reload |
| **T2/N5** missing-file | bootstrap missing config as empty | first expose initializes the file |
| **T1** YAML read | zero-dependency YAML-SUBSET decoder (yaml.go); auto-detect JSON vs YAML; encoder stays JSON (JSON ⊂ YAML) | stock crenel errors `invalid character 'h'` on the real `operator.yml`; fixed binary's status/audit/drift read it (blog + app + authelia@file detected); `go mod tidy` adds nothing |

All bench gaps are now closed. TOML stays declared-unsupported (not used by a Traefik
dynamic config crenel reads); a construct outside the YAML subset errors loudly rather
than mis-parsing.

### Enabling the runtime surfaces
Add to a settings edge: `traefik_api_url` (e.g. `http://127.0.0.1:8080`); or
`nginx_runtime: {test_cmd, reload_cmd, probe_url}` (commands run verbatim, e.g.
`["docker","exec","nginx-nginx-1","nginx","-t"]`) and optional `nginx_tls: {cert_path,
key_path}`. Omit them and crenel honestly reports "written; runtime verify unavailable".

## NetBird — why it's deferred
crenel's NetBird driver reads/writes a JSON grant **file**; it has no NetBird
management-server API client. A faithful live bench would need a NetBird management +
signal server + an IDP (e.g. Zitadel) **and** a glue exporter from that API to the JSON
grant store — heavyweight, and it would still not exercise a real control-plane path
crenel doesn't have. Defer until crenel grows a real NetBird API driver.
