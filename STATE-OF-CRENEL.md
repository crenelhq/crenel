# State of Crenel

> The single doc to read to understand Crenel's **true** current state: what is
> built, which backend supports what, what is solid vs partial vs known-risk, and
> the prioritized backlog. Written as a consolidation + adversarial-verification
> pass over a fast-moving build (M0–M13 + branding/HUD + usability + auth + P0
> detect-and-declare-unknown + P1.5 multi-server + partial P2 generator detection +
> P3 ingress + **P4 chain-aware read model**).
>
> Companions: **docs/internal/DESIGN.md** (architecture + invariants), **docs/internal/TOPOLOGY-RISK-REGISTER.md**
> (the long-tail safety spec — authoritative for §4 / the backlog), **docs/internal/STRAIN.md**
> (where the port strains), **docs/internal/AUTH-DESIGN.md** / **docs/internal/USABILITY-DESIGN.md** (feature
> semantics), **archive/BUILD_LOG.md** (per-increment narrative).
>
> **Anonymized for publication:** the maintainer's hostnames/zones/addresses appear
> throughout as consistent pseudonyms (`homelab.example`, `smallbiz.example`,
> RFC 5737/1918 ranges, generic host labels).
>
> _Last updated 2026-07-04 (public launch + independent audit follow-through: F5/F3/F2/
> ack-marker batch). Verified against `develop` HEAD `fd577e7`._
>
> **Correctness milestone (this pass).** The offline-provable silently-wrong gaps the
> roadmap had identified are closed: surgical record-level Cloudflare apply for shared
> zones (PR #11, LIVE-PROVEN on `crenel.sh`); dual-AdGuard split-horizon per-instance
> labeling + `dns_coverage_parity` audit (PR #12); `dns_value_drift` audit for owned
> records (PR #13); `DriftValueDNS` correction by `reconcile` (PR #14);
> wildcard-aware `dns_coverage_parity` (PR #15); wildcard-aware
> `dns_without_edge_route` + `edge_route_without_dns` siblings (PR #16); Tailscale
> serve.json per-host (funnel) recovery + per-edge authoritative public (PR #17);
> wildcard-aware `reconcile` / `drift` (`missing_dns_record` / `stale_dns_record`, PR #22).
> Each landed with RED→GREEN tests, an adversarial RED proof (the fix neutered
> reproduces the silent miss / cry-wolf), and **no live edge/DNS touched**. What
> remains is **live-only**, **structural / model-extension**, or **doc/coverage** —
> see §6.
>
> **Live-proof update (2026-06-28 → 06-30).** The live-only gates are now PROVEN on real
> infrastructure: home-edge durable-persist (expose + restart-survival + unexpose), the
> coordinated cross-chain write, surgical Cloudflare on the **shared** `homelab.example` zone,
> the dual-AdGuard split-horizon parity trial, and — closing punch-list #1 — the first
> **full-chain production expose (`finances.homelab.example` from the home-edge host, all 7 gates green)**.
> See §6.z **A0** and **docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md**. What's genuinely live-only
> now: Tailscale `serve.json` WRITE support.
>
> **Public launch + independent audit (2026-07-03 → 07-04).** Crenel shipped its first
> public release, `v0.4.0`, on `github.com/crenelhq/crenel`. An external audit
> (DeepSeek, 9 parallel code-tracing subagents) plus an independent verification pass
> found the default-deny and never-silently-wrong invariants SOUND, no CRITICAL/HIGH
> findings, and one MEDIUM (**F1** — a stock `http { server {} } `-wrapped nginx.conf,
> a stream-only config, an include-only config, or a map/upstream-only helper file all
> read as a false `ENFORCED` with zero routes/zero warnings). Fixed on `develop`
> (`548d8ad`; `server_not_read` now DECLARES the unrecognized block, downgrading deny to
> UNKNOWN) and shipped public as `v0.4.1`. See `docs/audits/independent-audit-2026-07-03.md`
> for the full audit + verification + the four remaining LOW items (F2/F3/F4/F5) it left
> at their original disposition. **This pass closes three of those four** — a minimal
> GitHub Actions CI (F5), a file-lock around the mutating apply path (F3), and a gate
> that REFUSES (rolls back) rather than silently stands an unconfirmed file-driver write
> when no runtime probe is configured (F2, `UnverifiedWriteError`/`--allow-unverified`) —
> plus ships the `ack` marker (operator acknowledgment of an intentionally-unmodeled
> route, `docs/design/ack-marker.md`), the real-use item that lets `audit`/`drift` stay
> cron-clean on a brownfield edge with a vetted carve-out. F4 (reconcile TOCTOU) remains
> open, documented, low-severity.
>
> _Earlier headlines:_ v0.3.2 (hardened Cloudflare DNS LIVE-PROVEN end-to-end on the
> dedicated `crenel.sh` zone, PR #10 merge `30e72ea`); v0.3.0 KNOWN-RISK BURNDOWN
> (path-granular routing now DETECTED+declared across all three data-plane drivers;
> declarative-apply auth read-back; per-host tunnel ingress recovery for cloudflared)._

---

## 0a. DNS-for-real (v0.3.1, LIVE-PROVEN v0.3.2) — real providers, EXPERIMENTAL & opt-in

Crenel can now drive **real** DNS as part of an `expose`/`unexpose`, grounding the
split-horizon the homelab runs by hand. **Off by default** (`dns.enabled: false`); with
no provider `type` (or `mock: true`) it uses an in-process fake and touches no real infra
(the entire test suite included). Two backends behind the one `ports.DNSProvider` port:

- **Cloudflare** (public, authoritative) via the **dnscontrol** adapter (`CLOUDFLAREAPI`,
  API-token creds in a `0600` throwaway `creds.json`). This is the path that finally
  exercises the real `OSShell`/`dnscontrol` exec.
- **AdGuard Home** (internal resolver **rewrites**) via a native control-API driver — NOT
  a dnscontrol provider — over an injectable `Doer` seam, with a **zone guardrail** that
  refuses to write a rewrite outside its configured zone (the `www.smallbiz.example`
  hijack trap). Credentials are env-ref-preferred and **redacted** at every output
  boundary. Faithful fakes for both reject what the real APIs reject (auth/zone-mismatch/
  conflict/rate-limit/invalid-content).

**Live trial status:** both scopes are now PROVEN live.
- **Internal AdGuard** — PROVEN live (a disposable host, disposable hostname, expose→verify→unexpose,
  byte-for-byte restored).
- **Public Cloudflare** — **PROVEN live on a dedicated zone (`crenel.sh`, 2026-06-30).**
  The hardened path ran end-to-end against the real `CLOUDFLAREAPI`/`dnscontrol` exec:
  preview (diff adds only the test record; the `dedicated_zone` guard allows the empty
  zone) → `expose crenel-dnstest.crenel.sh` (`dig` @both Cloudflare NS returns the A;
  proxied=false, ttl=300 — TTL/proxied fidelity holds) → `unexpose` (authoritative
  NXDOMAIN). Plus **idempotency ×2** (re-expose stable, re-unexpose no-op), a **true
  cross-provider rollback** (a failing edge after the DNS step → Crenel inverts the DNS
  change, re-adding the real record), and the **fail-safe abort** (a bad-token apply makes
  zero mutations). Zone restored empty; no production zone touched. This also validated the
  real `get-zones --format=tsv` 6/7-column + `cloudflare_proxy` contract against the live
  `dnscontrol 4.42.0` binary (the previously-unconfirmed §8.6/§8.7 assumption).

**Shared / real-zone management — surgical record-level apply BUILT + LIVE-PROVEN (PR
#11).** The whole-zone-authoritative `dnscontrol push` is fundamentally unsafe inside a
shared production zone, so Crenel grew a **non-destructive, record-level** Cloudflare
apply mode (`apply_mode: surgical`) that drives the Cloudflare REST API directly for
per-record CREATE/UPDATE/DELETE. Ownership marker = the safety boundary: every created
record carries `comment: managed-by:crenel host=<name>`; the `updateRecord` /
`deleteRecord` primitives REFUSE any record lacking it (defense in depth); `LiveRecords`
reports only marked records; and on expose, a foreign record at Crenel's exact name+type
is refused (default-deny). LIVE-PROVEN end-to-end on the dedicated `crenel.sh` zone
(2 foreign records BYTE-IDENTICAL across expose/unexpose, zone restored empty). A
multi-agent adversarial review caught + fixed a real prefix-collision break in
`owned()` (`HasPrefix` → word-boundary match) before the live trial. The
`homelab.example` **shared-zone surgical trial is now PROVEN LIVE (2026-06-30):** a
3-provider verify-expose of `crenel-fliptest` created only Crenel's `managed-by:crenel`
record while the pre-existing apex **wildcard stayed BYTE-IDENTICAL** across expose→unexpose,
all restored byte-for-byte (operator-record — see **docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md** §1).

**Two gaps the live preview surfaced → HARDENED (this pass, `feat/dns-hardening`):**

1. **`dedicated_zone` ownership default-deny.** The whole-zone-authoritative `dnscontrol
   push` only refused records Crenel *can't render* (MX/SRV/multi-value); a lone
   **wildcard A** slipped through, so a push would silently make Crenel authoritative over
   a shared zone. `model.Record` has no ownership marker, so Crenel now **refuses by
   default to push a zone holding any pre-existing record other than the op's own**; the
   operator sets **`dedicated_zone: true`** to assert whole-zone ownership. Unexpose /
   idempotent re-expose of a Crenel host and first-expose-onto-empty still work without
   the opt-in.
2. **TTL + proxied fidelity.** The render dropped a reproduced record's TTL (Auto→default)
   and proxied flag (would have un-proxied an orange-cloud record). `model.Record` gained
   `TTL`/`Proxied` (NOT in `Key()`); `LiveRecords` now reads the **real**
   `get-zones --format=tsv` 6/7-column layout (the old 4-column parse was misaligned with
   the actual binary) including the trailing `cloudflare_proxy=true`; the render carries
   `TTL(n)` + `CF_PROXY_ON` through unchanged (Cloudflare-gated) and excludes the
   provider-managed apex NS/SOA.

See **docs/DNS-DESIGN.md** (§5.2a-i/ii, §8.6/§9). `make check` green + race-clean.

---

## 0. Headline

Crenel is a **vendor-agnostic, live-state-authoritative CLI** for controlling what a
self-hosted reverse-proxy edge exposes. It holds **no stored desired state**; the only
truth is what the edge reports live. Three load-bearing invariants:

1. **Live-state-authoritative** — every mutating verb is `read-live → plan → apply →
   read-back-verify`; an admin-API `200` is never trusted as proof.
2. **Structural default-deny** — a host is reachable iff an explicit route exists +
   the catch-all deny is present; every driver always renders + reports the deny.
3. **Bounded honesty (detect-and-declare-unknown)** — anything `normalize` cannot
   fully parse becomes a *declared unknown* (counted, surfaced, mutation-blocking);
   default-deny is reported ENFORCED only when fully parsed; Crenel **refuses to
   manage** a route/edge it doesn't own.

**Verification status (current — develop `fd577e7`, post public-launch/audit-
follow-through/ack-marker):** `go build ./... && go vet ./... && go test -race -count=1
./...` all green — **17 test packages with tests, 545 test functions**, race-clean.
~21.9k LOC of non-test Go. (Each PR in the correctness phase landed RED→GREEN with an
adversarial-neuter RED proof; see §5i and §6. The 525-function count in the
2026-07-03 independent audit predates this session's F2/F3/ack-marker tests.)

**KNOWN-RISK BURNDOWN (latest):** four read/verify-side correctness items moved from
known-risk → correct, each RED-before/GREEN-after with a live-faithful fake, no live infra.
(1) **Path-granular routing is now DETECTED+declared** on all three data-plane drivers: a
route scoped by a non-host matcher (Caddy `path`/`method`/`header`, Traefik `&& PathPrefix()`,
nginx multiple `location` blocks) was SILENTLY read as a plain host route (dropping the path
constraint — a MISREAD-↓); now each is a declared `matcher_conditional` unknown, so deny
downgrades to UNKNOWN rather than falsely ENFORCED. (2) **Declarative `apply <file>` now
read-back-verifies auth** (+ upstream TLS), closing the consolidation-pass gap on that path
(expose + reconcile already did). (3) **Per-host tunnel ingress recovery**: Crenel reads a
cloudflared config's OWN ingress rules to resolve each host's external reachability by
OBSERVATION — naming observed-public hosts, flagging a dangling published-but-unserved
hostname, and folding tunnel-public into `public_without_auth`. Full path-granular *MODELING*
(per-path backend+auth) remains the P5 follow-on; see §5h.

**DURABLE-PERSIST (latest):** durability is now a first-class, detect-and-declare
property. `model.PersistenceModel` (durable-config/durable-file/resume/ephemeral-admin/
unknown) is set per-edge and SURFACED — status `Durability:` line, audit `ephemeral_writes`
warning, and a write-path declaration that a verified write on an ephemeral edge will NOT
survive a restart (the admin API carries no boot-source marker, so it's declared, never
inferred). And the home edge's durable path is BUILT: a wildcard-site Caddyfile reconciler
(`caddy/persist_caddyfile.go`) writes a managed host as a per-host handle INSIDE the
covering `*.zone` site (inheriting its TLS — NOT a shadowing top-level site), self-checks +
validates + **`caddy adapt` cross-checks** the candidate re-adapts to the live managed
state, then writes the host file + reloads — all over the home edge's TWO exec channels
(file→LXC host, caddy→container). Read-only-verified the boot model live (Caddyfile, no
`--resume`, ro-mounted from `/opt/stacks/caddy/conf`); the durable WRITE is now **PROVEN
LIVE end-to-end on the home edge** (expose + restart-survival + unexpose, byte-for-byte by
Crenel; TRIAL-RESULT-durable-persist-2026-06-28.md). See §5g.

**SECURITY (latest):** a security-hardening pass — **SECURITY.md** (threat model:
sensitive-data inventory, the loopback-first transport trust model, per-boundary
adversary analysis, residual risks, operator checklist) + **field-level secret
redaction** (`internal/redact`): a value-aware masker (key patterns + value
heuristics) applied to OUTPUT only (`status --json` excerpts, error echoes, rollback
prints, `export --redacted`), with a `--show-secrets` escape hatch and `0600` on
exports. The apply / read-back-verify / preserve-unmanaged paths keep REAL values
(proven: a managed expose leaves an unmanaged basic-auth secret byte-intact in live
config). See §5f.

**TRANSPORT (latest):** the pluggable **connection axis** — a `ports.Transport` the
Caddy admin driver uses for ALL admin calls, with `direct` (default; zero behavior
change), `ssh-exec` (run the call as a nested-exec curl against a loopback admin — no
port, no tunnel) and `ssh-tunnel` (crenel-managed local forward) implementations.
**READ-ONLY-verified LIVE** against the maintainer's home edge over ssh-exec (`ssh root@pve1 →
pct exec 113 → docker exec -i caddy → sh` → curl `127.0.0.1:2019`): `crenel status`
read 51 live services, default-deny ENFORCED, with the home admin still loopback-only
and the live config **byte-identical** before/after. See §5e.

**This pass fixed 6 real issues** (1 CLI coherence + 5 safety, all found by an
adversarial review) and corrected stale docs; see §5. The biggest finding: the
**Caddy full-load apply** (the default, non-granular mode) could silently drop
unparsed routes (falsely certifying default-deny) and strip forward-auth — now a
structural refusal.

---

## 1. Milestone / capability map (what's built)

Historical build order (all **BUILT** unless noted). Narrative in archive/BUILD_LOG.md.

| Track | What it delivered |
|---|---|
| **M0** | Scaffold, hexagonal core/ports/model, fake Caddy admin API; read-only `status`/`preview`; mutating `expose`/`unexpose` with read-back verify + structural default-deny; dnscontrol DNS (internal); `audit` + `export`. |
| **M1** | Transactional apply: compensating **rollback** + additive **granular** Caddy apply. |
| **M2** | **Traefik** file-provider driver (2nd edge; the port holds — docs/internal/STRAIN.md). |
| **M3** | Public DNS scope + unified cross-provider plan/apply with exposure-rank ordering. |
| **M4** | **Multi-edge** topology (home + VPS double-write): projection, cross-edge all-or-nothing transaction, per-edge wedge-safe rollback. |
| **M5** | **NetBird** mesh edge (3rd driver): reads; refuses mutation loudly. |
| **M6** | Typed **route Mode** (`http_proxy`/`tcp_passthrough`/`mesh_grant`) + loud `ErrModeUnsupported`. |
| **M7** | **resume** verb (re-drive an interrupted apply from live). |
| **M8** | Richer **audit** (TLS/SNI + mode-enabled cross-provider checks). |
| **M9** | Traefik TCP/SNI **passthrough** renderer (`tcp.routers`). |
| **M10** | **reconcile** verb (detect + fix ALL drift). |
| **M11** | Caddy **layer4** passthrough renderer (capability-gated). |
| **M12** | **nginx** edge driver (4th; a third config shape). |
| **M13** | **drift** verb (reconcile's read-only detect half; CI/cron). |
| **AUTH** | Forward-auth by reference (`--auth`, per-driver references, `public_without_auth` guardrail). |
| **USABILITY (UB1–4)** | Brownfield `import` (adoption), declarative `apply` (+JSON/YAML), Caddy on-disk persistence, `init`/quickstart/release. |
| **BRAND** | Crenellated wordmark + the status HUD as the real `status` surface. |
| **TRIAL-FIX** | Nested-subroute recursion + chain `auth_downstream` posture flag (from the real-VPS read-only trial). |
| **P0** | **Detect-and-declare-unknown**: `Unparsed[]`, ternary `Ownership`, default-deny downgrade, refuse-to-manage gate, status/audit surfacing. |
| **P2 (STARTED)** | Generator/foreign-ownership detection: **NPM** + **Traefik label/orchestrator providers** detected read-only. |
| **P3** | Tunnel/overlay ingress modeling (cloudflared/Tailscale): `IngressKind` declared/detected + surfaced. |
| **P4 (READ)** | **Chain-aware model**: front edge → `downstream_edge`; `model.ChainLink` follow-through; auth resolved by OBSERVATION (status real downstream dest + audit observed `public_without_auth`); honest "downstream, not observed" when unreadable. |
| **P4-write** | **Cross-chain coordinated WRITE**: one `expose`/`unexpose`/`reconcile` lands/tears the coordinated front-forward + downstream-route + DNS as ONE ordered (downstream→front→public-DNS), read-back-verified, all-or-nothing transaction; auth attaches downstream; gate spans both edges; chain-wide public-without-auth; half-present chain converges. |
| **TRANSPORT** | **Pluggable connection axis** (`ports.Transport`): the Caddy admin driver makes the SAME calls through a transport — `direct` (default; zero behavior change), `ssh-exec` (nested-exec curl against a loopback admin — no port, no tunnel), `ssh-tunnel` (crenel-managed local forward). Per-edge `transport` config; never-hang + wedge classification preserved above the seam. LIVE read-only-verified against the home edge over ssh-exec. See §5e. |
| **DURABLE-PERSIST** | **Persistence model as a detect-and-declare property + the durable home-edge Caddyfile reconciler.** `model.PersistenceModel` per edge (durable-config/durable-file/resume/ephemeral-admin/unknown) surfaced by status/audit + a write-path ephemeral warning (`ports.DurabilityReporter`); the wildcard-site reconciler makes an admin-API write SURVIVE a restart by reconciling it into the on-disk boot Caddyfile, **proven to re-adapt to live before commit** (no second SOT), over the home edge's two exec channels. Read-only-verified the boot model live; durable WRITE **PROVEN LIVE** (expose + restart-survival + unexpose, byte-for-byte; TRIAL-RESULT-durable-persist-2026-06-28.md). See §5g. |
| **SECURITY** | **Threat model (SECURITY.md) + field-level secret redaction.** SECURITY.md formalizes the sensitive-data inventory, the loopback-first transport trust model (network-exposing the plaintext/unauthenticated admin API is THE anti-pattern), per-boundary adversary analysis, and operator guidance. `internal/redact` masks secret-bearing fields (key patterns + PEM/bcrypt/JWT/Bearer value heuristics) in OUTPUT only — `status --json` excerpts, admin-body error echoes, rollback prints, `export --redacted` — gated by `--show-secrets`; exports are `0600`. Apply/verify/preserve keep REAL values. See §5f. |

### CLI surface (verified against `crenel help` + dispatch)

Read-only: `status` (`--hud`/`--banner`/`--plain`/`--json`), `audit`, `preview
<expose|unexpose> <svc>` / `preview rename <old-host> <new-host>`, `drift`, `export <file>
[--redacted]`. Mutating (preview → confirm → apply → read-back-verify):
`expose`/`unexpose`/`set <svc> <on|off>`, **`rename <old-host> <new-host>`** (the one-command
atomic move: add new copying the source backend/auth/mode + remove old, make-before-break,
durable, rolled back as a unit — `feat/rename-verb`), `resume`, `reconcile`,
`import [--dry-run]`, `apply <file> [--adopt|--prune|--dry-run]`. Scaffold: `init [dir]`. Plus
`version`/`help`.

Global flags: `-config -admin-url -zone -fake-seed -yes -force -json -show-secrets
-granular -layer4 -caddy-persist -mode -auth -param`. As of this pass, the post-settings-load
flags (`-yes -force -json -show-secrets -mode -auth -param`) are also honored **after** the verb
(see §5, the CLI fix).

---

## 2. Capability × backend matrix

Edge drivers behind the `EdgeProvider` port (+ optional `Adopter`/`Persister`/
`HealthChecker` capabilities). ✅ supported · ⚠️ partial/conditional · ❌ refused
loudly · — n/a.

| Capability | Caddy | Traefik | nginx | NetBird (mesh) |
|---|:--:|:--:|:--:|:--:|
| Read live state / `status` / `audit` | ✅ admin API | ✅ file | ✅ file | ✅ read-only |
| Structural default-deny (render + report) | ✅ | ✅ | ✅ (`444`) | ✅ (no grant) |
| `expose` / `unexpose` (http_proxy) | ✅ | ✅ | ✅ | ❌ refuses |
| TCP/SNI passthrough (`mode=passthrough`) | ⚠️ via `layer4`, gated + granular | ✅ `tcp.routers` | ❌ refuses (no `stream`/`ssl_preread`) | ❌ |
| Mesh grant (`mode=mesh`) | ❌ | ❌ | ❌ | ✅ native |
| Forward-auth by reference (`--auth`) | ⚠️ **granular + persist only** (full-load refuses) | ✅ middleware | ✅ `auth_request` | — (identity-enforced) |
| Additive apply (preserves unmanaged) | ⚠️ **granular only** (full-load is a full replace) | ✅ read-modify-write | ✅ read-modify-write | — |
| `import` (adoption / `Adopter`) | ✅ (nested @id PATCH) | ✅ (re-key) | ✅ (comment marker) | ❌ not implemented |
| On-disk persistence (`Persister`) | ✅ flat `caddy_persist_path` + **durable wildcard reconciler** (`caddy_persist`, re-adapt-verified) | — (file is durable) | — (file is durable) | — |
| Persistence model (declared+surfaced) | ✅ ephemeral-admin (default) / durable-file / resume | ✅ durable-config | ✅ durable-config | — |
| Wedge probe / `HealthChecker` | ✅ admin liveness | — (no admin endpoint) | — | — |
| Generator/foreign detection (P2) | ⚠️ caddy-docker-proxy via on-disk `Caddyfile.autosave` / declared hint (admin API has no marker); Pangolin → Traefik | ✅ docker/swarm/k8s provider suffix · **Pangolin** (`badger` middleware) | ✅ NPM signature | — |
| Ownership marker | `@id crenel-route-<host>` | `crenel-*` router/service key | `# crenel-managed:` comment | — |

DNS (v0.3.1, EXPERIMENTAL/opt-in — see §0a): **dnscontrol** adapter for **Cloudflare**
(public, `CLOUDFLAREAPI` via real `OSShell`) + a native **AdGuard Home** control-API driver
(internal rewrites); split-horizon **internal** + **public** scopes; off by default, mock
when unconfigured (the test seam — no real provider in any test). Adoption is by
**recognition** (no marker — deliberately, to avoid reintroducing stored state); the
whole-zone Cloudflare push requires `dedicated_zone: true` (ownership default-deny). Origin
resolution: **static** map driver, per-edge.

**Apply-mode caveat (important):** for any rich/brownfield/real edge use Caddy
**`--granular`**. Full-load (the default) is a full-config replace that is only safe
on a greenfield/crenel-owned edge — and now *refuses* (rather than silently
clobbers) when live holds unparsed constructs, real forward-auth, or passthrough.
`init`'s scaffold sets `granular_apply: true`.

---

## 3. Solid vs partial vs known-risk

### Solid (verified, well-tested)

- **The three invariants at READ time.** `DenyState()` ternary (ENFORCED ⟹
  FullyParsed), `Reachable` = deny ∧ explicit route, `Coverage()`/`Unparsed[]`
  surfacing in status/audit/HUD/JSON.
- **Refuse-to-manage gate** (`core.gateOwnership`) runs before any driver `Apply` on
  every mutating path (apply/reconcile/declarative/resume); import/`apply --adopt`
  classify foreign/unknown as conflicts/blocked before any `Adopt`. `--yes` never
  bypasses; `--force` covers `unknown` only, never `foreign`; a `Generator`-set edge
  is refused edge-wide. (Adversarially verified this pass.)
- **Read-back-verify + wedge-safe rollback.** Every mutate path re-reads live and
  asserts deny + host expectation; per-edge wedge probe skips only the wedged edge's
  compensator and still returns an error with a recovery hint. Every Caddy admin
  call is bounded by a per-op context deadline.
- **Granular/Traefik/nginx additive apply** preserve unmanaged routes verbatim
  (incl. brownfield auth). NetBird reads + refuses mutation honestly.
- **Multi-edge projection + reconcile managed boundary** — only `anyFronts`
  services enter the canonical set; reconcile never deletes a route outright or
  touches unmanaged DNS.
- **Zero-dependency build** (hand-rolled Caddyfile adapter, nginx tokenizer, Traefik
  rule parser, YAML-subset decoder). No live infra in any test.

### Partial / stubbed (works, with a documented boundary)

- **Caddy full-load apply** is greenfield-only by design and now *refuses* to lose
  state; the production path is granular. Full-load cannot render auth/passthrough.
- **P2 generator detection** covers NPM (nginx), Traefik label/orchestrator
  providers, **Pangolin** (Traefik `badger` middleware), and **caddy-docker-proxy**.
  CDP detection has a documented boundary: the Caddy **admin API carries no CDP
  marker** (verified against CDP docs), so detection needs either the mounted on-disk
  `Caddyfile.autosave` (`caddy_generator_config_path`) or an operator-declared hint
  (`caddy_generator`). Without one of those signals a CDP edge still reads
  read-only-safe via the P0 net, but its routes look `unmanaged` (mutable) — the
  residual MISMANAGE risk the two signals close.
- **Chain topology** is now a *chain-aware READ model* (P4, §5a): a front edge names
  a `downstream_edge` (+ optional `downstream_address`); core attaches
  `model.ChainLink` to each forwarded route and **follows through** — reading the
  downstream edge to resolve the host's real backend + the auth **observed** there.
  `status` shows the real downstream destination + auth; `audit` resolves
  `public_without_auth` by **observation** (a downstream-Authelia host is protected,
  a downstream-no-auth host IS flagged), falling back to the `auth_downstream`
  *assertion* (suppress, declared "downstream, not observed") only when the downstream
  is unreadable. The `auth_downstream` flag remains the fallback. **WRITE (P4-write):**
  cross-chain coordinated WRITE is now built — one `expose`/`unexpose`/`reconcile`
  lands/tears the front-forward + downstream-route + DNS as ONE ordered (downstream →
  front → public-DNS), read-back-verified, all-or-nothing transaction; auth attaches at
  the downstream edge that SERVES the host; the gate spans both edges; the
  public-without-auth guardrail evaluates the whole chain; a half-present chain
  converges via `reconcile`/`drift` (§5d). **Boundary:** built against fakes/fixtures
  only (a live cross-chain write trial is a separate, backed-up step); a pure-front
  chain (no `downstream_address`) stays READ-only until an address is configured; chain
  `Adopt` reuses per-edge adoption; two-zone front edges remain follow-on.
- **nginx managed-block re-render** reconstructs a crenel-owned block from
  address+auth only — extra directives an operator added *inside a crenel-managed
  block* are lost on an unrelated apply (the marker says "regenerated; edit other
  blocks"). Documented fidelity boundary, not a safety hole.
- **Traefik/nginx "live" read** is the desired file, not the running process (no
  admin read-back like Caddy's). Documented strain (docs/internal/STRAIN.md).
- **DNS reconcile** is presence/absence + mode only; record *value* drift (right
  name, wrong target) is not detected/fixed by `reconcile`. (The `expose` apply path IS
  value-aware as of v0.3.1 — a changed value re-asserts + read-back-verifies; only the
  separate `reconcile` drift-fixer remains value-blind. See §0a / docs/DNS-DESIGN.md.)

### Known-risk (the long tail — register §2; safe-by-default via P0)

These are topologies Crenel does not fully model. P0 makes each a *declared unknown*
(refuse/UNKNOWN) rather than a silent wrong answer, so they are **safe but not yet
correct**:

- **Regenerated-config generators** beyond NPM/Traefik-labels/Pangolin/cdp — until
  detected, an undetected generator's edits would read-back green then revert
  (MISMANAGE). Its *unmodeled shapes* still surface via the `Unparsed` net. (NPM,
  Traefik label/orchestrator providers, **Pangolin**, and **caddy-docker-proxy** are
  now detected; CDP needs the mounted autosave file or a declared hint — see §5a.)
- **Tunnel/overlay ingress** (cloudflared, Tailscale funnel/serve) — public decoupled
  from public port. **Surfaced (P3, §5a)** AND **per-host recovered for cloudflared
  (§5h):** `IngressKind ∈ {public-listener, tunnel, overlay, unknown}` is declared/detected
  and surfaced; Crenel now reads a **cloudflared** config's own ingress rules to resolve each
  host's external reachability by OBSERVATION (`ingress_public_hosts`, `tunnel_route_without_edge`,
  folded into `public_without_auth`). **Remaining:** Tailscale serve.json per-host (funnel keys)
  recovery — still coarse declared-unknown (safe). An externally-fronted edge Crenel can't
  classify is DECLARED UNKNOWN, never assumed internal.
- **Sub-host routing** (path/header/method; per-path auth) — host-granular model can't
  represent it, but a path-scoped route is **no longer SILENTLY misread** as a host route:
  it is DETECTED + declared `matcher_conditional` across Caddy/Traefik/nginx (§5h), so deny
  downgrades to UNKNOWN. Full path-granular MODELING (per-path backend+auth) is the P5
  follow-on.
- Multi-zone edge, HA/VIP pairs, TLS-terminated-downstream, Traefik KV provider,
  k8s ingress — all register §6/long-tail.

(**Resolved since the consolidation pass:** _Multiple Caddy `http.servers`_ — now
read in full; see §5a P1.5.)

---

## 4. Adversarial safety review — verdict

A dedicated review probed the six high-stakes surfaces (default-deny ternary,
refuse-to-manage, read-back-verify, ownership classification, cross-edge
transaction/rollback, exposure-correctness). **Invariants that held** (independently
re-verified): gate placement + `--yes`/`--force` semantics, edge-wide foreign
refusal, admin-API timeouts, rollback wedge-safety, case handling, mesh/public
correctness, the default-deny ternary *at read time*.

**The throughline of the bugs found:** the Caddy full-load path and reconcile's
canonical model were lossy about everything outside `{host, mode, address}`, and
read-back-verify didn't assert auth — so Crenel could degrade exposure/protection as
a *side effect of a mutation* and still report green. All such findings are now fixed
(§5).

**One gap surfaced this pass and NOT fixed (flagged):** Caddy `normalize` reads only
the one configured `http.servers` key; sibling servers (a route on `srv1`) are
silently ignored without an `UnknownServerBlock` entry — a MISREAD-↓ by omission on a
multi-server edge, contradicting the bounded-honesty invariant. It's left for a
follow-up because a naive fix would flag benign `:80`-redirect servers as unparsed
(amber-noise / cry-wolf); the correct fix declares only sibling servers that *forward*
(contain a `reverse_proxy`/subroute) as `UnknownServerBlock`. **P1.5 in the backlog.**
→ **FIXED (see §5a).**

---

## 5. What this consolidation pass changed

Six fixes (each its own commit, kept green), plus doc corrections:

| # | Commit | What |
|---|---|---|
| CLI | `fix(cli): honor global flags placed after the verb` | Go's `flag` stops at the first positional, so README-documented forms (`import --yes`, `expose <svc> --auth none`) silently dropped flags / `apply <f> --yes` errored. Added `absorbPostVerbFlags`. Guardrail unchanged. |
| F1/F2 | `fix(caddy): refuse full-config load that would silently lose state` | Full-load (default) rebuilt from understood routes only → dropped `Unparsed` (false ENFORCED) + stripped forward-auth (public-unprotected), read-back green. Added `fullLoadSafe` structural refusal → `--granular`. |
| F3 | `fix(reconcile): carry forward-auth through the canonical set` | Reconcile re-add/re-render dropped auth (protected → unprotected). Carry auth in `canonicalState`; read-back now re-asserts auth on touched routes. |
| F4 | `fix(caddy): bound the persist validate/reload subprocesses` | `caddy validate`/`reload` ran on an unbounded context (could hang). Bounded by the write timeout. |
| F5 | `fix(traefik,nginx): declare host-less forwarding routers unparsed` | A host-less router/server that *forwards* was silently dropped; now emits `Unparsed` (forward-only, to avoid redirect-server noise). |
| docs | `docs: correct stale milestone list + Caddy auth/full-load claims` | docs/internal/DESIGN.md milestones (was "M1 in progress"); docs/internal/AUTH-DESIGN.md Caddy full-load auth claim (full-load *refuses* auth; `import` is the persist form). |

**Smoke test (brownfield quickstart against `examples/settings-brownfield.json`):**
`status → audit → import --dry-run → apply --dry-run` all coherent; the HUD/coverage/
deny lines read correctly; `import --dry-run` correctly offers only the matching
`grafana` and exits non-zero. First-run UX notes (minor, not fixed):

- `crenel init` then `crenel status` (the printed "Next steps") fails with a raw
  `connection refused` when no real edge is up — the scaffold is brownfield-oriented
  (no `fake_seed`). Consider a hint pointing at `-fake-seed` for the no-infra demo.
- The `init`-scaffolded `crenel.exposures.yaml` (grafana, no `auth:`) would be
  *refused* by the public-without-auth guardrail on a real `apply` (correct + safe,
  but could surprise a new user). The scaffold comment shows `auth: none` as the
  opt-out.

---

## 5a. Danger-first backlog work (post-consolidation)

Worked in DANGER order after the consolidation pass. Each item is impl + tests +
docs, every commit green under `go build ./... && go vet ./... && go test -race`.

| # | Item | What changed | Safety property closed |
|---|---|---|---|
| **P1.5** | **Multi-server Caddy** | `normalize` now enumerates **all** `http.servers`, not just the configured key. A fully-modeled forwarding sibling has its leaf routes folded into the view (its hosts now appear in status); a sibling that **forwards** (`reverse_proxy`/subroute) but Crenel can't fully model becomes a single `UnknownServerBlock` (→ deny downgrades to UNKNOWN); a **benign** non-forwarding sibling (`:80`→`:443` redirect, pure `file_server`) is **not** flagged (no cry-wolf). Full-load `Apply` now also **refuses** a multi-forwarding-server edge (the single-server renderer would collapse it) → `--granular`. | Closes the MISREAD-↓-by-omission: a route on a sibling server is no longer invisible, and a forwarding server Crenel can't see can no longer keep default-deny falsely green. |
| **P2 (finish)** | **caddy-docker-proxy + Pangolin generator detection** | **Pangolin** → detected in the **Traefik** driver (it generates Traefik config) via its `badger` access middleware → edge + routes `OwnForeign`. **caddy-docker-proxy** → the Caddy admin API has **no** CDP marker (verified vs CDP docs), so detection reads CDP's on-disk `Caddyfile.autosave` (`caddy_generator_config_path`) by filename/content, with an operator-declared `caddy_generator` hint as the robust fallback → edge `OwnForeign`. Both keep routes READ-able (understanding ≠ ownership). | Closes the highest-prevalence MISMANAGE class: a generator-owned route now reads foreign so the gate refuses to mutate it (a Crenel edit would be reverted on the next regeneration). No false-positive on hand-written Caddy/Traefik. |
| **P3** | **Tunnel/overlay ingress modeling** | Typed `model.IngressKind ∈ {public-listener, tunnel, overlay, unknown}` + `External()`. Core overlays an edge's ingress posture (declared via `ingress_kind`, or detected by scanning a cloudflared `config.yml` / Tailscale `serve.json` via `ingress_config_path`) onto live state for status + audit. An externally-fronted edge Crenel can't classify → `IngressUnknown` (declared, never assumed internal). Surfaced as the `ingress_external` audit finding + a status `INGRESS:`/`⚠ Reachability` label. Driver-agnostic (lives in `core/ingress.go`; cloudflared/Tailscale front any proxy). | Closes the MISREAD-↓ "exposed isn't a public port": a service reachable via cloudflared / Tailscale funnel is PUBLIC even when the local proxy binds localhost; reading only the listener and calling it internal is now impossible — it's surfaced, or declared UNKNOWN. |

(crowdsec/tls are separate Caddy *apps*, not `http.servers` — the `Config` type only
models the http + layer4 apps, so they are structurally incapable of being misread as
server blocks; a regression test asserts this.)

### 5b. v0.1.1 — two Caddy real-edge misreads (the v0.1.0 read-only trial)

Cutting v0.1.0 and installing it **read-only** on the real VPS edge (loopback admin
API, GET-only, proven byte-for-byte unchanged) surfaced two normalizer MISREAD-↓-by-
omission bugs — both now fixed (impl + tests, green, race-clean), tagged `v0.1.1`:

| # | Item | What changed | Safety property closed |
|---|---|---|---|
| **M1** | **Grouped multi-host route** | A single Caddy route matching many hosts (`host:[a,b,c]` — his edge groups ~16 and ~7 vhosts that share the downstream backend into one route) read as ONLY its first host; the rest were silently dropped (status showed 9 of ~30 reachable). `hostMatches()` now enumerates every co-matched host; `normalizeServer` + `collectLeaves` loop over all of them. | The grouped hosts are no longer invisible — "what's exposed" answers all ~30 services, not 9. |
| **M2** | **`abort:true` deny** | His per-zone catch-all is `static_response{abort:true}` (no `status_code`); `isDeny` matched only `status_code>=400`, so it read as an unmodeled handler → false `UNKNOWN` default-deny + INCOMPLETE coverage. Added `Handler.Abort` to `isDeny`; `collectLeaves` returns a `resolved` bool so a deny-only subroute isn't flagged opaque. | Default-deny reads `ENFORCED` (not a cry-wolf `UNKNOWN`) on an edge that closes via `abort`; coverage is complete. |

Net: the real edge now reads correctly — ~30 services, 0 unparsed, default-deny
`ENFORCED`, auth-downstream suppression intact. **Still edge-level only** (unchanged
boundary): the grouped hosts that forward to the home edge are enumerated but the
chain is still modeled as terminal (P4), and `Adopt` still matches a grouped route by
its first host (write-path; irrelevant to read-only use).

### 5c. P4 — chain-aware modeling (read-correctness) + the demo-origins papercut

Promotes the chain from a blunt suppression flag to a first-class, OBSERVED
relationship; plus a config papercut fix. Each item is impl + tests, every commit
green under `go build ./... && go vet ./... && go test -race`.

| # | Item | What changed | Property closed |
|---|---|---|---|
| **P4.model** | **Chain as a first-class relationship** | `model.ChainLink` (`Route.Chain`) + `EdgeBinding.{DownstreamEdge,DownstreamAddress}` ← config. A CHAIN (front → downstream → origin) is modeled DISTINCT from parallel multi-edge (peer "double-write"): a front leaf that dials the downstream edge is a chain FORWARD, not a terminal origin. | The front's "backend" is no longer misread as a terminal — it is recognized as another edge. |
| **P4.follow** | **Follow-through (status)** | `core/chain.go` (`readAll`/`buildChainContext`/`resolveChain`); `status` overlays each forwarded route's `ChainLink` + the auth OBSERVED downstream and renders `front-dial → downstream-edge:real-backend [auth:…]` (or "→ edge (downstream, not observed)" when unreadable). A chain-target edge whose read fails degrades to a DECLARED-UNKNOWN row, never an abort. | The ~21 forwarded hosts now resolve to their REAL downstream destinations, not the opaque downstream-edge address. |
| **P4.auth** | **Auth resolved by OBSERVATION (audit)** | `effectiveAuth` (shared status/audit): real front auth > observed downstream auth (""=> flagged) > the `auth_downstream` assertion. A downstream-Authelia host reads PROTECTED; a downstream-**no-auth** host **IS** flagged `public_without_auth` (no longer blanket-suppressed); unreadable downstream falls back to the assertion + `chain_unresolved`/`edge_unreadable`. | `public_without_auth` is correct by OBSERVATION, not merely suppressed by a flag — closes the chain MISREAD (both the cry-wolf AND the silent over-suppression). |
| **Papercut** | **Demo origins no longer leak** | `config.Load` decodes a real config into a ZERO `Settings` (not merged UNDER `Defaults()`), so the bundled demo origins (grafana/photos/vault) stop leaking as phantom entries in `import --dry-run`. Empty-path/`init` scaffold still seed helpful defaults. | A real config's `import --dry-run` no longer offers phantom demo services. |

Proven end-to-end against the bundled two-edge fixtures (`examples/seed-chain-{front,
home}.json` + `settings-chain-p4.json`) mirroring the maintainer's shape: a wildcard front
grouping vhosts and forwarding to a downstream edge with a per-host Authelia host +
per-host open hosts. `status` follows through to the real backends + observed auth;
`audit` flags only the open hosts (`books`/`git`) and reports `chain_resolved`; vault
(Authelia downstream) is NOT flagged. **Boundary:** READ-correct; the cross-chain
WRITE transaction is now ALSO built — see §5d.

### 5d. P4-write — cross-chain coordinated WRITE

The follow-on the P4 read model deferred. A single `expose`/`unexpose`/`apply`/
`reconcile` on a CHAIN now lands the coordinated entries across the front edge + the
downstream edge + DNS as ONE all-or-nothing, read-back-verified transaction — no more
mutating a chain one edge at a time. Each item is impl + tests, every commit green
under `go build ./... && go vet ./... && go test -race`.

| # | Item | What changed | Property |
|---|---|---|---|
| **projection** | **Per-participant changeset** | `core/chain_write.go` `roleFor` classifies each edge TERMINAL (serves the service) / FORWARD (chain front whose downstream participates) / NONE. `Plan` projects a chain `expose` into the downstream's real route (carrying `op.Auth`) + the front's synthesized FORWARD route (`DirectBackend` dial to `downstream_address`, NO auth). Non-chain topologies project byte-for-byte as before. | The front leaf is no longer misread as terminal on WRITE — a chain op coordinates both edges. |
| **ordering** | **Chain-depth exposure rank** | `buildSteps` adds a chain-DEPTH secondary sort key: on expose **downstream → front → public-DNS LAST**; on unexpose the reverse. Depth 0 in any non-chain topology (ordering unchanged). | A chain host is announced to the world only after BOTH edges can serve it; torn down world-first. |
| **rollback** | **Cross-chain all-or-nothing** | Front + downstream are ordinary edge steps with per-edge inverse compensators, so any failure (apply OR read-back, on either edge or DNS) rolls back EVERY applied participant in reverse — wedge-safe per edge. Reuses the existing compensator machinery. | Nothing is left half-applied on either edge of a chain. |
| **auth-verify** | **Read-back auth where it lands** | `verify` now asserts each ADDED route reads back carrying the planned auth (AuthNone/"" normalized). In a chain this proves the policy attached at the DOWNSTREAM edge (the front carries none); generally it closes the consolidation-pass auth-verify gap. | A render that silently dropped/failed to attach auth FAILS verification instead of reading green. |
| **gate** | **Spans both edges** | `gateChainOwnership` refuses a chain write whose host is foreign/unknown on the front OR the downstream — even when that edge's planned change converges to a no-op (pre-existing foreign downstream). | foreign/unknown on EITHER edge → refuse to manage. |
| **guardrail** | **Chain-wide public-without-auth** | The CLI guardrail keys on `op.Auth` + the chain-wide `NewPublic` (the front forward), so a public chain expose with no auth anywhere is refused unless `--auth <policy>` (→ downstream) or `--auth none`. | No silent unprotected publish across a chain. |
| **converge** | **reconcile/drift chain-aware** | Reconcile participates an edge by chain ROLE; a half-present chain converges as one transaction (missing front forward → re-forward; missing downstream → re-serve by its own resolver); `drift` reports either half. Canonical auth comes from the SERVING (downstream) edge, never the front relay. | A drifted/half-present chain self-heals; auth is not stripped on a re-add. |

Proven end-to-end against the bundled two-edge write fixture
(`examples/settings-chain-write.json` + `seed-chain-write-edge.json`) and
`internal/core/chain_write_test.go` (real caddy fakes + DNS): expose lands
front+downstream+DNS atomically in order, read-back-verified; injected failure at each
step (front / downstream / public-DNS / silent auth-drop) → full rollback; unexpose
reverses; reconcile heals both half-present directions; foreign/generator downstream
refused; idempotent re-expose is a no-op. Captured demo: `examples/DEMO-chain-write.md`.
**Boundary:** fakes/fixtures only (a live cross-chain write trial is a separate,
backed-up step); a pure-front chain (no `downstream_address`) stays READ-only.

**TRIAL-FIX-2 — write-side subroute nesting (2026-06-28).** Grounding the next live
re-run in the captured real edge configs surfaced a write-side defect: Crenel's
granular insert PUT every per-host route to the FLAT top-level
`…/servers/srv0/routes/0`, but both real edges keep ALL per-host routing INSIDE wildcard
`*.zone` subroutes (no flat top-level per-host routes), so a flat insert misplaced the
route relative to where the read side (`collectLeaves`) enumerates it and where
`unexpose`/`Adopt` target it by `@id` — the **WRITE-side analog** of the already-fixed
read-side recursion. Fixed: `insertRoute` now resolves the insert location **per-zone**
(`httpRouteInsertPath`) — a wildcard `*.zone` subroute covering the host → nest at index
0 of that subroute; a flat zone (flat top-level sibling in the same zone) or a
flat/greenfield edge → the historical top-level insert (back-compat; a mixed edge can
route some zones via subroutes and keep others flat); ambiguous (>1 covering) or a zone
absent on an otherwise subroute-structured edge → **refuse loudly**. `unexpose`/`Adopt`
act on the route at its nested depth unchanged (global `@id`). Reproduce-then-fix tests
(each RED on the flat insert, GREEN after): driver-level nest/flat/refuse + the
cross-chain `TestChainWrite_NestsAcrossWildcardSubrouteChain` (front forward + home
terminal+auth both nest, byte-for-byte restore). The Caddy fake was made faithful first
(path-addressed nested PUT + global nested `@id` GET/DELETE) — the gap that let the
fake-based suite miss this. **The live cross-chain trial has since RUN at production scale**
(the `finances.homelab.example` full-chain expose from the home-edge host, 2026-06-30 — this route nests
across the `*.homelab.example` wildcard subroute on both edges; docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md §3).
A byte-logged re-run isolating the nesting axis alone remains an optional tidy-up.

**TRIAL-FIX-3 — valid forward-auth JSON renderer (2026-06-28).** The trial's OTHER
finding — the one that actually aborted the coordinated WRITE — is now fixed. Crenel's
granular auth path emitted a synthetic `{"handler":"forward_auth", …}`; **`forward_auth`
is a Caddyfile DIRECTIVE, not a JSON module**, so the home Caddy rejected the load at
provision (`unknown module: http.handlers.forward_auth`) and the all-or-nothing
transaction backed out (zero changes). Inspecting the real home edge config
(`live-backup/trial-chain-write-*`) showed Authelia expressed as a `reverse_proxy` to
`authelia:9091` with a `handle_response` subrequest (2xx → copy `Remote-*` headers →
continue; else return the 302) and a rewrite to `/api/verify?rd=…` — the canonical
`forward_auth` expansion. Fixed: the granular path now renders, before the backend, a
`vars` policy **marker** (`crenel_policy`, which round-trips the name off a real edge —
vars keys survive Caddy normalize) + a **VALID gate**, either the **canonical**
`reverse_proxy`+`handle_response` expansion of an operator-declared endpoint/verify-URI/
copy-headers (`caddy_forward_auth[_verify_uri/_copy_headers]`) or an operator **verbatim**
handler blob (`caddy_handler_json`, purest by-reference). A snippet-only granular policy
is **refused loudly** (the admin API can't express a Caddyfile `import`). The read model
now **skips the gate's authorizer `reverse_proxy`** for leaf enumeration and recognizes
the structural gate (so real Authelia routes read their true backend + `(detected)`).
**caddyfake was made faithful first** — it now PROVISIONS inserted handlers and rejects
an unknown module with Caddy's exact 500, reproducing the trial abort in-suite (the gap
that let the fakes round-trip the bogus handler). Reproduce-then-fix tests:
`caddyfake/fake_test.go` (synthetic `forward_auth` rejected / canonical gate accepted),
`caddy/auth_test.go` (canonical render + verbatim blob + snippet-only refused),
`core/chain_write_nested_test.go` (`TestChainWrite_ValidAuthGateNestedOnBothEdges` +
`--auth none`). See docs/internal/AUTH-DESIGN.md §2.1.

**TRIAL-FIX-4 — front-leg upstream TLS on chain-forward routes (2026-06-28).** With
nesting (FIX-2) and the valid auth gate (FIX-3) both landed live, RUN 2 of the trial
finally **applied the coordinated WRITE on both real edges (read-back-verified, exit 0)**
— but the through-the-chain curl returned `400 "Client sent an HTTP request to an HTTPS
server"`, a THIRD live-only gap: the FRONT forward was rendered as a **bare HTTP
`reverse_proxy` to the downstream's `:443`** — no upstream TLS, no Host. The real home
edge is HTTPS, so the front terminated the client's TLS and then spoke plain HTTP to a
TLS listener. The real working VPS forward routes carry `transport {protocol:http,
tls:{insecure_skip_verify, server_name:{http.request.host}}}` + a request
`Host:{http.request.host}`. Root cause spanned two layers: `chain_write.forwardRoute`
set the model's `ServerName` but `caddy.go insertRoute` DROPPED it, emitting only
`{handler:reverse_proxy, upstreams:[{dial}]}`. Fixed: `model.Upstream.UpstreamTLS` carries
the intent; `forwardRoute` sets it from the downstream scheme (explicit `downstream_scheme`
wins, else inferred from a `:443` dial); `insertRoute` renders the upstream `transport.tls`
+ `Host` **byte-faithful to the real VPS forward** when set, and the bare `reverse_proxy`
when not; read-back parses `transport.tls` so the forward's TLS hop round-trips and
`verify` asserts every TLS-planned forward reads it back (the front-leg analogue of the
auth read-back — a dropped-TLS render fails the transaction and rolls back). A
request-time 400 can't be reproduced against a static fake (it never opens a TLS socket),
so the tests assert the rendered shape STRUCTURALLY (transport.tls + server_name + Host)
against the real VPS forward, plus a plain-HTTP control that stays bare. Tests:
`caddy/nested_tls_forward_test.go` (HTTPS forward renders TLS nested in the wildcard
subroute + reads back `UpstreamTLS`; plain-HTTP stays bare), `core/chain_write_test.go`
(`TestChainWrite_FrontForwardTLSAndAuthRoundTrips` — full `--auth authelia` produces the
TLS-correct front forward + valid-auth home terminal, both verified, unexpose restores
both edges byte-for-byte; `TestChainWrite_ForwardTLSReadBackFailureRollsBack` — the
load-bearing guard), `core/chain_write_tls_test.go` (the scheme-inference matrix).
**The live cross-chain trial with `--auth authelia` has RUN:** the chain-write reruns drove the
literal `302 → auth.homelab.example` (TRIAL-RESULT-chain-write-2026-06-28.md), and the coordinated
auth-gated write is now proven at production scale by the `finances.homelab.example` full-chain
expose (2026-06-30 — docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md §3). See docs/internal/DESIGN.md "Cross-chain
coordinated WRITE → Front-leg upstream TLS" and docs/internal/AUTH-DESIGN.md §2.1.

### 5e. TRANSPORT — the pluggable connection axis (HOW Crenel reaches an admin API)

Before this, Crenel had exactly one way to reach an admin API — "open an HTTP client to
a configured `admin_url`" — and any plumbing (SSH tunnels) was the operator's
out-of-band problem. That was an implicit, hardcoded **fourth axis** and a hard wall:
the maintainer's home Caddy admin binds **container-localhost only and is not published**, so no
host could open an HTTP client to it (the chain-write trial's gating finding). TRANSPORT
makes connection a first-class, pluggable port alongside EdgeProvider / DNSProvider /
OriginResolver. Each increment is impl + tests, every commit green under `go build
./... && go vet ./... && go test -race`.

| # | Item | What changed | Property |
|---|---|---|---|
| **port + direct** | **`ports.Transport` + Direct behind the Caddy driver** | New `ports.Transport` (`Do(ctx, method, path, contentType, body) → status, body, err`). The driver's single admin-call seam (`doAdmin`) delegates the WIRE call to a transport; the per-op timeout + wedge classification stay ABOVE the seam, so never-hang + `ErrAdminUnresponsive` hold for EVERY transport (no import cycle). `direct` = today's net/http client moved verbatim behind the port; `caddy.New` builds it by default. | **Zero behavior change:** every admin_url/fake config behaves byte-for-byte as before (whole suite green unchanged). |
| **ssh-exec** | **Nested-exec curl to a loopback admin** | Run the admin call as a COMMAND on the far end (`ssh → pct exec → docker exec → sh`). The exec PREFIX is operator argv Crenel does NOT shell-parse; Crenel feeds a generated POSIX-sh curl/wget script over STDIN (nothing crosses a shell-parse boundary — quoting survives arbitrary nesting), body base64-embedded, status via `curl -w`. Three-way error class: admin-non-2xx (status+nil) / transport-unreachable (`ErrTransportUnreachable`+stderr) / wedge-timeout (wraps `DeadlineExceeded`). `Runner` seam (default OSRunner). | Reaches a loopback-only, **UNPUBLISHED** admin with **no port and no tunnel**. |
| **ssh-tunnel** | **crenel-managed local forward** | Open an ephemeral `ssh -N -L` as a managed child (Crenel owns the lifecycle), then talk Direct over the forward; opens lazily, closed on the cmd cleanup chain, reusable. `Forwarder` seam (default OSForwarder). | Automates the manual Option-A tunnel; no `ssh -fN` left running. |
| **wiring** | **`transport` config block** | Per-edge `transport` (type + params) on Settings + EdgeSettings; `buildTransport` at cmd selects the channel; ssh-tunnel registers its Close. **Back-compat:** absent / `direct` ⟹ the driver's default Direct-to-`admin_url`. Single/multi/chain configs unchanged. | Connection is declared config, not out-of-band plumbing. |

**Tests (all green, race-clean):** hermetic fake-Runner/fake-Forwarder tests assert the
exact generated argv + curl/wget script, GET/POST/PUT/DELETE/PATCH parsing, the
three-way error classification, and the open-once/use/close tunnel lifecycle; a
**guarded** integration tier runs REAL `sh`+`curl` against an in-process caddy fake
(driver + cmd wiring); and a **mixed-transport** chain-write test exercises the full
P4-write transaction with **front=direct, home=ssh-exec** end to end (expose lands
front-forward + downstream-real-backend+auth + DNS in order, read-back-verified;
unexpose reverses) — the exact trial shape, against fakes. No live infra in any test;
the guarded tier self-skips if `sh`/`curl`/`base64` are absent.

**LIVE READ-ONLY verification (no mutation):** configured ssh-exec for the maintainer's HOME edge
(`["ssh","root@pve1","pct","exec","113","--","docker","exec","-i","caddy","sh"]` →
curl `http://127.0.0.1:2019`) and ran `crenel status` + a read-only `preview` through
it. Crenel read the home edge's **live** config — **51 services, default-deny
ENFORCED** — with the admin still **container-loopback-only** (nothing published, no
tunnel) and the live config **sha256 byte-identical before/after**
(`174d1d92…`, matching the chain-write trial's HOME backup anchor). Capture (gitignored):
`live-backup/transport-sshexec-readonly-<TS>/`. Example: `examples/settings-transport-sshexec.json`.

**Boundary (honest):** OSForwarder (real `ssh -N -L`) and OSRunner are NEVER exercised
by the test suite (seams are faked) — the live read-only run above is the only real
exercise of OSRunner, and a real ssh-tunnel open against live infra is untested by
design. ssh-exec **wget** supports GET reads only (BusyBox far ends can't report the
HTTP status — success⟹200, failure⟹unreachable); use curl (the default; present on both
real edges) for writes. The live cross-chain WRITE trial can now run OVER ssh-exec — no
home-admin publish, no manual tunnel (TRIAL-PLAN-chain-write.md §0).

### 5f. SECURITY — threat model + field-level secret redaction

A security-hardening pass that **formalizes** the security posture (SECURITY.md) and
**hardens** the secret-leak surfaces (`internal/redact`). The motivating fact: Crenel
reads/writes the FULL edge config, which can carry real secrets (Cloudflare DNS-01
tokens, ACME account keys/email, basic-auth hashes, forward-auth secrets), plus
Crenel's own push token + operator backups. Each item is impl/doc + tests, every
commit green under `go build ./... && go vet ./... && go test -race`.

| # | Item | What changed | Property |
|---|---|---|---|
| **threat-model** | **SECURITY.md** | Sensitive-data inventory (secrets in a managed edge config + Crenel's token/backup files); trust boundaries + the loopback-first transport model (admin API is plaintext+unauthenticated → MUST stay loopback; `direct` on-box, `ssh-exec`/`ssh-tunnel` keep config inside SSH; network-exposing the admin is THE anti-pattern); what Crenel persists vs not; a per-boundary adversary table (local host / SSH channel / loopback admin / git remote / Crenel's own output); residual risks (operator SSH/known_hosts, backups hold real secrets, on-demand operator trust, best-effort redaction on unmodeled bytes); operator checklist. | The security posture is documented + honest, not implicit. |
| **redact pkg** | **`internal/redact`** (leaf) | A value-aware masker: conservative KEY match (`token`/`secret`/`password`/`api_key`/`private_key`/`email`/… — NOT bare `key`) + VALUE heuristics (PEM private keys, bcrypt/argon hashes, JWTs, `Bearer`/`Basic` auth-scheme creds). `JSON()` walks structurally preserving non-secret routing fields; `Text()`/`Snippet()` handle truncated/invalid JSON. Masks long→`••••<last4>`, short→`REDACTED`. Imports nothing of ours (dependency rule intact). | A reusable, conservative redactor that prefers over-masking. |
| **output wiring** | **Redaction at the CLI boundary only** | `status --json` `Unparsed.RawExcerpt` (the P0 declared-unknown excerpts can carry secret bytes — an nginx auth header/hash); admin-API error echoes (a Caddy `/load` rejection echoes the offending config); rollback-error prints; `export --redacted`. All gated by `--show-secrets` (default off). core/drivers stay real-valued, so the apply path is structurally unable to see a masked value. | Secrets don't leak into printed/exported/error output; the operator can still opt into raw. |
| **export/backup** | **`0600` + `--redacted`** | exports written `0600` (was `0644`; a snapshot can hold real secrets); `export --redacted` writes a secret-free copy for sharing; the export snapshot now also records each edge's declared-unknowns (faithful coverage). The restore-grade backup keeps REAL bytes (a redacted backup isn't restorable). | Backups are operator-only; a shareable scrub exists; restore stays correct. |

**The explicit guarantee (tested both ways):** redaction is OUTPUT-only. Each surface
masks by default and `--show-secrets` reveals; AND a granular `expose` performed
alongside an unmanaged basic-auth route leaves that route's secret **byte-intact** in
live config — proving the apply / read-back-verify / preserve-unmanaged paths use REAL
values. **Boundary (honest):** redaction is best-effort on bytes Crenel did not model
(a secret under an innocuous key with no value-heuristic match could slip into an
excerpt); it is conservative-by-design but not a guarantee for unmodeled shapes, and
it never affects correctness (apply/verify never redact). caddy's own `RawExcerpt`
re-marshals TYPED structs (so a stray token in an unmodeled handler field is dropped,
not leaked); the live-text leak surfaces are nginx excerpts, `LiveEdgeState.Raw` (kept
internal, not surfaced), and admin-body error echoes — all redacted. See SECURITY.md.

### 5g. DURABLE-PERSIST — the persistence model + the durable home-edge reconciler

The milestone that makes a home-edge write SURVIVE a restart. The home Caddy boots from
`/etc/caddy/Caddyfile` (`--adapter caddyfile`, **no `--resume`**; read-only-verified live
via `docker inspect`), so admin-API writes are EPHEMERAL — fine for read/trial, but it
BLOCKS the flagship rename/move use case (`archive → files.homelab.example`), which must
survive a restart. Each item is impl + tests, every commit green under `go build && go vet
&& go test -race`. Lands on branch `feat/durable-home-persist`.

| # | Item | What changed | Property |
|---|---|---|---|
| **model** | **Persistence as a detect-and-declare property** | `model.PersistenceModel` (durable-config/durable-file/resume/ephemeral-admin/unknown) on `LiveEdgeState`, set per-edge by the driver (caddy: durable-file when a persist path is configured, resume/durable declarable, else **ephemeral-admin** — the safe default; traefik/nginx: durable-config). The admin API carries NO boot-source marker, so it is DECLARED, never inferred. | "Will this write survive a restart?" is first-class, never assumed durable. |
| **surface** | **status / audit / write-path** | status `Durability:` line (ephemeral edges flagged); audit `ephemeral_writes` warning when an ephemeral edge actually holds crenel-managed routes; `ports.DurabilityReporter` → a `PersistWarning` when a verified write lands on an ephemeral edge. | A live-but-ephemeral write is never silently trusted (the DURABILITY MISREAD). |
| **reconciler** | **Durable wildcard-site Caddyfile reconcile** | `caddy/persist_caddyfile.go` + `caddyfile_edit.go`: a managed host's durable form is a per-host `@crenel_<host> host …` + `handle { [import <snippet>] reverse_proxy … }` INSIDE the covering `*.zone` site (inheriting its TLS — the flat persister's top-level `host {}` would SHADOW the wildcard and lose its cert config). Pipeline: partition by zone (refuse an operator-owned host) → render → **self-check** (parse the region back == managed routes) → `caddy validate` → **`caddy adapt` cross-check** (the candidate re-adapts to the live managed backend+auth) → write host file + reload. A bad candidate never touches the live boot file. | The on-disk config is a re-adaptation-VERIFIED mirror of live (no second SOT); a managed write reproduces on restart, byte-faithful to the operator's file. |
| **wiring** | **Two-channel exec seams + config** | `ConfigStore`/`Adapter` seams (+ `CaddyCLI`): local FS + `OSAdapter` on-box; `ExecConfigStore`/`ExecCaddyCLI`/`ExecAdapter` (transport-Runner-backed) for the home edge's TWO channels — file→LXC host (`/opt/stacks/caddy/conf/Caddyfile`, ro-mounted), caddy→container. Config block `caddy_persist` (`examples/settings-durable-home.json`). | The reconcile is identical whether the boot file is local or one `pct exec` away. |

**Tests (all green, race-clean):** a FAITHFUL fake adapter (adapts the candidate via the
same parse primitives real caddy exercises; a `drop=host` variant proves the re-adaptation
refuse-and-restore); reconcile-into-wildcard (operator preserved byte-for-byte, NO shadow
site, idempotent), unexpose clears the region, operator-owned host refused; edit-primitive
units (brace/comment-aware site scan, single-label coverage, merge round-trip + clear,
upstream-TLS round-trip); hermetic fake-Runner exec-seam tests (exact argv + sh script);
config decode + wire-to-durable-file. **Boundary (honest):** the REAL exec (OSRunner/
OSAdapter against live infra) is never run by the suite — like the transport's OSRunner/
OSForwarder, the live durable WRITE is the only real exercise and was a separate, GO-gated
trial (**TRIAL-PLAN-durable-persist.md**), **now RUN and PROVEN** (see below); the reconciler targets the wildcard-site +
flat-greenfield shapes (a JSON-boot or `--resume` edge is declared, not reconciled); an
in-place adopt of an operator-owned host into the Crenel region is a follow-on.

**LIVE TRIAL + TRIAL-FIX-DURABLE-1 (2026-06-28).** The durable WRITE was run live on the
home edge (option A): durable EXPOSE + **restart-survival PROVEN** — after `docker restart
caddy` the throwaway host still served its backend (it came from the Caddyfile, not
ephemeral admin); production restored byte-for-byte (TRIAL-RESULT-durable-persist-2026-06-28.md).
The trial found that durable UNEXPOSE rolled back: the persist reload re-derives the live
route from the Caddyfile WITHOUT a JSON `@id`, so delete-by-`@id` is a no-op (failed SAFE —
clean rollback). **TRIAL-FIX-DURABLE-1 (commit `81ef895`)** fixes it: (1) durable-edge
unexpose deletes by **host-match** (locate the route flat or nested in the covering wildcard
subroute, delete by config path), gated to durable-file edges + short-circuited when the
`@id` delete sufficed (non-durable behavior + never-hang wedge model byte-unchanged); (2)
the pre-flight drift check is folded into the reconciler as a **no-drift-loss gate** (every
live host must be reproduced by the candidate's adaptation, else refuse — a live-only
admin-drift route can never be clobbered by the reload); (3) caddyfake gained faithful
DELETE-by-config-path. A fake modelling the post-reload `@id`-less nested route reproduces
the rollback (RED with the sweep off, GREEN on). 318 test funcs, race-clean. The full
expose→restart→unexpose cycle re-trial was then **RUN and PASSED end-to-end on the real home
edge** — unexpose VERIFIED and removed (no rollback, no manual restore), Caddyfile returned to
the byte-for-byte anchor BY CRENEL (TRIAL-RESULT-durable-persist-2026-06-28.md §8). Durable
persist — expose, restart-survival, AND unexpose — is proven end-to-end on production.

### 5h. KNOWN-RISK BURNDOWN — read/verify-side correctness (off v0.2.0)

A burndown pass over the known-risk backlog toward a trustworthy release. Each item is a
read-side normalize/detection or verify-side correctness fix, unit-tested with a
LIVE-FAITHFUL fake that reproduces the real-world shape — no live production. Every commit
green under `go build ./... && go vet ./... && go test -race -count=1 ./...`. Lands on
branch `feat/known-risk-burndown`.

| # | Item | What was WRONG → the fix | Safety property closed |
|---|---|---|---|
| **A** | **Caddy path/non-host matcher** | The Caddy matcher decoder modeled only `host` (`type Match{ Host []string }`), so a route matched on `host + path` (or method/header/query) decoded as a bare host match and `collectLeaves` emitted a confident `host → backend` route — the path constraint SILENTLY DROPPED (a host split across `/admin/*`+`/*` read as one fully-exposed host; auth/exposure wrong). Fix: `Match` CAPTURES non-host matcher keys (`Extra`, round-tripped for the excerpt); `collectLeaves` DECLARES a non-host-matched route `matcher_conditional`. | A path/method/header-scoped route is no longer read as a plain host route; deny DOWNGRADES to UNKNOWN, never falsely ENFORCED. No cry-wolf (Crenel's own routes + the auth gate's nested match are host-only/opaque). |
| **C** | **Traefik + nginx path detect** | Same class: Traefik `parseHosts` emitted one route per `Host()` host, IGNORING a co-present `&& PathPrefix()`/`&& Method()`; nginx `classify` matched the FIRST `proxy_pass`, collapsing a vhost split across `location /api`+`location /app`. Fix: Traefik `nonHostPredicates(rule)` (host-family-aware) and nginx `proxyLocationPaths` (brace-aware, excluding the `auth_request` subrequest location) DECLARE a path/method-scoped route `matcher_conditional`. | Cross-driver path-granularity DETECT-and-declare complete (Caddy + Traefik + nginx). No cry-wolf on host-only renders or a brownfield forward-auth vhost. |
| **B** | **Declarative-apply auth read-back** | `verifyDeclarative` asserted reachability + deny + prune but NOT auth, so `apply <file>` with `auth:` could render a route that silently dropped the policy, read back reachable, verify GREEN, and publish UNPROTECTED (expose + reconcile already re-asserted auth via `verifyEdgeAuth`). Fix: `verifyDeclarative` runs `verifyEdgeAuth` + `verifyEdgeForwardTLS` over the routes the plan ADDS (parity with the primary path); a drop fails verification and rolls back all-or-nothing. | The auth read-back now covers ALL mutate paths (expose, reconcile, declarative apply) — closes backlog item 5. |
| **D** | **Per-host tunnel ingress (cloudflared)** | P3 flagged a tunnel-fronted edge externally-reachable only at EDGE granularity ("public/private UNKNOWN"). Fix: `tunnelIngressHosts` reads a cloudflared config's OWN `ingress:` rules to resolve each host by OBSERVATION — `ingress_public_hosts` (named observed-public served hosts), `tunnel_route_without_edge` (a published hostname NO edge serves — previously invisible), and tunnel-public folded into `public_without_auth`. Coarse declared-unknown kept as the safe fallback for an unparseable/Tailscale ingress. | The "real per-host public/private from the tunnel's own rules" CORRECT-ness step (the P3 remainder) — for cloudflared. Tailscale serve.json per-host is the documented follow-on (stays coarse/safe). |

**Net:** the worst class in this backlog — an ACTIVE silent MISREAD-↓ (path-granular routing
read as host-granular, contradicting bounded-honesty) — is closed across all three data-plane
drivers; the auth read-back is now uniform across every mutate path; and tunnel ingress is
per-host OBSERVED for the dominant (cloudflared) case. Anything still not fully modeled
(full path MODELING, Tailscale per-host) remains **safe-by-default / declared-unknown** — the
detect-and-declare invariant holds. **No live trial required** to trust any of these: each is
validated by a faithful fake that rejects/behaves like the real system. RED→GREEN tests:
`caddy/path_matcher_test.go`, `traefik/path_matcher_test.go`, `nginx/path_matcher_test.go`,
`core/declarative_auth_verify_test.go`, `core/ingress_perhost_test.go`.

### 5i. OFFLINE-CORRECTNESS PHASE — DNS hardening + wildcard awareness + Tailscale per-host

A second, capstone burndown over the DNS and per-host ingress correctness gaps the
roadmap had identified. **Seven PRs (#11–#17) merged to develop**, each landed with
RED→GREEN tests, an adversarial-neuter RED proof, and **no live edge/DNS touched**. The
faithful fakes (`cfapifake` for Cloudflare REST; `adguardfake` for AdGuard control API;
the on-disk ingress files for cloudflared / Tailscale serve.json) reproduce the real-
world failure shape, so each fix is rigorously verified offline.

| PR | What was WRONG → the fix | Safety property closed |
|---|---|---|
| **#11 — surgical Cloudflare** | The only Cloudflare apply mode was whole-zone `dnscontrol push`, fundamentally unsafe for a shared zone. Fix: `apply_mode: surgical` drives the Cloudflare REST API per-record; the ownership marker `managed-by:crenel host=<name>` is the safety boundary; mutate primitives REFUSE any record lacking it. **LIVE-PROVEN on `crenel.sh`** with foreign records BYTE-IDENTICAL across expose/unexpose. | Mixed/shared-zone management gains a non-destructive path that physically cannot touch a foreign record. |
| **#12 — dual-AdGuard split-horizon** | A homelab running TWO AdGuard resolvers (one per vantage) had no per-instance attribution — both rendered as a bare `adguard` in every plan/apply/verify label and in the conflict/guard error text. And a cross-resolver coverage gap (e.g. `adguard.homelab.example` present on VPS, missing from home) was invisible. Fix: `adguard.Config.Instance` woven into `Driver.Name()` → `adguard[home]`/`adguard[vps]`; new `dns_coverage_parity` audit compares live host sets across `scope:internal` providers and surfaces present/missing-on-which-resolver. | The split-horizon shape is now distinguishable AND its coverage drift is a first-class audit finding. |
| **#13 — `dns_value_drift` for owned records** | The audit's cross-provider DNS checks were host-NAME-only: a crenel-OWNED record whose live *value* drifted from the configured target read fully clean (right name, WRONG target — a silent misdirect; on a public record, internet traffic to the wrong place). Fix: audit value-checks each owned record against `DesiredRecords` and flags a mismatch (CRITICAL for public; warning for internal). Scoped via the optional `ports.OwnedRecordReporter` capability — surgical Cloudflare opts in; marker-less AdGuard deliberately does NOT. | Silent target-value misdirect on owned records is now detected. |
| **#14 — `DriftValueDNS` correction by reconcile** | The audit *detected* owned-record value drift, but `reconcile` (the detect-and-fix-ALL verb) still matched records by `Key()` = scope/type/NAME only — a wrong-target record read as "converged" and was left silently misdirecting. Fix: reconcile compares the live value of an OWNED record against the desired target and emits a corrective UPDATE; the surgical Apply turns it into an in-place update (marker preserved); value-aware read-back verifies. | Audit/reconcile asymmetry on owned-record value drift closed. |
| **#15 — wildcard-aware `dns_coverage_parity`** | Cry-wolf on the very feature #13 just shipped: a `*.homelab.example` rewrite came through `LiveRecords` as a literal name and double-fired — wildcard pattern itself flagged "missing", AND every explicit host the other resolver carries that the wildcard already covered flagged as drift. Fix: union built from EXPLICIT names only; a host is PRESENT on resolver R if either explicit or a wildcard there covers it. Value-mismatch guard preserves real drift: covering `*.zone`→B vs explicit `host`→A (B ≠ A) is still flagged with a value-aware message. | Parity check is now correct on the dominant homelab shape (per-vantage wildcard + per-host explicit). |
| **#16 — wildcard-aware sibling DNS-vs-edge checks** | Same cry-wolf class on the siblings: `dns_without_edge_route` flagged every wildcard as "dangling" (no edge route literally named `*.zone`), and `edge_route_without_dns` flagged a host backed only by a covering wildcard as "exposed but no DNS record". Fix: a wildcard is treated as a CATCH-ALL — `dns_without_edge_route` no longer flags a wildcard whose zone has at least one exposed host (still flags one whose zone has nothing exposed); `edge_route_without_dns` treats a host as reachable by name when any wildcard covers it. | Both DNS-vs-edge checks are now correct on a single-wildcard catch-all zone (the AdGuard default for a home setup). |
| **#17 — Tailscale serve.json per-host (funnel) + per-edge authoritative public** | Last open P3 silent-miss + cry-wolf pair. (a) A funnel host published in serve.json that no edge route serves was an INVISIBLE `tunnel_route_without_edge`. (b) Funnel-published hosts the edge DID serve got no positive `ingress_public_hosts` surfacing. (c) Symmetric cry-wolf: a tailnet-only `Web` entry (no `AllowFunnel`) was falsely flagged `public_without_auth` whenever no public DNS was managed, because the conservative `exposed → public` default fired on an identity-enforced host. Fix: parse `serve.json` `AllowFunnel` keys (port stripped from `host:port`) as the public set; the conservative default is now per-edge AUTHORITATIVE — a host on an edge with parsed per-host recovery contributes "public via this edge" ONLY via the recovery. | The last open offline-provable silent-miss + cry-wolf pair on the ingress-modeling axis. |
| **#22 — wildcard-aware `reconcile` / `drift`** | The drift-verb sibling of #15/#16 that dogfooding surfaced on the live home resolver. `reconcile`'s DNS drift checks matched by NAME only, so a live `*.homelab.example` wildcard silently read TWO ways wrong: (a) `missing_dns_record` fired on every exposed host under the wildcard's zone, because the desired explicit key was absent in live — reconcile would have ADDED an explicit record on top of the already-answering wildcard; (b) `stale_dns_record` fired on the wildcard itself (never a canonical host), so reconcile would have DELETED the load-bearing `*.homelab.example`. Fix: a live wildcard whose value equals the desired target counts as coverage (no `missing_dns_record`); a wildcard whose value differs STILL flags (real mis-answer — an explicit record is needed to override); wildcards are categorically excluded from stale removal (Crenel does not own operator wildcards). | Drift/reconcile now correct on the AdGuard-catch-all shape — the destructive `*.homelab.example` deletion path is closed. |

**Net:** the offline-provable silently-wrong gaps the roadmap had identified are
closed. The detect-and-declare invariant still holds for everything past this line —
items in §6.z buckets B/C read as declared unknowns, not confident wrong answers.

## 6. Prioritized remaining backlog

Pulled from the register's roadmap (§5) + what this pass surfaced. Ordered by
(prevalence × danger) ÷ cost, safety-first.

1. ~~**P1.5 — Caddy sibling `http.servers` → `UnknownServerBlock`**~~ **DONE (§5a).**
2. ~~**P2 (finish) — generator detection: caddy-docker-proxy + Pangolin.**~~ **DONE
   (§5a).** Pangolin → Traefik `badger`-middleware signature; CDP → on-disk
   `Caddyfile.autosave` (`caddy_generator_config_path`) or a declared `caddy_generator`
   hint (the admin API has no CDP marker — documented boundary). NPM + Traefik-labels
   were already done.
3. **P3 — tunnel/overlay ingress modeling** (cloudflared, Tailscale funnel/serve):
   ✅ **DETECTION + SURFACING DONE (§5a)** + ✅ **PER-HOST RECOVERY for cloudflared (§5h)
   AND Tailscale funnel (§5i) DONE** — the tunnel's own ingress rules are parsed to
   recover the real per-host public mapping by observation
   (`ingress_public_hosts`/`tunnel_route_without_edge`, folded into
   `public_without_auth`). **Remaining:** none of correctness consequence — a tailnet-only
   Tailscale `Web` entry (no `AllowFunnel`) is identity-enforced by the tailnet ACL and
   deliberately left out of the public set (modeling it would require a separate
   mesh-scope axis that is outside this gap).
4. ~~**P4 — chain / downstream-auth model.**~~ **READ-CORRECTNESS (§5a/§5c) + COORDINATED
   WRITE (§5d) DONE.** The `auth_downstream` flag is promoted to a first-class, OBSERVED
   chain (`downstream_edge` + `model.ChainLink` + follow-through; auth by observation),
   AND a single `expose`/`unexpose`/`reconcile` now lands/tears the coordinated
   front-forward + downstream-route + DNS as one ordered, read-back-verified,
   all-or-nothing transaction (auth attaches downstream; gate spans both edges).
   ~~A live cross-chain write trial~~ **DONE** — the coordinated auth-gated write is
   proven at production scale (§5c/§5d; docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md §3).
   **Remaining (follow-on):** chain `Adopt` of a pre-existing forward; an `auth: app`
   annotation for in-app auth.
5. ~~**Read-back-verify auth on the apply/declarative paths**~~ **DONE (§5h).** `verifyDeclarative`
   now runs `verifyEdgeAuth` + `verifyEdgeForwardTLS` over the routes it adds — the auth
   read-back is uniform across expose, reconcile, AND declarative apply.
6. **P5 — sub-host route granularity** (`Route.PathPrefix`, per-path backend+auth):
   unlocks path/header/method routing and per-path auth. **A path-scoped route is now
   DETECTED + declared `matcher_conditional` (§5h) — no longer silently misread** — so this
   item is now purely the MODELING follow-on (representing + writing per-path routes), not a
   safety gap. (This is the one item whose eventual WRITE support would warrant a gated live
   trial; the read-side detect-and-declare needs none.)
7. **P6 — long tail:** multi-zone edge (`zones []`), HA/VIP, TLS-terminated-
   downstream, Traefik KV provider, k8s ingress (likely a separate driver / explicit
   decline), ~~DNS record *value* drift~~ **DETECTED for crenel-OWNED records (`dns_value_drift`
   audit finding) — see below**, nginx managed-block full-fidelity re-render (F6).

**DNS target-value drift — DONE for owned records (audit `dns_value_drift`).** The audit's
cross-provider checks were host-NAME-only: a crenel-owned record whose live *value* drifted
from the configured edge target read fully clean (right name, WRONG target — a silent
misdirect; on a public record, internet traffic to the wrong place). Audit now value-checks
each owned record against `DesiredRecords` and flags a mismatch (`dns_value_drift`: **critical**
for public scope, **warning** for internal). Scoped via the optional `ports.OwnedRecordReporter`
capability — implemented by the surgical Cloudflare driver (its `LiveRecords` is marker-filtered,
so every record it reports is provably Crenel's) and **deliberately NOT** by the marker-less
AdGuard driver (an AdGuard rewrite carries no ownership marker, so a value check there would
cry wolf on the operator's legitimately-foreign rewrites). RED→GREEN with the faithful
`cfapifake`; the foreign-value-on-a-marker-less-provider case proves no cry-wolf. **Remaining:**
value drift for whole-zone/dedicated providers and any future ownable AdGuard provenance.

**DNS value drift — now also CORRECTED by `reconcile` (`wrong_dns_target` / `DriftValueDNS`).** The
audit *detected* owned-record value drift, but `reconcile` (the detect-and-fix-ALL verb) still
**matched records by `Key()` = scope/type/NAME only**, so a wrong-target record read as "converged"
and was left silently misdirecting — the fix command was value-blind on the exact thing it exists to
fix. Reconcile now compares the live value of an OWNED record (same `ports.OwnedRecordReporter` gate —
surgical Cloudflare; never marker-less AdGuard) against the desired target and emits a corrective
UPDATE when it drifted; the surgical Apply turns the re-added record into an in-place update (marker
preserved) and the value-aware read-back verifies it. RED→GREEN with `cfapifake` (owned drift
detected+corrected) + a marker-less no-cry-wolf case. Closes the audit/reconcile asymmetry (audit
flagged it, reconcile ignored it).

**Sibling DNS-vs-edge checks (`dns_without_edge_route`, `edge_route_without_dns`) are now
WILDCARD-AWARE too — finishes the cleanup from the parity work.** The two name-only checks
that flank the parity audit had the same cry-wolf class as parity did before #15: a
`*.homelab.example` rewrite always read as a "dangling record" (no edge literally named
`*.zone`), and an exposed host backed ONLY by the catch-all wildcard read as "exposed but no
DNS record" (the wildcard's literal name doesn't match the host). Fix: a wildcard is a
CATCH-ALL pattern, not a host. (a) `dns_without_edge_route` no longer flags a wildcard whose
zone has at least one exposed host (it's backing intent, not dangling) — but still flags a
wildcard whose zone has NOTHING exposed (real misdirect; critical for public, matching the
explicit case). (b) `edge_route_without_dns` treats a host as reachable by name when any
wildcard covers it. Suppression is name-only — value correctness stays the job of per-provider
desired-vs-live read-back and (for owned records) `dns_value_drift` / `DriftValueDNS`. 8 new
tests RED→GREEN with the stub `LiveRecords` (covering-wildcard + truly-dangling-wildcard +
public-dangling-critical + explicit-still-precedence + out-of-zone-still-flags) + an
end-to-end through the real AdGuard driver over the faithful fake. Adversarial RED proof:
neutering both suppressions reproduces the exact "dangling pattern" + "exposed but not
reachable by name" cry-wolves on the wildcard-covered cases. No live edge/DNS touched.

**Tailscale serve.json per-host (funnel) recovery — closes the last open P3 silent
miss + cry-wolf pair (§5i).** The cloudflared per-host recovery (§5h) already promoted
the dangling-tunnel and `ingress_public_hosts` checks from "edge UNKNOWN" to per-host
observation; the Tailscale path stayed coarse. That silently masked three real
correctness gaps on any Tailscale-funnel edge: (a) a funnel host published in
`serve.json` that NO edge route serves was an INVISIBLE `tunnel_route_without_edge`,
(b) the operator never saw the positive `ingress_public_hosts` surfacing for the
funnel-published hosts they DID serve, and (c) — symmetric to (a) — a tailnet-only
`Web` entry (no `AllowFunnel`) was CRY-WOLFED as `public_without_auth` whenever no
public DNS was managed, because the conservative "edge IS the public boundary"
default fired on a host that is identity-enforced by the tailnet, not internet-public.
Fix: `tunnelIngressHosts` now parses Tailscale `serve.json` and returns the
`AllowFunnel` keys (port stripped from `host:port`) as the public set — tailnet-only
`Web` entries are deliberately NOT returned. AND the conservative `exposed → public`
default is now per-edge AUTHORITATIVE: a host on an edge with parsed per-host recovery
contributes "public via this edge" ONLY via the recovery (additive `tunnelPublic`);
a host on an edge WITHOUT parsed recovery (plain, declared-only external, or
unparseable) still falls back to `exposed → public` so safe-by-default is preserved.
5 RED→GREEN tests (funnel host with no auth fires `public_without_auth`; funnel host
fires `ingress_public_hosts`; dangling funnel fires `tunnel_route_without_edge`;
tailnet-only `Web` is NOT claimed public via any code; `host:port` port-stripping).
Adversarial RED proof: neutering the Tailscale parser to `parsed=false` reproduces
all three silent misses (no `ingress_public_hosts`, no dangling finding, Web-only
host falsely claimed public_without_auth). No live edge touched.

**`dns_coverage_parity` is now WILDCARD-AWARE — kills the cry-wolf on the very feature `dns_value_drift`
just shipped.** The dual-AdGuard parity check diffed live host *sets*, but a wildcard rewrite like
`*.homelab.example` came through `LiveRecords` as a literal name and double-fired: the audit flagged
the wildcard pattern itself as "missing on the other resolver" AND flagged every explicit host the
other resolver carries (e.g. `adguard.homelab.example`) that the wildcard *already covered*. Same name
Crenel just shipped `dns_value_drift` and `DriftValueDNS` for, cry-wolfed in the very next audit run.
Fix: the union compared is built from EXPLICIT names only (wildcards are patterns, not hosts), and a
host `h` is treated as PRESENT on resolver `R` if either it has an explicit rewrite OR a wildcard on
`R` covers it (`*.zone` suffix-matches any name ending in `.zone`). **Value-mismatch guard (do NOT
hide real drift)**: wildcard substitution is only treated as parity-clean when the wildcard's answer
matches an explicit value for `h` elsewhere — explicit `host`→A on `R1` vs covering `*.zone`→B on
`R2` (with B ≠ A) is still flagged, with a value-aware message naming the pattern, the wildcard
value, and each resolver's explicit value. The pure vantage case (two explicit entries with
intentionally different vantage targets, no wildcard substitution) is unchanged. RED→GREEN with
stub `LiveRecords` (covering-wildcard at matching value → no finding; wildcard-only-on-one-resolver
literal not in union; value-mismatched wildcard still flagged with a value-aware message; out-of-zone
wildcard does NOT suppress) + a real-AdGuard-driver end-to-end at the matching-value shape over the
faithful fake. Adversarial RED proof: neutering `wildcardCovering` to always return false reproduces
the exact "MISSING from [adguard[home]]" cry-wolf on the bit-us case. No live edge/DNS touched.

### 6.z What's actually left (honest buckets, post-#17 capstone)

After PR #17 the offline-provable silently-wrong gaps the roadmap had identified are
closed. What remains, sorted by what it needs to ship — NOT by priority — so it's
clear at a glance which items are doable offline and which aren't.

**A0. Live trials — now PROVEN (2026-06-28 → 06-30).** The live-only gates the roadmap had
open are closed. Each was run against real infrastructure and reverted (or left as found):
- **Full-chain production expose — `finances.homelab.example` from the home-edge host (2026-06-30, punch-list #1).**
  One Crenel run brought up the whole chain coordinated + read-back-verified — home edge route, VPS
  edge forward/allowlist, both internal AdGuard rewrites, public Cloudflare record — all 7 gates green.
  This is also the **live cross-chain coordinated WRITE on the real home + VPS chain** at production
  scale, on top of the config-level chain-write in TRIAL-RESULT-chain-write-2026-06-28.md.
  (operator-record — **docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md** §3.)
- **Surgical Cloudflare on the shared `homelab.example` zone (2026-06-30).** Only Crenel's marked
  record created; the apex wildcard stayed byte-identical across expose→unexpose; all restored.
  (operator-record — docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md §1.)
- **Dual-AdGuard split-horizon parity (2026-06-30).** Both resolvers driven, restored byte-for-byte;
  `dns_coverage_parity` caught a real divergence live. (operator-record — docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md §2.)
- **Durable-persist write on the home edge (2026-06-28).** Durable expose + restart-survival +
  unexpose, byte-for-byte by Crenel (TRIAL-RESULT-durable-persist-2026-06-28.md).

**A. Live-only — still remaining (need a real edge / creds / a real node — no faithful fake gets there).**
- Tailscale serve.json WRITE support (the read-side is now per-host wildcard-aware; a write path would need a `tailscale serve` exec or local-API integration tested against a real Tailscale node).
- Repeat/scale-hardening of the full-chain expose as the routine daily-driver path (adoption, not a missing capability).

**B. Structural / model-extension (offline-doable but they are NEW MODEL surface, not correctness on existing surface — explicitly NOT silent-wrong gaps).**
- **Marker-less AdGuard value-drift.** AdGuard rewrites are `{domain, answer}` with no per-record metadata field, so Crenel cannot stamp a record-level marker the way the surgical Cloudflare driver does. `dns_value_drift` and `DriftValueDNS` therefore deliberately do NOT run on AdGuard — closing this gap would require either an AdGuard schema extension upstream or a side-channel manifest persisted by Crenel (a stored-desired-state shape that explicitly contradicts the live-state-authoritative invariant). Documented limit, not a fix.
- **Tailnet-scope axis for Tailscale `Web` entries.** A `Web` key without `AllowFunnel` is identity-enforced by the tailnet ACL. PR #17 stops the cry-wolf (it is no longer claimed public) but does NOT introduce a `mesh-scope` route mode for it. Adding one would be a model extension orthogonal to `ModeHTTPProxy`/`ModeTCPPassthrough`/`ModeMeshGrant`.
- **Path-granular route WRITE support** (P5 modeling follow-on). The read side already DETECTS+declares `matcher_conditional` (no silent misread). Representing + writing per-path backend+auth is a model + per-driver render surface, not a safety gap.
- **P6 long tail.** Multi-zone edge (`zones []`), HA/VIP, TLS-terminated-downstream, Traefik KV provider, k8s ingress (likely a separate driver or explicit decline), nginx managed-block full-fidelity re-render (F6). Each is a coverage extension, each currently reads as a declared unknown.
- **chain `Adopt` of a pre-existing forward** + **`auth: app`** annotation for in-app auth. Both are P4-write follow-ons (modeling, not safety).

**C. Doc / launch-readiness — CLOSED (public launch has shipped).**
- ~~`crenelhq` GitHub org status~~ **DONE** — `github.com/crenelhq/crenel` is public and live: `v0.4.0` shipped, an independent audit (2026-07-03) found one MEDIUM (nginx false-ENFORCED, F1 — see §0/CHANGELOG), fixed on `develop` and shipped as `v0.4.1`. CI now runs `go build/vet/test -race` + `gitleaks` on every push/PR.
- ~~`LICENSE` (Apache-2.0) + `NOTICE` + `CONTRIBUTING.md`/DCO~~ **DONE** — all present at repo root.
- ~~`CODE_OF_CONDUCT.md`~~ **DONE** — Contributor Covenant, added alongside this pass.
- ~~the open-core boundary~~ **DONE** — `docs/OPEN-CORE.md`.
- **Still open:** package-name reservations (npm/PyPI/crates — honest applicability: this is a Go binary, so these are placeholder/squat-prevention reservations, not real package manifests) and confirming GitHub Release binary artifacts are actually attached to the `v0.4.0`/`v0.4.1` tags (the `make release` cross-compile target exists; whether its output has been uploaded to a GitHub Release is an operator step, not verifiable from the repo alone).

### Each P2+ item that remains is **safe-by-default today**
because anything unmodeled reads as a declared unknown (refuse/UNKNOWN), not a confident
wrong answer — the whole point of P0. The remaining backlog is "drive coverage toward
100%, but no silent-wrong is being shipped in the meantime."
