# Changelog

All notable changes to Crenel are recorded here. Versioning is informal while
pre-1.0 (`v0.x` = "works, with documented boundaries"). The authoritative
current-state map is [`STATE-OF-CRENEL.md`](STATE-OF-CRENEL.md).

## v0.4.2 — 2026-07-05

Follow-through on the independent audit (2026-07-03): closes three of its four
remaining LOW items, plus the `ack` marker — a real-use feature the audit
didn't ask for but that makes `audit`/`drift` stay clean on a brownfield edge.
All packages green under `-race`, **zero external dependencies**.

- **CI (F5).** A minimal GitHub Actions workflow — `go build`, `go vet`,
  `go test -race`, and `gitleaks` — on every push to `main` and every PR.
  Previously just `go test -race` in the `Makefile` with no automated gate.
- **F2 — verify-honesty gate.** A file-based edge (Traefik/nginx) with no
  runtime probe configured can only re-read its OWN written file — never
  proof the running daemon picked up the change. Every mutating verb
  (`expose`/`unexpose`/`rename`/`resume`/`reconcile`/`apply`) now REFUSES —
  rolling back the write — when that happens, unless `--allow-unverified` is
  passed (or accepted interactively when not running `--yes`). The report
  already said "written; runtime verify unavailable" honestly; now the write
  itself is gated on it instead of standing as an unconfirmed green. Caddy is
  unaffected (its own admin-API re-read already is the live check).
- **F3 — file-lock on the mutating apply path.** Two overlapping
  `expose`/`reconcile`/`apply`/... invocations could interleave their
  read-plan-apply-verify cycles and stomp each other's rollback compensators.
  An exclusive, non-blocking flock (stdlib `syscall.Flock`, no new dependency)
  now serializes every mutating verb; a second overlapping run fails fast
  with a clear message instead of racing the first.
- **The `ack` marker.** Some declared-unknown routes are intentional
  operator-vetted carve-outs (a path scoped by a matcher Crenel doesn't yet
  model), not silent-wrong risks — but until now there was no way to tell
  Crenel that without either living with `UNKNOWN` forever or rewriting the
  config into a shape it understands. `crenel ack <host> --reason <slug>`
  stamps a `crenel-ack:<slug>` marker INTO the live config itself (a Caddy
  `@id`, a Traefik field, an nginx comment — no sidecar store, the same
  pattern the `managed-by:crenel` ownership marker already uses); `audit`/
  `status` show it as its own **ACK** state — never hidden, never blocking
  default-deny — instead of a recurring `UNKNOWN`. Never makes a route
  reachable; that's still only `expose`. Read-side recognition ships across
  Caddy/Traefik/nginx; the `ack`/`unack` write verbs are Caddy-only for now
  (Traefik/nginx recognize a hand-written marker but Crenel can't stamp one
  for them yet — an honest, documented gap, not a silent one). See
  [`docs/design/ack-marker.md`](docs/design/ack-marker.md).
- **Docs.** `STATE-OF-CRENEL.md` refreshed (stale header/SHA, the audit
  record, launch-readiness bucket closed out); `CODE_OF_CONDUCT.md` added
  (Contributor Covenant); `CONTRIBUTING.md`'s stale pre-launch framing fixed.

F4 (reconcile TOCTOU) remains open, documented, low-severity — the one audit
item this release doesn't close.

## v0.4.1 — 2026-07-03

Fixes the one MEDIUM finding from the independent audit below (**F1**): the
nginx read path silently skipped every top-level config chunk that was not a
`server{}` block. A realistic server-less shape — a stock `nginx.conf`
wrapping its vhosts in `http { server {} }`, a stream-only (L4/SNI-passthrough)
config, an include-only main config that delegates everything, or a bare
map/upstream helper file — therefore read as default-deny **ENFORCED with
zero routes and zero warnings**: a false green, not just "degenerate input"
as the audit first estimated.

`normalize` now DECLARES any unrecognized non-server top-level block as an
`Unparsed` (`server_not_read`) entry, so `DenyState()` downgrades to
**UNKNOWN** instead of falsely certifying ENFORCED. A pure comment/blank
chunk is still skipped, so a legitimate bare-`server{}` fragment (servers +
comments only) keeps reading fully-parsed/ENFORCED with its routes intact.
Tests cover all four realistic server-less shapes (each now UNKNOWN), the
comment-only no-cry-wolf case, and a bare-`server{}` ENFORCED regression.

## v0.4.0 — 2026-07-03

Initial public release. `github.com/crenelhq/crenel` goes live — the
correctness phase (M0–M13, P0–P4, DNS hardening, live-proof trials) that
`STATE-OF-CRENEL.md` documents in full, published for the first time.

## v0.3.2 — 2026-06-30

Consolidation release: the experimental Cloudflare DNS hardening from v0.3.1 is now
**proven live, end-to-end, on a dedicated zone** — no code change beyond the hardening
itself, which moves from "shipped + unit-tested" to "validated against the real
`dnscontrol`/Cloudflare path." All packages green under `-race`, **zero external
dependencies**. No production infra was touched (the proof ran on a dedicated `crenel.sh`
zone + a disposable LXC).

**DNS hardening — LIVE-PROVEN on the dedicated `crenel.sh` zone.** The two guards added in
v0.3.1 (`feat/dns-hardening`, merge `30e72ea` / PR #10) ran against the real
`CLOUDFLAREAPI` adapter and the live `dnscontrol 4.42.0` binary:

- **`dedicated_zone` ownership gate** — `preview` showed the diff adds *only* the test
  record and the guard **allows the empty dedicated zone** (no refusal); the lone-wildcard
  shared-zone case stays default-denied.
- **TTL + proxied fidelity** — the exposed record read back `proxied=false`, `ttl=300`, and
  the real `get-zones --format=tsv` **6/7-column + `cloudflare_proxy`** layout parsed
  correctly against the actual binary — confirming the previously-unvalidated CLI contract
  (DNS-DESIGN §8.6/§8.7).
- **Live cycle** — `expose crenel-dnstest.crenel.sh` → `dig` @both Cloudflare authoritative
  NS returns the A → `unexpose` → authoritative **NXDOMAIN**.
- **Idempotency ×2** — re-expose stays a single correct record (no duplicate/drift);
  re-unexpose is an explicit no-op.
- **Cross-provider rollback** — a multi-edge transaction where an edge fails *after* the DNS
  step applies: Crenel **rolls back and re-adds the real Cloudflare record**, restoring the
  prior live state (true atomic inversion across edge + DNS).
- **Fail-safe abort** — a bad-token apply fails its read precondition at plan time and makes
  **zero** mutations ("aborted: no changes applied").

The zone was restored empty and the proving-ground LXC left byte-for-byte as found.

**Still EXPERIMENTAL / opt-in / off by default.** This proves the **dedicated-zone** path.
Managing a record inside a **shared** production zone is still gated behind the
`dedicated_zone` default-deny and needs a future **non-destructive, record-level apply
mode** (a surgical add/remove that never re-asserts the whole zone) before Crenel can drive
a mixed zone safely. See `STATE-OF-CRENEL.md` §0a and `docs/DNS-DESIGN.md` §9.

## v0.3.1 — 2026-06-29

Patch on top of v0.3.0 — a brand/DX point release (the live battlement banner and a
terminal-fit fix), the first **experimental, opt-in** real DNS providers, and a recorded
live stress-test of the v0.3 edge guarantees. All packages green under `-race`, **zero
external dependencies**.

**Brand — the live battlement banner.** `crenel`'s hero surface is now a crenellated WALL:
the crenel gaps are the live exposed hosts in semantic colour (green = verified/private,
amber = about-to-go-public, red = fail-open) standing over the beveled pagga `CRENEL`
wordmark (mint-rim→deep-core tube bevel — depth from character texture, **no drop-shadow**).
It replaces the old drop-shadow primary, is the SAME mark `crenel banner` prints (demo hosts) and `status --hud` prints (LIVE hosts), and is byte-faithful to the approved still.

**Banner fits narrow terminals + centred Crenel labels.** The hero wall is 121 cols wide at
its demo hosts and used to wrap/garble on any narrower terminal; it now scales down to a
compact fallback (shrunk wordmark, a role-coloured glyph per Crenel, host labels stacked
below) so nothing wraps at 80/100/110 cols, while the full mark stays byte-identical at full
width. The between-merlon host label is now vertically centred in its crenel notch (it used to
float on one row of a taller battlement and read sparse).

**DNS-for-real providers — EXPERIMENTAL, opt-in, OFF BY DEFAULT, live-trial pending.** Crenel
can now drive **real** split-horizon DNS as part of an edge `expose`/`unexpose`: the **public**
record via **Cloudflare** (through the existing dnscontrol `CLOUDFLAREAPI` adapter) and the
**internal** resolver view via a new native **AdGuard Home** rewrite driver — one coordinated,
read-back-verified change. **Safety posture, stated plainly:** DNS is opt-in — `dns.enabled`
is `false` by default and the provider `type` defaults to **mock** (an in-process fake), so
nothing reaches a real provider unless the operator both enables DNS and supplies a real
provider with credentials. Credentials are taken by env-var *reference* (preferred) or a
literal that is redacted at every output boundary; the AdGuard driver refuses any rewrite
outside its configured zone (the guardrail AdGuard itself lacks). **This release ships the
design + faithful fakes + unit tests ONLY — no real Cloudflare or AdGuard endpoint is contacted
by the repo or its test suite. A live trial against real credentials is a separate, gated step
that has NOT yet been run.** See [`docs/DNS-DESIGN.md`](docs/DNS-DESIGN.md).

**Edge guarantees — stress-tested live.** A 5-beat live stress test on this develop line
exercised the v0.3 invariants end-to-end: granular Caddy expose/unexpose, a wedged-admin
bounded timeout (a clean failure, never a hang), drift→reconcile, the ephemeral-durability
warning proven by a real container restart, and cross-edge atomic rollback (Caddy + Traefik —
one edge fails → both roll back, none left half-applied). Every mutating beat was byte-for-byte
restored and all anchors identical before/after. Recorded in
[`TRIAL-RESULT-bench-stress-2026-06-29.md`](archive/trials/results/TRIAL-RESULT-bench-stress-2026-06-29.md) (doc-only;
no code change).

**Housekeeping.** The standalone `crenel banner` status line now prints the real build version
(ldflags / `git describe`-derived) instead of a hardcoded literal; `.DS_Store` is git-ignored.

## v0.3.0 — 2026-06-29

Minor — the arc from "writes the Caddy edge for real" (v0.2.0) to **"writes EVERY edge for
real, and verifies it against the running daemon — proven across vendors."** v0.2 made the
write path durable/atomic/faithful on Caddy; v0.3 makes the OTHER drivers real too, by
standing up a live multi-backend proving ground (a standing bench: real Traefik v3.1, nginx 1.27,
Caddy 2, Authentik) and burning down every gap the faithful fakes structurally couldn't
surface. Each fix is RED→GREEN with the fakes upgraded to reject what the real daemons
reject, and live-validated. 15 packages green, race-clean, **zero external dependencies**.

**Real runtime verification for the file drivers (the headline).** A file driver used to
"read-back-verify" by re-reading the config file it just wrote — a tautology that reported
success even when the daemon rejected the config. New optional `ports.RuntimeVerifier`:
Traefik verifies against its HTTP API (`/api/http/routers`); nginx via `nginx -t` + reload +
an HTTP probe (incl. a synthetic unmatched-host **deny probe** that confirms the default-deny
invariant live and beats the graceful-reload fail-open race). Tri-state — Confirmed →
"verified LIVE", Failed → rollback (the false green becomes a real red), Unavailable →
"written; runtime verify unavailable" (never a false green). Caddy already read its live
admin API and is unchanged.

**Valid edge output — Crenel now emits only config the real daemons accept.** Traefik: no
explicit deny router (its native 404 *is* default-deny; the old empty-`loadBalancer` deny was
rejected and dropped the whole file), and an emptied config serializes to `{}` not
`{"http":{}}` (so removing the last route actually takes effect). nginx: a valid `listen 80;`
by default (the old `listen 443 ssl` had no cert and failed `nginx -t`), with operator-provided
certs for `listen 443 ssl`.

**Correct nginx default-deny + a reload path.** nginx's deny is now modeled PER LISTEN PORT,
honoring the implicit-default-server rule — so `status` reports ENFORCED only when an unmatched
host is actually denied on the wire (previously it claimed ENFORCED while nginx served every
host via its first vhost). Apply runs an operator-declared `nginx -t` + reload, so a write is no
longer inert. Both file drivers bootstrap a not-yet-created config instead of hard-erroring.

**Zero-dependency Traefik YAML read.** A real Traefik file provider is fed YAML; Crenel's
JSON-only reader hard-errored (`invalid character 'h'`) on every read command. A minimal,
hand-rolled YAML-subset decoder (scoped to the dynamic-config shape) now reads a real
`dynamic.yml`; `decode()` auto-detects JSON vs YAML and the encoder stays JSON (JSON ⊂ YAML,
so Traefik accepts Crenel's output). **No new go.mod dependencies** — the module still has no
`go.sum`.

**Cross-vendor atomic coordination — proven live.** The brand claim ("every edge in atomic
agreement, verified") demonstrated on the proving-ground bench across a heterogeneous Caddy + Traefik pair on
the **unmodified** v0.3 binary: a coordinated `expose` verified on both real runtimes, and —
when the Traefik edge was pointed at a daemon-rejected target — the transaction **rolled back
BOTH edges** (Caddy not left half-applied), exit 1, honest `ROLLED BACK`.

**Safety — Caddy host-less subroute deny.** `normalizeServer` now descends a host-less
subroute (the shape the Caddyfile adapter emits for the default-deny), so a subroute wrapping
a *permissive* reverse_proxy is no longer misread as `DenyCatchAllPresent=true` (a real
fail-open misread), and the canonical deny no longer displays a spurious UNKNOWN.

**Batteries-included bundle (v0).** A turnkey `docker compose up` on-ramp — bundled Caddy edge
(default-deny baked in) + Crenel pre-wired to drive it + a read-only status HUD (`crenel serve`)
+ a demo upstream. The same binary still drives a BYO stack; the bundle is data + composition,
core unchanged.

**Brand + public-launch prep (not launch).** Locked the brand (crisp-green canonical wordmark,
four variants, new tagline), README hero + a one-command bundle quickstart alongside the
brownfield-adopt path, leveled status-HUD art, and legal + OSS scaffolding. Brand assets moved
`assets/ → docs/brand/`.

Live-validated on the proving-ground bench (full expose→runtime-verify→unexpose round-trips on real Traefik +
nginx; cross-vendor rollback) and against the maintainer's real production VPS edge **read-only**
(`version`/`status`/`audit`/`drift`, no write/persist path).

## v0.2.0 — 2026-06-28

Minor — the arc from "reads a real edge correctly" (v0.1.1) to "writes a real edge
DURABLY, atomically, and faithfully." Everything below is impl + faithful fakes + tests
(325 test functions, race-clean) and, where it touches production, validated by
sole-executor LIVE trials that left the home edge **byte-for-byte as found**.

**Flagship — the one-command durable `rename`.** `crenel rename <old-host> <new-host>`
moves a service to a new hostname as ONE atomic, read-back-verified transaction: add the
new host (copying the source route's exact backend / mode / upstream-TLS / auth) + remove
the old, make-before-break (new up before old down), all-or-nothing rollback, ONE
coordinated durable persist. **Proven live on production as a single command.**

**Durable home-edge persist (the big one).** An admin-API write now SURVIVES a control-
plane restart. The home Caddy boots from a Caddyfile (no `--resume`), so admin writes were
ephemeral; Crenel now reconciles the live config into the on-disk boot Caddyfile,
**read-back-verified by re-adaptation** (the candidate is proven to `caddy adapt` back to
the live managed state before commit — no second source of truth). A managed host's durable
form is a per-host handle INSIDE the covering `*.zone` wildcard (inheriting its TLS — not a
shadowing top-level site), over a two-channel exec model (file→host, caddy→container). A
**no-drift-loss gate** refuses any reload that would drop a live-only route. **Proven live**:
expose → `docker restart` → host survived; unexpose → Caddyfile back to anchor, all by Crenel.

**Persistence-model detection net.** `PersistenceModel` (durable-config / durable-file /
resume / ephemeral-admin / unknown) is detected + declared per edge and surfaced — a status
`Durability:` line, an audit `ephemeral_writes` warning, and a write-path warning when a
verified write lands on an ephemeral edge. The admin API carries no boot-source marker, so
durability is declared, never inferred — detect-and-declare-unknown extended to durability.

**Cross-chain coordinated WRITE — the literal 302, proven end-to-end.** One
`expose`/`unexpose`/`reconcile` lands/tears a chain (front-forward + downstream-route + DNS)
as one ordered, read-back-verified, all-or-nothing transaction; auth attaches downstream;
the gate spans both edges. Three live-only gaps found + fixed on production trials (subroute
nesting, a valid forward-auth JSON gate, front-leg upstream TLS) culminating in the literal
`302 → auth.homelab.example` through the real two-edge chain.

**Pluggable connection axis (TRANSPORT).** HOW Crenel reaches an admin API is now a
first-class `ports.Transport`: `direct` (default; zero behavior change), `ssh-exec` (a
nested-exec curl against a loopback-only, UNPUBLISHED admin — no port, no tunnel),
`ssh-tunnel` (a crenel-managed forward). The never-hang / wedge classification holds through
every transport. This is what lets Crenel reach the maintainer's home edge with no admin exposure.

**Security posture + secret redaction.** `SECURITY.md` (threat model, the loopback-first
transport trust model, per-boundary adversary analysis) + `internal/redact` (value-aware
field masking applied to OUTPUT only — `status --json` excerpts, error echoes, exports —
gated by `--show-secrets`; exports `0600`). The apply / read-back-verify / preserve paths
keep REAL values.

**Detect-and-declare-unknown maturity (the long-tail safety net).** Multi-server Caddy
(`UnknownServerBlock`), generator/foreign detection (caddy-docker-proxy, NPM, Traefik
label/orchestrator providers, Pangolin), tunnel/overlay ingress (`IngressKind`:
cloudflared/Tailscale), and the chain-aware read model (P4: front → downstream follow-
through, auth resolved by OBSERVATION). Anything Crenel can't fully parse is a *declared
unknown* (counted, surfaced, mutation-blocking) — never a confident wrong answer.

**Brownfield + reconcile maturity.** `import` (adopt-in-place), declarative `apply`
(`--adopt`/`--prune`, JSON/YAML), `reconcile`/`drift` (detect + fix ALL drift, CI/cron),
forward-auth by reference (`--auth`, per-driver), `set`/`resume`, and the branded status HUD.
Four edge drivers behind one port: **Caddy, Traefik, nginx, NetBird** (mesh; reads, refuses
mutation loudly).

The authoritative current-state map is [`STATE-OF-CRENEL.md`](STATE-OF-CRENEL.md); the live
trial records are the `TRIAL-RESULT-*` docs.

## v0.1.1 — 2026-06-27

Patch — two Caddy-normalizer misreads found by the v0.1.0 **read-only** trial
against the maintainer's real VPS edge (no mutation; the install proved nothing changed).
Both were MISREAD-↓ by omission — exactly the class the bounded-honesty invariant
exists to prevent — so they are fixed, not just declared:

- **Grouped multi-host routes are now fully enumerated.** A single Caddy route can
  match many hosts (`host: [a, b, c]` — a real edge groups dozens of vhosts that
  share one backend into one route). `normalize` took only the first host and
  silently dropped the rest; on the real edge that hid ~21 of ~30 reachable
  services. It now emits one route per co-matched host (`hostMatches`), at both the
  top level and through nested subroutes.
- **`abort: true` static_response is now recognized as a deny.** A per-zone
  catch-all spelled `{"handler":"static_response","abort":true}` (no `status_code`)
  read as an unmodeled handler, falsely downgrading default-deny to `UNKNOWN` and
  flagging coverage INCOMPLETE. `isDeny` now honors `abort`, and a deny-only
  subroute resolves cleanly instead of being flagged opaque.

Net effect on the real edge: status now enumerates all ~30 services, coverage is
complete (0 unparsed), and default-deny reads `ENFORCED` — the correct, complete
read. New tests (`grouped_multihost_test.go`) mirror the real shape. Green:
`go build ./... && go vet ./... && go test -race -count=1 ./...`.

## v0.1.0 — 2026-06-27

First cut. Crenel is a **vendor-agnostic, live-state-authoritative CLI** for
controlling what a self-hosted reverse-proxy edge exposes to the outside world.
It holds **no stored desired state** — the only truth is what the edge reports
live; every mutating verb runs `read-live → plan → apply → read-back-verify` and
never trusts an admin-API `200` as proof.

### Three load-bearing invariants

- **Live-state-authoritative** — read the edge, plan against live, apply, then
  re-read and verify the change actually took.
- **Structural default-deny** — a host is reachable *iff* an explicit route exists
  **and** the catch-all deny is present; every driver always renders + reports the
  deny.
- **Bounded honesty (detect-and-declare-unknown)** — anything `normalize` cannot
  fully parse becomes a *declared unknown* (counted, surfaced, mutation-blocking).
  Default-deny is reported `ENFORCED` only when the config was fully parsed
  (otherwise `UNKNOWN`, never falsely green), and Crenel **refuses to manage** a
  route/edge owned by another tool or whose ownership it can't determine.

### Capabilities

- **Verbs.** Read-only: `status` (`--hud`/`--banner`/`--plain`/`--json`),
  `audit`, `drift`, `preview <expose|unexpose> <svc>`, `export <file>`. Mutating
  (preview → confirm → apply → read-back-verify): `expose` / `unexpose` /
  `set <svc> <on|off>`, `resume` (re-drive an interrupted apply from live),
  `reconcile` (detect + fix all drift), `import [--dry-run]` (brownfield
  adoption), `apply <file> [--adopt|--prune|--dry-run]` (kubectl-style
  declarative, JSON or YAML). Scaffold: `init [dir]`. Plus `version` / `help`.
- **Four edge drivers** behind one `EdgeProvider` port: **Caddy** (admin API),
  **Traefik** (file provider), **nginx** (file), **NetBird** (identity mesh —
  reads, refuses mutation loudly).
- **Split-horizon DNS** via a **dnscontrol** driver — internal + public scopes.
- **Multi-edge topology** — home + VPS double-write with a cross-edge
  all-or-nothing transaction and per-edge wedge-safe rollback.
- **Forward-auth by reference** (`--auth <policy>`) — Crenel renders a *reference*
  to your auth provider per driver (Caddy `forward_auth`/`import`, Traefik
  middleware, nginx `auth_request`) while you own the actual auth config.
  Publishing a host public with no auth is a loud, explicit choice
  (`--auth none`); `audit` flags `public_without_auth`.
- **Status HUD** — `crenel status` renders a branded, color-coded live HUD on a
  TTY (semantic color: green = safe/private/verified, amber = about-to-go-public /
  drift, red = fail-open); degrades to clean scriptable text when piped /
  `--plain` / `--json`; honors `NO_COLOR`.
- **Generator / foreign-ownership detection** — NPM (nginx), Traefik
  label/orchestrator providers, **Pangolin** (Traefik `badger` middleware), and
  **caddy-docker-proxy** are detected and read as *foreign* so the refuse-to-manage
  gate blocks mutation (a generator would revert Crenel's edit on its next
  regeneration). Routes stay READ-able (understanding ≠ ownership).
- **Tunnel / overlay ingress modeling** — typed `IngressKind ∈ {public-listener,
  tunnel, overlay, unknown}`: a service reachable via cloudflared / Tailscale
  funnel is PUBLIC even when the local proxy binds localhost. Declared
  (`ingress_kind`) or detected (cloudflared `config.yml` / Tailscale `serve.json`
  scan); an externally-fronted edge Crenel can't classify is declared UNKNOWN,
  never assumed internal. Surfaced as the `ingress_external` audit finding +
  status label.
- **Brownfield-safe** — `import` adopts pre-existing routes in place (ownership
  marker only, no behavior change); Caddy on-disk persistence (`caddy_persist_path`)
  survives a `docker restart`; additive granular apply preserves unmanaged routes
  verbatim, incl. brownfield auth.
- **Zero-dependency build** — hand-rolled Caddyfile adapter, nginx tokenizer,
  Traefik rule parser, and a YAML-subset decoder. No live infrastructure in any
  test; everything runs against in-repo fakes/fixtures.

### Verification

`go build ./... && go vet ./... && go test -race -count=1 ./...` is green —
12 test packages OK, 3 with no tests, 192 test functions, race-clean. ~10.4k LOC
of non-test Go across 41 files.

### Known boundaries (honest, by design — safe-by-default via the P0 net)

Anything below reads as a *declared unknown* (refuse / `UNKNOWN`) rather than a
confident wrong answer. Full register in
[`TOPOLOGY-RISK-REGISTER.md`](TOPOLOGY-RISK-REGISTER.md); current state in
[`STATE-OF-CRENEL.md`](STATE-OF-CRENEL.md) §3.

- **Caddy: use `--granular` on any real/brownfield edge.** Full-load (the
  default) is a full-config replace, safe only on a greenfield/Crenel-owned edge —
  and it now *refuses* (rather than silently clobbers) when live holds unparsed
  constructs, real forward-auth, or passthrough. `init` scaffolds
  `granular_apply: true`. Forward-auth + layer4 passthrough on Caddy require
  granular (+ persist for auth).
- **caddy-docker-proxy detection needs a hint.** The Caddy admin API carries no
  CDP marker, so detection needs either the mounted on-disk `Caddyfile.autosave`
  (`caddy_generator_config_path`) or an operator-declared `caddy_generator` hint.
  Without one, a CDP edge still reads read-only-safe but its routes look
  `unmanaged` (mutable).
- **Tunnel/overlay ingress is edge-level only.** The edge is flagged external;
  recovering the *real* per-host public/private mapping from the tunnel's own
  ingress rules is a follow-on.
- **Chain topology is a posture flag, not a chain-aware model.** `auth_downstream`
  suppresses spurious `public_without_auth` and labels hosts `auth: downstream`;
  the front edge is still treated as terminal for routing/projection.
- **Traefik/nginx "live" read is the desired file, not the running process** (no
  admin read-back like Caddy's).
- **DNS reconcile** is presence/absence + mode only; record *value* drift (right
  name, wrong target) is not yet detected.
- **nginx managed-block re-render** reconstructs a Crenel-owned block from
  address + auth only; extra directives added *inside* a Crenel-managed block are
  lost on an unrelated apply (a fidelity boundary, not a safety hole). Sub-host
  (path/header/method) routing and per-path auth are not yet modeled.

### Install

```bash
make build          # -> ./dist/crenel (version-stamped)
make release        # linux/{amd64,arm64} + darwin/{amd64,arm64} static -> ./dist
crenel version      # crenel v0.1.0
```
