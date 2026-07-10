# Changelog

All notable changes to Crenel are recorded here. Versioning is informal while
pre-1.0 (`v0.x` = "works, with documented boundaries"). The authoritative
current-state map is [`STATE-OF-CRENEL.md`](STATE-OF-CRENEL.md).

## v0.5.0 — 2026-07-10

Minor — the arc from "audits and writes the edge it manages" to **"understands a
multi-zone, multi-resolver, residency-aware edge — and an agent can drive it safely."**
Six feature tracks plus a hardening pass, all green under `-race`, **zero external
dependencies**. Live status is stated per feature below: this release also carries a
week of live production trials (dual-instance coordinated writes, containerized durable
persist, a live Pi-hole cycle, and the production cutover — 2026-07-09/10, recorded in
`docs/internal/TRIAL-RECORD-live-proofs-2026-07-10.md` and
`docs/internal/TRIAL-RECORD-pihole-2026-07-10.md`), while the newest surfaces (MCP,
multi-zone routing, residency) are BUILT + hermetically tested but not yet individually
live-trialed.

**Pi-hole v6 — third internal-DNS provider, LIVE-PROVEN.** A second native
internal-resolver driver alongside AdGuard (`internal/drivers/dns/pihole`), speaking the
Pi-hole v6 REST API (session auth, one re-auth-and-retry on 401) with the API contract
captured live against a real `pihole/pihole` container and checked in as fixtures.
Honest divergences from AdGuard are refused loudly rather than mismodeled: IP-only
targets (a CNAME-shaped target is refused at plan time), wildcards refused (they live in
dnsmasq confs outside the API), and Pi-hole's silent same-name-duplicate trap is
Crenel's own conflict refusal. A full expose→verify→drift→unexpose cycle ran against a
real throwaway Pi-hole v6.4.3 instance with zero contract divergences. See
docs/DNS-DESIGN.md §3c.

**MCP server — an LLM agent can drive Crenel, read-only by construction.** `crenel mcp`
serves the Model Context Protocol over stdio: three read tools
(`crenel_status`/`crenel_audit`/`crenel_drift`) against the same narrow
`core.ReadOnlyEngine` interface `serve` and `audit <target>` use, so a mutating call is
unrepresentable, not merely refused; secrets in declared-unknown excerpts stay redacted
with no `--show-secrets` escape hatch. Opt-in `crenel mcp --write` adds a **two-phase
gated** write pair — `crenel_plan` returns a content-hash `plan_id`; `crenel_apply`
commits only if the id re-derives against *current* live state, then runs the normal
preview→apply→read-back-verify. BUILT + protocol-tested; no live end-to-end trial of a
real LLM client against a real edge yet. See docs/MCP.md.

**Multi-zone internal DNS — one block per resolver box.** A provider covering several
apexes lists them once (`zones: ["a.example", "b.example"]`); wiring expands the list
into per-zone zone-confined instances (equivalence-tested against the hand-expanded
form), Pi-hole expansions share one session, and a bare service name that could live
under two managed zones is refused with the candidate FQDNs. A new
optional `ports.ZoneReporter` capability declares the zone a provider is confined to;
core now routes each host only to the providers whose zone covers it (plan, apply-verify,
declarative, reconcile), `dns_coverage_parity` groups resolvers **by zone** (cross-zone
resolvers are never compared), and a host outside every managed zone gets the honest,
quieter `edge_route_outside_managed_zones` declaration instead of a standing
`edge_route_without_dns` cry-wolf. BUILT, fake-tested against the production shape
(2 zones × 2 resolver instances); no live multi-zone trial. See docs/DNS-DESIGN.md §13.

**Residency selector — per-host vantage-divergent DNS targets.** A host gains an
operator-declared residency class (`expose --residency <class>` / an apply file's
`residency:` key), and each internal resolver answers it from its OWN per-class
`targets:` map layered over the `edge_addr` default — the reference architecture's
`target(class, vantage)` rule (docs/REFERENCE-ARCH-split-horizon.md §2) made per-host.
Refuse-loudly throughout: a class with no target on an instance refuses at plan time
naming both; a non-default class on a provider without the capability refuses rather
than silently misdirecting a vantage; public providers ignore the class by design (the
public answer is class-invariant). Class unset behaves byte-identically to before.
BUILT, hermetically tested. See docs/DNS-DESIGN.md §14.

**Inline scope flags.** `expose`/`unexpose`/`set` gained `--scope internal|public|both`
(sugar over `--dns`), `--dns`, and `--edges <a,b>` — the inline twin of an apply file's
`dns:`/`edges:` fields, so an internal-only or single-edge expose is one command with no
apply file. See docs/design/expose-scope-flags.md.

**Ack hardening (live-found).** The ack marker is now host-qualified
(`crenel-ack:<host>:<reason>`) so two hosts sharing a reason slug no longer collide on
Caddy's globally-unique `@id` (legacy bare markers still parse); a failed ack now
surfaces each edge's real driver error instead of a generic "no participating edge";
a path-suffixed target (`ack host/api`) is refused with a specific message instead of
dying generically (path-scoped ack is not implemented — the doc and code now agree).

**Live proof — dual-instance + durable persist + production cutover (2026-07-09/10).**
Coordinated dual-AdGuard expose/unexpose PROVEN LIVE across three full cycles (edge +
both instances + surgical public applied atomically, read-back-verified per instance,
vantage-verified from three viewpoints, reversed to a captured baseline each time);
durable persist PROVEN LIVE on a containerized edge (route verified simultaneously in
the host boot file, the container's view, and the running config) after two
transport-truth fixes — the persist reload now runs through the edge's own transport
(`ssh-exec` → in-container `caddy reload`) and pins the IPv4 admin address instead of
bare `localhost`; and Crenel was promoted to the **production source of truth** (after
operator `ack` of three path-scoped carve-outs the live edge reads default-deny
ENFORCED at full coverage). A fail-closed forward-auth guard also landed live-found:
a `ForwardAuth` policy with an empty verify URI is refused at plan and render time
(it previously risked failing *open*).

## v0.4.5 — 2026-07-10

Public-snapshot patch. **Dual-instance internal DNS write path** — hermetic tests prove
one `expose` fans out to both same-scope resolver instances (coinciding and
vantage-divergent targets), read-back verifies each through its own labeled endpoint,
a mid-transaction failure rolls back the first instance's rewrite AND the edge route,
and unexpose removes each instance's own value. **Transport-true durability** — the
durable-persist `validate`/`reload`/`adapt` subprocesses now run through the same exec
chain as the admin calls on an `ssh-exec` edge, and `caddy reload` targets the exact
IPv4 admin address (dual-stack `localhost` → `::1` silently broke restart-survival on
the containerized edge). **Fail-closed auth guard** — a forward-auth policy with no
verify URI is refused at plan and render time instead of risking a fail-open gate.

*Honesty note:* the snapshot's own release notes described this as "proven against a
real production two-site edge" **before** the corresponding trial record existed; the
dual-instance *write* path was fake-proven at v0.4.5 cut time, and the live
dual-instance proof landed with the 2026-07-10 trials recorded under v0.5.0 above.

## v0.4.4 — 2026-07-09

Public-snapshot patch: **audit any edge, zero config** (M-A1–M-A6,
`docs/internal/AUDIT-ANYEDGE-DESIGN.md`). `crenel audit <target>` now takes a positional
target with no settings file: a Caddy admin URL or Caddyfile path, an Nginx Proxy
Manager data dir, a Traefik API URL (Pangolin and docker-labels setups included), or a
caddy-docker-proxy `Caddyfile.autosave` dir. The audit REFUSES until the operator
declares the boundary out loud (`--assume-public-boundary` / `--internal`); only the
pasted target is ever contacted, anything beyond is opt-in via `--probe`; a clean
foreign edge exits 0 so it crons quietly. Underneath: `Engine.ReadOnly` (config
`read_only: true`) refuses every mutating verb before any driver `Plan`/`Apply`,
exported as the narrow `core.ReadOnlyEngine` interface. BUILT + fixture-tested (the cdp
fixture captured from a real container); no live `--probe` trial recorded.

## v0.4.3 — 2026-07-09

Public-snapshot patch — DX + posture + release plumbing:

- **Adaptive HUD.** `status --hud` sizes to the real terminal (`TIOCGWINSZ` via stdlib
  syscall — zero-deps preserved), height-budgeted down to a crown-only render for
  short terminals; small wordmark scales render flat brand-green instead of a broken
  bevel. A stock 80×24 now shows the full castle + panel without wrapping or scrolling.
- **Recorded demo** (`docs/brand/crenel-demo.gif`) — the README hero now shows the real
  expose→verify→drift→unexpose loop.
- **Read-only engine posture** (`read_only: true`) — the M-A1 half of audit-any-edge,
  shipped ahead of the target modes.
- **Docs relaunch** — README repositioned around the split-horizon operator ("is Crenel
  for you?" triage table, honest driver-support matrix, proven-live table).
- **DCO-only contributions** (per-commit sign-off; CLA dropped) and a **release-binaries
  workflow** (static linux/darwin amd64/arm64 artifacts attached to tags).

## v0.4.2 — 2026-07-05

Public-snapshot patch — closes three of the four LOW findings the independent audit
left open (F2/F3/F5; see `docs/audits/independent-audit-2026-07-03.md`), plus the ack
marker:

- **CI (F5).** GitHub Actions runs `go build` / `go vet` / `go test -race` + `gitleaks`
  on every push and PR.
- **Verify-honesty gate (F2).** A file-driver write with no runtime probe configured is
  REFUSED (rolled back) rather than silently stood up unverified —
  `UnverifiedWriteError`, with `--allow-unverified` as the explicit escape hatch.
- **File lock (F3).** The mutating apply path takes a file lock, so two concurrent
  Crenel invocations can't interleave read-modify-write on a file-provider edge.
- **`ack` marker.** Operator acknowledgment of an intentionally-unmodeled route
  (`crenel ack <host> [reason]` / `unack` — `docs/design/ack-marker.md`): the vetted
  carve-out that lets `audit`/`drift` run cron-clean on a brownfield edge without
  pretending the route parses. F4 (reconcile TOCTOU) remains open, documented, low.

## v0.4.1 — 2026-07-04

Public-snapshot patch: **F1**, the one MEDIUM from the independent audit (DeepSeek,
9 parallel code-tracing subagents + an independent verification pass, 2026-07-03 —
which found the default-deny and never-silently-wrong invariants SOUND, no
CRITICAL/HIGH). An nginx config whose `server` blocks Crenel didn't read — a stock
`http { server {} }`-wrapped nginx.conf, a stream-only config, an include-only config,
or a map/upstream-only helper file — read as a false `ENFORCED` with zero routes and
zero warnings. Fixed: `server_not_read` now DECLARES the unrecognized block, so
default-deny downgrades to UNKNOWN — the bounded-honesty invariant restored on the
exact shape the audit found.

## v0.4.0 — 2026-07-03

**The first public release** — `github.com/crenelhq/crenel`, Apache-2.0, clean history
(v0.1.0–v0.3.2 remain the private pre-history; summarized below and in this file). No
new engine capability over v0.3.2 — this release is the launch packaging of what the
private line had built and proven:

- **`expose --to <host:port>`** — name the backend inline, no pre-edited origins map;
  the target is TCP-probed before any route is written (`--no-validate` to skip), and
  the origin persists into settings on a verified apply.
- **Launch scaffolding** — LICENSE/NOTICE/CONTRIBUTING (DCO), CODE_OF_CONDUCT,
  `docs/OPEN-CORE.md` (the Apache core is the whole product for an individual
  operator), a security-audit package under `docs/security/`, and the
  batteries-included `bundle/` quickstart.
- **Proven-live posture carried forward:** durable restart-surviving persist,
  one-command `rename`, cross-edge atomic rollback, surgical Cloudflare on a shared
  production zone, and the full-chain production expose — each backed by a trial
  record (`archive/trials/results/`, `docs/internal/TRIAL-RECORD-live-proofs-2026-06-30.md`).

Full launch notes: the `v0.4.0` GitHub release body
(`docs/launch/RELEASE-NOTES-v0.4.0.md` in the private repo).
An independent third-party audit ran against this release two days later — see v0.4.1.

*Note on versioning:* v0.4.x version numbers are labels on the scrubbed public
snapshot mirror (see `docs/internal/README.md`'s snapshot-flow convention), not tags
on the private `develop` line; dates are the snapshot publication dates.

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
[`docs/internal/TOPOLOGY-RISK-REGISTER.md`](docs/internal/TOPOLOGY-RISK-REGISTER.md); current state in
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
