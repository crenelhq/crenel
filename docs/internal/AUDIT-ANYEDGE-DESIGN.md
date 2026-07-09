# Crenel — Audit-Any-Edge (standalone read-only audit) — DESIGN DRAFT

> Phase-5 expansion draft. Companion to DESIGN.md (architecture),
> TOPOLOGY-RISK-REGISTER.md (the bounded-honesty spec this must not weaken),
> STRAIN.md (the file-read vs live-process gap that dominates §5 here), and
> STATE-OF-CRENEL.md §3/§6 (what already exists). **No code has been changed for
> this draft; every file:line cite is against the current tree.**

---

## 0. A correction that reshapes the whole design

The strategic framing ("bounded honesty makes crenel REFUSE to manage
generator-owned routes; that refusal leaves value on the table for READS") is
half right, and the half that's wrong is good news:

**Crenel does not refuse to READ a foreign edge today.** The refusal lives
exclusively on the mutation path:

- `internal/core/gate.go:23` — `ErrRefuseToManage`, and
  `gateOwnership` (`gate.go:38`) / `gateChainOwnership` (`gate.go:105`), which
  run **only** as the pre-mutation gate before any driver `Apply`. A
  `Generator`-set edge is refused edge-wide (`gate.go:64-69`); a foreign/unknown
  route is refused per-host (`gate.go:77-92`).
- `import`/`apply --adopt` refuse to stamp a marker on foreign/unknown blocks
  (STATE-OF-CRENEL §3 "Refuse-to-manage gate").

`Engine.Audit` (`internal/core/audit.go:99`) and `Engine.Status`
(`internal/core/status.go:20`) happily read a foreign edge and already emit the
right honesty findings: `ownership_unconfirmed` (`audit.go:256-270`),
`coverage_incomplete` (`audit.go:232-240`), the ternary deny verdict
(`audit.go:206-227`), `public_without_auth` (`audit.go:744-750`), and the
generator detectors are shipped: NPM (`internal/drivers/edge/nginx/codec.go:231`),
Pangolin via the `badger` middleware and Traefik label/orchestrator providers
(`internal/drivers/edge/traefik/codec.go:106-166`), caddy-docker-proxy via
`Caddyfile.autosave` / declared hint (`internal/drivers/edge/caddy/caddy.go:277-474`).

So "audit any edge" is **not** a relax-the-refusal project. The real gaps are:

1. **Bootstrapping.** Today an audit needs a settings file (`loadSettings`,
   `cmd/crenel/main.go:377` → `config.Load`, `internal/config/settings.go:507`)
   with edges, driver types, admin URLs / config paths, zone, origins. A
   Pangolin user evaluating crenel will not write that file. The 30-second
   experience is a **zero-config target** problem.
2. **Reading the generator's actual substrate.** The drivers read *one*
   configured file / admin URL. NPM's truth is a *tree*
   (`/data/nginx/proxy_host/*.conf`); Pangolin's Traefik config is partly served
   over Traefik's HTTP provider from `pangolin:3001`
   (`traefik/codec.go:106-108`), not only files; cdp's truth is in-memory admin
   state. Pointing today's drivers at one file may read a *subset* and the
   audit must say so.
3. **Report framing.** On a foreign edge, `ownership_unconfirmed` is a
   *warning* that flips `AuditReport.OK()` (`internal/core/report.go:99-106`).
   For a user who came *only* to audit, "crenel will not mutate this" is not a
   problem to fix — it is the expected posture. The finding must survive (never
   silently dropped) but be re-framed so an audit-only run has a usable exit
   code.
4. **Honest "verified" semantics with no write to verify.** For file-based
   edges, `ReadLiveState` reads the file, not the daemon (STRAIN.md §"live
   state is muddier"; `ports.RuntimeVerifier`, `internal/ports/ports.go:201`).
   A read-only audit of a *stale or unloaded* file is a MISREAD waiting to
   happen and needs its own evidence vocabulary (§5).

Everything below is designed around those four gaps.

---

## 1. Goal and non-goals

**Goal.** `crenel audit` works read-only against **any** reverse-proxy edge —
including edges owned by another generator (NPM, Pangolin, caddy-docker-proxy,
Traefik labels) — with zero settings file, and reports in ~30 seconds:

- every host the edge exposes (with backend, mode, auth evidence),
- the ternary default-deny verdict for the whole config,
- `public_without_auth` per host,
- coverage (`read N/M routes`) and every declared unknown,
- **ownership** per route (crenel / unmanaged / foreign / unknown), framed as
  information, not failure,
- and an explicit statement of what was and was not verifiable (§5).

This is the trust ramp: audit first, adopt writes later, on the SAME verb the
user will keep running in cron after adoption.

**Non-goals.**

- **Not write support for foreign edges.** The mutation gate
  (`gate.go`) is untouched. "Manage at the source" remains the answer; managing
  *at* the generator's source (labels/DB/API) stays the deferred P2 extension
  (register §5 P2 "Later, optional").
- **Not a security scanner.** No CVE checks, no TLS-cipher grading, no
  fuzzing, no unauthenticated-endpoint spidering. Crenel answers "what is
  exposed, is deny structural, is auth attached" from the edge's own state —
  the same three questions it answers on an owned edge.
- **Not a stored baseline.** No snapshot file, no "diff since last audit"
  state. Live is still the only truth (an operator who wants diffs pipes
  `--json` into their own store).
- **Not per-host reachability probing by default.** Active network probes of
  the audited hosts are opt-in only (§5, Q3).

---

## 2. UX — the chosen invocation

### Decision: extend `crenel audit` with a positional TARGET; no new verb.

```
crenel audit                          # unchanged: settings-file topology
crenel audit http://127.0.0.1:2019    # Caddy admin API (incl. cdp)
crenel audit ./Caddyfile              # Caddyfile on disk
crenel audit /etc/nginx/nginx.conf    # nginx (follows include, reads the tree)
crenel audit /data/nginx              # NPM data dir (proxy_host/*.conf tree)
crenel audit ./dynamic.yml            # Traefik file-provider config
crenel audit http://127.0.0.1:8080    # Traefik API (Pangolin's real substrate)
```

With a target argument, crenel builds a one-edge, DNS-less, origins-less
engine in memory (the same `build()` path in `cmd/crenel/wire.go`, fed a
synthesized `config.Settings`), forces **read-only** (§3), runs the ordinary
`Engine.Audit`, and prints the ordinary report plus the new evidence/scope
header. `status <target>` gets the same treatment for free.

**Why not a new verb (`scout` / `recon`)?** Three reasons:

1. **The trust ramp is the same verb.** The pitch is "the audit you ran on day
   0 is the audit you cron on day 100." A separate verb makes day-0 output a
   different product and forces a migration ("now rewrite your cron to use
   `audit`"). The register's whole vocabulary (`coverage_incomplete`,
   `ownership_unconfirmed`, deny ternary) already IS the scout report.
2. **Verb surface is a cost.** DESIGN.md's verb table is deliberately small and
   each verb has one job. "Audit, but pointed at a thing" is not a new job.
3. **No semantics change to hide.** Audit was always read-only
   (`audit.go:88-89` "reads, never writes"). A new verb would imply the old one
   wasn't safe to point at a foreign edge — false, and bad marketing for the
   honesty story.

**Why not `--read-only` as the switch?** Because audit is *already* read-only;
the flag would be a no-op that implies the default is dangerous. Read-only-ness
is not the new thing — target-zero-config is. (A global `--read-only` engine
mode does exist internally per §3, but it is set BY target mode, not a user
decision.)

**Target sniffing** (in `cmd`, not core — composition-root logic):

| Target shape | Detection | Driver wired |
|---|---|---|
| `http(s)://…` answering `GET /config/` with Caddy JSON | probe once | caddy (admin) |
| `http(s)://…` answering `GET /api/http/routers` | probe once | traefik (API-read, new — M-A4) |
| file starting `{`/YAML with `http:`/`tcp:` router keys | content sniff | traefik (file) |
| file with nginx brace DSL / `server {` | content sniff | nginx |
| file with Caddyfile site blocks | content sniff | caddy (Caddyfile adapter — read-only parse) |
| directory containing `proxy_host/*.conf` | layout sniff (NPM signature, `nginx/codec.go:231` reuses) | nginx over the tree |
| directory containing `Caddyfile.autosave` | layout sniff (`caddy/caddy.go:457-474`) | caddy file read + `Generator=caddy-docker-proxy` |
| ambiguous | **refuse loudly**, list what was tried | — |

Ambiguity is refused, never guessed — the same posture as the ambiguous
granular insert (DESIGN.md, Caddy driver "refuses loudly on a genuinely
ambiguous insert").

### The 30-second Pangolin experience (the design driver)

A Pangolin user has Traefik's API on the gerbil/traefik container. They type:

```
$ crenel audit http://localhost:8080
```

and see (sketch; real layout follows the existing audit/status renderers):

```
crenel audit — READ-ONLY EXPOSURE AUDIT (zero-config target)
Edge: traefik @ http://localhost:8080     FOREIGN-MANAGED: pangolin
Evidence: RUNTIME (Traefik API — the running process, not a file)
Scope: no DNS providers configured — public-ness assumes this edge is the
       public boundary; split-horizon/tunnel nuance NOT evaluated

  Coverage: read 14/14 routers — fully parsed
  Default-deny: ENFORCED (unmatched hosts 404)
  Exposed (14):
    vault.example.com   → 10.0.0.7:8200    auth: badger (pangolin)     PUBLIC
    notes.example.com   → 10.0.0.9:3000    auth: —                     PUBLIC ⚠
    …
  ⚠ public_without_auth: notes.example.com — anyone on the internet can reach it
  ℹ foreign_managed: this edge is generated by pangolin — crenel audits it
    read-only and will refuse to modify it; manage routes in the Pangolin UI
  Not verifiable here: whether Pangolin's WireGuard ingress publishes
    additional hostnames (ingress: EXTERNAL/overlay — declared, not read)

exit 1 (warning findings present)   # --json for CI
```

Every line above is existing machinery re-framed: coverage
(`report.go:38`), deny ternary (`report.go:69`), `public_without_auth`
(`audit.go:744`), Pangolin detection (`traefik/codec.go:117`), ingress-external
declaration (`audit.go:278-334`). The new work is the target bootstrap, the
evidence/scope header, and the `foreign_managed` re-framing (§3).

---

## 3. Model changes — auditing foreign must not weaken bounded honesty

### 3.1 No new Ownership value

`model.Ownership` already carries the needed axis
(`{OwnCrenel, OwnUnmanaged, OwnForeign, OwnUnknown}`, register §4.1). A foreign
route in a zero-config audit is **still `OwnForeign`** — reported, never
claimed as understood-and-owned. Do not add an `OwnAudited` state: ownership is
a property of the route, not of the verb reading it.

### 3.2 A read-only engine posture, structural not advisory

Add `Engine.ReadOnly bool` (set by `cmd` whenever a target argument is used;
also settable via settings `read_only: true` for the "I only ever audit this
edge" config). Semantics:

- Every mutating verb (`expose/unexpose/apply/reconcile/import/rename/resume/
  ack/unack`) refuses before planning, with a message naming the target mode.
  This is belt-and-braces: in target mode there is no origins map to plan from
  anyway, but the refusal must be structural, matching the MCP server's
  read-only-by-construction claim (docs/AUDIT.md §6 — the narrow
  `Status/Audit/DetectDrift` interface is a good pattern to reuse: target mode
  should construct the engine behind that same narrow interface so mutation is
  unreachable **by type**, not by flag-check).
- `Persister`/`Adopter` capabilities are never invoked.

### 3.3 Re-framing, not suppressing, the ownership finding

Today `ownership_unconfirmed` is severity `warning` (`audit.go:256-270`),
meaning "crenel would refuse to mutate — surprising if you expected to manage."
In read-only posture the *same fact* is not surprising; it is the contract.
Rule:

> When `Engine.ReadOnly`, the edge-wide generator finding is emitted as
> severity **ok** with code **`foreign_managed_readonly`** ("edge is generated
> by X — audited read-only; crenel refuses writes here by design"). Per-route
> `OwnUnknown` findings **stay warnings** — unknown is genuinely unresolved,
> and downgrading it would hide real ambiguity.

This is suppression-with-a-reason in the established style (the
`auth_downstream` precedent, `audit.go:751-758`): the information always
prints; only the severity — and therefore `OK()`/exit code — changes, and only
for the case where the "problem" is the user's chosen mode. The deny ternary,
`coverage_incomplete`, `public_without_auth` are **not** touched: a foreign
edge with an uncertifiable deny still exits non-zero. Bounded honesty is
strictly preserved — nothing is claimed managed, nothing unknown is hidden.

### 3.4 Scope declaration (the "what this audit is NOT" block)

Zero-config mode has no DNS providers, no origins, no chain topology. Several
audit checks silently change meaning: public-ness falls back to "edge route ⇒
public" (`hasPublicDNS == false` path, `audit.go:443-449`, `audit.go:724-733`);
parity/dangling-DNS checks don't run; chain follow-through doesn't run. That
must be **declared, not implied**. Add a first-class `AuditScope` on
`AuditReport`:

```go
type AuditScope struct {
    TargetMode   bool     // zero-config target, not a settings topology
    DNSEvaluated bool     // false => public-ness is the conservative edge-boundary default
    ChainDepth   int      // 0 in target mode — downstream edges not followed
    Evidence     map[string]EvidenceKind // per edge, §5
}
```

rendered as the `Scope:` header lines in §2 and carried in `--json`. This is
the same move as the coverage line: converting an implicit reduction of the
claim into an explicit one.

---

## 4. Driver work per edge

The unifying observation: **the refusal needs no relaxing anywhere** — it's
already write-side-only. Per-edge work is about *reaching and fully reading*
the generator's real substrate.

### 4.1 Generator-owned Caddy (incl. caddy-docker-proxy)

- **Admin-URL target: works today** minus bootstrap. The caddy driver over a
  `direct` transport reads `GET /config/`, recurses subroutes
  (`collectLeaves`), and detects cdp only via autosave/hint
  (`caddy/caddy.go:277-474`). In target mode, if the target is a *directory*
  containing `Caddyfile.autosave`, wire the hint automatically; if only the
  admin URL is given, the cdp boundary stands (documented in STATE §3:
  admin API carries no CDP marker) — routes read `unmanaged`, and the scope
  block must say "generator detection unavailable without the autosave path"
  rather than implying hand-written.
- **Caddyfile-path target: new read path.** The in-repo Caddyfile adapter
  exists for persistence (`caddy_persist_path` round-trip); target mode needs
  it exercised as a *primary read source* with `Unparsed` emission for any
  directive the adapter can't model. Evidence = CONFIG (a file, not the
  running process — §5).

### 4.2 NPM (nginx under the hood)

- The nginx driver already parses the brace DSL and detects NPM's signature
  (`nginx/codec.go:231`). Two gaps:
  1. **Tree reading.** NPM's exposure truth is `/data/nginx/proxy_host/*.conf`
     plus `default.conf` etc. The driver reads one path today. Target mode on a
     directory must read the tree (deterministic order), concatenating into one
     `LiveEdgeState`, and emit an `Unparsed` entry per file it skipped or
     couldn't tokenize. `include` directives inside files: follow when the
     glob resolves inside the target root; declare unknown when it points
     outside (never silently drop — the P0 rule).
  2. **Deny verdict on NPM's shape.** NPM's default server behavior differs
     from crenel's rendered `default_server return 444`; the deny detection
     must recognize NPM's catch-all (or honestly report MISSING/UNKNOWN — a
     genuinely useful finding for NPM users). Needs the fixture below to decide
     against real generated output, not guesses.
- **Explicitly out of scope:** reading NPM's SQLite DB. Zero-dependency Go
  cannot take a sqlite driver, and the *generated* config is the closer-to-live
  substrate anyway.

### 4.3 Pangolin (Traefik under the hood)

- Detection is done (`traefik/codec.go:117`, `badger` middleware
  `traefik/codec.go:156`). The substrate gap: Pangolin serves dynamic config to
  Traefik via the **HTTP provider** from `pangolin:3001`
  (`traefik/codec.go:106-108`), so a file-path target may see a subset or
  nothing.
- The right read source is **Traefik's own API** (`GET /api/http/routers`,
  `/api/http/services`, `/api/tcp/routers`) — exactly the "production-grade
  Traefik driver would additionally read the API" upgrade STRAIN.md §1 already
  called for on the write path. This is the single biggest new driver piece:
  a Traefik **API read mode** (reusing `ports.Transport` for reach, like
  Caddy). Bonus: API evidence is RUNTIME, the strongest kind (§5), and provider
  suffixes (`@http`, `@docker`) fall out of the API response, strengthening
  generator detection.
- Pangolin's WireGuard (`newt`) ingress stays an axis-4 declaration:
  `IngressKind=overlay` when Pangolin is detected (today ingress is declared or
  file-scanned via `EdgeBinding.IngressConfigPath`, `engine.go:43-50`; auto-set
  from generator detection is a small core rule: `Generator=="pangolin" ⇒
  ingress external/overlay unless declared otherwise`).

### 4.4 Traefik-docker-labels / cdp compose targets

- Same Traefik API read path as Pangolin (labels are invisible on disk;
  the API is the only honest read).
- Reading Docker itself (`docker inspect` for labels / compose files as a
  target) is **deferred** — it drags in a Docker-socket dependency and a
  second source of truth. A compose-file target can be sniffed and answered
  with a *pointed refusal*: "this is a compose file; point crenel at the
  running proxy's admin/API instead: try `http://…:2019` / `:8080`." A helpful
  refusal is on-brand; a half-parse of compose YAML is not.

### 4.5 Where the current refusal lives (for the record — none of it moves)

| Refusal | Location | Read-only audit change |
|---|---|---|
| Edge-wide generator refusal | `internal/core/gate.go:64-69` | none |
| Per-host foreign/unknown refusal | `internal/core/gate.go:77-92` | none |
| Chain-participant refusal | `internal/core/gate.go:105-151` | none |
| Adopt-refusal for foreign/unknown | import/apply-adopt classification (STATE §3) | none |
| `ownership_unconfirmed` warning | `internal/core/audit.go:256-270` | re-framed per §3.3 |

---

## 5. Verification semantics in read-only mode

"Verified" in crenel means read-back-after-write. A pure read has no write to
verify, so the word must not appear. Instead, every audited edge carries an
**evidence kind**, printed in the header and per-JSON-edge, extending the
`RuntimeVerifier` vocabulary (`ports.go:179-203`) to the read side:

| Evidence | Meaning | Sources |
|---|---|---|
| **RUNTIME** | the running process reported this state | Caddy admin API, Traefik API |
| **CONFIG** | a file/tree on disk declared this state; the daemon may differ | Caddyfile, nginx tree, Traefik file, NPM tree |
| **DECLARED** | asserted by operator/config, observed by nothing | `ingress_kind`, `auth_downstream` fallback |

Rules:

- CONFIG-evidence edges emit a standing informational finding,
  `config_evidence_only`: "this audit read the config file(s), not the running
  daemon — a failed reload or out-of-band change means reality may differ."
  This is the read-side analogue of `RuntimeVerifyUnavailable` ("written;
  runtime verify unavailable" — `report.go:141-146`), and it is what stops a
  stale NPM `.conf` tree from producing a confident wrong answer.
- **Staleness hint (cheap, honest):** for CONFIG evidence, print the newest
  mtime of the files read ("config last modified 41 days ago"). Not a verdict,
  just evidence the operator can weigh.
- **Optional runtime cross-check, opt-in:** `--probe` upgrades CONFIG toward
  RUNTIME where a probe URL is available (Traefik API, `nginx -t` is a write-
  adjacent exec so NO; an HTTP HEAD against the edge for one audited host is
  the honest nginx option). Probing is off by default because a zero-config
  audit that silently makes network requests to production hostnames violates
  least-surprise; when off, the report says what would have been probeable.
- **What was NOT verifiable is enumerated**, not implied: the `Scope`/evidence
  block always lists (a) DNS not evaluated, (b) tunnel/overlay ingress declared
  only, (c) daemon-vs-file gap for CONFIG edges, (d) any `Unparsed` entries.
  The audit's strongest sentence stays conditional in exactly the way
  `coverage_incomplete` already phrases it: findings cover the understood,
  evidenced subset only.

---

## 6. Risk register deltas

New rows in the TOPOLOGY-RISK-REGISTER style (verdicts for the proposed
feature, dangers in the existing vocabulary):

| # | New risk | Class | Mitigation |
|---|---|---|---|
| A.1 | **Partial-coverage complacency**: user points crenel at ONE substrate of a multi-substrate edge (one nginx file of a tree; Traefik file when the HTTP provider serves more) and treats the report as complete | MISREAD-↓ by omission (the trial's 25→2, re-armed) | Tree reading by default for directory targets; `coverage_incomplete` unchanged; the Scope block names the substrate read ("read 3 files under /data/nginx — the running daemon may load more"); Traefik file target on a Pangolin-detected config emits "config is partly served over the HTTP provider — audit the API instead" (the badger detector already fires from the file) |
| A.2 | **CONFIG-evidence staleness**: audited file ≠ running daemon (unloaded edit, failed reload, copied-out file) | MISREAD both directions | `config_evidence_only` finding + mtime hint (§5); prefer RUNTIME targets in all docs/examples; sniffer suggests the API/admin URL when it can |
| A.3 | **"Audit passed" read as endorsement of a foreign edge**: green exit on an NPM box taken to mean crenel certifies NPM's security | trust/vocabulary | `foreign_managed_readonly` prints on every run (ok-severity, never hidden); non-goal statement in `audit --help`; deny UNKNOWN/MISSING on generator shapes stays a warning/critical — the common real outcome on NPM is *not* a clean pass |
| A.4 | **Public-ness misfire with no DNS configured**: conservative "edge route ⇒ public" default cry-wolfs on a LAN-only edge (MISREAD-↑), or a tunnel-published host is missed (MISREAD-↓) | MISREAD-↑ / -↓ | Scope block states the assumption on every zero-config run; `--internal` flag to declare "this edge is not internet-facing" (mirrors `--auth none`: an explicit spoken choice, downgrades `public_without_auth` to an `exposure_unscoped` info); generator⇒overlay ingress auto-declaration (§4.3) keeps the tunnel direction declared-unknown, never "private" |
| A.5 | **Target sniffing misidentifies a file** and parses garbage confidently | MISREAD | Refuse on ambiguity (§2); sniffing must find a positive signature, not a best fit; unparseable target = loud error, exit 2, never an empty-but-green report |
| A.6 | **Zero-config probe surprise**: a "read-only" audit opening sockets to the target URL the user pasted | trust | Only the pasted target is ever contacted; `--probe` gates anything beyond it; docs state the exact requests made (GET /config/, GET /api/http/routers) |
| A.7 | **Re-framed ownership finding leaks into managed mode**: severity downgrade applied outside ReadOnly posture would blunt the MISMANAGE net | MISMANAGE (indirect) | Downgrade keyed strictly on `Engine.ReadOnly` (§3.3); a test asserts `ownership_unconfirmed` stays a warning on a writable engine — the invariant "the gate and its warning never diverge" |

---

## 7. Milestone slicing

Smallest-first; each shippable alone; hermetic-fake test strategy per slice
(rule unchanged: a fake may only accept what the real edge accepts).

**M-A1 — Read-only engine posture + finding re-frame.** `Engine.ReadOnly`,
narrow-interface construction (§3.2), `foreign_managed_readonly` ok-severity
re-frame (§3.3), `AuditScope` type + header/JSON rendering (§3.4).
No new drivers; works with existing settings files (`read_only: true`).
*Tests:* extend `generator_gate_test.go` / audit tests — foreign edge +
ReadOnly ⇒ ok-severity finding, exit 0 when nothing else fires; same edge
writable ⇒ warning unchanged; every mutating verb refuses on a ReadOnly engine.
*Fixtures:* none new.

**M-A2 — Zero-config target: Caddy admin URL + Caddyfile path.** Sniffer in
`cmd` (positional target → synthesized one-edge Settings, ReadOnly forced),
Caddyfile adapter as a primary read source with `Unparsed` emission, evidence
kinds RUNTIME/CONFIG wired into the report. This slice alone delivers the
30-second demo for hand-written and cdp-admin edges.
*Tests:* sniffer table-test (URL vs file vs ambiguous-refusal); audit-by-target
end-to-end against `caddyfake`; Caddyfile fixtures incl. one with directives
the adapter can't model (asserts declared-unknown, deny UNKNOWN).
*Fixtures:* real-shape Caddyfiles (wildcard site, forward_auth snippet,
unmodeled directive).

**M-A3 — NPM tree read.** Directory targets; `proxy_host/*.conf` +
`default.conf` tree concatenation; include-following inside the root;
NPM deny-shape classification; mtime staleness hint.
*Tests:* hermetic fixture tree captured from a real NPM container's generated
output (checked in, anonymized) — asserts: generator detected, every
proxy_host enumerated, deny verdict decided against NPM's real default server,
skipped/foreign include ⇒ `Unparsed`. Adversarial RED: delete one `.conf` from
the tree and assert coverage/output changes (no silent shrink).
*Fixtures needed:* NPM-generated conf tree (≥3 proxy hosts, one with
access-list auth, one websocket/custom-locations host).

**M-A4 — Traefik API read mode (Pangolin, labels).** Traefik driver gains an
API `ReadLiveState` source over `ports.Transport` (`/api/http/routers`,
`/api/http/services`, `/api/tcp/routers`); provider-suffix generator detection
from API data; sniffer recognizes the API; Pangolin ⇒ overlay-ingress
auto-declaration.
*Tests:* a `traefikapifake` HTTP fake (same discipline as `caddyfake`/
`cfapifake`) serving captured Pangolin and docker-labels API payloads; asserts
badger⇒pangolin, `@docker`⇒labels, foreign edge-wide, routes enumerated,
mutation refused. RED: file-target on the Pangolin fixture asserts the
"audit the API instead" finding (A.1).
*Fixtures needed:* Pangolin-generated router/service API JSON (badger
middleware attached), docker-labels API JSON.

**M-A5 — cdp directory target + auto-hint.** Directory containing
`Caddyfile.autosave` ⇒ caddy CONFIG read + `Generator=caddy-docker-proxy`
auto-set (reuses `caddy/caddy.go:457-474` detection).
*Tests:* fixture autosave dir; asserts foreign + CONFIG evidence +
`config_evidence_only`; admin-URL-only cdp target asserts the scope block's
"generator detection unavailable" honesty line.
*Fixtures needed:* cdp `Caddyfile.autosave` (label-generated shape).

**M-A6 — Opt-in `--probe` + `--internal`.** RUNTIME upgrade where an API
exists; the `--internal` declared-scope flag (A.4); docs + README relaunch
copy ("point crenel at your edge…").
*Tests:* probe-off asserts zero sockets beyond the target (fake transport
records calls); `--internal` downgrades `public_without_auth` to
`exposure_unscoped` info and is refused in settings-topology mode with public
DNS configured (contradiction).

Deliberately excluded from all slices: compose-file parsing, Docker-socket
introspection, NPM SQLite, any write path.

---

## 8. Open questions for Nate

1. **Verb surface:** this draft argues `audit <target>` over a new `scout`
   verb (§2). Veto point — if the relaunch marketing wants a distinct
   first-touch word, `scout` could alias `audit <target>` exactly (one
   implementation, two names). Worth the alias or not?
2. **Exit-code contract in target mode:** is `foreign_managed_readonly` at
   ok-severity (exit 0 when the edge is otherwise clean) the right cron
   behavior, or should zero-config audits *always* exit non-zero on any
   foreign edge until an explicit `--accept-foreign`? §3.3 chose the former;
   it's a judgment call about who crons a foreign audit.
3. **Probe posture:** is contacting ONLY the pasted target URL acceptable
   without a flag (needed for URL sniffing at all), with everything else
   behind `--probe`? Or must even the sniff probe be consented (`audit
   --target-kind caddy http://…`)?
4. **Open-core boundary:** does audit-any-edge (specifically the Traefik API
   read mode and NPM tree reader) belong in the Apache core as the trust ramp,
   or is "richer audits" exactly the proprietary seam docs/OPEN-CORE.md
   reserved? This draft assumes core (the ramp only works if free), but that's
   a business call.
5. **`--internal` naming/semantics** (A.4): flag, or a prompt-style refusal
   ("no DNS configured — pass --assume-public-boundary or --internal") the way
   `--auth none` forces the choice out loud?
6. **Pangolin API auth:** Traefik's API may require auth / be bound
   loopback-only in Pangolin deployments — is reusing `ports.Transport`
   (ssh-exec to loopback, as with the home Caddy admin) in zero-config mode
   worth the flag surface (`--ssh …`), or is that the point where we tell the
   user to write a settings file?
7. **Fixture provenance:** the NPM/Pangolin/cdp fixtures must be captured from
   real containers. OK to capture on CT120 (the crenel sandbox LXC) and check
   in anonymized, per the existing fixture discipline?

---

## 9. Decisions (maintainer, 2026-07-09)

All §8 questions resolved:

1. **No `scout` alias.** `audit <target>` is the single verb — the day-0 verb
   being the day-100 verb is the trust ramp.
2. **Exit 0 on an otherwise-clean foreign edge** (`foreign_managed_readonly`
   stays ok-severity). Cronning an audit of an NPM box must not page nightly
   for the box being an NPM box.
3. **Pasting a URL is consent to GET it.** Only the pasted target is ever
   contacted; everything beyond stays behind `--probe` (M-A6).
4. **The readers are core (Apache).** The trust ramp only works if free; the
   open-core seam is the compliance/audit LEDGER, not audit ability.
5. **`--internal` is a forced explicit choice**, `--auth none`-style: with no
   DNS configured, audit refuses until `--assume-public-boundary` or
   `--internal` is said out loud. (Lands with M-A6.)
6. **Zero-config stops at plain reachability.** Loopback-bound / authed
   Traefik APIs (Pangolin) are the line where the user writes a settings file
   — no `--ssh` flag surface in target mode.
7. **Fixture capture on CT120 approved**, checked in anonymized per the
   existing fixture discipline.
