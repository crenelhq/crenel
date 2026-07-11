# Crenel — Design

> **Crenel** is a working name (a crenel is the open gap in a battlement's
> parapet — the deliberate opening you shoot through). All naming is centralized
> in `internal/config/naming.go` so a rename is one find/replace.

## What this is

Crenel is a **vendor-agnostic, live-state-authoritative CLI** for controlling
what a self-hosted **reverse-proxy edge** exposes to the network. You tell it
"expose service `foo`" or "unexpose `foo`"; it reads the **live** state of the
edge (and DNS), computes a diff, shows you exactly what changes — crucially
**what is about to become publicly reachable** — applies it, and then **reads
the state back to verify the change actually took effect**.

## The two load-bearing ideas

### 1. Live-state-authoritative — there is NO stored desired state / source of truth

Most infra tooling (Terraform, Ansible, GitOps) keeps a *desired state* in a file
that is "the truth," and reconciles the world toward it. Crenel deliberately does
**not**. There is no `crenel.yaml` that defines what should be exposed.

- The **only** truth is what the edge reports **right now** (`ReadLiveState`).
- **Desired state exists only transiently** as the command currently being run —
  modeled by `model.Op` (an `Expose` / `Unexpose` intent). An `Op` is **never
  persisted**. It lives for the duration of one CLI invocation and is discarded.
- This means Crenel can never "drift" from a config file, because there is no
  config file. `status` always tells the truth because it only ever reads live.

Consequence: every mutating command is `read live → plan vs live → apply →
**read live again and verify**`. We never trust our own intent; we re-derive
reality after acting.

### 2. Structural default-deny — exposure is opt-in, enforced by an invariant

A host is reachable **iff** an explicit `Expose` added a route for it. This is
enforced *structurally*, not by convention:

- Every `EdgeProvider` driver **must always render and report a catch-all
  default-deny** route. `LiveEdgeState` carries a load-bearing
  `DenyCatchAllPresent bool`.
- It is a **hard invariant** (checked in `audit`, asserted in tests): if the
  catch-all deny is ever missing from live state, that is a critical finding.
- Negative test: an un-exposed host is **never** reachable through the rendered
  config. Removing the last explicit route must still leave the catch-all deny.

### 3. Bounded honesty — Crenel never silently misreports (detect-and-declare-unknown)

The first two ideas keep Crenel safe **on the topologies it models**. The third
keeps it safe on the long tail it does **not**: Crenel's confidence is bounded by
what it actually **parsed** and **owns**, and any gap is surfaced — counted,
declared, mutation-blocking — never swallowed. See TOPOLOGY-RISK-REGISTER.md §4 (the
authoritative spec) and the "Detect-and-declare-unknown" section below. Three
mechanisms:

- **`LiveEdgeState.Unparsed`** — every driver's `normalize` EMITS an entry for
  anything it sees but cannot fully model (an unknown handler, an undescended
  subroute, an indirect backend) instead of dropping it. `Coverage()` / `FullyParsed()`
  make the gap measurable; `status`/`audit` report it first-class.
- **The default-deny DOWNGRADE** — a structural `default-deny` claim is a statement
  about the *entire* config, so it is reported **ENFORCED** only when `FullyParsed()`.
  With any unparsed routes it downgrades to **UNKNOWN (amber)** — an unparsed route
  could itself be a permissive catch-all, so Crenel cannot certify deny over config
  it did not read. The hard invariant is now *ENFORCED ⟹ FullyParsed*.
- **Ternary+ ownership + refuse-to-manage** — `Route.Ownership ∈ {Crenel, unmanaged,
  foreign, unknown}`. A pre-mutation gate in `core` refuses (loudly, before any driver
  `Apply`) to mutate a route/edge that is `foreign` (a generator owns it — an edit
  would be reverted) or `unknown`. `--yes` does not bypass; `--force` is a documented
  human-load-bearing escape for `unknown` only.

## Architecture — hexagonal (ports & adapters)

```
        cmd/crenel  ── wires concrete drivers into core (composition root)
            │
            ▼
        internal/core  ── preview / apply / audit / status engine
            │  (depends only on ↓)
            ▼
        internal/ports  ── EdgeProvider, DNSProvider, OriginResolver (interfaces)
        internal/model  ── pure types: Op, Upstream, LiveEdgeState, Record, ChangeSet
            ▲
            │  (drivers implement ports, depend on model — never on core)
   ┌────────┴───────────────────────────────┐
   ▼                  ▼                       ▼
 drivers/edge/caddy  drivers/dns/dnscontrol  drivers/origin/static
```

### Dependency rule (enforced)

- `internal/core` and `internal/model` **NEVER** import a driver package.
- Drivers depend on `internal/model` (and `internal/ports`) only.
- Concrete drivers are wired in exclusively at `cmd/crenel` (the composition
  root). This keeps the **open-core seam** clean: the proprietary value (extra
  drivers, richer audits) can be layered in at `cmd` without touching `core`.

A unit test (`internal/core/deps_test.go`) asserts the import graph so the rule
cannot silently rot.

## Core types (`internal/model`)

| Type | Role |
|------|------|
| `Op` | Transient imperative intent (`Expose` / `Unexpose` a service). The **only** "intent," **never persisted**. |
| `Upstream` | Where a route points: `ForwardToOrigin` (proxy to a resolved backend) vs `DirectBackend`, plus SNI / TLS-passthrough handling. |
| `LiveEdgeState` | Snapshot of what the edge reports right now: the set of exposed routes + the load-bearing `DenyCatchAllPresent bool`. |
| `Record` | A DNS record (name, type, value, scope internal/public). |
| `ChangeSet` | The computed diff (edge adds/removes + DNS adds/removes). Includes `NewPublic []string` — the "about to go public" highlight. |

## Ports (`internal/ports`)

```go
type EdgeProvider interface {
    Name() string
    ReadLiveState(ctx) (model.LiveEdgeState, error)
    Validate(ctx) error
    Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error)
    Apply(ctx, model.ChangeSet) error
}
```
**Hard invariant:** every `EdgeProvider` ALWAYS renders + reports the catch-all
default-deny on live. A host is reachable iff an explicit `Expose` added it.

```go
type DNSProvider interface {
    Name() string
    Scope() model.Scope            // internal | public
    DesiredRecords(op model.Op) ([]model.Record, error)
    Diff(ctx, desired []model.Record) (model.DNSChange, error)
    Apply(ctx, model.DNSChange) error
}
```
Delegates record reconciliation to `dnscontrol`.

```go
type OriginResolver interface {
    Resolve(serviceName string) (string, error)   // static map driver for M0
}
```

## Verbs (CLI)

| Verb | Kind | Behavior |
|------|------|----------|
| `status` | read-only | "What is exposed right now." Reads live edge (+ DNS) and prints. |
| `audit` | read-only | Live-only invariant + consistency checks: catch-all deny present on every edge; cross-edge exposure + **mode** consistency; TLS **SNI/host** match; public DNS for a mesh-grant (private) host; dangling DNS / DNS-less route; **public host with no forward-auth policy** (`public_without_auth`). |
| `preview expose\|unexpose <svc>` | read-only | Compute `ChangeSet` vs live, print it, **no apply**. |
| `drift` | read-only | Report divergence from the canonical exposed set (reconcile's detect half) — **no apply**. Exits non-zero when drift exists, so it slots into CI/cron (`crenel drift \|\| alert`). Where `audit` flags invariant/consistency findings, `drift` reports specifically what `reconcile` would change. |
| `expose <svc>` / `unexpose <svc>` / `set` | mutating | `preview → confirm (or --yes) → apply → READ-BACK-VERIFY each provider → report`. |
| `resume <expose\|unexpose> <svc>` | mutating | Re-drive an interrupted apply from live: diagnose which providers already match intent, complete the REMAINING delta (same all-or-nothing transaction), or roll back cleanly. No stored state — the delta is re-derived from live. |
| `reconcile` | mutating | Detect + fix **ALL** drift: converge every edge + DNS provider onto the canonical currently-exposed set (re-add missing managed routes, fix mode mismatches, add missing / remove stale managed DNS records) via the same all-or-nothing transaction. Preview → confirm (`--yes`). **Never touches unmanaged routes.** See "Reconcile" below. |
| `import [--dry-run]` | mutating (ownership) | **Adopt a pre-existing (brownfield) setup.** Scan live, find UNMANAGED routes that fall in the managed domain (their service ∈ `origins`) and match their configured origin, and stamp each driver's ownership marker **in-place** — same backend, same behavior, only ownership changes. Preview → confirm (`--yes`); `--dry-run` previews + exits non-zero if anything is adoptable. Idempotent; never touches anything outside the domain; cannot expose or remove. See USABILITY-DESIGN.md §A. |
| `apply <file> [--adopt] [--prune]` | mutating (declarative) | **kubectl-style.** Diff the file's desired exposures vs LIVE → preview ("about to go public" highlighted) → all-or-nothing apply + read-back-verify. A point-in-time assertion, **not** a watched mirror (live stays truth). `--adopt` adopts matching unmanaged entries inline; `--prune` unexposes owned hosts absent from the file. See USABILITY-DESIGN.md §C. |
| `init [file]` | scaffold | Write a starter apply/exposures YAML (and a settings stub) to bootstrap a new setup. |
| `export <file>` | read-only dump | Dump current live state to a file. Throwaway; **never read back**. |

## Caddy edge driver

- **Read** live state via admin API `GET /config/` (against the **fake** in
  tests), normalize routes, **detect the catch-all deny**.
- **Nested subroute recursion.** A real edge does not list per-host routes flat:
  it routes a wildcard host into a `subroute` that nests further —
  `wildcard (*.homelab.example) → subroute → per-host route (vault.homelab.example)
  → subroute → leaf reverse_proxy` — down to the ~25 real services. `normalize`
  **recurses** through nested `subroute` handlers (`collectLeaves`) to enumerate
  each per-host LEAF: the real host (from the most-specific host matcher seen),
  the real backend dial (the leaf `reverse_proxy`, not the wildcard), ownership
  (the Crenel `@id` on the per-host route), and any forward-auth handler nested at
  that level. This turns the coarse "2 opaque wildcards" view into the real
  per-service view, so `status`/`audit`/`import` work at service granularity on a
  nested edge. **The default-deny reading is unchanged:** only a TOP-LEVEL
  host-less `reverse_proxy` is fail-open; a nested host-less `reverse_proxy` is
  scoped by its parent host matcher and inherits it as a leaf, and a
  wildcard-subroute-then-implicit-404 still reads as default-deny PRESENT. An
  opaque subroute that yields no resolvable leaf falls back to the `(subroute)`
  placeholder so visibility is never lost. `Adopt` recurses the same way to stamp
  the `@id` onto a per-host route nested inside a wildcard zone (the trial that
  surfaced this is `TRIAL-2026-06-27-real-vps-readonly.md`).
- **Apply** via `POST /load` (`text/caddyfile`), then **`GET /config/` again and
  verify** the change actually took.
- **CRITICAL:** a `200` from the admin API is **NOT** proof of application.
  Caddy can silently accept a reload that doesn't change the running config.
  We **always read-back-verify** — this models the real silent-reload footgun.
- **Two apply modes:**
  - *full-load* (default): render a managed Caddyfile from the driver's
    normalized model and `POST /load`. Simple, but a **full-config replace** —
    only safe on a greenfield/Crenel-owned edge, because it rebuilds solely from
    the understood, bare-`reverse_proxy` view. This is now a **structural refusal,
    not just a doc note**: `Apply` refuses a full-load whenever live holds anything
    a full replace would silently lose — any `Unparsed` construct (which would also
    falsely flip default-deny to ENFORCED), a surviving/added route carrying real
    forward-auth (which it would strip), or a TCP-passthrough route — directing the
    operator to `--granular`. (Safety review F1/F2; `fullLoadSafe`.)
    The **admin block** gets the same treatment (pihole-trial finding F1: a full
    replace with no `admin` global reverted a port-published admin socket to the
    localhost default mid-apply): a listen-only custom admin block is **carried
    through** the render as `{ admin <listen> }` and read-back-verified to have
    survived; an admin block carrying anything more (origins, enforce_origin,
    identity, …) has no faithful Caddyfile rendering, so the full-load is
    refused loudly. (`adminCarryListen`.)
  - *granular* (`WithGranularApply` / `--granular`): **additive** structured
    admin-API ops — insert each route at index 0 tagged with an `@id`, remove via
    `DELETE /id/crenel-route-<host>`. Never reads or rewrites routes Crenel does
    not manage (Authelia snippets, TLS/cert config, other vendors' routes stay
    byte-for-byte intact). **This is the mode required for any rich/real edge.**
    Proven by a test that exposes a host on a production-like fixture and asserts
    the unmodeled Authelia auth handler and all other routes survive.
    - **Insert nesting (WRITE-side mirror of `collectLeaves`).** *Where* index 0
      is depends on how the host's OWN zone is shaped on the edge — the write side
      MIRRORS the read side. On the real edges (VPS front + home) per-host routing
      lives **inside** wildcard `*.zone` subroutes
      (`srv0.routes[*.homelab.example].handle[subroute].routes[…]`) with **no** flat
      top-level per-host routes, so a flat top-level insert misplaces the route
      relative to where `collectLeaves` enumerates it and where `unexpose`/`Adopt`
      target it by `@id` (the defect the live cross-chain trial surfaced).
      `httpRouteInsertPath` resolves the location **per-zone**:
      a wildcard `*.zone` subroute that COVERS the host (Caddy one-label
      semantics) → `PUT …/routes/<w>/handle/<h>/routes/0` (exact-host wins in
      order); a flat zone (a flat top-level sibling in the same zone) or a
      flat/greenfield edge → the historical `PUT …/servers/<srv>/routes/0`
      (back-compat — a mixed edge can route some zones via subroutes and keep
      others flat). It **refuses loudly** on a genuinely ambiguous insert (more
      than one wildcard covers the zone) or a zone entirely absent on an otherwise
      subroute-structured edge, rather than silently misplacing the route. Removal
      is unaffected: the `@id` index is global, so `DELETE /id/…` (and `Adopt`'s
      nested-path walk) act on the route at its nested depth. `Persist` mirrors
      only the managed routes read back (recursing) into the Caddyfile region, so
      it is independent of the route's JSON depth.
  - *layer4 passthrough* (`WithLayer4` / `caddy_layer4`, M11): renders
    `ModeTCPPassthrough` via the **caddy-l4** `layer4` app — an `@id`-tagged
    SNI-matched `proxy` route in a managed `crenel-l4` server (match `tls.sni`, raw
    TCP proxy, no TLS termination). **Capability-gated** (the plugin isn't in stock
    Caddy → refuse loudly without it) and **additive** (touches only the layer4
    server; the http routes / deny / TLS are never read or rewritten), so it
    requires granular apply. SNI passthrough therefore renders on BOTH data-plane
    edges (Caddy + Traefik).

## nginx edge driver (M12)

A **fourth** `EdgeProvider`, added to validate the port's breadth: another dumb
data-plane edge but a third config SHAPE — the nginx **brace DSL**, owned by
**comment markers** (`# crenel-managed: <host>`) rather than @id (Caddy) or
key-prefix (Traefik). Like Traefik it is file-based (no admin endpoint to wedge, so
no `HealthChecker`) and applies an **additive read-modify-write**: it parses the
config into top-level chunks, preserves every unmanaged `server`/`upstream` block
verbatim, regenerates only its own marker-tagged server blocks, and always renders
the structural default-deny (a `default_server` returning `444`). `core` drives it
unchanged (`TestCore_DrivesNginxEdge`), and it participates in multi-edge + reconcile
(`TestCore_NginxInHeterogeneousReconcile`). It expresses `ModeHTTPProxy` and refuses
passthrough/mesh loudly (nginx `stream`/`ssl_preread` passthrough would be a future
capability gate, mirroring Caddy's `layer4`).

## dnscontrol DNS driver

- Generate a `dnsconfig.js` using `!inside` / `!outside` tags (internal vs public
  scope).
- Shell out to `dnscontrol preview` / `dnscontrol push`. The shell is **mocked**
  in tests (a `CommandRunner` seam) so no real DNS is ever touched.

## Safety posture (M0)

Everything is exercised against **in-repo fakes/fixtures only**: a fake Caddy
admin API HTTP server, sample Caddyfile/JSON fixtures, and a mocked dnscontrol
runner. Crenel never connects to real infrastructure in any test.

## Cross-provider apply ordering (M3)

A unified ChangeSet aggregates EDGE + INTERNAL-DNS + PUBLIC-DNS. When applying, the
providers are ordered by an **exposure rank** — `edge (0) < internal-DNS (1) <
public-DNS (2)` — in the direction the op moves exposure:

- **Increasing exposure (`expose`)** applies low→high: **edge → internal-DNS →
  public-DNS**. Bring the route up *before* announcing the name to the world; the
  global public record is created **last**, only once the edge actually serves.
- **Decreasing exposure (`unexpose`)** applies high→low: **public-DNS →
  internal-DNS → edge**. Stop announcing to the world **first**, then tear the
  route down.

This minimises the dangerous window where a public name resolves to an edge that
won't serve it (or a live route the world can't yet find). Each provider is
**read-back-verified** after apply; a partial failure rolls the applied providers
back in reverse order (and skips a compensating edge reload if the edge admin API
is wedged — see POSTMORTEM.md). `NewPublic` (the "about to go public" highlight) is
computed in **core**, not per-edge-driver: publicness depends on DNS scope, which
an edge cannot know — a host "goes public" when it gains a public-scope DNS record
(or, when no public DNS is managed, when it gains an edge route).

## Multi-edge topology — home + VPS "double-write" (M4)

Crenel targets **N edges**, not one. A real deployment fronts a service at both a
**home** edge (proxying a LAN IP) and a **VPS** edge (proxying via Tailscale). The
single edge generalises to a topology of named edges; a single-edge config is just
the degenerate **N=1** case and behaves exactly as before.

**Model.** `Engine.Edges []EdgeBinding`, where an `EdgeBinding` is `{Name,
Provider, Fronts}`. `Fronts(service) bool` is the **projection predicate** (built
at `cmd` from that edge's origins): a host lands on an edge **iff that edge fronts
the host's service**. The per-edge `OriginResolver` (also from that edge's origins)
decides the **address** — so the home edge resolves `grafana → 10.0.0.5:3000` while
the VPS edge resolves the same service to a Tailscale `100.64.x` address. The
ChangeSet gains `Edges []EdgePlan` (one projected `EdgeChange` per participating
edge) alongside the driver-level single `Edge`.

**Projection.** `core.Plan` fans out: for each edge that fronts the op's service it
reads that edge's live state and plans against it, producing one `EdgePlan`. An
`expose` of a service no edge fronts is an error; a service fronted by several
edges double-writes to all of them.

**Cross-edge transaction (all-or-nothing).** `core.Apply` orders ALL edge steps at
the edge rank (so on `expose` every edge precedes public-DNS; on `unexpose`
public-DNS precedes every edge — the M3 exposure-rank rule, preserved). Each edge
is applied and **read-back-verified independently**. If ANY edge (or DNS) fails, or
any read-back fails, the whole transaction rolls back: the generic compensator list
unwinds every applied edge + DNS in reverse. **Wedge safety is per-edge** — before
firing a compensating reload into an edge, that specific edge's health is probed;
a wedged edge's compensator is skipped (with a recovery hint) while every other
edge still rolls back. One wedged edge never blocks unwinding the rest.

**Status / audit.** Both report **per edge**. Audit adds a **cross-edge
consistency** check: a host exposed on one edge but missing from another edge that
*also fronts it* is a half-applied double-write (warning). The default-deny
invariant is checked on **every** edge, and the dangling-DNS check considers a host
exposed on **any** edge as backed.

**Heterogeneous edges.** The topology can mix drivers — e.g. a Caddy home edge and
a Traefik VPS edge — because everything goes through the `EdgeProvider` port. Proven
in `internal/core/multiedge_test.go`.

## Chain topology — front edge → downstream edge (CHAIN)

The M4 multi-edge model above is **parallel**: several edges each front the same
service independently (a "double-write" — home AND VPS both proxy `grafana`). A real
deployment also has a different shape: a **CHAIN**, where one edge sits *in front of*
another. the maintainer's real VPS edge is the front of such a chain — it terminates TLS and
proxies onward to a **downstream home edge** (`10.0.0.13`) that is where
forward-auth (Authelia) is actually enforced. The front (VPS) edge carries **no auth
handler at all**; auth happens one hop downstream.

**Why the distinction matters.** Crenel's `public_without_auth` posture check assumes
the edge it reads is the *terminal* enforcement point: a public host with no auth
there is exposed unprotected. On a **front** edge that assumption is wrong — the host
*is* authenticated, just downstream — so the warning fires **spuriously** for every
host on the chain. (This is exactly what the read-only trial saw: both wildcard zones
flagged `public_without_auth` even though the services behind them are authenticated
at the home edge.)

**Minimal mitigation (built).** A per-edge attribute, `auth_downstream`
(`EdgeSettings.AuthDownstream` / `Settings.AuthDownstream` → `core.EdgeBinding.
AuthDownstream`), marks an edge as the front of a chain whose auth lives downstream.
For an edge so marked:

- **`audit` suppresses `public_without_auth`** for that edge's (non-mesh) hosts —
  auth is *asserted* to live downstream — and emits one informational
  `auth_downstream` finding naming the suppressed hosts (suppression with a reason,
  never a silent drop). A genuine **terminal** edge leaves the flag false, so the
  warning still fires.
- **`status` labels** those hosts `auth: downstream` (core overlays
  `model.AuthDownstream` on the route's display auth; a route with a *real* auth
  reference read from live keeps its own policy — real auth wins). The overlay is
  display-only (computed on a copy; live state is untouched).

It changes **nothing** about routing or the default-deny — it is purely a posture
assertion about *where* in the chain auth is enforced. Centralized in
`EdgeBinding.effectiveAuth`, so `status` and `audit` agree. It remains the
FALLBACK assertion for a chain whose downstream edge Crenel cannot read (below).

### Chain-aware model (P4 — BUILT, read-correctness)

The `auth_downstream` flag above is a blunt instrument: it BLANKET-suppresses
`public_without_auth` for *every* host on the front edge, asserting (never
verifying) that each is protected downstream. That is safe against cry-wolf but
not *correct*: a host the downstream edge serves with **no** auth is silently
asserted protected. P4 promotes the chain to a **first-class, OBSERVED**
relationship: when Crenel can read the downstream edge, it FOLLOWS THROUGH each
forwarded host to its real backend + the auth actually enforced there, and resolves
exposure by **observation** — only falling back to the flag's assertion when the
downstream is genuinely unreadable.

**Chain ≠ parallel multi-edge.** The two edge topologies are distinct and modeled
distinctly:

- **Parallel multi-edge (M4, "double-write").** The *same* service is fanned to
  *several* edges at once, each independently fronting it to its own backend (home
  AND vps both reverse-proxy `grafana`). Projection (`Fronts`) decides which edges
  participate; an Expose lands on all of them; audit cross-checks them for a
  half-applied write. The edges are PEERS.
- **Chain (P4).** A host enters at the public **front** edge and is **forwarded**
  to a **downstream** edge that resolves it further (real per-host routing + auth).
  The front's backend for that host *is another edge*. The edges are SEQUENTIAL:
  front → downstream → origin.

**How a chain is expressed in config.** A front edge names its downstream edge:

```jsonc
"edges": [
  { "name": "vps",  "driver": "caddy", "downstream_edge": "home",
    "downstream_address": "10.0.0.13", ... },   // the front
  { "name": "home", "driver": "caddy", ... }      // the downstream, a normal edge
]
```

- `downstream_edge` references another edge in the topology by name — the edge the
  front forwards to. Setting it marks this edge the **front of a chain**.
- `downstream_address` (optional) is the address the front dials to reach the
  downstream edge. A front leaf route whose backend **host** matches it is a CHAIN
  FORWARD (its true destination is downstream); a leaf that dials anything else is a
  TERMINAL origin the front serves itself. Omitting it treats *every* non-mesh
  data-plane route on the front as a forward (the "pure front" case — the front does
  nothing but relay downstream).

Single-edge and parallel-multi-edge configs set neither field and behave **exactly
as before** — the chain path is inert without `downstream_edge`.

**How a forwarded host is represented.** The front edge's driver still reads its
leaf honestly — `vault.homelab.example → 10.0.0.13:443` is live truth at the
front. Chain resolution is a **core** concern (driver-free, like the ingress/auth
overlays): core recognizes the leaf dials the downstream edge and attaches a
`model.ChainLink` to the route (`Route.Chain`), recording the downstream edge and —
when read — the host's REAL backend + observed auth there. So a route is no longer a
terminal `(host → addr)`; a forwarded route is `(host → downstream-edge → real
backend, auth: observed)`.

**Following through.** Core reads the downstream edge's live state, indexes it by
host, and for each front chain-forward resolves the same host downstream:

- **Resolved** (downstream readable + routes the host) → `ChainLink{Resolved:true,
  DownstreamAddress, DownstreamAuth}`. `status` shows the real destination
  (`vault → home: 10.0.0.7:8200`) and the **observed** auth; the host's chain auth is
  whatever the downstream enforces.
- **Unresolved — downstream readable but host not routed there** → `Resolved:false,
  Reason:"host not routed at downstream edge"`. The forward lands on an edge that
  drops it (a dangling forward / downstream-side deny) — surfaced, not assumed.
- **Unresolved — downstream unreadable** (read error, or `downstream_edge` names an
  edge not in the topology) → `Resolved:false, Reason:…`. Crenel declares the
  destination/auth **"downstream, not observed"** and falls back to the
  `auth_downstream` *assertion* (suppress with a reason), never a misread. A
  chain-target edge whose live read fails is read **tolerantly** (it degrades the
  front to unresolved + surfaces the target as UNKNOWN) instead of aborting the whole
  status/audit.

**Exposure + auth correctness in a chain.** A host is PUBLIC iff reachable from the
public front edge (unchanged — the front is the public boundary). Its AUTH is
whatever is enforced **anywhere along the chain**, resolved in priority order
(`EdgeBinding.effectiveAuth`, shared by `status` and `audit`):

1. a **real** auth reference read at the **front** edge wins (a host genuinely gated
   at the front keeps its real policy);
2. else, if the route is a **resolved** chain forward, the **observed downstream
   auth** — a downstream Authelia host reads `authelia` (PROTECTED **by
   observation**, no warning); a downstream **no-auth** host reads `""` and **IS
   flagged** `public_without_auth` (the correctness win — no longer blanket-
   suppressed);
3. else (an **unresolved** forward, or the legacy flag with no `downstream_edge`) the
   `auth_downstream` **assertion** (`auth: downstream`) suppresses the warning but is
   surfaced as asserted-not-observed.

Mesh-grant routes are identity-enforced and never annotated. The default-deny
invariant is untouched.

**Read-side boundary.** The follow-through above is READ-correctness: `status`/`audit`
observe a chain through to its downstream. The WRITE side — a single `expose`/
`unexpose`/`reconcile` that lands the coordinated entries across the front edge, the
downstream edge, AND DNS as one all-or-nothing transaction — is specified and built in
**"Cross-chain coordinated WRITE (P4-write)"** below. (Two-zone edges — one front
fronting two DNS zones — remain a related follow-on: per-service derivation/DNS still
assume one `zone`.)

### Cross-chain coordinated WRITE (P4-write — BUILT)

The read model recognizes a front-edge leaf that dials the downstream edge as a chain
forward. The WRITE side makes a single verb mutate the *whole* chain coherently:
**one `expose <host>` on a chain topology lands the coordinated entries across the
front edge + the downstream edge + DNS as ONE all-or-nothing, read-back-verified
transaction.** No more mutating a chain one edge at a time and hoping they agree.

**Per-participant changeset (projection).** A chain `expose` no longer treats the
front's leaf as terminal. Core projects the op across the chain into one `EdgePlan`
*per participant*, classifying each edge's ROLE for the service (`core/chain_write.go`,
`roleFor`):

- **terminal** — the edge directly fronts the service (the service ∈ its `origins`).
  It plans the real route to the resolved origin via its own driver `Plan`, carrying
  `op.Auth`. This is the edge that *serves* the host. In the maintainer's shape this is the
  **downstream/home** edge.
- **forward** — the edge is a chain FRONT (`downstream_edge` set) that does NOT
  directly front the service, but its downstream (transitively) participates. Core
  synthesizes a FORWARD route `host → downstream_address` (a `DirectBackend` dial, no
  auth — see auth placement) and the front's driver renders it. In the maintainer's shape this
  is the **front/vps** edge.
- **none** — neither; the edge is skipped.

The recursion (`participates`) supports a multi-hop chain (front → mid → home): `home`
is terminal, `mid`/`front` are forwards. A non-chain op (no `forward` participant)
projects exactly as before, so single-edge and parallel multi-edge are byte-for-byte
unchanged.

**Ordering (exposure-rank extended across the chain).** The chain's depth is a
refinement of the M3/M4 exposure rank: the deeper (more internal) the edge, the lower
its exposure rank. `buildSteps` adds a chain-DEPTH secondary sort key so that, within
the edge rank:

- **on `expose`** (increasing exposure): **downstream route → front route → public
  DNS LAST** — bring up the edge that actually serves the host, then the public-facing
  forward, and only announce the name to the world once *both* edges can serve it;
- **on `unexpose`** (decreasing exposure): the exact reverse — **public DNS → front →
  downstream** — stop announcing globally, tear down the public forward, then remove
  the backend route.

Depth is 0 for every edge in a non-chain topology, so the ordering collapses to the
existing `edge < internal-DNS < public-DNS` scheme with no behavior change.

**Auth placement in a chain.** Auth attaches at the edge that actually
terminates/serves the host — the **downstream** (terminal) edge — per the P4 OBSERVED-
auth model. So `expose <host> --auth <policy>` renders the policy on the downstream
route; the front's forward route carries **no** auth handler (it is a relay). The
read model already resolves this correctly (front forward → observed downstream auth).
The downstream read-back asserts the auth landed where it was attached (closing the
consolidation-pass auth-verify gap for this path).

**Front-leg upstream TLS (HTTPS downstream — TRIAL-FIX-4).** A real downstream edge
listens on TLS (`:443`), so the front must not merely relay HTTP to it — it terminates
the client's TLS and then **re-originates TLS to the downstream**, preserving the Host so
the downstream's host matcher routes the request. `chain_write.forwardRoute` sets
`Upstream.UpstreamTLS` from the downstream scheme — an explicit `downstream_scheme`
(`"https"`/`"http"`) wins, else it INFERS from a `:443` dial — and the Caddy driver
renders the forward's `reverse_proxy` with `transport {protocol:http, tls:{insecure_skip_verify,
server_name:{http.request.host}}}` + a request `Host: {http.request.host}`, **byte-faithful
to the edge's own working forward routes**. The `{http.request.host}` placeholder (not a
literal FQDN) carries the matched host through the wildcard, so one rendering serves every
forwarded host. A plain-HTTP downstream leaves `UpstreamTLS` false and renders a bare
`reverse_proxy` unchanged. Read-back parses `transport.tls` so the forward's TLS hop
round-trips, and `verify` asserts every TLS-planned forward reads back carrying it — the
front-leg analogue of the auth read-back. Without this the forward dialed the `:443`
listener over plain HTTP and got `400 "Client sent an HTTP request to an HTTPS server"` —
the gap the live cross-chain trial RUN 2 caught (the fake never opens a real TLS socket,
so only a live edge — or the structural render assertions added with the fix — surfaces it).

**Public-without-auth across the WHOLE chain.** The CLI guardrail keys on
`op.Auth` + the chain-wide "about to go public" (`NewPublic`, which for a chain counts
the front's forward route): a chain `expose` that would make `host` public with auth
**unspecified** is refused — there is no auth anywhere along the chain — unless the
operator makes an explicit choice (`--auth <policy>` attaches downstream, or
`--auth none` publishes it unprotected on purpose). `--yes` does not bypass it.

**Cross-chain rollback (all-or-nothing, wedge-safe per edge).** The transaction reuses
the existing `buildSteps` → ordered apply → read-back-verify → compensator/rollback
machinery — generalized only by the depth ordering. The front and downstream are both
ordinary edge steps with per-edge inverse compensators, so **ANY** failure (an apply
error, or a read-back that disagrees on either edge or DNS) rolls back **every** applied
participant in reverse order, leaving nothing half-applied on either edge. Rollback is
wedge-safe per edge: each edge's health is probed before its compensating reload; a
wedged edge's reload is skipped (with a recovery hint) while the others still unwind.

**Gate spans BOTH edges.** The refuse-to-manage gate already iterates every
participant's live ownership; the chain projection puts front AND downstream into the
changeset, so a `foreign`/`unknown` route on EITHER edge refuses the whole chain write.
It also checks a pre-existing foreign/unknown downstream host even when that edge's
planned change is a converge no-op (so a foreign downstream can't be fronted by a new
forward). `--yes` never bypasses; `--force` covers `unknown` only.

**Idempotency / adoption.** A chain `expose` where the front and/or downstream route
already exists (managed) is a no-op/converge, not a duplicate: each participant's
projection no-ops when its host is already present. A half-present chain (front route
present but downstream missing, or vice versa) converges the missing side only — the
same logic `reconcile` uses to fix a drifted chain, and `drift` reports a half-present
chain. Foreign/unknown on either edge is refused (gate, above), never adopted.

**Nesting on the real edge shape.** Both projected routes — the downstream
TERMINAL route (reverse_proxy + auth reference) and the front FORWARD route
(reverse_proxy → downstream, no auth) — go through the granular insert, so each
lands at the correct nesting on its edge: on the real front+home shape (both edges
route the zone via a `*.homelab.example` wildcard subroute) the terminal route nests
into home's subroute and the forward route nests into front's subroute, top-level
route count unchanged on both, read-back-verified at depth and removable by `@id`
there (`TestChainWrite_NestsAcrossWildcardSubrouteChain`; see the granular **insert
nesting** note under the Caddy driver). The flat-fake chain-write tests keep
exercising the back-compat flat insert, so both real edge shapes are covered.

**Honest boundary.** This builds the coordinated WRITE for a `caddy`-fronted chain
against fakes/fixtures (a live cross-chain write trial is a separate, later, backed-up
step). The front's forward dial is `downstream_address` verbatim, so a chain WRITE
requires it set (host:port) — a pure-front config (`downstream_address` empty, "forward
everything") is READ-only until an address is configured. The chain `Adopt` of a
pre-existing forward (stamping the front's leaf as a managed forward) reuses the normal
per-edge adoption; two-zone front edges remain the related follow-on noted above.

## Internal-scope services — declared internal-only in a split-horizon topology (INTERNAL-SCOPE)

Split-horizon architectures deliberately keep some hosts internal-only: internal
DNS records exist, the home edge routes them, but the public chain-front edge does
NOT forward them and public DNS must NEVER carry them. Before this feature crenel
had no way to say that — a service in a chain-downstream edge's origins projection
made drift demand a forward route on the chain FRONT (`missing_route` "half-present
chain") and made the public DNS desired set demand a record; the only escape was
keeping the service OUT of origins entirely (unmanaged, unverified).

### The declaration

An origins entry is polymorphic (`config.Origin`): a plain address string keeps
today's semantics byte-identically, and the structured form declares the scope:

```jsonc
"origins": {
  "grafana": "10.0.0.7:3000",                        // default: all scopes
  "ha": {"addr": "10.0.0.19:8123", "scope": "internal"}
}
```

(YAML uses the nested block-map form — the yaml subset deliberately has no flow
maps.) Parse errors are LOUD: an unknown scope value, a missing `addr`, or an
unknown key (a typo'd `scop`) refuses the whole config load — a security-relevant
declaration is never silently defaulted. `expose <svc> --to <addr> --scope
internal` persists the structured form, so the per-op flag becomes the standing
declaration. Scope is a property of the SERVICE: declaring it `internal` on one
edge and default on another is refused at wiring (`collectInternalScope`).
The aggregated set lands on `core.Engine.InternalScope`.

### Demand gates (what crenel stops asking for)

- **Public DNS**: `Plan` and `planReconcile` skip PUBLIC-scope providers for an
  internal-scope service — no desired record, no `missing_dns_record` demand, no
  corrective Add, an empty (alignment-preserving) DNS slot. An explicit
  `--scope/--dns public` on such a service is refused loudly (it contradicts the
  config).
- **Chain front**: `roleFor` yields `roleNone` instead of `roleForward`, which
  gates every consumer at once — `Plan` never synthesizes the forward, reconcile
  never demands the "half-present chain" route, `verifyReconcile` never expects it.
- **Internal legs unchanged**: the downstream edge still fronts the service
  terminally; its route and the internal DNS records stay fully managed, drifted,
  reconciled, and read-back-verified exactly as before.

### The guarantee (what an ack could never give)

The demand gates only stop crenel from *creating* public legs. Audit additionally
ENFORCES the declaration on every run — `internal_scope_public_exposure`,
severity **critical**, when an internal-scope service IS publicly reachable:

- an EXPLICIT public DNS record at its host (owned or foreign — the
  `CoverageReporter` view; someone published this exact name);
- an explicit route/forward for the host at a chain-FRONT edge;
- the host observed published by a tunnel/overlay ingress.

Wildcards get deliberate, documented treatment: a zone-wide public `*.zone`
wildcard covers every internal host *by construction* (often unavoidable in the
very architecture this feature serves), and with no public route the name resolves
to an edge that default-denies it — unreachable in practice, so wildcard-only
coverage alone is **no finding** (a permanent cry-wolf would train the operator to
ignore audit). The COMBINATION — public wildcard coverage AND a covering wildcard
forward at the chain front — is real reachability and raises the lower-severity
`internal_scope_wildcard_covered` **warning** note. Finding text always says what
to do: remove the record/route/ingress rule, or change the declared scope.

Reconcile deliberately never *removes* an offending public record/route: that is a
posture violation, not mechanical drift, so audit flags it for the human instead
of a mutating verb silently deleting a public name.

### Surfacing

`status` tags internal-scope hosts `[internal]` on the route line
(`Engine.InternalScopedHost`, mapped through the same `serviceOf` derivation the
projection predicates use, so tagging and gating can never disagree).

## Typed route Mode — expressible intent + loud refusal (M6)

A route carries a **`RouteMode`** (on `model.Upstream`, requested via `model.Op`):

| Mode | Meaning | Expressed by |
|------|---------|--------------|
| `ModeHTTPProxy` (default) | edge terminates TLS and reverse-proxies host→backend | Caddy, Traefik |
| `ModeTCPPassthrough` | edge routes by SNI, does NOT terminate TLS (L4) | Traefik (`tcp.routers`+`HostSNI`+`tls.passthrough`); Caddy via the `layer4` app (capability-gated `caddy_layer4`/`WithLayer4` + granular; refuses loudly without the plugin) |
| `ModeMeshGrant` | exposure is an identity-mesh ACL grant (WireGuard), not HTTP routing | NetBird |

The point is **honesty about capability**. A driver's `Plan` declares what it can
express and returns `model.ErrModeUnsupported` (wrapped, classifiable) for the
rest, instead of silently approximating — e.g. Caddy refuses passthrough and
mesh-grant; NetBird expresses its native grant and refuses HTTP-proxy. This makes
the previously-inexpressible SNI passthrough *representable as intent* (even with no
renderer yet) and lets the mesh edge do its native thing rather than only erroring.
Mode-specific intent the core `Op` doesn't model travels in `Op.Params` (e.g.
`mesh_grant` needs `Params["group"]`). CLI: `--mode http|passthrough|mesh` +
repeatable `--param key=value`. A mesh-grant exposure is identity-scoped, so it is
**never** counted as "about to go public".

## Forward-auth by reference — attach an auth policy, don't own the auth system (AUTH)

An exposure can attach a **forward-auth policy** (Authelia, Authentik, …) by
**reference**. The full semantics live in **AUTH-DESIGN.md**; the essence:

- **Policy by NAME, rendered as a per-driver REFERENCE.** `model.Op`/`Upstream`
  gain `Auth` (a provider-agnostic policy name). Each driver renders its own
  reference — Caddy a granular auth **gate** (a `vars` policy marker + a VALID
  `reverse_proxy`+`handle_response` forward-auth gate, either the canonical expansion
  of a configured authorizer endpoint or an operator-pasted verbatim handler; and
  `import <snippet>` on the on-disk persistence path), Traefik a named middleware
  (`<policy>@file`), nginx an `auth_request` to a configured location — resolved from
  `auth_policies` in provider config (with default conventions). **Crenel never embeds
  the auth provider's internals** (verify URL, headers, cookies) — the canonical gate
  renders only operator-DECLARED fields (`caddy_forward_auth[_verify_uri/_copy_headers]`)
  and the verbatim path renders the operator's exact handler; the operator owns the
  snippet/middleware/location. The mapping is injected at `cmd` (like origins), so
  core/model stay driver-free.
  - **Caddy granular emits VALID admin-API JSON, never a synthetic handler.** The earlier
    `{"handler":"forward_auth"}` was a Caddyfile directive masquerading as a JSON module —
    no real Caddy registers it, which atomically aborted the first live cross-chain WRITE
    (`TRIAL-RESULT-chain-write-2026-06-28.md`). A snippet-only granular policy is now
    refused loudly (the admin API can't express an `import`), and `caddyfake` provisions
    inserted handlers so a wrong render fails the suite. See AUTH-DESIGN.md §2.1.
- **Orthogonal to default-deny.** Default-deny = *is it routed to the world at
  all*; auth = *who is allowed once routed*. Crenel owns routing and ATTACHES a
  policy; it does not own the auth system.
- **Mode interaction.** HTTP-proxy supports auth; SNI/TCP passthrough **errors
  loudly** (no HTTP layer to forward-auth at); a mesh grant is identity-enforced so
  auth is N/A (refused). Centralized in `model.ValidateAuth`.
- **Adoption preserves auth verbatim** (unchanged) and `normalize` now *recognizes*
  it read-only (Crenel's own `vars` marker round-trips the policy name; a hand-built
  gate — `reverse_proxy`+`handle_response`, the real Authelia shape — or a stock
  `authentication` handler surfaces as `(detected)`). The Caddy read model SKIPS the
  gate's authorizer `reverse_proxy` when finding the leaf backend, so a forward-auth'd
  route reports its real service, not the authorizer.
- **Safety guardrail.** Exposing a host **public with no auth** is a loud, explicit
  choice: the CLI refuses `expose`/`apply` unless `--auth <policy>` or `--auth none`
  (`auth:`/`auth: none` in a file) — `--yes` does not bypass it — and `audit` adds a
  `public_without_auth` warning for any public host with no auth policy. Never
  silently publish an unprotected service.

## Brownfield usability — import, declarative apply, Caddy persistence (UB)

Three features make Crenel usable on a real pre-existing edge; the full semantics
live in **USABILITY-DESIGN.md**. The substrate is a clean split between the
**managed DOMAIN** (a host whose service ∈ an edge's `origins` — the projection,
already used by reconcile) and the **OWNERSHIP marker** (Caddy `@id`, Traefik
`crenel-*` key, nginx comment; DNS has none — managed-ness is projection-derived).
`model.Route.Managed` surfaces ownership; optional `ports.Adopter`/`ports.Persister`
capabilities carry the new behavior; the dependency rule is unchanged.

- **`import` (adoption).** Stamp the ownership marker onto an existing UNMANAGED
  route in-place — host + origin match required, behavior never changes, nothing
  outside the domain is touched. Closes the lifecycle gap (an un-owned route could
  not be cleanly `unexpose`d). See §A of the design note.
- **`apply <file>` (declarative).** Diff a file's desired exposures vs LIVE →
  preview ("about to go public" highlighted) → all-or-nothing apply (same
  `buildSteps`/rollback as Apply/Reconcile) → read-back-verify. A **point-in-time
  assertion**, not a watched mirror; the file is intent only for the call's
  duration (no stored SOT). Additive by default; `--adopt` adopts matching
  unmanaged hosts inline (no duplication); `--prune` unexposes **owned** hosts
  absent from the file (never unmanaged ones). Files are JSON **or** YAML — the
  in-repo `internal/config/yaml` subset decoder reuses the `json:` tags, keeping
  the build zero-dependency. See §C.
- **Caddy on-disk persistence.** The admin API mutates in-memory config, so a
  `docker restart` drops Crenel routes. Opt-in `caddy_persist_path` additively
  writes crenel-managed routes into the mounted Caddyfile (sentinel-delimited),
  `caddy validate`s, then reloads with the correct debounced invocation. See §B.
  Durability for Caddy comes from this OR from re-running `apply` — never from
  `reconcile` (which is live-derived and has nothing to recover from after a wipe).

Three non-overlapping jobs: `import` makes hosts manageable, `apply` sets intent
from a file, `reconcile` keeps what's live mutually consistent.

## Reconcile — detect + fix ALL drift (M10)

`reconcile` is the operator-grade convergence verb. Where `resume` finishes ONE
interrupted op and `audit` only *reports*, `reconcile` makes the entire topology
self-consistent in one all-or-nothing transaction.

**Canonical exposed set (the "should be true", derived from live).** With no stored
desired state, the truth reconcile converges toward is itself read from live: the
**union** of managed hosts exposed across every edge. For each such host, its
**canonical mode** is the mode it carries on the FIRST edge (topology order) that
exposes it — the *primary-edge view*. A host should then be exposed, in that mode,
on **every edge that fronts its service**, and have its DNS records in every managed
scope.

**The managed boundary (load-bearing safety).** Reconcile only ever considers hosts
within Crenel's **managed domain** — a host whose service is fronted by some edge
(its origins-derived projection). Routes and DNS records *outside* that domain
(Authelia, dashboards, other vendors, hand-created records) are never read into the
canonical set, so they are never added, removed, or re-rendered. Reconcile also
**never deletes an edge route outright** — it only adds missing routes and
re-renders modes — so it cannot tear anything down by mistake. (The single
top-level edge with no explicit projection is treated as crenel-owned — the same
ownership assumption the full-load apply already makes; for a *shared* rich edge,
configure explicit `edges:` with origins so the projection scopes the managed set.)

**What drift `reconcile` FIXES vs what `audit` only FLAGS:**

| Drift | `audit` finding | `reconcile` |
|-------|-----------------|-------------|
| Managed route missing from an edge that fronts it | `edge_inconsistent_exposure` (warn) | **re-adds** the route (per-edge address resolved by that edge's own resolver) |
| Host exposed with a mode ≠ canonical (primary-edge) | `edge_mode_mismatch` (warn) | **re-renders** it in the canonical mode (fails loudly if a driver can't express it) |
| Managed host exposed but with no DNS record | `edge_route_without_dns` (warn) | **adds** the missing record |
| Managed DNS record for a host exposed on no edge | `dns_without_edge_route` (warn/crit) | **removes** the stale record |
| Catch-all default-deny MISSING (fail-open) | `deny_catchall_missing` (**critical**) | flag only — a permissive *unmanaged* catch-all is an operator/edge fix; reconcile won't touch unmanaged config |
| SNI/cert name ≠ route host | `sni_host_mismatch` (warn) | flag only — a cert-issuance concern, not a route presence/mode one |
| Public DNS record for a mesh-grant (private) host | `public_dns_for_mesh_grant` (warn) | flag only — an ambiguous intent conflict a human resolves |
| DNS record VALUE drift (right name, wrong target) | not checked | not fixed (presence/absence + mode only) — future work |

**Mechanics.** `reconcile` re-uses the existing apply pipeline: it builds one
corrective `EdgeChange` per drifted edge (a mode re-render is a Remove+Add of the
same host — drivers apply removes before adds so the canonical render wins) and one
`DNSChange` per provider, then runs them through the **same ordered, all-or-nothing
transaction** (`buildSteps` → apply → read-back-verify → wedge-safe rollback) as
`Apply`. Read-back verification asserts convergence directly: every managed host an
edge fronts is reachable in its canonical mode (deny present), and every DNS
add/remove actually took. Any failure rolls the whole transaction back.

## Visual identity & status surface (`internal/ui`)

The branded terminal surfaces live in `internal/ui`, a **presentation layer** that
depends only on view types and writes to an `io.Writer` — it is never imported by
`core`/`model`, preserving the dependency rule (a `cmd`-side concern, like the
drivers). It is pure and deterministic, so rendering is unit-tested.

- **Crenellated wordmark.** A brutalist 5x5 block font whose top edge is a
  battlement (merlons on a parapet, crenel gaps between) — the logo *is* the
  default-deny "solid wall with deliberate gaps". One grid (`WordmarkRows`) feeds
  both the ANSI renderer and the SVG generator so they can't diverge.
- **Semantic color.** Color carries meaning, never vibe: **green** =
  safe/private/verified, **amber** = about to go public / drift, **red** =
  fail-open / unexpectedly exposed. Roles (`Sem`) map to ANSI truecolor and to the
  SVG palette; color is emitted only when enabled (the plain/NO_COLOR/non-TTY path
  returns text unchanged). See `../brand/BRANDING.md`.
- **The status HUD is the real `status` output.** `crenel status` derives a
  `HUDModel` from the read-only `StatusReport` + `DetectDrift` and renders it as a
  compact colored header (default, on a TTY) or a full "CORE MATRIX // EXPOSURE
  STATE" banner (`--hud`/`--banner`). Fields are Crenel's actual domain: EXPOSED
  (n public — publicness via the same rule as `computeNewPublic`), DEFAULT-DENY
  (per-edge `DenyCatchAllPresent`), DRIFT (canonical-set divergence), EDGES
  (`name·driver`), DNS (split-horizon scopes), LAST APPLY (`unknown` — no persisted
  desired state; live is the only truth). `--plain`/`--json`/a pipe keep output
  scriptable. `docs/brand/crenel-status-hud.svg` is the same HUD as an SVG — the early
  read-only-dashboard mock (S5 drawn ahead).

## Detect-and-declare-unknown — the universal safety net (P0)

The full rationale is TOPOLOGY-RISK-REGISTER.md §4 (authoritative); this is the
shipped shape. The principle: **Crenel must be structurally incapable of silently
misreporting.** When it meets a handler, routing construct, ingress mechanism, or
ownership situation it cannot fully parse or confirm, that uncertainty becomes
first-class output — counted, surfaced, and mutation-blocking — not swallowed. This
converts almost every dangerous "confident-but-wrong" answer (a MISREAD-↓ by
omission, a MISMANAGE on a generated config) into a loud declared unknown.

- **Parser carries unknowns.** `LiveEdgeState` gained `Unparsed []Unparsed`
  (`{Locator, Kind, Reason, RawExcerpt}`), plus `Generator` / `IngressKind` and the
  `Coverage()` / `FullyParsed()` accessors. Every driver's `normalize` now EMITS an
  `Unparsed` entry instead of dropping anything it cannot model:
  - **Caddy** — an unmodeled terminal handler (`file_server`, `php_fastcgi`, a
    `vars`/`map`-indirect backend), a subroute whose leaves don't resolve, and a
    **top-level host-less subroute** (not descended — it could nest a permissive
    catch-all). `collectLeaves` threads an unparsed accumulator + a locator path.
  - **Traefik** — a router whose host(s) it can read but whose service has no
    resolvable upstream → `backend_indirect`.
  - **nginx** — a vhost it can see (`server_name`) that does not `proxy_pass`
    (static/fastcgi/return) → `handler_unrecognized`.
- **Ternary+ ownership.** `Route.Managed bool` is augmented by `Route.Ownership ∈
  {Crenel, unmanaged, foreign, unknown}` (`Managed == (Ownership == Crenel)`).
  `OwnershipFromMarker` maps the legacy marker bool to crenel/unmanaged; generator
  detection (`foreign`) and genuine ambiguity (`unknown`) layer on top (P2).
- **Default-deny downgrade (load-bearing).** A `default-deny` claim is a statement
  about the *entire* config, so `DenyState()` reports **ENFORCED** only when
  `FullyParsed()`; present-but-unparsed downgrades to **UNKNOWN (amber)**; absent is
  **MISSING (critical/fail-open)**. `audit`'s deny check is ternary (`audit`'s hard
  invariant is now *ENFORCED ⟹ FullyParsed* — deny is never *falsely* certified),
  `status` and the HUD render the amber UNKNOWN state.
- **Refuse-to-manage on ambiguous ownership.** A pre-mutation gate in `core`
  (`gateOwnership`, `internal/core/gate.go`) runs BEFORE any driver `Apply` for every
  mutating verb: it refuses (`ErrRefuseToManage`) to touch a `foreign` route/edge
  (naming the generator and pointing at the source) or an `unknown` one. `--yes` does
  not bypass (it skips *are-you-sure*, not *this-will-silently-break*); `--force`
  (`Engine.Force`) is the documented escape for `unknown` only — never `foreign`.
  `import`/`apply --adopt` likewise refuse to stamp a marker onto a foreign/unknown
  block (adopting one is itself a MISMANAGE); a clean `unmanaged` route is still
  adoptable.
- **Surfacing.** `status` prints a coverage line ("read N/M routes — K NOT
  UNDERSTOOD — exposure status INCOMPLETE"), a first-class "⚠ Not understood" section
  (locator + kind + reason), and FOREIGN-MANAGED / INGRESS header annotations; `--json`
  carries `unparsed[]` / `generator` / `ingress_kind`. `audit` adds
  `coverage_incomplete`, `ownership_unconfirmed`, and `ingress_external` findings (the
  last fires for any EXTERNAL `IngressKind` — tunnel/overlay/unknown). Ingress posture
  is resolved by core (`core/ingress.go`) from an edge's declared `ingress_kind` or a
  scanned cloudflared/Tailscale config (`ingress_config_path`); an externally-fronted
  edge Crenel can't classify is declared `unknown`, never assumed internal.

This is additive and dependency-rule-preserving. Each later parser improvement
(subroute recursion, tunnel modeling, chain auth) simply MOVES routes from `Unparsed`
into `Routes` — measurable as coverage climbing toward 100%.

## Transport / Connection — HOW Crenel reaches an edge's admin API (TRANSPORT)

The `EdgeProvider` port answers *what API shape* an edge speaks (Caddy admin JSON,
a Traefik file, an nginx config). It does **not** answer *how Crenel physically
reaches* that API. Until now there was only one answer, hardcoded: "open an HTTP
client to a configured `admin_url`," and any plumbing to make that URL reachable (an
SSH tunnel, a published port) was the operator's out-of-band problem. That made
**connection an implicit, hardcoded fourth axis** of the architecture — and it forced
a real wall: the maintainer's home Caddy admin API binds **container-localhost only and is not
published anywhere**, so no host can open an HTTP client to it. The cross-chain write
trial had to choose between publishing the admin (Option B) or hand-rolling an SSH
tunnel (Option A) — both manual, out-of-band setup the tool didn't model.

The **Transport port** makes connection a first-class, pluggable axis alongside
`EdgeProvider` / `DNSProvider` / `OriginResolver`. The Caddy driver makes the *same*
admin calls; the Transport decides how each call physically travels.

### The port

```go
// internal/ports
type Transport interface {
    // Do issues ONE admin request and returns the HTTP status, response body, and a
    // transport error. A nil error with a non-2xx status means "we reached the admin
    // and it answered <status>" — the driver interprets the status. A non-nil error
    // means we could NOT obtain an HTTP response at all (the channel failed). Do MUST
    // honor ctx's deadline/cancellation and MUST NOT outlive it — every admin call is
    // bounded by the driver's read/write timeout, and the wedge/hang lessons
    // (POSTMORTEM) apply to EVERY transport. On a deadline it returns an error that
    // wraps context.DeadlineExceeded (or a net.Error timeout) so the driver classifies
    // it as ErrAdminUnresponsive exactly as before.
    Do(ctx context.Context, method, path, contentType string, body []byte) (status int, respBody []byte, err error)
}
```

This is a deliberately thin HTTP-semantics RPC — it covers everything the Caddy
driver does: `GET /config/` (read), `POST /load` (`text/caddyfile` or json),
`PUT`/`PATCH`/`DELETE` granular `/config/` and `/id/` ops, and the `Healthy` probe.
The method/path/content-type/body are exactly what the driver already passes through
its single `doAdmin` seam, so the refactor is mechanical.

**Layering.** `Transport` is an infra/driver concern, wired at `cmd`. `core`/`model`
never import it (the dependency-rule test still passes). The Caddy `Driver` holds a
`ports.Transport` instead of constructing its own `*http.Client`; `doAdmin` keeps the
per-op timeout *and* the error classification (so `ErrAdminUnresponsive` stays in the
caddy package — no import cycle) and simply delegates the wire call to the transport.
The implementations live in **`internal/drivers/transport`** (`Direct`, `SSHExec`,
`SSHTunnel`), each implementing `ports.Transport`.

### Implementations

**`direct` (default — zero behavior change).** Real HTTP to `admin_url`, exactly
today's code moved behind the port: `http.NewRequestWithContext` → `client.Do` →
read body. `caddy.New(adminURL, …)` builds a `Direct` by default, so **every existing
config and test that just sets `admin_url` (or a fake URL) behaves identically** — the
transport is invisible unless you opt into another. This is the back-compat anchor.

**`ssh-exec` — run the admin call as a COMMAND on the far end, hitting the admin on
its own loopback.** This is the clean answer to a loopback-bound, unpublished admin:
no port published, no tunnel. The operator configures an **exec command prefix** —
an argv list Crenel does *not* shell-parse — that lands a shell wherever the admin
loopback lives, supporting arbitrary nesting:

```
["ssh","root@pve1","pct","exec","113","--","docker","exec","-i","caddy","sh"]
```

Crenel builds a small POSIX-`sh` script that runs `curl` (or `wget`) against the
admin's own loopback URL (default `http://127.0.0.1:2019`) and **feeds that script to
the prefix command over STDIN** — *nothing crosses a shell-parse boundary as an
argument*, so quoting survives arbitrarily nested `ssh → pct exec → docker exec`
chains (the classic failure of building one giant quoted `sh -c '…'` string). The
request body is **base64-embedded** in the script (`printf %s '<b64>' | base64 -d |
curl --data-binary @- …`) so a Caddyfile/JSON body with spaces, quotes, or newlines
travels safely. The status code is captured with `curl -w 'CRENEL_HTTP_STATUS:%{http_code}'`
appended after the body; Crenel splits on that marker.

Error classification is explicit and three-way:
- **admin-non-2xx** — the marker is present, so curl reached the admin and it answered;
  return `(status, body, nil)` and let the driver handle the status (same as direct).
- **transport-unreachable** — the marker is ABSENT (ssh failed, the host/container is
  down, curl couldn't connect, a binary is missing): return `ErrTransportUnreachable`
  enriched with the exit code + stderr.
- **wedge-timeout** — ctx deadline fired: return an error wrapping
  `context.DeadlineExceeded`, which the driver maps to `ErrAdminUnresponsive` with the
  usual recovery hint — so a wedged admin behind ssh-exec is bounded exactly like a
  direct one.

The exec is injected through a `Runner` seam (default `OSRunner` shells out;
`exec.CommandContext` so ctx kills the whole chain). Tests inject a fake Runner
(asserts the exact generated argv + script and returns canned IO — fully hermetic) and
a guarded integration test runs the REAL `sh`+`curl` against the in-process caddy fake
admin (skips if the binaries are absent). **No live infra in any test.**

`docker-exec` and `pct-exec` are not separate transports — they are just shorter
exec-prefix templates of the same `ssh-exec` (drop the `ssh` hop, or the container
hop). A future **`agent`** transport (a small crenel-side daemon co-located with the
admin, speaking a thin RPC) is noted but not built.

**`ssh-tunnel` — Crenel opens the local-forward itself, then talks `direct` over it.**
Automates the manual Option-A tunnel. Crenel runs `ssh -N -L
127.0.0.1:<local>:<remoteHost>:<remotePort> <target>` as a **managed child process**
(not `-f`, so the lifecycle is Crenel's), waits for the forward to accept connections
(bounded), then routes every `Do` through an internal `Direct` pointed at the local
forwarded port. Lifecycle is crenel-managed: the tunnel opens lazily on first use and
is **closed on teardown** (wired into the `cmd` cleanup chain, like the fake admin
API's `Close`) — ephemeral to the Crenel invocation, no manual `ssh -fN` left running.
The ssh process is injected through a `Forwarder` seam; tests use a fake Forwarder
that points the inner `Direct` at the in-process caddy fake and asserts
open-once/use/close, so the lifecycle is proven against fakes with no real ssh.

### Config

Each edge gains an optional `transport` block (top-level `Settings` for the single
edge, and per-edge on `EdgeSettings`):

```jsonc
"transport": {
  "type": "ssh-exec",                 // "direct" (default) | "ssh-exec" | "ssh-tunnel"
  // ssh-exec:
  "command": ["ssh","root@pve1","pct","exec","113","--",
              "docker","exec","-i","caddy","sh"],
  "admin_url": "http://127.0.0.1:2019", // admin URL AS SEEN FROM the far end
  "curl": "curl",                       // far-end http client (curl | wget)
  // ssh-tunnel:
  "ssh_target": "root@10.0.0.13", "ssh_identity": "~/.ssh/id_ed25519",
  "local_port": 12019, "remote_host": "127.0.0.1", "remote_port": 2019
}
```

**Back-compat is the contract:** an edge with just `admin_url` and **no** `transport`
block (or `type: "direct"`, or omitted) behaves *exactly* as today — a `Direct`
transport to `admin_url`. Single, multi-edge, and chain configs are unchanged; the
transport is purely additive. Only the Caddy (admin-API) driver consumes a transport;
file-based drivers (Traefik/nginx) and the mesh driver are untouched.

### Why this is the right shape

- It removes the implicit fourth axis: "how do I reach this admin" becomes declared
  config, not out-of-band operator plumbing.
- It reaches a **loopback-only, unpublished** admin with **zero port exposure and no
  tunnel** (`ssh-exec`) — so the home edge stays exactly as locked-down as it is now,
  which is precisely the maintainer's two-edge access constraint.
- It preserves every safety invariant uniformly: the bounded-timeout / never-hang
  guarantee, read-back-verify, and the classified wedge error all hold *through* every
  transport, because they live in the driver above the transport seam.
- It lets the live cross-chain WRITE trial run over `ssh-exec` instead of the manual
  Option-A tunnel + temporary home-admin publish — no home-admin change at all (see
  TRIAL-PLAN-chain-write.md).

## Durability — the persistence model (DURABLE-PERSIST)

An admin-API edge (Caddy) mutates its config IN MEMORY. Whether that change SURVIVES a
control-plane restart depends entirely on what the control plane BOOTS from — and the
admin API carries **no marker for the boot source**: a `GET /config/` cannot tell you
whether Caddy booted from a Caddyfile, a JSON file, or `--resume`. So "will this write
survive a restart?" is a **detect-and-declare** property, exactly like ingress: declared
from config, never inferred from the wire, and **never assumed durable**.

### The persistence model is a first-class, surfaced property

`model.PersistenceModel` classifies each edge:

| Model | Meaning |
|---|---|
| `durable-config` | a file provider (Traefik/nginx) — the file it writes IS the boot config; already durable. |
| `durable-file` | an admin-API edge whose in-memory writes Crenel ALSO reconciles into the on-disk boot config (a mounted Caddyfile/JSON), so a restart reproduces them. |
| `resume` | the control plane boots with Caddy's `--resume`; admin writes autosave durably with no Crenel action (operator-declared). |
| `ephemeral-admin` | an admin-API edge with NO durable path — in-memory writes are LOST on restart. **The safe default for a bare Caddy admin edge.** |
| `unknown` | Crenel cannot determine the model — declared, treated as ephemeral-for-warning (never assumed durable). |

The driver sets it on `LiveEdgeState.Persistence` (Caddy: `durable-file` when a persist
path is configured, `resume`/`durable` when declared, else `ephemeral-admin`; Traefik/
nginx: `durable-config`). It is surfaced three ways, folding durability into the
detect-and-declare net:

- **status** prints a `Durability:` line per edge; an ephemeral edge is flagged
  (`writes are LIVE-only — a control-plane restart DROPS them`).
- **audit** raises an `ephemeral_writes` warning when an ephemeral edge actually holds
  crenel-managed routes (something a restart would lose) — silent on a brownfield edge
  Crenel only reads (the operator's own config persists their routes; nothing of
  Crenel's is at risk).
- **the write path** (`ports.DurabilityReporter`) records a `PersistWarning` when a
  verified write lands on an ephemeral edge — the loud, at-the-moment declaration that a
  change won't survive a restart.

This closes a real DURABILITY MISREAD: trusting an admin-API `200` and calling the write
done, when the change is live but ephemeral.

### The durable reconcile — no second source of truth

The flagship use case (rename/move a service: `archive → files.homelab.example`) requires
a coordinated write to **survive a restart**. The home edge boots from
`/etc/caddy/Caddyfile` (`--adapter caddyfile`, no `--resume`), so durable persist must
reconcile the **live admin JSON** into that **on-disk Caddyfile** such that a restart
(which re-adapts the Caddyfile) reproduces exactly what is live — **without inventing a
second desired-state SOT that can drift**. The guarantee that makes "no second SOT"
literally true: the Caddyfile edit is **proven to re-adapt to the live managed state
before it is committed**. The on-disk config is a *verified mirror* of live, not an
independently authored truth.

**Why the wildcard-faithful path (not the flat sentinel persister).** The home Caddyfile
routes EVERY service through wildcard site blocks (`*.homelab.example { … }`) with per-host
`@name host X` + `handle @name { reverse_proxy … }` pairs. The existing flat persister
appends a top-level `host {}` site — which is MORE specific than the wildcard, **shadows**
it, and (lacking the wildcard's `tls { dns cloudflare }`) breaks cert issuance. So a
managed host's durable form is a per-host handle **inside** the covering wildcard site,
where it inherits that site's TLS and listener. Crenel owns only a sentinel-delimited
region inside the site, labelled `@crenel_<host>` (the Caddyfile analogue of the admin-JSON
`@id crenel-route-<host>` marker); every operator byte outside it is preserved.

**The reconcile pipeline** (`caddy/persist_caddyfile.go`; a bad candidate NEVER touches
the live boot file):

1. **partition** the managed routes by covering wildcard zone (+ a flat group for any
   host no wildcard covers); **REFUSE** a host an operator block already owns on disk
   (adopt it via `import` instead — the refuse-to-manage gate at the durability layer).
2. **render** the candidate: replace/insert Crenel's sentinel region inside each zone
   (faithful `import <snippet>` auth and `https://` upstream-TLS forms).
3. **self-check**: parse Crenel's own region back out and assert it reproduces exactly
   the managed routes — a render bug fails HERE, before any disk write.
4. **validate** the candidate (`caddy validate`).
5. **adapt cross-check** (`caddy adapt` the candidate → normalize → assert every managed
   host resolves to the SAME backend + auth posture as live) — the "a restart reproduces
   the same state" proof. Auth equality is by *posture* (enforced vs not), since the
   live route carries the policy name while the on-disk `import` re-adapts to a gate read
   as `(detected)` — both enforced.
6. **write** the candidate to the boot path + **reload** once.

Two safety gates beyond the managed-host match (both proven by the live trial):

- **No-drift-loss gate.** The reload (and any restart) re-derives the WHOLE live config
  from this Caddyfile, so the cross-check ALSO asserts every host that is live NOW is
  reproduced by the candidate's adaptation. A live-only route (added via the admin API but
  never written to the Caddyfile) would be silently dropped by the reload — Crenel refuses,
  naming the host. This makes durability safe-by-construction, not safe-by-discipline.
- **Durable unexpose by host-match.** After a durable persist's reload, the live route is
  re-derived from the Caddyfile and carries **no JSON `@id`** (a Caddyfile `handle` block
  has none), so a delete-by-`@id` is a no-op and the route would survive an unexpose
  (failing read-back-verify — the rollback the live trial hit). On a durable-file edge the
  driver therefore sweeps by **host match**: it locates the route (flat, or nested in the
  covering `*.zone` subroute — never the wildcard itself) and deletes it by config path.
  Scoped to durable edges and short-circuited when the `@id` delete sufficed, so
  non-durable behavior (and the never-hang wedge model) is byte-for-byte unchanged.

If the re-adaptation does not reproduce a managed host, persist **refuses** — restores
nothing (it never wrote), declares the write still ephemeral, and warns. Durability is
best-effort and OUTSIDE the apply transaction: the running state is already correct and
verified; only its durability is in question, so a persist failure is a WARNING, not a
rollback.

**The two-channel reality (the home edge).** The boot Caddyfile lives on the LXC HOST
(`/opt/stacks/caddy/conf/Caddyfile`, bind-mounted **read-only** into the container), but
`caddy validate/reload/adapt` must run INSIDE the container. So a durable persist crosses
TWO exec channels, each an operator-supplied argv prefix Crenel does not shell-parse (the
script travels over stdin, exactly like the ssh-exec admin transport):

- the **file channel** (`ExecConfigStore`) — a shell on the host that holds the file
  (`ssh root@pve1 pct exec 113 -- sh`) for `cat` / atomic `base64 | mv`;
- the **caddy channel** (`ExecCaddyCLI`/`ExecAdapter`) — a shell in the container
  (`… docker exec -i caddy sh`) for validate/reload/adapt.

Both are injected seams (`ConfigStore` / `CaddyCLI` / `Adapter`): the local filesystem +
local `caddy` is the on-box default; the exec-backed seams are the home-edge wiring
(config block `caddy_persist`, see `examples/settings-durable-home.json`). Like the
transport's `OSRunner`/`OSForwarder`, the REAL exec is never run by the unit suite — the
Runner is faked and the tests assert the exact generated argv + script; a live durable
write is a separate, GO-gated trial.

## Secret redaction — mask secrets in OUTPUT, never in apply (SECURITY)

Crenel reads and writes the FULL edge config, which can carry real secrets —
Cloudflare DNS-01 tokens, ACME account keys/email, basic-auth hashes, forward-auth
secrets (full inventory in **SECURITY.md §1**). Those bytes can reach a printed
status excerpt, a JSON dump, an error echo, or an export. The hardening rule:

> **Redaction applies ONLY to operator-facing OUTPUT. The apply / read-back-verify /
> preserve-unmanaged paths MUST keep using REAL values** — Crenel has to write the
> operator's real config and verify the edge against the real live state. Redaction
> is a *presentation* transform at the output boundary, never on the data Crenel acts
> on.

- **`internal/redact`** — a value-aware leaf package (imports nothing of ours, so the
  dependency rule is untouched). Detection is a conservative **key** match
  (`token`/`secret`/`password`/`api_key`/`private_key`/`email`/… — not bare `key`)
  PLUS a **value** heuristic (PEM private keys, bcrypt/argon hashes, JWTs, `Bearer`/
  `Basic` auth-scheme credentials) so a secret under an unexpected key is still
  caught. `JSON()` walks structurally and preserves non-secret routing fields;
  `Text()`/`Snippet()` handle truncated/invalid JSON (a bounded `RawExcerpt`, an
  admin-API error body). Masks long values to `••••<last4>`, short ones to `REDACTED`.
- **Applied at the CLI boundary only** (so core/drivers stay real-valued and the apply
  path is structurally unable to see a masked value): `status --json`'s
  `Unparsed.RawExcerpt` (the P0 declared-unknown excerpts can capture secret bytes —
  an nginx auth header, a basic-auth hash); error messages that echo admin-API config
  bytes (a Caddy `/load` rejection echoes the offending config); the rollback-error
  prints; and `export --redacted`.
- **`--show-secrets`** (default off) is the documented escape hatch to print raw
  values on a trusted terminal. The real error/report values are never mutated — only
  what is printed is masked — so programmatic callers and the apply/verify tests see
  real bytes.
- **Backups/exports** are written `0600` and hold REAL values by default (a redacted
  snapshot is not restore-grade); `export --redacted` writes a secret-free copy for
  sharing. The restore-grade backup (DEPLOY-VPS.md) deliberately keeps real bytes.

The guarantee is tested both ways: each output surface masks by default (and
`--show-secrets` reveals), AND a granular `expose` alongside an unmanaged basic-auth
secret leaves that secret BYTE-INTACT in live config (apply/preserve uses real
values; redaction is output-only). See **SECURITY.md** for the full threat model.

## Milestones

> This list is the historical build order. For the authoritative current-state map
> (what's solid vs stubbed vs known-risk + the remaining backlog) see
> **STATE-OF-CRENEL.md**; for the per-increment narrative see **archive/BUILD_LOG.md**.
> Everything below is **BUILT** unless explicitly noted.

- **M0** — scaffold + model + ports + fake Caddy admin API; read-only
  `status`/`preview`; mutating `expose`/`unexpose` with read-back verify +
  structural default-deny; dnscontrol DNS driver (internal scope); `audit` +
  `export`.
- **M1** — transactional apply: compensating **rollback** (inverse action per
  provider, built against a pre-apply snapshot; `Engine.Rollback` default on) +
  additive **granular** Caddy apply (the fix the live-test surfaced).
- **M2** — second edge driver: **Traefik** file provider (the port holds for a
  second dumb data-plane edge; see STRAIN.md).
- **M3** — public DNS scope + the unified cross-provider plan/apply with
  exposure-rank ordering.
- **M4** — **multi-edge** topology (home + VPS double-write): projection,
  cross-edge all-or-nothing transaction, per-edge wedge-safe rollback.
- **M5** — **NetBird** mesh edge (third driver): reads, and refuses mutation
  loudly — the port's LIMITS handled honestly.
- **M6** — typed **route Mode** (`http_proxy`/`tcp_passthrough`/`mesh_grant`):
  expressible intent + loud `ErrModeUnsupported` refusal.
- **M7** — **resume** verb: re-drive an interrupted apply from live state.
- **M8** — richer **audit**: TLS/SNI + mode-enabled cross-provider checks.
- **M9** — TCP/SNI **passthrough** renderer on Traefik (`tcp.routers`).
- **M10** — **reconcile** verb: detect + fix ALL drift across the topology.
- **M11** — Caddy **layer4** passthrough renderer (SNI passthrough on both edges,
  capability-gated).
- **M12** — **nginx** fourth edge driver (a third config shape; breadth-validates
  the vendor-agnostic claim).
- **M13** — **drift** verb: reconcile's read-only detect half (CI/cron check).
- **AUTH** — forward-auth by reference (`--auth`, per-driver references,
  `public_without_auth` guardrail). See AUTH-DESIGN.md.
- **USABILITY (UB1–UB4)** — brownfield `import` (adoption), declarative `apply`
  (+ JSON/YAML), Caddy on-disk persistence, `init`/quickstart/release. See
  USABILITY-DESIGN.md.
- **BRAND** — crenellated wordmark + the status HUD as the real `status` surface.
- **TRIAL-FIX** — nested-subroute recursion + chain `auth_downstream` posture flag
  (from the real-VPS read-only trial).
- **P0 — Detect-and-Declare-Unknown** — the universal safety net (`Unparsed[]`,
  ternary `Ownership`, default-deny downgrade, refuse-to-manage gate). See
  TOPOLOGY-RISK-REGISTER.md §4 / "Detect-and-declare-unknown" above.
- **P1.5** — multi-server Caddy: `normalize` reads **all** `http.servers` (folds
  fully-modeled forwarding siblings; flags forwarding-but-unmodeled ones
  `UnknownServerBlock`; ignores benign redirect/static siblings).
- **P2** — generator/foreign-ownership detection: **NPM**, **Traefik
  label/orchestrator providers**, **Pangolin** (Traefik `badger` middleware), and
  **caddy-docker-proxy** (on-disk `Caddyfile.autosave` / declared hint — the admin API
  has no marker) detected read-only → `OwnForeign` → gate refuses.
- **P3** — tunnel/overlay ingress: typed `IngressKind` + `External()`; core overlays a
  declared/detected (cloudflared/Tailscale) posture onto status + audit; an
  unclassifiable external front is declared `unknown`. Detection/surfacing done;
  per-host public/private recovery from the tunnel's rules remains.
- **P4 (READ)** — chain-aware model: `downstream_edge` + `model.ChainLink`
  follow-through; auth resolved by OBSERVATION (status real downstream dest; audit
  observed `public_without_auth`); honest "downstream, not observed" when unreadable.
- **P4-write** — cross-chain coordinated WRITE: one `expose`/`unexpose`/`reconcile`
  lands/tears the front-forward + downstream-route + DNS as ONE ordered (downstream →
  front → public-DNS), read-back-verified, all-or-nothing transaction; auth attaches at
  the serving (downstream) edge; gate spans both edges; chain-wide public-without-auth;
  half-present chains converge. See "Cross-chain coordinated WRITE (P4-write)".
- **TRANSPORT** — pluggable connection axis: a `ports.Transport` the Caddy admin driver
  uses for ALL admin calls, with `direct` (default; zero behavior change), `ssh-exec`
  (run the call as a nested-exec curl against a loopback admin — no port, no tunnel),
  and `ssh-tunnel` (crenel-managed local forward) implementations. See "Transport /
  Connection" above.
