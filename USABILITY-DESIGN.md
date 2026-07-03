# Crenel — Usability on a brownfield setup (design note)

This note nails three interacting semantics so Crenel is usable on a **real,
pre-existing** edge — the kind where the operator already has hand-built
`caddy-edge` + Caddy + AdGuard + Cloudflare config for the very hosts Crenel
would manage. It precedes the code. Three features, designed together because
they share one substrate (ownership):

- **A. Ownership & adoption** — `crenel import`: bring an existing UNMANAGED
  route/record under management without changing runtime behavior.
- **B. Persistence** — what survives if Crenel (or the edge) restarts, per
  driver, and a Caddy **on-disk** persistence option to close the admin-API gap.
- **C. Declarative apply** — `crenel apply <file>.yaml`: kubectl-style desired
  exposures that coexist with the imperative verbs, with brownfield-safe `--adopt`.

The two load-bearing invariants do not change: **live state is the only truth**
(no stored desired-state SOT), and **structural default-deny** (a host is
reachable iff an explicit route exists for it).

---

## 0. Two distinct notions of "managed" (the substrate)

Everything below hinges on separating two things the codebase currently
conflates only implicitly:

1. **Managed DOMAIN** (core/projection): a host whose *service* is in some edge's
   `origins`. This is already how `reconcile`'s managed boundary works
   (`anyFronts(serviceOf(host))`). It answers *"is Crenel responsible for this
   host?"* — derived from wiring config, costs nothing, persists nothing.

2. **OWNERSHIP marker** (driver/physical): the per-driver tag proving Crenel
   *physically wrote* a block — Caddy `@id: crenel-route-<host>`, Traefik
   `crenel-*` router/service keys, nginx `# crenel-managed:` comment. It answers
   *"did Crenel write this block?"* — read from live config.

The **brownfield gap** is exactly the case where these two disagree: a host is
in the managed domain (its service is in `origins`) **and** present on the edge,
but as an **unmanaged** block someone hand-wrote. Today Crenel can *observe* it
(`status` lists it; `reconcile` sees it satisfied and leaves it) but cannot
*manage its lifecycle*: a later `unexpose grafana` deletes by `@id
crenel-route-grafana…`, which 404-no-ops, the hand-written route survives, and
read-back-verify FAILS. Crenel sees the host but does not own it.

**Adoption closes the gap by stamping the ownership marker in-place** — same
backend, same behavior, only ownership changes — so the imperative verbs,
`reconcile`, and declarative `apply --prune` can all act on the host afterwards.

To make ownership legible to core, `model.Route` gains one field —
`Managed bool` — set truthfully by every driver's `normalize` from its marker.
This is read-only metadata; it changes no existing behavior (default `false`).

---

## A. Ownership & adoption — `crenel import`

### What it does

`crenel import` scans live across every edge, finds **unmanaged routes that fall
within Crenel's managed domain and match their configured origin**, previews
what it would adopt, and (per-item confirm, or `--yes`) stamps each driver's
ownership marker in-place. It is **idempotent**, **never changes runtime
behavior**, and **never touches anything outside the managed domain**.

### Detection & matching rules

For each edge, for each live route `r` with host `h`, service `s = serviceOf(h)`:

| Condition | Classification | Action |
|---|---|---|
| `r.Managed == true` | already owned | skip (idempotent) |
| edge does **not** front `s` (`s ∉ origins`) | outside managed domain | **never touch** (not even shown) |
| edge fronts `s`, `r` unmanaged, `r.addr == resolve(s)`, mode matches | **adoptable** | ADOPT (stamp marker) |
| edge fronts `s`, `r` unmanaged, `r.addr != resolve(s)` | **conflict (origin)** | report, do **not** adopt |
| edge fronts `s`, `r` unmanaged, mode differs from configured | **conflict (mode)** | report, do **not** adopt |

"Match" = **host + origin match**: the live route's backend address equals what
this edge's `OriginResolver` would resolve the service to (per-edge: the home
edge's LAN IP, the VPS edge's Tailscale IP). The resolver is the existing source
of the desired backend, so no new desired-state is introduced.

A **conflict** is a host the operator exposed *differently* than Crenel is
configured to expose it (wrong backend, or http where config implies
passthrough). Crenel refuses to adopt it, because adoption must be a no-op on
behavior and "fixing" the difference would change behavior. The operator
resolves the conflict explicitly (correct the `origins`, or `unexpose`/re-expose
deliberately).

### The ADOPT action per driver (behavior-preserving)

- **Caddy** (admin API): locate the http route whose host matches and that has
  **no** `@id` — **descending through nested `subroute` handlers** so a per-host
  route inside a wildcard zone (wildcard → subroute → per-host route) is adoptable,
  not just a flat top-level route — then `PATCH /config/apps/http/servers/<srv>/
  routes/<idx>[/handle/<h>/routes/<k>…]` with the same `match`/`handle` plus
  `@id: crenel-route-<host>`. Touches exactly that one route object at its real
  nesting depth; the deny, TLS, wildcard zone, and other routes are never read or
  rewritten. (The matching read is `normalize`'s nested recursion — see DESIGN.md
  "Caddy edge driver".)
- **Traefik** (file): re-key the unmanaged router → `crenel-<host>` and its
  service → `crenel-<host>`, preserving `rule`, `tls`, `middlewares`, `priority`,
  `entryPoints` verbatim (router name is an identifier, not behavior). Idempotent.
- **nginx** (file): insert the `# crenel-managed: <host>` marker line above the
  existing unmanaged `server {}` block, body preserved verbatim.
- **DNS (dnscontrol)**: **no ownership marker exists** — DNS managed-ness is
  *derived* from the `origins` projection, not stamped. A record matching a
  managed host is therefore **adopted by recognition** (already in the domain);
  there is nothing to mutate. A record whose value ≠ the edge address is a
  conflict. This asymmetry is **deliberate**: a DNS sidecar marker would
  reintroduce stored state and break the no-SOT invariant. (Documented, not a TODO.)

Each driver implements an optional `ports.Adopter` capability
(`Adopt(ctx, hosts) error`) — like `HealthChecker`, drivers that cannot stamp
ownership simply do not implement it (NetBird does not).

### The "leave as unmanaged" path

Adoption is **opt-in per item**. The preview lists every adoptable candidate;
interactive mode confirms each (`--yes` adopts all). **Declined candidates stay
unmanaged** — Crenel keeps *observing* them (they appear in `status`/`audit`/
`drift`) but will never rewrite or remove them. "Observe-only" is the default for
anything not explicitly adopted, which is the safe brownfield posture.

### Idempotency & safety

Re-running `import` after adoption finds those routes now `Managed` → nothing to
do. `import` only ever ADDS markers (never removes routes, never changes
backends, never reloads behavior). It cannot, by construction, take anything
down or expose anything new.

### Refuse to adopt what Crenel can't own (P0)

Adoption stamps Crenel's marker onto an existing route. That is only safe for a
route whose ownership Crenel can confirm is `unmanaged` (hand-written, no
generator). With the ternary ownership model (TOPOLOGY-RISK-REGISTER.md §4.5),
`import` and `apply --adopt` **refuse to stamp** a route classified `foreign` (a
generator — caddy-docker-proxy / NPM / Traefik labels / Pangolin — owns it: the
marker would be regenerated away, so adopting it is itself a MISMANAGE) or `unknown`
(ownership undetermined). Such a route surfaces as a `foreign_managed` /
`ownership_unknown` import conflict (blocked host for declarative apply), naming the
source to manage it at. A clean `unmanaged` route is still adopted normally. The
same gate (`core.gateOwnership`, `ErrRefuseToManage`) guards every *mutating* verb,
so neither `import` nor a later `expose`/`reconcile` can touch a foreign/unknown
route by mistake — `--yes` does not bypass it; `--force` covers `unknown` only.

---

## B. Persistence — what survives a restart, per driver

### "If Crenel goes away, what persists?"

| Driver | Mutation lands in | Survives edge restart? | Survives Crenel going away? |
|---|---|---|---|
| Traefik (file) | dynamic-config file on disk | **yes** (file provider re-reads) | **yes** |
| nginx (file) | nginx config file on disk | **yes** (`nginx -s reload`) | **yes** |
| dnscontrol (DNS) | the DNS provider | **yes** (provider is the store) | **yes** |
| NetBird | — (read-only) | n/a | n/a |
| **Caddy (admin API)** | **in-memory running config** | **NO** — `docker restart` reloads the on-disk Caddyfile and **drops crenel-managed routes** (proven on the live edge) | yes, until restart |

The Caddy admin API mutates the *running* config in memory. The mounted on-disk
Caddyfile is unchanged, so a restart reverts to it and crenel-managed routes
vanish. This is the one real persistence gap.

### The recovery story, and why `reconcile` cannot be it

`reconcile` derives its canonical set **from live**. If a Caddy restart drops
every Crenel route, live shows *nothing exposed*, so reconcile's canonical set is
empty and it has **nothing to re-add**. In the no-SOT model there is no stored
desired state to recover from. Therefore:

- **Persistence OFF** → the durable recovery source is the **declarative file**:
  re-run `crenel apply edges.yaml` to re-assert intent after a restart. (Feature
  C is the persistence story for an ephemeral-edge that has no file-on-disk.)
- **Persistence ON** → the on-disk Caddyfile *is* the durable store; Caddy
  reloads it itself on restart with **zero Crenel involvement**. True durability.

This is the sharp design statement: **for Caddy, durability comes from on-disk
persistence (B) or from re-applying a file (C) — never from reconcile.**

### The Caddy on-disk persistence option

Opt-in via `caddy_persist_path` (setting) / `--caddy-persist <path>` (flag).
Default **OFF** — keeps the zero-config fake/demo path simple and never assumes a
writable mounted Caddyfile. When set:

1. **After a verified admin-API apply** (core calls it *post-read-back-verify*,
   so only confirmed-live state is persisted), Crenel writes the current
   crenel-managed routes into the on-disk Caddyfile **additively**: it replaces
   only the block delimited by

   ```
   # crenel-managed-begin
   …crenel route blocks…
   # crenel-managed-end
   ```

   leaving every byte outside those sentinels — the operator's hand-written
   `import`/snippets/TLS/CrowdSec config — untouched.
2. **Validate first**: `caddy validate --config <path> --adapter caddyfile`.
   Never reload an invalid file.
3. **Reload with the correct invocation**: `caddy reload --config <path>` — the
   exact form diagnosed on the live edge. **Never** bare `caddy reload` (which
   targets the wrong/empty config and can wedge).
4. **Debounce**: one validate+reload per `Persist` call (per apply), never
   per-route — back-to-back reloads are the wedge trigger (a reload *storm*; see
   `DIAGNOSTICS-2026-06-27.md`). Persist coalesces the whole managed set into a
   single reload.

Persistence is a **best-effort durability step, not part of the apply
transaction**: the live apply has already succeeded and verified. A persist
failure is surfaced as a **warning** on the report (with the `caddy validate`
output) — it does **not** trigger rollback, because the running state is already
correct; only its durability is in question.

Implemented via an injected `CaddyCLI` (mirrors the dnscontrol `Shell` seam):
`Validate(path)` / `Reload(path)`, faked in tests so the repo never shells out.
The driver implements optional `ports.Persister` (`Persist(ctx) error`); core
calls it on participating edges after a verified apply.

---

## C. Declarative apply — `crenel apply <file>.yaml`

Declarative and imperative coexist. `apply` is a **point-in-time assertion** that
converges *the managed set* to a file — **NOT** a watched mirror. Live stays the
truth; nothing in the file is persisted as SOT.

### YAML support (and the zero-dependency constraint)

The repo is deliberately **zero-dependency / fully-offline** (it hand-rolls an
nginx brace tokenizer, a Caddyfile adapter, a Traefik rule parser rather than
take a dep). Adding `gopkg.in/yaml.v3` would break that. So Crenel ships a
**minimal YAML-subset decoder** (`internal/config/yaml`) scoped to exactly the
Crenel schema: block mappings, block sequences (`- `), 2-space nested
indentation, `key: value` scalars, `#` comments, optional quotes, lists in flow
(`[a, b]`) form. No anchors, flow maps, or multiline scalars. It is small,
bounded by a fixed schema, and unit-tested — in the same spirit as the existing
format parsers. JSON remains fully supported; the decoder is selected by file
extension (`.yaml`/`.yml`) or leading-`{` sniff.

This applies to **both**:
- **(i) provider/topology config** — `-config settings.yaml` decodes into the
  same `config.Settings` (edges, dns, origins, timeouts) as JSON does.
- **(ii) the desired-exposures document** — the `apply` file.

### The apply-file schema

```yaml
# crenel apply file — desired exposures (a point-in-time assertion)
zone: example.com
exposures:
  - host: grafana.example.com   # required (or derived from service+zone)
    service: grafana            # required: the origin/service key
    mode: http_proxy            # optional; default http_proxy
    edges: [home, vps]          # optional; default = every edge that fronts the service
    dns: [internal, public]     # optional; default = every configured scope
  - service: vault              # host derived as vault.<zone>
```

### Apply semantics

1. **Parse** the file → desired exposures. The engine is wired from `-config` as
   usual; the apply file supplies intent, not topology (topology can live in a
   YAML `-config`).
2. **Diff vs LIVE**: for each desired exposure, on each fronting edge, compute the
   route to add if not already live; aggregate DNS adds per scope. Merge into one
   **unified ChangeSet** across all exposures + edges + DNS.
3. **Preview** the whole plan, with **"⚠ ABOUT TO GO PUBLIC"** highlighted
   (reuses `computeNewPublic` over the union).
4. **All-or-nothing apply**: run the merged ChangeSet through the **same**
   ordered, transactional `buildSteps` → rollback machinery as `Apply` (edges
   before public-DNS on expose; any step failing rolls back every applied step).
5. **Read-back-verify** every desired host is reachable in its mode and the deny
   holds on each edge; on failure, roll back.

Apply is **additive by default** (it exposes what the file declares and live
lacks; it does **not** remove live hosts absent from the file — no surprise
teardown). `crenel apply --prune <file>` additionally unexposes **crenel-managed
(owned)** hosts that are absent from the file — and **only owned ones**, never
unmanaged/adopted-elsewhere hosts (the ownership marker is the safety boundary).

### Brownfield interaction (no duplication)

A desired host that already exists **unmanaged** on the edge must not be
duplicated:

- **Default**: `apply` **refuses** that host with a clear error — *"`grafana…`
  exists unmanaged; run `crenel import` first, or `apply --adopt`"*. The default-
  deny ethos extends to ownership: don't write a second route next to a hand-built
  one.
- **`apply --adopt`**: adopts matching unmanaged entries **inline** (stamp
  ownership, per A's rules) as part of the apply, so the host becomes a managed
  no-op rather than a duplicate. Origin mismatch → conflict error (still no
  duplicate, no silent behavior change).

### Relationship to `reconcile` and `import`

- **`import`**: brings hand-built config under management (stamps ownership) so
  the others can act on it. Mutates ownership only.
- **`apply <file>`**: converges the **managed set → the file**, *at this moment*.
  Intent comes from the file, for the duration of the call only.
- **`reconcile`**: converges **live → the live-derived canonical set** (fixes
  half-applied double-writes, stale DNS). No file, no external intent.

Three non-overlapping jobs: `import` makes hosts manageable, `apply` sets intent
from a file, `reconcile` keeps what's live mutually consistent.

---

## New ports & types (all additive, dependency rule preserved)

- `model.Route.Managed bool` — ownership, set by each driver's `normalize`.
- `ports.Adopter` — optional edge capability: `Adopt(ctx, hosts []string) error`.
- `ports.Persister` — optional edge capability: `Persist(ctx) error`.
- `core.Import` / `core.ImportPlan` (adopt list + conflicts + already-managed).
- `core.ApplyDeclarative` over a parsed `[]Exposure` (+ `--adopt`/`--prune`).
- `internal/config/yaml` — minimal YAML-subset decoder.

core/model still import **no** driver; the new capabilities are interfaces in
`ports`, implemented in drivers, wired at `cmd`. The dependency-rule test stays
green.
