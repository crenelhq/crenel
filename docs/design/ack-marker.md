# Crenel — the `ack` marker

> Operator acknowledgment of an intentionally-unmodeled route, expressed as a
> marker on the route itself in the live config. Lets `default-deny` be
> **certified** without hiding anything: a route Crenel can't fully understand is
> either an unaddressed unknown (deny stays UNKNOWN, correctly) OR an
> operator-vouched carve-out (deny certifies, and the carve-out is surfaced as
> its own visible state — never silently green, never silently red).
>
> Status: **implemented (partial), first shipped batch.** The maintainer's
> idea; the crux (§3) is his catch. See **§11 Implementation status** for
> exactly what shipped vs. what §9's original rollout sketch proposed — read
> §11 before relying on any per-driver claim below, since a couple of
> specifics (esp. §5's Traefik row) changed shape during implementation.
>
> Companions: **docs/DNS-DESIGN.md §11a** (the `managed-by:crenel` ownership
> marker — the pattern this proposal directly generalizes), **STATE-OF-CRENEL.md
> §5h / §6 item P5** (the "declared-unknown, safe-not-silently-wrong"
> path-granular gap this closes the long tail of), **docs/WHAT-CRENEL-DOES.md**
> (live-state-authoritative + default-deny framing).

---

## 0. TL;DR

- **Problem.** Crenel refuses to certify `default-deny ENFORCED` while any live
  route is unparseable (bounded honesty, invariant 3). That's correct — but some
  of those routes are **intentional** operator-vetted carve-outs. Today the
  operator has no way to say "I know, this one's deliberate — acknowledge it,"
  which means either (a) live with `UNKNOWN` forever, or (b) rewrite the config
  into a shape Crenel understands (not always possible or desirable).
- **Solution.** An **`ack` marker written into the live config on the route
  itself.** A route stamped `crenel-ack:<reason>` is treated as an
  operator-acknowledged, intentionally-unmodeled route: it is EXCLUDED from the
  deny-blocking set (so `default-deny` can certify), and STILL surfaced in
  `status`/`audit` as its own distinct **"acknowledged-unknown"** state — its
  own colour, its own count, never hidden.
- **The elegant part (this is the crux).** Crenel has **no stored desired
  state** — a marker cannot live in a crenel-owned sidecar because there is no
  sidecar. It doesn't need to. It lives **in the infra** (as a Caddy `@id`, a
  Traefik label, an nginx comment) and Crenel re-reads it every run. It
  "persists for next time" **for free**, by the same trick the ownership marker
  already uses (docs/DNS-DESIGN.md §11a). The philosophy holds unchanged.
- **UX.** The marker can be added by hand (it's a plain string), and a proposed
  `crenel ack <host>[/<path>] --reason "..."` verb stamps it end-to-end (preview
  → apply → read-back, same posture as `expose`), plus `crenel unack`. `status`
  shows an ack'd route as `ACK` (a deliberate operator-vouched state — neither
  verified-green nor fail-open-red); `audit` reports `acknowledged-unknown: N
  route(s)` as a first-class line.
- **Not a substitute for P5.** P5 (path-granular modeling) teaches Crenel to
  *understand* common shapes natively — fewer routes will ever need acking.
  `ack` handles the genuine long tail: an idiosyncratic carve-out Crenel will
  never model, or one the operator doesn't want it to.

---

## 1. Problem — the honest P5 gap

Crenel's third invariant is **bounded honesty (detect-and-declare-unknown)**:
anything `normalize` cannot fully parse becomes a *declared unknown*
(`Unparsed`) — counted, surfaced, and (for ownership/ingress kinds)
mutation-blocking. `DenyState()` is a ternary that returns `ENFORCED` **only**
when the state is `FullyParsed()` (no `Unparsed` entries). Otherwise it
downgrades to `UNKNOWN`. This is right and load-bearing: a route Crenel doesn't
understand could be a bypass, a shadow, or a legitimate carve-out — and it is
never safe to *assume* which. So `default-deny` cannot certify.

The P5 backlog item (STATE-OF-CRENEL.md §6 item 6, §5h item A/C) closed the
worst class of this: a path/method/header-scoped route used to be SILENTLY read
as a host route (dropping the matcher — a MISREAD-↓); now Caddy, Traefik, and
nginx all DECLARE such a route `matcher_conditional` (`UnknownMatcher`). Deny
downgrades to `UNKNOWN` instead of falsely certifying `ENFORCED`. **That is the
safe posture, and it is the correct one for a route Crenel truly doesn't
understand.**

But some of those declared-unknown routes are **intentional**. The motivating
example is live on the maintainer's edge, in the shape §5h item A explicitly describes:

```caddyfile
# home edge, docker-exec transport
app.homelab.example {
    # tailnet agents post here — bypass Authelia for this path
    handle /api/webhook/* {
        reverse_proxy app:8080
    }
    # everything else is Authelia-gated as usual
    forward_auth authelia:9080 { ... }
    reverse_proxy app:8080
}
```

Crenel now correctly reads this route as **`matcher_conditional`** — it saw the
`handle /api/webhook/*` matcher, it can't fully model per-path routing yet
(that's P5-WRITE), and rather than silently drop the path constraint it
DECLARES the route unknown. Result:

- `crenel status` on the host edge reports `Coverage: N/N (1 declared unknown)`;
- `default-deny` is reported `UNKNOWN, not ENFORCED`;
- and the operator can't certify the edge is closed by construction — even
  though **the operator *knows* this carve-out is deliberate and safe**
  (tailnet-only agents; the path is scoped; the host is otherwise gated).

This is the honest gap. Crenel can't certify because it doesn't understand.
The operator DOES understand. Today, they have no way to tell Crenel that.

**What we need:** a way for the operator to say *"I know, this one's
deliberate — acknowledge it,"* that:

1. lets `default-deny` certify **as long as everything unparsed is
   acknowledged** (no bypasses, no silent green),
2. does **not** hide the carve-out — it's still surfaced in `status`/`audit` as
   its own state ("acknowledged-unknown"), so an operator or reviewer can
   always see the list of ack'd routes and the reasons,
3. does not require Crenel to grow stored desired state (that would break
   invariant 1 — live-state-authoritative),
4. is **scoped to the one route** — never a blanket "ignore all unknowns."

The rest of this doc is the proposal.

---

## 2. Solution — an `ack` marker that lives in the live config

Every Crenel edge driver already reads a per-route identifier or comment. The
`ack` marker is a small string the operator writes onto that same slot, of the
form:

```
crenel-ack:<slug>[:<reason-slug>]
```

- Caddy: the route's `@id`, e.g.
  `@id crenel-ack:webhook-tailnet-agents`.
- Traefik: a router label,
  `traefik.http.routers.app-webhook.crenel-ack=webhook-tailnet-agents`.
- nginx: a leading `# crenel-ack:` comment on the `location` block.

Crenel reads this in `normalize`, the same pass that today emits `Unparsed`.
When a route or subroute is going to be declared unknown (`matcher_conditional`,
`handler_unrecognized`, `subroute_not_descended`, or the sibling forwarding-
server `server_not_read`), the driver checks for the ack marker on the same
route/subroute node. If present, the `Unparsed` entry is emitted with a new
kind, **`acknowledged_unknown`**, carrying the operator's reason.

`DenyState()` then evaluates over the **effective unknown set** — the set of
`Unparsed` entries whose kind is NOT `acknowledged_unknown`. Once that set is
empty, deny can report `ENFORCED`. The `acknowledged_unknown` entries are still
counted, still listed, still shown by `status --json` and `audit` — just not
deny-blocking.

That's the entire mechanism.

### 2a. The states of a route (after this change)

| Route state | Deny | `status` renders as | Notes |
|---|:---:|---|---|
| Fully-parsed, understood | ENFORCED | `photos → home:8080 [auth: authelia]` | Today's normal path. |
| Understood but foreign-owned | ENFORCED (edge-wide refuse to manage) | `photos [foreign: cdp]` | P2. |
| Declared unknown, no ack | **UNKNOWN** | `app/api/webhook [unknown: matcher_conditional]` | Today's honest gap; safe but never certifies. |
| Declared unknown, **ack'd** | ENFORCED | `app/api/webhook [ACK: webhook-tailnet-agents]` | **New.** Certifies deny; still visible as ACK. |

The ACK row is deliberately its own colour in the HUD — not the verified-green
of an understood route, not the amber-alert of an unaddressed unknown. It reads
as **"operator-vouched"** and it lists the reason inline. That is the whole
point: the operator's assertion is preserved as a distinct, first-class state.

---

## 3. Why this fits the philosophy — the crux (this is the maintainer's catch)

Crenel has **no stored desired state**. The only truth is what the live edge
reports. So an obvious wrong shape for this feature would be a
`~/.config/crenel/acks.yaml` that lists ack'd routes: it would immediately
violate invariant 1 (a second source of truth that can drift), and every
consumer of Crenel would have to know about it and reconcile against it.

The `ack` marker doesn't need any of that. **It lives in the infra**, as a
marker Crenel re-reads every run. It "persists for next time" for free — the
next `crenel status` reads the live Caddy config, sees the `@id crenel-ack:…`,
and re-classifies the route as `acknowledged_unknown` without knowing anything
was persisted anywhere. The persistence *is* the config file.

**This is the exact same trick as the ownership marker.** The surgical
Cloudflare driver (docs/DNS-DESIGN.md §11a) stamps every record it creates with
`comment: managed-by:crenel host=<name>` and uses that comment as the safety
boundary — a record is Crenel's to manage iff its comment carries the marker.
There is no `crenel-managed-records.yaml`; there is no state file. The proof is
the record, and the record is on the box.

`ack` is the same pattern applied to a different question — instead of *"is
this Crenel's to manage?"* it answers *"has the operator acknowledged this
unknown?"* — and it inherits every property of the ownership-marker approach:

- **Live-state-authoritative.** Delete the marker in Caddy? The route reverts
  to unaddressed-unknown on the next read; deny goes back to UNKNOWN. There
  is no cached "Crenel thinks this is ack'd" — because Crenel doesn't cache.
- **Trivially inspectable.** `grep crenel-ack` on the Caddy config lists every
  acknowledged carve-out on the box; no Crenel tooling required. An operator
  auditing the edge sees them directly.
- **Zero migration.** Deploying Crenel on a new box picks up existing acks
  automatically. Removing Crenel from a box leaves the acks in place as
  self-documenting comments; the Caddy config still works.
- **No new invariant to defend.** The mechanism is a read-side classification
  rule (`Unparsed[]` grows a new `Kind`), not a new store, not a new
  ordering, not a new failure mode.

That's the elegant bit. The proposal is small because the pattern is right.

---

## 4. UX

### 4a. Manual — the marker is a plain string

The lowest form. An operator opens the Caddy config and adds `@id
crenel-ack:webhook-tailnet-agents` on the affected route, reloads Caddy, and
re-runs `crenel status`. The route now reads:

```
app.homelab.example                              [ACK: webhook-tailnet-agents]
    ↳ /api/webhook/* → app:8080  (declared unknown, acknowledged)
    ↳ / → app:8080  [auth: authelia]
default-deny                                                        ENFORCED ✓
```

`audit` grows a line:

```
acknowledged-unknown: 1 route
  · app.homelab.example /api/webhook/*  reason=webhook-tailnet-agents
```

This is enough for the operator who is comfortable editing the config directly.
The next two verbs are quality-of-life for the operator who'd rather Crenel do
the stamping.

### 4b. `crenel ack <host>[/<path>] --reason <slug>`

Stamps the marker on the target route in the live config, following the same
posture as `expose`:

1. **Read live** — locate the route (host or host+path); if there's no matching
   declared-unknown to attach the marker to, refuse loudly.
2. **Preview** — print the exact change ("stamp `@id crenel-ack:webhook-tailnet-
   agents` on `apps.http.servers.srv0.routes[3]`"), ask the operator to confirm
   unless `--yes`.
3. **Apply** — through the same admin/file transport the driver already uses
   (Caddy admin `@id` PATCH; nginx comment write; Traefik label add).
4. **Read-back-verify** — re-read the route and assert the marker is present
   AND the route is now classified `acknowledged_unknown` instead of the prior
   kind. If not, roll back per the driver's usual mechanism.
5. **Persist** — same durability posture as `expose`: on a durable-file edge
   the marker is durable by construction; on an ephemeral-admin edge the same
   `caddy_persist` reconciler that already makes `expose` survive a restart
   applies here (a one-line addition to the persist path).

`--reason` is required; the slug goes into the marker. A `--path` is required
whenever the underlying route is scoped by matcher (so an ack is always scoped
to what the operator actually meant — never a blanket "ack the whole host").

### 4c. `crenel unack <host>[/<path>]`

The exact inverse — removes the marker. The route reverts to whatever
`Unparsed` kind it had before (typically `matcher_conditional`), and deny
downgrades to UNKNOWN on the next read. `unack` on a non-ack'd route is a
clean no-op.

### 4d. Rendering — the "third colour"

The HUD, `status --plain`, and `audit` treat `ACK` as its own state:

- Not verified-green (that would hide the fact that Crenel doesn't model this
  route — the whole point of surfacing acks is that they *stay visible*).
- Not amber-alert (that would fire on the operator's own vetted carve-outs
  every run and normalize alarm-fatigue — the cry-wolf class §5h has been
  systematically closing).
- A distinct **operator-vouched** state — see the mock in §2a. The line always
  carries the reason, so a reviewer glancing at `status` reads what the ack is
  for at the same time they read that it exists.

`status --json` gains an `acknowledged_unknown` array parallel to the existing
`unparsed` array (both come from `Unparsed[]`; kinds distinguish). Machine
consumers stay stable.

---

## 5. Per-driver

The marker generalizes because every one of Crenel's driver backends already
has a per-route slot for identifiers or comments. The following table lists
the concrete carrier and any per-driver honesty notes.

| Driver | Ack carrier | Notes |
|---|---|---|
| **Caddy** | `@id crenel-ack:<slug>` on the route node | Same slot the ownership marker `@id crenel-route-<host>` uses. Admin-API round-trips it verbatim; `caddy adapt` preserves it; the durable-persist reconciler already round-trips `@id`. |
| **Traefik** | `traefik.http.routers.<name>.crenel-ack=<slug>` label (labels provider) OR a `# crenel-ack:` comment in file-provider TOML/YAML | Traefik ignores the unknown label at runtime. For file-provider edges the driver already re-keys Crenel routers by `crenel-*`; the marker is read from the same source. |
| **nginx** | Leading `# crenel-ack:<slug>` comment on the `location` (or `server`) block | Same slot family as `# crenel-managed:`; the nginx tokenizer already carries per-block leading comments through normalize. |
| **NetBird (mesh)** | **n/a** | The driver is read-only and refuses mutation loudly. Mesh grants have no ambient "unknown" class — there's nothing to ack. |
| **AdGuard Home (DNS)** | **not supported — honest limit** | The AdGuard control API's rewrite object is `{domain, answer}` only; there is **no per-record comment/metadata field** (docs/DNS-DESIGN.md §12a). We can't stamp a marker where the API has no slot. The proposal explicitly does NOT invent a shadow store for this. If the operator wants to acknowledge an out-of-model rewrite on AdGuard, the tools they have today are (i) the zone-confinement guardrail refusing it in the first place, and (ii) the existing `dns_coverage_parity` audit line. Note about the audit and honesty: `ack` here would need to be tracked out-of-band on the operator side (e.g. a runbook), and that's the honest posture — this is the same asymmetry that keeps `dns_value_drift` off marker-less AdGuard by design. |
| **Cloudflare (surgical DNS)** | Not needed by design | The surgical driver only manages records that carry `managed-by:crenel`; any record without that marker is FOREIGN and physically cannot be touched. There is no "unknown, ack'd" bucket — either the record is Crenel's (marked) or it's the operator's (unmarked, refused). The `ack` concept doesn't apply. |

The overall shape: **wherever the config has a per-route annotation slot, `ack`
uses it; where the API has no such slot, the doc SAYS so** and does not paper
over the gap. Same posture as everywhere else in Crenel.

---

## 6. Relationship to P5

`ack` and P5 (STATE-OF-CRENEL.md §6 item 6) are **complementary**, not
alternatives.

- **P5** teaches Crenel to *understand* common path-granular shapes natively:
  a route model that carries `PathPrefix`, `Method`, per-path backend/auth, and
  per-driver renderers that write it. Every shape P5 covers stops being an
  `Unparsed` entry at all — it's a first-class `Route`, deny certifies with no
  ack needed. P5 shrinks the population of routes that would ever need acking.
- **`ack`** handles the residual long tail: an idiosyncratic carve-out that
  P5 doesn't cover (a bespoke matcher, a hand-tuned Caddy handler chain, a
  method+header combination the model won't grow to represent), or a shape
  P5 could cover but that the operator doesn't want Crenel writing to. `ack`
  gives them a way to move deny from UNKNOWN to ENFORCED without waiting for
  Crenel to grow support for their specific shape.

**Sequencing recommendation.** Ship `ack` first. It's small (a new `Unparsed`
kind, a marker read in each driver, a `DenyState()` predicate change,
`ack`/`unack` verbs). It unlocks certifiable default-deny on real live edges
today. P5 is a bigger structural expansion that will take longer, and every
route P5 eventually understands is a route that no longer needs its `ack`
(remove the marker; it self-heals). Neither ships as a substitute for the
other.

---

## 7. Safety posture

An ack is an operator **assertion**: trusted for the purpose of deny
certification, but kept **visible** and **narrow**. The specific safety
properties, in order of importance:

1. **Never hidden.** An ack'd route is still counted in `Coverage()`, still
   listed by `status`, still enumerated by `audit`. It never becomes
   invisible-because-vouched. `audit` reports `acknowledged-unknown: N
   route(s)` on its own line so a reviewer immediately sees the size of the
   ack surface. (Compare: a silent "trust me" flag that just moves the
   `Unparsed` entry out of the report would be strictly worse than today's
   `UNKNOWN` deny — that's not the proposal.)
2. **Reason required.** The marker carries a reason slug (`crenel-ack:webhook-
   tailnet-agents`) and — for the verb form — a `--reason` flag. A future
   `crenel audit --ack-reasons` (out of scope for this proposal, cheap
   follow-on) can print the acknowledgment log directly.
3. **Scoped to one route.** The marker attaches to a single route/subroute
   node, never to a whole server or edge. Deny certification is the sum of
   per-route decisions, so an operator cannot use one ack to blanket-quiet
   Crenel across multiple routes — each carve-out is its own explicit
   acknowledgment.
4. **Ack does not override foreign / generator.** The refuse-to-manage gate
   (STATE-OF-CRENEL.md §3 "Solid") runs at the edge/ownership level and is
   independent of `ack`. An `ack` on a foreign or generator-owned route is a
   configuration error: the ownership gate still refuses to mutate it, and the
   deny model treats it as foreign, not acknowledged. `ack` is for
   **crenel-visible-but-not-fully-parsed** routes only.
5. **Ack does not override ingress-external unknowns.** `UnknownIngress` (an
   externally-fronted edge Crenel can't classify) is an edge-level property
   about *reachability mechanism*, not a route-level parsing gap. Acking a
   route on such an edge does not change the edge-level ingress classification
   — that would silence a real safety signal. If an operator wants to declare
   the ingress kind, the existing `ingress_kind` config field is the right
   place; `ack` is not.
6. **Ack does not silence permissive-catch-all warnings.** `audit` can and
   should still WARN on an ack'd route that smells like a permissive catch-all
   (empty matcher, `*` host, `/` path with no auth), independently of whether
   the route is ack'd. The operator's assertion is *"I know about this
   route"*; it is not *"I certify it's safe"* — and Crenel keeps its own
   independent voice on obvious over-broad shapes. This is a small extension
   to the existing audit-warning surface, not a new check class.
7. **Value is the marker string.** No tags matched by regex, no reserved
   words other than the `crenel-ack:` prefix itself. `crenel-ack:<slug>` where
   `<slug>` is `[a-z0-9-]+`. The reason encoded in the slug is the whole of
   the operator's assertion; no ambient meaning attaches to it.

---

## 8. Out of scope (deliberately)

- **A `crenel-ack-all` "silence every unknown on this edge" mode.** Not
  proposed. Each ack is per-route and required to carry a reason. Blanket
  silence is the shape §7.1 explicitly rules out.
- **Ack for foreign / generator-owned routes.** Different gate, different
  invariant; see §7.4.
- **Ack for `UnknownIngress`.** Wrong axis; see §7.5.
- **AdGuard rewrite acks.** No API slot for it; see §5 table.
- **A crenel-side stored ack list.** The whole point is not to grow one; see
  §3.

Each of these could be motivated in the future by a different problem, but
each is either an invariant break or a shape that shouldn't ride on this
proposal.

---

## 9. Rollout

This is a docs-only PR. Concrete implementation would be a separate branch,
approximately:

1. `internal/model`: new `UnknownKind = "acknowledged_unknown"`; new
   `Unparsed.Ack` field carrying the reason slug (round-tripped through
   `status --json`).
2. Each edge driver's `normalize` pass: when about to emit an `Unparsed`
   entry, check for the marker on the same node; if present, emit with kind
   `acknowledged_unknown` and the reason.
3. `DenyState()` predicate: evaluate `FullyParsed()`-equivalent over the set
   `Unparsed` entries whose kind is not `acknowledged_unknown`.
4. `status`/`audit` rendering: add the `ACK` row style and the
   `acknowledged-unknown` audit line.
5. CLI: `ack` / `unack` verbs, mirroring `expose`/`unexpose`'s preview →
   confirm → apply → read-back posture; per-driver stamp/remove primitive.
6. Tests: RED→GREEN parity with the existing detect-and-declare tests
   (`caddy/path_matcher_test.go` etc.) — a `matcher_conditional` route with a
   `crenel-ack:` marker is reclassified as `acknowledged_unknown`, deny
   certifies, cry-wolf check (no ack → still UNKNOWN, unchanged).

No live infra needed to trust any of this: the ack path is a read-side
classification rule tested with the same faithful fakes the existing burndown
uses.

---

## 10. Attribution

The `ack` marker as designed here is the maintainer's idea, and the crux — that it can
live in the infra rather than in Crenel because Crenel doesn't cache config,
inheriting every property of the existing `managed-by:crenel` ownership
marker — is his catch. This doc writes it up for review.

---

## 11. Implementation status (first shipped batch)

What actually shipped, against §9's original sketch — read this before relying
on any per-driver claim in §5 or §9.

**Model (§9 item 1) — shipped as designed.** `model.UnknownAcknowledged`
(`"acknowledged_unknown"`), `model.ParseAckMarker`/`model.AckMarker`/
`model.AckMarkerPrefix` (`internal/model/model.go`). `LiveEdgeState.FullyParsed`
and `core.EdgeStatus.FullyParsed` both now ignore `UnknownAcknowledged` entries;
`core.EdgeStatus.Acknowledged()` returns just those. `Unparsed.Reason` doubles as
the reason-slug carrier (`"acknowledged by operator (<slug>) — <original
diagnosis>"`) rather than a separate `Ack` field — keeps the original diagnosis
visible alongside the ack instead of replacing it.

**Read-side recognition (§9 item 2) — shipped for all three drivers, SCOPED to
per-route declared-unknowns.** Caddy (`@id`), Traefik, and nginx (`#
crenel-ack:` comment) all recognize the marker and reclassify. Deliberately
**not** wired into edge/server-WIDE unknowns (Caddy's sibling-server
`UnknownServerBlock`, nginx's non-server top-level chunk, Traefik's host-less
forwarding case) — those have no single route to scope an ack to, and §7.3
("scoped to one route, never a blanket ack") argues against inventing an
edge-wide ack to cover them. If that gap matters in practice, it needs its own
follow-on design, not a silent stretch of this one.

**Traefik's carrier (§5 table) — changed shape.** The original table proposed
"a `crenel-ack` label (labels provider) OR a comment (file-provider TOML/YAML)."
This driver's file provider reads/writes **JSON**, not YAML/TOML, and JSON has
no comment syntax — so the shipped carrier is a **`crenelAck` field Crenel adds
to the router object itself** (`internal/drivers/edge/traefik/types.go`),
holding the literal marker string (`"crenel-ack:<slug>"`). Traefik ignores
unrecognized router fields at runtime, so this is inert to the running proxy —
same principle as the label/comment idea, adapted to the actual file format
this driver speaks.

**Write-side (§9 item 5, `ack`/`unack` verbs) — Caddy only.** `ports.Acker`
(`internal/ports/ports.go`) is the optional-capability interface (mirrors
`Adopter`); only `caddy.Driver` implements it (`Ack`/`Unack` in
`internal/drivers/edge/caddy/caddy.go`, walking the raw config the same way
`Adopt`/`adoptWalk` already does, PATCHing `@id` in place). `crenel ack
<host> --reason <slug>` / `crenel unack <host>` are wired in
`cmd/crenel/commands.go`, gated by the same file-lock as every other mutating
verb (`mutatingVerbs` in `cmd/crenel/lock.go`).

Traefik and nginx do **not** yet have an `Ack`/`Unack` primitive — `crenel ack`
on those edges returns a plain "no participating edge could ack a route"
error. The manual path (§4a: hand-edit the `crenelAck` field / `#
crenel-ack:` comment directly) already works on both, since read-side
recognition doesn't depend on the write primitive — this is the honest,
partial-support posture §5's own AdGuard/Cloudflare rows already establish for
this proposal, extended to two more drivers for now. A follow-on can add
`Ack`/`Unack` for Traefik (read-modify-write the JSON, same shape Adopt would
need there) and nginx (insert/remove the leading comment) without touching
anything shipped here.

**`ack` is scoped to the FIRST matching route per host, not `--path`-scoped
yet.** §4b's sketch included a `--path` flag for disambiguating multiple
declared-unknown routes on the same host. Not implemented in this batch — if a
host has more than one such route, `ack` targets whichever the driver's
traversal reaches first. Fine for the common case (one carve-out per host);
worth adding `--path` if a real multi-route-per-host case shows up.

**Audit/status rendering (§9 item 4) — shipped, format differs slightly from
§4a/§4d's mock.** `audit` gets a dedicated `acknowledged_unknown` finding at
`"ok"` severity (`internal/core/audit.go`), separate from and never folding
into `coverage_incomplete`'s count. `status` text output gets a distinct `ACK —
acknowledged by operator (N, not blocking default-deny):` section
(`cmd/crenel/commands.go`), listing locator + reason, alongside (not replacing)
the existing `⚠ Not understood` section for genuine unknowns. The exact
inline-per-route rendering §2a/§4a sketch (`[ACK: <slug>]` beside the route
itself, colored as a "third state" in the HUD) was not built — the current
form surfaces the same information (never hidden, distinct from both green and
amber) via a separate section rather than inline annotation + a HUD color.
Revisit if the inline form turns out to matter more than the section form in
practice.

**Tests (§9 item 6) — shipped per-driver plus core/CLI integration**, beyond
§9's original scope of read-side RED→GREEN parity alone:
`internal/drivers/edge/{caddy,traefik,nginx}/ack_test.go` (per-driver
read-side reclassification + full-edge-certifies-ENFORCED cases),
`internal/drivers/edge/caddy/ack_test.go` (write-side: stamp + read-back,
idempotent re-ack, refuse-on-crenel-managed-route, revert-on-unack),
`internal/core/ack_test.go` + `ack_engine_test.go` (audit findings, `Engine.
Ack`/`Unack` fan-out across the `ports.Acker` capability + read-back-verify),
`cmd/crenel/ack_test.go` (CLI `ack`/`unack` verbs through `dispatch`, including
the `--reason`-required refusal).
