# Crenel — inline edge + DNS-scope appointment on `expose`

> One command, one place: appoint a route to one edge, the other, or both, and to
> internal / public / both DNS — without dropping into a declarative `apply` file.
>
> Status: **implemented, first batch (Deliverable #1).** Closes the imperative/
> declarative parity gap: an `Exposure` in an apply file already carries `edges`
> and `dns` (scopes), but `crenel expose` had no inline flag for either, so
> "internal-only" or "just one edge" forced a detour through `apply`.
>
> Companions: `internal/core/declarative.go` (the `Exposure.Edges` / `Exposure.Scopes`
> mechanism this reuses), `AUTH-DESIGN.md §6` (the public-without-auth guardrail
> this leaves fully intact), `internal/core/engine.go` `computeNewPublic` (the
> publicness notion that makes `--scope internal` naturally suppress "about to go
> public").

---

## 0. TL;DR

- **Problem.** `Exposure{Edges, Scopes}` already lets the DECLARATIVE `apply` path
  land a route on specific edges and specific DNS scopes. The IMPERATIVE `expose`
  had no equivalent inline flag — so to get internal-only or a single edge you had
  to write an apply file. That breaks crenel's core promise (one command).
- **Fix.** Three flags on `expose` / `unexpose` / `set`:
  - `--scope internal|public|both` — the ergonomic bundle (primary).
  - `--edges <comma-list>` — appoint to specific named edges.
  - `--dns internal|public|both` — appoint to specific DNS scopes (the granular
    half of `--scope`).
- **No parallel code path.** The flags populate two new fields on `model.Op`
  (`Edges`, `Scopes`) that are honored by `engine.Plan` / `engine.verify` through
  the **same selection predicates** the declarative path uses for
  `Exposure.Edges` / `Exposure.Scopes` (`edgeSelected` / `scopeSelected`, extracted
  and shared). `targetEdges` and `scopeWanted` now delegate to those predicates, so
  there is exactly one edge-selection rule and one scope-selection rule in the code.

---

## 1. Flag semantics

| Flag | Values | Meaning |
|------|--------|---------|
| `--scope` | `internal` \| `public` \| `both` | Sugar. Expands to `--dns` (see §2). |
| `--dns` | `internal` \| `public` \| `both` | Restrict the DNS records this op touches to the named scope(s). |
| `--edges` | comma list of edge names | Restrict the edge routes this op touches to the named edge(s). Empty ⇒ every edge that fronts the service (today's default). |

`both` (or unset) is exactly today's behavior: every fronting edge, every
configured DNS scope. `--scope` and `--dns` are mutually exclusive (`--scope` IS
the `--dns` shorthand); passing both is an error. `--scope`/`--dns` and `--edges`
are orthogonal and may be combined.

## 2. `--scope` resolution — and the one design fork

`--scope` maps to a DNS-scope selection **only**:

| `--scope` | `Scopes` on the op | Edge selection | Auth |
|-----------|--------------------|----------------|------|
| `internal` | `[internal]` | unchanged (all fronting, or `--edges`) | not required |
| `public` | `[public]` | unchanged (all fronting, or `--edges`) | **required** (via the existing guardrail) |
| `both`/unset | `nil` (all) | unchanged | required if it goes public |

**Why `--scope` does not itself filter edges.** The brief describes `internal` as
"internal-serving edge(s) + internal DNS only" and `public` as "all public edges".
That presumes a per-edge internal/public classification. **crenel's model has no
such first-class field, and none is cleanly derivable** from a real config:

- A plain LAN Caddy has an ordinary `:443` public listener (`IngressPublicListener`),
  so ingress-kind would classify *every* edge as "public" — `--scope internal`
  would then select zero edges and the route would land nowhere. That breaks the
  most common single-proxy topology (and the acceptance case).
- The home↔VPS distinction is real but lives in operator knowledge, not in any
  configured provider field — so keying off it would mean hardcoding names, which
  the brief explicitly forbids.

crenel already *defines* publicness through DNS, not edges: `computeNewPublic`
decides a host is public **because it gains a public DNS record** (or, when no
public DNS is managed, because it gains an edge route). So the faithful,
config-derivable reading of "internal vs public" is a **DNS-scope** decision:

- `--scope internal` ⇒ create the internal DNS record, **skip** the public one ⇒
  `NewPublic` is empty ⇒ no "ABOUT TO GO PUBLIC", no forced auth. The host is
  reachable only where an internal name resolves. **This is exactly the acceptance
  case.**
- `--scope public` ⇒ create the public DNS record ⇒ `NewPublic` non-empty ⇒ the
  existing public-without-auth guardrail fires unless `--auth <policy>`/`--auth
  none`. "Auth required" falls out for free; no new auth logic.

Edge appointment ("one edge, the other, or both") is served by the explicit
`--edges` flag, which reuses `Exposure.Edges`' exact mechanism. This keeps
`--scope` = *reachability posture* and `--edges` = *edge selection* — orthogonal
and predictable.

> **FORK FLAGGED:** if you later want `--scope` to *also* drop the public edge in a
> multi-edge topology, that needs a new first-class per-edge `scope`/`public`
> declaration in `EdgeSettings` (operators would opt in). That is a deliberate,
> separate change; this batch does not guess a classification. See §6.

## 3. Implementation — one mechanism, not two

- `model.Op` gains `Edges []string` and `Scopes []model.Scope` (transient, never
  persisted — same status as the rest of `Op`).
- `edgeSelected(names, name)` and `scopeSelected(scopes, scope)` are the shared
  predicates. `declarative.go`'s `targetEdges` and `scopeWanted` delegate to them.
- `engine.Plan`:
  - edge fan-out skips an edge when `!edgeSelected(op.Edges, b.Name)`.
  - DNS fan-out, for a non-selected scope, appends an **empty**
    `model.DNSChange{Scope: …}` — preserving the `cs.DNS[i] ↔ e.DNS[i]` positional
    alignment `Apply`/`verify` rely on, while contributing no record. `buildSteps`
    already skips empty changes, so it is a clean no-op.
- `engine.verify` is op-driven for DNS (it recomputes `DesiredRecords(op)` per
  provider), so it must gate on the same scope: a non-selected provider verifies
  trivially "scope not selected — unchanged" instead of expecting a record that was
  deliberately not written. (The edge loop is cs-driven and already excludes skipped
  edges.)
- The CLI `buildOp` populates `op.Edges` / `op.Scopes` from the flags, validates the
  scope strings, rejects `--scope`+`--dns` together, and rejects an unknown edge
  name (against the live topology) so a typo fails loudly instead of silently
  landing nowhere.

Everything downstream is unchanged: plan → preview → confirm → apply →
read-back-verify; default-deny; the public-without-auth guardrail; ownership gate;
runtime-verify honesty. `--scope internal` is safe by construction because it
simply omits the public record — no code path is weakened.

## 4. Acceptance case

    crenel expose ha --to 10.0.0.19:8123 --scope internal --auth none

produces a plan with **only** the internal edge route + the internal DNS A record,
**no** public/Cloudflare record, and **no** "ABOUT TO GO PUBLIC" (asserted in
`internal/core/scope_flags_test.go`). Before this change the default plan wrongly
added a public record and warned; internal scope now suppresses both.

## 5. unexpose / set

The same `buildOp` feeds `unexpose` and `set`, so they honor `--edges` / `--dns` /
`--scope` uniformly: the flags restrict *which edges' routes* and *which DNS
scopes' records* the teardown (or `set off`) touches. `unexpose ha --scope
internal` removes the internal record + edge route and leaves any public record
standing. `rename` keeps its own atomic-move path and ignores these flags.

## 6. Not in this batch (deliberate)

- A first-class per-edge internal/public classification (would make `--scope`
  filter edges in a multi-edge topology). Flagged in §2; needs config + operator
  opt-in.
- `--scope` interaction with edge chains beyond naming the participating edges.
