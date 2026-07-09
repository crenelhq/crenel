# Crenel: Claims to Verify

> Part of the [third-party audit package](../AUDIT.md). **This is the heart of
> the package.** Every entry is a specific, testable property of the code,
> phrased as something to try to BREAK, not as a feature description. Each
> entry names the mechanism and an anchoring test file so you can go straight
> to the code, then try to construct an input that defeats it. A confirmed
> break is a finding regardless of how contrived the triggering config is.
> "Contrived" configs are exactly what real-world edges turn out to look like
> (see `../internal/TOPOLOGY-RISK-REGISTER.md` Appendix B for prevalence sourcing).
>
> Severity vocabulary: use `MISREAD-↓` / `MISREAD-↑` / `MISMANAGE` /
> `READ-SAFE` / `READ-CORRECT` / `MANAGEABLE` from
> [THREAT-MODEL.md](THREAT-MODEL.md) §3 when reporting.

---

## A. Default-deny certification

**Claim:** `status`/`audit` report the structural default-deny as **ENFORCED**
if and only if (1) a catch-all deny is actually present on live, AND (2) the
entire live config was parsed with nothing left `Unparsed`.

**Try to break it:**
- Construct an edge config where a permissive host-less `reverse_proxy` (a
  fail-open catch-all) sits *inside* a subroute Crenel doesn't descend into.
  Does `status` still report ENFORCED?
- Construct an edge with a deny-shaped construct Crenel's `isDeny` doesn't
  recognize (a non-standard abort mechanism, a deny expressed via a different
  handler chain). Does it report MISSING (safe, if noisy) or silently
  ENFORCED (unsafe)?
- Find any code path where `DenyCatchAllPresent` can be `true` while
  `Unparsed` is non-empty and the reported verdict is still ENFORCED rather
  than UNKNOWN.

**Mechanism / where to look:** `model.LiveEdgeState.{Unparsed,FullyParsed,Coverage}`,
`core`'s ternary deny verdict. Each driver's `isDeny`/`normalize`:
`internal/drivers/edge/caddy/caddy.go`, `internal/drivers/edge/traefik/traefik.go`,
`internal/drivers/edge/nginx/nginx.go`. Anchoring tests:
`internal/core/unknown_surface_test.go`, `internal/core/chain_p4_test.go`,
and each driver's own normalize tests.

---

## B. Bounded honesty / never-silently-drops-a-route

**Claim:** any handler, subroute, matcher, or server block Crenel's parser
cannot fully model appears in `Unparsed[]`. It is never simply absent from
both `Routes` and `Unparsed`.

**Try to break it:**
- Find a construct in any of the three data-plane drivers (Caddy/Traefik/
  nginx) that is silently dropped, i.e. `status` claims 100% coverage
  (`FullyParsed() == true`) but a route that actually exists on the edge is
  missing from the reported output.
- Multi-server Caddy configs specifically: a *second* `http.servers` block
  that forwards traffic should surface as `UnknownServerBlock` if not fully
  modeled. Try to construct a forwarding sibling server that neither appears
  in `Routes` nor triggers `UnknownServerBlock`.
- Grouped multi-host Caddy routes (`host: [a, b, c]` on one route object):
  confirm every listed host is enumerated, not just the first.

**Mechanism / where to look:** `collectLeaves` (Caddy), the Traefik/nginx
codec normalizers. Anchoring tests: driver-level `*_test.go` files under
`internal/drivers/edge/*/`, especially any test with "multi" or "sibling" in
its name.

---

## C. Refuse-to-manage (ownership gate)

**Claim:** Crenel refuses to mutate any route classified `foreign` (generator-
owned) or `unknown` (undetermined), for **every** mutating verb
(`expose`/`unexpose`/`apply`/`reconcile`/`import`), before any driver `Apply`
runs. `--yes` never bypasses this. `--force` bypasses `unknown` only, **never**
`foreign`.

**Try to break it:**
- Find any mutating verb that skips the gate entirely (check each CLI command
  handler calls into the path that runs `gateOwnership`).
- Find a way `--yes` alone (no `--force`) causes a mutation on a `foreign` or
  `unknown` route.
- Find a way `--force` causes a mutation on a `foreign` route. This should be
  impossible; there's no code path documented to allow it.
- **Chain-specific:** construct a chain where the *downstream* edge has a
  pre-existing foreign or unknown route at the target host, but the front
  edge's planned change converges to an empty diff (a no-op) for that host.
  Does the gate still refuse? (`gateChainOwnership` exists specifically to
  catch this. A per-edge-only gate would miss it because the changeset never
  touches that host on the down-edge.)
- Find a way `import`/`apply --adopt` stamps an ownership marker onto a route
  that is actually `foreign`. Adopting a generator-owned route is itself a
  MISMANAGE: the marker gets silently regenerated away.

**Mechanism / where to look:** `internal/core/gate.go` (`gateOwnership`,
`gateChainOwnership`, `ErrRefuseToManage`). Anchoring tests:
`internal/core/gate_test.go`, `internal/core/generator_gate_test.go`,
`internal/core/chain_write_test.go`.

---

## D. Preview → apply → read-back-verify, all-or-nothing rollback

**Claim:** (1) a `200`/success response from an edge admin API is never
treated as sufficient proof of an applied change; every mutation re-reads
live and asserts the expected state. (2) If any provider in a multi-provider
transaction (edge, internal DNS, public DNS, and, for a chain, front +
downstream edges) fails to apply or fails read-back, **every already-applied
provider in that transaction is rolled back**, leaving nothing half-applied.

**Try to break it:**
- Find a code path where `Apply` returns success purely from the driver's
  HTTP status without a subsequent `ReadLiveState`/`LiveRecords` call.
- Inject a failure at each position in a multi-step transaction (first
  provider, middle provider, last provider; on `expose` and on `unexpose`,
  which apply in opposite orders) and confirm every earlier-applied provider
  is actually reverted, not just reported as "should be reverted."
- **Chain-specific:** inject a failure on the *downstream* leg of a
  coordinated chain write after the front leg already applied. Confirm the
  front is rolled back too, not left serving a route to a downstream that
  never got its real backend + auth.
- **Wedge case:** simulate one edge's admin API hanging/unresponsive during a
  multi-edge rollback. Confirm the wedged edge's compensator is skipped (with
  a surfaced recovery hint) while every *other* edge/DNS provider still rolls
  back. One stuck edge should not silently block unwinding the rest, and
  should not hang the whole CLI invocation.

**Mechanism / where to look:** `internal/core/apply.go` (or equivalent:
`buildSteps`/ordered apply/compensator logic), `internal/core/chain_write.go`.
Anchoring tests: `internal/core/rollback_test.go`,
`internal/core/multiedge_test.go`, `internal/core/wedge_test.go`,
`internal/core/chain_write_test.go`, `internal/core/runtime_verify_test.go`.

---

## E. Public-without-auth guardrail

**Claim:** no mutating path can make a host public with auth left
unspecified. The CLI refuses unless the operator passes `--auth <policy>` or
the explicit `--auth none` opt-out. `--yes` does not bypass this refusal.

**Try to break it:**
- Find any of `expose`, `apply <file>`, `reconcile`, or a chain write that
  can publish a previously-unexposed host with `Auth == ""` and no refusal.
- Declarative `apply <file>`: confirm a file with an exposure that has no
  `auth:` key is refused the same as the CLI-flag path, not silently allowed
  because the check only lives on one entry point.
- Chain-specific: the guardrail is supposed to evaluate the **whole chain's**
  "about to go public" state (the front's forward route), not just the
  downstream terminal route. Construct a chain expose with no auth anywhere
  along the chain and confirm it's refused even though no single edge's
  local diff looks unambiguously "the public one."
- Mode interaction: confirm a *passthrough* (SNI/TCP) or *mesh-grant* exposure
  correctly refuses a *real* auth policy (there's no HTTP layer / identity is
  already enforced) rather than silently dropping the requested policy.

**Mechanism / where to look:** `model.ValidateAuth`, the CLI guardrail wired
around `computeNewPublic`, `../internal/AUTH-DESIGN.md` §6. Anchoring tests:
`internal/core/audit_test.go`, `internal/core/chain_p4_test.go`,
`internal/core/chain_write_test.go`.

---

## F. Surgical Cloudflare: ownership marker as the safety boundary

**Claim:** in `apply_mode: surgical`, Crenel only ever creates records
stamped with its own `managed-by:crenel host=<name>` comment marker, and its
`updateRecord`/`deleteRecord` primitives **refuse to act on any record
lacking that marker**, enforced at the primitive level (defense in depth),
not merely by the caller checking first. A foreign (unmarked) record sitting
at the exact name+type Crenel would create is refused outright, never
shadowed or overwritten.

**Try to break it:**
- Seed a zone with a foreign record at the exact name+type an `expose` would
  create. Confirm `expose` refuses rather than creating a second record or
  updating the foreign one.
- Try to call the driver's update/delete path directly (bypassing whatever
  caller-side check exists) against an unmarked record and confirm the
  primitive itself refuses. This is the "even a logic bug upstream can't
  delete a foreign record" claim; test the boundary at the lowest level, not
  just the CLI.
- Check the marker-matching logic for a **prefix-collision** class of bug (one
  was found and fixed here before; see `../internal/DESIGN.md`/`STATE-OF-CRENEL.md` for
  the `HasPrefix` → word-boundary fix history). Confirm a record whose comment
  merely *starts with* something marker-like but isn't Crenel's own doesn't
  get treated as owned, and vice versa: a marker-ish-but-foreign comment
  shouldn't be adoptable by accident.
- Confirm `LiveRecords` (what `status`/`audit`/read-back all see) reports
  **only** marked records. A foreign record should never appear as part of
  Crenel's own footprint even for display purposes.

**Mechanism / where to look:** `internal/drivers/dns/cloudflare/cloudflare.go`
(`updateRecord`, `deleteRecord`, the `owned()` marker check), `docs/DNS-DESIGN.md`
§11. Anchoring tests: `internal/drivers/dns/cloudflare/cloudflare_test.go`,
`internal/drivers/dns/cloudflare/doer_test.go`.

---

## G. AdGuard zone-confinement guardrail

**Claim:** the AdGuard DNS driver refuses to write a rewrite for a domain
outside its configured zone, and refuses to write a bare wildcard rewrite,
regardless of what the (real) AdGuard control API would itself accept (it has
no zone concept and would happily accept either).

**Try to break it:**
- Configure the driver for zone `example.com` and attempt to expose a host
  whose derived record name is outside that zone (or a name in a *sibling*
  zone that shares a suffix, to check for a naive suffix-match bug). Confirm
  the driver refuses before any API call reaches the (fake) control API. The
  test should assert the fake received **no** request, not merely that the
  overall command errored.
- Attempt to get the driver to write `*.example.com` or any bare wildcard
  rewrite.
- Construct a same-domain, different-answer scenario (an existing rewrite for
  `host.example.com` pointing at one address, Crenel computing a different
  desired address) and confirm it's treated as a **conflict** requiring
  resolution, not silently overwritten with an ambiguous second rewrite.

**Mechanism / where to look:** `internal/drivers/dns/adguard/adguard.go`
(the zone guard). Anchoring tests: `internal/drivers/dns/adguard/adguard_test.go`,
`internal/drivers/dns/adguard/doer_test.go`.

---

## H. Whole-zone Cloudflare push guardrail (`dedicated_zone`)

**Claim:** the whole-zone `dnscontrol push` path refuses to push a zone that
contains (1) a record type/shape it cannot faithfully re-render (multi-field:
MX/SRV/CAA/SOA; multi-value: round-robin A, multiple TXT at one name), or (2)
**any** pre-existing record it does not already manage, unless the operator
has explicitly set `dedicated_zone: true`.

**Try to break it:**
- Point a non-dedicated-zone push at a zone containing an MX record and a
  managed A record change. Confirm the push is refused rather than silently
  dropping the MX on push (which whole-zone `dnscontrol push` would otherwise
  do, since it's authoritative over everything it renders).
- Same for a zone with only a **single wildcard A record** as the sole
  pre-existing content. This is the case the design doc flags as the
  trickiest: a wildcard is *renderable* as a single A, so the fidelity check
  alone doesn't catch it; only the separate ownership check does. Confirm
  it's still refused without `dedicated_zone: true`.
- Confirm the TTL and Cloudflare `proxied` flag survive a legitimate
  dedicated-zone push unchanged for records the push reproduces but didn't
  intend to modify (a silent TTL reset to default, or silently un-proxying an
  orange-cloud record, would itself be a finding even on an authorized push).

**Mechanism / where to look:** `internal/drivers/dns/dnscontrol/dnscontrol.go`,
`docs/DNS-DESIGN.md` §5 (2a, 2a-i, 2a-ii). Anchoring tests:
`internal/drivers/dns/dnscontrol/dedicated_zone_test.go`,
`internal/drivers/dns/dnscontrol/cloudflare_provider_test.go`.

---

## I. Read-only MCP server (branch `feat/crenel-mcp`)

**Claim:** the MCP server is read-only **by construction**, not merely by
runtime refusal. Its Go type only ever holds a narrow `readOnlyEngine`
interface exposing `Status`/`Audit`/`DetectDrift`, so no mutating `core.Engine`
method is reachable through the server's held reference, regardless of what a
malicious or malformed `tools/call` request contains.

**Try to break it:**
- Enumerate every `tools/call` the server accepts and confirm none maps to a
  mutating operation, directly or via some indirection (e.g. a tool argument
  that gets interpreted in a way that reaches a mutating code path).
- Attempt to smuggle a mutating request through malformed/unexpected JSON-RPC
  params. Confirm it errors rather than being loosely parsed into something
  that reaches a wider interface.
- Check whether `readOnlyEngine` can be **widened** by a caller of `newMCPServer`
  passing something other than what the CLI wires up. In other words, is the
  read-only property actually enforced by the *type* (compile-time), or does
  it just happen to be true of the one call site today? (The claim is
  compile-time. Confirm it, don't just spot-check the current wiring.)

**Mechanism / where to look:** `cmd/crenel/mcp.go`: the `readOnlyEngine`
interface, the `mcpServer` struct, the
`var _ readOnlyEngine = (*core.Engine)(nil)` assertion.
This is on branch `feat/crenel-mcp` (not yet on `develop`; see AUDIT.md §6 for
how to get it). No dedicated test file existed as of this writing beyond the
compile-time assertion, so writing an adversarial test here (fuzz `tools/call`
params) is itself a useful contribution, not just a check.

---

## J. Chain auth resolution (front → downstream)

**Claim:** for a front-edge-forwards-to-downstream-edge topology, a host's
auth status is resolved by **observation** when the downstream is readable.
A downstream host that is genuinely unauthenticated **is flagged**
`public_without_auth`; it is not blanket-suppressed by the "auth is
downstream" assertion. The assertion fallback ("downstream, not observed")
applies **only** when the downstream is actually unreadable, and is itself
surfaced as an assertion, not presented as equivalent to an observed fact.

**Try to break it:**
- Construct a two-edge chain fixture where the downstream edge is fully
  readable and has a host with **no** auth handler. Confirm `audit` flags
  `public_without_auth` for that host (not suppressed).
- Construct a chain where the downstream is readable and the host **does**
  have a recognized auth handler (Authelia-shaped gate, a stock
  `authentication` handler). Confirm it's reported protected. This is the
  cry-wolf direction; getting it wrong here erodes trust, but the more
  dangerous direction is the previous bullet.
- Construct a chain where the downstream read genuinely fails (network error,
  the named edge doesn't exist in the topology). Confirm the front degrades
  to a declared-unknown/asserted state rather than aborting the whole
  `status`/`audit` run, and that the assertion is visibly labeled as such.
- Coordinated **write**: `expose <host> --auth <policy>` on a chain should
  attach the policy at the **downstream** (terminal) edge, and the read-back
  should assert it actually landed there. Try to get a chain write to report
  success while the auth policy silently failed to attach (e.g. a render bug
  that emits invalid JSON the edge rejects, or attaches it at the wrong edge).

**Mechanism / where to look:** `core/chain.go` (`buildChainContext`/`resolve`/
`effectiveAuth`), `core/chain_write.go`. Anchoring tests:
`internal/core/chain_p4_test.go`, `internal/core/chain_test.go`,
`internal/core/chain_write_test.go`, `internal/core/chain_write_tls_test.go`.

---

## K. Cross-provider make-before-break ordering

**Claim:** on `expose`, the route is live on the edge(s) *before* the public
DNS record announces the name to the world; on `unexpose`, the public DNS
record is removed *before* the route is torn down. There is no window where a
publicly-resolvable name points at a host that doesn't yet (or no longer)
serve it.

**Try to break it:**
- Trace the actual apply order for a multi-provider `expose` (edge + internal
  DNS + public DNS) and a chain `expose` (downstream + front + public DNS).
  Confirm public DNS is provably last in every code path, not just the
  common one.
- Inject a failure specifically at the public-DNS step of an `expose` after
  the edge route already applied. Since public DNS is last, this should mean
  the edge route now needs to roll back too (nothing should be left routed-
  but-unannounced in a way that matters, and nothing should be announced
  without a route). Confirm the rollback actually removes the edge route
  rather than leaving it live with no compensating DNS.
- Confirm the reverse holds symmetrically for `unexpose` (public DNS first).

**Mechanism / where to look:** the exposure-rank ordering in `core`'s apply
step-builder (edge < internal-DNS < public-DNS, extended by chain depth).
Anchoring tests: `internal/core/multiedge_test.go`,
`internal/core/chain_write_test.go`.

---

## L. (Lighter-weight, secrecy-adjacent) Redaction boundary

This axis properly belongs to `SECURITY.md`'s threat model, not this one, but
it's cheap to check while already in the code and worth including for
completeness. See `SECURITY.md` §6 for the full claim.

**Try to break it:**
- Find a secret-shaped value (a key that matches none of the documented key
  patterns, in a construct Crenel doesn't model) that leaks into a
  `status --json`/`audit` `Unparsed.RawExcerpt` without being caught by the
  value heuristics (PEM block / bcrypt-family hash / JWT shape).
- Confirm the **apply path** never accidentally redacts a value it's about to
  write. Redaction must be output-only: a redacted value making it into an
  actual API call would silently corrupt the operator's real config, which is
  its own class of MISMANAGE even though it originates from the secrecy
  layer.

**Mechanism / where to look:** `internal/redact`. Anchoring tests:
`internal/redact/*_test.go`.
