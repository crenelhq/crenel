# Crenel — DNS-for-real design (split-horizon: Cloudflare + AdGuard Home)

> The doc to read to understand how Crenel drives **real DNS** as part of an edge
> `expose`/`unexpose`: what providers it speaks to, how it keeps a **public** view
> (Cloudflare, authoritative) and an **internal** view (AdGuard Home, resolver
> rewrites) in sync, how credentials are handled, and the safety posture.
> Companions: **DESIGN.md** (the two load-bearing invariants + apply ordering),
> **SECURITY.md** (the secret inventory + redaction this design inherits),
> **AUTH-DESIGN.md** (auth-by-reference, the same "operator owns the secret" stance).
>
> Status: **design + faithful fakes + unit tests only.** No real Cloudflare or
> AdGuard endpoint is contacted by this repo or its test suite. A live trial is a
> separate, gated step (see §9) that needs the maintainer's real API token + AdGuard creds.

---

## 0. TL;DR

- A Crenel **expose** can drive DNS on **two scopes at once**: the **public**
  record (so the world resolves the name to the public edge) and the **internal**
  rewrite (so on-LAN / Tailscale clients resolve the same name to the *local* edge).
  This is the split-horizon the homelab already runs by hand; Crenel makes it one
  coordinated, read-back-verified change.
- **Public scope → Cloudflare**, driven through the existing **dnscontrol** adapter
  using the `CLOUDFLAREAPI` provider and a Cloudflare **API token**.
- **Internal scope → AdGuard Home**, driven through a **new native driver** that
  speaks the AdGuard **control API** (`/control/rewrite/{list,add,delete}`). AdGuard
  is a *resolver with rewrites*, **not** an authoritative DNS provider, so it is not
  (and cannot be) a dnscontrol provider — it gets its own adapter.
- **DNS stays opt-in** (`dns.enabled: false` by default) and **defaults to mock**.
  Nothing reaches a real provider unless the operator both enables DNS and selects a
  real provider `type` with credentials.
- **Credentials are never hardcoded.** Each provider takes either an env-var
  *reference* (preferred — the secret never lands in a config file) or a literal that
  is **redacted** at every output boundary by the existing `internal/redact` pass.
- **Crenel is the guardrail AdGuard lacks.** The internal driver refuses to write a
  rewrite for a domain outside its configured zone — the exact failure that once
  broke `www.smallbiz.example` when a bare `*.smallbiz.example → .13` wildcard
  hijacked the public marketing site (see §2).

---

## 1. Grounding — the split-horizon homelab it was built against (anonymized)

Sourced from the knowledge wiki, **not** invented here:
`homelab/runbooks/tailscale-dns-split-architecture` and
`homelab/runbooks/caddy-cloudflare-dns01-propagation` (both `confidence: high`,
updated 2026-06-26). Where this design extrapolates beyond what those pages state,
it is **flagged** in §8.

**Two authorities, one name.** A homelab hostname like `auth.homelab.example` has two
correct answers depending on who is asking:

| Asker | Resolver | Answer | Why |
|---|---|---|---|
| Off-LAN, no Tailscale | **Cloudflare** public NS (`carmelo`/`emely.ns.cloudflare.com`) | the **VPS edge** public IP (`203.0.113.7`) | the only reachable path is the public internet |
| LAN / Tailscale | **AdGuard Home** (LXC 130 `10.0.0.53`, + synced VPS `100.100.0.2`) | the **home Caddy** `10.0.0.13` | stays local — no VPS hairpin, direct LAN/WireGuard |

- **Cloudflare** is **public-authoritative**: it owns the apex zones
  `homelab.example` and `smallbiz.example` and is what the rest of the world queries.
  It is already used for ACME **DNS-01** wildcard issuance via a scoped API token
  (`CLOUDFLARE_API_TOKEN`).
- **AdGuard Home** is the **internal resolver**. It holds **split-horizon rewrites**
  (`/opt/adguard/conf/AdGuardHome.yaml` → `rewrites:`) that *override* the public
  answer for on-network clients, e.g. `*.homelab.example → 10.0.0.13`, with **exact
  overrides** for VPS-resident services (`vault.homelab.example → 203.0.113.7`).

**The load-bearing safety rule (verbatim from the wiki):**
> Use **exact** rewrites for the homelab set, **never a bare wildcard** — a bare
> `*.smallbiz.example → .13` once broke `www.smallbiz.example` (the public marketing
> site) and hijacked `ssh`/`ftp`/`mysql`.

`smallbiz.example` *mixes* homelab subdomains (`auth`, `erp`, `expenses`, …) with
external/marketing records (`www`, apex, `ssh`, `ftp`, `mysql`, MX → Google
Workspace). A DNS automation that is careless about scope is actively dangerous here.
**This is the single most important constraint the internal driver must enforce.**

---

## 2. What an `expose` does to DNS

Crenel's model is **live-state-authoritative**: there is no stored desired state, only
the transient `Op` of one CLI invocation (DESIGN.md). DNS slots into that unchanged.
A `crenel expose grafana` with DNS enabled produces **one `ChangeSet`** aggregating:

1. the **edge** change (the route + default-deny — the existing behavior), then
2. one **`DNSChange` per configured provider/scope**.

For each provider the op's host maps to a single desired record:

- **public (Cloudflare):** `grafana.<zone>  A  <public-edge-addr>` — the VPS edge IP.
- **internal (AdGuard):** `grafana.<zone>  →  <internal-edge-addr>` — the home Caddy
  `10.0.0.13`, expressed as an AdGuard **rewrite**.

The provider `Diff`s desired against **live** records (Cloudflare zone read /
AdGuard rewrite list) and emits only the delta (add on expose, remove on unexpose,
empty if already correct — idempotent).

### Apply ordering (already implemented in `core/apply.go`, unchanged)

Steps are ranked and sorted so exposure widens **outward** and teardown narrows
**inward** — *make-before-break*:

```
expose   (ascending):  edge(0)  →  internal DNS(1)  →  public DNS(2)
unexpose (descending): public DNS(2) → internal DNS(1) → edge(0)
```

Rationale: on `expose`, the route must exist before any resolver points a client at
it, and the **public** announcement (the whole internet) goes **last**. On
`unexpose`, stop announcing to the world **first**, then pull the LAN record, then
tear the route down. Each step is **read-back-verified** where the provider supports
it (`LiveRecords` after apply: present after expose, absent after unexpose). A
DNS-step failure does not roll back the edge silently — it surfaces, and the
operator sees exactly which scope diverged (status cross-checks the two scopes).

---

## 3. Provider abstraction

Crenel already defines a scope-bound `ports.DNSProvider`
(`internal/ports/ports.go`):

```go
type DNSProvider interface {
    Name() string
    Scope() model.Scope            // internal | public — each instance is ONE scope
    DesiredRecords(op model.Op) ([]model.Record, error)
    Diff(ctx, op, desired) (model.DNSChange, error)
    Apply(ctx, change) error       // success is not proof; callers read-back-verify
    LiveRecords(ctx) ([]model.Record, error)
}
```

Two concrete adapters implement it. Neither is a new *interface* — they are two
backends behind the same port, chosen by a `type` discriminator in config.

### 3a. Cloudflare — via the dnscontrol adapter (public, authoritative)

The existing `internal/drivers/dns/dnscontrol` driver already shells out to the
`dnscontrol` tool with `!inside`/`!outside` scope tags. The only thing it lacked was
the ability to emit a **real provider**: `render.go` hardcoded
`NewDnsProvider("mock")` / `NewRegistrar("none")` and `workdir` wrote a stub
`creds.json = {}`. This design adds a `Provider` to the driver `Config`:

```go
type Provider struct {
    CredsKey  string            // dnsconfig.js NewDnsProvider() arg AND creds.json key, e.g. "cloudflare"
    Type      string            // dnscontrol provider TYPE, e.g. "CLOUDFLAREAPI"
    Registrar string            // NewRegistrar() arg; default "none"
    Creds     map[string]string // creds.json values under CredsKey, e.g. {"apitoken": "<token>"}
}
```

- `render.go` now emits `NewDnsProvider(<CredsKey>)` + `NewRegistrar(<Registrar>)`.
  An **empty** `Provider` falls back to `mock`/`none` — **byte-identical to today**,
  so every existing mock test still passes.
- `workdir` writes a **real** `creds.json` (`{"cloudflare":{"TYPE":"CLOUDFLAREAPI",
  "apitoken":"…"}}`) at **`0600`** in a `0700` temp dir, cleaned up per call. The
  token lives only in that throwaway file and the process; it is **never** written
  to the rendered `dnsconfig.js` (which references the *key*, not the secret) and
  never persisted.
- A configured-but-not-mocked provider exercises the real `OSShell` → `dnscontrol`
  exec path (previously untested; see §6).

Why dnscontrol for Cloudflare: it is already the homelab's mental model for
authoritative DNS, and it matches the existing ACME/DNS-01 token Caddy already uses.
Cloudflare is a first-class dnscontrol provider (`CLOUDFLAREAPI`).

> **Honesty note on the `{"scope":…}` tag.** The rendered records carry a
> `{"scope":"!inside"|"!outside"}` metadata map. This is **Crenel's own annotation**,
> which the faithful fake interprets; real dnscontrol/`CLOUDFLAREAPI` does **not** use
> it to implement split-horizon. Crenel achieves split-horizon by running **one
> provider per scope** (Cloudflare for public, AdGuard for internal) — each provider
> instance is bound to a single scope and zone — so the tag is **decorative** on the
> single-provider, single-scope invocation Crenel actually makes. The live trial should
> confirm the installed dnscontrol version ignores (does not reject) the unknown record
> metadata; if it rejects it, drop the tag from `renderConfigJS`.

### 3b. AdGuard Home — native control-API driver (internal, rewrites)

AdGuard Home is **not** an authoritative DNS server and is **not** a dnscontrol
provider. It is a recursive resolver whose **rewrites** feature overrides answers for
specific names. So it gets its own adapter, `internal/drivers/dns/adguard`, that
speaks the AdGuard **control API** over an injectable HTTP seam (`Doer`, mirroring
the `ports.Transport` pattern so tests inject a fake and no socket is opened):

| Crenel op | AdGuard control API |
|---|---|
| `LiveRecords` | `GET /control/rewrite/list` → `[{domain, answer}, …]` |
| add (`Apply`) | `POST /control/rewrite/add`  `{domain, answer}` |
| remove (`Apply`) | `POST /control/rewrite/delete` `{domain, answer}` |

Mapping: a Crenel `Record{Name, Type:"A", Value}` ⇄ an AdGuard rewrite
`{domain: Name, answer: Value}`. On read-back, an answer that parses as an IP is
reported as an `A` record, otherwise `CNAME`. The driver's scope is always
**internal** (AdGuard is the LAN resolver; it can never be public-authoritative —
configuring it `public` is a config error, flagged loudly).

Auth: AdGuard Home's control API takes **HTTP Basic** credentials (the same account
as the web UI). The driver sends `Authorization: Basic …` built from the configured
user + password (or password env-ref).

---

## 4. Credentials & secret handling

**Principle (from SECURITY.md §1): the operator owns the secret; Crenel only
references and redacts it.** Two ways to supply each credential, preferred first:

1. **Env-var reference** (`*_env` field): Crenel reads the named env var at wiring
   time. The secret **never appears in any config file on disk** — the same posture
   as Caddy's `{$CLOUDFLARE_API_TOKEN}`. **Recommended.**
2. **Literal** (`api_token` / `password` field): accepted for flexibility, but the
   value is a real secret in the config file. It is **redacted at every output
   boundary** because its JSON key (`api_token`, `password`) is in
   `redact.secretKeyParts` — so `status`/`audit`/error echoes/`export --redacted`
   mask it to `••••<last4>`. The **apply path keeps the real value** (the redaction
   guarantee in SECURITY.md §6: redaction changes only what is *printed*, never what
   is written).

Config shape (`DNSProviderSettings`, also mirrored on the single-provider
`DNSSettings` for back-compat):

```yaml
dns:
  enabled: true
  providers:
    - type: cloudflare           # public, authoritative
      scope: public
      zone: edge.homelab.example   # a DEDICATED, all-crenel-owned zone (NOT the mixed apex)
      edge_addr: 203.0.113.7   # VPS edge — what the public A record points at
      dedicated_zone: true        # REQUIRED: assert crenel owns the whole zone (default deny)
      api_token_env: CLOUDFLARE_API_TOKEN   # preferred: env-ref, never on disk
      # api_token: "…"            # literal alternative (redacted in output)
    - type: adguard              # internal, resolver rewrites
      scope: internal
      zone: homelab.example
      edge_addr: 10.0.0.13      # home Caddy — what on-LAN clients resolve to
      endpoint: http://10.0.0.53:3000   # AdGuard control API base
      username: admin
      password_env: ADGUARD_PASSWORD       # preferred env-ref
      # password: "…"             # literal alternative (redacted in output)
```

If DNS is enabled and a real provider is selected but its credential resolves empty
(env var unset and no literal), wiring **fails fast** with a clear message rather
than silently sending an unauthenticated request — the missing-credential check is
in `cmd/crenel/dns_wire.go` and surfaces through `build()`'s error return.

---

## 5. Default-deny / safety posture

DNS automation that points names at machines is one careless wildcard away from an
outage or an exposure. The safety design:

1. **Opt-in, mock-by-default.** `dns.enabled` is `false` by default; with no `type`
   (or `mock: true`) the provider is the in-process fake — **no real provider is ever
   contacted without explicit operator intent.**
2. **Zone confinement (the AdGuard guardrail).** The internal driver **refuses** to
   add/remove a rewrite whose domain is **not a subdomain of its configured zone**,
   and refuses a **bare-wildcard** desired record. This is exactly the failure the
   wiki warns about: AdGuard itself would *happily* accept `www.smallbiz.example →
   10.0.0.13` and break the marketing site — Crenel is the layer that says no. The
   faithful fake (§6) confirms the API *would* accept it; the **driver** is what
   refuses, and a test asserts the add request never reaches the fake.

2a. **No-destructive-push guard (the Cloudflare guardrail).** `dnscontrol push` is
   **whole-zone authoritative** — it deletes any live record absent from the rendered
   `dnsconfig.js`. Crenel's narrow `Name/Type/Value` model cannot faithfully re-render
   the whole zone, so a push would **corrupt or delete** records it can't represent —
   e.g. dropping a domain's MX (an email outage) on the very first `expose`. The driver
   therefore **refuses to push** (at **both plan and apply time**) a zone whose live
   state contains either:
   - a **multi-field** type — MX preference, SRV priority/weight/port, CAA, SOA — the
     single-value render form can't carry; or
   - a **multi-value set** — more than one record at the same name+type (round-robin A,
     SPF + verification TXT, a multi-NS delegation) — which the value-blind
     `Record.Key()` collapses to one on the round-trip.

   It allows only single-valued `A/AAAA/CNAME/TXT/NS/PTR`, excepting the auto-managed
   apex NS/SOA set (which the render also EXCLUDES — declaring them would fight the
   provider).

2a-i. **Ownership default-deny (`dedicated_zone`).** The fidelity check above is
   necessary but **not sufficient**: a zone whose only record is a single load-bearing
   **wildcard** (`*.homelab.example A`, the real homelab.example shape) is a *renderable*
   single A — it passes the fidelity check, yet a whole-zone push would make Crenel
   **authoritative over a record it does not own**. Because `model.Record` carries no
   ownership marker (unlike `model.Route`), Crenel cannot statelessly tell its own prior
   records from foreign ones. So by **default Crenel REFUSES to push a zone that holds any
   pre-existing record it does not manage**. "Manages" is **value-aware**: a live record
   counts as Crenel's only when it matches a managed record by name/type AND value — so a
   foreign record sitting at the op's own name (a value Crenel didn't author) is refused,
   never silently overwritten by the push. First-`expose`-onto-empty, unexpose, and
   idempotent re-expose of a Crenel host all pass; a value *change* on a non-dedicated
   zone is refused (Crenel can't prove it owns the prior value — set `dedicated_zone`). The
   apply-time check uses the SAME managed set as the plan (carried on the change), so a
   `reconcile`/declarative apply never flags an already-correct managed record as foreign.
   To manage a real zone the
   operator sets **`dedicated_zone: true`** on the provider, an explicit assertion that
   Crenel owns the ENTIRE zone — only then is whole-zone management allowed (the fidelity
   refusals still apply). First-`expose`-onto-empty needs no opt-in. The safe production
   configuration is a **dedicated, delegated zone** (e.g. `edge.homelab.example` as its own
   Cloudflare zone). This was the gap the live preview on homelab.example surfaced.

2a-ii. **Record-attribute fidelity (TTL + proxied).** When the whole-zone render
   reproduces a record it did **not** change, it carries that record's **TTL** (`TTL(n)`)
   and **Cloudflare proxied state** (`CF_PROXY_ON` for an orange-cloud A/AAAA/CNAME)
   through **unchanged** — so a push never silently resets a sibling's TTL (Auto → 300) or
   un-proxies an orange-cloud record. `model.Record` gained `TTL`/`Proxied` (NOT part of
   `Key()`), `LiveRecords` reads them from the real `get-zones --format=tsv` layout
   (`NameFQDN, ShortName, TTL, IN, Type, Target [, cloudflare_proxy=true]`), and the render
   re-emits them (Cloudflare-gated). Proxied **OFF** is indistinguishable from absent in
   the TSV (only ON emits a token), so grey-cloud stays grey by default; a proxied record
   reads back at TTL=1 (auto) — Crenel treats 1/0 as auto, not drift.

2b. **Value-aware updates.** Both drivers treat a live record at the same name/type but
   a **different value** as an **update**, not a satisfied no-op: the Cloudflare driver
   re-asserts the record so the new value lands (and read-back then truthfully passes),
   and the AdGuard driver surfaces a same-domain/different-answer **conflict** rather
   than silently writing an ambiguous second rewrite. (A naive key-only diff would
   silently leave a stale public IP in place.)
3. **Exact records only.** `DesiredRecords` emits one exact host record per op
   (`grafana.<zone>`), never a wildcard — so an `expose` can never widen beyond the
   single name the operator named.
4. **Make-before-break ordering** (§2): a client is never pointed at a route that
   doesn't exist yet; the world is the last to learn of an expose and the first to be
   told of an unexpose.
5. **Read-back verification.** `LiveRecords` after apply confirms the record is
   actually present (expose) / absent (unexpose). A 2xx from a provider is necessary
   but never sufficient — the same posture as the edge drivers.
6. **No persisted desired state.** As everywhere in Crenel, there is no DNS config
   file that is "the truth" — the truth is the live zone / live rewrite list, read
   every time.

---

## 6. Failure modes & faithful fakes

The fakes are not stubs — they **reject what the real APIs reject**, so the
RED→GREEN tests prove Crenel handles the real failure surface, not a happy path.

### 6a. Cloudflare (faithful dnscontrol `Shell`, `dnscontrol/cloudflarefake`)

Models documented Cloudflare API behavior surfaced through `dnscontrol`:

| Failure | Real Cloudflare | Fake behavior |
|---|---|---|
| **Auth failure** | 403 `Invalid request headers` (10000) on a bad/expired token | empty/unknown token in `creds.json` → `Run` returns an auth error |
| **Zone mismatch** | token cannot see the zone → "could not find zone" | `D("zone")` not in the fake's account zones → zone error |
| **Conflicting record** | 81053 — can't add an `A` where a `CNAME` already exists at that name | live `CNAME` at the name + push adds `A` → conflict error |
| **Invalid content** | 9005/1004 — `A` value not an IP | non-IPv4 `A` value → invalid-content error |
| **Rate limit** | 429 — "More than N requests per 300s" | `RateLimited` set / call-count exceeded → 429-style error |

### 6b. AdGuard Home (faithful control-API server, `adguard/adguardfake`)

Implements the `Doer` seam as an in-process fake of the control API:

| Failure | Real AdGuard | Fake behavior |
|---|---|---|
| **Auth failure** | 401 when Basic creds are wrong/absent | wrong/absent `Authorization` vs configured creds → 401 |
| **Conflicting rewrite** | adding an entry where the domain already maps to a **different** answer is ambiguous split-horizon | driver reads live first and **refuses** (clear error); fake also returns 400 on an exact-duplicate add as a backstop |
| **Zone hijack** (the dangerous one) | AdGuard **accepts** an out-of-zone domain (no zone concept) — this is the trap | **driver refuses** before any call; test asserts the fake received **no** add |
| **Rate limit** | a fronting proxy (Caddy/Authelia) can return 429 | `RateLimited` set → 429 |
| **Malformed** | 400 on bad JSON | bad body → 400 |

### 6c. The real exec path (`OSShell`)

Previously **never exercised** by the suite (tests inject a fake, by design). This
design adds a test that runs `OSShell` against a **throwaway fake `dnscontrol`
script** on a temp path (`OSShell{Bin: …}`): it proves the real `exec.CommandContext`
seam passes args, sets the working dir (where `dnsconfig.js`/`creds.json` live),
captures stdout+stderr, and propagates a non-zero exit as an error — **without
contacting any real DNS provider.** This closes the one untested seam between Crenel
and `dnscontrol` while preserving the "touches no real infra in CI" guarantee.

### 6d. Other operational failure modes (documented, handled by existing machinery)

- **Cloudflare propagation lag** (~30–60s before authoritative NS serve a new TXT/
  record; see the DNS-01 runbook): Crenel's `Apply` returns when `dnscontrol push`
  reports success; **read-back of public propagation is best-effort** — `LiveRecords`
  reads the zone via the API (authoritative-immediate), not via a recursive resolver,
  so it does not block on edge-NS propagation. (Trial caveat in §9.)
- **Partial split-horizon** (public applied, internal failed or vice-versa): surfaces
  as a failed step in the apply report and a **cross-scope divergence** in `status`
  (the two scopes are read independently). Crenel does not auto-reconcile across
  scopes — it reports, the operator decides.
- **Known limitation — `reconcile` value-drift.** The apply path (`expose`) is now
  value-aware: a managed record pointing at the wrong value is updated and
  read-back-verified. But the separate `reconcile` drift-fixer still classifies managed
  records by name/type only, so a managed record whose VALUE has drifted (e.g. the edge
  IP changed out-of-band) is not auto-corrected by `reconcile` — an explicit re-`expose`
  corrects it. Making `reconcile` value-aware is a tracked follow-up (out of scope for
  this workstream).

---

## 7. Wiring & render

`cmd/crenel/dns_wire.go` dispatches on `spec.Type`:

- `""` / `"mock"` (or `mock: true`) → dnscontrol driver with the simple in-process
  fake — today's behavior, the safe demo path.
- `"cloudflare"` → dnscontrol driver with `Provider{CredsKey:"cloudflare",
  Type:"CLOUDFLAREAPI", Creds:{"apitoken": <resolved>}}`; real `OSShell` unless
  `mock: true`.
- `"adguard"` → the native AdGuard driver with the resolved endpoint + Basic creds;
  real HTTP `Doer` unless `mock: true`.

Credential resolution (`*_env` → `os.Getenv`, else literal) and the missing-credential
check live here; `buildDNS` now returns an error, threaded through `build()`.

`render.go` (`renderConfigJS`) takes the provider key + registrar instead of the
hardcoded `mock`/`none`. With an empty provider it renders byte-identically to before.

---

## 8. Pre-trial assumptions & the live-trial gate — RESOLVED (historical)

This design originally shipped with a list of conservative assumptions (control-API
endpoint/auth, token scope, the dedicated-zone constraint, the dnscontrol TSV/metadata
contract, exact-vs-wildcard posture) and a gated live-trial plan. Both are now
**historical** — the assumptions were confirmed and the gated trials ran and passed:

- **Dedicated-zone Cloudflare (whole-zone dnscontrol path):** proven live on the
  dedicated `crenel.sh` zone — expose → public `dig` on the real resolvers → unexpose →
  NXDOMAIN, idempotency ×2, and a true cross-provider rollback — against the real
  `dnscontrol` binary (4.42.0), which validated the `get-zones` TSV +
  `CF_PROXY_ON`/TTL contract this section had flagged. See `STATE-OF-CRENEL.md` §0a.
- **Surgical (record-level) Cloudflare in a shared zone:** proven first on `crenel.sh`,
  then on the real shared production zone — Crenel touched only its own
  `managed-by:crenel`-marked record and the operator's pre-existing wildcard stayed
  byte-identical across expose/unexpose (§11 below;
  `TRIAL-RECORD-live-proofs-2026-06-30.md` §1).
- **AdGuard control-API driver + dual-resolver split-horizon:** proven live on a
  disposable instance, then across both production resolvers together, each restored
  byte-for-byte — with the `dns_coverage_parity` audit catching a real divergence
  (§12 below; `TRIAL-RECORD-live-proofs-2026-06-30.md` §2).
- **Per-host exact public records** (Crenel never touches an operator wildcard) shipped
  as the default, exactly as this section assumed.

What remains genuinely live-only on the DNS side is tracked in `STATE-OF-CRENEL.md`
§6.z — not here.


## 11. Surgical (record-level) Cloudflare mode — managing a host in a SHARED zone

The whole-zone path above (`dnscontrol push`) is the right tool for a **dedicated,
all-crenel zone**, but it is structurally unable to manage a single host inside a
**shared production zone** (the real `homelab.example`, with its MX, `www`, wildcard,
SPF): a whole-zone push is authoritative over everything it renders, and Crenel's
narrow model can't faithfully re-render what it doesn't own — hence the
`dedicated_zone` gate that REFUSES the shared zone outright.

**Surgical mode is the non-destructive sibling.** It drives the Cloudflare REST API
**directly**, one record at a time, and is selected with `apply_mode: surgical` on a
`type: cloudflare` provider:

```yaml
dns:
  enabled: true
  providers:
    - type: cloudflare
      apply_mode: surgical          # ← the per-record REST path (vs "" / "whole-zone")
      scope: public
      zone: homelab.example          # MAY be a shared zone — dedicated_zone NOT required
      edge_addr: 203.0.113.7     # the public edge a created A record points at
      api_token_env: CLOUDFLARE_API_TOKEN   # Zone:DNS:Edit on this zone; never on disk
      proxied: false                # orange-cloud state for CREATED records (default grey)
      # zone_id: "..."              # optional: pin the zone id, else resolved by name
```

Driver: `internal/drivers/dns/cloudflare` (native REST), over an injectable `Doer`
HTTP seam (mocked in tests — the suite contacts no real Cloudflare), mirroring the
AdGuard driver's structure.

### 11a. The ownership marker IS the safety boundary

Every record Crenel CREATES carries a Cloudflare `comment` of the form
`managed-by:crenel host=<name>`. A record is Crenel's to manage **iff** its comment
begins with `managed-by:crenel`. This is the single load-bearing invariant:

- The low-level mutate primitives (`updateRecord`, `deleteRecord`) **REFUSE** to act on
  any record whose comment lacks the marker — so even a logic bug upstream cannot
  delete or overwrite a foreign record (defense in depth).
- `LiveRecords` (what `status`/`audit`/read-back see) reports **only** marked records —
  Crenel's footprint, never the operator's foreign records.
- `CREATE` is always Crenel's own (it stamps the marker), so it carries no precondition;
  it is gated instead by the foreign-conflict rule below.

### 11b. Expose / unexpose semantics (per-record)

`expose host` reads the full live zone and:

- **absent** at `host`/A → CREATE one A → edge, stamped with the marker.
- **a marked record present, right value** → idempotent no-op.
- **a marked record present, wrong value** → UPDATE in place (PUT by id), preserving the
  marker, TTL, and proxied state — so a re-expose corrects a drifted edge IP.
- **a FOREIGN (unmarked) record sits at `host`/A** → **REFUSE** (default-deny). Creating a
  second A would shadow/round-robin it; updating it would overwrite a record Crenel does
  not own. Crenel writes nothing and surfaces the conflict.

`unexpose host` DELETEs **only** the marked record(s) at `host`/A (by id). A foreign
record at the same name, or an absent name, is a clean no-op. Value is not matched on
teardown — an owned record is Crenel's to remove even if its value drifted.

Both Diff and Apply re-read live state and re-derive every mutation, so the ownership
check is enforced against current reality (not a stale plan). Removes precede adds.

### 11c. Guard posture vs whole-zone mode

| | whole-zone (`dnscontrol`) | surgical (`apply_mode: surgical`) |
|---|---|---|
| Shared zone | REFUSED unless `dedicated_zone: true` | **Allowed** — touches only owned records |
| `dedicated_zone` | required for a non-empty shared zone | **not used** (per-record, no whole-zone authority) |
| Foreign record at op's name | n/a (whole zone) | **refused** (default-deny) |
| Unmarked record | n/a | **never** updated/deleted (primitive-level refusal) |
| Wildcard / out-of-zone name | refused | refused |
| Apply unit | one rendered zone, pushed | individual CREATE/UPDATE/DELETE by id |

Surgical mode is the path intended for the gated **homelab.example** trial: it is the
only mode that can safely manage one homelab host alongside the live MX/marketing/
wildcard records, because it provably never reads-to-overwrite and never touches a
record lacking Crenel's marker.

### 11d. Faithful fake & failure surface

`internal/drivers/dns/cloudflare/cfapifake` is a faithful in-repo fake of the
Cloudflare v4 API (both a `Doer` and an `http.Handler` for the real-OSDoer Bearer-auth
loopback test). It REJECTS what real Cloudflare rejects — bad/absent token (403/10000),
non-IPv4 A content (9005), identical-duplicate (81058), A/CNAME collision (81053),
unknown record id on PUT/DELETE (81044), rate limit (429/971) — and, crucially, it does
**not** itself enforce Crenel's marker (real Cloudflare would happily let the token
delete any record). That foreign records are never touched is proved as the **driver's**
guarantee: tests seed a zone with foreign records (`*` wildcard, MX, `www` A, SPF TXT)
and assert they are byte-identical before/after expose+unexpose, that a refused expose
reaches no mutating call, and that the primitives refuse an unmarked record.

---

## 12. Dual-resolver split-horizon — two AdGuard instances, one per vantage

The homelab runs **two** internal resolvers, split by client *vantage* (Tailscale
presence): a **home** AdGuard answers no-tunnel clients, a **VPS** AdGuard answers tunnel
clients. Crenel models this as **two `scope: internal` AdGuard providers** in `dns.providers`
— same zone, **different `endpoint`** and **vantage-correct `edge_addr`**, each distinguished
by an **`instance`** label (`"home"`, `"vps"`). The engine already plans/applies/verifies N
providers per scope independently (one `cs.DNS[i]` per provider, stable-sorted, per-provider
Diff/Apply/verify), so two same-scope providers compose without special-casing. See
`examples/settings-dual-adguard.json` and `docs/REFERENCE-ARCH-split-horizon.md`.

### 12a. Per-instance labeling & ownership (honest about AdGuard's API)

`adguard.Config.Instance` is woven into `Driver.Name()` → `adguard[home]` / `adguard[vps]`,
so the two are distinguishable in **every** plan/apply/verify/audit label and in the
conflict/guard error text (an operator always knows WHICH resolver a finding or refusal
belongs to; before this, both rendered as a bare `adguard`).

Ownership is **per-instance and marker-less by necessity**: an AdGuard rewrite is
`{domain, answer}` only — the control API has **no per-record comment/metadata field**, so
Crenel **cannot** stamp a record-level ownership marker the way the surgical Cloudflare
driver does (§11a). Ownership here is therefore **zone-confinement + value-match**, evaluated
**independently against each instance's own endpoint**: each provider refuses a wildcard, an
out-of-zone name, and (the load-bearing guarantee) a same-host/**different-answer** overwrite
on its own instance — naming itself in the refusal. This is the faithful analogue of the
Cloudflare marker for an API that has no metadata to mark with; provenance across the two
instances is tracked by Crenel's config manifest, not by anything readable on the box.

### 12b. The `dns_coverage_parity` audit (the drift the design exists to catch)

"Sync" for the dual resolver is **same coverage, vantage-correct targets** — both must cover
the same managed host set, but each may legitimately answer with a *different* per-vantage
address. So a new **cross-instance** audit, `dns_coverage_parity`, compares the live **host
sets** (not values) of all `scope: internal` providers and surfaces, as a first-class
**warning**, any host present on one resolver but **missing** from another — naming the host,
where it is present, and where it is missing. This is the exact silent drift discovery found
in the field (a host with an exact rewrite on the VPS resolver but not the home one, so
tunnel and non-tunnel clients resolve it differently — see the reference-arch doc). It is the
DNS-provider sibling of the cross-edge `edge_inconsistent_exposure` check, and like it a
warning (flips the report's `OK()` without failing CI as critical). Coverage parity is about
**presence**; per-host **target correctness** stays the job of each provider's own
desired-vs-live read-back/reconcile. (Note: AdGuard has no provenance marker, so parity is a
value-blind presence check — two same-scope providers SHOULD set distinct `instance` labels
so present/missing name the right resolver.)

#### 12b.i Wildcard-aware coverage (cry-wolf fix from the live drift)

A naive `LiveRecords` host-set diff treats `*.homelab.example` as a literal name, which
double-fires: the audit cries wolf both on the wildcard *pattern* itself (present on one
resolver, "missing" from another) and on every explicit host the other resolver carries
that the first resolver answers *via* the wildcard (e.g. `adguard.homelab.example`). That is
exactly the false positive observed on the home/VPS pair after `dns_value_drift` shipped.
So the parity check is **wildcard-aware**:

- The compared union is built from **EXPLICIT** rewrite names only — a wildcard pattern is
  not a host, so it never enters the union.
- A host `h` is treated as **present** on resolver `R` if either `R` has an explicit
  rewrite for `h`, or any wildcard pattern on `R` covers `h` (`*.zone` covers any name
  ending in `.zone`, suffix-match; AdGuard's wildcards live in this shape).
- **Value-mismatch guard (don't hide real drift).** Wildcard substitution is only treated
  as parity-clean when the wildcard's answer value matches at least one explicit value
  for `h` across the other resolvers. Otherwise the wildcard answers the wrong target for
  that host — explicit `host`→A on `R1` vs covering `*.zone`→B on `R2` (with B ≠ A) is a
  silent misdirect on `R2`'s clients, and the audit still flags it (as
  `dns_coverage_parity` with a value-aware message that names the host, the resolver, the
  wildcard pattern, the wildcard's value, and each resolver's explicit value).
- The pure vantage case (two resolvers, two EXPLICIT entries with intentionally different
  vantage targets, **no** wildcard substitution) is unchanged and remains parity-clean.

#### 12b.ii Wildcard-aware sibling checks (`dns_without_edge_route` / `edge_route_without_dns`)

The same cry-wolf class hits the two sibling DNS-vs-edge checks, which read NAMES only:

- `dns_without_edge_route` (a DNS record whose host has no backing edge route) always
  fires on a wildcard, because `*.zone` is never a literally-exposed host name. With
  wildcard awareness, a wildcard rewrite is treated as a CATCH-ALL that is "backed" by
  any exposed host under its zone. The dangling check fires only when **nothing** is
  exposed under `.zone` (the wildcard answers names Crenel cannot reach — a real
  misdirect that still flags, critical for public scope to match the explicit case).
- `edge_route_without_dns` (an exposed host with no DNS record) cries wolf when the
  zone is served by a single catch-all wildcard with no explicit per-host entries.
  With wildcard awareness, a host is "reachable by name" if either an explicit record
  names it OR any wildcard covers it; the suppression is name-only — value correctness
  for any one host stays the job of the per-provider desired-vs-live read-back and, for
  owned records, `dns_value_drift` / `DriftValueDNS` on `reconcile`.

This matches the parity check's posture: suppress only when the wildcard actually
covers/backs the thing being checked; do NOT hide a real gap (out-of-zone wildcard,
no-backing wildcard).

#### 12b.iii Wildcard-aware drift / reconcile (`missing_dns_record` / `stale_dns_record`)

The same class hits `reconcile`'s two DNS drift kinds, which also matched by NAME only:

- `missing_dns_record`: an exposed host whose desired record key is absent in live was
  flagged as missing — even when a covering `*.zone` wildcard was already answering
  the host with Crenel's desired value. Reconcile would then ADD an explicit record on
  top of the already-answering wildcard (cry-wolf drift + spurious write). With
  wildcard awareness the desired record is treated as already present when a covering
  wildcard's value equals the desired value. A real **value** mismatch under the
  wildcard STILL flags — the wildcard answers the WRONG target, so an explicit record
  is genuinely needed to override it (mirror of the 12b.i value guard).
- `stale_dns_record`: a wildcard is never a canonical exposed host, so every live
  `*.zone` was proposed for **removal**. On the live home resolver that would have
  wiped the load-bearing `*.homelab.example` — a destructive misdiagnosis. Reconcile
  categorically leaves wildcards in place: Crenel does not OWN operator wildcards (the
  AdGuard driver's `guard` refuses to emit one), and a wildcard that backs any
  exposed host is the intentional catch-all.

The rule matches the sibling checks' posture: suppress only when the wildcard is
actually the answer for what reconcile would change; NEVER remove a wildcard.

### 12c. Reaching the VPS instance — transport

Read-only pre-flight on the live homelab confirmed the VPS AdGuard admin binds the tailnet
interface (`*:3000`), so a **direct HTTP `endpoint`** (`http://100.100.0.2:3000`) reaches it —
**no ssh-exec shim is needed**. (The DNS provider has only a direct-HTTP `Doer`; an ssh-exec
`Doer` would be new work, warranted ONLY if a VPS resolver were loopback-only. It is not.)

## 10. File map (what this workstream adds/changes)

- `internal/config/settings.go` — `type` + credential fields on `DNSProviderSettings`
  / `DNSSettings`.
- `internal/drivers/dns/dnscontrol/render.go` — emit real provider/registrar.
- `internal/drivers/dns/dnscontrol/dnscontrol.go` — `Provider` in `Config`; real
  `creds.json` (`0600`).
- `internal/drivers/dns/dnscontrol/cloudflarefake/` — faithful Cloudflare fake shell.
- `internal/drivers/dns/adguard/` — native AdGuard driver + `Doer` seam + faithful
  `adguardfake`.
- `cmd/crenel/dns_wire.go` — type dispatch + credential resolution (error-returning);
  `apply_mode: surgical` selects the native Cloudflare REST driver (§11).
- `cmd/crenel/wire.go` — thread the `buildDNS` error.
- `internal/drivers/dns/cloudflare/` — native surgical Cloudflare REST driver + `Doer`
  seam + faithful `cfapifake` (§11).
- `internal/config/settings.go` — `apply_mode` / `zone_id` / `proxied` / `ttl` fields.
- Tests — see §6 (faithful rejections, OSShell exec, wiring dispatch, redaction) and §11d
  (surgical foreign-untouched proof, ownership refusal, primitive refusal, OSDoer auth).
```
