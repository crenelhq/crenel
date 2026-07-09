# EdgeProvider port — where the second driver strains it

> Written while adding the **Traefik file-provider** driver (M2) as the second
> `EdgeProvider` implementation. A port with only one implementation (Caddy) is
> fake agnosticism; this document is the honest accounting of where the abstraction
> holds, where it strains even for a well-fitting edge, and where a genuinely
> different (mesh) edge would force it to error loudly. This is the whole point of
> doing the second driver now.

## Verdict

For a **dumb data-plane edge** (Traefik, like Caddy: it routes host → backend and
denies the rest), the `EdgeProvider` port **holds with no interface changes**.
`core` drives the Traefik driver end-to-end — plan → apply → read-back-verify →
structural default-deny — exactly as it drives Caddy (`core.TestCore_DrivesTraefikEdge`).
One **responsibility correction** was surfaced and made (NewPublic → core, below).
Deeper **expressiveness** gaps exist in `model.Upstream`; they are real but are NOT
exercised by either current driver, so they are documented here with a recommended
fix rather than speculatively changing the port now.

> **UPDATE (M12): a FOURTH driver — nginx — confirms the verdict at breadth.** After
> Caddy (admin API), Traefik (JSON file), and NetBird (identity mesh), the **nginx**
> config-file driver is a third config SHAPE again: the nginx brace DSL, with
> **comment-marker ownership** (`# crenel-managed:`) rather than @id (Caddy) or
> key-prefix (Traefik). The port held with **no interface change**:
> `core.TestCore_DrivesNginxEdge` drives it end-to-end, and it slots straight into
> the multi-edge + reconcile machinery (`TestCore_NginxInHeterogeneousReconcile`).
> Same properties as Traefik — additive read-modify-write (unmanaged vhosts
> preserved verbatim), structural default-deny always rendered (a `default_server`
> returning 444), no admin endpoint so `HealthChecker` stays unimplemented. The ONE
> new strain it surfaces: parsing a brace DSL by text needs a small tokenizer
> (`codec.go`'s `splitTopLevel`) — faithful but more fragile than a structured
> format; a production driver would lean on `nginx -t` / a real parser. nginx
> *could* also do SNI passthrough via the `stream`/`ssl_preread` module, which would
> be a capability gate exactly like the Caddy `layer4` one — left as future work; it
> refuses passthrough loudly today.

## What fit cleanly (abstraction confirmed)

- **The five methods map directly.** `Name / Validate / ReadLiveState / Plan /
  Apply` all have natural Traefik meanings. `Plan` is *byte-for-byte the same
  shape* as Caddy's (resolve origin on expose, remove host on unexpose) — strong
  evidence the port captures the real verb semantics, not Caddy's.
- **Structural default-deny generalised.** Traefik denies unmatched hosts with an
  implicit 404, exactly like Caddy. `DenyCatchAllPresent` is reported truthfully
  (false only when a router forwards *all* hosts to a real backend — a permissive
  catch-all), and Apply always renders the explicit `crenel-deny` catch-all. The
  invariant is edge-agnostic.
- **Additivity generalised via a different mechanism.** Caddy gets additivity from
  structured admin-API ops; Traefik gets it from an additive read-modify-write of
  the dynamic-config file touching only `crenel-*` keys. Same property
  (unmanaged routers/services — Authelia, dashboards — survive untouched), proven
  the same way (`TestApply_AdditiveExposePreservesUnmanaged`), via a completely
  different transport. That the *property* survived the transport change is the
  best signal the abstraction is real.
- **`HealthChecker` is correctly OPTIONAL.** A file provider has no admin endpoint
  to wedge, so the Traefik driver does **not** implement `ports.HealthChecker`, and
  `core` handles its absence gracefully (the wedge-safe rollback path simply treats
  the edge as never-wedged). The second driver *validated* the optional-capability
  design instead of requiring a change to it.

## Where it strains even for Traefik (documented, not yet fixed)

1. **"Live state" is muddier for a declarative-file edge.** Caddy's admin API
   returns the **running** config, so `ReadLiveState` is a true read-back and the
   silent-reload footgun is catchable. Traefik's file provider has no such API: the
   file is the **desired** config and Traefik hot-reloads it; if Traefik rejects a
   bad dynamic config it keeps serving the old one, so **file ≠ running** until the
   reload succeeds. This driver reads the file (file == live, against the fake). A
   production-grade Traefik driver would *additionally* read Traefik's read-only API
   (`GET /api/http/routers`) to confirm the running state — i.e. reconstruct the
   read-back the Caddy admin API gives for free. The port doesn't forbid this (the
   driver can read whichever source it wants), but it does **assume** `ReadLiveState`
   returns running truth — an assumption that is free for API edges and costs an
   extra integration for file edges. Noted on `ReadLiveState`'s doc comment.

2. **`model.Upstream` couldn't express TLS/SNI passthrough — NOW FIXED (typed
   route Mode).** Originally `Upstream` carried only `TLSPassthrough bool`, which
   neither driver used; both emitted HTTP reverse-proxy routes, and the flat
   `Route{Host, Upstream}` had no way to say "L4 SNI-passthrough" vs "L7
   reverse-proxy" vs "identity-mesh grant". **Built:** `model.RouteMode` on
   `Upstream` and `Op` (`ModeHTTPProxy` default | `ModeTCPPassthrough` |
   `ModeMeshGrant`), a shared `model.ErrModeUnsupported`, and `--mode`/`--param`
   CLI flags. Each driver now declares what it can express and **errors loudly**
   (wrapping `ErrModeUnsupported`) on the rest:
   - **Traefik** expresses `ModeHTTPProxy` AND **`ModeTCPPassthrough`** — the
     latter is now a REAL renderer (M9): it writes a `tcp.routers` entry with
     `HostSNI(...)` + `tls.passthrough: true` and a TCP service, additively (HTTP
     routers + the deny preserved), reads it back as a passthrough route, and
     removes it on unexpose. The previously-inexpressible SNI passthrough now
     works on a real driver.
   - **Caddy** expresses `ModeHTTPProxy` AND — as of M11 — **`ModeTCPPassthrough`**
     via the **`layer4` app** (github.com/mholt/caddy-l4): it inserts an @id-tagged
     SNI-matched `proxy` route into a managed `crenel-l4` layer4 server (match
     `tls.sni`, raw-TCP proxy, no TLS termination), reads it back as a passthrough
     route, and removes it on unexpose. This is **capability-gated** (`WithLayer4` /
     `caddy_layer4`): the plugin is not in stock Caddy, so WITHOUT the gate the
     driver refuses passthrough LOUDLY rather than emit config a stock Caddy would
     reject. It also requires granular apply so the additive layer4 write never
     disturbs the http routes / deny / TLS. Caddy still refuses `ModeMeshGrant`
     loudly. So **SNI passthrough now renders on BOTH data-plane edges** (Traefik
     `tcp.routers` + Caddy `layer4`) — the same typed intent, two faithful
     renderers, each refusing what it genuinely can't express.
     - *Residual strain:* layer4 binding `:443` must front the http app (real
       deployments put the http app on a loopback port and let layer4 dispatch
       non-passthrough SNIs to it). The driver models the routes additively but does
       not orchestrate that listener hand-off — an edge-provisioning concern, noted.
       Full-load (non-granular) apply cannot coexist with the separate layer4 app
       (it would clobber it), which is why passthrough requires granular — full-load
       remains greenfield-only as documented since M0.
   - **NetBird** expresses its NATIVE `ModeMeshGrant` (a real Plan+Apply writing a
     WireGuard ACL grant) and refuses HTTP-proxy / passthrough — so the mesh is no
     longer read-only; it does its native thing and refuses the rest.
   Same intent (`ModeTCPPassthrough`) is honoured where a driver can render it
   (Traefik) and refused loudly where it can't (Caddy) — the whole point of the
   typed mode. (Tests: per-driver mode-refusal + Traefik passthrough round-trip +
   NetBird mesh-grant round-trip.)

3. **No notion of auth/middleware composition — NOW BUILT (forward-auth by
   reference).** Originally Crenel could **preserve** an unmanaged router's
   middleware chain (`authelia-forward`) but could not **compose** one: "expose host
   X *behind Authelia*" was inexpressible. **Built (AUTH):** an exposure carries an
   `Auth` policy NAME (`model.Op`/`Upstream`), and each driver renders a per-driver
   forward-auth **reference** — Caddy a granular `forward_auth` handler (+ `import
   <snippet>` on persistence), Traefik a named middleware, nginx an `auth_request` —
   resolved from `auth_policies` provider config (default conventions). The line the
   strain drew ("exposure ≠ authz policy") is **honored, not crossed**: Crenel
   attaches a policy by reference and **never embeds the auth provider's internals**
   (verify URL/headers/cookies stay in the operator's snippet). Auth is orthogonal to
   default-deny; it is HTTP-only (`model.ValidateAuth` refuses it on SNI passthrough —
   no HTTP layer — and on a mesh grant — identity-enforced). Adoption still preserves
   existing auth verbatim and now *recognizes* it read-only (`(detected)`). A
   `public_without_auth` audit check + a loud expose/apply guardrail (`--auth none`
   the explicit opt-out) make publishing an unprotected service a deliberate choice.
   See **AUTH-DESIGN.md**. (Tests: per-driver render+round-trip, brownfield
   adopt-preserves-auth + new-expose-references-policy, passthrough refusal, guardrail.)

4. **Serialization format.** Real Traefik file providers use YAML/TOML; this driver
   uses JSON to keep Crenel a zero-dependency offline build. The format is isolated
   to `codec.go` (one `encode`/`decode` pair) so a real deployment swaps in a YAML
   codec without touching the driver logic. The dynamic-config *shape* is faithful.

## Where an integrated MESH edge forces the port to error loudly — NOW BUILT

> UPDATE: this is no longer just a prediction. The **NetBird identity-mesh driver**
> (`internal/drivers/edge/netbird`) implements exactly this and is tested
> (`netbird_test.go`, `core.TestCore_NetbirdEdgeReadsButRefusesMutation`): READ
> verbs work (a mesh reads as default-deny by construction; grants surface
> read-only with a deliberately non-HTTP `mesh-grant:<group>` pseudo-address so the
> collapse is VISIBLE in `status`), while every MUTATION errors loudly with
> `ErrIntentUnsupported` and a message that explains the mismatch and points at the
> typed-route-Mode fix (strain #2). The port supports erroring; this driver is the
> discipline of USING it. M2 proved the port's reach (a second dumb data-plane edge
> fits); the NetBird driver proves the port's LIMITS are handled honestly.

The design predicts that **integrated mesh edges (NetBird, Tailscale `serve`,
Cloudflare Tunnel) collapse transport + identity + auth + SNI into one model** and
should **error loudly on intents they can't express** rather than fake a mapping.
Implementing Traefik made concrete *why*, and the NetBird driver acts on it:

- There is no "route host → backend with a default-deny catch-all" document to
  additively edit. Exposure on a mesh edge is an **ACL grant to an identity/peer**,
  and the edge terminates **WireGuard**, not TLS-by-SNI. `ReadLiveState` has no
  routes-and-a-deny to normalize; the structural default-deny invariant maps to
  "no ACL grant exists," which is a different shape than a catch-all route.
- `model.Upstream{Kind, Address, TLSPassthrough, ServerName}` largely doesn't
  apply: a mesh peer isn't a `dial` address, and SNI/TLS-termination is not the
  mesh's concern.
- **Correct behaviour (now implemented):** the NetBird driver's `Plan` **returns
  `ErrIntentUnsupported`** for the reverse-proxy intent Crenel's Op implies, instead
  of approximating — a leaky pretend-mapping is worse than a loud refusal. `core`
  surfaces the error from `Plan`, so `preview`/`expose`/`unexpose` all fail loudly
  while `status`/`audit`/`export` keep working. This is the typed-intent extension
  recommended in strain #2 in spirit: once a route `Mode` exists, the mesh driver
  would instead express its NATIVE grant intent for a grant-mode op and reject only
  the HTTP-proxy mode.

## Port change actually made this session

- **`NewPublic` moved out of the edge drivers into `core`.** The Caddy driver was
  setting `cs.NewPublic` in `Plan`; a second driver would have had to duplicate
  that logic — and it's *wrong* for an edge to own it, because "publicly reachable"
  depends on **DNS scope**, which an edge cannot know. `core.Plan` now computes
  NewPublic authoritatively (a host goes public when it gains a public-scope DNS
  record, or — with no public DNS managed — when it gains an edge route). The
  Traefik driver therefore sets nothing public-related; it just plans routes. This
  is a concrete port-responsibility correction the second driver surfaced.

No change to the `EdgeProvider` **interface** was required for the second
dumb-data-plane edge — which is the honest, and the intended, result of this
exercise.

## Brownfield usability — what the new optional capabilities strain (UB1–UB4)

Three new optional port capabilities (`Adopter`, `Persister`) plus
`Route.Managed`. None changed the core `EdgeProvider` interface; each is opt-in,
implemented where it makes sense and absent where it doesn't. Where they strain:

- **Ownership is per-driver and DNS has none.** Adoption stamps a marker the driver
  understands (Caddy `@id`, Traefik key prefix, nginx comment). DNS records carry
  no ownership marker, and adding one would reintroduce stored state — so DNS
  managed-ness stays *derived from the `origins` projection*. The result is an
  honest asymmetry: edge routes are adopted by **mutation**, DNS records by
  **recognition**. `import` documents this rather than papering over it.

- **Adoption preserves behavior at adoption time, not arbitrary config forever.**
  Crenel's model is host → backend → mode. Caddy adopt (PATCH @id via the RAW
  config) and Traefik adopt (re-key) preserve *all* surrounding fields verbatim;
  nginx adopt preserves the block body. But the FIRST subsequent crenel-managed
  re-render of a host (an explicit unexpose+expose) renders Crenel's canonical
  form — extras beyond host→backend that the model doesn't capture are Crenel's to
  re-emit. `reconcile` never re-renders a present host, so adopted extras survive
  it; only deliberate re-exposure canonicalizes. Documented in USABILITY-DESIGN §A.

- **Caddy persistence is a genuine dual-write the other edges don't need.** Traefik/
  nginx/DNS already persist (a file, the provider). Only Caddy's in-memory admin API
  needs `Persister`. And because the no-SOT model derives canonical state from LIVE,
  a Caddy restart that wipes Crenel routes leaves `reconcile` with nothing to
  recover from — so Caddy durability MUST come from on-disk persistence or from
  re-running `apply <file>`. This is the sharpest place the live-state-authoritative
  stance and a stateless control plane (Caddy admin API) pull against each other;
  the persistence option + the "re-apply the file" recovery path resolve it
  explicitly rather than pretending reconcile is a backup.

## Real-VPS trial — two strains the live edge surfaced (NEST1, CHAIN1)

A read-only trial against the real VPS edge (`TRIAL-2026-06-27-real-vps-readonly.md`)
exposed two strains that fixtures hadn't, both fixed/mitigated this session without a
port change:

- **`LiveEdgeState.Routes` is FLAT, but a real edge nests.** `normalize` read only
  the top-level `srv0.routes`, so a deeply-nested edge (wildcard → subroute →
  per-host route → subroute → leaf) collapsed ~25 services to 2 opaque wildcards —
  `status` coarse, `import` a no-op, `audit` blind per-service. The port's *shape*
  (a flat `[]Route`) was right; the Caddy driver's *parsing* was shallow. Fixed by
  recursing (`collectLeaves`) so each per-host leaf flattens into one `Route` with
  its real host/dial/ownership/auth — the abstraction held, only the driver's read
  deepened. The matching strain in the fake: PATCH addressed only top-level routes;
  `Adopt` of a nested route needed generic path addressing (`setByPath`), faithful to
  Caddy's real path-addressed admin API.

- **The topology model is PARALLEL (double-write); the real deployment is a CHAIN.**
  M4's multi-edge fans an exposure to several *independent* edges. But the VPS edge
  sits *in front of* a downstream home edge that enforces auth — a front→downstream
  CHAIN the model has no first-class notion of. The immediate symptom was
  `public_without_auth` firing spuriously on the (auth-less) front edge. The minimal
  fix is a per-edge `auth_downstream` posture flag (suppress + label), NOT a chain
  model: Crenel still treats the front edge as terminal for routing/projection. A
  true fix — chain edges as ordered topology, exposure projected across the chain,
  end-to-end read-back through the chain — is real future work, scoped in DESIGN.md
  "Chain topology". This is the honest boundary: the flag removes the wrong warning;
  it does not yet make Crenel *understand* the chain.

## Detect-and-declare-unknown — the strain RELIEF the long tail demanded (P0)

Every strain above is a place reality has a degree of freedom the model collapses —
and the failure that matters is when Crenel collapses it *silently into a confident
wrong answer*. P0 (TOPOLOGY-RISK-REGISTER.md §4, built this session) makes that
impossible without needing to model each topology: `normalize` now EMITS a
`model.Unparsed` entry for anything it can't fully parse (instead of dropping it),
`Coverage()`/`FullyParsed()` make the gap measurable, the default-deny verdict
DOWNGRADES to UNKNOWN whenever the config isn't fully parsed (*ENFORCED ⟹
FullyParsed*), and a `core` pre-mutation gate REFUSES (`ErrRefuseToManage`) to touch
a `foreign`/`unknown`-owned route or edge. So an unmodeled handler, an undescended
subroute, a generator-owned config, or an off-edge ingress now reads as a *declared
unknown* — counted in `status`/`audit`, mutation-blocking — rather than a silent
misread. The port shape is unchanged (additive fields on `LiveEdgeState`/`Route`);
this is bounded honesty layered over the existing two invariants. Generator/ingress
*detection* (which would SET `Generator`/`IngressKind` and turn the relevant
`Unparsed`/ownership signals on automatically) is the P2/P3 follow-on; until then the
net is driven by the parser's own can't-model signals, which is already safe.
