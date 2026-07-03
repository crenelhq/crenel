# Crenel — Forward-auth by reference (design note)

This note nails the semantics for attaching **forward-auth** (Authelia,
Authentik, or any forward-auth provider) to an exposure, designed before the
code. It precedes the build the same way USABILITY-DESIGN.md did.

The shape of the feature is fixed by one principle: **Crenel attaches an auth
POLICY by reference; it never embeds the auth provider's internals.** Crenel
already owns *routing/exposure* and the *structural default-deny*. Auth is a
distinct, orthogonal axis, and the auth system stays the operator's to own.

The two load-bearing invariants do not change: **live state is the only truth**
(no stored desired-state SOT), and **structural default-deny** (a host is
reachable iff an explicit route exists for it). Auth is a *third* property layered
on top, never a replacement for either.

---

## 0. STEP-0 baseline — what existed before this change

Verified by reading the model + every edge driver:

- **No AUTH dimension in the model.** `model.Op` carried `{Verb, Service, Host,
  Mode, Params}`; `model.Upstream` carried `{Kind, Mode, Address, TLSPassthrough,
  ServerName}`; `model.Route` carried `{Host, Upstream, Managed}`. Nothing named
  auth anywhere.
- **No driver rendered forward-auth for a NEW exposure.** Caddy full-load emits
  `reverse_proxy <addr>`; Caddy granular inserts a route with a single
  `reverse_proxy` handler; Traefik creates a router with `{rule, service,
  priority}` and **no** middlewares; nginx renders `location / { proxy_pass … }`.
  Every driver rendered *plain reverse-proxy + route mode* and nothing else.
- **Existing auth was already PRESERVED on adoption / additive apply** (the
  inverse of rendering it): Caddy granular insert leaves an unmanaged route's
  `authentication` handler byte-for-byte intact (`granular_test.go`); Traefik
  adoption re-keys a router preserving its `middlewares` (e.g. `authelia-forward`,
  `secheaders`) verbatim (`traefik_test.go`); nginx adoption preserves the block
  body including an Authelia `auth_request`/upstream verbatim (`nginx_test.go`).
  So Crenel could *keep* hand-built auth but could not *attach* it.

This change adds the missing half — *attaching* an auth reference — while keeping
the preservation half exactly as-is.

---

## 1. The model: an `auth` policy NAME, provider-agnostic

An exposure gains one new field: `auth`, naming a **policy** (e.g. `authelia`,
`authentik`, `none`). It is a provider-agnostic *name*, not a configuration:

- `model.Op.Auth string` — the requested policy for one CLI invocation.
- `model.Upstream.Auth string` — the realized policy on a route (set by a driver's
  `Plan` from the op, and by `normalize` from live for read-back / recognition).
  It sits beside `Mode` for the same reason `Mode` does: it is a per-route
  exposure semantic that `status`/`audit`/`verify` must see.

Three values are meaningful:

| `Auth` value | Meaning |
|---|---|
| `""` (empty) | **unspecified** — no auth policy attached. The default. |
| `"none"` | **explicit opt-out** — the operator deliberately exposes with no auth. |
| any other (`authelia`, …) | a **named policy** Crenel renders a reference to. |

`""` vs `"none"` is the whole safety story: `""` is *silence* (flagged), `"none"`
is a *loud explicit choice* (allowed). `model.Op.HasAuthPolicy()` reports
`Auth != "" && Auth != "none"`.

## 2. The reference lives in PROVIDER CONFIG, rendered per driver

Crenel is auth-provider-agnostic, so the *policy name → per-driver reference*
mapping lives in provider config (`auth_policies`) and each driver renders its
own reference shape:

```yaml
auth_policies:
  authelia:
    # --- Caddy granular admin-API path: ONE of these two renders a VALID gate ---
    caddy_forward_auth: authelia:9080                                  # authorizer endpoint → CANONICAL
    caddy_forward_auth_verify_uri: /api/verify?rd=https://auth.example.com  #   verify path (operator-declared)
    caddy_forward_auth_copy_headers: [Remote-User, Remote-Groups, Remote-Name, Remote-Email]
    # caddy_handler_json: '{ ...verbatim Caddy handler... }'           # OR paste a known-good gate (purest by-reference)
    # --- Caddy on-disk PERSISTENCE path (Caddyfile) ---
    caddy_import: authelia            # `import authelia` inside the persisted site block
    # --- other drivers ---
    traefik_middleware: authelia@file # attach this named middleware
    nginx_auth_request: /authelia     # auth_request to this internal location
```

> **Caddy granular auth needs a JSON-renderable reference.** `caddy_import` is a
> Caddyfile construct with NO admin-API representation, so the granular path uses either
> `caddy_forward_auth` (an authorizer endpoint Crenel expands to the canonical
> `reverse_proxy`+`handle_response` gate) or `caddy_handler_json` (an operator-pasted
> verbatim handler). A snippet-only policy is REFUSED loudly on the granular path (it
> still works on persistence). This is the fix for the live-trial abort — see §2.1.

**Sensible default conventions** mean the map is optional *for the file-based drivers
and the Caddy persistence path*. With no `auth_policies` entry for a policy `p`, Crenel
uses:

- **Caddy (persistence / on-disk Caddyfile)** → `import p` (a snippet the operator defines once).
- **Traefik** → middleware `p@file`.
- **nginx** → `auth_request /p`.

So `--auth authelia` works out of the box for Traefik / nginx / Caddy-persistence,
rendering `authelia@file` / `auth_request /authelia` / `import authelia`. **The Caddy
GRANULAR admin-API path is the exception**: it has no way to express a Caddyfile
`import`, so it needs an explicit `caddy_forward_auth` endpoint or `caddy_handler_json`
blob — without one, granular auth is refused loudly (it never emits invalid JSON). An
explicit `auth_policies` entry otherwise just overrides the convention. The operator
always owns the *actual* snippet / handler / middleware / location — Crenel only emits
the **reference** to it.

The mapping reaches each driver the same way origins do: translated at the `cmd`
composition root into a per-driver option (`caddy.WithAuthPolicies`,
`traefik.WithAuthMiddlewares`, `nginx.WithAuthRequests`). The model stays
driver-free (it carries only the policy *name*); the dependency rule is unchanged.

### Per-driver rendering (additive, preserving everything else)

- **Caddy** — auth is attached on the **granular** path (the production path) and
  the **on-disk persistence** path; the **full-load admin apply REFUSES it**.
  - *Granular JSON*: prepend, before the backend `reverse_proxy`, two handlers —
    (1) a **policy MARKER**: a `vars` handler `{"handler":"vars","crenel_policy":<p>}`.
    Caddy preserves a `vars` handler's keys across a config round-trip (unlike a
    `reverse_proxy`'s unknown fields, which it drops on normalize), so the policy NAME
    round-trips off a **real** edge, and (2) a **VALID gate**, one of:
    - **canonical** (`caddy_forward_auth` endpoint): the `reverse_proxy`+`handle_response`
      expansion Caddy's `forward_auth` directive compiles to — on a 2xx from the
      authorizer, copy the operator-declared `caddy_forward_auth_copy_headers` and
      continue; else return the authorizer's 302. The verify URI and headers are
      **operator-declared** (`caddy_forward_auth_verify_uri` / `_copy_headers`), not
      invented by Crenel. This is the EXACT shape the maintainer's home edge accepts, verified
      byte-for-byte against `live-backup/trial-chain-write-*`.
    - **verbatim** (`caddy_handler_json`): the operator's exact handler JSON, inserted
      unchanged — Crenel owns NONE of the provider's internals (purest by-reference).
    Reading the route back recovers the policy from the marker; an unmarked / brownfield
    gate (a `reverse_proxy`+`handle_response`, a stock `authentication` handler) is
    recognized as `(detected)`. **A snippet-only / default policy is REFUSED** on the
    granular path — the admin API cannot express a Caddyfile `import`, so Crenel errors
    rather than emit a handler Caddy can't load (the live-trial bug; see §2.1).
  - *On-disk persistence Caddyfile* (`caddy_persist_path`): emit the canonical
    `import <snippet>` reference inside the host's site block, before
    `reverse_proxy` (the operator owns the snippet).
  - *Full-load admin apply* (the simple greenfield bootstrap) **cannot** carry the
    operator's auth snippet, so attaching a policy there is **refused loudly**
    (`Plan` errors, directing the operator to `--granular`) rather than rendered
    as a bare unprotected `reverse_proxy`. As of the F1/F2 safety gate, full-load
    also refuses to *strip* auth off an existing route on an unrelated apply.

  **Crenel never invents the provider's verify URL / headers / cookies** — the canonical
  expansion renders only what the operator DECLARED in `auth_policies` (endpoint, verify
  URI, copy-headers), and the verbatim path renders the operator's exact handler. That is
  the "internals" boundary the principle draws (in the same spirit as Traefik-JSON-not-YAML
  and the nginx hand-tokenizer).
- **Traefik** — set the crenel-managed router's `middlewares` to include the
  policy's middleware (default `p@file`). Additive: only the `crenel-*` router is
  written; unmanaged routers + their middleware chains are untouched.
- **nginx** — emit `auth_request <uri>;` inside the managed server's `location /`
  (default `/p`). Additive: only Crenel's own server blocks are regenerated.
- **NetBird (mesh)** — renders nothing; see §4.

Each driver's `normalize` detects an auth reference on read-back and sets
`Upstream.Auth`: Crenel's own marker round-trips the policy name; a generic
hand-built auth directive — a **forward-auth GATE** (`reverse_proxy`+`handle_response`,
the real Authelia shape), a stock `authentication` handler, a non-empty middleware
chain, an `auth_request` — is recognized as `"(detected)"` so *recognition* of
brownfield auth works even when the policy name can't be recovered (the design's
"surface detected auth in status if practical"). The Caddy read model additionally
**skips the gate's `reverse_proxy`** (it dials the AUTHORIZER, not the service) when
enumerating the leaf backend — without that skip a real Authelia route reads the
authorizer as its backend (a MISREAD the live trial also exposed).

### 2.1 The live-trial abort — root cause + fix

The first live cross-chain WRITE (`TRIAL-RESULT-chain-write-2026-06-28.md`) aborted
atomically with zero changes because Crenel's granular path emitted a synthetic
`{"handler":"forward_auth", …}` handler. **`forward_auth` is a Caddyfile DIRECTIVE, not
a JSON handler module** — the admin API has no `http.handlers.forward_auth`, so the home
Caddy rejected the load at provision (`unknown module: http.handlers.forward_auth`) and
Crenel's all-or-nothing transaction backed out. The fakes round-tripped the bogus
handler, so the suite never caught it.

The fix (above): render the **canonical** `reverse_proxy`+`handle_response` gate (or an
operator **verbatim** blob) — the shape real Caddy compiles `forward_auth` to and the
home edge accepts byte-for-byte — fronted by a `vars` policy marker; refuse a
snippet-only granular policy rather than emit invalid JSON; and make **caddyfake
provision inserted handlers** (rejecting an unknown module exactly as Caddy does) so a
wrong auth render now fails the suite. Reproduced-then-fixed in `caddyfake/fake_test.go`
and `caddy/auth_test.go`.

**Follow-on (TRIAL-FIX-4) — the front leg, not the auth gate.** With the valid gate in
place, RUN 2 of the trial applied the WRITE on both real edges but the through-the-chain
request still failed — `400 "Client sent an HTTP request to an HTTPS server"`. That is NOT
an auth fault: the home Authelia gate rendered correctly and the control host (`home.
homelab.example`) returned a real `302`. The fault was the **front-leg transport** — the
front forwarded plain HTTP to the home edge's HTTPS `:443` listener, so the request never
reached the gate. The auth attaches at the terminal edge (this doc); the front forward
carries no auth but MUST re-originate TLS to an HTTPS downstream. See DESIGN.md
"Cross-chain coordinated WRITE → Front-leg upstream TLS (TRIAL-FIX-4)".

## 3. Layering — auth is ORTHOGONAL to default-deny

Two independent questions:

- **Default-deny**: *is this host routed to the world at all?* — Crenel owns this,
  structurally (a host is reachable iff an explicit route + the catch-all deny).
- **Auth**: *who is allowed once it is routed?* — Crenel owns the *attachment* of a
  policy to the route; the auth *system* stays the operator's.

Auth never weakens default-deny and default-deny never implies auth. A host can be
routed with no auth (public, dangerous) or denied with an auth policy attached
(unreachable regardless). They compose; neither subsumes the other.

## 4. Mode interaction

| Mode | Auth |
|---|---|
| `http_proxy` | **supported** — there is an HTTP layer to forward-auth at. |
| `tcp_passthrough` | **error loudly** — SNI/L4 passthrough has no HTTP layer; Crenel cannot inject forward-auth, so a real policy on a passthrough exposure is refused (`ErrAuthUnsupportedForMode`), not silently dropped. |
| `mesh_grant` | **N/A** — an identity mesh enforces identity itself (the grant *is* the authn/authz). A forward-auth policy on a mesh grant is refused loudly with that explanation. |

`"none"` (and `""`) are fine on any mode — they attach no policy. Only a *real*
policy on a non-HTTP mode errors. The check is centralized in
`model.ValidateAuth(mode, auth)` and enforced in `core.Plan` / declarative plan so
every path (preview/expose/apply/reconcile) refuses identically.

## 5. Adoption — keep preserving existing auth verbatim

Unchanged from STEP-0: `import` adoption stamps only the ownership marker and never
rewrites a route's body, so a hand-built Authelia rule (Caddy handler, Traefik
middleware, nginx `auth_request`) survives byte-for-byte. On read-back, `normalize`
now additionally *recognizes* that auth (`Upstream.Auth = "(detected)"` or the
policy if it's Crenel's marker) so `status`/`audit` reflect it — read-only
recognition, never a rewrite. The first deliberate Crenel re-render of a host
canonicalizes (renders the *referenced* policy), exactly as mode/backend already
canonicalize on re-exposure (documented in USABILITY-DESIGN §A's adoption caveat).

## 6. Safety guardrail — never silently publish an unprotected service

Two coordinated mechanisms, wired to the existing amber "about to go public" path:

1. **`public_without_auth` audit check (new).** `audit` flags, as a **warning**,
   any host that is **public-scope** (a public DNS record exists for it, or — when
   no public DNS is managed — it has a non-mesh edge route) **and** carries no auth
   policy (`Auth == ""`). An explicit `Auth == "none"` is *acknowledged* (an `ok`
   informational finding noting it is intentionally unauthenticated), not warned.
   Severity is warning, never critical, so it never fails CI on its own — it raises
   the posture signal next to the existing default-deny / dangling-DNS checks.

   **Chain resolution (`downstream_edge`, P4) + the `auth_downstream` fallback.**
   When the edge is the **front of a chain**, a public host with no auth HERE may be
   authenticated one hop DOWNSTREAM. Crenel resolves this by OBSERVATION where it can:
   with a `downstream_edge` configured, `audit` FOLLOWS THROUGH to the downstream edge
   and reads the host's actual auth — a downstream-Authelia host is PROTECTED (not
   flagged), a downstream-**no-auth** host **IS** flagged `public_without_auth` (the
   correctness win — no longer blanket-suppressed). When the downstream edge cannot be
   read (or only the blunt `auth_downstream` flag is set with no `downstream_edge`),
   Crenel falls back to the ASSERTION: it suppresses `public_without_auth`, labels the
   host `auth: downstream`, and emits an informational `auth_downstream` / a
   `chain_unresolved` finding ("downstream, not observed" — suppression with a reason,
   never a silent drop). A real auth reference read from the front edge always wins.
   The resolution order (front auth > observed downstream > assertion) is centralized
   in `core` chain resolution (`effectiveAuth`), shared by `status` and `audit`. See
   DESIGN.md "Chain-aware model (P4)".

   **Coordinated WRITE (P4-write).** The chain read model has a write dual: `expose
   <host> --auth <policy>` on a chain attaches the policy at the edge that SERVES the
   host — the DOWNSTREAM (terminal) edge — while the front gets a plain FORWARD route
   with NO auth handler (it is a relay). So the auth lands exactly where the read model
   then OBSERVES it. The downstream auth is **read-back-verified** at the edge it
   attached to (the apply path now asserts every added route carries its planned auth —
   closing the consolidation-pass auth-verify gap), and the public-without-auth guardrail
   evaluates the WHOLE chain: a public chain expose with no policy anywhere is refused
   unless `--auth <policy>` or `--auth none`. See DESIGN.md "Cross-chain coordinated
   WRITE (P4-write)".

2. **expose / apply guardrail (CLI).** Making a host **public** with auth
   **unspecified** (`""`) is refused with a loud error that requires an *explicit*
   choice: pass `--auth <policy>` to protect it, or `--auth none` to publish it
   unprotected on purpose (for `apply`, set `auth:` on the exposure). `--yes` does
   **not** bypass this — that is the point: `--yes` skips the *are-you-sure*, not
   the *did-you-mean-to-leave-this-open*. The guardrail lives at the CLI boundary
   (the safety UX layer); `core.Apply` stays a pure library call so programmatic
   callers and the existing transactional tests are unaffected, while no human can
   publish an unprotected service without typing the explicit opt-out.

"Public" here uses the same definition as `computeNewPublic`, so the guardrail and
the amber highlight always agree on what "going public" means.

**Bounded-honesty caveat (P0).** This guardrail reasons over the auth state Crenel
can *read*. On a partially-parsed edge that reasoning is over the *understood subset
only* — `audit` says so via `coverage_incomplete`, and the default-deny verdict
downgrades to UNKNOWN, so `public_without_auth` is never presented as a complete
auth audit when it isn't. The `--yes`-doesn't-bypass posture here is the same one
the refuse-to-manage gate uses for foreign/unknown ownership: `--yes` skips
*are-you-sure*, not *this-will-silently-break*. See TOPOLOGY-RISK-REGISTER.md §4 and
DESIGN.md "Detect-and-declare-unknown".

## 7. New types & seams (all additive, dependency rule preserved)

- `model.Op.Auth` / `model.Upstream.Auth` (`string`), `model.AuthNone` constant,
  `model.Op.HasAuthPolicy()`, `model.ValidateAuth(mode, auth) error`,
  `model.ErrAuthUnsupportedForMode`.
- `config.AuthPolicy` (+ `caddy_handler_json`, `caddy_forward_auth_verify_uri`,
  `caddy_forward_auth_copy_headers`) + `config.Settings.AuthPolicies map[string]AuthPolicy`.
- `core.Exposure.Auth` (the apply-file field), threaded into the per-edge plan op.
- Driver options: `caddy.WithAuthPolicies` (over `caddy.AuthRef{Import, ForwardAuth,
  VerifyURI, CopyHeaders, Handler}`), `traefik.WithAuthMiddlewares`,
  `nginx.WithAuthRequests`; each driver's `normalize` sets `Upstream.Auth`. The Caddy
  driver renders the marker (`vars`+`crenel_policy`) + canonical/verbatim gate, and
  `detectAuth`/`isAuthGate`/`firstReverseProxyDial` read it back.
- `audit` finding `public_without_auth`; CLI `--auth` flag + `authTag` display.

core/model still import **no** driver. The driver-facing references are injected at
`cmd`, exactly like origins, granular, layer4, and persistence already are.
