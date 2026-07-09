# Crenel — Topology Risk Register

> A forward-looking enumeration of the real-world reverse-proxy / edge / auth
> topologies Crenel will meet **in the wild** — the long tail of configs people
> *don't* post publicly — and an honest classification of how Crenel behaves on
> each today. The point is not to support everything now; it is to know **exactly
> where Crenel would lie**, and to make it physically incapable of lying silently.
>
> Companion to DESIGN.md (what Crenel models), STRAIN.md (where the port strains),
> AUTH-DESIGN.md / USABILITY-DESIGN.md (auth + brownfield), and
> TRIAL-2026-06-27-real-vps-readonly.md (the cautionary real-edge run). Read those
> first. **No live infra was touched producing this doc.** Prevalence claims are
> grounded in homelab/self-hosting sources (see Appendix B).
>
> **Axis note:** this register is about *correctness* — where Crenel would MISREAD,
> MISMANAGE, or LIE about exposure. **Secrecy is a separate axis** (where Crenel could
> LEAK a secret it legitimately read): the edge config carries Cloudflare/ACME/
> basic-auth/forward-auth secrets, and they must not reach printed/exported/error
> output. That axis is owned by **SECURITY.md** (threat model + the field-level
> secret-redaction guarantee — redaction is output-only, the apply path keeps real
> values). The two compose: the P0 detect-and-declare-unknown excerpts that close the
> correctness gaps here are exactly the bytes SECURITY.md redacts before display.

---

## 0. The classification framework

For every topology variation we ask three independent questions, then assign a
**danger class** and a **prevalence × danger rank**.

### The three verdicts

| Verdict | Question | Failure = |
|---|---|---|
| **READ-SAFE** | Will a *read* (`status`/`audit`/`drift`/`import --dry-run`) avoid mutating anything wrongly? | A read path that mutates, reload-storms, or wedges the edge. |
| **READ-CORRECT** | Does Crenel report the **true** exposure + auth state? | Reports private/protected when actually public/unprotected (or vice-versa); under- or over-counts exposed services. |
| **MANAGEABLE** | Can Crenel `expose`/`unexpose`/`import`/`apply`/`reconcile` and have the change **stick**? | A change that read-back-verifies green, then **silently reverts**; or a verb that no-ops on a shape it can't address. |

READ-SAFE is the floor (Crenel is a *read-mostly* tool and the trial proved the
read discipline holds byte-for-byte). The dangerous failures live in the other
two columns.

### The two danger classes (the things that must be flagged)

- **MISREAD** — Crenel reports a **security-relevant falsehood**. Two directions,
  asymmetric in severity:
  - **MISREAD-↓ (under-report exposure / over-report protection)** — reports
    *private* when actually *public*, or *authenticated* when actually *open*.
    **This is the worst class.** It tells the operator a service is safe when it
    is on the internet. Always ranked CRITICAL.
  - **MISREAD-↑ (over-report exposure / under-report protection)** — "cries wolf":
    flags a host `public_without_auth` that is actually protected one hop away, or
    counts an internal-only route as public. Less dangerous (errs toward caution)
    but erodes trust and trains operators to ignore warnings — a real second-order
    risk.
- **MISMANAGE** — Crenel applies a change, **read-back-verifies it green**, and
  the change is then **silently reverted** by a force Crenel doesn't model
  (a config generator regenerating the file, a container restart, a tunnel
  re-sync). The operator believes a service is unexposed; minutes-to-hours later
  it is reachable again. This is uniquely dangerous because the read-back-verify —
  Crenel's core safety mechanism — gives **false confidence**: it confirms the
  in-the-moment state, not the durable one.

A clean read-only run on a topology Crenel doesn't fully model is **not** safe if
Crenel reports a confident-but-wrong answer. The trial (TRIAL-2026-06-27) is the
worked example: every read was byte-for-byte safe, yet `status` answered "2 hosts
exposed" for a ~25-service edge — a textbook **MISREAD-↓ by omission**.

---

## 1. The variation axes

Crenel's domain model (today) is essentially:

```
edge ∈ {caddy, traefik, nginx, netbird}
  route = (host, backend-address, mode ∈ {http_proxy, tcp_passthrough, mesh_grant}, auth-name, managed-bool)
  + DenyCatchAllPresent bool
zone = one DNS zone, scopes ∈ {internal, public}
"public" = (has public-scope DNS record) OR (no public DNS managed AND has a non-mesh edge route)
"managed domain" = host whose service ∈ some edge's origins
"owned" = route carries crenel's marker (@id / crenel-* key / # comment)
```

Every real-world variation is a place where reality has a **degree of freedom the
model collapses**. The seven axes below enumerate those degrees of freedom.

| # | Axis | The degree of freedom the model collapses |
|---|---|---|
| 1 | **Caddy/config STRUCTURE** | A route is assumed to be a top-level host→backend object. Reality nests: subroutes, `handle_path`, named matchers, snippets/`import`, path/header/method routing, rewrites that change the effective backend. |
| 2 | **AUTH PLACEMENT** | Auth is assumed to be *at this edge or nowhere*. Reality: auth at a downstream edge, inside the app, at the tunnel/overlay, per-path, mTLS, basic. |
| 3 | **PROXY MECHANISM / OWNERSHIP** | The config is assumed to be a static file/admin-API state Crenel can additively edit and own. Reality: the config is **generated** from Docker labels / a DB / a tunnel orchestrator, and Crenel's edits are transient. |
| 4 | **INGRESS TYPE** | "Exposed" is assumed to mean "a route on a public listener port." Reality: tunnels (cloudflared), overlays (Tailscale funnel/serve), CDN-fronting, external LB. |
| 5 | **EDGE TOPOLOGY** | Edges are assumed parallel-and-independent (multi-edge, built). Reality: front→downstream **chains**, CDN→edge, HA pairs. |
| 6 | **TLS** | TLS is assumed terminated here per-host. Reality: wildcard, DNS-01 vs HTTP-01, passthrough/SNI, termination downstream, custom CA. |
| 7 | **DNS** | One zone, split internal/public. Reality: split-horizon, no internal DNS, apex vs sub, multiple resolvers, multi-zone edge. |

---

## 2. The risk register

Each row: the variation, the three verdicts (✅ holds / ⚠️ partial / ❌ fails),
the danger class, prevalence, and the **model/driver change** it would need.
Sorted within each axis; the global ranking is in §3.

Legend — Prevalence: **H** (most real edges), **M** (common), **L** (niche).
Danger: **CRIT / HIGH / MED / LOW**. Verdicts apply to *current* `develop` (~ea0fe7e).

### Axis 1 — Caddy / config structure

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 1.1 | **Nested subroutes** (`wildcard → subroute → per-host → subroute`) — the trial case | ✅ | ✅ **(TRIAL-FIX)** | ✅ **(TRIAL-FIX-2)** | ~~HIGH~~ | **H** | **READ done** (TRIAL-FIX): `normalize`/`collectLeaves` **recurse** into `subroute` handlers to enumerate per-host leaf routes (host + leaf `reverse_proxy` dial + nested auth); an undescended subroute is an **unparsed** entry (§4), never a silent "(subroute)" route. **WRITE done** (TRIAL-FIX-2, 2026-06-28): the granular insert MIRRORS the read side — `httpRouteInsertPath` nests a new per-host route INSIDE the wildcard `*.zone` subroute that covers the host (per-zone; flat zones still flat-insert; ambiguous/absent-zone refuse), and `unexpose`/`Adopt` act on it at that depth by global `@id`. Flat top-level insert was the misplacement the live cross-chain trial caught. |
| 1.2 | **`handle_path` / path-stripped routes** | ✅ | ⚠️ | ⚠️ | MED | M | Treat `handle_path` like `handle` for host detection; record the path prefix on the route (needs `Route.PathPrefix`). |
| 1.3 | **Path-based routing** (N services on one host, split by path) | ✅ | ❌ **MISREAD** | ❌ | **HIGH** | M | The model is host-granular; a host with `/grafana`→A, `/`→B collapses to one opaque host. Needs **(host, path) route granularity** — `Route.PathPrefix` + per-path backend/auth. Some paths public, some authed is *invisible* today. |
| 1.4 | **Named matchers** (`@admin`, `@internal`) gating a route | ✅ | ⚠️ | ⚠️ | MED | M | A route reachable only under a matcher (CIDR, header) is reported as plainly exposed. Parser must surface match conditions; an un-modeled matcher → unparsed/`(conditional)`. |
| 1.5 | **`rewrite` / `header_up` changing the effective backend or Host** | ✅ | ⚠️ **MISREAD** | ⚠️ | MED | M | `firstReverseProxyDial` reads the dial, not the post-rewrite target. A `header_up Host` or upstream rewrite means the *reported* backend ≠ the *effective* one. Record rewrites; flag when the effective route is non-obvious. |
| 1.6 | **`snippets` / `import` of route blocks** | ✅ | ⚠️ | ⚠️ | MED | M | Caddyfile `import` expands before the admin API, so the JSON read-back is already flattened (OK for granular). But on-disk persistence (§B) editing a Caddyfile with imports must not duplicate. Low risk for admin-API reads. |
| 1.7 | **Header/method-based routing** (same host, different backend by method/header) | ✅ | ❌ **MISREAD** | ❌ | MED | L | Same shape as 1.3 but keyed on header/method. Needs route-condition modeling; today collapses to one host. |
| 1.8 | **`map` / `vars` indirection** | ✅ | ⚠️ | ⚠️ | LOW | L | A backend computed from a `map` is opaque to a static dial read → unparsed backend. |
| 1.9 | **Multiple server blocks** (`srv0`, `srv1`, ports 80/443/8443) | ✅ **FIXED (P1.5)** | ⚠️ | ⚠️ | MED | M | ~~Crenel reads one configured `serverKey`; routes on other servers are invisible.~~ `normalize` now enumerates **all** `http.servers`: a fully-modeled forwarding sibling is folded in (hosts visible); a forwarding sibling it can't fully model → `UnknownServerBlock` (deny → UNKNOWN); a benign non-forwarding sibling (`:80` redirect / static `file_server`) is **not** flagged (no cry-wolf). Full-load refuses a multi-forwarding-server edge → `--granular`. |

### Axis 2 — Auth placement

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 2.1 | **forward_auth at THIS edge** (Authelia/Authentik) | ✅ | ✅ | ✅ **(TRIAL-FIX-3)** | LOW | H | Recognized read-only (`(detected)`, or the policy name off Crenel's `vars` marker). **WRITE was BROKEN until TRIAL-FIX-3 (2026-06-28):** the granular path emitted a synthetic `{"handler":"forward_auth"}` — a Caddyfile DIRECTIVE, NOT a JSON module — which real Caddy rejects (`unknown module: http.handlers.forward_auth`); this ATOMICALLY ABORTED the first live cross-chain WRITE. **Fixed:** render the canonical `reverse_proxy`+`handle_response` gate (from the operator-declared endpoint/verify-URI/copy-headers) or an operator verbatim `caddy_handler_json` blob, fronted by a `vars` policy marker; refuse a snippet-only granular policy (no admin-API `import`); the read model SKIPS the gate's authorizer `reverse_proxy` for leaf enumeration. caddyfake now provisions handlers (rejects unknown modules) so a wrong render fails the suite. See AUTH-DESIGN §2.1. |
| 2.2 | **Auth at a DOWNSTREAM edge** (the chain — the maintainer's case) | ✅ | ✅ **OBSERVED (P4)** | ⚠️ | **HIGH** | M | ~~This edge has *no* `forward_auth`; auth is one hop down; `audit` cries wolf.~~ **P4:** with a `downstream_edge` configured, core FOLLOWS THROUGH to the downstream edge and resolves auth by **observation** — a downstream-Authelia host reads PROTECTED (not flagged); a downstream-**no-auth** host IS flagged (no longer blanket-suppressed); a downstream Crenel can't read is declared "downstream, not observed" (falls back to the `auth_downstream` assertion). MANAGEABLE ✅ **(P4-write):** a single `expose --auth` lands the downstream auth + the front forward + DNS in ONE read-back-verified, all-or-nothing transaction (auth attaches where the host is SERVED) — now rendering VALID Caddy JSON the downstream edge accepts (TRIAL-FIX-3; the earlier synthetic-handler render aborted the first live attempt). **Front-leg transport (TRIAL-FIX-4, 2026-06-28):** a real downstream is HTTPS (`:443`), so the front forward must RE-ORIGINATE TLS to it (+ preserve Host), not relay plain HTTP — the gap RUN 2 caught (`400 "Client sent an HTTP request to an HTTPS server"` even with the auth gate correct). `forwardRoute` sets `Upstream.UpstreamTLS` (explicit `downstream_scheme` wins, else inferred from `:443`); `insertRoute` renders `transport.tls` + `server_name`/`Host` `{http.request.host}` byte-faithful to the edge's own forward routes; read-back + `verify` confirm the TLS hop round-trips. See DESIGN.md "Cross-chain coordinated WRITE → Front-leg upstream TLS". |
| 2.3 | **Auth INSIDE the app** (Nextcloud, Grafana, etc. self-auth) | ✅ | ❌ **MISREAD-↑** | n/a | MED | H | Invisible to any proxy. `public_without_auth` fires on a self-protected app. Can't be *detected* from the edge; needs an operator annotation (`auth: app` opt-out, acknowledged like `auth: none` but semantically "app-enforced"). |
| 2.4 | **Auth at the TUNNEL/overlay** (Cloudflare Access, Tailscale ACL) | ✅ | ❌ **MISREAD-↓** | ❌ | **CRIT** | M | The dangerous direction: Access can be **mis**configured/absent and Crenel can't see the tunnel layer at all, so it can neither confirm nor deny protection. Pairs with 4.x. Must **declare the ingress external + protection UNKNOWN**, never assert either way. |
| 2.5 | **PER-PATH auth** (same host, `/api` open, `/admin` authed) | ✅ | ❌ **MISREAD** | ❌ | **HIGH** | M | Host-granular auth field can't express it. Needs (host, path)-granular auth (with 1.3). Today a half-protected host reads as fully one or the other. |
| 2.6 | **mTLS / client-cert auth** | ✅ | ⚠️ | ⚠️ | MED | L | A `tls client_auth` block is auth Crenel doesn't model. Recognize it as `auth: (detected mTLS)` read-only; refuse to claim `public_without_auth`. |
| 2.7 | **HTTP Basic auth** (`basic_auth`/`basicauth`) | ✅ | ⚠️ | ⚠️ | LOW | M | Recognize as `(detected)` so it satisfies the auth check; weak but present. |
| 2.8 | **oauth2-proxy / authproxy SIDECAR** in the route chain | ✅ | ⚠️ | ⚠️ | MED | M | A `reverse_proxy` to an oauth2-proxy sidecar that then proxies on — reads as a normal backend; the auth role is invisible. Heuristic recognition by known image/port, else unparsed-intent. |

### Axis 3 — Proxy mechanism / config ownership (**the biggest gap**)

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 3.1 | **caddy-docker-proxy** (Caddy config generated from Docker **labels**) | ✅ **DETECTED (P2)** | ⚠️ | ❌ **MISMANAGE** | **CRIT** | M | cdp regenerates the **in-memory Caddyfile** on *every Docker event* and reloads. ~~Crenel's granular `@id` route vanishes on the next container change.~~ **Detected**: the Caddy admin API has **no** CDP marker (verified vs CDP docs), so Crenel scans CDP's on-disk `Caddyfile.autosave` (`caddy_generator_config_path`, by filename/content) or honors an operator-declared `caddy_generator` hint → edge **FOREIGN-MANAGED → gate refuses to mutate**. *Boundary:* without the mounted autosave file or the declared hint, a CDP edge reads read-only-safe (P0) but its routes look `unmanaged` (mutable). |
| 3.2 | **Traefik via Docker LABELS** (not file provider) | ✅ | ⚠️ | ❌ **MISMANAGE** | **CRIT** | H | Same trap: the dynamic config is derived from container labels; Crenel's file/key edit is overwritten when the provider re-syncs from Docker. Detect `providers.docker`/`providers.swarm` → FOREIGN-MANAGED → refuse to mutate. (Trend is toward file provider, but labels remain dominant — see Appendix B.) |
| 3.3 | **Nginx Proxy Manager** (DB-driven, SQLite → regenerated `.conf`) | ✅ | ⚠️ | ❌ **MISMANAGE** | **CRIT** | **H** | NPM is the **most common homelab proxy**. Its nginx files under `/data/nginx/proxy_host/*.conf` are **regenerated from the DB** on any UI save. Crenel's `# crenel-managed:` comment edit is wiped on the next save. Detect NPM's signature header / file layout → FOREIGN-MANAGED → refuse, point at the NPM UI/API. |
| 3.4 | **Pangolin** (Traefik + newt WireGuard, config generated by Pangolin's API/DB) | ✅ | ⚠️ **DETECTED (P2)** | ❌ **MISMANAGE** | **HIGH** | M | Pangolin owns the Traefik dynamic config *and* fronts via a WireGuard tunnel (axis 4). Double trap: file edits regenerated **and** ingress is non-port. **Detected in the Traefik driver** via Pangolin's `badger` access middleware (github.com/fosrl/badger, attached to every generated router) → edge + routes **FOREIGN-MANAGED → gate refuses**. (Ingress UNKNOWN is the separate axis-4/P3 piece — see §4.3.) |
| 3.5 | **Komodo / Dockge / other compose-orchestrators owning the config** | ✅ | ⚠️ | ❌ **MISMANAGE** | MED | M | Any tool that templates the proxy config from its own source of truth. Generic generator-detection net (3.x) + the §4 "ownership UNKNOWN → refuse" rule cover the unknown ones. |
| 3.6 | **Traefik KV provider** (Consul / etcd / Redis) | ✅ | ❌ | ❌ **MISMANAGE** | MED | L | The dynamic config lives in a KV store, not a file. Crenel's file driver reads/writes the wrong substrate entirely → reads nothing, writes nothing durable. Needs a KV-backed Traefik driver, or detect+refuse. |
| 3.7 | **Kubernetes Ingress / Gateway API / IngressRoute CRD** | ✅ | ❌ | ❌ | MED | M | A different control plane (the API server). Out of scope for the file/admin-API drivers; detect the cluster context and decline rather than misread a rendered nginx-ingress conf as ownable. |
| 3.8 | **Static hand-written file** (the assumed happy path) | ✅ | ✅ | ✅ | LOW | M | What Crenel is built for. Granular/additive edits stick. |

### Axis 4 — Ingress type

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 4.1 | **Public listener port** (`:443` open, port-forwarded) | ✅ | ✅ | ✅ | LOW | H | The assumed model. "Exposed" = "route on this port." |
| 4.2 | **cloudflared / Cloudflare Tunnel** (no open port) | ✅ **SURFACED (P3)** | ❌ **MISREAD-↓** | ❌ | **CRIT** | **H** | The service is **public via the tunnel** while bound to `localhost`. ~~Crenel would conclude "internal/not public".~~ **Surfaced**: core scans a cloudflared `config.yml` (`ingress_config_path`) — `tunnel:`/`credentials-file:` + `ingress:` → `IngressKind=tunnel`, edge flagged `ingress_external` ("a host may be PUBLIC even if the proxy binds localhost"). Also declarable via `ingress_kind: tunnel`. *Remaining (CORRECT):* map the tunnel's `ingress:` rules to per-host public/private. |
| 4.3 | **Tailscale `funnel`** (public) vs **`serve`** (tailnet-only) | ✅ **SURFACED (P3)** | ❌ **MISREAD** | ❌ | **HIGH** | M | `funnel` = public to the internet; `serve` = private mesh. **Surfaced**: core scans a Tailscale `serve.json` (`AllowFunnel`/`Web`/`Handlers`) → `IngressKind=overlay`, edge flagged `ingress_external`. An externally-fronted edge Crenel can't classify → `IngressUnknown` (declared, never assumed internal). *Remaining (CORRECT):* split funnel (public) vs serve (tailnet) per host. |
| 4.4 | **CDN-fronted** (Cloudflare proxied DNS, "orange cloud") | ✅ | ⚠️ **MISREAD** | ⚠️ | MED | H | Public DNS resolves to the CDN, not the edge; the origin may be IP-allowlisted to CDN ranges. Crenel's public-DNS-based "public" test sees the CDN record and is *roughly* right, but origin-lockdown nuance (authenticated origin pulls, WAF) is invisible. |
| 4.5 | **External LB / HA edge pair** (keepalived/VRRP, cloud LB) | ✅ | ⚠️ | ⚠️ | MED | M | A VIP fronts two edges; "exposed" is a property of the pair. Multi-edge models parallel edges but not a shared VIP / active-passive failover. Needs an HA-group concept (axis 5). |
| 4.6 | **NetBird / WireGuard mesh ingress** | ✅ | ✅ | ✅ | LOW | M | Already modeled as `mesh_grant`; correctly *not* counted as public. The one overlay Crenel handles today. |

### Axis 5 — Edge topology

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 5.1 | **Single edge** | ✅ | ✅ | ✅ | LOW | H | Degenerate N=1. |
| 5.2 | **Parallel multi-edge** (home + VPS double-write) | ✅ | ✅ | ✅ | LOW | M | Built (M4). |
| 5.3 | **Front→downstream CHAIN** (VPS edge → home edge → app) | ✅ | ✅ **FOLLOWED (P4)** | ⚠️ | **HIGH** | M | the maintainer's real shape. ~~Crenel models edges as independent; can't see the VPS "backend" is itself an edge.~~ **P4:** a front edge names its `downstream_edge`; core attaches `model.ChainLink` to a forwarded route and FOLLOWS THROUGH — `status` shows the host's real downstream backend + observed auth (or an honest "downstream, not observed" when unreadable). READ-correct. MANAGEABLE ✅ **(P4-write):** one `expose`/`unexpose`/`reconcile` lands/tears the front forward + downstream route + DNS as ONE ordered, read-back-verified, all-or-nothing transaction across both edges. |
| 5.4 | **CDN → edge** | ✅ | ⚠️ | ⚠️ | MED | H | Chain where the front is a CDN (axis 4.4). |
| 5.5 | **HA active-passive pair** | ✅ | ⚠️ | ⚠️ | MED | M | See 4.5. A half-applied change to only the active node looks consistent until failover. |

### Axis 6 — TLS

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 6.1 | **Wildcard cert** (`*.domain`, DNS-01) | ✅ | ✅ | ✅ | LOW | H | Fine; the trial edge used exactly this. |
| 6.2 | **Per-host cert** (HTTP-01) | ✅ | ✅ | ✅ | LOW | H | Fine. Audit's `sni_host_mismatch` already covers cert/route name drift. |
| 6.3 | **TLS passthrough / SNI** | ✅ | ✅ | ✅ | LOW | L | Modeled (`tcp_passthrough`, layer4 / Traefik tcp routers). |
| 6.4 | **Termination at a DOWNSTREAM layer** (edge passes through, app terminates) | ✅ | ⚠️ **MISREAD** | ⚠️ | MED | M | Crenel may report HTTP-proxy where the real TLS terminates two hops down; auth attach assumptions break. Couple with the chain model (5.3). |
| 6.5 | **Custom CA / private PKI** | ✅ | ✅ | ⚠️ | LOW | L | Routing-orthogonal; mostly fine. |

### Axis 7 — DNS

| # | Variation | READ-SAFE | READ-CORRECT | MANAGEABLE | Danger | Prev | Model/driver change needed |
|---|---|:--:|:--:|:--:|---|:--:|---|
| 7.1 | **Split-horizon DNS** (internal resolver ≠ public) | ✅ | ✅ | ✅ | LOW | H | Modeled (internal/public scopes). |
| 7.2 | **No internal DNS** (hosts file / IP-only LAN) | ✅ | ⚠️ | ⚠️ | LOW | M | "internal scope" has nothing to read; the public-only path still works. |
| 7.3 | **Multi-zone edge** (`*.homelab.example` **and** `*.smallbiz.example`) | ✅ | ⚠️ **MISREAD** | ⚠️ | MED | M | Trial finding #4: one `zone` config; the edge fronts two. It coped (listed both wildcards) but per-service derivation + DNS assume a single zone. Needs **multi-zone**: `zones []` and per-host zone attribution. |
| 7.4 | **Apex vs sub** / **multiple internal resolvers** | ✅ | ⚠️ | ⚠️ | LOW | L | Edge cases in record derivation; low danger. |

---

## 3. Prevalence × danger ranking — the top findings

Ranked by **(prevalence × danger)**, weighting MISREAD-↓ and MISMANAGE highest
because they make a *confident security claim that is wrong in the unsafe
direction*.

> **#1 — The regenerated-config trap (config-generator ownership).**
> *Axis 3.1–3.4 — caddy-docker-proxy, Traefik Docker labels, Nginx Proxy Manager,
> Pangolin. Prevalence **H**, Danger **CRIT** (MISMANAGE).*
> This is the single biggest coverage gap. On a generator-owned edge, Crenel's
> additive edit is real, read-back-verifies **green**, and is then **silently
> reverted** when the generator next regenerates the config from its own source of
> truth (a Docker event, a UI save, an API call). The read-back-verify — Crenel's
> flagship safety property — actively *manufactures false confidence* here. An
> `unexpose` that reverts is a service the operator believes is offline but is
> back on the internet. **NPM alone makes this the highest-prevalence danger**, and
> labels (cdp/Traefik) cover most of the Docker-native homelab. Crenel must detect
> generator ownership and **refuse to manage**, never edit-and-hope.

> **#2 — Nested / multi-level routing collapse (silent route omission).**
> *Axis 1.1, 1.3, 1.9 — the trial's 25→2. Prevalence **H**, Danger **HIGH**
> (MISREAD-↓ by omission).*
> The parser walks only top-level routes of one server and never descends into
> subroutes (or sibling servers, or path splits). ~25 reachable services answer as
> "2 opaque wildcards." `status` *under-reports exposure*, `audit` reasons over a
> phantom 2-host config, and — most dangerously — the **default-deny "PRESENT"
> claim is asserted over a config that was 92% unparsed.** The fix is two-fold:
> recurse the parser (§5 roadmap P1) *and*, universally, stop pretending an
> undescended subroute is a single understood route (§4).

> **#3 — Tunnel / overlay ingress (public decoupled from public port).**
> *Axis 4.2, 4.3, 2.4, 3.4 — cloudflared, Tailscale funnel, Pangolin/newt,
> Cloudflare Access. Prevalence **H**, Danger **CRIT** (MISREAD-↓).*
> "Exposed" stops meaning "a route on a public listener port." A service bound to
> `localhost` and published by a `cloudflared` sidecar is **on the internet**;
> Crenel, reading only the local proxy, would call it internal. This is the
> worst-direction misread (private-when-public) and cloudflared is extremely
> common. Crenel cannot see the tunnel layer, so it must **declare the ingress
> external and the public-reachability UNKNOWN** rather than infer "private."

> **#4 — Auth enforced somewhere Crenel can't see (chain / app / overlay / per-path).**
> *Axis 2.2, 2.3, 2.4, 2.5, 5.3. Prevalence **H**, Danger **HIGH** (MISREAD both
> directions).*
> The `public_without_auth` guardrail assumes auth is at this edge or absent. In
> the wild auth is routinely one hop downstream (the maintainer's chain), inside the app, at
> the tunnel, or per-path. The result is **cry-wolf** (flagging protected hosts —
> erodes trust in the warning) *and*, in the tunnel/per-path cases, **genuine
> misses** (a half-protected host read as fully protected). The auth axis needs a
> richer vocabulary than `{policy-name, none, (detected)}`: it needs
> "**asserted-elsewhere / unverifiable-here**" as a first-class, *non-green* state.

> **#5 — Sub-host routing granularity (path/header/method).**
> *Axis 1.3, 1.7, 2.5. Prevalence **M**, Danger **HIGH** (MISREAD).*
> The host-granular model can't represent "one host, several backends, mixed
> public/authed by path." A single `Route` for `app.example.com` hides that
> `/admin` is open while `/` is authed. Needs `(host, path/condition)` route
> granularity. Lower prevalence than #1–#4 but the *per-path auth* sub-case is a
> direct security misread.

**Honorable mentions** (real, lower rank): Caddy admin-API in-memory + `docker
restart` drops Crenel routes (axis 3.1-adjacent — *known/documented*, persistence
option mitigates when configured); multi-zone edge (7.3, trial #4); TLS terminated
downstream (6.4); HA pair half-apply (4.5/5.5).

---

## 4. THE KEY RECOMMENDATION — "Detect-and-Declare-Unknown"

> **Crenel must never silently misreport. When it meets a handler type, routing
> construct, ingress mechanism, or ownership situation it cannot fully parse or
> confirm, that uncertainty becomes first-class output — counted, surfaced, and
> mutation-blocking — not swallowed.**

This is the **universal safety net**. It does not require understanding any of the
topologies in §2; it requires Crenel to be *honest about what it does not
understand*. Critically, it converts almost every MISREAD-↓ and MISMANAGE above
from a **silent confident falsehood** into a **loud declared unknown** — which is
the entire difference between dangerous and safe. The trial's silent 25→2 collapse
is the cautionary example: with this principle, that run would have said *"read
2/25 routes; 23 not understood — exposure status INCOMPLETE; default-deny UNKNOWN,"*
which is true and safe, instead of *"2 exposed, default-deny PRESENT,"* which is
false and dangerous.

### 4.1 The data the parser must carry

Today `normalize` returns `LiveEdgeState{Routes, DenyCatchAllPresent, Raw}`. Every
route is either understood-or-absent; there is no third state. Add the accounting:

```go
// model — additive; dependency rule unchanged.

type UnknownKind string
const (
    UnknownHandler       UnknownKind = "handler_unrecognized"     // a handler crenel doesn't model
    UnknownNestedRoute   UnknownKind = "subroute_not_descended"   // routing exists below where we stopped
    UnknownMatcher       UnknownKind = "matcher_conditional"      // route gated by a matcher we didn't evaluate
    UnknownBackend       UnknownKind = "backend_indirect"         // dial via map/vars/rewrite — effective target unknown
    UnknownServerBlock   UnknownKind = "server_not_read"          // an http.server we didn't enumerate
    UnknownGenerator     UnknownKind = "foreign_managed"          // config owned by a generator (cdp/NPM/labels/Pangolin)
    UnknownIngress       UnknownKind = "ingress_external"         // reachability determined off-edge (tunnel/overlay/CDN)
)

type Unparsed struct {
    Locator    string      // where: "apps.http.servers.srv0.routes[1]" / "cloudflared:ingress" / "edge"
    Kind       UnknownKind
    Reason     string      // human: "subroute with 23 nested routes not descended"
    RawExcerpt string      // bounded snippet for the operator to inspect
}

type LiveEdgeState struct {
    Routes              []Route
    DenyCatchAllPresent bool
    Unparsed            []Unparsed   // NEW — everything we saw but did not fully understand
    Generator           string       // NEW — "" | "caddy-docker-proxy" | "nginx-proxy-manager" | "traefik-docker-labels" | "pangolin" | ...
    IngressKind         IngressKind  // NEW — "" (port) | public-listener | tunnel | overlay | unknown  (typed; .External() ⇒ off-edge)
    Raw                 string
}

func (s LiveEdgeState) Coverage() (understood, total int) // total = len(Routes)+len(Unparsed)
func (s LiveEdgeState) FullyParsed() bool { return len(s.Unparsed) == 0 }
```

And ownership becomes **ternary**, not binary. `Route.Managed bool` →

```go
type Ownership string
const (
    OwnCrenel  Ownership = "crenel"   // carries our marker — safe to mutate
    OwnUnmanaged Ownership = "unmanaged" // hand-written, no generator — adoptable
    OwnForeign Ownership = "foreign"   // a generator owns it — DO NOT mutate (would revert)
    OwnUnknown Ownership = "unknown"   // cannot determine — DO NOT mutate
)
type Route struct {
    Host string; Upstream Upstream
    Ownership Ownership   // replaces/augments Managed (keep Managed==(Ownership==OwnCrenel) for compat)
}
```

### 4.2 How `status` surfaces it

`status` gains a **coverage line** and an explicit unknowns section. It never
again presents a partial parse as a complete one:

```
Edge [caddy·caddy]   ⚠ FOREIGN-MANAGED (caddy-docker-proxy)   INGRESS: cloudflare-tunnel
  Coverage: read 2/25 routes — 23 NOT UNDERSTOOD — exposure status INCOMPLETE
  Default-deny catch-all: UNKNOWN (config not fully parsed)        # was: PRESENT
  Exposed (understood, 2):
    *.homelab.example         -> (subroute: 23 nested routes not descended)
    *.smallbiz.example       -> (subroute: not descended)
  ⚠ Not understood (23):
    apps.http.servers.srv0.routes[0].handle[0]/subroute   subroute_not_descended
    ... (host/leaf enumeration unavailable until parser recursion; P1)
  ⚠ Not crenel-ownable: edge is generated by caddy-docker-proxy — manage at the label source.
```

The HUD `DEFAULT-DENY` field becomes **amber "UNKNOWN (23 unparsed)"** instead of
green "ENFORCED" (see §4.4). `--json` carries `coverage`, `unparsed[]`,
`generator`, `ingress_kind` so CI can gate on them.

### 4.3 How `audit` surfaces it

Two new findings + one **downgrade rule**:

- **`coverage_incomplete` (warning)** — emitted whenever `len(Unparsed) > 0`.
  Carries the count and the locators. "Exposure/auth findings below are computed
  over the *understood* subset only." This re-frames every other finding as
  conditional, which is the honest posture.
- **`ownership_unconfirmed` (warning, or critical if a mutation was attempted)** —
  any route whose `Ownership ∈ {OwnForeign, OwnUnknown}`. On a foreign-managed edge
  this is edge-wide.
- **`ingress_external` (warning)** — when `IngressKind.External()` (tunnel / overlay /
  unknown): "reachability for these hosts is determined by <tunnel/overlay>, not this
  edge's listener — a host may be PUBLIC even if the local proxy binds localhost;
  public/private status is UNKNOWN to Crenel." An externally-fronted edge Crenel can't
  classify surfaces as `unknown` ("an EXTERNAL ingress Crenel could not classify"). The
  posture is resolved by core from the edge's declared `ingress_kind` or a detected
  cloudflared/Tailscale config (`ingress_config_path`) — see §5 Built.

### 4.4 The default-deny downgrade (the load-bearing interaction)

This is the most important single rule in the whole register.

> **A structural default-deny "ENFORCED" claim is a statement about the *entire*
> config — "nothing not-listed is reachable." It is only sound if the entire
> config was parsed. Therefore `DenyCatchAllPresent == true` may be reported as
> ENFORCED *only* when `FullyParsed()`. With any unparsed routes, the claim is
> DOWNGRADED to UNKNOWN.**

The deny check becomes **ternary**:

```
denyState =
    !DenyCatchAllPresent        -> MISSING   (critical — fail-open, unchanged)
    DenyCatchAllPresent && unparsed==0 -> ENFORCED  (green, unchanged)
    DenyCatchAllPresent && unparsed>0  -> UNKNOWN   (amber — NEW)
```

Rationale: an unparsed route *could itself* be a permissive host-less
`reverse_proxy` (a fail-open catch-all) or a route that opens a host Crenel can't
see. The current code computes `DenyCatchAllPresent = !permissiveCatchAll` by
scanning only top-level routes — so a permissive catch-all *nested in a subroute*
would be missed and deny falsely reported PRESENT. The downgrade closes exactly
that hole: **Crenel cannot certify default-deny over config it didn't read.** This
directly fixes the trial, where "default-deny PRESENT" was asserted with 23 routes
unparsed. (The `audit` invariant test must be updated: the hard invariant becomes
"deny is never *falsely* ENFORCED," i.e. ENFORCED ⟹ FullyParsed.)

### 4.5 Refuse-to-manage on ambiguous ownership

Mutating verbs (`expose`/`unexpose`/`apply`/`reconcile`/`import`) gain a
**pre-mutation ownership gate**, enforced in `core` before any driver `Apply`:

- Target route/edge `Ownership == OwnForeign` → **refuse**, naming the generator
  and the source to manage at: *"`grafana.example.com` is owned by
  caddy-docker-proxy; a Crenel edit would be reverted on the next Docker event.
  Add the route at the label source instead."* No `--yes` override (same posture as
  the `public_without_auth` guardrail — `--yes` skips *are-you-sure*, not
  *this-will-silently-break*).
- Target `Ownership == OwnUnknown` → **refuse**, with a `--force` escape hatch only
  for the operator who has verified ownership out-of-band (documented as
  load-bearing-on-the-human).
- `import` adoption already refuses out-of-domain and origin-conflicts; it
  additionally must refuse to stamp a marker onto a **foreign-managed** block (the
  marker would be regenerated away — adopting it is itself a MISMANAGE).

### 4.6 How generators + ingress are *detected*

Detection is heuristic and best-effort — and that's fine, because the **default
when detection is uncertain is `OwnUnknown` → refuse**, which is safe. Signals:

- **caddy-docker-proxy**: `Caddyfile.autosave` in the config dir; admin config
  whose routes bear cdp's label-derived structure / no on-disk Caddyfile mounted.
- **Traefik Docker labels**: `providers.docker` / `providers.swarm` enabled (vs a
  pure `providers.file`); routers with auto-generated names.
- **Nginx Proxy Manager**: the NPM-generated header comment + the
  `/data/nginx/proxy_host/<id>.conf` file layout / `# managed by Nginx Proxy
  Manager` signature.
- **Pangolin**: Traefik dynamic config bearing Pangolin's resource markers + a
  `newt`/`gerbil` sidecar.
- **cloudflared**: a `cloudflared` process/sidecar + its `ingress:` config; or
  public DNS pointing to `*.cfargotunnel.com`.
- **Tailscale**: `tailscaled` serve/funnel config (`tailscale serve status`).

Each sets `Generator` / `IngressKind` at the edge level. Where Crenel can read the
generator's *own* source of truth (cloudflared `ingress:`, Tailscale serve config),
it should — to recover the real exposure — but still mark those routes
**foreign-managed (read-only)**: understanding ≠ ownership.

### 4.7 Why this is the right primitive

- **It is topology-agnostic.** It doesn't need to know what a cloudflared tunnel
  *is*; it needs to notice "this edge's reachability is decided somewhere I can't
  read" and say so.
- **It degrades safely.** Unknown → declared + mutation-refused. The failure mode
  is "Crenel won't touch this and tells you why," never "Crenel quietly did the
  wrong thing."
- **It makes every later feature additive.** Each parser improvement (subroute
  recursion, tunnel modeling, chain auth) *moves routes from `Unparsed` into
  `Routes`* and shrinks the unknown set — measurable as the coverage metric
  climbing. The roadmap below is literally "drive coverage toward 100%, danger-first."

---

## 5. Prioritized roadmap

Ordered by **(prevalence × danger) ÷ cost**, safety-net first.

### P0 — Detect-and-Declare-Unknown (the universal net). ✅ **BUILT.**
The §4 spec: `Unparsed[]` + `Coverage()` + ternary `Ownership` + the **default-deny
downgrade** + **refuse-to-manage on ambiguous ownership** + status/audit surfacing.
Touches `model` (additive types), `core` (audit downgrade + mutation gate), each
driver's `normalize` (emit `Unparsed` instead of silently dropping). **Cheap,
purely additive, dependency-rule-preserving, and it neutralizes the worst of #1–#4
immediately** by converting silent falsehoods into declared unknowns. Nothing else
should land before this.

> **Built (develop).** `LiveEdgeState.{Unparsed,Generator,IngressKind}` +
> `Coverage()`/`FullyParsed()`/`DenyState()`; `Route.Ownership` (ternary, augmenting
> `Managed`); each driver's `normalize` emits `Unparsed` (Caddy unmodeled
> terminals / undescended host-less subroutes; Traefik unresolvable backends; nginx
> non-proxy vhosts). Audit deny is ternary (`deny_catchall_unknown`; invariant
> *ENFORCED ⟹ FullyParsed*) with `coverage_incomplete` / `ownership_unconfirmed` /
> `ingress_external` findings; `status` prints the coverage line + "⚠ Not understood"
> section + FOREIGN/INGRESS annotations; the HUD's DEFAULT-DENY shows amber UNKNOWN.
> The `core` pre-mutation gate (`ErrRefuseToManage`) refuses foreign/unknown
> routes/edges before any driver `Apply` (`--yes` never bypasses; `--force` covers
> `unknown` only, never `foreign`); `import`/`apply --adopt` refuse to stamp
> foreign/unknown blocks. Generator/ingress *detection* that SETS `Generator` /
> `IngressKind` is P2/P3 — until then those fields stay empty and the net is driven
> by the `Unparsed`/`Ownership` parser signals (already safe-by-default).

### P1 — Caddy subroute recursion (+ enumerate all server blocks).
Directly fixes finding #2 / trial #1: descend `subroute` handlers to enumerate
per-host leaf routes (host + leaf dial + nested auth), and read every
`http.servers` block, not one. Each route recovered moves from `Unparsed` →
`Routes` (coverage climbs 2/25 → 25/25). Highest-value READ-CORRECT fix; the trial
already names it the "highest-leverage fix." Pure parser work in the Caddy driver.

### P2 — Generator / foreign-ownership detection (the regenerated-config net). 🟡 **STARTED.**
Finding #1. Implement the §4.6 detectors → set `Generator` → mark routes
`OwnForeign` → the P0 gate refuses mutation. **Read-only safe by construction**;
it doesn't need to *manage* generator-owned edges, only to *stop pretending it
can*. Start with NPM (highest prevalence) + Docker-labels (cdp/Traefik) + Pangolin.
Later, optional: manage *at the source* (write the label/DB/API) — a much bigger
lift, deferred.

> **Started (develop).** Two in-band detectors landed, read-only and best-effort:
> **Nginx Proxy Manager** (the nginx driver recognizes NPM's generated-file
> signature → `Generator="nginx-proxy-manager"`) and **Traefik label/orchestrator
> providers** (a router with a `@docker`/`@swarm`/`@kubernetes*`/… provider suffix →
> `Generator="traefik-docker-labels"` etc.). Both mark the edge + every route
> `OwnForeign` (Crenel still READS them — understanding ≠ ownership), so the P0 gate
> refuses any mutation edge-wide and `status`/`audit` show FOREIGN-MANAGED. Proven
> end-to-end (real nginx driver: NPM config → status foreign → audit
> `ownership_unconfirmed` → expose/unexpose refused, file untouched), with
> false-positive guards (a hand-written / file-provider config is NOT flagged).
>
> **Now also detected (P2 finish):** **Pangolin** — in the Traefik driver, via its
> `badger` access middleware (attached to every Pangolin-generated router) →
> `Generator="pangolin"`, edge foreign. **caddy-docker-proxy** — the Caddy admin API
> carries **no** CDP marker (verified vs CDP docs), so Crenel reads CDP's on-disk
> `Caddyfile.autosave` (`caddy_generator_config_path`) by filename/content, with an
> operator-declared `caddy_generator` hint as the robust fallback →
> `Generator="caddy-docker-proxy"`, edge foreign. Both proven end-to-end (CDP: fake
> admin + autosave → status foreign → audit `ownership_unconfirmed` → expose refused,
> live config untouched) with hand-written false-positive guards.
> **Now also surfaced (P3):** **tunnel/overlay ingress** — typed
> `IngressKind ∈ {public-listener, tunnel, overlay, unknown}` + `External()`; core
> overlays an edge's posture (declared `ingress_kind`, or a scanned cloudflared
> `config.yml` / Tailscale `serve.json` via `ingress_config_path`) onto status + audit
> (`ingress_external`). An externally-fronted edge Crenel can't classify → `unknown`
> (declared, never assumed internal). Proven (declared + cloudflared + tailscale +
> unknown + no-false-positive). Detection/surfacing only — recovering per-host
> public/private from the tunnel's rules is the remaining CORRECT-ness step.
> CDP's admin-API-only auto-detection is structurally impossible (no marker) so it
> needs the mounted autosave file or the declared hint. An undetected generator's
> unmodeled shapes still surface via the P0 `Unparsed` net.

### P3 — Tunnel / overlay ingress modeling. ✅ DETECTION + SURFACING DONE
Finding #3. `IngressKind` detection for cloudflared + Tailscale; read their own
ingress/serve config to recover real public/private status; mark hosts
"public-via-tunnel" / "tailnet-only." Until modeled, P0 already declares ingress
external + reachability UNKNOWN (safe). This phase upgrades UNKNOWN → CORRECT.

### P4 — Chain / downstream-auth model. ✅ **READ-CORRECTNESS + COORDINATED WRITE BUILT.**
Findings #4 + 5.3. Promotes the `auth_downstream` posture flag to a first-class,
**OBSERVED** chain relationship. A front edge names a `downstream_edge` (+ optional
`downstream_address`); core recognizes a front leaf that forwards to that edge as a
**chain forward**, attaches `model.ChainLink` to the route, and FOLLOWS THROUGH —
reading the downstream edge to recover the host's REAL backend + the auth actually
enforced there. Exposure/auth resolve by **observation**: a downstream-Authelia host
is PROTECTED (not flagged), a downstream-**no-auth** host **IS** flagged
`public_without_auth` (no longer blanket-suppressed), and a downstream Crenel can't
read is declared **"downstream, not observed"** (fall back to the `auth_downstream`
assertion, never a misread). A chain-target edge whose read fails is read tolerantly
(degrades to unresolved + UNKNOWN), not an abort.

> **Built (develop).** `model.ChainLink` (`Route.Chain`); `EdgeBinding.{Downstream
> Edge,DownstreamAddress}` ← `Settings`/`EdgeSettings`; `core/chain.go`
> (`buildChainContext`/`resolve`/chain-aware `effectiveAuth`/tolerant `readAll`);
> `status` follows through (real downstream destination + observed auth, or an honest
> "downstream, not observed"); `audit` resolves `public_without_auth` by observation
> + emits `chain_resolved`/`chain_unresolved`. Two-edge chain fixture
> (`internal/core/chain_p4_test.go`, `examples/seed-chain-{front,home}.json` +
> `settings-chain-p4.json`) mirrors the maintainer's shape: front wildcards forwarding to a
> downstream edge with a per-host Authelia host + a per-host no-auth host →
> protected-by-observation NOT flagged, no-auth-downstream IS flagged,
> downstream-unreadable → declared unresolved.
>
> **Coordinated WRITE (develop).** A single `expose`/`unexpose`/`reconcile` on a chain
> now lands the coordinated entries across the front edge + the downstream edge + DNS as
> ONE all-or-nothing, read-back-verified transaction (`core/chain_write.go`). Core
> projects the op into one changeset PER PARTICIPANT — the downstream (terminal) edge
> gets the real route + auth, the front gets a synthesized FORWARD route (no auth) —
> applied **downstream → front → public-DNS** on expose (reverse on unexpose) via the
> chain-DEPTH ordering, with auth read-back-verified where it lands. Any failure on
> either edge or DNS rolls back ALL applied participants (wedge-safe per edge); the gate
> spans BOTH edges (foreign/unknown on either refuses); the public-without-auth guardrail
> evaluates the whole chain. `reconcile`/`drift` converge a half-present chain.
> `internal/core/chain_write_test.go` + `examples/settings-chain-write.json` +
> `examples/DEMO-chain-write.md`.
>
> **Follow-on (NOT built):** a live cross-chain write trial (a separate, backed-up step
> — the build is against fakes/fixtures only); chain `Adopt` of a pre-existing forward
> reuses normal per-edge adoption; pairs with an `auth: app` operator annotation for
> in-app auth (2.3). A pure-front chain (no `downstream_address`) is READ-only until an
> address is configured. Two-zone front edges remain a related follow-on.

### P5 — Sub-host route granularity.
Finding #5. `Route.PathPrefix` / route-condition modeling → `(host, path)` routes
with per-path backend + auth. Unlocks path/header/method routing (1.3/1.7) and
per-path auth (2.5). Larger model change; lower prevalence than P0–P4.

### TRANSPORT — pluggable connection axis (HOW Crenel REACHES an admin API). ✅ **BUILT.**
Orthogonal to the modeling axes above (axes 1–7 are about *reading the config
correctly*; this is about *being able to reach the control plane at all*). Previously
Crenel had one hardcoded reach — HTTP to a configured `admin_url` — and any plumbing was
the operator's out-of-band problem. That was an implicit fourth deployment axis and a
hard wall for a **loopback-only, unpublished** admin (the maintainer's home Caddy admin binds
container-localhost and is not published, so nothing could open an HTTP client to it).
Now a first-class `ports.Transport` lets the Caddy driver make the same admin calls over
**`direct`** (default; zero behavior change), **`ssh-exec`** (run the call as a
nested-exec curl on the far end — `ssh → pct exec → docker exec → sh` → curl
`127.0.0.1:2019` — **no port published, no tunnel**), or **`ssh-tunnel`** (a
crenel-managed local forward). The never-hang/wedge guarantee sits above the transport
seam, so it holds for every channel. **This dissolves the chain-write trial's gating
access-model constraint** (no host could reach both admins): the home admin is reached
where it lives, locked-down, and the live cross-chain WRITE can run over ssh-exec
without publishing the home admin or hand-rolling a tunnel. READ-ONLY-verified live
against the home edge (51 services, deny ENFORCED, config byte-identical). See
DESIGN.md "Transport / Connection", STATE §5e.

### P6 — Long tail.
Multi-zone edge (`zones []`, trial #4); HA-group / VIP modeling (4.5/5.5); TLS
terminated-downstream coupling (6.4); Traefik KV provider (3.6); k8s ingress (3.7,
likely a separate driver / explicit decline). Each is a contained, lower-rank
follow-up — and each is *safe-by-default* the moment P0 lands, because anything
unmodeled reads as a declared unknown rather than a confident wrong answer.

---

## Appendix A — the principle restated

Crenel's existing safety rests on two invariants: **live-state is the only truth**
and **structural default-deny**. This register adds the third that the long tail
demands:

> **Bounded honesty: Crenel's confidence is bounded by what it actually parsed and
> owns. It reports unknowns as unknowns, refuses to manage what it can't own, and
> never certifies default-deny over config it didn't read.**

A tool that says "I read 2 of your 25 routes and won't touch this generator-owned
edge" is *useful and trustworthy*. A tool that says "2 services exposed,
default-deny enforced" about a 25-service tunnel-fronted generator-managed edge is
*dangerous* — precisely because it sounds authoritative. The whole register
reduces to: **make Crenel structurally incapable of the second sentence.**

## Appendix B — prevalence grounding (sources)

Real-world homelab/small-prod patterns, used to weight prevalence (not Crenel-specific):

- Reverse-proxy popularity (NPM most common entry point; Traefik label-driven;
  Caddy rising): [HomeLab Starter showdown](https://homelabstarter.com/homelab-reverse-proxy-comparison/),
  [HomelabAddiction 2026 comparison](https://homelabaddiction.com/nginx-proxy-manager-vs-caddy-vs-traefik/),
  [HN discussion](https://news.ycombinator.com/item?id=44540145).
- Traefik labels vs file provider (both prevalent; file trend rising, labels still
  dominant in Docker-native setups): [SimpleHomelab Traefik guide](https://www.simplehomelab.com/udms-18-traefik-docker-compose-guide/),
  [Traefik providers docs](https://doc.traefik.io/traefik/providers/overview/).
- caddy-docker-proxy regenerates an in-memory Caddyfile on every Docker event and
  saves `Caddyfile.autosave`: [lucaslorentz/caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy),
  [virtualizationhowto walkthrough](https://www.virtualizationhowto.com/2025/09/caddy-reverse-proxy-in-2025-the-simplest-docker-setup-for-your-home-lab/).
- Nginx Proxy Manager is DB-driven (SQLite) and regenerates nginx `.conf` from the
  DB: [NPM setup docs](https://nginxproxymanager.com/setup/),
  [NPM advanced config](https://nginxproxymanager.com/advanced-config/).
- Pangolin (Traefik + newt WireGuard tunnel, config from its own API/DB; "best
  self-hosted project of 2025"): [Pangolin HN Show](https://news.ycombinator.com/item?id=44526015),
  [leewc writeup](https://leewc.com/articles/self-hosted-cloudflared-tailscale-alternative-pangolin/).
- Cloudflare Tunnel ingress (public hostname, no open port, optional Cloudflare
  Access auth at the edge): [Cloudflare Tunnel config docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/),
  [zero-port-forward guide](https://sumguy.com/cloudflare-tunnel-advanced/).
</content>
</invoke>
