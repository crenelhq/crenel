# Crenel — Build Log

> **ARCHIVED / FROZEN (2026-07-02).** Per-increment development narrative through
> v0.3.1. Newer history lives in the root `CHANGELOG.md` and `STATE-OF-CRENEL.md`.
> Identifiers anonymized for publication.

<!-- Newest summary at TOP. Append per-increment entries below the summary. -->

## v0.3.0 cut — 2026-06-29

Consolidated the day's branches into `develop` (`7054157` → `e9eab5a`, five real `--no-ff`
merges, full suite green + race-clean after each) and tagged **`v0.3.0`**:

1. `feat/caddy-hostless-subroute-deny` — safety: descend the host-less subroute-wrapped deny
   so a permissive subroute is no longer misread as default-deny (`normalizeServer` /
   `classifyHostlessSubroute` + byte-faithful fixture).
2. `feat/mixed-vendor-trial` — doc: the cross-vendor atomic-coordination trial result.
3. `feat/bundle-design` — doc: BUNDLE-DESIGN.md.
4. `feat/bundle-v0` — the turnkey bundle (compose + Dockerfile + `crenel serve` read-only HUD
   + tests).
5. `feat/public-launch-prep` — rebased onto current develop: locked brand, README hero +
   merged-in bundle quickstart, legal/OSS scaffolding, docs/brand assets.

The release captures the v0.2.0→v0.3.0 arc (see CHANGELOG.md): file-driver RUNTIME verification
(`ports.RuntimeVerifier` — Traefik API / nginx -t+reload+probe; the hollow file re-read
replaced with a real daemon probe), valid Traefik/nginx output, the correct per-port nginx
default-deny, nginx reload, missing-file bootstrap, the zero-dependency Traefik YAML read, and
cross-vendor atomic coordination proven live — all surfaced and validated on the standing live
proving ground (`PROVING-GROUND.md`). 15 packages green, race-clean, zero external deps.

## Mixed-vendor atomic-coordination trial (PASSED on STOCK develop) — 2026-06-29

Branch `feat/mixed-vendor-trial` off `develop@7054157` (doc-only; pushed, NOT merged). The
live demo of the brand claim — "Every edge in atomic agreement. Verified." — across DIFFERENT
vendors, on the bench host (real caddy admin-API + real traefik file-driver, the merged runtime-verify
in play). Proven on the **unmodified develop binary** — no code change required.

- **PART A:** ONE `edges[]` config with a heterogeneous caddy+traefik pair; `expose mvdemo`
  landed on BOTH as one all-or-nothing op, each read-back-verified against its REAL runtime
  (Caddy admin API + Traefik `/api/http/routers` `enabled`), live 200 on both; coordinated
  `unexpose` left both clean (Caddy admin byte-identical to baseline, Traefik file emptied).
- **PART B (the proof that matters):** re-ran the expose with the Traefik edge pointed at an
  INVALID target (`bad host:80`, daemon-rejected). Caddy applied, Traefik's runtime-verify
  caught that the router never went `enabled`, and the transaction **ROLLED BACK BOTH edges** —
  Caddy admin config byte-identical to baseline (NOT half-applied), no residue, exit 1, honest
  `ROLLED BACK` (never a false green). Report: `TRIAL-RESULT-mixed-vendor-2026-06-29.md`.
- **Separate finding (decoupled, NOT fixed here):** with an honest `:80 { respond 403 }` deny,
  Caddy `status` *displays* `Default-deny UNKNOWN` because `normalizeServer` doesn't descend the
  Caddyfile-adapter's host-less SUBROUTE-wrapped deny. It did NOT block the trial: `verify()`
  gates on model-level `DenyCatchAllPresent` (true for that shape), not the display. The display
  fix (RED→GREEN + byte-faithful fixture) is parked on branch `feat/caddy-hostless-subroute-deny`
  (commit `0e628af`) for separate review. Bench left byte-for-byte as found.

## v0.2.0 cut — 2026-06-28

Tagged `v0.2.0` on `develop` (`1b50aa8`). The release captures the v0.1.1→v0.2.0 arc — see
CHANGELOG.md: durable home-edge persist (proven live, restart-survival + the one-command
rename), the persistence-model detection net, the cross-chain coordinated WRITE (the literal
302), the pluggable TRANSPORT axis, the security/redaction pass, detect-and-declare-unknown
maturity (multi-server/generator/ingress/chain), and the first-class atomic `rename` verb.
325 test functions, race-clean. VPS install refreshed to v0.2.0 **read-only** (no write/
persist path) — `version`/`status`/`audit`/`drift` confirmed reading the real edge.

## TRIAL-FIX-4 — front-leg upstream TLS on chain-forward routes (2026-06-28)

The third live-only gap, caught by RUN 2 of the cross-chain trial: with nesting (FIX-2)
and the valid auth gate (FIX-3) both in, the coordinated WRITE finally LANDED on both real
edges (read-back-verified, exit 0) — but the through-the-chain curl returned `400 "Client
sent an HTTP request to an HTTPS server"`. The FRONT forward was rendered as a **bare HTTP
`reverse_proxy` to the home edge's HTTPS `:443`** — no upstream TLS, no Host — so the front
terminated the client's TLS and then spoke plain HTTP to a TLS listener. The real working
VPS forward routes (`live-backup/trial-chain-write-20260628T140225Z/vps-front-config-*.json`,
e.g. `git.homelab.example → 10.0.0.13:443`) carry `transport {protocol:http,
tls:{insecure_skip_verify, server_name:{http.request.host}}}` + a request
`Host:{http.request.host}` (both the Caddy placeholder, not a literal FQDN). Root cause
spanned two layers: `chain_write.forwardRoute` set `Upstream.ServerName` but
`caddy.go insertRoute` DROPPED it, emitting only `{handler:reverse_proxy, upstreams:[{dial}]}`.
The fake never opens a real TLS socket, so the suite structurally couldn't catch it (third
live-only finding in a row). Three green increments, each `go build ./... && go vet ./... &&
go test -race -count=1 ./...` clean, pushed to Forgejo per increment.

**Increment 1 — core carries the upstream-TLS intent (`5667d06`).**
`model.Upstream.UpstreamTLS` (distinct from `TLSPassthrough`, which is about NOT terminating
client TLS, and from `ServerName`, the cert host the edge SERVES). `chain_write.forwardRoute`
sets it from the downstream scheme: an explicit `downstream_scheme` (`"https"`/`"http"`) wins,
else inferred from a `:443` dial (`dialIsTLSPort`, conservative — bare host / other port =
plain). New `downstream_scheme` config knob threaded `config` → `wire` → `EdgeBinding`. Core
stays driver-free (dependency-rule test green). White-box `chain_write_tls_test.go` pins the
inference matrix (port, explicit override, case-insensitivity, IPv6 literal, bare host).

**Increment 2 — renderer + read-back (`e677402`).** `insertRoute`, when `Upstream.UpstreamTLS`,
renders the backend `reverse_proxy` with the `transport.tls` block + the `Host` request header
byte-faithful to the real VPS forward (server_name + Host = `{http.request.host}` placeholder);
a plain-HTTP downstream renders the bare `reverse_proxy` unchanged. `types.go` parses
`reverse_proxy` `transport.tls` (`ReverseProxyTransport`/`...TLS` + `firstReverseProxyUpstreamTLS`);
`collectLeaves` sets `Upstream.UpstreamTLS` on read-back so the forward's TLS hop round-trips
(`firstReverseProxyDial`/normalize still resolve the dial — no regression). Tests in
`nested_tls_forward_test.go`: HTTPS forward renders transport.tls + server_name + Host nested
in the wildcard subroute and reads back `UpstreamTLS=true`; plain-HTTP control stays bare
(reproduce-the-gap — TLS intent is the only flip).

**Increment 3 — read-back verify + cross-chain end-to-end (`0d4b907`).**
`apply.verifyEdgeForwardTLS` asserts every chain-forward planned with `UpstreamTLS` reads back
carrying it (the front-leg analogue of the auth read-back). `core/chain_write_test.go`:
`TestChainWrite_FrontForwardTLSAndAuthRoundTrips` — full `expose vault --auth authelia`
produces the TLS-correct front forward AND the valid-auth home terminal, both verified,
`unexpose` restores both edges byte-for-byte; `TestChainWrite_ForwardTLSReadBackFailureRollsBack`
— a memEdge that drops `UpstreamTLS` on apply (the old bare-HTTP render) fails verify and rolls
the chain back (load-bearing guard); the headline ordering test also asserts the front carries
`UpstreamTLS` and the home terminal does not.

**Increment 4 — docs** (this entry): DESIGN (cross-chain WRITE → front-leg upstream TLS),
AUTH-DESIGN §2.1 (front-leg follow-on), STATE-OF-CRENEL (TRIAL-FIX-4 + counts),
TOPOLOGY-RISK-REGISTER row 2.2, TRIAL-PLAN (RE-RUN #3 ready), TRIAL-RESULT (TRIAL-FIX-4 done).
**The live trial is unblocked to re-run with `--auth authelia` for the real 302** (GO-gated).
NO live infra mutated — build/test against fakes only.

## TRIAL-FIX-3 — valid forward-auth JSON renderer (2026-06-28)

The finding that ACTUALLY aborted the live cross-chain WRITE: crenel's granular auth path
emitted a synthetic `{"handler":"forward_auth","crenel_policy":…}` handler. **`forward_auth`
is a Caddyfile DIRECTIVE, not a JSON handler module** — no real Caddy registers
`http.handlers.forward_auth`, so the home edge rejected the load at provision
(`unknown module: http.handlers.forward_auth` → admin PUT 500) and crenel's all-or-nothing
transaction backed out (zero changes). The fakes round-tripped the bogus handler, so the
suite never caught it. Inspecting the captured real home config
(`live-backup/trial-chain-write-20260628T115717Z/home-edge-config-*.json`) showed Authelia
expressed as a `reverse_proxy` → `authelia:9080` with a `handle_response` subrequest
(2xx → copy `Remote-User/Groups/Name/Email` → continue; else return the 302) + a rewrite to
`/api/verify?rd=https://auth.homelab.example` — the canonical `forward_auth` expansion. Four
green increments, each `go build ./... && go vet ./... && go test -race -count=1 ./...` clean,
pushed to Forgejo per increment.

**Increment 1 — read model reads the backend behind the gate, not the authorizer.**
`Handler` gains `HandleResponse`; `isAuthGate()` = a `reverse_proxy` carrying
`handle_response`. `firstReverseProxyDial` now SKIPS the gate (it dials the AUTHORIZER), so
a real Authelia route reads its true service backend (`shlink-web:8080`, not `authelia:9080`).
`detectAuth` recognizes the structural gate as `(detected)` AND round-trips crenel's policy
name off a `vars` marker (`crenel_policy`) — vars keys survive real-Caddy normalize, unlike a
`reverse_proxy`'s unknown fields. Tests: brownfield gate → backend+`(detected)`; marker →
name. (No fixture had `handle_response`, so a pure read improvement.)

**Increment 2 — emit VALID JSON + make the fake faithful (reproduce-then-fix).** Pointing
the now-strict fake at the OLD renderer reproduced the trial abort byte-identically
(`admin PUT … returned 500: loading module 'forward_auth': unknown module:
http.handlers.forward_auth`). Fix: the granular path renders, before the backend, a `vars`
policy marker + a VALID gate — either the CANONICAL `reverse_proxy`+`handle_response`
expansion of an operator-declared endpoint/verify-URI/copy-headers
(`caddy_forward_auth[_verify_uri/_copy_headers]`) or an operator VERBATIM handler blob
(`caddy_handler_json`, purest by-reference). A snippet-only granular policy is REFUSED at
Plan (the admin API can't express a Caddyfile `import`). `caddyfake` now PROVISIONS inserted
handlers (recursing handle/routes/handle_response) against a known-module set and rejects an
unknown module with Caddy's exact 500. `config.AuthPolicy` + `cmd/wire` + `caddy.AuthRef`
gain the new fields; core/model stay driver-free. Tests: canonical render + verbatim blob +
snippet-only-refused (caddy), synthetic-rejected + canonical-accepted (caddyfake); the chain
helpers configure the authelia ref on the terminal edge.

**Increment 3 — cross-chain end-to-end.** `TestChainWrite_ValidAuthGateNestedOnBothEdges`:
`expose vault --auth authelia` across a both-edges-wildcard-subroute chain lands the VALID
gate (marker + `handle_response` + endpoint + verify URI) NESTED inside the home subroute
ahead of the backend (accepted by the faithful fakes, read-back-verified) while the front
relay carries a plain forward with no auth. Plus `--auth none` on the chain (publishes,
verifies, renders no gate).

**Increment 4 — docs** (this entry): AUTH-DESIGN §2/§2.1, DESIGN, STATE-OF-CRENEL (TRIAL-FIX-3),
TOPOLOGY-RISK-REGISTER, TRIAL-PLAN (re-run ready with `--auth authelia` for the 302 proof).

## TRIAL-FIX-2 — write-side subroute nesting (2026-06-28)

The live cross-chain WRITE trial (`TS=20260628T115717Z`) aborted ATOMICALLY with zero
mutation — crenel's all-or-nothing transaction did its job. Grounding the follow-up in
the **captured real edge configs** (`live-backup/trial-chain-write-20260628T115717Z/`)
surfaced a **write-side defect that the entire fake-based suite structurally could not
catch**: crenel's granular insert flat-inserted every per-host route at the top level
(`PUT …/servers/srv0/routes/0`), but BOTH real edges (VPS front + home) keep **all**
per-host routing INSIDE wildcard `*.zone` subroutes
(`srv0.routes[*.homelab.example].handle[subroute].routes[…]`) with **zero** flat
top-level per-host routes. A flat insert misplaces the route relative to where the read
side (`collectLeaves`) enumerates it and where `unexpose`/`Adopt` target it by `@id` —
the **WRITE-side analog** of the already-shipped read-side recursion. Three green
increments, each `go build ./... && go vet ./... && go test -race -count=1 ./...` clean,
pushed to Forgejo per increment.

**STEP 1 — make the Caddy fake faithful (the reason the suite missed it).** The fake
modelled only flat (6-token) PUTs and a top-level-only `@id` search, so a flat insert
"worked" against it. Extended it to mirror real Caddy in exactly the two ways the fix
depends on: **path-addressed PUT at any depth** (`insertByPath`/`insertAt`, shared
`navigate()` with `setByPath`) so a nested insert into a wildcard subroute lands at that
depth, and a **GLOBAL `@id` index** (`actOnID` recurses subroute handlers) so GET/DELETE
`/id/<id>` find + remove a route tagged at any depth. New `caddyfake/fake_test.go` proves
nested insert lands at depth, is found/deleted by id, restores byte-for-byte.

**STEP 2 — the fix: per-zone nesting (`httpRouteInsertPath`).** `insertRoute` now reads
live structure and resolves WHERE index 0 is, **per-zone** (a real edge can route some
zones via subroutes and keep others flat): a wildcard `*.zone` subroute COVERING the
host (Caddy one-label semantics — `wildcardCovers`) → `PUT …/routes/<w>/handle/<h>/routes/0`;
a flat zone (a flat top-level sibling in the same zone — `sameZone`/`zoneOf`) or a
flat/greenfield edge / absent server → the historical top-level insert (back-compat);
>1 covering wildcard (ambiguous) or a zone entirely absent on an otherwise
subroute-structured edge → **refuse loudly**. Removal/Adopt act on the route at its
nested depth unchanged (global `@id` / nested PATCH walk). Core/model stay driver-free
(dependency-rule test green). **Reproduce-then-fix** (each test ran RED on the flat
insert, GREEN after the fix): `NestsPerHostRouteIntoWildcardSubroute` (lands inside the
subroute at index 0, top-level unchanged, others byte-intact, read-back at depth,
unexpose → byte-for-byte restore), `WildcardShadowingAdditive` (updated flat→nested),
`FlatEdgeStillFlatInserts` + `FlatZoneOnMixedEdge_FlatInserts` (back-compat per zone),
`NoWildcardSubrouteForZone_Refused`. The settle-wedge test was re-modelled as an
unexpose (delete-by-id needs no structural read) so it still exercises the
post-mutation settle wedge after the insert path gained a pre-read.

**STEP 3 — the cross-chain end-to-end proof on the real shape.**
`TestChainWrite_NestsAcrossWildcardSubrouteChain`: a front→home chain whose BOTH edges
route the zone via a `*.homelab.example` wildcard subroute; one `expose vault --auth
authelia` lands the home TERMINAL route (real origin + authelia) nested in home's
subroute AND the front FORWARD route (→ downstream, no auth) nested in front's subroute,
each at depth (top-level count unchanged on both), applied downstream→front→public-DNS,
read-back-verified; unexpose reverses → byte-for-byte restore on both edges. The
existing flat-fake chain-write tests keep covering the back-compat flat insert.

**Boundary / honesty.** This fixes the **nesting** axis only. The trial's *hard* abort
was a SEPARATE finding — crenel's granular `forward_auth` renderer emits a synthetic
JSON handler (`http.handlers.forward_auth`) that no real Caddy registers — which remains
a deferred follow-on (`TRIAL-RESULT-chain-write-2026-06-28.md`). NO live infra was
mutated; all work is against fakes/fixtures. The live cross-chain trial is unblocked to
re-run on the nesting axis (separate, GO-gated; rebuild the staged binary from the new
`develop` first). See `TRIAL-PLAN-chain-write.md` (RE-RUN READY note).

## SECURITY — threat model + field-level secret redaction (2026-06-28)

Formalize the security posture and harden the secret-leak surfaces. The motivating
fact: crenel reads/writes the FULL edge config, which can carry real secrets —
Cloudflare DNS-01 tokens, ACME account keys/email, basic-auth hashes, forward-auth
secrets — plus crenel's own push token and operator backups. None of that should leak
into printed/exported/error output, and **none of the redaction may touch the apply
path** (crenel must write real config and verify against it). Four green increments,
each `go build ./... && go vet ./... && go test -race -count=1 ./...` clean, pushed to
Forgejo per increment.

**STEP 1 — SECURITY.md (threat model).** Sensitive-data inventory (what secrets a
managed edge config holds + crenel's token/backup files); trust boundaries and the
loopback-first transport model — the admin API is **plaintext + unauthenticated**, so
it MUST stay loopback-bound; `direct` is on-box-only-safe, `ssh-exec`/`ssh-tunnel` keep
the config inside the SSH-encrypted channel, and network-exposing the admin is THE
anti-pattern; what crenel persists vs not (no SOT, no stored secret, push token read
fresh); a per-boundary adversary table (local host / SSH channel / loopback admin /
Forgejo remote / crenel's own output); residual risks (operator SSH+known_hosts,
backups hold real secrets, on-demand operator trust, best-effort redaction on unmodeled
bytes); and an operator checklist. Linked from README + DESIGN.

**STEP 2 — secret redaction.** The rule: **redaction applies to OUTPUT only; apply /
read-back-verify / preserve-unmanaged keep REAL values.**

- **`internal/redact`** — a value-aware leaf package (imports nothing of ours; the
  dependency-rule test stays green). Detection is a conservative KEY match
  (`token`/`secret`/`password`/`api_key`/`private_key`/`email`/… — deliberately NOT
  bare `key`, which matches every JSON map key) PLUS a VALUE heuristic (PEM private
  keys, bcrypt/argon/apr1 hashes, JWTs, `Bearer`/`Basic` auth-scheme creds) so a secret
  under an unexpected key is still caught. `JSON()` walks structurally and preserves
  non-secret routing fields; `Text()`/`Snippet()` handle truncated/invalid JSON (a
  bounded `RawExcerpt`, an admin-API error body). Masks long→`••••<last4>`,
  short→`REDACTED`.
- **Wired at the CLI boundary only** (so core/drivers stay real-valued and the apply
  path is structurally unable to see a masked value): `status --json`'s
  `Unparsed.RawExcerpt` (the P0 declared-unknown excerpts can capture secret bytes — an
  nginx auth header, a basic-auth hash); admin-API error echoes (a Caddy `/load`
  rejection echoes the offending config) masked at the print boundary without mutating
  the real error value; the rollback-error prints; and `export --redacted`. A
  `--show-secrets` global flag (default off) is the documented escape hatch.
- **export hardening:** `0600` (was `0644`; a snapshot can hold real secrets);
  `export --redacted` writes a secret-free shareable copy; the snapshot now also records
  each edge's declared-unknowns (faithful coverage). The restore-grade backup keeps real
  bytes by design.

**The guarantee, tested both ways.** Each output surface masks by default and
`--show-secrets` reveals; AND a granular `expose` performed alongside an unmanaged
basic-auth route leaves that route's secret **byte-intact** in live config — proving the
write/verify/preserve path uses REAL values. **Honest boundary:** caddy's own
`RawExcerpt` re-marshals TYPED structs (a stray token in an unmodeled handler field is
dropped, not leaked); the live-text leak surfaces are nginx excerpts,
`LiveEdgeState.Raw` (kept internal, never surfaced), and admin-body error echoes — all
redacted. Redaction is conservative-by-design but best-effort on bytes crenel never
modeled, and never affects correctness (apply/verify never redact). See SECURITY.md.

### Increment — SECURITY.md threat model + README/DESIGN links
- `SECURITY.md`: full threat model (§§0–7) — TL;DR, sensitive-data inventory, transport
  trust model + boundary diagram, persists-vs-not, per-boundary adversary table,
  residual risks, the redaction guarantee, operator checklist. Linked from README.

### Increment — `internal/redact` package
- Value-aware masker: `IsSecretKey`, `Value`, `JSON`, `Text`, `Snippet`, key patterns +
  PEM/bcrypt/JWT/Bearer value heuristics. Thorough table tests (each secret class, the
  value heuristic under an innocuous key, clean-config-untouched, truncated-excerpt,
  directive forms, Snippet JSON-vs-text routing).

### Increment — redaction at status/error output boundaries
- `--show-secrets` flag (bind + absorb-post-verb + usage); `redactStatus` for
  `status --json` `RawExcerpt`; `errMessage`/`printError` for admin-body error echoes;
  `redactLines` for rollback errors; the Authorization-scheme heuristic added. Tests
  cover default-mask + reveal on each surface, plus the apply-preserves-real-secret
  guarantee.

### Increment — export `0600` + `--redacted`
- `cmdExport` parses `--redacted`, writes `0600`, scrubs excerpts via `redactSnapshot`;
  `core.ExportSnapshotData` exposes the struct + records `Unparsed`; usage updated.
  Tests: 0600 enforced, `--redacted` scrubs an excerpt secret while keeping routing.

## TRANSPORT — pluggable connection axis (HOW crenel reaches an admin API) (2026-06-28)

The fourth axis, made explicit. Until now crenel had exactly one way to reach an admin
API — open an HTTP client to a configured `admin_url` — and any plumbing (SSH tunnels)
was the operator's out-of-band problem. That hardcoded assumption was also a wall:
the maintainer's home Caddy admin binds **container-localhost only and is not published**, so no
host can open an HTTP client to it (the chain-write trial's gating finding). This work
makes the connection a first-class, pluggable port (`ports.Transport`) alongside
EdgeProvider / DNSProvider / OriginResolver. DESIGN-first (a "Transport / Connection"
section in DESIGN.md), then five green increments; fakes/seams only in tests, plus one
READ-ONLY live verification against the real home edge.

**The seam.** Every Caddy admin call already funnels through one method, `doAdmin`.
`ports.Transport` is a thin HTTP-semantics RPC — `Do(ctx, method, path, contentType,
body) → (status, body, err)` — and `doAdmin` now delegates just the WIRE call to it.
Crucially the **per-op timeout AND the wedge/error classification stay in `doAdmin`,
ABOVE the seam**, so the never-hang guarantee and `ErrAdminUnresponsive` apply uniformly
to every transport — and `ErrAdminUnresponsive` stays in the caddy package, no import
cycle. The transport contract requires a fired ctx deadline to surface as a wrapped
`context.DeadlineExceeded` (or a net timeout) so the driver classifies a wedge the same
no matter how the call traveled.

**direct (zero behavior change).** The existing `net/http` admin client, moved verbatim
into `transport.Direct`. `caddy.New(baseURL, …)` builds a Direct by default (carrying
any `WithHTTPClient` override), so every edge configured with just an `admin_url` (or a
fake URL in tests) behaves byte-for-byte as before — the whole suite passed unchanged on
the refactor commit. `WithTransport` injects an alternate channel.

**ssh-exec (no port, no tunnel).** Reach the admin by running the call as a COMMAND on
the far end. The operator configures an exec PREFIX as argv crenel does NOT shell-parse
(`["ssh","root@proxmox","pct","exec","100","--","docker","exec","-i","caddy","sh"]`);
crenel generates a POSIX-sh curl/wget script and feeds it to the prefix over **STDIN**.
That is the key insight for nesting: nothing crosses a shell-parse boundary as an
argument, so quoting survives an arbitrarily deep `ssh → pct exec → docker exec` chain
(the classic failure of building one giant quoted `sh -c '…'` string). The body is
**base64-embedded** (`printf %s '<b64>' | base64 -d | curl --data-binary @-`) so a
Caddyfile/JSON body with spaces/quotes/newlines travels safely; the status is captured
with `curl -w 'CRENEL_HTTP_STATUS:%{http_code}'` after the body. Errors split three ways:
marker present ⟹ admin answered (return status + nil err, even non-2xx); marker absent ⟹
`ErrTransportUnreachable` enriched with exit code + stderr; ctx deadline ⟹ wrapped
`DeadlineExceeded` ⟹ the driver's `ErrAdminUnresponsive`. The exec is a `Runner` seam
(default `OSRunner`). wget is supported for GET reads (BusyBox far ends) with a
synthesized 200 (it can't report the HTTP status); curl is the default for full fidelity.

**ssh-tunnel (managed local forward).** crenel opens an ephemeral `ssh -N -L` as a
MANAGED child (not `-fN` — crenel owns the lifecycle), waits for the forward to accept,
then routes every call through an inner Direct on the local port. Opens lazily, closed
on the cmd cleanup chain, reusable across calls. ssh is a `Forwarder` seam (default
`OSForwarder`). Automates the manual Option-A tunnel.

**Wiring + back-compat.** A per-edge `transport` block (type + type-specific params) on
Settings + EdgeSettings; `buildTransport` at cmd is the single place a concrete
transport is chosen, and ssh-tunnel registers its `Close` into the wiring cleanup.
Absent / `type:"direct"` ⟹ the driver's default Direct, so single/multi/chain configs
are unchanged. The fake-seed demo path keeps reaching its in-process admin directly.

**Tests (green, race-clean; 13 pkgs, 256 test funcs).** Hermetic fake-Runner /
fake-Forwarder tests pin the EXACT generated argv + script, GET/POST/PUT/DELETE/PATCH
parsing, the three-way error classification, and the open-once/use/close tunnel
lifecycle. A **guarded** integration tier runs REAL `sh`+`curl` against an in-process
caddy fake at both the transport layer and through `build()` wiring (skips if
sh/curl/base64 are absent). A **mixed-transport** core test runs the full P4-write
chain transaction with **front=direct, home=ssh-exec** end to end (expose lands
front-forward + downstream-real-backend+auth + DNS in order, read-back-verified;
unexpose reverses) — the exact trial shape, no live infra.

**LIVE READ-ONLY verification.** Pointed ssh-exec at the real home edge
(`ssh root@proxmox → pct exec 100 → docker exec -i caddy → sh → curl 127.0.0.1:2019`) and
ran `crenel status` + a read-only `preview`. crenel read the home edge's **live** config
— **51 services, default-deny ENFORCED** — with the admin still container-loopback-only
(nothing published, no tunnel) and the live config **sha256 byte-identical before/after**
(`174d1d92…`, the chain-write trial's HOME anchor). NO mutation. This means the live
cross-chain WRITE trial can now run OVER ssh-exec instead of the manual Option-A tunnel
(no home-admin publish, no container recreate) — TRIAL-PLAN-chain-write.md §0 updated.

**Honest boundaries.** OSForwarder (real `ssh -N -L`) and OSRunner are faked in the
suite; the live read-only run is OSRunner's only real exercise, and a real ssh-tunnel
open against live infra is untested by design. The live WRITE over ssh-exec remains a
separate, backed-up, GO-gated step.

Files: `internal/ports/ports.go` (the port), `internal/drivers/transport/`
(`direct.go`/`sshexec.go`/`sshtunnel.go` + tests), `internal/drivers/edge/caddy/caddy.go`
(the `doAdmin` seam + `WithTransport`), `internal/config/settings.go` +
`cmd/crenel/wire.go` (`transport` config + `buildTransport`), tests in `cmd/crenel` +
`internal/core/transport_chain_test.go`, `examples/settings-transport-sshexec.json`.

## P4-write — cross-chain coordinated WRITE (2026-06-27)

The write dual of the P4 read model. A single `expose`/`unexpose`/`apply`/`reconcile`
on a CHAIN now lands the coordinated entries across the front edge + the downstream
edge + DNS as ONE all-or-nothing, read-back-verified transaction — no more mutating a
chain one edge at a time and hoping they agree. DESIGN-confirmed first (addendum to
DESIGN.md "Chain-aware model (P4)"), then built in green increments; fakes/fixtures
only, no live infra.

**The projection decision.** A chain `expose` no longer treats the front's leaf as
terminal. Core projects the op into one changeset PER PARTICIPANT, classifying each
edge's ROLE for the service (`core/chain_write.go` `roleFor`): a TERMINAL edge (the
service is in its origins — the downstream/home) plans the real route via its own
driver carrying `op.Auth`; a chain FRONT (`downstream_edge` set, doesn't itself front
the service) gets a synthesized FORWARD route — a `DirectBackend` dial to
`downstream_address`, NO auth (auth attaches where the host is SERVED). The recursion
supports multi-hop fronts; a non-chain op yields only terminal participants, so
single-edge / parallel multi-edge project byte-for-byte as before.

**Ordering, rollback, gate, guardrail.** `buildSteps` gains a chain-DEPTH secondary
sort key: on expose **downstream → front → public-DNS LAST** (announce to the world
only once both edges serve); on unexpose the reverse. Depth is 0 in any non-chain
topology, so ordering there is unchanged. The front and downstream are ordinary edge
steps with per-edge inverse compensators, so the existing all-or-nothing, wedge-safe
rollback already spans the chain — any failure on either edge or DNS unwinds every
applied participant. `verify` now read-back-asserts each ADDED route's auth landed
(AuthNone/"" normalized) — proving the policy attached at the DOWNSTREAM edge and
closing the consolidation-pass auth-verify gap. `gateChainOwnership` spans BOTH edges
(foreign/unknown on either refuses, even a pre-existing foreign downstream that
converges to a no-op). The CLI public-without-auth guardrail evaluates the whole chain.

**Converge.** `reconcile`/`drift` are chain-aware: an edge participates by chain ROLE,
a half-present chain converges as one transaction (missing front forward → re-forward;
missing downstream → re-serve by its own resolver), and the canonical auth comes from
the SERVING edge so a re-add never strips protection.

**Tests + demo.** `internal/core/chain_write_test.go` (real caddy fakes + DNS):
expose lands front+downstream+DNS atomically in the safe order, read-back-verified;
injected failure at each step (front / downstream / public-DNS / silent auth-drop) →
full rollback with nothing half-applied on either edge; unexpose reverses; reconcile
heals both half-present directions; generator/foreign downstream refused; idempotent
re-expose is a no-op. Captured CLI demo against `examples/settings-chain-write.json`
in `examples/DEMO-chain-write.md`. Every increment green under `go build ./... && go
vet ./... && go test -race -count=1 ./...`, pushed to Forgejo.

**Honest boundary.** Built against fakes/fixtures only — a live cross-chain write
trial is a separate, later, backed-up step. A pure-front chain (no `downstream_address`)
stays READ-only until an address is configured. Chain `Adopt` of a pre-existing forward
reuses normal per-edge adoption; two-zone front edges remain follow-on.

## P4 — chain-aware modeling (read-correctness) + demo-origins papercut (2026-06-27)

Promotes the chain from a blunt suppression flag (`auth_downstream`) to a
first-class, OBSERVED front-edge → downstream-edge relationship. DESIGN-first (a
model change), then built in green increments; fakes/fixtures only, no live infra.

**The model decision.** A CHAIN (front → downstream → origin) is modeled DISTINCT
from the parallel multi-edge "double-write" (peer edges fanning the SAME host to
several edges at once). In a chain a host enters at the public FRONT edge and is
FORWARDED to a DOWNSTREAM edge that resolves it further — so the front's "backend"
for that host *is another edge*. Config: a front edge names `downstream_edge` (+
optional `downstream_address`); a front leaf that dials the downstream edge is a
chain FORWARD (its real destination/auth live downstream), any other leaf a terminal
origin. Single-edge / parallel-multi-edge configs set neither and are unchanged.

**What status/audit now show.** Resolution is a CORE concern, driver-free (a driver
only sees its own leaf): core attaches `model.ChainLink` to a forwarded route and
FOLLOWS THROUGH — reading the downstream edge to recover the host's real backend +
the auth OBSERVED there. `status` renders `front-dial → downstream-edge:real-backend
[auth:…]`; `audit` resolves `public_without_auth` by OBSERVATION (downstream-Authelia
→ protected, not flagged; downstream-no-auth → flagged) and emits
`chain_resolved`/`chain_unresolved`. When the downstream edge is unreadable, the host
is DECLARED "downstream, not observed" and falls back to the `auth_downstream`
assertion (suppress + `edge_unreadable`) — never a misread, never assumed safe.

**Honest boundary.** READ-correctness + honest auth resolution are built; cross-chain
transactional WRITE (one verified `expose` across both edges) is deliberate follow-on
— a chain is mutated one edge at a time; the front's write-path `Adopt`/projection
still treats its leaf as terminal.

**Increments (each green under `go build && go vet && go test -race`, pushed):**
- **A** — `model.ChainLink` (`Route.Chain`) + `EdgeBinding/EdgeSettings/Settings.
  {DownstreamEdge,DownstreamAddress}` plumbing (inert seam; config decode test).
- **B** — `core/chain.go` (`readAll` tolerant of chain-target read failures,
  `buildChainContext`, `resolveChain`, chain-aware `effectiveAuth`, `dialHost`);
  `status` follow-through + unreadable-target degrades to DECLARED-UNKNOWN row. Old
  `EdgeBinding.effectiveAuth` folded into the chain context. Tests:
  follow-through + observed auth + all three unresolved branches.
- **C** — `audit` resolves `public_without_auth` by observation;
  `chain_resolved`/`chain_unresolved`/`edge_unreadable` findings. Tests: observation
  (not blanket-suppression) drives protection; unreadable falls back honestly.
- **D** — CLI `chainDest` rendering; bundled two-edge fixtures
  (`examples/seed-chain-{front,home}.json` + `settings-chain-p4.json`) mirroring
  the maintainer's shape; end-to-end CLI test.
- **E (papercut)** — `config.Load` decodes a real config into a ZERO `Settings`
  (not under `Defaults()`), so demo origins (grafana/photos/vault) stop leaking as
  phantom `import --dry-run` entries; empty-path/`init` still seed helpful defaults.
- **F** — docs: DESIGN "Chain-aware model (P4)", register P4 + axis 2.2/5.3,
  AUTH §6, STATE §5c, this entry.

Live demo (`crenel -config examples/settings-chain-p4.json status`):
`vault.homelab.example -> 10.0.0.13:443 → home:10.0.0.7:8200 [auth:(detected)]`;
`books`/`git` resolve to their open downstream backends and `audit` flags only those.

## v0.1.1 — Caddy real-edge misreads from the v0.1.0 read-only trial (2026-06-27)

The v0.1.0 read-only install on the maintainer's real VPS edge (loopback admin API, GET-only,
proven byte-for-byte unchanged) surfaced TWO Caddy-normalizer misreads — both
MISREAD-↓ by omission, the class P0/bounded-honesty exists to prevent — so both are
fixed (impl + tests + docs, green, race-clean):

- **Grouped multi-host routes.** His edge groups many vhosts that share one backend
  into ONE Caddy route (`host: [auth, books, git, …]` → home edge; one 16-host
  group + one 7-host group). `caddy.normalize`/`collectLeaves` read only the FIRST
  host of a multi-host match (`hostMatch` → `Host[0]`) and silently dropped the
  rest — status showed 9 hosts when ~30 were reachable. Fix: `hostMatches()` returns
  every host across all matcher sets (deduped, ordered); `normalizeServer` and the
  `collectLeaves` nested descent now loop over ALL hosts (one leaf per co-matched
  host). `hostMatch` is retained only for the host-PRESENCE check in `isCatchAllDeny`.
- **`abort: true` deny.** His per-zone catch-alls are
  `{"handler":"static_response","abort":true}` with NO `status_code`. `isDeny` only
  matched `status_code >= 400`, so the closing route read as an unmodeled handler →
  declared unparsed → default-deny falsely `UNKNOWN`, coverage INCOMPLETE. Fix: added
  `Handler.Abort`; `isDeny` honors it. `collectLeaves` now returns a `resolved` bool
  so a deny-ONLY subroute (a close with no backends) resolves cleanly instead of
  tripping the opaque-subroute check (which keyed on a bare leaf+unparsed count).

Net on the real edge: ~30 services enumerated, 0 unparsed, default-deny `ENFORCED` —
the correct, complete read; auth-downstream still suppresses the false
`public_without_auth`. Tests: `grouped_multihost_test.go` (grouped enumeration /
abort-deny / flat-multi-host-top-level), all existing caddy tests still green.
Tagged `v0.1.1`; `main` fast-forwarded; redeployed read-only to the VPS.

## Release — v0.1.0 (2026-06-27)

First tagged cut. No code change beyond release hygiene: added `CHANGELOG.md`
(what Crenel is + the full verb/driver/capability set + the honest known-boundary
list), confirmed the version stamp (`-X main.version` from `git describe --tags`,
so a build on the `v0.1.0` tag reports `crenel v0.1.0`), and produced the
multi-platform static artifacts via `make release` (linux/{amd64,arm64} +
darwin/{amd64,arm64}). Green bar at tag: `go build ./... && go vet ./... && go test
-race -count=1 ./...` — 12 pkgs OK, 3 no-test, race-clean. Tagged on `develop`;
`main` fast-forwarded to the same commit. Installed read-only on the live VPS edge
(see the v0.1.0 trial note).

## Danger-first backlog (post-consolidation) — current-state summary

Worked in DANGER order over the STATE-OF-CRENEL backlog, each item impl + tests +
docs, every commit green under `go build ./... && go vet ./... && go test -race
-count=1 ./...`, pushed to Forgejo per increment.

- **P1.5 — Multi-server Caddy (register §1.9).** `caddy.normalize` enumerated only
  the one configured `http.servers` key, so a route on a sibling server (`srv1`) was
  invisible — a MISREAD-↓-by-omission that under-reports exposure and could keep
  default-deny falsely green. Fix: extract `normalizeServer` (the per-server route
  walk) and run it over EVERY server. A fully-modeled forwarding sibling has its leaf
  routes folded into the view (its hosts now appear in status); a sibling that
  **forwards** (`reverse_proxy`/subroute) but can't be fully modeled becomes one
  `UnknownServerBlock` (→ deny downgrades to UNKNOWN); a **benign** non-forwarding
  sibling (a `:80`→`:443` redirect, a pure `file_server`) is **not** flagged —
  `serverForwards` is the no-cry-wolf gate. Full-load `Apply` gained
  `multiServerFullLoadSafe`: it refuses a multi-forwarding-server edge (the
  single-server renderer would collapse it) → `--granular`. 7 new tests
  (`multiserver_test.go`) cover fold / unknown-downgrade / benign-redirect /
  static-file / separate-apps-not-misread / full-load-refusal / granular-preserves.

- **P2 (finish) — generator detection: Pangolin + caddy-docker-proxy (register
  §3.1/§3.4).** Closes the highest-prevalence MISMANAGE class for the two remaining
  generators. **Pangolin** generates *Traefik* config (not Caddy — confirmed: it
  serves Traefik dynamic config via the HTTP provider and attaches its `badger`
  access plugin to every router), so detection lives in the **Traefik** driver:
  `detectGenerator` now fires `Generator="pangolin"` when any router references the
  `badger` middleware (base-name match, so `badger`/`badger@http`/`badger@file` all
  count) → edge + routes `OwnForeign`. **caddy-docker-proxy**: the Caddy **admin API
  carries no CDP marker** (verified against CDP's own docs — its only artifact is the
  on-disk `Caddyfile.autosave`), so the Caddy driver gained two real signals:
  `WithGeneratorConfigPath` scans that mounted autosave file (by filename/content)
  and `WithGenerator` honors an operator-declared hint; either sets
  `Generator="caddy-docker-proxy"` → edge foreign. Both keep routes READ-able
  (understanding ≠ ownership). Wired through `config.Settings`
  (`caddy_generator` / `caddy_generator_config_path`, top-level + per-edge) and
  `wire.go`. Tests: traefik `generator_test.go` (Pangolin detected / no-false-positive
  on ordinary middleware); caddy `generator_test.go` (autosave detected / declared
  hint / no-false-positive on hand-written Caddy / missing-file tolerated); core
  `generator_gate_test.go` end-to-end (CDP edge → status foreign → audit
  `ownership_unconfirmed` → expose refused, live config untouched). **Honest boundary:**
  CDP auto-detection from the admin API alone is structurally impossible (no marker);
  without the mounted autosave file or the declared hint a CDP edge is still
  read-only-safe via P0 but its routes look `unmanaged`.

- **P3 — tunnel/overlay ingress (register §4.2/§4.3 — the "exposed isn't a public
  port" MISREAD-↓).** A service reachable via cloudflared / Tailscale funnel is PUBLIC
  even when the local proxy binds localhost; reading only the listener and calling it
  internal is a worst-direction misread. Built: typed `model.IngressKind ∈
  {public-listener, tunnel, overlay, unknown}` + `External()` (the field was a free
  string; now typed). Ingress is orthogonal to the proxy driver (cloudflared/Tailscale
  front anything), so detection lives in **core** (`core/ingress.go`) and is overlaid
  onto live state via `EdgeBinding.resolveIngressKind`: an operator-DECLARED
  `ingress_kind` wins; else a signature scanned from `ingress_config_path` (a
  cloudflared `config.yml` → `tunnel`; a Tailscale `serve.json` → `overlay`); a
  present-but-unrecognized ingress file → `unknown` (declared external, **never**
  assumed internal); an absent file → no claim. Surfaced as the `ingress_external`
  audit warning (now keyed on `External()`, fires for the unknown case too) + a status
  `INGRESS:` header / `⚠ Reachability` note. Wired through `config.Settings`
  (`ingress_kind` / `ingress_config_path`, top-level + per-edge) and `wire.go` onto the
  `EdgeBinding`. Tests: core `ingress_test.go` (declared tunnel / cloudflared-detected
  / tailscale-detected / unrecognized→unknown / no-ingress-clean / missing-file). One
  existing test updated to the typed `model.IngressTunnel`. **Boundary:** this flags
  the edge; recovering the *real* per-host public/private from the tunnel's own ingress
  rules (the CORRECT-ness upgrade) is left for a follow-up.

## P0 — Detect-and-Declare-Unknown (the universal safety net) — current-state summary

The register's **P0** (TOPOLOGY-RISK-REGISTER.md §4) is built: Crenel is now
structurally incapable of silently misreporting exposure. When `normalize` meets a
handler / routing construct / ownership situation it can't fully parse or confirm,
that uncertainty is first-class — counted, surfaced, and mutation-blocking — never
swallowed. Landed in four green increments (each `go build ./... && go vet ./... &&
go test -race ./...`, pushed to Forgejo per increment):

1. **Model + ternary ownership.** `LiveEdgeState.{Unparsed []Unparsed, Generator,
   IngressKind}` + `Coverage()` / `FullyParsed()`; `DenyState` ternary
   (MISSING/ENFORCED/UNKNOWN) with the load-bearing rule *ENFORCED ⟹ FullyParsed*;
   `Route.Ownership ∈ {crenel,unmanaged,foreign,unknown}` augmenting `Managed`
   (`Managed == Ownership==crenel`; `OwnershipFromMarker` keeps unmarked == unmanaged,
   behavior-equivalent). Drivers set `Ownership` alongside `Managed`.
2. **Drivers EMIT `Unparsed`, never drop.** Caddy: unmodeled terminal handlers
   (file_server/php_fastcgi/vars), unresolvable subroute leaves, and a TOP-LEVEL
   host-less subroute (not descended — could nest a permissive catch-all);
   `collectLeaves` threads an unparsed accumulator + locator, and the old
   `(subroute)` placeholder route is replaced by an honest `UnknownNestedRoute`.
   Traefik: a router with readable host(s) but no resolvable upstream
   (`backend_indirect`). nginx: a `server_name` vhost that doesn't `proxy_pass`
   (`handler_unrecognized`). `testdata/unparseable-prod.json` + driver tests prove
   it; a regression test locks the real nested fixture at FULL coverage.
3. **Deny downgrade + surfacing.** `audit` deny is ternary
   (`deny_catchall_unknown` warning; new `coverage_incomplete`,
   `ownership_unconfirmed`, `ingress_external` findings); `status` prints a coverage
   line + "⚠ Not understood" section + FOREIGN/INGRESS header annotations, with
   `--json` carrying `unparsed[]`/`generator`/`ingress_kind`; the HUD/SVG render
   DEFAULT-DENY as amber UNKNOWN distinct from green ENFORCED / red FAIL-OPEN. The
   trial's silent 25→2 now reads "read 1/4 routes — 3 NOT UNDERSTOOD — INCOMPLETE,
   default-deny UNKNOWN" instead of a confident falsehood.
4. **Refuse-to-manage gate.** `core.gateOwnership` (new `internal/core/gate.go`)
   runs before any driver `Apply` for every mutating verb: refuses
   (`ErrRefuseToManage`) a `foreign` route/edge (generator-owned — would be reverted)
   or an `unknown` one. `--yes` never bypasses; `-force`/`Engine.Force` is the
   documented escape for `unknown` only, never `foreign`. `import`/`apply --adopt`
   refuse to stamp foreign/unknown blocks; clean `unmanaged` routes stay adoptable;
   crenel/unmanaged routes stay fully mutable (gate dormant — no regression).

**Generator/ingress DETECTION (set `Generator`/`IngressKind`) is P2/P3** — not yet
wired, so those fields stay empty today and the net is driven by the parser's
`Unparsed`/`Ownership` signals. The whole thing is additive and dependency-rule-
preserving (`core`/`model` driver-free; `deps_test` green): each later parser fix
just MOVES routes from `Unparsed` into `Routes` and shrinks the unknown set.

**P2 started (read-only generator detection).** Two in-band detectors now SET
`Generator` so the P0 gate fires on real generators: the **nginx** driver recognizes
**Nginx Proxy Manager** (the highest-prevalence homelab proxy) from its generated-file
signature, and the **Traefik** driver recognizes label/orchestrator providers from a
router's `@docker`/`@swarm`/`@kubernetes*` suffix. Both mark the edge + every route
`OwnForeign` (still READ — understanding ≠ ownership), so `status`/`audit` show
FOREIGN-MANAGED and any mutation is refused edge-wide. Proven end-to-end on the real
nginx driver (NPM config → refused expose/unexpose, file byte-for-byte untouched),
with false-positive guards. Remaining (logged): caddy-docker-proxy (needs the on-disk
`Caddyfile.autosave` signal, outside the admin-API read), Pangolin, and the
cloudflared/Tailscale ingress detectors (P3). Read-only-safe by construction.

## TRIAL-FIX — real-VPS read-only trial gaps (current-state summary)

A strictly read-only trial of `develop` against the maintainer's live VPS Caddy edge
(`TRIAL-2026-06-27-real-vps-readonly.md`) surfaced two model-vs-reality gaps. The
load-bearing things held (default-deny read correctly, read-only discipline,
import refused the wildcards), but:

- **NEST1 — nested subroute recursion (the high-leverage fix).** The real edge
  nests `wildcard → subroute → per-host route → subroute → leaf reverse_proxy` down
  to ~25 services; `normalize` walked only the TOP level, so `status` showed 2
  opaque wildcards, `import` was a no-op (no service-level routes visible), and
  `audit` couldn't see per-service. Now `normalize` RECURSES (`collectLeaves`):
  each per-host leaf is enumerated with its real host, real leaf dial, ownership
  (`@id` on the per-host route), and any nested auth handler. `Adopt` recurses too
  (stamps the `@id` onto a per-host route inside a wildcard zone; the fake's PATCH
  gained generic nested-path addressing, faithful to Caddy). **Default-deny reading
  unchanged** (only a TOP-LEVEL host-less forward is fail-open; nested host-less
  forwards inherit the parent host as a leaf). Fixture
  `testdata/nested-subroute-prod.json` mirrors the real shape (two wildcard zones,
  mixed managed/unmanaged leaves, one with a nested auth handler). Tests prove
  status enumerates the real services, default-deny still PRESENT, import sees the
  adoptable set (vault+photos) / conflict (cloud) / already-managed (jelly+git),
  audit warns `public_without_auth` only on the no-auth leaves, and nested
  adopt+read-back targets the correct leaf — the flat-topology tests still pass.
- **CHAIN1 — chain topology + downstream auth (design + minimal mitigation).** The
  VPS edge carries NO forward-auth: auth is enforced one hop DOWNSTREAM at the home
  edge — a front-edge→downstream-edge CHAIN, distinct from the parallel multi-edge
  double-write. A per-edge `auth_downstream` attribute (`config.Settings`/
  `EdgeSettings` → `core.EdgeBinding.AuthDownstream`, wired at cmd) marks an edge as
  the front of such a chain: `audit` SUPPRESSES `public_without_auth` for its
  (non-mesh) hosts and emits one informational `auth_downstream` finding naming them
  (suppression with a reason, not a silent drop); `status` labels them
  `auth: downstream` (core overlays `model.AuthDownstream`, display-only on a copy; a
  real auth reference read from live still wins). The warning still fires for genuine
  terminal edges. Centralized in `EdgeBinding.effectiveAuth` so status/audit agree.
  Full chain-aware projection/transaction (and two-zone edges) scoped as follow-on in
  DESIGN.md "Chain topology". Tests: `chain_test.go` +
  `TestNestedSubroute_AsDownstreamAuthFrontEdge` (the faithful trial topology).

`go build ./... && go vet ./... && go test -race ./...` green throughout. Core/model
still import no driver (dependency-rule test green). Fakes/fixtures only — no
live-infra mutation.

## AUTH — forward-auth by reference (current-state summary)

Attach a **forward-auth policy** (Authelia/Authentik/…) to an exposure **by
reference**, never embedding the provider's internals. Designed first in
**AUTH-DESIGN.md**, then built incrementally. Fakes/fixtures only. Closes the
auth-composition gap STRAIN.md §3 flagged as inexpressible.

STEP-0 baseline (verified): the model had **no auth dimension**; **no driver
rendered auth** for a new exposure (only plain reverse-proxy + route mode); existing
auth was already *preserved* on adoption/additive apply but could not be *attached*.

- **AUTH1 — model + config + CLI.** `model.Op.Auth` + `model.Upstream.Auth` (a
  provider-agnostic policy NAME); `model.AuthNone`, `Op.HasAuthPolicy()`,
  `ValidateAuth(mode,auth)` + `ErrAuthUnsupportedForMode` (auth is HTTP-only —
  refused on passthrough/mesh, centrally in core.Plan + the declarative plan).
  `config.AuthPolicy` + `Settings.AuthPolicies`; `core.Exposure.Auth`; `-auth` flag
  + `[auth:<policy>]` on status/preview route lines.
- **AUTH2 — render per driver + read-back recognition.** Caddy: granular JSON
  `forward_auth` reference handler (+ on-disk `import <snippet>`), auth requires
  granular apply (mirrors the layer4 gate). Traefik: named middleware on crenel's
  router only. nginx: `auth_request` in the managed `location /`. Policy→reference
  injected at `cmd` from `config.AuthPolicies` (default conventions). `normalize`
  recognizes auth read-only (own reference round-trips the policy; brownfield →
  `model.AuthDetected`).
- **AUTH3 — audit check + guardrail.** `public_without_auth` audit WARNING (never
  critical; mesh excluded). CLI refuses to publish a host PUBLIC with auth
  unspecified (`--yes` doesn't bypass) — explicit `--auth none`/`auth: none` is the
  opt-out.
- **AUTH4 — brownfield E2E + docs.** import (adopt, Authelia handler preserved
  verbatim + recognized) → apply a new host WITH a referenced policy; passthrough+auth
  refusal; guardrail. Docs: DESIGN/STRAIN/USABILITY/README/AUTH-DESIGN.

Dependency rule unchanged (core/model import no driver; references injected at cmd).
`go build ./... && go vet ./... && go test -race ./...` green throughout.

## USABILITY (brownfield) — current-state summary + what's next

Making Crenel usable on a **real, pre-existing** edge (the operator already has
hand-built caddy-edge + Caddy + AdGuard + Cloudflare for the exact hosts Crenel
would manage). Designed first in **USABILITY-DESIGN.md** (read it for the precise
semantics), then built incrementally. Fakes/fixtures only.

Three interacting features:
- **A. Ownership & adoption — `crenel import`** (DONE, UB1): bring an existing
  UNMANAGED route under management in-place (ownership only, no behavior change).
- **C. Declarative `crenel apply <file>.yaml`** (DONE, UB2): kubectl-style desired
  exposures, brownfield-safe `--adopt`/`--prune`, + JSON/YAML config support.
- **B. Caddy on-disk persistence** (DONE, UB3): additive Caddyfile injection +
  validate-first + correct-invocation debounced reload; warning-not-rollback.
- **Installability** (DONE, UB4): `crenel init`/`version`, brownfield quickstart in
  the README, linux/arm64 cross-compile + a Makefile release step.

Substrate decision: separate **managed DOMAIN** (service ∈ `origins`, projection)
from the **OWNERSHIP marker** (Caddy `@id`, Traefik `crenel-*` key, nginx comment;
DNS has none — managed-ness is projection-derived). `model.Route.Managed` now
surfaces ownership; optional `ports.Adopter`/`ports.Persister` capabilities added.

The brownfield usability arc (UB1–UB4) is complete: `import` → `status`/`drift` →
`apply` is demonstrably safe on a setup like his (wildcard subroutes + an unmanaged
Authelia vhost preserved throughout). Next candidates: real-edge persistence
validation, `apply --prune` polish, a Traefik/nginx persistence story if needed.

### UB1 — `crenel import`: adoption of a brownfield setup

`crenel import` scans live, finds unmanaged-but-matching routes in the managed
domain, previews, and stamps ownership markers in-place — idempotently, without
changing runtime behavior, never touching anything outside the domain.

- `model.Route.Managed bool` — ownership, set by each driver's `normalize` from
  its marker (Caddy `@id == crenel-route-<host>`, Traefik `crenel-*` key prefix,
  nginx `# crenel-managed:` comment). Read-only metadata; default false.
- Optional `ports.Adopter` (`Adopt(ctx, hosts)`) implemented per driver:
  Caddy PATCHes `@id` into the existing route via the RAW config (preserves
  unmodeled fields verbatim); Traefik re-keys router/service → `crenel-*`
  (preserves rule/tls/middlewares/priority); nginx prepends the comment marker
  (preserves the block body). NetBird has no marker → not an Adopter.
- `core.Import` / `DetectImport` / `ImportPlan` (adopt / conflicts /
  already-managed). Matching = host + **origin match** (live backend == the
  driver's resolved origin). Mismatch → conflict (not adopted). Out-of-domain
  (Authelia, wildcard subroutes for a non-origin service) → never shown/touched.
  DNS has no ownership marker → adopted by recognition (no mutation; documented).
- cmd `import [--dry-run]` verb (preview → confirm/`--yes`; `--json`); usage row.
- Closes the **lifecycle gap**: a host that could not be cleanly `unexpose`d
  before adoption (delete-by-marker no-ops, read-back fails) unexposes cleanly
  after. Proven in `core/import_test.go` (brownfield across Caddy+Traefik+nginx:
  adopt 3, Authelia untouched, origin-mismatch conflict, idempotent, then clean
  unexpose). Driver tests assert verbatim preservation (Caddy `terminal`/headers,
  Traefik middlewares/tls, nginx custom directive) + idempotency. Fake gained
  `PATCH /config/.../routes/<idx>`. `examples/seed-brownfield-caddy.json` +
  `settings-brownfield.json` (wildcard subroutes + Authelia + adoptable grafana).
  Dependency-rule test green. `go build/vet/test -race` all green.

### UB2 — `crenel apply <file>`: declarative exposures (+ JSON/YAML config)

kubectl-style declarative apply that coexists with the imperative verbs. Diffs a
file's desired exposures vs LIVE, previews, and converges all-or-nothing — a
point-in-time assertion, NOT a watched mirror (no stored SOT).

- `internal/config/yaml` — a minimal, schema-bounded YAML-subset decoder (block
  maps/seqs, nested indent, `#` comments, quoted scalars, flow lists). Parses to
  the SAME generic tree as encoding/json, then JSON-roundtrips into the target so
  struct mapping reuses the existing `json:` tags. Keeps the build zero-dependency.
  `config.DecodeFile` selects JSON/YAML by extension then content sniff; `Load`
  uses it, so every settings file may now be YAML. Tested (nested shapes, URL
  colons not mis-split, quoted-stays-string, same-indent seqs, tabs rejected).
- `core.ApplyDeclarative` / `PlanDeclarative` / `Exposure` / `DeclarativeOptions`:
  per exposure, per target edge, classify already-satisfied / adoptable / blocked
  / needs-route; aggregate DNS adds; `--prune` removes OWNED hosts absent from the
  file (never unmanaged). Reuses the exact `buildSteps` → rollback → read-back
  transaction as Apply/Reconcile (ascending/Expose order). Blocked hosts (present-
  unmanaged without `--adopt`, or origin mismatch) abort BEFORE any mutation;
  `--adopt` adopts matching unmanaged hosts inline (no duplication).
- cmd `apply <file> [--adopt|--prune|--dry-run]`; `printChangeSet` split into
  header + reusable `printChangeBody`; usage row. `examples/exposures.yaml` +
  `settings-apply.yaml` (proves YAML config + YAML exposures end-to-end).
- Tests: additive expose + idempotency + NewPublic; blocks-unmanaged-without-adopt
  then adopts-inline-no-duplicate; `--prune` removes owned but spares unmanaged;
  origin-mismatch blocks even with `--adopt`. `go build/vet/test -race` all green.

### UB3 — Caddy on-disk persistence: close the admin-API durability gap

The Caddy admin API mutates the IN-MEMORY config; a `docker restart` reloads the
on-disk Caddyfile and drops crenel routes (proven live). Opt-in persistence mirrors
the managed routes onto disk so they survive — and reconcile can't help here (it's
live-derived; after a wipe there's nothing to recover from), so durability comes
from THIS or from re-running `apply`.

- `ports.Persister` (`Persist(ctx)`), implemented by the Caddy driver when a
  persist path is set. core calls `persistEdges` on participating edges AFTER a
  verified apply, in Apply / Reconcile / ApplyDeclarative. Best-effort: a failure
  is a `PersistWarnings` entry on the report, NEVER a rollback (the running state
  is already correct + verified; only durability is in question).
- `caddy.WithPersistPath` + injected `CaddyCLI` seam (validate/reload). `Persist`
  reads live, filters crenel-MANAGED http-proxy routes, merges them into the
  sentinel-delimited region of the on-disk Caddyfile (`# crenel-managed-begin/end`)
  preserving everything outside byte-for-byte, writes a candidate, `caddy validate`s
  it, atomically replaces the live file ONLY on success, then reloads ONCE
  (debounced) via `caddy reload --config <path>` — the correct, non-wedging
  invocation diagnosed on the live edge (never bare `caddy reload`).
- Seams: `OSCaddyCLI` (real binary), `LogCaddyCLI` (no-exec demo: skips validate,
  logs the reload it would run) — wired automatically for a fake-seeded edge so the
  injection is demoable with no infra. cmd: `caddy_persist_path` setting (top-level
  + per-edge) + `-caddy-persist` flag; persist warnings surfaced in apply/reconcile/
  apply-declarative output.
- Tests: driver (additive injection preserves operator config + omits unmanaged
  routes; validate-before-replace; one reload; idempotent region; invalid candidate
  never touches the live file or reloads) + core integration (apply persists after
  verify; a persist failure is a warning, not a rollback, route stays live).
  `examples/Caddyfile.base` + `settings-caddy-persist.json`; demoed end-to-end via
  the CLI. `go build/vet/test -race` all green.

### UB4 — installability: init scaffold, quickstart, cross-compile, release

Made Crenel installable and bootstrappable on a fresh machine / his VPS.

- `crenel init [dir]`: scaffolds `crenel.settings.yaml` (annotated providers/
  topology, origins, optional persist + split-horizon DNS) + `crenel.exposures.yaml`
  (declarative apply starter), refusing to overwrite; prints the brownfield next
  steps (init → status → import → drift → expose/apply). `crenel version` (build
  version injected via `-ldflags -X main.version`).
- README: an Install section (`go install`, `make install/build/release`) and a
  brownfield Quickstart (adopt → drive imperatively or declaratively), plus a
  no-infra trial using the bundled fakes. Points at USABILITY-DESIGN.md.
- Cross-compile verified for **linux/arm64** (static, zero-dep ELF aarch64) +
  amd64/darwin. `Makefile`: `build`/`install`/`check` (the green-bar gate)/`test`/
  `release` (cross-compiles the 4-platform matrix into `./dist`, **does not
  publish**). `.gitignore` gains `/dist/`.
- Tests: cmd-level `init` (writes + decodes + refuses overwrite), `import --dry-run`
  (lists adoptable grafana, non-zero exit), `apply --dry-run` (YAML exposures →
  about-to-go-public preview). `go build/vet/test -race` all green.

## BRAND — visual identity + the status HUD as the REAL status surface

Gave Crenel a tech-noir terminal identity and made it FUNCTIONAL: the diagnostic
HUD is now the real `crenel status` output, wired to live state, not a mock. New
presentation-layer package `internal/ui` (pure/deterministic; depends only on view
types — never imported by core). Fakes/fixtures only.

- **Crenellated CRENEL wordmark** — a brutalist 5x5 block font whose TOP EDGE is a
  battlement (merlons on a parapet with crenel gaps), so the logo literally is the
  default-deny "solid wall with deliberate gaps". One grid (`WordmarkRows`) feeds
  both the ANSI renderer and the SVG generator → they can't drift.
- **Semantic color (not vibe)** — green = safe/private/verified, amber = about-to-
  go-public / drift, red = fail-open / unexpectedly exposed. `Sem` roles map to
  ANSI truecolor; the same rule drives the SVG. Color emitted only when enabled
  (plain/NO_COLOR/non-TTY returns text unchanged).
- **The killer one — `crenel status` HUD wired to real domain fields:** EXPOSED
  (n hosts, m public — publicness mirrors `core.computeNewPublic`), DEFAULT-DENY
  (ENFORCED/FAIL-OPEN from `DenyCatchAllPresent` on every edge), DRIFT (from
  `DetectDrift` vs the canonical exposed set), EDGES (configured `name·driver`),
  DNS (split-horizon scopes), LAST APPLY (`unknown` — no persisted desired state).
  Compact colored header by default on a TTY; full banner on `status --hud`/
  `--banner`; `--plain`/pipe/`--json` stay scriptable; honors NO_COLOR + non-TTY.
  No-arg `crenel` shows a branded landing.
- **SVG assets** — `docs/brand/crenel-wordmark.svg` + `docs/brand/crenel-status-hud.svg`
  (the early read-only-dashboard mock / S5 drawn ahead), generated from the SAME
  renderers (`CRENEL_GEN_ASSETS=1 go test ./internal/ui/ -run TestGenerateAssets`).
- **Docs** — `BRANDING.md` (palette + semantic rule + wordmark + HUD); README now
  leads with the wordmark + a sample HUD; DESIGN gains a "Visual identity & status
  surface" note.
- Tests: `internal/ui` (wordmark width/crenellation, color gating, plain fallback,
  semantic-color meaning, panel alignment, SVG field/color presence) + cmd (HUD
  banner wired to real data, piped suppression, color gating, `--plain`, landing).
  Demoed end-to-end on the multi-edge Traefik fixture (4 hosts, drift none, the
  unmanaged Authelia vhost preserved). `go build/vet/test -race` all green (11 test
  packages).

## M13 — DRIFT verb — reconcile's read-only detect half (CI/cron drift check)

Added a read-only `drift` verb: the detection half of `reconcile` surfaced on its
own, with a CI/cron-friendly non-zero exit when drift exists. Rounds out the verb
spectrum — status (what is) / audit (is it safe+consistent) / drift (does it match
the canonical set) / reconcile (make it match). Fakes only.

- `core.DetectDrift(ctx)` returns the `ReconcilePlan` (drift list + corrective
  change) via the shared `planReconcile` — no mutation.
- cmd: `drift` verb prints the divergence (reuses the reconcile-plan renderer; also
  `-json`) and returns an error (exit 1) when any drift exists, so `crenel drift ||
  alert` works. Clean world → exit 0.
- Tests: `TestDetectDrift_ReadOnly` (detects the missing-route drift, asserts NOTHING
  was mutated, then reports clean after a reconcile). DESIGN verb table row.
  Demoed end-to-end. `go build/vet/test -race` all green (10 test packages).

## M12 — nginx FOURTH edge driver — breadth-validating the vendor-agnostic claim

Added a **fourth `EdgeProvider`** — an **nginx config-file** driver — to further
validate the port's breadth. After Caddy (admin API), Traefik (JSON file), and
NetBird (identity mesh), nginx is another dumb data-plane edge but a third config
SHAPE: the nginx brace DSL, with COMMENT-MARKER ownership (`# crenel-managed:`)
rather than @id or key-prefix. Fakes only (a temp file).

- `internal/drivers/edge/nginx`: ReadLiveState/Validate/Plan/Apply over an nginx
  config file. codec.go splits the file into top-level chunks (brace-depth
  tokenizer), classifies each as a crenel-managed server block / the crenel-deny
  block / unmanaged text, and renders crenel's own blocks. Apply is an ADDITIVE
  read-modify-write: unmanaged `server`/`upstream` blocks preserved VERBATIM, only
  crenel's marker-tagged blocks regenerated, structural default-deny always rendered
  (a `default_server` returning 444). Expresses ModeHTTPProxy; refuses passthrough
  (would need stream/ssl_preread) + mesh loudly.
- No admin endpoint to wedge, so — like Traefik — it does NOT implement
  ports.HealthChecker (re-confirming that capability is optional).
- Wired at cmd via `edge_driver: "nginx"` + `nginx_config_path` (top-level +
  per-edge). `examples/settings-nginx.json` + `seed-nginx.conf`.
- Tests: `nginx_test.go` (additive expose preserves an unmanaged Authelia vhost +
  hand-written upstream; fail-open detection; mode refusal; empty-config deny) +
  `core/nginx_edge_test.go` (core drives it unchanged + it participates in a
  heterogeneous reconcile with per-edge address resolution). Demoed end-to-end.
  Dependency-rule test green (core/model never import nginx). STRAIN.md verdict +
  DESIGN.md driver section. `go build/vet/test -race` all green (10 test packages).

## M11 — CADDY layer4 PASSTHROUGH renderer — SNI passthrough on BOTH edges

Made `ModeTCPPassthrough` a REAL renderer on the Caddy driver via Caddy's
`layer4` app (github.com/mholt/caddy-l4) — so SNI passthrough now works on BOTH
data-plane edges (Traefik since M9, Caddy now). Capability-gated; refuses loudly
when the plugin isn't present. Fakes only.

- caddy: `WithLayer4()` / `caddy_layer4` declares the caddy-l4 plugin is built in.
  When set (AND granular), a passthrough expose inserts an @id-tagged SNI-matched
  `proxy` route into a managed `crenel-l4` layer4 server (match `tls.sni`, raw-TCP
  proxy, NO TLS termination) — ADDITIVELY (only crenel-l4 @ids; the http routes /
  deny / TLS are never read or rewritten). `normalize` reads layer4 routes back as
  `ModeTCPPassthrough`; unexpose removes them. Removal is idempotent across BOTH
  trees (404-tolerant DELETE by @id).
- LOUD refusal: without `WithLayer4`, Plan refuses passthrough (`ErrModeUnsupported`,
  pointing at caddy-l4); with layer4 but NOT granular, it refuses (additive write
  needs granular). Mesh-grant still refused. So the same typed intent renders where
  expressible (Traefik tcp.routers, Caddy layer4) and refuses where not.
- core: `computeNewPublic` now flags passthrough exposures as "about to go public"
  too (only mesh-grant — identity-scoped — is excluded), aligning M9+M11.
- fake: generalized the structured admin API — PUT
  `/config/apps/<app>/servers/<srv>/routes/<idx>` (creates the layer4 app/server on
  demand) and `@id` search/delete across both the http and layer4 apps.
- CLI: `-layer4` flag + `caddy_layer4` setting (+ per-edge). `examples/settings-caddy-layer4.json`.
- Tests: `caddy/layer4_test.go` (passthrough Plan/Apply round-trip, additivity of
  the http route + deny, refuse-without-capability, requires-granular, still-refuses-
  mesh) + `core/caddy_layer4_test.go` (engine drives passthrough end-to-end +
  NewPublic). Demoed end-to-end. STRAIN §2 + DESIGN Mode table updated.
  `go build/vet/test -race` all green (9 test packages).

## M10 — RECONCILE verb — detect + fix ALL drift; converge the whole topology

Added the operator-grade `reconcile` verb: the third point on the
mutation spectrum after `resume` (finish ONE interrupted op) and `audit` (only
report). Reconcile makes EVERY edge + DNS provider agree with the canonical
currently-exposed set — derived FROM live, no stored desired state. Fakes only.

- **Canonical set = union of MANAGED exposed hosts across edges**; per host, the
  canonical mode is its mode on the FIRST (primary) edge that exposes it. Each host
  should be exposed, in that mode, on every edge that fronts its service, with its
  DNS records present.
- **Fixes:** missing managed route on a fronting edge (re-add, per-edge address via
  that edge's own resolver) · mode mismatch (re-render in the canonical mode;
  Remove+Add same host — drivers now apply removes BEFORE adds so the canonical
  render wins) · missing managed DNS record (add) · stale managed DNS record for a
  host exposed nowhere (remove). All via the SAME all-or-nothing transaction +
  read-back-verify + wedge-safe rollback as Apply (`buildSteps` reused).
- **Managed boundary (safety):** only hosts whose service some edge fronts enter the
  canonical set — UNMANAGED routes/records (Authelia, other vendors, hand-made
  records) are never read in, so never added/removed/re-rendered. Reconcile also
  never deletes an edge route outright (adds + mode re-renders only). A driver that
  can't express the canonical mode (Caddy + passthrough) makes reconcile fail LOUDLY.
- **Drift reconcile FIXES vs audit only FLAGS** documented precisely in DESIGN.md
  (fail-open, SNI mismatch, public-DNS-for-mesh-grant, DNS value drift = flag-only).
- CLI `reconcile` (preview drift + corrective change → confirm / `--yes`; `-json`).
  Refactored the rollback/wedge fields into a shared `txnOutcome` embedded by both
  `ApplyReport` and `ReconcileReport`.
- Tests (`reconcile_test.go`): a multi-edge world drifted four ways at once
  (missing route + mode mismatch + missing DNS×2 + stale DNS) converges and is
  idempotent on a second run; a clean world is a no-op; a mid-apply failure rolls
  the whole transaction back; an unmanaged route is never touched/propagated.
  Demoed end-to-end on the two-Traefik multi-edge config. `go build/vet/test -race`
  all green (9 test packages).

## M9 — TCP/SNI PASSTHROUGH renderer on Traefik (completes the Mode story)

Turned `ModeTCPPassthrough` from a representable-but-unrendered intent into a REAL
renderer on the Traefik driver — the SNI passthrough that STRAIN.md §2 flagged as
inexpressible now works on a real edge. Fakes only.

- traefik: a passthrough expose writes a `tcp.routers` entry (`HostSNI(host)` +
  `tls.passthrough: true`) + a TCP service (host:port `address`), ADDITIVELY
  (only `crenel-tcp-*` keys; HTTP routers + the deny preserved). `normalize` reads
  TCP routers back as `ModeTCPPassthrough` routes; unexpose removes them.
- Plan now accepts `ModeHTTPProxy` + `ModeTCPPassthrough`, refuses mesh-grant.
  Caddy still refuses passthrough loudly (would need the layer4 plugin) — same
  intent honoured where renderable, refused where not.
- Tests: Traefik passthrough Plan/Apply round-trip (renders HostSNI+passthrough,
  reads back as a passthrough route, unexpose removes it, unmanaged HTTP + deny
  survive); Traefik mode-refusal narrowed to mesh-grant. Demoed end-to-end
  (`expose --mode passthrough` verifies; status shows `[tcp_passthrough]`).
- STRAIN.md §2 + DESIGN.md Mode table updated. `go build/vet/test -race` green.

## M8 — RICHER AUDIT — TLS/SNI + mode-enabled cross-provider checks

Sharpened `audit` with three new live-only checks, two of them enabled by the M6
route Mode. Fakes only.

- **sni_host_mismatch** (warning): an HTTP-proxy route whose edge-served
  SNI/cert `ServerName` differs from the route host — a TLS name mismatch.
- **edge_mode_mismatch** (warning): a host exposed with CONFLICTING modes across
  edges (e.g. HTTP-proxy on one, mesh-grant on another) — inconsistent exposure
  semantics.
- **public_dns_for_mesh_grant** (warning): a PUBLIC DNS record naming a
  mesh-grant (identity-scoped, private) host — resolves globally but only mesh
  peers can reach it; a misleading intent leak.
- Audit now collects per-host modes + SNI while reading each edge once; output
  stays deterministic. Tests: a fixed-live-state `stubEdge` double crafts the
  precise mode/SNI inputs for each new finding. `go build/vet/test -race` green
  (9 test packages). DESIGN.md audit row updated.

## M7 — RESUME verb — re-drive an interrupted apply from live state

Added a `resume <expose|unexpose> <svc>` verb. Because Crenel keeps NO stored
desired state, "resume" = read live across every edge + DNS, recompute the
REMAINING delta toward the op's intent, diagnose which providers are already done,
and complete the rest with the SAME all-or-nothing transaction (so a failure
mid-completion rolls back cleanly). This works precisely because every provider's
Plan is a delta-against-live, so a half-applied double-write yields an empty change
for the done edge and a real change for the pending one. Fakes only.

- `core.Resume` (new `resume.go`): plans, diagnoses each provider as Already/Pending
  from the per-provider change, and — if anything is pending — completes it via the
  shared `applyPlanned` (Apply was refactored to expose it, so resume reuses the
  exact transactional + read-back-verify + rollback machinery). `ResumeReport`
  carries the diagnosis + the completion `ApplyReport`.
- cmd: `resume` verb prints the diagnosis ("already in intended state: …",
  "completing: …") then the apply report; honors `--mode`/`--param`/`--yes`.
- Tests: completes an interrupted heterogeneous double-write (home done, vps
  pending → both consistent); a fully-consistent world is a clean no-op; a failed
  completion (DNS push fails) rolls back the resume's OWN attempt (pending vps
  reverted) while the already-done home stays intact. Demoed end-to-end.
- `go build/vet/test -race` all green (9 test packages).

## M6 — TYPED ROUTE MODE — expressible intent + loud refusal (STRAIN §2 built)

Added a typed **`model.RouteMode`** (on `Upstream` + `Op`) so transport/exposure
intent is explicit and drivers can express what they can and **refuse the rest
loudly** instead of approximating. Closes STRAIN.md §2 (TLS/SNI passthrough was
inexpressible) and lets the NetBird mesh do its NATIVE thing instead of only
erroring. Fakes only; no live infra.

- **Modes:** `ModeHTTPProxy` (default), `ModeTCPPassthrough`, `ModeMeshGrant`;
  shared `model.ErrModeUnsupported` (classifiable via errors.Is). `Op.Params`
  carries mode-specific intent (e.g. mesh `group`).
- **Caddy / Traefik:** express `ModeHTTPProxy`; refuse passthrough + mesh-grant
  loudly (Traefik notes it doesn't yet render `tcp.routers`). 
- **NetBird:** now expresses its NATIVE `ModeMeshGrant` with a REAL Plan+Apply
  (writes/removes a WireGuard ACL grant in its store); refuses HTTP-proxy /
  passthrough with an actionable `--mode mesh --param group=…` hint. The mesh is no
  longer read-only.
- **CLI:** `--mode http|passthrough|mesh` + repeatable `--param key=value`; preview
  and status show a `[mode]` tag for non-default routes. A mesh-grant (identity-
  scoped) exposure is never counted as "about to go public".
- **Tests:** per-driver mode-refusal (caddy/traefik error on non-HTTP modes,
  classified) + NetBird mesh-grant Plan/Apply round-trip + missing-group error.
  STRAIN.md §2 recommended→built; DESIGN.md gains the Mode table. `go
  build/vet/test -race` all green (9 test packages). Demoed end-to-end.

## M5 (capstone) — NetBird mesh edge: the port's LIMITS handled by a LOUD refusal

Added a **third EdgeProvider** — a **NetBird identity-mesh** driver — to validate
the EdgeProvider port's *limits*, not just its reach. M2 (Traefik) proved the port
HOLDS for a second dumb data-plane edge; this proves a genuinely different
(integrated mesh) edge is handled by **erroring loudly on intents it can't
express**, exactly as DESIGN.md/STRAIN.md predicted — no leaky approximation.

- A mesh collapses transport + identity + authz + SNI: exposure is a WireGuard ACL
  grant to a peer/group, NOT a host→backend HTTP route with edge TLS termination.
- **READ works, honestly:** a mesh is default-deny by construction
  (`DenyCatchAllPresent` always true); grants surface read-only with a deliberately
  non-HTTP `mesh-grant:<group>` pseudo-address so the collapse is VISIBLE in
  `status`/`audit`/`export`.
- **MUTATE refuses LOUDLY:** `Plan` returns `ErrIntentUnsupported` with a message
  explaining the mismatch and pointing at the typed-route-Mode fix (STRAIN.md §2);
  `core` surfaces it so `preview`/`expose`/`unexpose` fail loudly while read verbs
  keep working. Demoed end-to-end (`examples/settings-netbird.json`).
- Tests: `netbird_test.go` (default-deny read + loud classified Plan refusal) and
  `core.TestCore_NetbirdEdgeReadsButRefusesMutation` (status works, expose errors
  through the engine). Wired at cmd via `driver: "netbird"`. core/model still import
  no driver; dependency-rule green. `go build/vet/test -race` all green (9 test
  packages).

## M4 — MULTI-EDGE (2026-06-27, resumed) — home + VPS double-write; the #1 feature

Turned the single edge into an **N-edge topology** — the home+VPS "double-write"
the original operator brief asked about. A single-edge config is now the degenerate N=1 case
and behaves identically (all prior tests unchanged). All against fakes; no live
infra. **See DESIGN.md §"Multi-edge topology" for the model + transaction
semantics.**

**Model.** `Engine.Edges []EdgeBinding` (`{Name, Provider, Fronts}`); `New` builds
a one-edge topology (back-compat), `NewMulti` takes several. `ChangeSet.Edges
[]EdgePlan` carries one projected `EdgeChange` per participating edge alongside the
driver-level single `Edge` (a driver stays multi-edge-unaware).

**Projection.** An edge declares which services it fronts (its origins double as
the projection set). `core.Plan` fans out: a host lands on an edge iff that edge
fronts the service; the per-edge `OriginResolver` gives the per-edge address (home
→ LAN IP, VPS → Tailscale). A service fronted by several edges double-writes; an
`expose` no edge fronts errors.

**Cross-edge transaction (all-or-nothing).** `core.Apply` orders ALL edges at the
edge rank (M3 exposure ordering preserved: every edge before public-DNS on expose,
after on unexpose), applies + read-back-verifies each edge independently, and on
ANY failure rolls back every applied edge + DNS in reverse. **Wedge safety is now
per-edge**: each edge's health is probed before its compensating reload; a wedged
edge is skipped (with a recovery hint) while the others still unwind.

**status / audit / export** are per-edge; audit adds a CROSS-EDGE consistency
check (host on one edge but missing from another that also fronts it = warning),
checks the deny invariant on every edge, and treats a host exposed on ANY edge as
DNS-backed.

**Heterogeneous proof:** `multiedge_test.go` wires a **Caddy home + Traefik VPS**
topology and tests projection, double-write+verify-both, cross-edge all-or-nothing
rollback (one edge fails → the other reverts), and cross-edge audit. `cmd` gains an
`edges:` config list (`examples/settings-multiedge.json`); demoed end-to-end.
core/model still import no driver. `go build/vet/test -race` all green (8 test
packages).

Caveat noted in the example: the in-process **fake Caddy admin API is per-process**
(resets each invocation), so a fake-Caddy edge can't show cross-command
persistence; the demo config uses two Traefik file edges (which persist on disk),
and the heterogeneous Caddy+Traefik double-write is proven within-process by tests.

## M2 — DE-RISKING SECOND EDGE DRIVER (2026-06-27, resumed) — Traefik file provider; the port holds

Added a **second `EdgeProvider`** — a **Traefik file-provider** driver — to prove
the abstraction isn't Caddy-shaped. A port with one implementation is fake
agnosticism; this is the proof it's real. All against fakes (a temp dynamic-config
file); no live infra touched. **See STRAIN.md** for the full honest accounting.

**Verdict: the port HOLDS with no interface change for a dumb data-plane edge.**
`core` (unchanged) drives Traefik end-to-end — plan → apply → read-back-verify →
structural default-deny — exactly as it drives Caddy
(`core.TestCore_DrivesTraefikEdge`, incl. cross-provider public-DNS ordering over
the second edge).

**What the driver does (and why it stresses the port differently):**
- Traefik's file provider has **no admin API**: the dynamic-config FILE is the
  config. The driver does an **additive read-modify-write** of that file, touching
  ONLY `crenel-*` routers/services — so unmanaged routers (Authelia + its
  middleware/TLS, dashboards, other vendors) survive untouched. Same additivity
  property as Caddy's granular apply, proven via a totally different transport
  (`TestApply_AdditiveExposePreservesUnmanaged`).
- **Structural default-deny generalised:** Traefik denies unmatched hosts with an
  implicit 404 (like Caddy); `DenyCatchAllPresent` is false only when a router
  forwards ALL hosts to a real backend (permissive catch-all). Apply always renders
  an explicit `crenel-deny` catch-all router (no upstream ⇒ 503).
- **`HealthChecker` correctly OPTIONAL:** a file provider can't wedge an admin
  endpoint, so the driver doesn't implement it; core handles its absence. The
  second driver *validated* the optional-capability design.
- Wired at `cmd` only (`edge_driver: "traefik"` + `traefik_config_path`);
  `examples/settings-traefik.json` + `seed-traefik.json` demo it. Dependency-rule
  test still green (core/model never import a driver).

**Where it STRAINS (documented in STRAIN.md, not papered over):**
1. **Live-state is muddier for a declarative-file edge** — the file is *desired*,
   not *running*; a faithful driver would also read Traefik's `/api/http/routers`
   to read-back-verify (the Caddy admin API gives this for free).
2. **`model.Upstream` can't express TLS/SNI passthrough** — Traefik passthrough is
   a different config tree (`tcp.routers` + `HostSNI` + `tls.passthrough`); the flat
   `Route{Host,Upstream}` has no layer/mode. Latent in the Caddy driver too;
   recommended fix: a typed route `Mode` and drivers that can't honour a mode error
   loudly.
3. **No auth/middleware composition** — Crenel can preserve middleware chains but
   not compose "expose behind Authelia".
4. **Format** — real Traefik uses YAML/TOML; this driver uses JSON to stay
   zero-dependency, isolated to `codec.go` for a one-spot YAML swap.

**Port change made (surfaced by the second driver):** `NewPublic` moved OUT of the
edge drivers INTO `core` — publicness depends on DNS scope, which an edge can't
know, and a second driver shouldn't duplicate that logic. (Already landed in M3.)

**Predicted (not built):** an integrated **mesh** edge (NetBird / Tailscale serve)
would collapse transport+identity+auth+SNI and should **error loudly** on
inexpressible intents (TLS passthrough, host→addr reverse proxy) rather than fake a
mapping — the port supports erroring; the discipline is to use it. STRAIN.md §"mesh".

## CONSOLIDATE + M3 (2026-06-27, resumed) — hardening is the baseline; public DNS + unified cross-provider plan

**Consolidation.** Fast-forwarded `m0` up to the `fix/apply-hardening` tip
(73dcbfe) and cut **`develop`** off it as the new mainline baseline — all future
work builds on the bounded-timeout / wedge-safe-rollback hardening. `m0`,
`fix/apply-hardening`, and `develop` all point at the same consolidated commit;
`develop` is where M3/M2 land. `go build ./... && go vet ./... && go test -race
./...` green before and after. (`.serena/` added to `.gitignore`.)

**M3 — public DNS scope + unified cross-provider plan/apply (done).** Crenel now
manages internal (AdGuard `!inside`) AND public (Cloudflare `!outside`) DNS at
once, aggregating EDGE + INTERNAL-DNS + PUBLIC-DNS into ONE ChangeSet — the hero
"what's about to go public" view — with the design's apply ORDERING rules and
per-provider read-back-verify. Still 100% against fakes; no live infra touched.
- **Multi-provider DNS wiring:** `config.DNSSettings.Providers []DNSProviderSettings`
  (one entry per scope); `buildDNS` builds a list (back-compat single-provider
  path preserved). New `examples/settings-dns-split.json` wires internal+public
  mock shells.
- **Apply ordering by exposure rank** (`edge 0 < internal-DNS 1 < public-DNS 2`):
  expose applies low→high (edge → internal → **public last**); unexpose applies
  high→low (**public first** → internal → edge). Minimises the window where a
  public name resolves to an edge that won't serve it. `core.buildSteps` builds +
  stably sorts the steps; rollback still reverses applied steps and stays
  wedge-safe.
- **NewPublic moved to core.** It's a cross-provider concern (publicness depends
  on DNS scope, which an edge can't know), so `core.Plan` computes it
  authoritatively: a host "goes public" when it gains a public-scope DNS record,
  or — when no public DNS is managed — when it gains an edge route (preserves the
  edge-only behaviour M0 shipped). Latent bug fixed along the way: `cs.DNS` is now
  kept positionally aligned 1:1 with `e.DNS` (was dropping empty changes, which
  could misalign provider↔change in a multi-provider apply).
- **Unified preview** renders a layered EDGE → INTERNAL DNS → PUBLIC DNS diff with
  the ⚠ ABOUT TO GO PUBLIC highlight; read-back lines are labelled by scope
  (`dnscontrol/internal`, `dnscontrol/public`).
- **Tests:** `core/ordering_test.go` proves expose order = `[edge, internal,
  public]` and unexpose = `[public, internal, edge]` (recording wrappers over the
  real fakes), the unified 3-provider plan aggregation, and the public NewPublic
  highlight. `rollback_test.go` reframed: an unexpose whose DNS teardown fails
  first leaves the edge route intact (ordering safety), nothing to roll back.

## POSTMORTEM + APPLY-HARDENING (2026-06-27, resumed) — root-caused the wedge; bounded every admin call

Resumed after the wedge incident. Wrote **POSTMORTEM.md** and shipped
**`fix/apply-hardening`** (off `m0`). Read-only live investigation; **no edge
mutation this session**.

**Root cause (evidence in `docker logs caddy-edge`):** every `/config/` write
triggers a FULL Caddy reload, and each reload calls `replaceLocalAdminServer`
(restart the admin endpoint). crenel fired `PUT` → several `GET` → `DELETE` in a
~75 ms burst — a reload storm. The DELETE-triggered reload's admin-server swap
could not drain its in-flight request and hit Caddy's **10 s graceful-shutdown
timeout** (logged verbatim: `stopping admin server: 10s timeout`), wedging the
admin endpoint ~90 s+. Aggravator (strongly supported upstream, timing-consistent,
not directly proven on this edge): the reload re-provisions the TLS app and
**synchronously flushes/reloads the cert cache** (caddy/#5589), which on this
**custom xcaddy v2.11.4 + `dns.providers.cloudflare v0.2.4`** Cloudflare-DNS-01
build is slow and can block (caddy/#7385). Data plane (443) never dropped.
`RestartCount=0`, `ExitCode=0` → no crash-loop; the self-restarts the operator sees are
most likely a healthcheck hitting the wedged admin API. **Key correction:**
granular ops are additive but **NOT lighter** than `POST /load` — each is a full
reload (confirmed by Caddy's own architecture docs).

**Hardening shipped (fix either way):**
- **Bounded, configurable timeouts on EVERY admin call** (read 10s / write 60s
  defaults; `admin_read_timeout_seconds` / `admin_write_timeout_seconds`,
  `caddy.WithTimeouts`). crenel can now NEVER hang on a wedged API — the exact
  failure that hung the prior session. Per-operation `context` deadlines, not one
  blunt client cap; timeouts are **classified** as `caddy.ErrAdminUnresponsive`
  with a `docker restart` recovery hint.
- **Settle between granular ops** — after each insert/delete, re-check admin
  health before the next mutation (no back-to-back reload storm) + post-apply
  health re-check on the full-load path too.
- **Wedge-safe rollback** — before running compensators, core probes the edge via
  the new optional `ports.HealthChecker`; if wedged, it **SKIPS the compensating
  edge reload** (which would only deepen the wedge) and reports
  `EdgeUnresponsive` + a `RecoveryHint` instead of piling on.
- **Tests:** new `caddyfake` cancellable stall (`WriteDelay`/`ReadDelay`) models a
  hung/slow admin API; `caddy/timeout_test.go` proves Apply/ReadLiveState/Healthy
  time out cleanly (bounded, classified, never hang) and that a slow-but-legit
  reload still succeeds; `core/wedge_test.go` proves rollback does NOT fire a
  reload into a wedged edge (`applyCalls==1`) and that core.Apply over the real
  driver + hanging fake returns bounded.

**Still open (the maintainer / edge-side, in POSTMORTEM §7):** capture a goroutine dump on
the next reproduced wedge to prove the TLS-reprovision block; check the container
healthcheck isn't probing 2019 with a short timeout; add TLS `resolvers`; prefer
infrequent disk-based reloads; upgrade past caddy PR #7597.

## LIVE-DEMO (2026-06-27, ~07:55 ET) — expose PASSED; unexpose wedged Caddy admin API

Ran the edge-only mutating demo on the VPS (loopback admin API, additive granular
apply, throwaway host `crenel-selftest.homelab.example`, DNS untouched). Model fix
deployed first; read-only `status`/`audit`/`preview` all read the real edge
correctly (Default-deny PRESENT, two wildcard subroutes, audit exit 0).

**What worked (expose):**
- `crenel --granular --yes expose crenel-selftest` → inserted ONE @id-tagged
  exact-host route at index 0. **Read-back-verify PASSED** ("crenel-selftest…
  is now reachable", "verified: live state matches intent").
- Safety check confirmed: 3 routes, BOTH wildcard subroutes intact, crenel @id
  present. `status` listed all three. The additive insert behaved exactly as the
  CI test predicted.

**What broke (unexpose):**
- `crenel --granular --yes unexpose crenel-selftest` → `DELETE /id/crenel-route-…`
  exceeded crenel's 10s HTTP client timeout (a real-edge reload re-provisions
  TLS/crowdsec and is far slower than the fake). crenel returned an error; the
  delete did NOT take effect.
- Worse: the admin API (127.0.0.1:2019) then went **unresponsive** (socket still
  LISTENING on the same pid, but no response for 90s+). The DELETE-triggered
  reload appears to have wedged the admin handler.

**Live state right now (all confirmed read-only):**
- **Production data plane HEALTHY** — `auth.homelab.example` via the edge → 200.
  caddy-edge container Up 12h, same pid, ports 80/443/2019 listening.
- **Admin control plane WEDGED** — `GET /config/` hangs (no response 90s+).
- **Dangling test route** — `crenel-selftest.homelab.example` → 502 (my route is
  still in the in-memory config, proxying to the closed 127.0.0.1:9999). Harmless
  (throwaway host) but NOT "as found."

**Why recovery is clean & deterministic (key facts):**
- caddy-edge starts with `caddy run --config /etc/caddy/Caddyfile --adapter
  caddyfile` (NOT `--resume`). On reload/restart it loads the **on-host Caddyfile**
  `/opt/caddy-edge/Caddyfile`, which is **pristine** (mtime 00:06, before the
  test). My admin PUT/DELETE only changed the in-memory config + `autosave.json`
  (mtime 11:52) — and autosave is **not** read on startup. So a reload/restart
  restores the exact original config AND clears the wedge.
- Restore-from-backup via `POST /load` is also available once the admin API is
  back (backup: `live-backup/caddy-config-20260627T115109Z.json`, on VPS + Mac).

**Recovery plan (awaiting the maintainer's go — production-affecting):**
1. Least-disruptive first: `docker kill --signal=SIGUSR1 caddy-edge` (graceful
   zero-downtime reload from the pristine Caddyfile). If the admin API recovers
   and `crenel-selftest` stops returning 502 → done.
2. If SIGUSR1 doesn't clear it: `docker restart caddy-edge` (~2–5s blip across all
   edge services; deterministic — reloads the pristine Caddyfile).
3. Then verify: admin `GET /config/` 200; `crenel-selftest` → no longer 502;
   `auth` still 200; and `GET /config/` == backup (semantic compare).

**Bug fixes this surfaced (to do before any retry):**
- crenel's admin HTTP client timeout (10s) is too low for real-edge reloads —
  needs to be configurable / much higher (e.g. 60–120s) for granular ops.
- A granular op that times out should NOT leave ambiguity — add post-op
  read-back to confirm whether the server applied it, and treat the dangling
  case explicitly (retry/verify) rather than just erroring.

## ARCHITECTURE Q — SINGLE EDGE (no double-write) as built today

**Definitive, from the code:** Crenel targets **ONE** edge — whichever single
Caddy admin API you point `admin_url` at. It does **NOT** double-write to both the
home Caddy (LXC 100, 10.0.0.13) and the VPS edge (100.100.0.2).

Evidence:
- `core.Engine` holds a single `Edge ports.EdgeProvider` (not a slice) —
  `internal/core/engine.go:15`.
- The composition root builds exactly one driver: `edge := caddy.New(adminURL,
  …)` — `cmd/crenel/wire.go:53`. There is no second edge constructed anywhere
  (grep for `[]ports.EdgeProvider` / `edges` / `double-write` → none).
- The apply path calls `e.Edge.Apply(ctx, cs)` **once** —
  `internal/core/apply.go:60`. (DNS *is* multi-provider — `DNS []ports.DNSProvider`
  — but the edge is singular.)

**What local+VPS double-write (multi-edge, the "M4 multi-target" work) would
take:**
1. `Engine.Edge ports.EdgeProvider` → `Edges []ports.EdgeProvider` (or a named
   map for targeting), plus a `Targets`/topology concept in `config.Settings`
   (e.g. `edges: [{name: home, admin_url: …}, {name: vps, admin_url: …}]`).
2. `Plan` fans out: compute a per-edge `ChangeSet` (origins/SNI may differ per
   edge — the home edge proxies to a LAN IP, the VPS proxies via Tailscale), and
   aggregate into a multi-edge plan for one preview.
3. `Apply` becomes an **all-or-nothing transaction across edges**: apply edge A,
   apply edge B, read-back-verify BOTH; if either fails, the existing
   compensating-rollback machinery (already generic over providers) rolls back
   *both*. The `compensator` list in `apply.go` already supports this shape —
   it'd just hold edge-A and edge-B undos.
4. `status`/`audit` report per-edge and add a **cross-edge consistency** check
   (a host exposed on the VPS but not at home, or vice-versa).
5. Reachability semantics: decide whether "exposed" means exposed on *all*
   target edges or *any*, and make default-deny hold per-edge.
The ports/rollback design already anticipates this; it's an additive change to
`core` + `config` + `cmd`, no driver rewrites. Estimated as the M4 milestone.

## DEPLOY-VPS (2026-06-27, ~07:15 ET) — read-only proof on PRODUCTION; NO mutation

Ran Crenel **on the VPS** against its loopback admin API (the safe path — admin
API never rebound or exposed). See `DEPLOY-VPS.md` for the full runbook.

**Reached the VPS:** yes — `ssh vps-edge` (Ubuntu 22.04.5, **aarch64**,
user `ubuntu`). Caddy admin `GET http://127.0.0.1:2019/config/` → **200** from the
VPS itself (confirming why it's unreachable from the Mac: loopback-bound).

**Built/deployed:** cross-compiled `GOOS=linux GOARCH=arm64` →
`bin/crenel-linux-arm64` (static), scp'd to `~/crenel-test/crenel` with
`config.json` (admin_url 127.0.0.1:2019, granular_apply, zone homelab.example,
crenel-selftest→127.0.0.1:9999).

**Backup (verified):** `~/crenel-test/live-backup/caddy-config-20260627T111446Z.json`
(4607 bytes, valid JSON, srv0 / 2 routes). Copied to the Mac repo at
`live-backup/caddy-config-20260627T111446Z.json` (gitignored — may hold secrets).
Restore command documented in `DEPLOY-VPS.md` (POST /load of that exact file);
NOT executed (a reload is a mutation — staged behind the maintainer's go).

**Read-only proof — crenel ran end-to-end against the live edge:**
- `status` → `Default-deny catch-all: MISSING ⚠ FAIL-OPEN`, `Exposed: (nothing)`.
- `preview expose crenel-selftest` → `+ expose crenel-selftest.homelab.example →
  127.0.0.1:9999`, `⚠ ABOUT TO GO PUBLIC`. (Pure plan, no apply.)
- `audit` → `✗ CRITICAL: catch-all default-deny is MISSING`, exit 1.

**⚠ KEY FINDING — Crenel's M0 edge model does NOT fit this production config.**
The real srv0 has just two routes: `*.smallbiz.example` and `*.homelab.example`,
each a **`subroute`** handler (nested per-host routing inside), plus separate
`crowdsec` and `tls` apps. There is **no** flat top-level `host{reverse_proxy}`
route and **no** explicit host-less `static_response` catch-all — unmatched hosts
get Caddy's implicit 404. Crenel only recognizes flat reverse_proxy routes + an
explicit static_response deny, so it **misreads** this edge: reports nothing
exposed and a false-positive "fail-open". This is why we STOP before mutating:
- A granular `expose` here would insert a flat route at index 0 (additive, would
  not harm the wildcard subroutes) — BUT crenel's read-back-verify calls
  `live.Reachable(host)` which requires `DenyCatchAllPresent`, currently `false`
  on this edge ⇒ verification would FAIL ⇒ auto-rollback removes the route. Net
  effect would be safe (self-cleaning) but the demo would "fail" on the model gap,
  not a real fault.
- **Fix needed before a meaningful mutating demo:** teach the Caddy normalizer to
  understand `subroute`-based configs and Caddy's implicit default-deny (treat
  "no catch-all static_response" + wildcard-subroute topology correctly), and/or
  make the default-deny model recognize 404-for-unmatched. Logged as next work.

**Edge left exactly as found:** only GETs were issued (backup + read-only verbs).
Re-fetched `GET /config/` and diffed against the backup → **byte-for-byte
identical (EDGE UNCHANGED)**. Nothing to restore. **Awaiting the maintainer's go** for the
mutating throwaway-host demo — and recommend fixing the subroute/default-deny
model first so verification passes honestly.

## LIVE-TEST (2026-06-27, ~04:05 ET) — OUTCOME: NO LIVE MUTATION; STAYED ON FAKES

The maintainer authorized optional live testing against the real Caddy edge + DNS under
strict guardrails (backup-first, additive throwaway host only, restored +
diff-verified by 5:30 ET, healthy edge beats a finished demo). **Decision: do NOT
mutate either plane. Stay on fakes.** Two independent blockers, EITHER sufficient
on its own. **The live edge was never touched** — the only live operations were
read-only reachability probes, both of which failed to connect (zero bytes sent
to any admin API; no SSH performed).

### Blocker 1 — the Caddy admin API is not reachable from this machine
- Per the wiki (`raw/homelab/2026-06-11-networking-architecture.md` +
  `…-port-reference.md`): Caddy is the **production public edge on the VPS**
  (`vps-edge`, Tailscale `100.100.0.2`, a cloud provider), fronting
  vault/auth/status/photos/etc. with Authelia forward_auth, Cloudflare DNS-01
  wildcard certs, and Traefik/Pangolin backends. The wiki documents **only**
  ports 80/443 for Caddy — **no** admin API (2019) endpoint anywhere. Default
  Caddy admin binding is loopback (`127.0.0.1:2019`) on the VPS.
- Read-only probe from this Mac (`100.100.0.4`):
  - `GET http://100.100.0.2:2019/config/` → `curl (7) Failed to connect … after 40 ms` (refused).
  - `nc -z 100.100.0.2 2019` → not reachable.
- Reaching it would require SSH to the VPS or rebinding the admin API to a
  non-loopback interface. Both are explicitly forbidden by the non-negotiable
  rules ("Do not SSH around hunting for it or expose the admin API to reach
  it"). → Precondition 3 fails: cannot reach it safely ⇒ stay on fakes.

### Blocker 2 — the M0 Caddy driver is NOT additive; it would wipe production
- `caddy.Driver.Apply` renders a **complete** managed Caddyfile from the
  driver's *lossy* normalization (it models only `host { reverse_proxy … }`
  routes + the catch-all deny) and pushes it via `POST /load`, which **replaces
  the entire running config**.
- Against the real edge that render would DROP everything the driver doesn't
  model: Authelia `forward_auth` snippets, Cloudflare DNS-01 TLS/cert config,
  global options, per-host middleware, all Traefik/Pangolin routes — i.e. it
  would take down vault/auth/photos/etc. This violates rule 4 ("additive only;
  never modify or delete existing production routes") and rule 7 ("if you cannot
  guarantee a clean restore … do NOT mutate"). A full-config backup would not
  make this *additive* — the operation itself is a destructive replace.
- **This is a real design finding, not just a test-night caveat.** Before Crenel
  can ever touch a rich real edge it needs **additive granular apply** via
  Caddy's structured admin API (`PUT/POST /config/apps/http/servers/<srv>/routes…`
  to insert/remove a single route) instead of `POST /load`. Logged as the next
  M1 task. Implemented + tested against the FAKE this session (see Increment 5)
  so a *future* live test could be additive — but NOT exercised against live.

### DNS plane — also skipped
- Edge is unreachable, so a full edge+DNS demo is impossible regardless. Public
  Cloudflare DNS has real blast radius; mutating it at ~04:00 ET inside a 90-min
  window, with provider credentials I'd have to source from production, is not a
  safe trade. No DNS backup was taken and no `dnscontrol push` was run. Stayed on
  the in-process fake DNS shell (`dns.mock`).

### Net state of live infrastructure
- **Untouched.** No mutation, no SSH, no config push on either plane. Nothing to
  restore. M0/M1 remain solid and green against the fakes (the real win for the
  night). A real live demo is gated on Blocker 1 (reachable admin API via an
  approved path) AND Blocker 2 (additive apply) — both must be resolved first.

---

## Current state / how to build & run / next steps

**State: M0–M13 landed on the `develop` baseline. All green** (`go build ./...`, `go
vet ./...`, `go test -race ./...` — 10 test packages). Baseline = the apply-hardening
(bounded admin timeouts, no reload storms, wedge-safe rollback). On top of it:
- **M13** — read-only **`drift`** verb: reconcile's detect half on its own, exits
  non-zero when drift exists (CI/cron). Verb spectrum is now status / audit / drift
  / reconcile.
- **M12** — **nginx** fourth edge driver (file-based dumb data-plane edge; nginx
  brace DSL with comment-marker ownership; additive read-modify-write preserving
  unmanaged vhosts; structural default-deny via `default_server` 444). core drives
  it unchanged; participates in multi-edge + reconcile. Breadth-validates the
  vendor-agnostic claim (4 edge drivers now: caddy/traefik/nginx/netbird).
- **M11** — Caddy **layer4 passthrough** renderer: `ModeTCPPassthrough` now renders
  on Caddy via the caddy-l4 `layer4` app (capability-gated `caddy_layer4`; additive;
  requires granular; refuses loudly without the plugin) — so SNI passthrough works
  on BOTH data-plane edges (Caddy + Traefik). `computeNewPublic` now counts
  passthrough as public.
- **M10** — `reconcile` verb: detect + fix ALL drift, converging every edge + DNS
  onto the canonical (live-derived) exposed set — re-add missing managed routes, fix
  mode mismatches, add/remove managed DNS records — via the same all-or-nothing
  transaction + read-back-verify + wedge-safe rollback. NEVER touches unmanaged
  routes. DESIGN.md documents the drift-reconcile-fixes vs audit-only-flags split.
- **M9** — real **TCP/SNI passthrough** renderer on Traefik (`tcp.routers` +
  `HostSNI` + `tls.passthrough`); Caddy still refuses it loudly. Completes the M6
  Mode story (STRAIN §2 passthrough now works on a real driver).
- **M8** — richer `audit`: TLS SNI/host mismatch, cross-edge mode mismatch, and
  public-DNS-for-a-mesh-grant (private) host — two enabled by the M6 route Mode.
- **M7** — `resume` verb: re-drive an interrupted apply from live (diagnose
  already-done vs pending providers, complete the remaining delta with the same
  all-or-nothing transaction, or roll back cleanly). No stored state.
- **M6** — typed route **Mode** (`ModeHTTPProxy`/`ModeTCPPassthrough`/`ModeMeshGrant`)
  on the route model + `Op`. Drivers express what they can and refuse the rest
  loudly (`model.ErrModeUnsupported`); NetBird now does its NATIVE mesh-grant. CLI
  `--mode`/`--param`. (STRAIN.md §2 built.)
- **M5** — third EdgeProvider: a **NetBird identity-mesh** driver that READS
  honestly (mesh = default-deny; grants visible read-only) but REFUSES mutations
  loudly (`ErrIntentUnsupported`) — validates the port's limits per STRAIN.md.
- **M4** — MULTI-EDGE topology (home + VPS double-write). `Engine.Edges
  []EdgeBinding` with per-edge projection (Fronts) + per-edge origins; `core.Plan`
  fans out one `EdgePlan` per participating edge; `core.Apply` is an all-or-nothing
  cross-edge+DNS transaction with per-edge read-back-verify and per-edge wedge-safe
  rollback. Per-edge + cross-edge status/audit. Heterogeneous Caddy+Traefik proven.
- **M3** — public DNS scope + unified cross-provider plan/apply. Internal (AdGuard
  `!inside`) + public (Cloudflare `!outside`) DNS managed together; one ChangeSet
  aggregates EDGE + INTERNAL-DNS + PUBLIC-DNS into the "about to go public" view;
  apply ORDERED by exposure rank (expose edge→public, unexpose public→edge) with
  per-provider read-back-verify. NewPublic computed in core.
- **M2** — second `EdgeProvider`: a **Traefik file-provider** driver (additive
  file read-modify-write, structural default-deny, no admin API). Proves the port
  holds for a non-Caddy edge; STRAIN.md documents where it strains.

**Live infra NOT mutated this session — everything is fakes/fixtures.** Read-only
(`status`/`preview`/`audit`/`export`) and mutating (`expose`/`unexpose`/`set`)
verbs work end-to-end over BOTH edge drivers; read-back verification catches the
silent-reload footgun.

**Build & run:**
```bash
cd ~/src/crenel
go build ./... && go test -race ./...
go build -o bin/crenel ./cmd/crenel

# Caddy edge against the bundled fake (no real infra):
./bin/crenel --fake-seed examples/seed-grafana.caddyfile status
./bin/crenel --fake-seed examples/seed-grafana.caddyfile preview expose photos
./bin/crenel --fake-seed examples/seed-grafana.caddyfile --yes expose photos
./bin/crenel --fake-seed examples/seed-failopen.json audit        # fail-open => exit 1

# M3 unified internal+public DNS (fake edge + fake dnscontrol):
./bin/crenel --config examples/settings-dns-split.json --fake-seed examples/seed-grafana.caddyfile preview expose photos
./bin/crenel --config examples/settings-dns-split.json --fake-seed examples/seed-grafana.caddyfile --yes expose photos

# M2 Traefik file-provider edge (writes a dynamic-config file):
mkdir -p /tmp/crenel-traefik-demo && cp examples/seed-traefik.json /tmp/crenel-traefik-demo/dynamic.json
./bin/crenel --config examples/settings-traefik.json status
./bin/crenel --config examples/settings-traefik.json --yes expose grafana

# M4 multi-edge home+VPS double-write (two persistent Traefik file edges):
mkdir -p /tmp/crenel-multiedge-demo
echo '{}' > /tmp/crenel-multiedge-demo/home-dynamic.json
echo '{}' > /tmp/crenel-multiedge-demo/vps-dynamic.json
./bin/crenel --config examples/settings-multiedge.json preview expose grafana   # double-write, two addresses
./bin/crenel --config examples/settings-multiedge.json --yes expose grafana     # lands on BOTH edges
./bin/crenel --config examples/settings-multiedge.json --yes expose photos      # home only (projection)
./bin/crenel --config examples/settings-multiedge.json status                   # per-edge

# M10 reconcile — converge drift back to the canonical exposed set:
echo '{}' > /tmp/crenel-multiedge-demo/vps-dynamic.json   # simulate drift: grafana lost on vps
./bin/crenel --config examples/settings-multiedge.json audit                    # flags inconsistency
./bin/crenel --config examples/settings-multiedge.json drift                    # read-only; exits 1 on drift (CI/cron)
echo n | ./bin/crenel --config examples/settings-multiedge.json reconcile       # preview the fix
./bin/crenel --config examples/settings-multiedge.json --yes reconcile          # re-adds grafana on vps
./bin/crenel --config examples/settings-multiedge.json --yes reconcile          # clean no-op (idempotent)

# M11 Caddy SNI passthrough via the layer4 app (capability-gated; refuses loudly):
./bin/crenel --fake-seed examples/seed-empty.caddyfile --granular --mode passthrough --yes expose vault   # REFUSED (no -layer4)
./bin/crenel --fake-seed examples/seed-empty.caddyfile --granular --layer4 --mode passthrough --yes expose vault   # renders + verifies
./bin/crenel --config examples/settings-caddy-layer4.json --mode passthrough preview expose vault          # [tcp_passthrough] + ABOUT TO GO PUBLIC

# M12 nginx fourth edge driver (additive; preserves unmanaged vhosts):
mkdir -p /tmp/crenel-nginx-demo && cp examples/seed-nginx.conf /tmp/crenel-nginx-demo/edge.conf
./bin/crenel --config examples/settings-nginx.json status                       # unmanaged auth vhost + deny
./bin/crenel --config examples/settings-nginx.json --yes expose grafana         # additive; auth vhost untouched

# M5 NetBird identity-mesh edge (read works; mutation refused loudly):
mkdir -p /tmp/crenel-netbird-demo && cp examples/seed-netbird-grants.json /tmp/crenel-netbird-demo/grants.json
./bin/crenel --config examples/settings-netbird.json status                     # grants visible read-only
./bin/crenel --config examples/settings-netbird.json --yes expose vault         # ERRORS loudly (exit 1)
```

**Next (candidate M13+):** nginx `stream`/`ssl_preread` SNI-passthrough (a 3rd
passthrough renderer, capability-gated like Caddy layer4); a `diff`/`drift` read-only
verb (reconcile preview as a first-class read verb with a non-zero exit when drift
exists — for CI/cron); a 5th driver (Cloudflare Tunnel / Tailscale serve, another
collapse-the-stack edge that refuses loudly); read-only exposure-status JSON polish.
Live edge-side diagnostics remain a separate, on-hold task.

---

## Increments (newest first)

### Increment 17 — M13: read-only drift verb
- core: `DetectDrift(ctx)` exposes `planReconcile` as a read-only detection.
- cmd: `drift` verb (prints divergence; `-json`; exits non-zero on drift). usage.
- tests: `TestDetectDrift_ReadOnly` (detects without mutating; clean after reconcile).
  DESIGN verb table row + BUILD_LOG demo.

### Increment 16 — M12: nginx fourth edge driver
- `internal/drivers/edge/nginx`: nginx.go (ReadLiveState/Validate/Plan/Apply,
  additive read-modify-write, structural default-deny, HTTP-only mode refusal) +
  codec.go (splitTopLevel brace tokenizer, classify chunks, renderConfig).
- cmd: `edge_driver: nginx` + `nginx_config_path` (top-level + per-edge) in wire.go;
  config NginxConfigPath. examples/settings-nginx.json + seed-nginx.conf.
- tests: nginx_test.go (additivity, fail-open, mode refusal, empty-config deny) +
  core/nginx_edge_test.go (core drives it + heterogeneous reconcile). STRAIN verdict
  + DESIGN section. Dependency-rule test still green.

### Increment 15 — M11: Caddy layer4 passthrough renderer
- caddy: `WithLayer4()` capability + `layer4` field; types.go layer4 app model
  (`Layer4App`/`Layer4Route`/match `tls.sni`/`proxy` handler) + `l4RouteID`;
  `normalize` appends layer4 routes as passthrough; Plan accepts passthrough only
  when layer4+granular (else refuses, classified); applyGranular routes passthrough
  adds to `insertLayer4Route` (PUT /config/apps/layer4/...) and removes from both
  trees via 404-tolerant `deleteByID`; targetRoutes skips passthrough.
- caddyfake: generalized PUT to `apps/<app>/servers/<srv>/routes/<idx>` (auto-create
  layer4 server) + `@id` search/delete across http+layer4 (`allServers`/`serverFor`).
- core: `computeNewPublic` counts passthrough (only mesh-grant excluded).
- config/cmd: `caddy_layer4` setting (+ per-edge) + `-layer4` flag; wire.go
  `WithLayer4`. `examples/settings-caddy-layer4.json`.
- tests: caddy/layer4_test.go (round-trip + additivity + 3 refusals) +
  core/caddy_layer4_test.go (engine round-trip + NewPublic). STRAIN §2 + DESIGN.

### Increment 14 — M10: reconcile verb (detect + fix all drift)
- `core/reconcile.go`: `Reconcile` (+ `planReconcile`/`verifyReconcile`/`canonicalRoute`):
  derives the canonical exposed set from live (union of MANAGED hosts; per-host
  canonical mode = primary edge), builds a corrective ChangeSet, runs it through the
  shared `buildSteps` transaction, read-back-verifies convergence, rolls back on
  failure. `Drift`/`DriftKind`, `ReconcilePlan`, `ReconcileReport`,
  `ReconcileConfirmFunc`/`AlwaysYesReconcile`.
- Extracted `txnOutcome` (rollback/wedge fields) shared by `ApplyReport` +
  `ReconcileReport`; `rollback`/`probeEdge` now take `*txnOutcome`.
- Drivers (traefik, caddy-granular) now apply RemoveHosts BEFORE AddRoutes so a
  mode re-render (Remove+Add same host) replaces cleanly.
- cmd: `reconcile` verb (drift+change preview → confirm/`--yes`; `-json`), usage.
- tests: `reconcile_test.go` (4-way drift converges + idempotent; clean no-op;
  failure rolls back; unmanaged route never touched). DESIGN.md reconcile section +
  drift-vs-audit table; verb table row.

### Increment 13 — M9: TCP/SNI passthrough renderer (Traefik)
- traefik types: tcp.routers/services; codec: HostSNI parser; normalize reads TCP
  passthrough routes; Apply renders `crenel-tcp-*` (HostSNI + tls.passthrough)
  additively; Plan accepts passthrough, refuses mesh-grant.
- tests: passthrough round-trip + narrowed mode-refusal. STRAIN §2 / DESIGN updated.

### Increment 12 — M8: richer audit (TLS/SNI + mode-enabled checks)
- audit gains sni_host_mismatch, edge_mode_mismatch, public_dns_for_mesh_grant;
  collects per-host modes + SNI in the single per-edge read pass.
- tests: a fixed-live `stubEdge` double crafts the mode/SNI inputs for each.
  DESIGN.md audit row updated.

### Increment 11 — M7: resume verb
- `core/resume.go`: `Resume` plans, diagnoses providers Already/Pending, completes
  pending via shared `applyPlanned` (Apply refactored to expose it). `ResumeReport`.
- cmd: `resume <expose|unexpose> <svc>` prints diagnosis + apply report.
- tests: completes interrupted double-write; consistent→no-op; failed completion
  rolls back its attempt, leaving the already-done edge intact. DESIGN verb table.

### Increment 10 — M6: typed route Mode
- model: `RouteMode` (+ `ModeHTTPProxy`/`ModeTCPPassthrough`/`ModeMeshGrant`) on
  `Upstream` + `Op`; `Op.Params`; shared `model.ErrModeUnsupported`.
- caddy/traefik Plan: accept HTTPProxy, error (wrapping ErrModeUnsupported) on
  other modes. netbird Plan/Apply: native mesh-grant (real grant add/remove via
  the store), error on non-mesh modes with an actionable hint.
- cmd: `-mode` + repeatable `-param key=value`; buildOp threads them; preview +
  status show a `[mode]` tag. computeNewPublic ignores mesh-grant (private).
- tests: caddy/traefik mode-refusal (classified), netbird mesh-grant round-trip +
  missing-group error. STRAIN.md §2 + DESIGN.md updated.

### Increment 9 — M5: NetBird mesh edge (third driver; validates the port's limits)
- `internal/drivers/edge/netbird`: ReadLiveState (mesh = default-deny always;
  grants surfaced read-only as `mesh-grant:<group>` so the transport/identity
  collapse is visible) + Plan/Apply returning `ErrIntentUnsupported` with a clear,
  classified message. Wired at cmd via `driver: "netbird"` + `netbird_grants_path`.
- Tests: `netbird_test.go` + `core.TestCore_NetbirdEdgeReadsButRefusesMutation`
  (read works through core; expose errors loudly). STRAIN.md §mesh updated from
  "predicted" to "built". Examples + end-to-end demo.

### Increment 8 — M4: multi-edge topology (home + VPS double-write)
- model: `ChangeSet.Edges []EdgePlan` (per-edge aggregation) alongside the
  driver-level single `Edge`; `Empty()` spans both.
- engine: `Engine.Edges []EdgeBinding` (`{Name, Provider, Fronts}`); `New` →
  one-edge topology (back-compat), `NewMulti` → several. `Plan` fans out across
  fronting edges (projection by per-edge origins); `computeNewPublic` over
  `cs.Edges`.
- apply: ordered steps span ALL edges (rankEdge) + DNS; all-or-nothing cross-edge
  transaction; per-edge pre-snapshots + inverses; rollback probes EACH edge's
  health and skips only the wedged edge's compensator; verify re-reads every
  participating edge.
- status/audit/export per-edge; audit cross-edge consistency + per-edge deny.
- cmd: `edges:` config list, per-edge resolver+Fronts; per-edge preview/status.
- tests: `multiedge_test.go` (Caddy+Traefik heterogeneous): projection,
  double-write+verify-both, all-or-nothing rollback, cross-edge audit. Existing
  single-edge tests updated to the per-edge StatusReport, behaviour unchanged.

### Increment 7 — M2: second edge driver (Traefik file provider)
- `internal/drivers/edge/traefik`: ReadLiveState/Validate/Plan/Apply over a
  dynamic-config FILE (additive read-modify-write of `crenel-*` keys only),
  structural default-deny (`crenel-deny` catch-all + implicit-404 model), no
  HealthChecker (proves the capability is optional). codec.go isolates JSON↔shape
  (zero-dep; YAML swap is one spot).
- Tests: additivity (unmanaged Authelia router survives), fail-open detection,
  empty-edge deny, and `core.TestCore_DrivesTraefikEdge` (core drives the second
  edge unchanged + cross-provider public-DNS ordering). Wired at cmd via
  `edge_driver: traefik`. STRAIN.md written.
- Finding: the port HOLDS with no interface change for a dumb data-plane edge; the
  one responsibility correction (NewPublic → core) was made in M3. Deeper gaps
  (TLS passthrough, auth composition, mesh edges) documented, not papered over.

### Increment 6 — M3: public DNS scope + unified cross-provider plan/apply
- Multi-provider DNS wiring (internal + public via `dns.providers`); core.Plan
  aggregates EDGE + INTERNAL-DNS + PUBLIC-DNS into one ChangeSet, cs.DNS kept
  positionally aligned 1:1 with providers (fixes a latent misalignment).
- Apply ordered by exposure rank (expose edge→internal→public; unexpose
  public→internal→edge) via `buildSteps`; per-provider read-back-verify; rollback
  still reverses applied steps and stays wedge-safe. NewPublic computed in core.
- Unified layered preview + scope-labelled read-back lines. Tests: ordering_test
  (both directions + 3-provider aggregation), rollback_test reframed for ordering
  safety. DESIGN.md documents the ordering rule.

### Increment 5 — M1: additive granular apply (the fix the live-test surfaced)
- Added `caddy.WithGranularApply()` / `--granular` / `granular_apply` setting:
  Apply switches from a full `POST /load` replace to ADDITIVE structured
  admin-API ops — insert each route at index 0 via
  `PUT /config/apps/http/servers/<srv>/routes/0` tagged `@id: crenel-route-<host>`,
  remove via `DELETE /id/crenel-route-<host>`.
- Fake gained the structured endpoints (PUT route insert at index, DELETE/GET by
  @id) so the behavior is testable without real Caddy.
- **Headline test** (`granular_test.go` + `testdata/rich-prod.json`): expose a
  throwaway host on a production-like edge (Authelia auth handler + two prod
  routes + deny). Asserts every unmanaged route survives byte-for-byte and only
  the Crenel route is added; unexpose removes only the Crenel route. This is the
  property whose ABSENCE was Blocker 2 for the live test.
- Demo: `crenel --config examples/settings-selftest.json --yes expose
  crenel-selftest` granularly exposes on the rich fixture and read-back-verifies.
- Still NOT run against live (Blocker 1: admin API unreachable from this Mac).
  But the tool is now *capable* of a safe additive live test once an approved
  reachable admin path exists.

### Increment 4 — M1: rollback/resume on partial apply
- Apply is now transactional. Each provider apply registers a compensating
  inverse action (built against a pre-apply edge snapshot). On any provider
  apply error OR failed read-back verification, the engine runs compensators in
  reverse to restore prior live state.
- `Engine.Rollback` (default true) gates it; `ApplyReport.RolledBack` /
  `RollbackErrors` surface the outcome; CLI prints "ROLLED BACK".
- invertEdge: add↔remove (prior upstream recovered from snapshot); invertDNS:
  swap add/remove.
- Tests: DNS-push failure reverts an edge expose; unexpose+DNS-fail re-adds the
  edge route; rollback-disabled leaves partial state. Existing silent-reload
  test still passes (verify fail → rollback attempted, error still returned).
- Decision: inverse-change compensation reuses existing Apply (reads current
  live, applies delta) — no new port methods, keeps the seam clean.

### Increment 3 — PR4: richer audit + public-scope + M0 sign-off
- Audit gains reverse cross-provider check: an exposed edge route with no DNS
  record is flagged "exposed but not reachable by name" (only when DNS is
  configured, to avoid noise). Tests added for both directions.
- examples/settings-dns.json (DNS enabled) + examples/seed-failopen.json (no
  catch-all deny) for the audit-critical demo.
- Verified the binary end-to-end: status/preview/expose/unexpose/set/audit/
  export all behave; audit on a fail-open config exits 1.
- M0 declared complete. `go build ./...` + `go test ./...` green.

### Increment 2 — PR3: dnscontrol DNS driver + unified ChangeSet
- `drivers/dns/dnscontrol`: generates dnsconfig.js with `!inside`/`!outside`
  scope tags, shells out via an injected `Shell` seam (`OSShell` real, never hit
  by tests). DesiredRecords/Diff/Apply/LiveRecords implemented. Apply reads live,
  applies the op delta, renders a throwaway dnsconfig.js, and pushes — keeping
  Crenel live-authoritative while using dnscontrol's desired-state push.
- `dnscontrolfake`: in-memory fake shell; `push` parses the generated
  dnsconfig.js, `get-zones` dumps TSV, `preview` emits a CREATE/DELETE diff.
- Port refined: `Diff(ctx, op, desired)` now carries the op so the provider
  knows add (expose) vs remove (unexpose). core.Plan + verify updated.
- cmd wires DNS (opt-in via settings; default off). core unified test proves
  one ChangeSet aggregates edge + DNS and both read-back-verify.
- Decision: dnscontrol is desired-state, but used transiently per-apply so no
  dnsconfig.js is a persisted SOT — consistent with live-authoritative design.
- Next: PR4 polish — public DNS scope demo, richer audit, M1 start.

### Increment 1 — PR1 + PR2 implementation & tests
- model/ports/static/caddy/caddyfake + core engine + cmd CLI all implemented.
- Tests: model (default-deny reachability), caddy driver (normalize, detect
  deny, plan, apply round-trip, reject-load), core (apply+verify, **silent
  reload detection**, decline, no-op, unexpose-leaves-deny), audit (deny present
  / missing-critical / dangling DNS public-critical+internal-warning), cmd
  integration (status/preview/expose/decline/audit-error/export/run-e2e), and a
  **dependency-rule test** asserting core+model never import drivers.
- Decisions:
  - CLI is stdlib `flag` + hand-rolled dispatch — zero external deps, fully
    offline `go build`. (cobra was permitted but unnecessary for this surface.)
  - `--fake-seed` boots an in-process fake Caddy admin API so the shipped binary
    is self-demoable and can NEVER touch real infra in this repo.
  - Caddy apply renders a tiny managed Caddyfile dialect; the fake "adapts" it to
    Caddy JSON. Faithful to the real POST /load (text/caddyfile) → GET /config/
    round-trip, including the silent-reload footgun (SilentReload mode).
  - Read-back verification lives in `core` (provider-agnostic), not the driver.
- Next: PR3 dnscontrol DNS driver.


### Increment 0 — scaffold + design
- `git init`, `go mod init github.com/crenelhq/crenel`, go 1.22.
- Created package dirs: `cmd/crenel`, `internal/{model,core,ports,config}`,
  `internal/drivers/{edge/caddy,dns/dnscontrol,origin/static}`.
- Wrote `DESIGN.md` (full hexagonal architecture, the two load-bearing ideas:
  live-state-authoritative + structural default-deny), `README.md` (plain +
  technical descriptions), and centralized naming in `internal/config/naming.go`.
- Decision: name "Crenel" adopted; all naming centralized in one file.
- Decision: no persisted desired state — `Op` is the only intent and is transient.
- Next: model types.
