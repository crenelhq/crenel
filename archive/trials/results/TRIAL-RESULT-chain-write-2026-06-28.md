# TRIAL RESULT — live cross-chain coordinated WRITE (P4-write) across the two real edges

**Date:** 2026-06-28 (~11:57–12:07 UTC) · **Trial TS:** `20260628T115717Z`
**Companion:** `TRIAL-PLAN-chain-write.md` (the ordered plan this executed), `SECURITY.md`,
`DIAGNOSTICS-2026-06-27.md`, `DESIGN.md` "Transport / Connection".

> **OUTCOME (honest headline):** The coordinated WRITE was issued against both **real**
> production edges and **aborted atomically with ZERO changes applied** — because it
> surfaced a genuine crenel bug: the granular `forward_auth` renderer emits a **synthetic
> JSON handler name (`http.handlers.forward_auth`) that no real Caddy registers**, so the
> home edge's Caddy rejected it at config-load validation. crenel's all-or-nothing
> transaction did exactly its job: home is applied first, its Caddy validated-and-rejected
> the change, and crenel **aborted the whole transaction touching neither edge**.
> **Production was verified byte-for-byte pristine and healthy throughout.** The 302
> auth-attach success criterion was therefore **not reached** — blocked by the bug, not by
> any infra failure. The live trial caught a gap the entire fake-based test suite
> structurally cannot.

---

## What this run proved (and did not)

| Claim | Result |
|---|---|
| Transport port reaches **both** real admins with **zero exposure** (front `direct`, home `ssh-exec`) | ✅ proven — `status` + `preview` read both live edges over the Transport port; no admin published, no tunnel, no home container change |
| Read-only chain projection matches reality (`preview` vs live) | ✅ byte-identical to the prep dry-run (front `→10.0.0.13:443`; home `→10.0.0.13:9999 [auth:authelia]`; deny remains; ABOUT TO GO PUBLIC) |
| Public-without-auth **guardrail** refuses on the real chain | ✅ refused (`--yes` did not bypass) |
| Coordinated cross-chain WRITE lands on both edges (the headline happy path) | ❌ **blocked** — home Caddy rejected the `forward_auth` handler at validation |
| **Atomic abort on apply failure — ZERO mutation, wedge-safe** | ✅ **proven on production** — `aborted: no changes applied`; both edges byte-for-byte unchanged; no wedge; no restart |
| 302 auth-challenge through the chain | ❌ not reached (depends on the write landing) |
| Production health preserved throughout | ✅ 3 prod hosts `200` before/during/after; both containers `RestartCount=0`, running |

The safety net (atomic, read-back-verified, no-partial-apply) is arguably the single most
important property to validate on a real edge, and **this run validated it against a real
apply rejection on production** — not a fake.

---

## Access model used (resolved at execution time)

The plan's literal "crenel on the VPS, home via `ssh root@pve1`" had a name-resolution
snag: on the VPS, `pve1` resolves to a public IP (`203.0.113.7`) that is firewalled on
:22, so the hostname timed out. The Proxmox host's reachable **Tailscale IP `100.100.0.7`**
*is* open on :22 from the VPS, and the pre-authorized key **`vps-to-pve1-20260628`** was
already present in pve1's root `authorized_keys`. Resolution (no home-side change needed):

- **crenel ran ON THE VPS** (`~/crenel-test/crenel-develop`, develop `f3d144d`, linux/arm64).
- **FRONT (vps):** transport `direct` → `http://127.0.0.1:2019` (VPS loopback).
- **HOME:** transport `ssh-exec`, exec prefix
  `ssh -i ~/.ssh/pve1_key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes root@100.100.0.7 pct exec 113 -- docker exec -i caddy sh`
  → curl `http://127.0.0.1:2019` on the container loopback. `100.100.0.7` **is** `pve1`
  (its Tailscale IP); host key pinned + verified (`SHA256:S4fx6Lpf…`), not TOFU.
- **No home admin published, no tunnel, no home container config touched.** Both admin APIs
  stayed loopback-only and unpublished the entire run (stop-condition #6 never approached).
- The **only** access-setup action was VPS-side and already in place (key + pinned host
  key); **nothing was added that needs reverting on the home side.**

---

## The finding — root cause

crenel's granular auth path renders auth as a handler literally named `forward_auth`:

```
internal/drivers/edge/caddy/types.go:140  handlerForwardAuth = "forward_auth"  // crenel's auth reference handler
emitted JSON:  {"handler":"forward_auth","crenel_policy":"authelia","upstreams":[{"dial":"authelia:9091"}]}
```

But in Caddy, **`forward_auth` is a Caddyfile *directive*** (sugar the caddyfile adapter
expands into a `reverse_proxy` + `handle_response` subrequest) — **there is no JSON handler
module `http.handlers.forward_auth`.** The home edge's live config confirms it: the only
handler modules present are `headers`, `reverse_proxy`, `subroute`, `vars`, and the string
`forward_auth` appears **0 times** (Authelia is wired as a `reverse_proxy` to `authelia:9091`).

So the granular PUT was rejected by Caddy at config-load validation:

```
admin PUT /config/apps/http/servers/srv0/routes/0 returned 500:
  loading module 'forward_auth': unknown module: http.handlers.forward_auth
→ aborted: no changes applied   (CRENEL_EXIT=1)
```

**Why the test suite missed it:** crenel's fakes round-trip arbitrary JSON and never run
Caddy's module-registration/provision step, so `{"handler":"forward_auth"}` "applies"
against a fake but is invalid for any real Caddy admin API. This is precisely the class of
bug only a live trial can catch.

**Fix direction (for a follow-up, not done here):** the granular renderer must emit a
*real* Caddy handler. The faithful expansion of `forward_auth <upstream>` is a
`reverse_proxy` handler with `handle_response` (auth subrequest) + `copy_headers` +
a rewrite to the provider's verify URI. Note crenel by design carries auth **by reference**
and does not model the operator's `uri /api/verify?rd=…`/`copy_headers`, so even a
syntactically-valid bare expansion may not reproduce a working Authelia 302 on this edge —
the verify URI is load-bearing. Worth deciding whether the granular path should (a) emit a
correct `reverse_proxy`-based `forward_auth`, or (b) require the operator's snippet via the
`import` path for real auth attachment.

---

## Verification that production was untouched (post-abort)

| Check | Result |
|---|---|
| `crenel status` — `crenel-selftest` on either edge | **absent** (count 0); status byte-identical to pre-trial capture |
| Both denies still ENFORCED | ✅ VPS (32 forward routes) + home (51 terminal routes), unchanged |
| VPS live config vs Step-0 anchor | **byte-for-byte identical** — sha256 `05b1646a…` |
| HOME live config vs Step-0 anchor | **byte-for-byte identical** — sha256 `174d1d92…` |
| 3 prod hosts (`auth`/`git`.homelab.example, `auth`.smallbiz.example) | **200** |
| `caddy-edge` (VPS) / `caddy` (home) RestartCount | **0 / 0**, both running |
| Admin-API wedge (crowdsec storm signature) | **none** — clean 500 + responsive admin |
| Throwaway responder (LXC 113 :9999) | stood up, verified reachable from caddy container, then **torn down** (port free) |

No hard stop-and-restore condition was tripped; no R1–R4 recovery was needed (crenel's own
atomic abort left both edges clean). Backups + sha anchors at
`live-backup/trial-chain-write-20260628T115717Z/` (gitignored, `0600`).

---

## Status of the headline

**Not yet proven on the live edges.** The cross-chain *coordination + atomic-abort* half is
proven on production; the *write-lands + auth-attaches (302)* half is blocked by the
`forward_auth` JSON-handler bug above. A clean re-run requires either a renderer fix (emit a
valid Caddy auth handler) or an explicit `--auth none` variant (which proves raw chain
routing but goes open-200, and was not the GO'd success criterion). **Pending the maintainer's call.**

---
---

# RUN 2 — 2026-06-28 (~14:02–14:10 UTC) · Trial TS `20260628T140225Z` · binary `14cdd14` (TRIAL-FIX-2 + TRIAL-FIX-3 in)

> **OUTCOME (honest headline):** This time the coordinated WRITE **LANDED on both real
> production edges** — `expose crenel-selftest --auth authelia -yes` applied home→front, each
> **read-back ✓**, `verified: live state matches intent`, exit 0. **TRIAL-FIX-2 (subroute
> nesting) and TRIAL-FIX-3 (valid forward-auth renderer) are both validated on production:**
> crenel-selftest landed *inside* the `*.homelab.example` wildcard subroute, and the home Caddy
> **accepted** the auth gate (no more `unknown module: forward_auth`). The rendered gate is
> byte-faithful to the home edge's own Authelia gate (only cosmetic copy-header *ordering*
> differs). **But the headline 302 was still NOT reached** — the through-the-chain curl returned
> **`400 "Client sent an HTTP request to an HTTPS server"`**, which surfaced a **third, distinct
> crenel gap: the FRONT forward route is rendered as a bare HTTP `reverse_proxy` to the
> downstream's `:443`, with no upstream TLS transport and no `Host` preservation.** The home
> auth gate and nesting are correct; the request just never completes the TLS hop to reach them.
> A `400` is **not** an open `200` — the responder was never served, auth+TLS both intercept, so
> no security criterion was violated. Production stayed healthy and byte-clean of crenel's
> footprint throughout.

## What RUN 2 proved (and did not)

| Claim | Result |
|---|---|
| Transport reaches both real admins, zero exposure (front `direct`, home `ssh-exec`) | ✅ re-proven; home admin `10.0.0.13:2019` stayed refused from the VPS the entire run (never on tailnet, no tunnel, no home container change) |
| Read-only `status`/`preview` match reality; public-without-auth guardrail refuses | ✅ VPS 32 / home 51, both deny ENFORCED; preview = front `→10.0.0.13:443`, home `→10.0.0.13:9999 [auth:authelia]`; `expose` w/o `--auth` refused (exit 1, `--yes` no bypass) |
| **Coordinated cross-chain WRITE lands on BOTH edges** (the headline coordination) | ✅ **PROVEN on production** — `applied`, home+front each `read-back ✓`, `verified`, exit 0; counts +1 each (33/52), both denies still ENFORCED |
| **TRIAL-FIX-3: auth gate is VALID Caddy the home edge ACCEPTS** | ✅ **PROVEN** — gate rendered as `vars` marker + `reverse_proxy→authelia:9091` + `handle_response` (status 2xx) + rewrite `/api/verify?rd=https://auth.homelab.example` + 4 `Remote-*` copy-headers; **byte-faithful** to `home.homelab.example`'s live gate (diff = copy-header order only) |
| **TRIAL-FIX-2: route nested inside the `*.zone` wildcard subroute** | ✅ **PROVEN** — crenel-selftest landed in `srv0 route[1] (*.homelab.example) → subroute`, exactly where the read side enumerates per-host routes |
| **302 auth-challenge through the chain** | ❌ **not reached** — `400 "Client sent an HTTP request to an HTTPS server"` (NEW front-leg TLS gap, below) |
| Clean `unexpose`, zero crenel residue | ✅ home+front each `read-back ✓`, `verified`; **0** `crenel-route` @id tags remain anywhere; VPS byte-for-byte identical to the Step-0 anchor |
| Production health preserved throughout | ✅ 3 prod hosts `200` before/during/after; both containers `RestartCount=0`, running; no wedge, no restart |

## The NEW finding — front-leg HTTPS-transport gap (root cause)

The control proves the chain + Authelia work: `home.homelab.example` through the same VPS→home
chain returns `302 → https://auth.homelab.example/?rd=…`. crenel-selftest returns `400`. The 400
body — **"Client sent an HTTP request to an HTTPS server"** — pins it to the **VPS→home hop**,
not the auth gate. Comparing the two VPS forward routes:

```
git.homelab.example (working):              crenel-selftest (crenel-rendered):
  upstreams: [{dial: 10.0.0.13:443}]       upstreams: [{dial: 10.0.0.13:443}]
  transport: {protocol: http, tls: {         transport: null          ← speaks PLAIN HTTP to :443
    insecure_skip_verify: true,              headers:   null          ← no Host preservation
    server_name: "{http.request.host}"}}
  headers: {request:{set:{Host:["{http.request.host}"]}}}
```

Root cause in code: `internal/core/chain_write.go` `forwardRoute()` correctly sets the model's
`Upstream.ServerName = host` (and `Mode = ModeHTTPProxy`), **but** the Caddy granular renderer
`internal/drivers/edge/caddy/caddy.go` `insertRoute()` (≈L1141) emits only
`{"handler":"reverse_proxy","upstreams":[{"dial":<addr>}]}` — it **drops `ServerName`** and never
renders a `transport.tls` block or the `Host` header. So a front route that must dial an HTTPS
downstream (`:443`) goes out as plain HTTP → Caddy on the far side answers 400.

**Why the suite missed it (same class as FIX-2/FIX-3):** the Caddy fake round-trips the bare
`reverse_proxy` JSON and never actually opens a TLS connection to a real downstream `:443`, so a
transport-less forward route "works" against a fake and only fails against a real HTTPS edge.
Third live-only finding in a row.

**Fix direction (follow-up code change, not done here):** in `insertRoute`, when the route is a
chain-forward to an HTTPS downstream (model carries `ServerName`/a `:443` dial / a "downstream
HTTPS" flag), render the upstream `transport: {protocol:"http", tls:{server_name:"{http.request.host}",
insecure_skip_verify:true}}` + `headers.request.set.Host = "{http.request.host}"`, mirroring the
edge's own working forward routes. Then re-run for the real 302. (Consider a `downstream_scheme`/
`downstream_tls` knob on the front edge config so the dial scheme is explicit rather than inferred.)

## Verification that production was left clean (post-unexpose)

| Check | Result |
|---|---|
| `crenel status` — crenel-selftest on either edge | **absent** (0); VPS back to 32, home 52* |
| Both denies still ENFORCED | ✅ unchanged |
| `crenel-route` @id residue anywhere | **0** — zero crenel footprint on both edges |
| VPS live config vs Step-0 anchor (`jq -S` diff) | **byte-for-byte identical** (sha `05b1646a…`) |
| HOME live config vs Step-0 anchor | non-empty, but the **only** non-cosmetic delta is an **external** `archive.homelab.example → filebrowser:80` route (no `@id`, not in the Step-0 backup, unknown to crenel) added by another actor during the 14:02–14:10 window; the rest is Caddy auto-`group` counter renumbering it triggered. **NOT crenel residue** — deliberately **not** reverted (a `docker restart` would either keep a SOT change or destroy a live one — not crenel's call). Flagged for the maintainer. |
| 3 prod hosts (`auth`/`git`.homelab.example, `auth`.smallbiz.example) | **200** throughout |
| `caddy-edge` (VPS) / `caddy` (home) RestartCount | **0 / 0**, both running; no wedge, no R1–R4 needed |
| Home admin published / on tailnet at any point | **never** — `10.0.0.13:2019` refused from the VPS start to finish |

\* home count is 52 not 51 **solely** because of the external `archive.homelab.example` route, not
because of anything crenel did (crenel's own route was added and cleanly removed).

## Status of the headline (RUN 2)

**Coordination half: now PROVEN on production** — a single `crenel` coordinated a real,
auth-attached, ordered, read-back-verified WRITE across both production edges and cleanly tore it
down, zero residue, admin never exposed. **FIX-2 and FIX-3 both validated live.** The **302
end-to-end** is the one remaining gap, blocked by the newly-found front-leg HTTPS-transport
omission (a bare-HTTP forward to an HTTPS `:443`). One more renderer fix — emit the upstream
`transport.tls` + `Host` on chain-forward routes — and the 302 should land. **Pending the maintainer's
call on the fix + a re-run.**

---
---

# TRIAL-FIX-4 — front-leg upstream TLS on chain-forward routes (DONE, 2026-06-28)

The RUN 2 finding above is now **fixed on `develop`** (commits `5667d06` → `e677402` →
`0d4b907`; every commit green under `go build ./... && go vet ./... && go test -race
-count=1 ./...`, pushed to Forgejo per increment).

**Precise root cause (confirmed in code).** `internal/core/chain_write.go forwardRoute`
set the model's `Upstream.ServerName = host` for the chain-forward, but
`internal/drivers/edge/caddy/caddy.go insertRoute` **dropped it** — it emitted only
`{"handler":"reverse_proxy","upstreams":[{"dial":<addr>}]}`, with `transport:null` and
`headers:null`. So a front route that must dial an HTTPS `:443` downstream went out as
plain HTTP → the home edge's TLS listener answered `400 "Client sent an HTTP request to an
HTTPS server"`. The fake round-trips the bare `reverse_proxy` JSON and never opens a real
TLS socket, so the entire fake-based suite structurally could not catch it (the third
live-only finding in a row).

**The real VPS forward-route JSON shape (byte-faithful target, from
`live-backup/trial-chain-write-20260628T140225Z/vps-front-config-20260628T140225Z.json`,
e.g. `git.homelab.example → 10.0.0.13:443`):**

```json
{"handler":"reverse_proxy",
 "headers":{"request":{"set":{"Host":["{http.request.host}"]}}},
 "transport":{"protocol":"http","tls":{"insecure_skip_verify":true,"server_name":"{http.request.host}"}},
 "upstreams":[{"dial":"10.0.0.13:443"}]}
```

Note both `server_name` and `Host` use the Caddy placeholder `{http.request.host}` (NOT a
literal FQDN) — the wildcard carries the matched host through, so one rendering serves
every forwarded host. crenel now mirrors this exactly.

**The fix (three increments).**
1. **core** (`5667d06`): `model.Upstream.UpstreamTLS` carries the intent.
   `chain_write.forwardRoute` sets it from the downstream scheme — explicit
   `downstream_scheme` (`"https"`/`"http"`) wins, else inferred from a `:443` dial. New
   `downstream_scheme` config knob threaded through `config` → `wire` → `EdgeBinding`. Core
   stays driver-free (dependency-rule test green).
2. **caddy renderer + read-back** (`e677402`): `insertRoute`, when `Upstream.UpstreamTLS`,
   renders the backend `reverse_proxy` with the `transport.tls` block + the `Host` request
   header above, byte-faithful to the real VPS forward; a plain-HTTP downstream renders the
   bare `reverse_proxy` unchanged. `types.go` parses `transport.tls` on read-back;
   `collectLeaves` sets `Upstream.UpstreamTLS` so the forward's TLS hop round-trips (and
   `firstReverseProxyDial`/normalize still resolve the dial — no regression).
3. **verify** (`0d4b907`): `apply.verifyEdgeForwardTLS` asserts every chain-forward planned
   with `UpstreamTLS` reads back carrying it — the front-leg analogue of the auth read-back;
   a render that drops the TLS transport fails the transaction and rolls the chain back.

**Tests (fakes mirroring the real forward shape; reproduce-the-gap where structurally
possible).** A request-time 400 cannot be reproduced against a static fake (it never opens
a TLS socket), so the render is asserted STRUCTURALLY against the real shape:
- `caddy/nested_tls_forward_test.go`: an HTTPS-downstream forward renders `reverse_proxy`
  **with** `transport.tls` + `server_name` + `Host`, nested at index 0 of the `*.homelab.example`
  wildcard subroute, and reads back `UpstreamTLS=true`; a plain-HTTP downstream stays bare
  (the reproduce-the-gap control — TLS intent is the only flip).
- `core/chain_write_test.go`: `TestChainWrite_FrontForwardTLSAndAuthRoundTrips` — full
  `expose vault --auth authelia` produces the TLS-correct front forward **and** the
  valid-auth home terminal, both read-back-verified, then `unexpose` restores BOTH edges
  byte-for-byte; `TestChainWrite_ForwardTLSReadBackFailureRollsBack` — a forward that drops
  the TLS transport on apply (the old bare-HTTP render) fails verify and rolls back.
- `core/chain_write_tls_test.go`: the scheme-inference matrix (`:443` infers https,
  non-443 infers http, bare host conservative-plain, explicit `https`/`http` override,
  case-insensitive, IPv6 literal port).

**Confirmation:** the cross-chain front forward now renders with upstream TLS + Host, so
the request completes the TLS hop to the HTTPS downstream and reaches the (correct, valid)
Authelia gate — **the real 302 should land on the live re-run**. **NO live infra was
mutated for this fix** (build/test against fakes only).

## Status of the headline (post TRIAL-FIX-4)

All three live-only findings (FIX-2 nesting, FIX-3 valid auth gate, FIX-4 front-leg TLS)
are now fixed and green. The coordination + atomic-abort half is already PROVEN on
production; the **302 end-to-end** is unblocked. **Live trial RE-RUN #3 is GO-gated and
ready** (separate, pending the maintainer's explicit GO) — keep `downstream_address:
10.0.0.13:443` (the `:443` infers HTTPS automatically; no config change needed).

---
---

# RUN 3 — 2026-06-28 (~15:26–15:43 UTC) · Trial TS `20260628T152625Z` · binary `350b7c1` (TRIAL-FIX-2 + FIX-3 + FIX-4 all in)

> **OUTCOME (honest headline):** The coordinated, auth-attached, TLS-correct WRITE **LANDED
> cleanly on both real production edges** and the **end-to-end auth enforcement is now PROVEN
> through the chain** — the front-leg `400` is GONE (FIX-4 works) and the request reaches a
> live, enforcing Authelia gate (FIX-3 works). The through-the-chain curl returned **`403
> Forbidden`, not the literal `302`** that was the written success image. **This is not a
> miss and not a stop-condition** — a `403` is auth *attached and enforcing a deny*, the
> opposite of the open-`200` failure mode. The `403` vs `302` difference is owned entirely by
> **Authelia's own per-domain access-control config**, which is outside crenel's scope
> (crenel carries auth *by reference*; the provider owns the per-host policy): the throwaway
> `crenel-selftest.homelab.example` has **no access-control rule in Authelia**, so its
> `default_policy` (deny) returns `403` with no login redirect, whereas a *configured* host
> (`home.homelab.example` → `one_factor`) returns the `302` portal redirect through the **same
> chain** (proven as a live control). So all three crenel properties the trial set out to
> prove — **coordinated cross-edge write, TLS-correct front leg, auth attached at the home
> edge** — are validated on production; the exact `302` code would require an Authelia rule
> for the throwaway host (an auth-provider change, deliberately not made). Production stayed
> healthy and byte-for-byte clean of crenel's footprint throughout; clean unexpose; both
> edges restored byte-for-byte; admin never exposed.

## What RUN 3 proved (and the one nuance)

| Claim | Result |
|---|---|
| Transport reaches both real admins, zero exposure (front `direct`, home `ssh-exec`) | ✅ re-proven; home admin `10.0.0.13:2019` **refused from the VPS** start→finish (never on tailnet, no tunnel, no home container change) |
| Read-only `status`/`preview` match reality; public-without-auth guardrail refuses | ✅ VPS deny ENFORCED (31 fwd routes), home deny ENFORCED (51 terminal); preview = front `→10.0.0.13:443`, home `→10.0.0.13:9999 [auth:authelia]`; `expose` w/o `--auth` refused (exit 1, `--yes` no bypass) |
| **Coordinated cross-chain WRITE lands on BOTH edges** | ✅ **PROVEN** — `applied`, home+front each `read-back ✓`, `verified: live state matches intent`, exit 0; counts +1 each (32/52), both denies still ENFORCED |
| **FIX-2: route nested inside the `*.zone` wildcard subroute** | ✅ **PROVEN** — crenel-selftest front route is a sibling of `vault`/`git` inside `srv0`'s `*.homelab.example` subroute |
| **FIX-3: home auth gate is VALID Caddy + dials the REAL Authelia** | ✅ **PROVEN** — gate = `vars crenel_policy:authelia` + `reverse_proxy→authelia:9091` + `handle_response` + rewrite `/api/verify?rd=https://auth.homelab.example` + 4 `Remote-*` copy-headers, then proxy to `10.0.0.13:9999`. Byte-faithful to home's native Authelia gate. |
| **FIX-4: front forward renders upstream TLS + Host** | ✅ **PROVEN on production** — `reverse_proxy` with `transport.tls{insecure_skip_verify, server_name:{http.request.host}}` + `Host:{http.request.host}` → `10.0.0.13:443`, byte-faithful to the real VPS forward. **The RUN 2 `400` is GONE.** |
| **End-to-end through the chain** | ⚠️ **`403`, not `302`** — auth **attached + enforcing a deny** (NOT an open `200`, NOT a `400`). See the nuance below. |
| Clean `unexpose`, zero crenel residue, byte-for-byte restore | ✅ home+front each `read-back ✓`, `verified`; **0** `crenel-route` @id anywhere; **both edges byte-for-byte identical** to the Step-0 anchors (python-normalized diff; `jq` is not on the VPS) |
| Production health preserved throughout | ✅ 3 prod hosts `200` before/after; both containers `RestartCount=0`, Running; no wedge, no R1–R4 |

## The `403`-not-`302` nuance — root cause (NOT a crenel defect)

Through-the-chain (public): `curl https://crenel-selftest.homelab.example/` → **`HTTP/2 403`**, `via: 1.1 Caddy`, `content-type: text/plain`, body `403 Forbidden` (13 B), **carrying none of Authelia's response headers**. Live control through the *same* VPS→home chain: `curl https://home.homelab.example/` → **`HTTP/2 302`** → `location: https://auth.homelab.example/?rd=…` + `set-cookie authelia_session` + Authelia's `permissions-policy`/`x-frame-options`/etc.

Both hosts traverse byte-equivalent gates (crenel's gate is byte-faithful to home's native one, confirmed by reading the live home-edge config). The only variable is the **Host** the gate forwards to Authelia's `/api/verify`. Authelia decides per-domain from its `access_control`:
- `home.homelab.example` is configured (`one_factor`) → unauthenticated → **`302`** redirect to the portal (Caddy's `handle_response` copies the redirect through).
- `crenel-selftest.homelab.example` has **no rule** → Authelia's `default_policy` (deny) → **`403`** with no redirect (deny ≠ "offer login") → Caddy surfaces the bare `403`.

So the `403` is the **auth gate working**: the python responder on `:9999` was **never reached** (its directory-listing body never appeared — a `403`, then after unexpose an *empty* `200`, never the listing), proving the gate intercepted. A `403` is therefore a *stronger* deny than the `302` proxy-criterion, not a failure. (Authelia's own config was **not** read — that container was out of the trial's authorized scope and carries secrets; the conclusion rests on the in-scope caddy-edge gate inspection + the live `302` control + the gate dialing `authelia:9091`.)

**To see the literal `302`:** add an Authelia `access_control` rule for `crenel-selftest.homelab.example` (e.g. `policy: one_factor`) and re-run — an **auth-provider** change, deliberately not made here (out of crenel's scope and the trial's authorization).

## Stop-conditions (none tripped) + restore verification

| Check | Result |
|---|---|
| (1) Either edge prod health drops | ✅ no — 3 prod hosts `200` before/after; `RestartCount` 0/0 unchanged |
| (2) Admin wedge (crowdsec storm) | ✅ no — clean apply/unexpose, responsive admin throughout |
| (3) Read-back fails | ✅ no — every apply leg `read-back ✓` + `verified` |
| (4) `crenel-selftest` open `200` under `--auth` | ✅ **no — `403` (auth enforcing); never reached the responder** |
| (5) Any OTHER crenel-relevant host changed | ✅ no — pre-vs-post `status` diff = only the two `Exposed (N)` count lines (+1 each); no host's reachability/auth/backend changed |
| (6) Home admin leaks onto tailnet | ✅ no — `10.0.0.13:2019` **refused** from the VPS start→finish |
| (7) crenel's routes don't restore clean | ✅ no — **both edges byte-for-byte identical** to the Step-0 anchors; **0** crenel @id residue |
| crenel-selftest after unexpose | back to pre-trial baseline: **empty `200`** (`content-length: 0`), identical to a control never-exposed host (`randomzzz123.homelab.example` → `200`) — the generic `*.homelab.example` wildcard fall-through, not the responder |
| Throwaway responder (`:9999`, transient systemd unit `crenel-responder`) | stood up, reachable from caddy container (`200`), then **stopped**; `:9999` free; refused from caddy |
| Backups / secret hygiene | Step-0 anchors `0600` (gitignored `live-backup/`); all `/tmp` full-config dumps (real secrets) `shred`+`rm` on the VPS; trial config copies wiped (Mac + VPS); git tree clean |

Step-0 anchors (this run's restore baseline): VPS `43901caf…` (4604 B), HOME `e509c326…` (24877 B) at `live-backup/trial-chain-write-20260628T152625Z/`.

## Status of the headline (RUN 3)

**The full proof is in:** a single `crenel` coordinated a real, ordered, read-back-verified
WRITE across **both** production edges, rendering a **TLS-correct front forward** (FIX-4 — no
more `400`) and a **valid, enforcing Authelia gate** at the home edge (FIX-3 — dials the real
`authelia:9091`), nested correctly (FIX-2), then tore it all down to a **byte-for-byte clean**
restore, with the admin never exposed and production healthy throughout. The end-to-end
response is a **`403` (Authelia default-deny for the unconfigured throwaway host)** rather than
the literal `302` portal redirect — auth **attached and enforcing**, the difference owned by
Authelia's per-domain policy (out of crenel's by-reference scope), with the `302` path proven
live on a configured control host. **All three live-only findings (FIX-2/3/4) are validated on
production; crenel's cross-chain coordinated-write feature is proven end-to-end.**

---
---

# RUN 3-RERUN — 2026-06-28 (~16:26–16:35 UTC) · Trial TS `20260628T162634Z` · binary `350b7c1` (freshly rebuilt; sha `5943069c…`)

> **OUTCOME (honest headline):** A **fresh, independent re-execution** of the full trial
> (new binary build of the same `develop @ 350b7c1`, new backups, new responder) that
> **reproduced RUN 3's result exactly** — the coordinated, auth-attached, TLS-correct WRITE
> **landed cleanly on both production edges** (`applied`, read-back ✓ both, `verified`, exit 0),
> all three fixes validated at the **JSON level** on the live edges, then tore down to a
> **RAW byte-for-byte identical** restore (no drift this run — both edge sha256 matched the
> Step-0 anchors *exactly*, not merely normalized-identical). The through-chain curl returned
> **`403`** (Authelia default-deny for the unconfigured throwaway host), the control
> `home.homelab.example` returned **`302 → auth.homelab.example`** through the same chain.
> **NEW this run:** the maintainer granted explicit permission to `docker restart` Authelia to chase the
> literal `302`. After a header-level + responder-log diagnosis (below), I **deliberately did
> not** bounce Authelia, because the evidence proves the `403` is **config-determined** (a
> missing `access_control` rule for the throwaway host) and a restart reloads the *same* on-disk
> config → same `403`; a restart would blip auth homelab-wide for **zero** diagnostic gain. No
> stop-condition tripped; admin never exposed; production healthy throughout.

## What RUN 3-RERUN proved

| Claim | Result |
|---|---|
| Transport reaches both real admins, zero exposure (front `direct`, home `ssh-exec`) | ✅ re-proven; home admin `10.0.0.13:2019` **refused from the VPS** start→finish (no tunnel, no publish, no home container change) |
| Edges sat at RUN 3's exact clean baseline before the trial | ✅ Step-1 anchors **identical to RUN 3's**: VPS `43901caf…` (4604 B), HOME `e509c326…` (24877 B) |
| Read-only `status`/`preview` match reality; public-without-auth guardrail refuses | ✅ VPS deny ENFORCED (31 fwd), home deny ENFORCED (51 terminal); preview = front `→10.0.0.13:443`, home `→10.0.0.13:9999 [auth:authelia]`; `expose` w/o `--auth` refused (exit 1, `--yes` no bypass) |
| **Coordinated cross-chain WRITE lands on BOTH edges** | ✅ **PROVEN** — `applied`, home+front each `read-back ✓`, `verified: live state matches intent`, exit 0; counts +1 each (32/52), both denies still ENFORCED |
| **FIX-2: nested inside the `*.zone` wildcard subroute** | ✅ **PROVEN** — `@id crenel-route-crenel-selftest.homelab.example` landed as a sibling of the other `*.homelab.example` hosts on both edges |
| **FIX-3: home auth gate is VALID Caddy + dials the REAL Authelia** (JSON captured live) | ✅ **PROVEN** — `vars crenel_policy:authelia` → `reverse_proxy→authelia:9091` with `rewrite /api/verify?rd=https://auth.homelab.example` + `X-Forwarded-Method/Uri` + `handle_response` copying all 4 `Remote-*` headers → then `reverse_proxy→10.0.0.13:9999`. Byte-faithful to home's native gate. |
| **FIX-4: front forward renders upstream TLS + Host** (JSON captured live) | ✅ **PROVEN** — `reverse_proxy` with `transport{protocol:http, tls:{insecure_skip_verify, server_name:{http.request.host}}}` + `headers.request.set.Host:{http.request.host}` → `10.0.0.13:443`. No `400`. |
| **End-to-end through the chain** | ⚠️ **`403`, not `302`** — auth **attached + enforcing a deny** (NOT open `200`, NOT `400`). Diagnosis below. |
| Clean `unexpose`, zero residue, byte-for-byte restore | ✅ home+front each `read-back ✓`, `verified`; **0/0** crenel `@id` residue; **both edges RAW sha256 == Step-0 anchors exactly** |
| Production health preserved throughout | ✅ 3 prod hosts `200` before/after; `RestartCount` 0/0 unchanged, both Running; no wedge, no R1–R4 |

## The `403`-vs-`302` diagnosis (fresh evidence this run) — and why I did NOT restart Authelia

Three independent pieces of live evidence pin the cause, all read-only:

1. **The request traversed both Caddy hops.** The `403` response carries `via: 2.0 Caddy` **and**
   `via: 1.1 Caddy` → it went VPS-front → home, i.e. **FIX-4's TLS hop completed** and it reached
   the home auth gate (a transport-less render would have died at `400` on the front leg, as in RUN 2).
2. **The responder was never reached.** The `:9999` responder's journal shows **only** the Step-4
   reachability probe (`172.22.0.7 … "GET / HTTP/1.1" 200` at 16:32:17, from the caddy container) —
   **no entry** for the 16:34:15 public curl. The auth gate intercepted before the backend.
3. **The `403` carries none of Authelia's portal headers** (`text/plain`, 13 B, no `location`,
   no `set-cookie authelia_session`, no `permissions-policy`/`x-frame-options`), whereas the
   `home.homelab.example` control's `302` carries **all** of them (`location:
   https://auth.homelab.example/?rd=…`, `set-cookie authelia_session=…`, the full Authelia header set).

That is Authelia returning **deny (403)** for a host with no `access_control` rule
(`default_policy: deny`) vs **redirect-to-login (302)** for a configured host (`one_factor`).
**A `docker restart` of Authelia reloads the same on-disk config → the same `403`.** Turning the
`403` into a `302` requires *adding* an `access_control` rule for `crenel-selftest.homelab.example`
— an **Authelia config edit**, outside the restart-only permission the maintainer granted and outside the
trial's scope (crenel carries auth *by reference*; the provider owns per-host policy). So I used
the granted permission's intent — **diagnose the 302 path** — via the read-only header + log
evidence above, concluded a restart cannot change the outcome, and (per the maintainer's "don't keep a route
up indefinitely while debugging") tore the route down rather than bounce Authelia for the whole
homelab for no gain. **Zero Authelia restarts were performed.**

## Stop-conditions (none tripped) + restore verification

| Check | Result |
|---|---|
| (1) Either edge prod health drops | ✅ no — 3 prod hosts `200` before/after; `RestartCount` 0/0 unchanged |
| (2) Admin wedge (crowdsec storm) | ✅ no — clean apply/unexpose, responsive admin throughout |
| (3) Read-back fails | ✅ no — every apply/unexpose leg `read-back ✓` + `verified` |
| (4) `crenel-selftest` open `200` under `--auth` | ✅ **no — `403` (auth enforcing); responder never reached** |
| (5) Any OTHER crenel-relevant host changed | ✅ no — pre/post `status` diff = only the two `Exposed (N)` counts (+1 then back) |
| (6) Home admin leaks onto tailnet | ✅ no — `10.0.0.13:2019` **refused** from the VPS start→finish |
| (7) crenel's routes don't restore clean | ✅ no — **both edges RAW byte-for-byte identical** to the Step-0 anchors; **0/0** `@id` residue |
| crenel-selftest after unexpose | back to baseline: behaves **identically to a never-exposed control** (`randomzzz123.homelab.example`) — http1.1 empty-reply / http2 stream-reset = the `*.homelab.example` `abort` default-deny |
| Throwaway responder (`:9999`, transient unit `crenel-responder`, PID 1406377) | stood up, reachable from caddy (`200`), then **stopped**; `:9999` refused from caddy afterward |
| Secret hygiene | Step-1 anchors `0600` (gitignored `live-backup/`); `/tmp` full-config dumps (real secrets) `shred`+`rm` on the VPS; trial config copies wiped (Mac scratchpad + VPS); no secrets printed |

Step-1 anchors (this run's restore baseline): VPS `43901caf…` (4604 B), HOME `e509c326…` (24877 B)
at `live-backup/trial-chain-write-20260628T162634Z/` (on the VPS, `0600`).

## Status of the headline (RUN 3-RERUN)

**Reconfirmed on a fresh build, even cleaner than RUN 3.** A single `crenel` coordinated a real,
ordered, read-back-verified WRITE across **both** production edges — TLS-correct front forward
(FIX-4), valid enforcing Authelia gate dialing the real `authelia:9091` (FIX-3), correctly nested
(FIX-2) — captured at the JSON level live, then tore it down to a **RAW byte-for-byte identical**
restore (no drift), admin never exposed, production healthy throughout. The end-to-end response is
a **`403`** (Authelia default-deny for the unconfigured throwaway host), with the **`302`** portal
path proven on the configured `home.homelab.example` control through the same chain. The `403`↔`302`
gap is owned by Authelia's per-host `access_control` (a config rule), which a `docker restart`
cannot supply — so despite the new restart permission, **no Authelia restart was warranted or
performed**. **crenel's cross-chain coordinated-write feature is proven end-to-end; the only path
to the literal `302` is an auth-provider config change, deliberately out of scope.**

---
---

# RUN 3-RERUN-B — THE LITERAL 302, demonstrated 2026-06-28 (~16:45–16:58 UTC) · binary `350b7c1`

> **OUTCOME (headline):** With the maintainer's explicit authorization to **edit Authelia's config** (beyond the
> earlier restart-only permission), I added a temporary `access_control` rule for the throwaway host,
> and the through-the-chain curl returned **the literal `302` → `auth.homelab.example`** — the exact
> success image from the original plan. **Crucially, the crenel-rendered gate was byte-identical to
> the 403 runs;** the ONLY thing changed was Authelia's per-host policy. So this is the definitive
> proof that the RUN 3 / RERUN `403` was **100% Authelia's per-host default-deny, never a crenel
> defect**: flip the Authelia rule, and the *unchanged* crenel gate yields the `302`. Everything was
> then fully reverted — crenel unexposed, Authelia config restored **byte-for-byte** (sha
> `7f622e23…`), both caddy edges **byte-for-byte** (sha `43901caf…` / `e509c326…`), all hosts back to
> baseline, production healthy throughout.

## First: the gate was grounded in the HOME edge's real routes (the maintainer's note 1) — and PROVEN correct

Before touching anything, I extracted the home edge's own working `home.homelab.example` Authelia gate
from the live backup and compared it field-by-field to crenel's render. **They match in every
load-bearing field** — same endpoint `authelia:9091` (the HOME Authelia, on the home container
network, exactly as home's own routes use), same `rewrite /api/verify?rd=https://auth.homelab.example`,
same `X-Forwarded-Method/Uri`, same 4 `Remote-*` copy-headers, same `handle_response` 2xx semantics.
The only diffs are cosmetic (a `subroute` wrapper, a no-op `vars crenel_policy` marker, copy-header
order) and do not affect the auth decision. **So the gate is NOT pointed at a wrong/second Authelia;
it dials the correct home Authelia.** (the maintainer's "maybe there's a vps-edge Authelia" was correctly
disregarded — there is one Authelia, `authelia/authelia:4.39.20`, on LXC 113.)

## Then: a mutation-free direct probe pinned the cause to Authelia's per-host policy

Asking the home Authelia's `/api/verify` directly (forward-auth headers, **no crenel route exposed**):

| `X-Forwarded-Host` → `authelia:9091/api/verify` | before rule | after temp rule | after revert |
|---|---|---|---|
| `crenel-selftest.homelab.example` | **403** (no rule) | **302** → portal | **403** (rule gone) |
| `home.homelab.example` (configured) | 302 | 302 | 302 |
| `dockhand.homelab.example` (configured) | 302 | — | 302 |
| `randomzzz999.homelab.example` (never configured) | **403** | **403** | **403** |

Authelia uses **explicit per-host rules** (`default_policy: deny`, no `*.homelab.example` wildcard —
`randomzzz999` also 403s). That is the entire `403`-vs-`302` story.

## The temporary Authelia change (authorized, minimal, fully reverted)

- **Backed up** `/opt/stacks/authelia/config/configuration.yml` (LXC 113) → `…crenel-trial-bak`,
  sha `7f622e23…` (the restore anchor), `0600`. Edit performed **on LXC 113** so the secret-bearing
  config never transited to the VPS or any log.
- **Inserted** a marker-delimited rule after `home.homelab.example`:
  ```yaml
      # CRENEL-TRIAL-TEMP-BEGIN (temporary 302 demo; remove + restart after)
      - domain: crenel-selftest.homelab.example
        policy: one_factor
      # CRENEL-TRIAL-TEMP-END
  ```
  `authelia validate-config` → exit 0. `docker restart authelia` (#1) → healthy.
- **Re-ran the full crenel trial** (fresh `config-chain-write.json`, responder up, `expose
  crenel-selftest --auth authelia -yes` → read-back ✓ both, verified, exit 0).

## 🎯 The literal 302 — end-to-end through the chain

```
curl https://crenel-selftest.homelab.example/  →  HTTP/2 302
  location:   https://auth.homelab.example/?rd=https%3A%2F%2Fcrenel-selftest.homelab.example%2F&rm=GET
  set-cookie: authelia_session=…;  x-frame-options: DENY;  permissions-policy: …;  referrer-policy: …
  via: 2.0 Caddy + 1.1 Caddy        (front VPS hop + home hop — the full chain)
```
VPS front (FIX-4 TLS forward) → home edge (FIX-3 gate → real `authelia:9091`) → Authelia portal 302.
The crenel gate bytes were identical to the 403 runs; only the Authelia rule changed. `home`
control still 302; 3 prod hosts 200 throughout.

## Full revert + verification (production left exactly as found)

| Check | Result |
|---|---|
| crenel `unexpose` | read-back ✓ both, verified, exit 0 |
| Both caddy edges byte-for-byte | **VPS `43901caf…` / HOME `e509c326…` == Step-1 anchors**, 0/0 crenel `@id` residue |
| Authelia config restored | byte-for-byte from backup → sha **`7f622e23…` == original**, `CRENEL-TRIAL-TEMP` marker count 0 |
| Authelia post-revert probe | `crenel-selftest` → **403** again; `home`/`dockhand` → 302; `randomzzz999` → 403 (no collateral) |
| Authelia container | **healthy**, running; `RestartCount=0` (manual `docker restart` doesn't increment it; bounced 3× total — apply-rule, one accidental no-op, real restore — all healthy) |
| 3 prod hosts | 200 / 200 / 200 |
| caddy RestartCount | VPS 0 / HOME 0, both running; no wedge |
| Home admin on tailnet | refused throughout |
| Responder (`:9999`) | stopped; refused from caddy |
| LXC-113 trial backup | shredded/removed — Authelia config dir back to pristine (only `configuration.yml` + the maintainer's own `.bak`s) |
| Temp files | VPS trial config + helper scripts removed; Mac scratchpad wiped; no secrets printed |

**One honest process note:** the first restore attempt ran `cp`/`sha256sum` on the **pve1 host**
instead of **inside LXC 113** (missing `pct exec 113 --`), so it was a no-op and Authelia briefly
restarted still carrying the temp rule. Caught immediately from the output (`cp: cannot stat …`,
marker count still 2, `crenel-selftest` still 302), re-ran the restore correctly inside the
container, and confirmed the byte-for-byte revert. No crenel route was up during that window
(unexpose had already completed); the only transient was the temp Authelia rule, which was then
removed.

## Status of the headline (RUN 3-RERUN-B)

**The literal `302` is now proven end-to-end on production** — the last symbolic gap from RUN 3 is
closed, and closing it required *only* an Authelia `access_control` rule (an auth-provider change),
with the crenel gate untouched. This is the strongest possible confirmation that crenel's three
fixes (FIX-2 nesting, FIX-3 valid gate dialing the real home Authelia, FIX-4 front-leg TLS) are
correct and that the `403` was always Authelia's by-design per-host deny. All changes — crenel's and
the temporary Authelia rule — were reverted byte-for-byte; production was left exactly as found.

### FINAL STATE addendum (per the maintainer's amendment) — `crenel-selftest` kept as a PERMANENT 302 fixture

After the byte-for-byte revert above (which briefly returned Authelia to pristine), the maintainer amended the
plan: **keep the `crenel-selftest` rule in Authelia permanently** so the host is a reusable self-test
fixture that returns a clean `302`, letting future crenel trials prove the full 302 chain **without
editing Authelia each run**. So the Authelia config was NOT left pristine — the rule was re-added as a
**clean, first-class permanent entry** (no trial-marker comments):

```yaml
    - domain: home.homelab.example
      policy: one_factor

    # crenel self-test fixture (permanent): returns a clean 302 for crenel chain-write trials
    - domain: crenel-selftest.homelab.example
      policy: one_factor
```

- **Record backup kept:** the pre-edit pristine config (sha `7f622e23…`, byte-identical to the
  original pre-trial bytes) is preserved on LXC 113 as
  `/opt/stacks/authelia/config/configuration.yml.bak.20260628-pre-crenel-selftest` (`0600`), alongside
  the maintainer's own `configuration.yml.bak.*` files.
- **Final active Authelia config:** sha `f1c6d250…` = pristine + the single permanent `crenel-selftest`
  rule. `authelia validate-config` → exit 0; `docker restart authelia` → healthy.
- **Verified (direct probe to `authelia:9091/api/verify`):** `crenel-selftest.homelab.example` → **302**
  (`Location: https://auth.homelab.example/?rd=…crenel-selftest…` + `Set-Cookie authelia_session`);
  `home.homelab.example` → 302; `dockhand.homelab.example` → 302; `randomzzz999.homelab.example` → **403**
  (default-deny intact — no collateral, the rule is host-specific).
- **Edges:** both Caddy edges remain **byte-for-byte** at the Step-1 anchors (`43901caf…` / `e509c326…`),
  **0** crenel `@id` residue — the edge teardown was correct and is unchanged by this amendment.

**Net effect:** the ONLY permanent change from this entire trial campaign is one host-specific Authelia
`access_control` rule that makes `crenel-selftest.homelab.example` a permanent, Authelia-recognized
self-test host returning a clean `302`. From now on, a crenel chain-write trial can `expose
crenel-selftest --auth authelia` and the through-chain `curl` will return the literal `302` end-to-end
**without any Authelia edit** — the fixture is in place. Both Caddy edges are byte-for-byte clean;
production is otherwise exactly as found.
