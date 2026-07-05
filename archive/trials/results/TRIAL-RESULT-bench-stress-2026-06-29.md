# Live trial — bench stress-test (resume): expose/unexpose, wedged-admin, drift→reconcile, ephemeral-durability, cross-edge atomic rollback

**Five operator-grade beats run live against real Caddy + Traefik + nginx, every mutating beat byte-for-byte restored, abort-on-fail.**

- **When:** 2026-06-29
- **Where:** the bench host `crenel-proving` — the standing live bench (`ssh root@proxmox 'pct exec 110 -- …'`).
  Real `caddy:2` (admin API 127.0.0.1:2019, booted from a read-only `/etc/caddy/Caddyfile`),
  real `traefik:v3.1` (file provider watching `/dynamic`, API 127.0.0.1:8080), real
  `nginx:1.27` (file driver). Throwaway hosts only; no production, no DNS, no real auth backend.
- **Binary:** rebuilt from **`develop@fe9a749`** (the stale `crenel-dev` was `d3e1e1f`).
  Cross-compiled `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, `version=v0.3.0-6-gfe9a749`,
  sha256 `f35e7724…`, deployed to `/opt/crenel-bench/bin/crenel-dev`. No source changes — every
  beat runs on the stock develop build.
- **Discipline:** three sha256 restore anchors captured up front and re-verified before the run,
  after **every** mutating beat, and at teardown. Sole executor. Abort-only-on-fail. Bench left
  byte-for-byte as found.
- **Already passed before this resume (not redone):** unknown-service error; public-without-auth refusal.

## Restore anchors — identical before and after the entire run

| Anchor | sha256 (truncated) | start | after every beat + teardown |
|---|---|---|---|
| Caddy live admin config (`GET :2019/config/`) | `1dc642d3…` | ✅ | ✅ |
| Traefik `dynamic/operator.yml` | `4f10f93e…` | ✅ | ✅ |
| nginx `conf.d/crenel.conf` | `caa588ec…` | ✅ | ✅ |

A byte-faithful local backup of all three was taken first; each backup re-hashed to its anchor,
giving a verified recovery path (`POST /load` for Caddy, file write for Traefik/nginx) that was
never needed.

## Verdict

| Beat | Claim | Result (develop@fe9a749) |
|---|---|---|
| 1 | Real `expose → read-back → unexpose` on a throwaway host, restored byte-for-byte | ✅ granular expose `read-back ✓` + `verified`; unexpose returned Caddy admin to `1dc642d3…` **byte-for-byte** |
| 2 | Wedged admin never hangs — clean bounded timeout | ✅ read path errored at **10.02s** (`10s` read bound), write path at **10.01s**, exit 1 (not 124); no mutation; real admin untouched |
| 3 | `drift` detects divergence; `reconcile` fixes + read-back-verifies | ✅ `drift` → `missing_route`, exit 1; `reconcile` → fixed 1, both edges `read-back ✓`, verified; `drift` → none, exit 0 |
| 4 | crenel warns when a write won't survive a restart — and the warning is **true** | ✅ ephemeral persist warning on the Caddy write; a real control-plane restart **dropped** the route exactly as warned (Traefik/nginx report `durable-config`, no warning) |
| 5 | Inject a failure on one edge of a 2-edge expose → **BOTH** roll back | ✅ Caddy applied then traefik failed → `ROLLED BACK`, exit 1, Caddy back to `1dc642d3…` byte-for-byte, no half-apply; positive control proves the same expose lands on both when traefik can write |

**Finding logged (not fixed here):** the Caddy bench edge's host-less `static_response 200`
catch-all reads as Default-deny **UNKNOWN** (`subroute_not_descended`) — honest + safe, with a
concrete classify-as-fail-open enhancement proposed below.

---

## Beat 1 — expose → read-back → unexpose (throwaway host `demo3`, Caddy)

`demo3` is in the Caddy edge's `origins` but not currently exposed — the ideal throwaway. Two
safety gates fired first, each leaving the admin config at the anchor (`1dc642d3…`):

```
# preview expose demo3            → read-only plan, admin still 1dc642d3…
# expose demo3 (no auth)          → error: refusing to expose demo3.bench.local PUBLIC with no auth
# expose demo3 --auth none        → aborted: no changes applied
#   error: refusing full-config load on an edge with 1 unparsed construct(s) — a full replace
#   would silently drop them and could falsely certify default-deny; use --granular
```

The second refusal is defense-in-depth tied to the finding below: rather than risk dropping the
unparsed host-less subroute via a full-config replace, crenel refuses and points at `--granular`.
The granular (additive) apply then succeeded:

```
applied: expose demo3 (host=demo3.bench.local)
  read-back ✓ [edge[caddy·caddy]] demo3.bench.local is now reachable
  verified: live state matches intent
  ⚠ persist (durability) warning: … EPHEMERAL (ephemeral-admin) — it will NOT survive a control-plane restart
# admin hash now 4adb2d61… (drifted from anchor, as expected)
# unexpose demo3 --granular →
applied: unexpose demo3 (host=demo3.bench.local)
  read-back ✓ [edge[caddy·caddy]] demo3.bench.local is no longer exposed
  verified: live state matches intent
# admin hash back to 1dc642d3… — BYTE-FOR-BYTE; host-less subroute index restored to routes[1]
```

All three anchors re-verified intact.

## Beat 2 — wedged admin never hangs

A black-hole listener (`python3` socket that **accepts but never responds**) was stood up on
`127.0.0.1:2999` and crenel pointed at it with `-admin-url` — wedging the admin API **without
touching the real Caddy admin (2019)**. crenel's Caddy driver uses per-operation context
deadlines (`readTimeout=10s`, `writeTimeout=60s`), not an unbounded client.

```
# READ path (status):
error: read live edge state (caddy): caddy admin GET /config/: … caddy admin API unresponsive
  (bounded timeout exceeded) after 10s: the admin API did not respond — it may be mid-reload or
  wedged. If it stays unresponsive, recover the edge (e.g. `docker restart caddy-edge`) …
CRENEL_EXIT=1   ELAPSED=10.02s      # not 124 — crenel self-terminated, no hang

# WRITE path (expose) against the same wedge:
aborted: no changes applied
error: … caddy admin API unresponsive (bounded timeout exceeded) after 10s …
CRENEL_EXIT=1   ELAPSED=10.01s      # fails closed at the read stage, no mutation
```

The real Caddy admin stayed at `1dc642d3…` throughout. Wedge torn down; port freed; temp files removed.

## Beat 3 — drift → reconcile

crenel's reconcile derives the canonical exposed set **from live across all edges** (no stored
SOT), so drift requires ≥2 edges fronting the same service; and `verifyReconcile` requires
`DenyCatchAllPresent` on every edge. Of the bench's three edges only **Traefik** reads
deny-clean (Caddy = UNKNOWN per the finding; nginx = fail-open). The traefik driver reads live
state **from its config file** (the API is only for runtime-verify), so a clean, converging
demonstration was built from **two throwaway dynamic files** (`opA.yml`, `opB.yml`) served by the
same Traefik — leaving the anchor `operator.yml` **untouched**:

```
# 2-edge config (traefik-a → opA.yml, traefik-b → opB.yml), both front service "shared".
# expose shared --auth none → atomic, read-back ✓ on BOTH with runtime API confirm; drift = none.
# KNOCKOUT: overwrite opB.yml back to minimal (simulate a half-applied / hand-edited edge).

# drift:
  drift [missing_route] shared.bench.local @ traefik-b — exposed elsewhere but missing from edge
    "traefik-b" which also fronts "shared"
  EDGE [traefik-b·traefik]  + route shared.bench.local -> whoami:80
error: drift detected: 1 item(s) diverge from the canonical exposed set (run `reconcile`)
DRIFT_EXIT=1

# reconcile:
reconciled: fixed 1 drift item(s)
  read-back ✓ [edge[traefik-a·traefik]] consistent with the canonical exposed set
  read-back ✓ [edge[traefik-b·traefik]] consistent with the canonical exposed set
  verified: live state matches the canonical exposed set      RECONCILE_EXIT=0

# drift (again): (no drift — already consistent)  DRIFT_EXIT=0
```

Teardown: `unexpose shared` (read-back ✓ both, runtime-confirmed), throwaway files removed →
`/dynamic` = `operator.yml` only, Traefik API back to its 4 baseline routers, anchor `4f10f93e…`
untouched the entire beat. All three anchors re-verified.

## Beat 4 — ephemeral-durability warning (and proof it is true)

The Caddy edge is `ephemeral-admin`; Traefik and nginx are `durable-config`. Caddy boots from a
read-only Caddyfile (`caddy run --config /etc/caddy/Caddyfile`) that reproduces the anchor
deterministically, so a control-plane restart is anchor-safe **and** proves the warning.

```
# status (caddy): Durability: ephemeral-admin ⚠ writes are LIVE-only — a control-plane restart DROPS them
# expose demo3 (granular):
  read-back ✓ … demo3.bench.local is now reachable    verified: live state matches intent
  ⚠ persist (durability) warning: edge[caddy·caddy]: write applied + verified LIVE but this edge
    is EPHEMERAL (ephemeral-admin) — it will NOT survive a control-plane restart …
    (the running state is correct + verified; on-disk persistence did not complete)
# demo3 LIVE (hash 4adb2d61…).  docker restart caddy-caddy-1 → admin back in 2s.
# AFTER RESTART: demo3 GONE (only blog3 remains) — dropped exactly as warned;
#   admin hash == 1dc642d3… (durable Caddyfile reloaded → anchor restored byte-for-byte).
```

The same expose on Traefik (beat 3) and nginx emits **no** such warning — crenel distinguishes
the ephemeral admin from durable file edges and warns only where a write truly won't survive.

## Beat 5 — cross-edge atomic rollback (Caddy + Traefik)

Traefik has no settings file in its bench dir, so it was wired into a 2-edge config with
`traefik_api_url: http://127.0.0.1:8080` + a dynamic path. Caddy is wired first (so it applies
first and is the edge that must be rolled back). The failure is injected on the Traefik edge by
pointing its `traefik_config_path` at a path whose **parent dir does not exist** —
`read()` treats a missing file as empty (graceful), but `write()` (`os.WriteFile`, in place) hits
`ENOENT` even for root.

```
# expose rollbacksvc --granular --auth none (caddy first, traefik-fail second):
ROLLED BACK: expose rollbacksvc (host=rollbacksvc.bench.local) — partial apply reverted to prior live state
error: apply edge[traefik-fail·traefik]: write dynamic-config …/nope/opFail.yml:
  open …/nope/opFail.yml: no such file or directory      EXPOSE_EXIT=1

# POST: caddy admin == 1dc642d3… BYTE-FOR-BYTE (it HAD applied, then was rolled back);
#       traefik operator.yml == 4f10f93e…; rollbacksvc ABSENT on caddy (no half-apply);
#       …/nope dir never created.
```

**Positive control** (same config, Traefik pointed at a writable `opOK.yml`): the identical expose
**succeeds on both** edges — `read-back ✓` on Caddy and on Traefik (runtime API confirmed) — proving
Caddy's write in the failure case was real and the rollback genuinely undid it. `unexpose` cleared
both; throwaway file removed.

```
applied: expose rollbacksvc (host=rollbacksvc.bench.local)
  read-back ✓ [edge[caddy·caddy]]        rollbacksvc.bench.local is now reachable
  read-back ✓ [edge[traefik-ok·traefik]] rollbacksvc.bench.local is now reachable
      ↳ runtime: traefik API confirms expose for rollbacksvc.bench.local on the running daemon
  verified: live state matches intent     EXPOSE_EXIT=0
```

The Caddy edge and the Traefik edge move together or not at all; the verdict is grounded in each
vendor's real runtime, and an honest `ROLLED BACK` + exit 1 is reported on failure — never a false green.

---

## Finding (logged, NOT fixed on this branch)

**Caddy host-less `static_response <400` reads as Default-deny UNKNOWN instead of explicit FAIL-OPEN.**

The bench Caddy edge's `srv0.routes[1]` is the Caddyfile site block `:80 { respond "bench-caddy
default-vhost" }`, which Caddy's adapter emits as a **top-level host-less subroute** wrapping a
`static_response` with **no `status_code` (⇒ HTTP 200)**. crenel `status` reports:

```
Default-deny catch-all: UNKNOWN (config not fully parsed — 1 unparsed)
⚠ Not understood (1):
  apps.http.servers.srv0.routes[1]  subroute_not_descended —
    top-level host-less subroute not descended (no host to attribute its leaves to)
```

`normalizeServer` → `classifyHostlessSubroute` (internal/drivers/edge/caddy/caddy.go) already
classifies two host-less-subroute shapes and leaves the rest declared-unparsed:

- host-less **reverse_proxy** forward ⇒ `permissive` (fail-open, `DenyCatchAllPresent=false`);
- `static_response` with **status ≥ 400** / `abort` ⇒ `denyOnly` (keeps the default-deny);
- **anything else** (incl. a `static_response` with status **< 400**) ⇒ both false ⇒ **declared unparsed ⇒ UNKNOWN**.

**Why it is honest + safe today:** UNKNOWN does not certify default-deny, so `core` `verify()`
gates correctly on the model field and nothing is mis-applied — beats 1, 4, and 5 all exposed on
this edge without issue, because Apply does not require a clean deny (only `reconcile` does, which
is why beat 3 deliberately used the deny-clean Traefik edges).

**Candidate enhancement (worth doing, low-risk, symmetric):** classify a host-less subroute whose
only leaf is a `static_response` (or `respond`) with status **< 400** as **explicit fail-open**
(`permissive=true` ⇒ `DenyCatchAllPresent=false`) — the mirror of the existing `≥400 ⇒ deny`
rule. A non-deny terminal that returns a body to *every* unmatched host *is* fail-open; promoting
it from UNKNOWN to an actionable `⚠ FAIL-OPEN` (the same banner the nginx edge already shows) is
strictly more informative and still byte-faithful. Anything genuinely ambiguous (nested host
matcher, deeper subroute, unmodeled handler) should keep its declared-unparsed honesty.

This is the **fail-open sibling** of the deny-side read-correctness work parked on
`feat/caddy-hostless-subroute-deny` (`0e628af`); it also affects how the crenel **bundle's** baked
default-vhost reads. Reviewer's call whether to fold it into that branch.

## Teardown / hygiene

- All three anchors identical to start: Caddy `1dc642d3…`, Traefik `4f10f93e…`, nginx `caa588ec…`.
- No leftover temp files (`/tmp/crenel-*`, `/tmp/op*.yml`, `/tmp/wedge*` all clean); Traefik
  `/dynamic` = `operator.yml` only; bench dirs unchanged.
- 10 bench containers healthy. `caddy-caddy-1` shows a fresh uptime — the **intentional, anchor-safe**
  restart in beat 4 (the ephemeral-durability proof); it reloaded the durable Caddyfile to the
  exact baseline. No other container was bounced.
- `bin/crenel-dev` = the rebuilt `develop@fe9a749` (`v0.3.0-6-gfe9a749`, sha `f35e7724…`), as
  requested in STEP 0; `crenel` / `crenel-fixed` / `crenel-v2` untouched.
- This report is the entire diff of branch `trial/bench-stress-2026-06-29` (doc-only, off
  `develop@fe9a749`; pushed, **NOT merged**).
