# Live trial — mixed-vendor atomic coordination (Caddy + Traefik)

**The demo that proves the brand claim: "Every edge in atomic agreement. Verified." — across DIFFERENT vendors.**

- **When:** 2026-06-29
- **Where:** the bench host `crenel-proving` (10.0.0.20) — the standing live bench. Real
  `caddy:2` (admin API 127.0.0.1:2019) + real `traefik:v3.1` (file provider watching
  `/dynamic`, API 127.0.0.1:8080). Throwaway hosts only; no production, no DNS, no auth.
- **Binary:** **STOCK `develop@7054157`, unmodified** (cross-compiled linux/amd64, staged at
  `/opt/crenel-bench/bin/crenel-stock`, removed at teardown). The core proof needs **zero
  code changes** — see the "Separate finding" note below for the one normalize gap surfaced,
  which is decoupled and did NOT gate the trial.
- **Config:** ONE `edges[]` topology with a heterogeneous pair — edge A = caddy (admin API,
  granular), edge B = traefik (file driver + `traefik_api_url` for the merged runtime verify).
  Both edges' `origins` carry the service `mvdemo`, so an expose projects onto BOTH. Caddy
  backend `whoami:80` (caddy net), Traefik backend `whoami:80` (traefik net).
- **Discipline:** backed up Caddyfile / operator.yml / live Caddy admin config with sha256
  anchors; abort-only-on-fail; restored byte-for-byte; bench left exactly as found.

## Verdict

| Claim | Result (stock develop@7054157) |
|---|---|
| crenel expresses a heterogeneous Caddy+Traefik pair in ONE config | ✅ yes — `edges[]` multi-edge, per-edge driver + origins |
| **PART A** — coordinated `expose` lands on BOTH edges, all-or-nothing, read-back-verified on EACH with the REAL runtime verify | ✅ Caddy admin-API read-back + Traefik `/api/http/routers` `enabled` confirm; live 200 on both; exit 0 |
| coordinated `unexpose` across both, verified, both clean | ✅ Caddy→403 / Traefik→404; Caddy admin byte-identical to baseline; Traefik file emptied |
| **PART B** — inject a Traefik-side failure → transaction rolls back **BOTH** edges, Caddy NOT half-applied, honest failure | ✅ **ROLLED BACK**, exit 1, Caddy admin byte-identical to baseline, no residue on either edge |

**Cross-vendor atomic expose works live. The rollback holds when one vendor fails. On the
unmodified develop binary.**

## PART A — coordinated expose + unexpose across Caddy + Traefik

`preview expose mvdemo --auth none` rendered ONE plan spanning both edges, and — note —
declared the default-deny invariant satisfied on every edge from the MODEL state, even though
the Caddy edge's *status display* reads UNKNOWN (the separate finding below):

```
Plan: expose mvdemo (host=mvdemo.bench.local)
  EDGE [caddy-edge·caddy]    + route mvdemo.bench.local -> whoami:80 [auth:none]
  EDGE [traefik-edge·traefik]+ route mvdemo.bench.local -> whoami:80 [auth:none]
  default-deny will remain present on every edge: true
```

`expose mvdemo --auth none --yes`:

```
applied: expose mvdemo (host=mvdemo.bench.local)
  read-back ✓ [edge[caddy-edge·caddy]]    mvdemo.bench.local is now reachable
  read-back ✓ [edge[traefik-edge·traefik]] mvdemo.bench.local is now reachable
      ↳ runtime: traefik API confirms expose for mvdemo.bench.local on the running daemon
  verified: live state matches intent          EXIT=0
```

Independent on-the-wire evidence (not crenel's own report):

- Caddy `:8082` Host=mvdemo → **HTTP 200** (whoami); unrouted host → **403** (edge A genuinely denies on the wire).
- Traefik `:8000` Host=mvdemo → **HTTP 200** (whoami); unrouted host → **404** (Traefik native deny).
- Traefik API: `crenel-mvdemo.bench.local@file status=enabled` — the real daemon accepted+serves it.
- Caddy admin: `@id=crenel-route-mvdemo.bench.local` route ahead of the brownfield `blog3` and the catch-all deny.

`unexpose mvdemo --yes` → both `read-back ✓` + Traefik runtime "confirms unexpose", verified, exit 0.
After: Caddy mvdemo→**403**, Traefik mvdemo→**404**, **Caddy admin config sha == STEP-0 baseline byte-for-byte**
(`eac932b8…`), Traefik `crenel-mvtrial.yml` emptied to `{}`, brownfield `operator.yml` untouched.

## PART B — the rollback proof (one vendor fails)

Same two-edge config, but the **Traefik edge's origin** points at an **invalid target**
(`bad host:80` → `http://bad host:80`, which Traefik rejects: *"invalid character ' ' in host
name"*). Isolated to Traefik — Caddy's origin stays valid. The bad URL passes crenel's own
`validate()` (the loadBalancer has a server), so it only fails at the **real daemon**.

`expose mvdemo --auth none --yes`:

```
ROLLED BACK: expose mvdemo (host=mvdemo.bench.local) — partial apply reverted to prior live state
error: read-back verification FAILED (provider reported success but live state did not change):
  edge[traefik-edge·traefik]: runtime verify FAILED — traefik API does not list an enabled router
  for mvdemo.bench.local — the daemon has not accepted the route (rejected config, or not yet reloaded)
EXIT=1
```

The sequence proven: Caddy applied (route added), Traefik applied (file written, crenel-valid),
then the read-back-verify probed the **real Traefik API**, saw the router never went `enabled`,
flipped the transaction to FAILED, and rolled back **both** edges. The post-state:

- **Caddy admin config sha == baseline `eac932b8…` BYTE-FOR-BYTE** — Caddy was **NOT left half-applied**;
  the side that DID apply was un-applied by the compensating inverse.
- Caddy admin: **no `crenel-route-mvdemo` residue**; Caddy wire mvdemo → **403**.
- Traefik `crenel-mvtrial.yml` → `{}`; Traefik wire mvdemo → **404**.
- Controls healthy throughout: Caddy `blog3`→200, Traefik `blog`→200; `operator.yml` sha unchanged.
- Honest report: **exit 1**, explicit `ROLLED BACK`, a real reason — never a false green.

This is the core "atomic agreement, verified" promise under a genuine cross-vendor partial
failure: the Caddy edge and the Traefik edge move together or not at all, and the verdict is
grounded in each vendor's real runtime (Caddy admin API + Traefik `/api/http/routers`), not in
the apply call's success report. The engine is driver-agnostic (`core/apply.go applyPlanned`
snapshots each participating edge, applies ordered steps, and on any step/verify failure runs the
per-edge compensating inverse in reverse), so the heterogeneous Caddy+Traefik pair works for free.

## Separate finding (NOT a blocker; decoupled, not fixed on this branch)

Setting up the Caddy edge with an honest wire-level default-deny (`:80 { respond 403 }`) showed
that crenel's Caddy `status` *displays* `Default-deny: UNKNOWN (1 unparsed — subroute_not_descended)`
for that edge. Root cause: the canonical Caddyfile default-deny adapts to a **host-less route
whose only handler is a SUBROUTE wrapping `static_response 403`** (Caddy wraps every site block's
directives in a subroute); `normalizeServer` recognizes a *direct* host-less deny but does not
descend the host-less subroute, so it declares it unparsed → the status/coverage line downgrades
to UNKNOWN.

**Why it did NOT block this trial:** the read still sets model-level `DenyCatchAllPresent = true`
for that shape (the undescended subroute is flagged unparsed but is not permissive, so the deny
invariant holds), and `core` `verify()` gates on that model field — not on the status display. So
the coordinated expose verified and the rollback fired correctly on the stock binary, exactly as
shown above. The trial does **not** require edge A to read as default-deny; the apply / read-back /
rollback semantics are what's being proven.

A read-correctness fix for the display (descend the host-less subroute; deny-only keeps the
default-deny, a permissive forward marks fail-open, anything ambiguous stays declared-unparsed) is
written, tested (RED→GREEN, byte-faithful fixture), and parked on the separate branch
**`feat/caddy-hostless-subroute-deny`** (commit `0e628af`) for review — it is **out of scope for
this trial** and not part of this branch. Worth noting it also affects the crenel bundle's baked
`:80 { respond "…" 403 }` default-deny reading (follow-up chip filed).

## Teardown / hygiene

- Caddyfile restored from anchor (`34e83378…`); `caddy reload`; **live admin config back to the
  original anchor `1dc642d3…` byte-for-byte** (the bench's original permissive default vhost).
- `crenel-mvtrial.yml` removed → Traefik `/dynamic` = `operator.yml` only; Traefik API back to its
  baseline 4 routers (api/blog/dashboard/secure-app).
- All trial artifacts removed (`_mvtrial`, `_mvtrial-backup`, `bin/crenel-stock`); `bin/` = as found
  (`crenel`, `crenel-fixed`, `crenel-v2`).
- 10 bench containers Up 11h (no restarts — `caddy reload` not container bounce); controls 200.
- This report is the entire diff of branch `feat/mixed-vendor-trial` (doc-only, off stock
  develop@7054157; pushed, **NOT merged**). The decoupled normalize fix lives on
  `feat/caddy-hostless-subroute-deny`.
