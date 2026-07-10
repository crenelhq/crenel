# Live-proof record — 2026-07-09/10: dual-AdGuard multi-site trial, durability fixes, production cutover

Operator-record for the gated live trials that took the dual-AdGuard multi-site
architecture (docs/REFERENCE-ARCH-split-horizon.md) from BUILT to LIVE-PROVEN,
and ended with Crenel promoted to the production source of truth on the
maintainer's edge. As with the 2026-06-30 record: hostnames, zones, and
addresses are anonymized (`homelab.example`, `smallbiz.example`, RFC 1918 /
RFC 5737 / CGNAT-range placeholders); the command sequences, outputs, and
results are otherwise verbatim. Every mutating step was previewed, confirmed
by the operator at a `[y/N]` prompt, read-back-verified, and reversed to the
captured baseline before the next gate.

## 0. Pre-trial gates (all passed before any write)

- **Code gate:** the dual-AdGuard write-path tests (`internal/core/
  dual_adguard_write_test.go`, `feat/dual-adguard`) — dual same-scope providers,
  instance labels, independent verify/rollback, mid-transaction compensation —
  merged green before the live run.
- **Baseline capture:** both AdGuard rewrite lists exported to files and diffed
  (20 vs 21 entries, zero same-host-different-answer conflicts). Two stale
  rewrites (`hermes`, `terminal` — retired hosts) deleted from both instances
  by the operator before the trial snapshot, per the runbook.
- **Reachability gate (new finding):** the SOT host could not reach the
  tunnel-side AdGuard (`100.100.0.2:3000` timed out; the LAN default gateway
  knows nothing about the overlay range). Fixed with ONE static route on the
  SOT host via the LAN's existing overlay subnet router — no mesh enrollment,
  no tunnel shim — then persisted in `if-up.d`. Generalized as
  docs/REFERENCE-ARCH-split-horizon.md §2.5 ("the Crenel host must reach every
  control plane it manages").

## 1. Coordinated dual-instance expose/unexpose (PROVEN LIVE, 3 cycles)

Config: home edge (Caddy, docker, ssh-exec transport) + `adguard[home]`
(`10.0.0.53`) + `adguard[vps]` (`100.100.0.2`) + surgical Cloudflare on the
shared zone. Disposable host `crenel-fliptest.homelab.example → 127.0.0.1:9099`
(dead on purpose — the trial exercises the control plane, not an app), gated
`--auth authelia`.

Each cycle: one `expose` produced the four-leg plan (edge route + rewrite on
each instance + public record), flagged ABOUT TO GO PUBLIC, applied atomically,
and read-back-verified all four legs independently under their instance labels:

```
read-back ✓ [edge[caddy·caddy]]      … is now reachable
read-back ✓ [cloudflare-api/public]  records present
read-back ✓ [adguard[home]/internal] records present
read-back ✓ [adguard[vps]/internal]  records present
verified: live state matches intent
```

Vantage verification (external to Crenel): both internal resolvers answered the
home edge (`10.0.0.13`) — the coinciding home-resident case — and true public
DNS (checked over DoH to dodge LAN `:53` interception) answered the public edge
(`203.0.113.9`). Three vantages, three correct answers, one command. Each
`unexpose` removed all four legs, read-back-verified absent, and the rewrite
lists matched the captured baseline (wildcard-covered, as expected).

## 2. Seven dogfood findings (the trials' real yield)

The cycles surfaced seven real defects — all deployment-shape issues the
hermetic suite structurally could not catch, all fixed with regression tests
in the same pass (§5m of STATE-OF-CRENEL.md):

1. Persist reload dialed `localhost:2019` → `::1`; the admin API is IPv4-only
   (fix: explicit `--address`).
2. Persist reload ran on the HOST while the admin API lives in the container
   (fix: reload/adapt ride the edge transport; plus the two-channel
   `caddy_persist` config — the boot file is bind-mounted read-only into the
   container, so FILE writes land host-side and validate/reload run
   container-side). The third cycle completed with NO persist warning and the
   route was verified in the host boot file, the container's view, and the
   running config simultaneously — durable persist is LIVE-PROVEN on a
   containerized edge.
3. A forward-auth policy with an authorizer but no verify URI rendered a gate
   that 502'd (fail-open risk); now refused at plan time. With the completed
   policy the live gate answered with the authorizer's own decision.
4. The SOT-host overlay reachability gap (§0 above; topology, not code).
5. Ack markers collided on Caddy's globally-unique `@id` when two hosts shared
   a reason slug (fix: host-qualified markers, legacy form still read).
6. The engine swallowed the driver's real error ("duplicate @id") behind a
   generic refusal (fix: per-edge errors surfaced).
7. The documented `ack <host>/<path>` form was unimplemented and failed
   silently (fix: loud refusal + doc correction).

## 3. Production cutover (2026-07-10)

After the clean third cycle, the operator promoted the dual-instance config and
the current binary to production (backups retained): Crenel is now the SOT for
the multi-site edge — 53 exposures, dual-vantage internal DNS, surgical public
DNS, durable-file persistence. The three hand-written path-scoped API-bypass
routes (the only unparsed carve-outs) were operator-acknowledged with distinct
reasons, after which:

```
Default-deny catch-all: ENFORCED
```

— full coverage, certified default-deny, on the infrastructure Crenel was
built from.

## What this record does NOT claim

- No live Pi-hole trial (fake/fixture-proven only; the fixtures ARE from a real
  v6.4.3 container, but no production Pi-hole has been driven).
- No live multi-zone-provider trial (merged after the cutover; the two-zone
  production config is prepared but not yet applied).
- No MCP-agent live trial, no Tailscale serve write (unchanged from §6).
- The residency selector (vantage-DIVERGENT per-host targets) was not exercised:
  the trial host was home-resident (coinciding targets) by design.
