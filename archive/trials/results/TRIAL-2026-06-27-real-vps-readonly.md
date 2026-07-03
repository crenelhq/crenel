# Read-only trial vs the REAL VPS edge — 2026-06-27

A strictly **read-only** observation run of `develop` (~ea0fe7e) against the maintainer's
live `vps-edge` Caddy edge (loopback admin API `127.0.0.1:2019`, the
custom xcaddy build: crowdsec + cloudflare-DNS, `caddy-edge` container, two
wildcard subroute vhosts + unmanaged Authelia). **No mutations.** Only `status`,
`audit`, `drift`, and `import --dry-run` were run — all GET-only.

Binary: `bin/crenel-linux-arm64` (linux/arm64 cross-compile). Config:
`trial-2026-06-27/config.json` on the VPS (admin loopback, `granular_apply`,
`zone: homelab.example`, real origins, `auth_policies.authelia` →
`172.18.0.6:9091`; **no** `caddy_persist_path` so no write path can fire; DNS off).

## Proof nothing changed
- Live config **byte-for-byte identical** before vs after:
  `sha256 a6b307f82d9cbd0a47c9f8087207be0e1f08bd5dfee6523a32d53b4a264dc74c`
  (canonicalized `GET /config/`, both snapshots).
- `caddy-edge` **RestartCount=0**, `StartedAt` unchanged, `Status=running`.
- Prod still healthy: `auth.homelab.example` 200, `git.homelab.example` 200.

## What it read (captured output)

```
$ crenel status
Edge [caddy·caddy]
  Default-deny catch-all: PRESENT
  Exposed (2):
    *.smallbiz.example               -> (subroute)
    *.homelab.example                 -> (subroute)

$ crenel audit
✓ [OK] default-deny holds: unmatched hosts get an implicit 404 (or explicit deny)
▲ [WARNING] host *.homelab.example is PUBLIC with no forward-auth policy …
▲ [WARNING] host *.smallbiz.example is PUBLIC with no forward-auth policy …
✓ [OK] 2 host(s) exposed across 1 edge(s)

$ crenel drift          # exit 0
  (no drift — already consistent)

$ crenel import --dry-run   # exit 0
  (nothing to adopt — no unmanaged routes in the managed domain)
```

## Honest assessment

**Correct & safe (the load-bearing things worked):**
- **Default-deny read correctly as PRESENT/ENFORCED** even though the edge has no
  explicit host-less catch-all — it routes wildcards into subroutes and aborts.
  `normalize` treats that as default-deny satisfied (not a false fail-open). This
  is exactly the `seed-subroute-prod.json` case it was built for.
- **Read-only discipline held byte-for-byte.** No reload storm (pure GETs), no
  restart, prod untouched.
- **`import` correctly refused** to touch the wildcard subroutes and the Authelia
  vhost — they fall outside the managed domain (`service ∉ origins`). Safe
  brownfield posture confirmed.
- The custom build's `crowdsec`/`tls` apps were ignored cleanly; no confusion.

**Misreads / model-vs-reality gaps (the real findings):**
1. **~25 real vhosts collapse to 2 wildcard entries.** `normalize` walks only the
   **top-level** `srv0.routes` (the two `*.x` wildcards) and never descends. The
   real per-host routes (vault, git, photos, jellyfin, auth-vps, …) are nested two
   levels deep (`wildcard → subroute → per-host → subroute`), so `status` shows
   `*.smallbiz.example`/`*.homelab.example → (subroute)` and nothing per-service.
   "What is exposed right now" answers 2 opaque wildcards, not the ~25 reachable
   services.
2. **`import` is a no-op on this topology.** The only routes crenel sees are the
   wildcards (`service "*"`, not an origin), so there is nothing in the managed
   domain to adopt — even with all 19 real services in `origins`. The headline
   brownfield-adoption feature never engages with his actual config shape.
3. **Auth detection can't fire here.** His VPS edge carries **no**
   `forward_auth`/`authentication` handler at all — auth is enforced one hop
   downstream at the home edge (`10.0.0.13:443`). So `(detected)` recognition has
   nothing to recognize, the `auth_policies` mapping is inert for reads, and
   `audit` flags BOTH wildcards `public_without_auth` — true at the VPS layer but
   misleading, since many of those hosts ARE authenticated downstream. crenel has
   no model for "auth enforced at a different edge in the chain."
4. **Two-zone edge vs single `zone`.** The edge fronts both `*.homelab.example` and
   `*.smallbiz.example`; crenel models one `zone`. It coped (lists both opaque
   wildcards) but per-service derivation/DNS assume one zone.

**Highest-leverage fix:** make the Caddy `normalize` **recurse into subroutes** to
enumerate per-host leaf routes (host + real leaf `reverse_proxy` dial + any nested
auth handler). That single change turns the 2-wildcard view into the real
~25-service view and makes `status`/`audit`/`import` work at service granularity on
nested edges like this one — without changing the (already-correct) default-deny
reading.

VPS artifacts: `~/crenel-test/trial-2026-06-27/{config.json,before.json,after.json}`.

## Resolution (follow-up, fakes/fixtures only — no live mutation)

- **Finding 1 + 2 (nested subroutes / import no-op) — FIXED.** The Caddy
  `normalize`/`Adopt` now RECURSE through nested `subroute` handlers
  (`collectLeaves`), enumerating each per-host LEAF with its real host, real leaf
  dial, ownership, and any nested auth handler. `status` enumerates the real
  per-service view; `import --dry-run` sees the adoptable per-host set; the
  default-deny reading is unchanged. Fixture `nested-subroute-prod.json` mirrors the
  real shape; see BUILD_LOG "TRIAL-FIX / NEST1" and DESIGN.md "Caddy edge driver".
- **Finding 3 (auth enforced downstream) — MITIGATED + scoped.** A per-edge
  `auth_downstream` attribute marks an edge as fronting a downstream edge: it
  suppresses the (now-spurious) `public_without_auth` warning and labels those hosts
  `auth: downstream`. The full chain-aware projection is scoped as follow-on in
  DESIGN.md "Chain topology". See BUILD_LOG "TRIAL-FIX / CHAIN1".
- **Finding 4 (two-zone edge vs single `zone`) — documented, follow-on.** Per-host
  derivation/DNS still assume one zone; the second wildcard zone's leaves are
  enumerated in `status` but not adoptable under a single-zone domain.

## v0.1.0 read-only re-trial (2026-06-27, the v0.1 cut + install) — 2 NEW misreads, FIXED in v0.1.1

Installing the tagged **v0.1.0** binary read-only on the same edge (config at
`~/.config/crenel/config.json`, `auth_downstream: true`) read the per-host services
correctly (NEST1 recursion works) and the auth-downstream suppression worked
(no false `public_without_auth`) — but surfaced two MORE normalizer misreads the
older trial's config shape had masked. Both are MISREAD-↓-by-omission; both fixed in
**v0.1.1** (impl + `grouped_multihost_test.go`, green/race-clean):

1. **Grouped multi-host route → only first host read.** His edge groups vhosts that
   share the downstream backend into single routes (`host:[auth,books,git,…]` — one
   16-host group on `*.homelab.example`, one 7-host group on `*.smallbiz.example`).
   `normalize` took `Host[0]` only, so `status` listed **9 of ~30** reachable
   services and silently dropped ~21 (not even declared unparsed). **Fix:**
   `hostMatches()` enumerates every co-matched host.
2. **`abort:true` catch-all not recognized as a deny.** His per-zone close is
   `{"handler":"static_response","abort":true}` (no `status_code`); `isDeny` matched
   only `status_code>=400`, so it read as an unmodeled handler → 2 unparsed →
   default-deny **falsely UNKNOWN** + coverage INCOMPLETE. **Fix:** `isDeny` honors
   `abort`; `collectLeaves` returns `resolved` so a deny-only subroute isn't flagged
   opaque.

After v0.1.1 the same edge reads correctly: **~30 services enumerated, 0 unparsed,
default-deny ENFORCED**, auth-downstream suppression intact. Proven byte-for-byte
unchanged across BOTH the v0.1.0 and v0.1.1 read-only runs (config sha256 identical,
`caddy-edge` RestartCount=0, prod `auth.homelab.example` 200).
