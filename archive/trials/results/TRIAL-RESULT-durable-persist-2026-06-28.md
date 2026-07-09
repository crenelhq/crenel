# Live-trial result — durable home-edge persist (restart-survival PROVEN)

> **Executed 2026-06-28 ~20:05–20:16 UTC. GO'd by the maintainer (option A). The durable write
> landed on the real home edge and SURVIVED a `docker restart caddy`; production restored
> byte-for-byte. One real design finding: `unexpose` of a durable-persisted route (the
> teardown half) — see §6.**
>
> Sole executor, no sub-agents. Binary built from `feat/durable-home-persist` @ `a4a0f63`
> (10,731,618 bytes), run FROM THE MAC over `ssh root@pve1 → pct exec 113 → …`. TS
> `20260628T200507Z`. Backups (gitignored): `live-backup/durable-persist-20260628T200507Z/`.

---

## 0. Headline

- **The durable write landed:** `expose crenel-durable-test --auth none --yes` against the
  home edge → applied, **read-back ✓**, verified, exit 0, **no persist warning** (the
  durable-file reconcile succeeded). The route landed LIVE (admin) AND on-disk as a per-host
  handle **INSIDE the `*.homelab.example` wildcard** — NO shadow top-level site, operator
  bytes byte-identical outside crenel's region.
- **THE RESTART-SURVIVAL PROOF:** after a full `docker restart caddy`, the trial host
  **still served HTTP 200 / 56,334 bytes** (the homepage backend) — it came from the
  Caddyfile, not ephemeral admin state. Pre-expose it was 0 bytes (wildcard deny); an
  ephemeral admin-only write would have been wiped by the restart. **Durability proven.**
- **Production restored byte-for-byte:** final Caddyfile sha == the pre-trial anchor
  (`eac4c45a…`); live admin host set back to 51 (== pre-trial); zero crenel residue;
  caddy RestartCount 0; conf dir exactly as found.
- **One finding (teardown):** crenel's `unexpose` rolled back cleanly instead of removing
  the route, because the durable persist's reload makes the live route **Caddyfile-owned
  (no `@id`)** and `unexpose` deletes by `@id` BEFORE it would clear the Caddyfile. Teardown
  was completed via the byte-for-byte anchor restore. The expose path is proven; the
  unexpose path needs a host-match/ordering fix (§6) — the next "TRIAL-FIX".

## 1. The persistence model (verified live, read-only)

`docker inspect caddy` → `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`,
**no `--resume`** (admin writes ephemeral); Caddyfile bind-mounted **read-only** from
`/opt/stacks/caddy/conf` (the home-edge host) into the container. `crenel status` declared, LIVE:

- ephemeral config (no `caddy_persist`): `Durability: ephemeral-admin ⚠ writes are
  LIVE-only — a control-plane restart DROPS them`.
- durable config (`caddy_persist`): `Durability: durable-file (writes survive a restart)`.

Both read 51 services, default-deny ENFORCED. The persistence-model net is live-correct.

## 2. Pre-flight (all read-only; production untouched)

| Anchor | Value |
|---|---|
| Caddyfile (host `/opt/stacks/caddy/conf/Caddyfile`) | sha `eac4c45a…`, 8755 B, 278 lines |
| Live admin JSON (`GET /config/`) | sha `e509c326…`, 24877 B, **51 hosts** |
| `caddy adapt` baseline | 24877 B → host set |
| caddy container | RestartCount 0, Running, Started `2026-06-27T22:00:48Z` |

- **Operator backup** created on the home-edge host: `Caddyfile.bak-crenel-durable-trial-<TS>` (sha == live).
- **BLOCKING drift check** (the key safety gate I added): live admin host set **== Caddyfile-
  adapted host set** (51 == 51, sets equal, **zero drift**). A durable reload/restart re-derives
  from the Caddyfile, so this proves no live-only route would be clobbered. **PASS.**
- Trial host `crenel-durable-test.homelab.example` **absent** (no conflict/shadow); **zero**
  crenel `@id` residue (clean start).
- Pre-expose reachability (from inside the container, SNI `--resolve` to `127.0.0.1:443`):
  trial host **0 bytes** (wildcard fall-through deny); controls git 200, files 200,
  jellyfin 302; backend `homepage:3000` serves 56,334 bytes.

## 3. The durable write (the only mutations: 1 expose + 2 restarts + 1 restore)

`crenel -config cfg-durable.json expose crenel-durable-test --auth none --yes`:

```
applied: expose crenel-durable-test (host=crenel-durable-test.homelab.example)
  read-back ✓ [edge[caddy·caddy]] crenel-durable-test.homelab.example is now reachable
  verified: live state matches intent
```

Post-write assertions (pre-restart):

- **Live:** route present in `GET /config/`.
- **On-disk:** the crenel region landed at Caddyfile lines 238–243, **INSIDE** the
  `*.homelab.example` site: `@crenel_crenel_durable_test_homelab_example host …` +
  `handle { reverse_proxy homepage:3000 }`. **NO** top-level `crenel-durable-test… {` site.
- **Byte-faithful:** with the crenel region stripped, the post-expose Caddyfile is
  **byte-identical to the anchor** (`region-stripped == anchor: True`).
- **Functional:** trial host now serves **HTTP 200, 56,334 bytes, "homepage" signature**
  (was 0 bytes pre-expose).

The reconcile ran the full pipeline over the two exec channels (file→the home-edge host host,
caddy→container): stage candidate → `caddy validate` → `caddy adapt` cross-check → atomic
`mv` commit → `caddy reload`. No warning, no rollback.

## 4. THE restart-survival proof

`docker restart caddy` (Started → `2026-06-28T20:13:11Z`, RestartCount 0 — a manual restart
doesn't increment it). Admin came back HTTP 200. After the restart:

```
POST-RESTART crenel-durable-test.homelab.example  -> HTTP 200 ; body 56334 bytes   <-- SURVIVED
POST-RESTART git.homelab.example                  -> HTTP 200 ; body 14258 bytes
POST-RESTART files.homelab.example                -> HTTP 200 ; body 5647 bytes
POST-RESTART jellyfin.homelab.example             -> HTTP 302 ; body 0 bytes
```

The trial host survived a full control-plane restart because it lives in the on-disk
Caddyfile. **This is the durable-persist proof, end-to-end on production.**

## 5. Teardown (byte-for-byte restore)

1. Captured post-restart admin (record). Observed `crenel unexpose crenel-durable-test
   --yes` → **ROLLED BACK**: `read-back verification FAILED … route still present` (see §6).
   The rollback was a clean no-op (Caddyfile still sha `98366a08…` = post-expose, route up,
   **no half-state**).
2. **Byte-for-byte restore**: `cp Caddyfile.bak-crenel-durable-trial-<TS> Caddyfile` →
   sha back to `eac4c45a…` → `caddy reload --config /etc/caddy/Caddyfile` (adapted cleanly).
   Live admin: trial host gone (count 0).
3. Final `docker restart caddy` → admin 200 → trial host **0 bytes** (denied again); controls
   git 200/14258 B, files 200/5647 B, jellyfin 302 — identical to the pre-trial baseline.

## 5a. Final clean-state confirmation

- Caddyfile FINAL **== ANCHOR byte-for-byte** (sha `eac4c45a…`).
- Live admin host set **== pre-trial** (51 == 51, sets equal); `crenel-durable-test` absent.
- **Zero crenel residue:** 0 `crenel-route` `@id` in admin, 0 `crenel-managed` region in the
  Caddyfile, 0 `crenel-durable-test` references anywhere.
- caddy RestartCount 0, Running.
- My trial `.bak` (and any `.crenel-candidate`/`.crenel-commit`) removed from the home-edge host — conf
  dir exactly as pre-trial. No DNS was touched (none configured). No auth/Authelia touched.

## 6. Finding — `unexpose` of a durable-persisted route — **FIXED (TRIAL-FIX-DURABLE-1, commit `81ef895`)**

> **Resolved in the build before any re-trial.** Durable unexpose now deletes by host-match
> (no `@id` dependency), gated to durable-file edges and short-circuited when the `@id`
> delete sufficed (non-durable behavior byte-for-byte unchanged); and the pre-flight drift
> check is folded into the reconciler (no-drift-loss gate). A fake modelling the post-reload
> `@id`-less nested route reproduces the rollback (proven RED with the sweep disabled, GREEN
> with it). See the re-trial plan (TRIAL-PLAN-durable-persist.md §4a). Original finding below.


**What:** after the durable persist's `caddy reload`, the live route is re-derived from the
Caddyfile, which carries **no JSON `@id`** marker (a Caddyfile `handle` block has none). So
the live route is effectively **Caddyfile-owned / unmanaged-looking**. crenel's `unexpose`
Apply path does an admin **delete-by-`@id`** (`/id/crenel-route-<host>`) FIRST, then
read-back-verifies, and only persists (clears the Caddyfile region) AFTER a successful
verify. With no `@id`, the delete is a no-op, the route stays live, read-back fails, and the
op **rolls back** — never reaching the region-clear. (The expose path is unaffected and is
fully proven; this is purely the teardown half, and it failed SAFE — clean rollback, no
half-state, no production left dirty.)

**Why the unit suite missed it:** `persist_caddyfile_test.go`'s unexpose-clears test calls
`Persist` directly with an empty managed set (proving the region clears). The LIVE flow goes
through Apply+verify FIRST, which the @id-less route fails — the same class of gap as the
chain-write trial's live-only findings (a fake round-trips state a real reload re-derives).

**Proposed fix (TRIAL-FIX-DURABLE-1), to land before a re-run:** on a `durable-file` edge,
make unexpose teardown Caddyfile-aware. Options (pick the cleanest):
- (a) Delete the live route by **host match** when no `@id` is found (the route is ours by
  position in our region), then persist-clear + reload; OR
- (b) For a durable-file edge, run the **region-clear + reload FIRST** (persistInSite with the
  host removed), then read-back-verify against the reloaded state — so the source-of-truth
  edit drives the removal and verify confirms it. This mirrors the expose ordering and makes
  the Caddyfile authoritative on both verbs.
Plus a live-faithful test: a fake whose granular insert + reload **drops the `@id`** (as real
caddy does), so the suite reproduces the rollback before the fix.

**Net:** durable EXPOSE + restart-survival is proven on production; durable UNEXPOSE needs
the above fix. Teardown for this trial used the byte-restore, leaving production pristine.

## 7. Stop conditions

None tripped. 3 prod hosts healthy throughout (200/200/302), caddy RestartCount 0 start→finish,
home admin `127.0.0.1:2019` never published (reached only via the ssh-exec chain). The one
"failure" (unexpose rollback) was a SAFE read-back refusal that changed nothing — exactly the
invariant working as designed. Production ends byte-for-byte as found.

---

## 8. RE-TRIAL — the FULL cycle through crenel (TRIAL-FIX-DURABLE-1)

> **Executed 2026-06-28 ~21:12–21:18 UTC. GO'd by the maintainer. The full
> expose → restart → UNEXPOSE-THROUGH-CRENEL → restart cycle PASSED end-to-end on the real
> home edge — the unexpose VERIFIED and removed (no rollback, no manual restore), and the
> Caddyfile returned to the byte-for-byte anchor BY CRENEL.** Fixed binary from branch tip
> `5183790` (sha `287d568f…`), same access model (Mac → `ssh root@pve1 → pct exec 113`),
> TS `20260628T211207Z`. Backups: `live-backup/durable-persist-recycle-20260628T211207Z/`.

**Pre-flight (clean, exactly where the first trial left it):** Caddyfile anchor `eac4c45a…`
(8755 B) and live admin `e509c326…` (24877 B) — byte-identical to the first trial's anchors.
Drift check PASS (51 == 51 hosts, sets equal). Trial host absent, zero `crenel-route` residue.
caddy RestartCount 0. `status` → `Durability: durable-file (writes survive a restart)`.

| Step | Action | Result |
|---|---|---|
| 1 | `expose crenel-durable-test --auth none --yes` | applied, **read-back ✓**, verified, no persist warning; region inside `*.homelab.example` (lines 238–243), NO shadow site, operator bytes byte-identical (region-stripped == anchor); drift gate + `caddy adapt` cross-check passed. |
| 2 | `docker restart caddy` | admin 200; trial host **survived — 200 / 56,334 B**; controls 200/200. (restart-survival re-confirmed.) |
| **3** | **`unexpose crenel-durable-test --yes`** | **applied, read-back ✓ "is no longer exposed", VERIFIED — NOT rolled back.** The host-match delete removed the live (`@id`-less, Caddyfile-derived) route; the persist cleared the crenel region. Live admin: host gone. On-disk: crenel region GONE. **Caddyfile == anchor `eac4c45a…` BYTE-FOR-BYTE — achieved BY CRENEL, no manual restore.** Trial host: 0 bytes (denied). |
| 4 | `docker restart caddy` | admin 200; trial host **stays gone — 0 bytes** (the removal is durable; the route is out of the Caddyfile); controls 200/200/302. |
| 5 | final clean-state | Caddyfile sha `eac4c45a…` (== anchor); live admin host set 51 == pre-trial (sets equal), trial host absent; **zero** `crenel-route` residue; caddy RestartCount 0, Running. Trial `.bak` + any `.crenel-candidate`/`.crenel-commit` removed → conf dir pristine. |

**The headline (step 3): durable UNEXPOSE now works THROUGH crenel.** The rollback the first
trial hit is gone — `unexpose` deletes the `@id`-less route by host match, read-back-verifies
the host is gone, and the persist clears the Caddyfile region back to byte-identical operator
bytes. The whole expose → restart → unexpose → restart lifecycle is crenel-driven and
byte-faithful; the manual byte-restore was NOT used (it is now the abort-only fallback).

**Stop conditions:** none. 3 control prod hosts healthy throughout (200/200/302), caddy
RestartCount 0 start→finish, home admin `127.0.0.1:2019` never published. Production ends
byte-for-byte as found, **by crenel**. The durable-persist feature — expose, restart-survival,
AND unexpose — is now proven end-to-end on production.
