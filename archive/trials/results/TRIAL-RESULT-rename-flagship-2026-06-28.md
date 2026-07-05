# Flagship demo — "rename/move a service", end-to-end through crenel (PROVEN, durable)

> **Executed 2026-06-28 ~21:35–21:42 UTC on the real home edge. GO'd by the maintainer.** The flagship
> "move a service to a new hostname" was proven end-to-end through crenel — durable across a
> `docker restart caddy` — on a throwaway self-test backend (no real service touched).
> Production left byte-for-byte as found, BY crenel.
>
> Sole executor. Binary from `develop` @ `25dcec9` (sha `b62db2c8`), Mac → `ssh root@proxmox →
> pct exec 100`. TS `20260628T213550Z`. Backups: `live-backup/rename-demo-20260628T213550Z/`.
> Two services in `origins`, both → `homepage:3000` (a harmless 56,334-byte dashboard):
> `crenel-rename-old` and `crenel-rename-new`.

---

## 0. Headline

- **The rename works end-to-end through crenel and is DURABLE.** A service at
  `crenel-rename-old.homelab.example` was moved to `crenel-rename-new.homelab.example`; after a
  full `docker restart caddy` the **new name still served (56,334 B) and the old stayed gone
  (0 B)** — the move came from the on-disk Caddyfile, not ephemeral admin state.
- **No first-class `rename`/`move` verb today** — the move was `expose <new>` + `unexpose
  <old>`, each durable + read-back-verified. **Verdict: a first-class `rename` verb is worth
  adding** (see §5) — it would make this a single atomic one-command flagship.
- **A real finding surfaced — and the safety net caught it.** A make-before-break attempt
  (both names durable at once) tripped the **no-drift-loss gate** (TRIAL-FIX-DURABLE-1): the
  reconciler mirrors only `@id`-tagged routes, so persisting the new host while the old was
  already in the Caddyfile (now `@id`-less after its own reload) would have DROPPED the old —
  the gate REFUSED rather than lose it. Production stayed safe; the rename still completed
  correctly via the break step. This is **TRIAL-FIX-DURABLE-2** (multi-host durable persist),
  §4 — a follow-on, not a blocker.
- **Clean teardown BY crenel:** `unexpose <new>` returned the Caddyfile to the byte-for-byte
  anchor; a second restart confirmed clean. Final: anchor match, 51 hosts == pre-trial, zero
  residue, 3 control prod hosts healthy.

## 1. Pre-flight (read-only; production untouched)

Caddyfile anchor `eac4c45a…` (8755 B), live admin `e509c326…` (51 hosts) — byte-identical to
the prior trials' anchors (operator hasn't touched it). On-the home-edge host backup
`Caddyfile.bak-crenel-rename-<TS>` (sha matches). Drift check PASS (51 == 51). Both rename
hosts absent; zero `crenel-route` residue. caddy RestartCount 0.

## 2. The rename (the only mutations)

| Step | Action | Result |
|---|---|---|
| setup | `expose crenel-rename-old --auth none --yes` | applied, read-back ✓, verified, DURABLE; old serves 56,334 B, new 0 B. |
| make | `expose crenel-rename-new --auth none --yes` | applied, read-back ✓, verified LIVE — **both names serve (zero-downtime overlap)**. **Durable persist REFUSED** (no-drift-loss gate: *"1 live host absent from the on-disk config: crenel-rename-old"*). New is live, not yet durable. **Finding §4.** |
| break | `unexpose crenel-rename-old --yes` | applied, read-back ✓, verified; host-match delete removed old (live) AND the persist **re-rendered the Caddyfile region to `{new}`** (now no drift) → **new is durable, old gone**. After: old 0 B, new 56,334 B; region on-disk = `crenel-rename-new` only; operator bytes byte-identical outside the region; no shadow site. |

**Net result: the service moved old → new, durable, through crenel.** (The make-before-break
overlap means the new name was reachable before the old was removed — zero-downtime in intent;
the new name became *durable* only at the break step, see §4.)

## 3. Durability + teardown

- **`docker restart caddy`** → admin 200; **new still serves 56,334 B, old stays gone (0 B)**;
  controls git 200/14258 B, files 200/5647 B. **The rename survived the restart — durable.**
- **Teardown:** `unexpose crenel-rename-new --yes` → applied, read-back ✓, verified; the
  persist cleared the region → **Caddyfile == anchor `eac4c45a…` BYTE-FOR-BYTE, BY crenel**
  (no manual restore). A second `docker restart caddy` → both rename hosts gone (0 B), controls
  healthy.
- **Final clean-state:** Caddyfile == anchor; live admin host set 51 == pre-trial (sets equal),
  both rename hosts absent; **zero** `crenel-route` / `crenel-managed` / `crenel-rename`
  residue (admin + Caddyfile); caddy RestartCount 0; trial `.bak`/candidate/commit removed →
  conf dir pristine.

## 4. Finding — multi-host durable persist (TRIAL-FIX-DURABLE-2, recommended)

**What:** `Persist` mirrors the crenel region from `live.Routes` filtered to `r.Managed`
(== carries crenel's `@id`). But a durable persist's `caddy reload` re-derives crenel's routes
from the Caddyfile, which carries **no `@id`** — so a previously-persisted host reads back
**unmanaged**. When a SECOND host is durably exposed, `Persist` therefore renders the region
from only the new (`@id`-tagged) host and **omits the already-persisted one**. The
**no-drift-loss gate caught exactly this** and refused (the first host is still live but absent
from the candidate's adaptation), so nothing was lost — but the new host's persist did not
complete until the old host was removed.

**Impact:** today the durable reconciler effectively supports **one crenel-managed host at a
time per edge** through a clean make/break sequence; a true make-before-break (two durable
crenel hosts simultaneously) does not persist the second until the first leaves. The rename
still completes correctly (the break step re-renders the region), and the safety net prevents
any data loss — this is a completeness gap, not a safety hole.

**Fix (bounded):** the persist's mirror set should be the live routes whose host is `@id`-
managed **OR present in the existing crenel Caddyfile region** (parse `parseInSiteRegion` for
the already-owned hosts, union with the `@id` set, intersect with live). Then a second durable
expose renders the region as `{old, new}` and the gate passes. A test: two sequential durable
exposes both land in the region; the second does not drop the first.

## 5. Verdict — a first-class `rename` / `move` verb IS worth adding

Today a rename is two verbs (`expose <new>` + `unexpose <old>`) and is **not a single atomic
transaction** — there is an intermediate state where the move is half-applied (and, per §4,
the new name is live-but-not-yet-durable until the old leaves). A first-class verb —
`crenel rename <old-host> <new-host>` (or `crenel move <svc> <new-host>`) — should:

1. **Be atomic** — one all-or-nothing plan (add new + remove old), rolled back as a unit on any
   failure, with a single coordinated durable persist (so the region is rendered as `{…, new}`
   without `{old}` in one write — which also **sidesteps the §4 multi-host ordering issue**).
2. **Copy the source route's exact config** — backend, auth policy, mode, upstream-TLS — to the
   new host, so the operator does not re-specify it (a rename should preserve behavior, only the
   hostname changes). This is the real ergonomic win over expose+unexpose.
3. **Read-back-verify both** the new (present + serving the copied config) and the old (absent),
   and on a chain, coordinate both edges (reusing the P4-write transaction machinery).

The building blocks all exist (plan/apply/rollback, ordering, durable persist, the host-match
delete). A `rename` verb composes them into the natural one-command flagship and is the right
next step to make "rename/move a service" a single durable, atomic operation. **Recommended.**

## 6. Stop conditions

None. 3 control prod hosts healthy throughout (200/200/302), caddy RestartCount 0 start→finish,
home admin `127.0.0.1:2019` never published (ssh-exec only). The one "refusal" (the make-step
drift-gate) was the safety net working as designed — it changed nothing on disk. Production ends
byte-for-byte as found, BY crenel. No real service was touched (throwaway self-test backend only).
