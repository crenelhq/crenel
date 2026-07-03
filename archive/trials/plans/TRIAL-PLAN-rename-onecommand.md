# Re-demo plan — the ONE-COMMAND flagship rename (`crenel rename`)

> **Status: PROPOSED — GO-gated, not yet run.** The flagship "move a service" was already
> proven on production as two verbs (expose-new + unexpose-old, see
> `TRIAL-RESULT-rename-flagship-2026-06-28.md`). This re-demo proves the SAME move as a
> single atomic command — `crenel rename <old> <new>` — built on `feat/rename-verb`
> (TRIAL-FIX-DURABLE-2 + the rename verb). Build + tests done (325 funcs, race-clean); this
> is the separate live step before v0.2.

---

## 0. What this proves (vs the two-verb demo)

- **One atomic command**: `crenel rename crenel-rename-old.homelab.example crenel-rename-new.homelab.example`
  does the whole move — add new (copying the source backend/auth/mode) + remove old — as ONE
  read-back-verified, all-or-nothing transaction, with ONE coordinated durable persist.
- **No intermediate half-state**: unlike expose-then-unexpose, the new host is added and the
  old removed under a single rollback unit; a failure at any point restores the prior state.
- **Make-before-break (zero-downtime)**: the new host is inserted + settled BEFORE the old is
  deleted; if the insert fails, the old is never removed.
- **TRIAL-FIX-DURABLE-2 by construction**: the single persist renders the final region
  (`… , new` − `old`) in one write, so the multi-host-persist gap the two-verb demo hit
  (the make-step drift refusal) cannot occur.

## 1. Same discipline as the prior demos

Sole executor. Home edge only, throwaway self-test backend (`crenel-rename-old`/`-new` →
`homepage:3000`), NO real service touched, NO DNS/auth/chain. Full backup + sha256 anchor of
`/etc/homeedge/caddy/Caddyfile` (the home-edge host) BEFORE anything; drift check (now also enforced
in-reconciler). read-back-verify every mutation; ssh-exec only; home admin never published.
Byte-for-byte anchor restore is ABORT-ONLY — the demo should leave production clean BY crenel.
Binary built from `feat/rename-verb` tip. Config: the rename config with both names in
`origins` (only needed for the SETUP expose; rename itself copies the live route).

## 2. The one-command cycle

| Step | Command | Expected |
|---|---|---|
| setup | `crenel expose crenel-rename-old --auth none --yes` | durable; old serves the backend (live + on-disk region inside `*.homelab.example`). |
| **rename** | **`crenel rename crenel-rename-old.homelab.example crenel-rename-new.homelab.example --yes`** | **ONE command**: applied, **read-back ✓ (`renamed old → new`)**, verified; the persist warning from the two-verb demo MUST NOT appear (single coordinated persist). After: new serves the backend, old denied (0 B), on-disk region holds `crenel-rename-new` ONLY, operator bytes byte-identical, no shadow site. |
| restart | `docker restart caddy` | new still serves, old stays gone — the move is durable from disk. |
| teardown | `crenel unexpose crenel-rename-new --yes` | region cleared; Caddyfile == anchor BY crenel; a second restart confirms clean. |
| final | — | Caddyfile == anchor, admin host set == pre-trial, zero crenel residue, 3 control prod hosts healthy, RestartCount sane. |

## 3. The headline to confirm

Step "rename" is the whole point: **the two-verb sequence (and its intermediate drift
refusal) collapses into one `crenel rename …` that applies, verifies BOTH transitions, and
persists durably in a single pass.** That is the one-command flagship for v0.2.

## 4. Abort / fallback

Any read-back-verify failure rolls back the whole rename (new removed if added, old restored)
— nothing half-applied. The no-drift-loss gate still guards the persist. If anything trips,
restore the Caddyfile from the on-the home-edge host backup, reload, and report. (Expected: zero drift, as
in the prior three trials.)

## 5. Honest boundaries (note in the result)

- Rename targets the edges that DIRECTLY serve the host; a chain-forwarded host (front forward
  + downstream terminal) coordinated rename reuses the P4-write machinery and is a follow-on.
- A source route whose auth reads as `(detected)` (a brownfield / post-reload gate whose policy
  name crenel can't recover) is refused by name-safety — configure `--auth <policy>` and
  re-expose under the new name. The self-test backend is `--auth none`, so this does not arise.
- No DNS coordination in this build (the demo config has none); a DNS-aware rename (move the A
  record too) is a follow-on.
