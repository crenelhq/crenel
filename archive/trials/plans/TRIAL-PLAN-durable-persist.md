# Live-trial plan — durable home-edge persist (the restart-survival write)

> **Status: PROPOSED — not yet run. GO-gated, exactly like the chain-write 302 trial.**
> This plan touches PRODUCTION (the home Caddy edge's on-disk Caddyfile + a reload).
> Nothing here runs until the maintainer green-lights it. Build + unit tests are complete on
> `feat/durable-home-persist`; this is the separate live step.
>
> Companion: **DESIGN.md "Durability — the persistence model"**, the chain-write trial
> (**TRIAL-PLAN-chain-write.md** / **TRIAL-RESULT-chain-write-2026-06-28.md**) for the
> proven ssh-exec write shape this builds on.

---

## 0. What this trial proves (and what it does NOT)

**Proves:** a crenel `expose` against the home edge lands LIVE (admin API, immediate) AND
is reconciled into the on-disk boot Caddyfile, **read-back-verified**, such that a
**container restart reproduces the exposure** — closing the ephemeral-write gap that
blocks the rename/move use case.

**Does NOT:** change how the operator boots Caddy (no `--resume`), introduce a stored
desired-state SOT, or touch the VPS front edge. It is single-edge (home), HTTP-proxy,
terminal — the simplest durable write, deliberately.

## 1. The discovered persistence model (verified read-only, 2026-06-28)

- Home Caddy boots: `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile` — **no
  `--resume`** (verified via `docker inspect caddy`). ⟹ admin-API writes are EPHEMERAL.
- The Caddyfile is at **`/etc/homeedge/caddy/Caddyfile` on the home-edge host** (the LXC host),
  **bind-mounted READ-ONLY** into the container at `/etc/caddy/Caddyfile` (verified via
  `docker inspect` mounts: `bind … rw=false`). ⟹ crenel cannot write it from inside the
  container; it must write the host path and run `caddy` in the container.
- Structure: a global block, `(authelia)`/`(authelia-s2m)` snippets, and two wildcard
  sites (`*.homelab.example`, `*.smallbiz.example`) with per-host `@name host X` +
  `handle @name { [import authelia] reverse_proxy … }`. The operator hand-edits this file
  and keeps `Caddyfile.bak-<change>-<ts>` snapshots (incl. today's `bak-archive-*` and
  `bak-files-repoint-*` — the rename done by hand).

`crenel status` over this edge already declares **`Durability: ephemeral-admin ⚠`** and a
write warns it will not survive a restart — the read-time half is live-correct.

## 2. Pre-flight (read-only, reversible)

1. **Full backup** (gitignored `live-backup/durable-persist-<TS>/`):
   - `GET /config/` (live admin JSON, both edges), sha256-anchored.
   - `cp /etc/homeedge/caddy/Caddyfile` → `Caddyfile.bak-crenel-trial-<TS>` on the home-edge host
     (operator's own backup idiom) AND pulled into `live-backup/`.
   - `caddy adapt --config /etc/caddy/Caddyfile` baseline JSON (the re-adaptation anchor).
2. **Pick a SAFE trial host** — a NEW host the operator's Caddyfile does NOT already
   handle (no shadow/conflict), pointing at a harmless backend. Proposal: a throwaway
   `crenel-durable-test.homelab.example → <a 200-returning internal service>`, public DNS
   left OUT (edge-only durable test; no `--zone`/DNS in the op) so nothing goes public.
3. **Config**: `examples/settings-durable-home.json` (ssh-exec admin + the two
   `caddy_persist` channels). `verify_adapt: true`.
4. **Dry-run the channels read-only**: `crenel status` (admin via ssh-exec) + a manual
   `ExecConfigStore.Read` equivalent (`ssh … pct exec 150 -- sh -c "cat /opt/.../Caddyfile"`)
   and a `caddy adapt` in-container — confirm all three channels work and the adapt
   baseline matches live for the existing hosts. Still zero mutation.

## 3. The trial (GO-gated; each step read-back-verified)

1. `crenel expose crenel-durable-test --auth none --yes` against the home edge.
   - **Live half**: granular admin insert of the per-host route, nested in the
     `*.homelab.example` subroute (proven shape from the chain-write trial),
     read-back-verified at the JSON level.
   - **Durable half** (`persistInSite`): read the host Caddyfile → render the
     `@crenel_crenel_durable_test… host …` + `handle { reverse_proxy … }` inside
     `*.homelab.example`'s crenel region → **self-check** → `caddy validate` (container) →
     **`caddy adapt` the candidate → assert the trial host resolves to the same backend**
     → `base64|mv` the host file → `caddy reload --config /etc/caddy/Caddyfile`.
2. **Assert post-write, pre-restart**:
   - `GET /config/` shows the trial route live; `curl` the trial host returns the backend's 200.
   - The on-disk Caddyfile contains the crenel region INSIDE `*.homelab.example`; NO
     top-level `crenel-durable-test.homelab.example {` site; every operator handle + the
     `tls` block byte-identical outside the region (diff vs the backup).
3. **THE restart proof** (the whole point): `docker restart caddy` (operator command,
   with the maintainer present) → wait healthy → `GET /config/` and `curl` the trial host AGAIN.
   - **PASS**: the trial host is STILL exposed after the restart (it came from the
     Caddyfile, not ephemeral admin state). This is the durable-persist proof.
   - Re-run `crenel status`: `Durability: durable-file (writes survive a restart)`, no
     `ephemeral_writes` finding for the trial host.

## 4. Teardown (byte-for-byte restore — non-negotiable)

1. `crenel unexpose crenel-durable-test --yes` → live route removed + the crenel region
   cleared from the Caddyfile (the unexpose-clears path), read-back-verified.
2. `caddy reload` → `docker restart caddy` once more → confirm the trial host is gone and
   the edge serves exactly its pre-trial set.
3. **Diff the live Caddyfile against the pre-trial backup → MUST be byte-identical**
   (crenel's region fully removed, zero operator drift). If not, restore from
   `Caddyfile.bak-crenel-trial-<TS>` and reload.
4. sha256 the live admin JSON (both edges) vs the pre-flight anchors → unchanged.
5. Remove the temp DNS if any was added (none planned). Record results in
   `TRIAL-RESULT-durable-persist-<date>.md`.

## 4a. RE-TRIAL (after TRIAL-FIX-DURABLE-1) — the FULL expose→restart→unexpose cycle

> The first trial (§3–§4, RESULT doc) proved durable EXPOSE + restart-survival, then found
> that `unexpose` rolled back (the Caddyfile-reloaded route has no `@id`); teardown used a
> manual byte-restore. **TRIAL-FIX-DURABLE-1 (committed `81ef895`) fixes this** — durable
> unexpose now deletes by host-match (no `@id` needed) + a no-drift-loss gate is folded in.
> This re-trial proves the WHOLE cycle works through crenel, with no manual restore.

Same access model, same smallest-proof discipline (home edge, ONE throwaway host, no DNS/
auth/chain), same pre-flight (§2) INCLUDING the now-built-in drift gate (it runs inside the
reconciler now, but still capture the anchors). Rebuild the binary from the branch tip
(`feat/durable-home-persist`, ≥ `81ef895`).

1. **Expose** `crenel-durable-test --auth none --yes` → as §3: live + on-disk region inside
   the wildcard, read-back-verified; `caddy adapt` cross-check + drift gate pass.
2. **Restart** `docker restart caddy` → the host SURVIVES (§4). (Already proven; re-confirm.)
3. **THE NEW STEP — `crenel unexpose crenel-durable-test --yes` (no manual restore):**
   - Expect: **applied, read-back ✓, verified, exit 0** (NOT a rollback). The host-match
     delete removes the live route (re-derived, `@id`-less); the persist clears the crenel
     region from the Caddyfile + reloads.
   - Assert: trial host back to 0 bytes (denied); on-disk crenel region GONE; operator
     bytes byte-identical to the anchor; `crenel status` clean.
4. **Restart again** `docker restart caddy` → confirm the removal is durable (host stays
   gone — it's out of the Caddyfile now), controls healthy.
5. **Final**: live Caddyfile **== pre-trial anchor byte-for-byte** achieved BY CRENEL (the
   byte-restore is now only a fallback, not the teardown path); admin host set == 51; zero
   crenel residue; RestartCount sane.

**Drift-gate live check (bonus, optional):** the no-drift-loss gate now lives in the
reconciler. If the pre-flight drift check (§2) ever shows a live host absent from the
Caddyfile, the durable persist will REFUSE on its own (naming the host) rather than reload —
no separate harness discipline needed. (We expect zero drift, as in the first trial.)

The byte-restore from `Caddyfile.bak-crenel-durable-trial-<TS>` remains the abort-path
fallback (§5) if anything trips.

## 5. Abort / rollback triggers

- Any read-back-verify failure (live OR re-adaptation) → crenel already refuses and does
  NOT write the boot file; restore is a no-op. Surface the warning, stop, investigate.
- `caddy validate`/`reload` non-2xx or a wedge → the never-hang bound fires; the candidate
  never replaced the live file (temp + `mv`); restore from backup if `mv` had landed.
- The trial host turns out to collide with an operator handle → crenel refuses
  (operator-owned) before writing. Pick a different host.
- ANY operator-byte drift detected at teardown → restore the backup Caddyfile verbatim,
  reload, and stop.

## 6. Why this is safe to propose

- **No new SOT, no boot change.** crenel reconciles into the operator's existing
  Caddyfile and proves it re-adapts to live before committing.
- **A bad candidate never touches the live file** (validate + adapt run on a sibling
  candidate; the boot file is replaced only after both pass, via atomic `mv`).
- **Refuse-to-manage holds at the durability layer** (an operator-owned host is refused,
  not shadowed) and the whole thing is **byte-faithful** outside crenel's region.
- It is the **smallest** durable write (single edge, one new throwaway host, no DNS, no
  chain, no auth) — the minimal proof, expandable to the real `archive → files` rename
  only after this passes.
