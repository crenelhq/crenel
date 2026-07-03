# Re-demo result — the ONE-COMMAND flagship rename (`crenel rename`) — PASSED

> **Executed 2026-06-28 ~22:11–22:18 UTC on the real home edge. GO'd by the maintainer.** The flagship
> "move a service" collapsed to a SINGLE atomic command — `crenel rename <old> <new>` — and
> passed end-to-end, durable across a `docker restart caddy`, on a throwaway self-test backend.
> Production left byte-for-byte as found, BY crenel.
>
> Sole executor. Binary from `feat/rename-verb` @ `8ecae98` (sha `7016f76c`), Mac → `ssh
> root@pve1 → pct exec 150`. TS `20260628T221115Z`. Backups:
> `live-backup/rename-onecommand-20260628T221115Z/`. Throwaway self-test hosts
> `crenel-rename-old`/`-new` → `homepage:3000` (56,334 B). No DNS / no auth / no chain.

---

## 0. Headline

**The two-verb move is now ONE command.** What the prior demo did as
`expose crenel-rename-new` + `unexpose crenel-rename-old` (and hit a multi-host-persist drift
refusal mid-way) is now:

```
crenel rename crenel-rename-old.homelab.example crenel-rename-new.homelab.example --yes
→ applied: rename (host=crenel-rename-new.homelab.example)
  read-back ✓ [edge[caddy·caddy]] renamed crenel-rename-old.homelab.example → crenel-rename-new.homelab.example
  verified: live state matches intent
```

**No persist warning** — the single coordinated durable persist rendered the final region
(`crenel-rename-new` only) in one pass; the drift refusal the two-verb demo hit (TRIAL-FIX-
DURABLE-2) is gone by construction.

## 1. Pre-flight (read-only; production untouched)

Caddyfile anchor `eac4c45a…` (8755 B), live admin `e509c326…` (51 hosts) — byte-identical to
the prior trials. On-the home-edge host backup `Caddyfile.bak-crenel-1cmd-<TS>` (sha matches). Drift check
PASS (51 == 51). Both rename hosts absent; zero `crenel-route` residue. caddy RestartCount 0;
`status` → `Durability: durable-file (writes survive a restart)`; pre-trial reachability:
both rename hosts 0 B, git 14,258 B.

## 2. The one-command cycle

| Step | Command | Result |
|---|---|---|
| setup | `expose crenel-rename-old --auth none --yes` | durable; old serves 56,334 B. |
| **rename** | **`rename crenel-rename-old.homelab.example crenel-rename-new.homelab.example --yes`** | **applied, read-back ✓ (`renamed old → new`), verified, NO persist warning.** After: new serves **56,334 B**, old **0 B**; on-disk crenel region holds **`crenel-rename-new` ONLY** (old absent); operator bytes **byte-identical** (region-stripped == anchor); **no shadow site**. |
| restart | `docker restart caddy` | admin 200; **new still serves 56,334 B, old stays 0 B** — the move is durable from disk; controls 200/200. |
| teardown | `unexpose crenel-rename-new --yes` | applied, read-back ✓, verified; region cleared → **Caddyfile == anchor `eac4c45a…` BYTE-FOR-BYTE, BY crenel**. |
| restart 2 | `docker restart caddy` | admin 200; both rename hosts 0 B; controls git 200/14258, files 200/5647, jellyfin 302. |
| final | — | live admin host set **51 == pre-trial** (sets equal), rename hosts absent; **zero** `crenel-route` / `crenel-managed` / `crenel-rename` residue (admin + Caddyfile); caddy RestartCount 0; trial `.bak`/candidate/commit removed → conf dir PRISTINE. |

## 3. What this proves

- **One atomic command** does the whole move: add new (copying the source backend) + remove
  old, read-back-verified (both transitions: `renamed old → new`), with ONE coordinated durable
  persist — no intermediate drift refusal, no manual byte-restore, no two-step dance.
- **Durable**: the renamed host survived a full `docker restart caddy` (it came from the
  Caddyfile); the removal of the old name survived too.
- **Byte-faithful**: operator bytes untouched throughout; the region held exactly the new host;
  teardown returned the Caddyfile to the anchor BY crenel.

## 4. Stop conditions

None. 3 control prod hosts healthy throughout (200/200/302), caddy RestartCount 0 start→finish,
home admin `127.0.0.1:2019` never published (ssh-exec only). The byte-restore fallback was NOT
used. No real service touched (throwaway self-test backend only). Production ends byte-for-byte
as found, BY crenel.

## 5. Verdict

**PASSED CLEAN.** The first-class `crenel rename` verb is proven live on production as the
one-command flagship. TRIAL-FIX-DURABLE-2 (multi-host durable persist) is validated by the
absence of the drift refusal during the rename's single persist. **Next step: merge
`feat/rename-verb` → develop → cut v0.2 with the one-command rename flagship included.**
