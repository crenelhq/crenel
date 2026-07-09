# TRIAL PLAN — live cross-chain coordinated WRITE (P4-write) across the two real edges

> **Status: PREP COMPLETE / NO MUTATION PERFORMED.** This document is the ordered
> execution plan for the *real* write trial. The first mutating command is gated on
> **the maintainer's explicit GO** (see §0 and the 🟥 GO GATE). Everything done so far is
> read-only: backups captured, both edges confirmed healthy, dry-run preview captured.
>
> **RE-RUN READY (2026-06-28) — write-side nesting fixed.** The first attempt
> (`TS=20260628T115717Z`, see `TRIAL-RESULT-chain-write-2026-06-28.md`) aborted ATOMICALLY
> with zero mutation. Grounding the fix in the captured real edge configs surfaced a
> **write-side subroute-nesting defect**: crenel's granular insert flat-inserted each
> per-host route at `…/servers/srv0/routes/0`, but BOTH real edges keep per-host routing
> INSIDE wildcard `*.zone` subroutes — a flat insert misplaces it. **FIXED on `develop`**
> (`httpRouteInsertPath`: per-zone nest-into-wildcard-subroute, flat for flat zones,
> refuse on ambiguous/absent; the Caddy fake made faithful first; reproduce-then-fix
> tests incl. the cross-chain `TestChainWrite_NestsAcrossWildcardSubrouteChain`). The
> trial is **unblocked to re-run on the nesting axis** — rebuild the staged binary from
> the new `develop` before Step 1.
>
> **AUTH-RENDERER ALSO FIXED (2026-06-28, TRIAL-FIX-3).** The finding that ACTUALLY
> aborted the WRITE — crenel emitting a synthetic `{"handler":"forward_auth"}` Caddy
> rejects as `unknown module: http.handlers.forward_auth` — is now fixed too. The granular
> path renders the **canonical** `reverse_proxy`+`handle_response` gate (the real
> Authelia expansion, from the operator-declared `caddy_forward_auth[_verify_uri/
> _copy_headers]`) or an operator **verbatim** `caddy_handler_json` blob, fronted by a
> `vars` policy marker; the fake now provisions handlers and rejects unknown modules. **So
> the re-run can go straight to `--auth authelia` for the real 302 proof** — no longer
> blocked to `--auth none`. Set the home edge's `auth_policies.authelia` with the verify
> URI + copy-headers matching the live config (see §config below). See AUTH-DESIGN.md §2.1.
>
> **FRONT-LEG TLS ALSO FIXED (2026-06-28, TRIAL-FIX-4).** RUN 2 (`TS=20260628T140225Z`)
> applied the WRITE on both real edges (read-back-verified, exit 0) with FIX-2 + FIX-3 in,
> but the through-the-chain curl returned `400 "Client sent an HTTP request to an HTTPS
> server"` — a THIRD live-only gap: the FRONT forward was rendered as **bare HTTP to the
> home edge's HTTPS `:443`** (no upstream TLS, no Host). **FIXED on `develop`:** the
> chain-forward now renders `transport {protocol:http, tls:{insecure_skip_verify,
> server_name:{http.request.host}}}` + request `Host:{http.request.host}` — byte-faithful
> to the real VPS forward routes — whenever the downstream is HTTPS (`downstream_scheme:
> https`, else inferred from a `:443` dial); read-back + `verify` confirm the TLS hop. **So
> the re-run (RUN 3) should finally land the real 302** through the chain. Keep
> `downstream_address: 10.0.0.13:443` (the `:443` infers HTTPS; no config change needed).
> Rebuild the staged binary from the new `develop` before Step 1. See DESIGN.md
> "Cross-chain coordinated WRITE → Front-leg upstream TLS".
>
> Prep timestamp `TS = 20260628T012152Z`. Companion docs: `DEPLOY-VPS.md` (loopback-admin
> discipline), `DESIGN.md` "Cross-chain coordinated WRITE (P4-write)" (+ the granular
> **insert nesting** note under the Caddy driver), `AUTH-DESIGN.md` §6,
> `DIAGNOSTICS-2026-06-27.md` (the crowdsec reload-storm wedge + recovery),
> `TRIAL-RESULT-chain-write-2026-06-28.md` (the aborted first attempt).

---

## 0. The gating finding (READ THIS FIRST) — access model

A coordinated cross-chain write needs **one** `crenel` process that can reach **both**
edges' Caddy admin APIs. Today, neither admin API is reachable off its own loopback:

| Edge | Admin API | Bound to | Reachable from |
|---|---|---|---|
| **VPS front** (`vps-edge`, TS `100.100.0.2`) | `127.0.0.1:2019` | VPS loopback | the VPS only (confirmed: TS-IP `100.100.0.2:2019` → connection refused) |
| **HOME downstream** (`caddy` container on LXC 113 `10.0.0.13`) | `127.0.0.1:2019` **inside the container** | container-localhost | the `caddy` container only. **Port 2019 is `EXPOSE`d by the image but NOT published** → unreachable from the LXC host (`127.0.0.1:2019` refused on the LXC) and from the VPS (`10.0.0.13:2019` refused over Tailscale, though ICMP/ping + `:443` + `:22` all succeed) |

**Conclusion: there is no host today that can reach both admin APIs, so a single-
transaction live run is impossible without a deliberate, reversible change to make the
HOME admin reachable to wherever `crenel` runs.** The home admin's container-localhost
binding is the load-bearing constraint — it must be published somewhere regardless of
path. This is exactly the boundary the build docs flagged ("a live cross-chain write
trial is a separate, backed-up step").

> **UPDATE (TRANSPORT shipped) — Option A is now superseded by the `ssh-exec` transport.**
> crenel can now reach a loopback-only, UNPUBLISHED admin by running the admin call as a
> nested-exec curl on the far end — **no home-admin publish, no manual SSH tunnel, no
> container recreate.** This is **READ-ONLY-verified LIVE** against the home edge:
> `crenel status` over `ssh root@pve1 → pct exec 113 → docker exec -i caddy → sh → curl
> 127.0.0.1:2019` read 51 services, deny ENFORCED, config byte-identical (sha256
> `174d1d92…`, the HOME anchor below). The live WRITE trial should therefore run with the
> home edge configured as an `ssh-exec` transport (see `examples/settings-transport-sshexec.json`)
> and the front edge as `direct` — exactly the mixed-transport shape proven end-to-end
> against fakes in `internal/core/transport_chain_test.go`. This **eliminates Step 2's
> reversible home-admin change entirely** (the gating §0 constraint is dissolved: crenel
> reaches the home admin where it lives, on container-loopback, without exposing it). The
> single-transaction atomic guarantee is preserved (one crenel process, one transaction,
> both edges). Options A/B/C below are retained for historical context / fallback.

### Execution options, ranked

**🟢 Option A — single atomic transaction, crenel on the VPS, home admin via an
ephemeral SSH tunnel (RECOMMENDED).**
- Run the one `crenel` **on the VPS**. Front admin = its own `127.0.0.1:2019` (the
  `DEPLOY-VPS.md` "admin never leaves the VPS" invariant stays fully intact — we tunnel
  the *home* admin, never the VPS admin).
- Temporarily make the home admin reachable on **LXC-loopback only** (NOT the LAN/tailnet):
  add `admin 0.0.0.0:2019` to the home Caddyfile global options + publish
  `127.0.0.1:2019:2019` in the home `caddy` compose, then `docker compose up -d` (one
  container recreate, ~10 s home blip — the home image has **no crowdsec**, so the recreate
  is clean). Revert both after the trial.
- From the VPS, open an **ephemeral authenticated** tunnel to it (LXC 113 sshd is up and
  reachable from the VPS — confirmed): `ssh -fN -L 127.0.0.1:12019:127.0.0.1:2019 root@10.0.0.13`.
- crenel home edge `admin_url = http://127.0.0.1:12019`. Neither admin is ever on the
  tailnet/LAN; the only off-box hop is the SSH-tunneled home admin (authenticated, ephemeral).
- **Validates the headline feature** (the atomic cross-chain transaction + cross-chain
  rollback). Cost: one home-caddy recreate + a temporary Caddyfile/compose edit.

**🟡 Option B — bind the home admin to the tailnet interface, firewalled to the VPS.**
Add `admin 0.0.0.0:2019` + publish `10.0.0.13:2019:2019`, plus an nftables rule on LXC
113 allowing tcp/2019 **only** from the VPS/tailnet source and dropping all else; run crenel
on the VPS. Single transaction, but it puts an **unauthenticated** Caddy admin API on the
tailnet (firewall-restricted) — a broader, longer-lived surface than Option A's loopback +
ephemeral SSH tunnel. Use only if the SSH-tunnel hop in A is undesirable. **Never bind the
admin to `0.0.0.0`/public without the firewall.**

**🟠 Option C — two-phase run (FALLBACK; breaks the single-transaction guarantee).**
No home-caddy change at all: Phase 1 runs crenel **on the VPS** for the front FORWARD leg
only; Phase 2 runs crenel **inside the home `caddy` container** (`docker cp` a linux/amd64
crenel in — the container is amd64 and has `/bin/sh`) against `127.0.0.1:2019` for the home
TERMINAL leg only. Each leg is individually read-back-verified, but there is **no
cross-edge atomic rollback** — if Phase 2 fails you must manually undo Phase 1. Acceptable
*only* because the host is throwaway with a tiny blast radius; it does **not** exercise the
P4-write atomic guarantee, so it's a weaker trial of the actual feature.

> **Recommendation: Option A.** It is the only option that both validates the atomic
> cross-chain transaction AND keeps every admin API off the tailnet. If the maintainer would rather
> not touch the home caddy container at all, Option C is the zero-infra-change fallback at
> the cost of the atomicity guarantee. **the maintainer picks the option before any mutation.**

### What the maintainer must set up / decide before GO
1. **Choose the execution option** (A recommended).
2. For **A/B**: approve the temporary home-Caddy admin exposure + one container recreate.
   For **A**: approve the ephemeral VPS→LXC113 SSH tunnel.
3. Confirm the throwaway backend host:port (§2) — default `10.0.0.13:9999`.
4. Give the explicit **GO** (§ the 🟥 GO GATE).

---

## 1. What the trial proves

A single `crenel expose crenel-selftest --auth authelia` lands a coordinated changeset
across **both** edges as one ordered, read-back-verified, all-or-nothing transaction:

- **HOME (downstream/terminal)**: `+ route crenel-selftest.homelab.example → 10.0.0.13:9999 [auth:authelia]` — the real backend, auth attaches HERE.
- **VPS (front/forward)**: `+ route crenel-selftest.homelab.example → 10.0.0.13:443` — a plain relay to the home edge, NO auth.
- **DNS**: **none** — `crenel-selftest.homelab.example` is already resolvable on both horizons via existing wildcards (§ DNS below), so the trial makes no DNS change.

Then `unexpose` tears it down in reverse, and both edges return **byte-for-byte** to the
captured backups.

### Captured dry-run preview (real configs, $TS) — the plan to eyeball against reality
```
$ crenel -config preview-config-chain.json preview expose crenel-selftest --auth authelia
Plan: expose crenel-selftest (host=crenel-selftest.homelab.example, auth=authelia)
  EDGE [vps·caddy]
    + route   crenel-selftest.homelab.example   -> 10.0.0.13:443
  EDGE [home·caddy]
    + route   crenel-selftest.homelab.example   -> 10.0.0.13:9999  [auth:authelia]
  default-deny will remain present on every edge: true

  ⚠ ABOUT TO GO PUBLIC: crenel-selftest.homelab.example
```
Guardrail confirmed: dropping `--auth` → *"refusing to expose … PUBLIC with no auth"*
(`--yes` does not bypass). `--auth none` is the explicit opt-out. `preview unexpose`
pre-expose = *"no changes — already in the desired state"* (idempotent/state-aware).

The preview was produced read-only by seeding two in-process crenel fakes from the **real
captured live configs** of both edges (`live-backup/trial-chain-write-$TS/`), so the
projection above is computed against reality, not a toy fixture.

---

## 2. Throwaway service plan (PROPOSED — do NOT create until GO)

The simplest sufficient backend: a trivial HTTP responder on a reachable home host/port,
fronted by the throwaway hostname `crenel-selftest.homelab.example`.

- **Stand up (Step T below):** on **LXC 113** (the home apps box, `10.0.0.13`), run a
  one-liner responder on **port 9999** in the foreground/backgrounded for the trial window:
  ```
  python3 -m http.server 9999 --bind 0.0.0.0    # or: a 2-line whoami; body proves the path
  ```
  Port 9999 is currently unused on 10.0.0.13. The home `caddy` container already proxies
  to `10.0.0.13:<port>` for several hosts (e.g. `git → 10.0.0.13:3030`), so
  `10.0.0.13:9999` is reachable from the container by the same path. Tear it down (Ctrl-C
  / kill) at the end.
- **crenel origin mapping:** home edge `origins: { "crenel-selftest": "10.0.0.13:9999" }`
  (this is what makes the home edge the TERMINAL participant for the service). The VPS edge
  does **not** list `crenel-selftest` (so it is classified FORWARD).

### Hostname conflict check — clear
- `crenel-selftest` is **absent** from the home Caddyfile and the VPS config (grepped — clean,
  no existing route).
- The wildcards already *match* `crenel-selftest.homelab.example`, but **non-conflictingly**:
  - At the **VPS front** today: it matches `*.homelab.example` but no per-host group →
    hits the `abort` default-deny → currently DENIED. crenel adds a dedicated additive
    `@id`-tagged FORWARD route → it begins forwarding to home.
  - At the **HOME edge** today: it matches `*.homelab.example` but no inner `handle @host` →
    falls through to an empty 200. crenel adds a dedicated additive `@id`-tagged TERMINAL
    route → it begins serving the responder (under auth).
  - **DNS** already resolves it (public → VPS, internal → home) via the wildcards, so the
    forward/serve chain lights up with no DNS change.
- TLS: `crenel-selftest` is a single-label sub of `*.homelab.example` → **covered by the
  existing wildcard cert on both edges** → no new-cert (DNS-01) issuance on reload (avoids
  the `DIAGNOSTICS §6.4` reload-hang class entirely).

---

## 3. Backups (DONE — read-only, verified, on the Mac)

Captured to `live-backup/trial-chain-write-$TS/` (gitignored), with `SHA256SUMS.txt`:

| Artifact | File | Restore |
|---|---|---|
| **VPS front config** (`GET /config/`, 4627 B, srv0) | `vps-front-config-$TS.json` | re-`POST /load` of these exact bytes (see Recovery R1) |
| **HOME edge config** (`GET /config/` from inside the container, 24880 B, srv0, 2 wildcard routes) | `home-edge-config-$TS.json` | re-`POST /load` of these exact bytes (Recovery R2) — **or** simply `docker restart caddy` (home starts from the pristine `:ro` Caddyfile, NOT `--resume`, so admin-API edits are ephemeral and a restart fully reverts) |
| **DNS state** (public wildcard + AdGuard rewrites + TLS note) | `dns-state-$TS.txt` | **N/A — no DNS mutation in the trial** |
| **Preview capture** (the read-only projection + guardrail) | `preview-capture-$TS.txt` | — |

SHA256 (restore-integrity anchors):
- VPS: `05b1646a9ead5177ad1db69e8e3d4de5f7df54d1ef3a73142ff9d5575381822f`
- HOME: `174d1d92147e01cffb9d488392be20fd3682dcb77ec10ed3d94b6228cb9ce330`

**Health confirmed (both edges, through the chain):** `https://auth.homelab.example` → 200,
`https://git.homelab.example` → 200, `https://auth.smallbiz.example` → 200. VPS `caddy-edge`
and home `caddy` both `RestartCount=0`, running.

**Re-capture immediately before GO** (configs may have changed since prep) — Step 0 below
re-snapshots and re-verifies health, and that fresh snapshot becomes the restore anchor.

---

## 4. Ordered execution steps (each with rollback)

> Notation: 🟥 = mutating (needs GO + happens only after it). All others are read-only/setup.
> Commands assume **Option A**; Option B/C variants noted inline. Run from a terminal with
> `ssh vps-edge` and `ssh root@pve1` working (both confirmed).

### Step 0 — fresh backups + health (read-only) [pre-GO]
- `TS2=$(date -u +%Y%m%dT%H%M%SZ)`; re-`GET /config/` on the VPS → `vps-front-config-$TS2.json`;
  re-capture the home config (`pct exec 113 -- docker exec caddy wget -qO- http://127.0.0.1:2019/config/`)
  → `home-edge-config-$TS2.json`; copy both to the Mac; `python3 -m json.tool` each (valid);
  record sha256. Curl the three prod hosts → all 200. Confirm `RestartCount=0` on both containers.
- **STOP if:** either config fails to parse, either edge is already unhealthy, or RestartCount≠0.

### Step 1 — build + stage the binary (read-only) [pre-GO]
- On the Mac: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/crenel-linux-arm64 ./cmd/crenel`
  (the develop build — the VPS only has v0.1.1, which predates P4-write). For Option C also
  build `GOARCH=amd64` for the home container.
- `scp bin/crenel-linux-arm64 vps-edge:~/crenel-test/crenel-develop` ; `chmod +x`.
- Write the trial config on the VPS, `~/crenel-test/config-chain-write.json` (Option A):
  ```json
  {
    "zone": "homelab.example",
    "auth_policies": { "authelia": {
      "caddy_forward_auth": "authelia:9091",
      "caddy_forward_auth_verify_uri": "/api/verify?rd=https://auth.homelab.example",
      "caddy_forward_auth_copy_headers": ["Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email"]
    } },
    "edges": [
      { "name": "vps", "driver": "caddy", "admin_url": "http://127.0.0.1:2019",
        "granular_apply": true, "downstream_edge": "home",
        "downstream_address": "10.0.0.13:443", "origins": {} },
      { "name": "home", "driver": "caddy", "admin_url": "http://127.0.0.1:12019",
        "granular_apply": true, "origins": { "crenel-selftest": "10.0.0.13:9999" } }
    ]
  }
  ```
  (No `dns` block → DNS disabled → relies on the existing wildcards.)

### Step 2 — open home-admin access (Option A) [pre-GO; reversible setup]
- On LXC 113: back up `/opt/stacks/caddy/conf/Caddyfile` and the compose
  (`cp … .bak-pre-trial-$TS2`). Add `admin 0.0.0.0:2019` inside the Caddyfile global
  `{ … }` options block; add `- "127.0.0.1:2019:2019"` to the `caddy` service `ports:`.
  `cd /opt/stacks/caddy && docker compose up -d` (recreate; ~10 s blip).
- Verify the home admin is now on LXC-loopback only: `curl 127.0.0.1:2019/config/` on the LXC → 200;
  `curl 10.0.0.13:2019/config/` from the VPS → **still refused** (must NOT be on the tailnet).
- From the VPS: `ssh -fN -L 127.0.0.1:12019:127.0.0.1:2019 root@10.0.0.13`; verify
  `curl -s 127.0.0.1:12019/config/ | head -c 50` on the VPS returns config.
- **Rollback (this step):** kill the tunnel (`pkill -f 12019:127.0.0.1:2019`); restore the
  Caddyfile + compose `.bak`; `docker compose up -d`. (Or just leave revert to Step 9.)
- **STOP if:** after the recreate, home prod (`https://git.homelab.example`) is not 200, or
  the admin appears on `10.0.0.13:2019` from the VPS (tailnet leak — revert immediately).

### Step 3 — read-only proof against the LIVE edges (read-only) [pre-GO]
- On the VPS: `./crenel-develop -config config-chain-write.json status` → expect VPS deny
  ENFORCED + home deny ENFORCED, chain follow-through resolving real downstream backends.
- `./crenel-develop -config config-chain-write.json preview expose crenel-selftest --auth authelia`
  → expect the exact §1 changeset (front `→ 10.0.0.13:443`, home `→ 10.0.0.13:9999 [auth:authelia]`,
  deny remains true, ABOUT TO GO PUBLIC).
- `./crenel-develop -config config-chain-write.json expose crenel-selftest -yes` (no `--auth`)
  → expect the guardrail **refusal** (proves no accidental open publish).
- **STOP if:** the live preview differs materially from the captured dry-run (e.g. deny not
  ENFORCED, an unexpected participant, or a foreign/unknown ownership refusal).

### Step T — stand up the throwaway responder (mutating, but local + trivial) [needs GO]
- On LXC 113: `python3 -m http.server 9999 --bind 0.0.0.0 &` (note the PID). Verify from the
  caddy container: `pct exec 113 -- docker exec caddy wget -qO- http://10.0.0.13:9999/ | head -c 40`.
- **Rollback:** `kill <PID>`.

---

### 🟥 GO GATE — the maintainer's explicit GO is required before the next command 🟥
Everything above is read-only or trivially-reversible local setup. **The next step is the
first real edge mutation.** Proceed only on the maintainer's explicit "GO", with the chosen option
confirmed and the fresh backup (Step 0) verified.

---

### Step 4 — 🟥 apply the coordinated expose (the trial) [needs GO]
- On the VPS:
  `./crenel-develop -config config-chain-write.json expose crenel-selftest --auth authelia -yes`
- Expect: applied in order **home route → front route** (DNS LAST = none), each
  **read-back ✓** per edge, `verified: live state matches intent` (incl. the auth policy
  asserted at the home edge).
- **Rollback (automatic):** any apply error or read-back mismatch on either edge → crenel
  rolls back **every** applied participant in reverse, wedge-safe per edge. If crenel reports
  a wedged edge + recovery hint, go to Recovery R3/R4.

### Step 5 — verify it landed on both edges + through the chain (read-only) [post-apply]
- `./crenel-develop -config config-chain-write.json status` → `crenel-selftest` present on
  **both** edges (front forward + home terminal `[auth:authelia]`), both denies still ENFORCED.
- Edge-level read-back: VPS `curl -s 127.0.0.1:2019/config/ | grep crenel-selftest` (front
  forward route present, NO `handle_response`); home (via tunnel)
  `curl -s 127.0.0.1:12019/config/` → the terminal route carries the VALID gate — a
  `vars` `crenel_policy:authelia` marker + a `reverse_proxy` to `authelia:9091` with a
  `handle_response` block (NOT a `forward_auth` handler, which Caddy would have rejected).
- **Through-the-chain curl** (the real end-to-end proof), from anywhere public:
  `curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' https://crenel-selftest.homelab.example/`
  - **Expected with `--auth authelia`: a 302 redirect to the Authelia portal**
    (`auth.homelab.example`), i.e. unauthenticated access is challenged → **proves auth
    attached at the home edge AND the forward chain works**. A flat `200` from the responder
    would mean auth did NOT attach — treat as a failure, roll back.
  - (Optional sanity: re-run the whole trial with `--auth none` to see a clean `200` from
    the responder, proving raw chain routing without auth.)
- **Fidelity note (post TRIAL-FIX-3):** with the config above, crenel renders the CANONICAL
  gate — a `reverse_proxy` to `authelia:9091` with the `handle_response` subrequest, the
  `/api/verify?rd=https://auth.homelab.example` rewrite, and the four `Remote-*` copy-headers —
  i.e. the EXACT shape the home edge uses for its own Authelia hosts (byte-faithful to the
  live config). The verify URI + headers are *operator-declared in `auth_policies`*, not
  invented by crenel, so the auth-by-reference principle holds. This means the challenge should
  be a real Authelia 302, and (because the verify URI matches) a full interactive login should
  work too — though the 302 challenge alone is the success criterion. *(If you prefer the
  purest by-reference, set `caddy_handler_json` to the verbatim gate block copied from the live
  config instead of the endpoint fields.)*
- **STOP & restore if:** the host returns an open `200` while `--auth authelia` was requested;
  either default-deny flips to UNKNOWN/absent; or any *other* host's reachability/auth changed
  (collateral — compare `status` to the pre-trial capture).

### Step 6 — 🟥 unexpose (teardown) [needs GO continuation]
- `./crenel-develop -config config-chain-write.json unexpose crenel-selftest -yes`
- Expect: applied in reverse order (front route removed → home route removed), each
  read-back ✓, `verified`.
- **Rollback:** same automatic cross-chain rollback semantics as Step 4.

### Step 7 — verify clean removal (read-only)
- `status` → `crenel-selftest` absent from both edges; both denies ENFORCED; all other hosts
  unchanged vs the pre-trial capture.
- `curl https://crenel-selftest.homelab.example/` → back to the pre-trial behavior (VPS
  default-deny / abort; no longer forwards).

### Step 8 — byte-for-byte restore check (read-only)
- VPS: `curl -s 127.0.0.1:2019/config/ > /tmp/vps-after.json` ;
  `diff <(jq -S . vps-front-config-$TS2.json) <(jq -S . /tmp/vps-after.json) && echo "VPS RESTORED"`.
- HOME: `curl -s 127.0.0.1:12019/config/ > /tmp/home-after.json` ;
  `diff <(jq -S . home-edge-config-$TS2.json) <(jq -S . /tmp/home-after.json) && echo "HOME RESTORED"`.
  (Additive granular expose+unexpose is a clean round-trip → expect identical. If the home
  diff is non-empty, `docker restart caddy` reverts it to the pristine `:ro` Caddyfile.)
- **STOP & restore (R1/R2) if:** either diff is non-empty after unexpose.

### Step 9 — tear down trial scaffolding (Option A) [cleanup]
- Kill the responder (`kill <PID>` from Step T).
- Kill the SSH tunnel (`pkill -f 12019:127.0.0.1:2019` on the VPS).
- Revert the home Caddyfile + compose to `.bak-pre-trial-$TS2`; `docker compose up -d`;
  confirm the admin is back to container-localhost only (`10.0.0.13:2019` refused from VPS,
  `127.0.0.1:2019` refused on the LXC host).
- Final health: three prod hosts → 200; both `RestartCount` unchanged-or-explained.

---

## 5. Hard STOP-and-restore conditions (any one → stop, restore, re-verify, regroup)
1. Either edge's prod health drops (a known-good host stops returning 200) at any step.
2. crenel reports a **wedged** admin API (the crowdsec reload-storm signature on the VPS:
   `stopping admin server: 10s timeout`) — see Recovery R3.
3. Read-back-verify fails / crenel cannot confirm intent on either edge.
4. `crenel-selftest` serves an **open 200** when `--auth authelia` was requested.
5. **Collateral**: any host other than `crenel-selftest` changes reachability/auth/backend
   vs the pre-trial `status` capture.
6. The home admin becomes reachable on `10.0.0.13:2019` from the VPS (tailnet leak).
7. The byte-for-byte diff (Step 8) is non-empty and `docker restart` does not resolve it.

On any STOP: do NOT issue more crenel verbs. Go straight to Recovery, restore, verify health
+ byte-for-byte, then stop and report.

## 6. Recovery commands (the `docker restart` analog per edge)
- **R1 — VPS full restore** (re-POST the captured config verbatim):
  ```
  ssh vps-edge 'curl -sS -X POST -H "Content-Type: application/json" \
    --data-binary @~/crenel-test/live-backup/vps-front-config-<TS2>.json http://127.0.0.1:2019/load'
  # verify: diff jq -S of GET /config/ vs the backup → identical
  ```
- **R2 — HOME full restore** (re-POST verbatim via the tunnel, OR the restart analog):
  ```
  # via tunnel (running):
  ssh vps-edge 'curl -sS -X POST -H "Content-Type: application/json" \
    --data-binary @/path/home-edge-config-<TS2>.json http://127.0.0.1:12019/load'
  # OR the deterministic restart analog (reverts to the pristine :ro Caddyfile — admin edits
  #   are ephemeral, home runs WITHOUT --resume):
  ssh root@pve1 'pct exec 113 -- docker restart caddy'   # ~10 s
  ```
- **R3 — VPS admin wedge** (crowdsec reload-storm, per DIAGNOSTICS): the only reliable
  recovery is `ssh vps-edge 'docker restart caddy-edge'` (~11 s; re-reads the pristine
  Caddyfile, provisions certs async). The 443 data plane stays up during a wedge.
- **R4 — HOME admin/container issue:** `ssh root@pve1 'pct exec 113 -- docker restart caddy'`
  (~10 s; no crowdsec, clean). Reverts any ephemeral admin-API state to the `:ro` Caddyfile.

> **Wedge-avoidance note:** the trial issues at most ONE granular op per edge per verb,
> spaced by crenel's settle-between-ops — it does NOT fire the back-to-back reloads that
> trigger the VPS crowdsec wedge. The residual risk is a rollback firing a compensating
> reload right after an apply reload on the VPS; crenel's rollback is wedge-safe (probes
> health, skips a wedged edge with a recovery hint) and R3 covers it.

## 7. Boundary / honesty notes
- **Option A/B require a deliberate, reversible home-admin change.** There is no
  zero-change single-transaction path (the gating finding, §0). Option C avoids the change
  but is not atomic.
- **Home admin-API writes are ephemeral** (home runs without `--resume`): a crenel-injected
  route lives in the running config until the next `caddy reload`/`docker restart`, then
  reverts to the `:ro` Caddyfile. Fine for an expose→unexpose self-test (and a safety bonus:
  a restart wipes any residue), but it means crenel's home change is **not durable** — making
  the route permanent would require it in the SOT Caddyfile, which is out of scope here.
- **Auth fidelity (post TRIAL-FIX-3):** crenel renders the canonical
  `reverse_proxy`+`handle_response` gate from the operator-DECLARED endpoint + verify URI +
  copy-headers (or a verbatim `caddy_handler_json` blob) — VALID admin-API JSON that real
  Caddy accepts, byte-faithful to the home edge's own Authelia shape. crenel still does not
  INVENT the internals (they come from `auth_policies`). Success = the Authelia 302 challenge
  on the throwaway host; with the matching verify URI a full login should also work.
- **DNS untouched:** the wildcards already cover the host on both horizons; the trial makes
  no Cloudflare/AdGuard change and triggers no new-cert issuance.
