# Edge Diagnostics — Caddy admin-API wedge, root-caused on the live edge

**Date:** 2026-06-27 (~15:50–16:01 UTC)
**Target:** `vps-edge` (a cloud provider, aarch64), `caddy-edge` Docker container,
Caddy admin API loopback `127.0.0.1:2019`.
**Method:** read-only inventory + ONE controlled reproduction of the wedge (backup-first,
throwaway hosts → closed port 9999, recovered via `docker restart`).
**Outcome:** the wedge was **reproduced and root-caused with a goroutine dump** — the one
piece of evidence POSTMORTEM.md §7 was missing. **It corrects the postmortem's leading
hypothesis.** Production data plane (443) never dropped; admin recovered cleanly; live config
restored byte-for-byte (semantic match) to the pre-test backup.

Raw artifacts in `diag-artifacts/`: `goroutine-wedge-sample.txt` (blocked reload stack),
`goroutine-baseline.txt`, `storm-sampler-log.txt`, `wedge-window-docker-logs.txt`. Backup +
full dumps also on the VPS under `~/crenel-test/diag/` and `~/crenel-test/live-backup/`.

---

## TL;DR — corrected root cause

The admin-API wedge is **NOT** caused by TLS/Cloudflare-DNS-01 cert re-provisioning (the
postmortem's leading theory). The goroutine dump captured *during* a reproduced wedge shows the
reload blocked here, stable across the entire wedge window:

```
net/http.(*conn).serve                              ← the DELETE admin request
 └ adminHandler.ServeHTTP → handleConfig            admin.go:1069
   └ changeConfig                                    caddy.go:247   (reload runs SYNCHRONOUSLY
     └ unsyncedDecodeAndRun                          caddy.go:375    inside the admin request)
       └ unsyncedStop                                caddy.go:734
         └ crowdsec.(*CrowdSec).Stop                 crowdsec.go:309
           └ core.(*Core).Shutdown   ← BLOCKED 10s+  internal/core/core.go:231
```

**Mechanism:** the **CrowdSec bouncer's `Core.Shutdown()` hangs** while the reload tears down the
previous app instances (`caddy-crowdsec-bouncer v0.13.1`). Because Caddy runs the config change
*synchronously inside the admin HTTP handler*, that hung shutdown blocks the in-flight admin
request, which in turn prevents the outgoing admin server's `http.Server.Shutdown` from draining
— it hits Caddy's 10 s graceful cap and the admin endpoint wedges. Verbatim log:
`admin "stopping current admin endpoint" error:"shutting down admin server: stopping admin server: 10s timeout"`.

This is **hslatman/caddy-crowdsec-bouncer #61** — which the postmortem cited but ranked *below*
TLS. The dump promotes it to the confirmed mechanism. **No `caddytls`/`obtainCertificate`
goroutine appears anywhere in the blocking chain.**

**Trigger:** a **reload storm** — two config-mutating reloads ~40 ms apart with concurrent reads.
A *single, spaced* reload does **not** wedge (proven below).

---

## 1. Read-only inventory (Phase 1.1)

| Item | Finding |
|------|---------|
| Caddy version | **v2.11.4**, custom xcaddy build |
| Modules (relevant) | `dns.providers.cloudflare`, `crowdsec` + `http.handlers.crowdsec` + `layer4.matchers.crowdsec`, `layer4`, `tls.issuance.acme`/`internal`/`zerossl`, `http.handlers.acme_server` |
| Build (Dockerfile) | `xcaddy build --with github.com/caddy-dns/cloudflare --with github.com/hslatman/caddy-crowdsec-bouncer` (crowdsec bouncer **v0.13.1**) |
| Container | `caddy-edge`, image `caddy-edge:local`, **`network_mode: host`**, compose project `/opt/caddy-edge/docker-compose.yml` |
| Start cmd | `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile` (**not `--resume`** → restart loads pristine on-disk Caddyfile; autosave.json ignored) |
| **HEALTHCHECK** | **NONE** — `Config.Healthcheck` is `null`, no `State.Health`, image has no `HEALTHCHECK`. |
| RestartPolicy | `unless-stopped`, `MaximumRetryCount: 0` |
| RestartCount | **0** over the container's life; `ExitCode=0`, `OOMKilled=false` |
| Mounts | Caddyfile bind `/opt/caddy-edge/Caddyfile:ro`; `/var/log/caddy` (access logs); named volumes `/data` (certs) + `/config` (autosave) |
| Caddyfile | 2 wildcard sites `*.homelab.example` + `*.smallbiz.example`; per-host `handle @host` blocks; default-deny via `handle { abort }`; CrowdSec L7 in global block **and** per-handle; **TLS already hardened**: `(tls-cf)` has explicit `resolvers 1.1.1.1 1.0.0.1 8.8.8.8`, `propagation_delay 60s`, `propagation_timeout 300s` |
| Reload front-door (from edge runbook) | `scp` rendered Caddyfile to VPS + **`caddy reload`** (→ admin `POST /load`), triggered by a Forgejo post-receive hook / `make deploy` |

Host check: no kernel OOM / `Killed process` in `journalctl -k` or `dmesg`; no `caddy` systemd
timer; no cron restarting caddy; no docker restart/die/oom events. **There is no autonomous
restart loop and no external watchdog.**

## 2. Which failure mode is "live edits don't take"? (Phase 1.2)

Three candidates from the brief:
- **(a) on-disk Caddyfile edit + reload not applying** — *contributes.* `caddy run` does NOT watch
  the file; edits apply only via `caddy reload` → admin `POST /load` → a **full reload**. When that
  reload wedges (see §3), the edit appears "not to take" and the admin API stops responding.
- **(b) admin-API writes wedging the reload** — **CONFIRMED, this is it.** Both crenel's granular
  `PUT`/`DELETE` *and* the maintainer's `caddy reload` funnel through the same full-reload path, which
  re-provisions the crowdsec bouncer (and re-reads certs) and restarts the admin server. Under a
  storm this wedges (§3).
- **(c) healthcheck flapping the container** — **FALSIFIED.** There is no healthcheck at all.

**So "live edits don't take" and the crenel wedge are the *same* mechanism reached through two
different front-doors** (`caddy reload` vs the structured admin API). The reload count, not the
verb, is what correlates with the wedge.

## 3. Controlled reproduction (Phase 1.4) — backup-first, recovered

**Backup:** `GET /config/` → `live-backup/caddy-config-20260627T155227Z.json` (4607 B, valid;
apps crowdsec/http/tls), copied to the Mac (gitignored). Baseline goroutine dump: 76 goroutines,
admin responsive in 3 ms.

**Test A — ONE spaced granular write (one reload).** `PUT` an additive `@id` throwaway route
(`crenel-diag-selftest.homelab.example` → `127.0.0.1:9999`, index 0).
→ **CLEAN: PUT 200 in 30 ms**, admin swap drained in ~18 ms, no goroutine leak (73→59), route
count 3, prod 200. The reload re-provisioned the TLS app but **obtained no cert** — the throwaway
host matches the existing `*.homelab.example` wildcard already in `/data`, so no ACME/DNS-01 call.
**Confirms a single spaced reload is safe and fast on this edge.**

**Test B — the STORM.** `PUT` route2 then `DELETE` it **~40 ms later**, with a concurrent
`GET /config/` read loop, sampling goroutine dumps throughout.
→ **WEDGE REPRODUCED:**
- `PUT` (reload 1) 200 in 16 ms — admin swap drained.
- `DELETE` (reload 2) **hung the full 90 s** and never returned.
- Admin `GET /config/`: 200 at t+1 s, then **timeout (000) from t+2 s onward**.
- Docker log at exactly +10 s: `stopping admin server: 10s timeout` (verbatim incident signature).
- **Prod `auth.homelab.example` → HTTP/2 200 the entire time** — data plane never dropped.
- Goroutine dumps (samples 13–30, the reload-2 window) all show the identical blocked stack in §TL;DR.

Why the storm and not a single op: reload 1 starts a fresh crowdsec `Core`; reload 2, ~70 ms
later, calls `Stop()`/`Core.Shutdown()` on that barely-initialized instance and it hangs (the log
shows crowdsec "stopping…" → "processing…stopped" → "usage metrics disabled" with **no
"finished"**, vs Test A where "finished" appears). A reload re-entrancy/lifecycle hang in the
bouncer, exposed only by back-to-back reloads.

**Recovery:** `docker restart caddy-edge` (~11 s; the SIGTERM itself hit the same 10 s admin-drain
on the way down). Post-recovery: admin 200 in 0.8 ms; route count back to 2; both diag routes 404;
prod 200; `RestartCount=0 ExitCode=0 OOM=false`; **live config semantically identical to the
pre-test backup**. Edge left exactly as found.

## 4. The pre-existing "restart issues" (Phase 1.3 / §5.2c of the postmortem)

Re-attributed with evidence. There is **no healthcheck, no OOM, no watchdog, RestartCount=0** — so
the self-restarts are **not** a healthcheck hitting the wedged admin API (the postmortem's leading
guess) and **not** a crash loop. The most consistent explanation: the maintainer's "restart issues" are
**reloads wedging the admin API**, after which the only recovery is a manual `docker restart` — so
he *experiences* it as "having to restart the container," but the root event is the same crowdsec
reload-shutdown hang, reached via `caddy reload` during a deploy.

## 5. Prioritized fixes

**Edge-side (the maintainer) — these remove the wedge at the source:**
1. **The crowdsec bouncer reload-shutdown hang is the mechanism.** Options, best first:
   - Upgrade `caddy-crowdsec-bouncer` past v0.13.1 and re-test the storm (track #61); if no fix
     exists upstream, file with this goroutine dump (`diag-artifacts/goroutine-wedge-sample.txt`,
     blocked at `internal/core/core.go:231`).
   - Reduce reload frequency / **avoid back-to-back reloads** on deploys (debounce the generator so
     a deploy is ONE `caddy reload`, never a burst).
   - Consider whether the L7 crowdsec bouncer must sit in the hot reload path, or could run as the
     standalone CrowdSec firewall bouncer (L3/L4, nftables) so a Caddy reload doesn't start/stop a
     streaming bouncer each time.
2. **TLS is already mitigated** — explicit resolvers + generous propagation are in the Caddyfile,
   and certs are pre-provisioned in `/data`; reloads do not re-obtain. No action needed here (this
   *demotes* a postmortem action item).
3. Optional: a Docker healthcheck that probes **443 (data plane)**, never `127.0.0.1:2019`, so a
   slow/wedged admin reload can never turn into a restart loop. (Today there's none, which is
   *safer* than a bad one — only add a data-plane probe.)
4. Keep recovery deterministic: container already boots from the pristine Caddyfile (not
   `--resume`) — good, don't change.

**crenel-side — already shipped on `develop` (apply-hardening), validated in Phase 2:**
bounded+classified admin timeouts (never hang on a wedged API), **settle between granular ops**
(no reload storm — directly prevents the trigger reproduced here), and wedge-safe rollback (probe
health before any compensating reload; skip + print recovery hint if wedged).

---

## 6. "Why won't this edge take live edits without a `docker restart`?" (added after the maintainer's clue)

New data point: yesterday, after manually adding config, the maintainer had to `docker restart caddy-edge`
for it to take effect. Tested directly (backup-first; Caddyfile edits reverted; edge left as
found). **The reload path is NOT generally broken — it works for the common case** — so the
restart-reflex comes from several specific, identifiable failure modes, not one defect.

**Proven WORKING:** edited the mounted Caddyfile to add a benign throwaway route under the
existing `*.homelab.example` wildcard, then ran the maintainer's path
`docker exec caddy-edge caddy reload --config /etc/caddy/Caddyfile`:
→ **exit 0 in 103 ms; the route went live WITHOUT a restart** (`curl` returned the new body;
`load complete`; crowdsec drained cleanly; admin + prod stayed healthy). Reverting via a second
`caddy reload` removed it just as cleanly. **So a single, correctly-invoked reload of a
wildcard-covered change applies fine.**

**The reasons a reload "doesn't take" on THIS edge — in order of likelihood for yesterday:**

1. **Yesterday's actual change was the CUTOVER: a listener port change `*.homelab.example:8443`
   → `:443` (+ added `vpn.homelab.example` routes), done while Traefik released `:443`.** (Confirmed
   by diffing `Caddyfile.bak-precutover` → current.) A live reload cannot bind `:443` until the old
   owner frees it; a port-handoff like this legitimately needs a restart. **One-time migration
   event, not a recurring reload bug.**
2. **The `caddy reload` invocation trap.** The natural `docker exec caddy-edge caddy reload`
   (no `--config`) fails with **`Error: no config file to load`** — the container's workdir `/srv`
   has no Caddyfile. It silently applies nothing. You MUST use
   `caddy reload --config /etc/caddy/Caddyfile`. (`--adapter` is optional — it auto-detects.)
3. **The crowdsec reload-storm wedge (§TL;DR).** Any second reload fired while one is in flight
   hangs on `Core.Shutdown()` → admin wedges → that change and all subsequent reloads fail to apply
   until `docker restart`. (This is what crenel hit; a human firing two quick reloads hits it too.)
4. **Latent (armed, not currently triggered) — new-cert DNS-01 reload hang.** Cert storage is
   clean (only the two wildcard certs; no stuck locks) and **every host is a single-label sub of a
   wildcard**, so nothing currently forces issuance on reload. But the `(tls-cf)` snippet sets
   `propagation_delay 60s` + `propagation_timeout 300s`: the moment a host NOT covered by the
   wildcards is added (an apex `homelab.example`, a 2-label `a.b.homelab.example`, or a new domain),
   the reload BLOCKS 60–300 s obtaining that cert via Cloudflare DNS-01 (#5589/#7385) — "the edit
   doesn't take." A `docker restart` *appears* to fix it because on a fresh start cert provisioning
   is **asynchronous** (the server serves immediately and obtains in the background), whereas during
   a *reload* it is synchronous and blocks. **This is the most insidious form of "reloads don't
   take" and is the one to watch for.**

**Unifying cause:** on this custom build a `caddy reload` re-provisions the **crowdsec** app and the
**TLS** app *synchronously inside the admin handler*. For a wildcard-covered route change that's
~100 ms and applies live. Anything that makes that re-provision slow or hang — a reload storm
hitting the crowdsec shutdown bug (§TL;DR), or a new-cert DNS-01 issuance (§6.4) — blocks the
reload, so only a `docker restart` (re-reads the pristine Caddyfile, provisions certs
asynchronously) reliably applies it.

**Fix — makes BOTH the maintainer's manual edits and crenel reliable:**
- Always reload with the explicit form: `caddy validate --config /etc/caddy/Caddyfile && docker exec caddy-edge caddy reload --config /etc/caddy/Caddyfile`. Never the bare `caddy reload`.
- **Never fire reloads back-to-back** — debounce the generator/deploy so one deploy = one reload (avoids the crowdsec wedge).
- **Upgrade/track the crowdsec bouncer** past v0.13.1 (hslatman #61) to remove the wedge mechanism.
- For a host that needs a **new cert**, expect a 60–300 s reload (or pre-provision the cert
  out-of-band); the explicit `resolvers` already in the snippet help but don't eliminate the wait.
- A reload that changes **listener ports/bindings** (like the cutover) is the one class that
  genuinely warrants a restart.
- crenel already embodies the good-citizen version of all of this (Phase 2).
