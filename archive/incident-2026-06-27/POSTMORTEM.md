# Post-mortem — Caddy admin-API wedge during the first live Crenel mutating demo

**Date of incident:** 2026-06-27, ~07:52 ET (11:52 UTC)
**Author:** Crenel build session (resumed 2026-06-27)
**Severity:** control-plane only — Caddy admin API (127.0.0.1:2019) unresponsive
~90 s+. **Production data plane (443) never went down.** No customer-facing outage.
**Status:** RESOLVED by `docker restart caddy-edge`. Edge healthy and clean.
**Blast radius:** one throwaway host (`crenel-selftest.homelab.example`); DNS untouched.

This is a blameless post-mortem. The goal is to understand the failure mechanism
from evidence, not to assign fault. The short version: **crenel provoked a real
Caddy admin-server reload deadlock by firing several config-mutating reloads in a
~75 ms burst.** It is an *interaction* bug — crenel's apply pattern is the
trigger, Caddy's per-reload admin-server restart is the mechanism. Both ends get a
fix.

---

## 1. What we were doing

First live *mutating* demo of Crenel against the real production edge
(`vps-edge`, a cloud provider, Caddy in the `caddy-edge` Docker container,
admin API loopback-bound on 127.0.0.1:2019). Strict guardrails: run on the VPS
against the loopback admin API, additive granular apply only, a throwaway host
mapped to a closed port (127.0.0.1:9999), DNS not touched, full config backup
taken first.

The plan: `expose crenel-selftest` (insert one `@id`-tagged route), confirm, then
`unexpose crenel-selftest` (delete that route) and prove the edge was byte-for-byte
back to the backup.

## 2. Timeline (from `docker logs caddy-edge`, authoritative)

Times UTC; ET = UTC−4.

| UTC | Event |
|-----|-------|
| 11:51:09 | `GET /config/` — backup / read-only proof (curl). Healthy. |
| 11:52:49.512 | **`PUT /config/apps/http/servers/srv0/routes/0`** — crenel inserts the expose route. |
| 11:52:49.514 | `admin endpoint started` — the PUT-triggered full reload **restarts the admin server**. |
| 11:52:49.526–.585 | Several `GET /config/` (crenel read-back + status, interleaved). |
| 11:52:49.532 | `stopped previous server` — first admin swap drains cleanly (**18 ms**). |
| 11:52:49.586 | **`DELETE /id/crenel-route-crenel-selftest.homelab.example`** — crenel's unexpose, **~37 ms after the PUT's reload**. |
| 11:52:49.587 | `admin endpoint started` — the DELETE-triggered reload **restarts the admin server again**. |
| 11:52:59.588 | **`ERROR admin "stopping current admin endpoint" error:"shutting down admin server: stopping admin server: 10s timeout"`** — exactly 10 s later, the outgoing admin server **fails to drain**. Admin endpoint now wedged. |
| 11:55–11:59 | `GET /config/` probes (curl, every ~30–60 s) — these are the "no response 90s+" reads. |
| 12:29:08 | `SIGTERM` (the `docker restart` recovery). `shutting down apps … exiting; byeee!! 👋` |
| 12:29:18 | `serving initial configuration` — fresh start from the **pristine on-disk Caddyfile**. 10 s gap from SIGTERM (the admin server hit its 10 s drain timeout *again* on shutdown). |
| (now) | `GET /config/` → `ADMIN_OK`. `RestartCount=0`, `ExitCode=0`, `OOMKilled=false`. Edge healthy. |

## 3. What worked

- **Read path — fully correct on the real edge.** `status` / `preview` / `audit`
  read production correctly: default-deny PRESENT, the two `*.homelab.example` /
  `*.smallbiz.example` wildcard **subroutes** surfaced, audit exit 0.
- **The M2 model fix held.** The normalizer now understands subroute-based configs
  and Caddy's implicit-404 default-deny — the real edge read as default-deny
  *satisfied*, not a false fail-open (the M0 gap that blocked the earlier demo).
- **The additive granular insert did exactly what the CI test predicted.** After
  the `PUT`, the config had 3 routes: both wildcard subroutes **intact** and the
  single `@id`-tagged crenel route at index 0. Read-back-verify PASSED
  ("crenel-selftest… is now reachable"). **No unmanaged route was touched** — the
  additivity property is real and proven on production.
- **The data plane never dropped.** reverse_proxy access logs (jellyfin, auth,
  etc.) continue straight through the incident window. The reload swaps HTTP
  servers gracefully; only the *admin* endpoint wedged.
- **Recovery was deterministic.** The container boots from the pristine on-disk
  Caddyfile (not `--resume`/autosave), so `docker restart` restored the exact
  original config and cleared the wedge in one step.

## 4. What failed

- **`unexpose` wedged the Caddy admin API for ~90 s+.** The `DELETE`-triggered
  reload's admin-server swap deadlocked; the outgoing admin server could not drain
  within its 10 s timeout, and the endpoint stayed unresponsive until
  `docker restart`.
- **crenel returned an ambiguous error and the DELETE did not take effect.** Its
  flat 10 s client timeout fired at the same instant as Caddy's internal 10 s
  admin-drain timeout, so crenel reported a timeout with no clear "the admin API
  is wedged; here's how to recover" signal.
- **A dangling in-memory test route was left** (`crenel-selftest` → 502 to the
  closed 9999) until the restart. Harmless (throwaway host) but not "as found."
- **The prior overnight session itself hung** on an admin probe with **no
  timeout** against the by-then-wedged API — a request to a wedged endpoint never
  returns. That hang is the same failure class one layer out (the *tooling/manual
  probe* lacked a bounded timeout, just as the wedge lacked a bounded client cap).

## 5. Root-cause analysis

### 5.1 The mechanism (high confidence — directly in the logs)

**Every write to `/config/…` (PUT/POST/PATCH/DELETE) and every `POST /load`
triggers a *full* Caddy config reload.** On each reload Caddy re-provisions all
apps and calls `replaceLocalAdminServer`, which **starts a new admin server and
stops the previous one** — visible as the paired `admin endpoint started` /
`stopped previous server` log lines on *every* granular op. The outgoing admin
server is stopped via a graceful `http.Server.Shutdown` that **waits for in-flight
admin requests to drain, with a 10 s cap**.

crenel issued, within ~75 ms: `PUT` → several `GET /config/` → `DELETE`. That is a
**reload storm** — two config-mutating reloads back-to-back, each restarting the
admin server, interleaved with concurrent reads. The first swap drained in 18 ms.
The second (DELETE) could not: the request driving the reload — and/or the
overlapping in-flight GETs on the outgoing server — kept the old admin server from
draining, so its `Shutdown` hit the **10 s timeout** (logged verbatim at
11:52:59.588) and left the admin endpoint in a wedged transitional state.

This is a **self-induced admin-server-restart deadlock**: a reload that restarts
the admin server, driven *through* that same admin server, while other admin
requests are in flight. It is a known-shaped Caddy footgun, not a Caddy crash —
note `RestartCount=0`, `ExitCode=0`, no panic, no goroutine dump in the logs.

**Key correction to a design assumption:** granular structured-admin ops are
**additive but NOT lighter** than `POST /load`. Each granular write is a *full*
reload. So a multi-step granular sequence (expose **then** unexpose in one demo
run) causes *N* reloads / *N* admin-server restarts — strictly more reload churn
than a single batched `POST /load`. The reload count, not the apply verb, is what
correlates with the wedge.

### 5.2 The three hypotheses, weighed against evidence

**(a) crenel's apply path — the PUT/DELETE sequence + no bounded behavior.**
*Verdict: the TRIGGER. Confirmed contributor.*
- Evidence FOR: the wedge begins immediately after crenel's DELETE; the reload
  storm (PUT+GETs+DELETE in 75 ms) is entirely crenel's traffic pattern; crenel's
  flat 10 s client timeout gave up with no useful classification; and the prior
  session's hang was a no-timeout probe.
- Evidence AGAINST being the *whole* story: a single, well-spaced reload is normal
  and safe — the PUT's own admin swap drained in 18 ms. crenel didn't do anything
  Caddy forbids; it just did it too fast and too concurrently.
- **What would distinguish it:** replaying a *single* spaced-out granular op (one
  reload, wait for the admin endpoint to settle, verify, stop) should NOT wedge.
  Firing two reloads <100 ms apart with concurrent reads should reproduce it.
- **Fix (in this PR):** bounded+configurable timeouts on every admin call; a
  generous *write* timeout (don't abort a legitimately-slow reload at 10 s);
  **serialize and space mutations** — apply one op, poll until the admin endpoint
  is healthy *and* the change is visible, then proceed; minimize reload count
  (batch multi-route changes into ONE reload); and on timeout, health-probe before
  doing anything else (never pile a compensating reload onto a wedged admin
  server).

**(b) Caddy admin-server reload deadlock, possibly aggravated by the custom
xcaddy + cloudflare-dns build.** *Verdict: the MECHANISM. Confirmed for the
admin-restart deadlock; the cloudflare-DNS aggravation is plausible but NOT proven
by these logs.*
- Evidence FOR the deadlock: the verbatim `"stopping admin server: 10s timeout"`
  error; the per-reload `admin endpoint started` / `stopped previous server`
  churn; even the SIGTERM recovery took ~10 s (same admin-drain timeout). This is
  real Caddy reload behavior, independent of crenel.
- On the custom build: confirmed it **is** a custom xcaddy build — `caddy version`
  = **v2.11.4**, with `dns.providers.cloudflare v0.2.4` compiled in (plus
  `tls.issuance.acme` / `http.handlers.acme_server`). Every full reload
  re-provisions the TLS app. Caddy's own behaviour here is the missing link:
  **a reload flushes the certificate cache and synchronously re-reads/re-caches
  all certs from storage** (caddyserver/caddy **#5589** — measured at 10–15 s for
  ~50 sites on local disk, *minutes* on networked storage), and **if a cert can't
  be (re)provisioned the reload blocks — historically forever** (caddyserver/caddy
  **#7385**, fixed in PR #7597). For a Cloudflare **DNS-01 wildcard** build, that
  re-provisioning can stall on the Cloudflare API / DNS-propagation checks for
  tens of seconds. **This is almost certainly why the outgoing admin server could
  not drain:** the in-flight `DELETE` request was blocked *inside* the reload
  (re-provisioning TLS) when Caddy tried to replace the admin server, so its
  graceful `Shutdown` hit the 10 s cap. The admin-drain timeout we see in the logs
  and the cert-cache-flush mechanism are the **same event**, not competing ones.
- Honesty caveat: our grep of the wedge-window logs surfaced the admin-drain
  timeout but did **not** capture explicit `certificate obtaining` / `reprovision`
  lines (we filtered on a keyword set; they may simply not have been in the
  sampled lines). The cert-reprovision-blocks-reload chain is strongly supported by
  Caddy's docs and the upstream issues above, and fits the timing perfectly, but to
  *prove* it on this edge, capture a goroutine dump + unfiltered reload logs next
  time (see §7).
- **What would distinguish it:** capture `GET /debug/pprof/goroutine?debug=2`
  during a wedge (shows whether goroutines are blocked in TLS/ACME provisioning vs
  admin shutdown); time a single `POST /load` of an unchanged config (measures
  pure reload+reprovision cost on this build); compare reload latency with the
  cloudflare module removed.
- **Fix (Caddy side, for the maintainer — not crenel):** upstream-track the admin-restart
  deadlock (see §6); consider whether the edge needs the admin endpoint at all in
  steady state, or whether reloads should go via `caddy reload`/SIGUSR1 from disk
  rather than the live admin API; keep reloads infrequent.

**(c) the maintainer's pre-existing restart instability with the custom build.**
*Verdict: NOT supported as a crash-loop in the observable window, but consistent
with the same reload mechanism.*
- Evidence AGAINST a crash-loop: `RestartCount=0` over the container's 15 h life;
  the only restart in the logs is the clean manual recovery (`SIGTERM`, exit 0);
  no panic / OOM / signal-kill anywhere in retained logs.
- Evidence that RECONCILES it: if the maintainer's "restart issues" are really *reloads
  hiccuping the edge* (every config change restarts the admin server **and**
  re-provisions Cloudflare DNS-01 TLS), then his symptom and this incident share
  one mechanism — reloads on this build are expensive and admin-disruptive. The
  most likely concrete path: **a container healthcheck / liveness probe hits the
  admin API (or a `/load`-based probe) while a reload is wedged, times out, and the
  orchestrator restarts the container** — i.e. the self-restarts are a *symptom of
  (b)*, not independent instability. (No known crash/OOM bug exists for
  cloudflare-dns v0.2.4 or Caddy 2.11.4 — researched, none found.) Worth checking
  the container's healthcheck definition. Spontaneous restarts unrelated to reloads
  are not evidenced here (`Memory=0` = *unlimited*, so not a cgroup OOM) and would
  need a longer log window / host dmesg to characterise.
- **What would distinguish it:** persist Docker logs beyond container lifetime
  (json-file is volatile across recreate) and check `journalctl`/host dmesg for
  prior OOM/kills; watch `RestartCount` and `State.FinishedAt`/`ExitCode` over
  days; if restarts correlate with reloads (deploys), it's the same mechanism.
- **Fix:** out of crenel's scope, but crenel should be a *good citizen* on a
  reload-fragile edge — which is exactly what §3's hardening makes it.

### 5.3 Leading conclusion

The incident is **(a) triggering (b)**: crenel's rapid-fire multi-reload apply
pattern provoked a Caddy reload that blocked while re-provisioning the TLS app, so
the admin-server swap could not drain its in-flight request and hit the 10 s
graceful-shutdown timeout. The TLS/Cloudflare-DNS-01 re-provisioning aggravator is
**strongly supported upstream** (Caddy docs + #5589/#7385) and **fits the timing
exactly**, though direct edge-side proof (a goroutine dump showing the reload
blocked in TLS provisioning) is still TODO. (c) is not evidenced as a spontaneous
crash-loop in the available window; if real it most likely shares this same reload
mechanism (a healthcheck restarting the container while the admin API is wedged). The fix Crenel
owns is to stop creating reload storms and to never hang or blindly pile on when a
reload is slow or wedged.

## 6. Known-upstream check

This failure shape is **well-documented upstream and never definitively
root-caused** — it's a recognised pattern, not a single bug number.

**Granular ops = a full reload (the load-bearing correction), per Caddy's own docs:**
- Caddy Architecture docs: "The admin API endpoints — which permit granular
  changes by traversing into the structure — **mutate only an in-memory
  representation of the config, from which a whole new config document is generated
  and loaded.**" A reload "works by **provisioning the new modules**." → our
  `PUT`/`DELETE` each regenerate the *entire* config and run a **full provision
  cycle of all apps**, TLS included. Granular is **not** lighter than `POST /load`;
  only an *identical* config is short-circuited.
  https://caddyserver.com/docs/architecture · https://caddyserver.com/docs/api

**Reload blocks on TLS/ACME re-provisioning (the aggravator, strong support):**
- **caddyserver/caddy #5589** — a reload **flushes the cert cache and synchronously
  re-reads all certs from storage**; 10–15 s for ~50 sites locally, *minutes* on
  networked storage. https://github.com/caddyserver/caddy/issues/5589
- **caddyserver/caddy #7385** — if a cert/key can't be provisioned during reload,
  servers enter "shutting down with eternal grace period" and **the reload hangs
  indefinitely**; fixed by PR #7597. A momentarily-unobtainable Cloudflare DNS-01
  wildcard cert sits exactly in this mode. https://github.com/caddyserver/caddy/issues/7385

**Admin API hang / reload deadlock (the symptom class, no canonical fix):**
- **caddyserver/caddy #6844** — admin API hangs when adding config via the API
  (2.7.5/2.8.4/2.9.1); no confirmed root cause. https://github.com/caddyserver/caddy/issues/6844
- **caddyserver/caddy #4495** — process locks up on reload; "needs info."
  https://github.com/caddyserver/caddy/issues/4495
- **caddy.community "/load endpoint sometimes times out"** — `/load` intermittently
  hangs with `context deadline exceeded`; thread logs show **TLS provisioning during
  the reload**. https://caddy.community/t/load-api-endpoint-sometimes-times-out/9644
- **hslatman/caddy-crowdsec-bouncer #61** — graceful reload makes the admin API hang
  with `shutting down admin server: context deadline exceeded` — the **exact
  signature** here (admin wedges, data plane keeps serving).
  https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61

**Custom-build crash/OOM:** no known crash/OOM/self-restart attributable to
`caddy-dns/cloudflare` v0.2.4 or Caddy 2.11.4 (searched). The self-restarts are
better explained by a healthcheck hitting the wedged admin API (§5.2c) than by a
build bug.

**Upstream-side mitigations worth taking on the edge (the maintainer):** add explicit
`resolvers` to the TLS block to cut DNS-propagation stalls; ensure the container
healthcheck does **not** probe `127.0.0.1:2019` with a short timeout (turns a slow
reload into a restart loop); upgrade past the #7385 fix (PR #7597) so a transient
cert failure no longer hangs the reload forever; prefer infrequent disk-based
`caddy reload` over live-admin mutation.

## 7. Action items

| # | Action | Owner | Where |
|---|--------|-------|-------|
| 1 | Bounded + configurable timeouts on **every** admin call (read + write); never hang. | crenel | `fix/apply-hardening` |
| 2 | Serialize mutations + post-op readiness poll (admin healthy AND change visible) before the next op; settle between granular ops. | crenel | `fix/apply-hardening` |
| 3 | Minimise reloads: batch multi-route changes into ONE reload; document that granular ≠ lighter. | crenel | `fix/apply-hardening` |
| 4 | On timeout/failure: health-probe the admin endpoint first; only roll back if it is responsive; otherwise STOP and print the manual-recovery command. Never pile a compensating reload onto a wedged admin server. | crenel | `fix/apply-hardening` |
| 5 | Tests incl. a fake admin API that hangs, proving crenel times out cleanly and reports rather than hanging. | crenel | `fix/apply-hardening` |
| 6 | Capture a goroutine dump next time a wedge is reproduced (read-only `GET /debug/pprof/goroutine?debug=2`) to confirm the admin-shutdown block. | the maintainer | runbook |
| 7 | Decide the edge's reload strategy: prefer infrequent, disk-based `caddy reload`/SIGUSR1 over live-admin mutation; track the admin-restart deadlock upstream. | the maintainer | edge ops |
| 8 | Persist Docker logs across container recreate + check host for prior OOM/kills to characterise (c). | the maintainer | edge ops |

## 8. Lessons

- **A 200 (or a 2xx) is not the unit of safety; the *reload* is.** Count reloads,
  space them, and confirm each settled before the next.
- **Additive ≠ cheap.** Granular admin ops preserve unmanaged routes (the property
  we needed) but each is still a full reload. Optimise for *fewest reloads*.
- **Every external call needs a bounded timeout** — including ad-hoc probes. The
  tool hanging is the same bug as the wedge, one layer out.
- **Health beats a finished demo.** The guardrails worked: throwaway host, no DNS,
  pristine-Caddyfile recovery, data plane never down.
</content>
</invoke>
