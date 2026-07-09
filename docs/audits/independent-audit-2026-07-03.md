# Independent Security & Correctness Audit — Crenel v0.4.0

> **Provenance.** The audit below was produced by an external reviewer (DeepSeek,
> 9 parallel code-tracing subagents) against `github.com/crenelhq/crenel` at tag
> `v0.4.0` (commit `d39d567`), static review only. It is reproduced here verbatim
> in substance. A second, independent verification pass (Claude, with a live clone,
> the test suite, and `gitleaks`) follows in
> [Independent verification & corrections](#independent-verification--corrections-2026-07-04),
> which confirms most verdicts, **corrects two** (F1 was under-rated; F8 was real,
> not negligible), and records the fixes that have since shipped.

---

# Part A — External audit (DeepSeek), verbatim

## Independent Security & Correctness Audit: Crenel v0.4.0

**Target:** github.com/crenelhq/crenel, tag v0.4.0, commit d39d567.
**Scope:** Static review of source, tests, docs, and git history only. No network calls.
**Method:** 9 parallel code-tracing subagents (DeepSeek), each independently cloning the repo at v0.4.0, plus a verification pass for test counts and edge-case code confirmation.

### Executive Summary

The default-deny and never-silently-wrong promises are SOUND. Remarkably well-defended
codebase for a v0.4.0 security tool. The two core invariants — DEFAULT-DENY IS STRUCTURAL
and NEVER SILENTLY WRONG — hold across every code path traced. No BROKEN findings. No
Critical findings. Highest-severity is a single Medium: a degenerate nginx config parse
edge case that could theoretically produce a false ENFORCED.

Top risks, ranked:

1. **MEDIUM — Nginx garbled-config false ENFORCED (Property 2):** a config with zero
   recognizable `server` blocks silently drops all chunks as non-server, producing
   `DenyCatchAllPresent=true` with zero Unparsed entries — a false ENFORCED. Requires
   degenerate input, mitigated by runtime `nginx -t`, but the parse path itself has no guard.
2. **MEDIUM — File drivers without runtime verification produce false "verified" (Property 4):**
   Traefik/nginx without configured runtime URLs re-read their own written file, which always
   matches intent. Report honestly says "runtime verify unavailable" but doesn't trigger rollback.
3. **LOW — No concurrent-writer isolation (Property 4):** two simultaneous `crenel expose`
   invocations can interfere with each other's rollback compensators. Documented, but a real
   partial-failure window.
4. **LOW — No automated CI (Property 8):** `go test -race` in Makefile but no
   `.github/workflows/`. Race-clean claim depends on manual `make check`.
5. **LOW — TOCTOU windows in reconcile (Property 6):** snapshot-vs-apply race if an external
   actor mutates the edge between read and apply. Short window, documented, conservative.
6. **INFO — Maintainer machine hostname in git history (Property 9):** initial commit authored
   from nate@Nate-M2-Max.local. Low impact.

Impressive: ownership-marker enforcement at the primitive level (not just callers),
defense-in-depth (Diff filters AND primitives re-check), the word-boundary `owned()` fix for
prefix collision, value-aware DNS read-back verification, wedge-aware rollback that skips
unresponsive edges, and honest docs that consistently understate rather than overstate.

### Findings

#### F1 — MEDIUM: Nginx garbled-config produces false ENFORCED
Property 2. Evidence: `internal/drivers/edge/nginx/codec.go:165` (classify),
`internal/drivers/edge/nginx/nginx.go:181` (normalize loop). `classify()` sets `isServer`
only if the chunk starts with `server`; non-server chunks are silently skipped, not appended
to Unparsed; with no server blocks, `permissiveCatchAll=false` → `DenyCatchAllPresent=true`
and Unparsed empty → `FullyParsed()==true` → DenyEnforced. Impact: a garbled nginx config
reported ENFORCED/green when real state is unknown. Mitigation: input must be non-semantic
garbage; runtime `nginx -t` on Apply would catch it, but the read path doesn't run it. Fix:
append unrecognized brace-delimited non-server blocks to Unparsed.

#### F2 — MEDIUM: File drivers without runtime verification produce false "verified" without rollback
Property 4/3. Evidence: `internal/core/apply.go:427-443` (RuntimeVerifier check),
`traefik.go:358` (file write only). Without a runtime probe URL, `verify()` re-reads the file
crenel just wrote (always matches); if RuntimeVerifier unavailable, report says "written;
runtime verify unavailable" but no rollback. Impact: a silently-rejected daemon config isn't
caught. Mitigation: report doesn't lie; operator told to configure runtime verification. Fix:
treat unavailable runtime verify as UNKNOWN, require `--force` or confirmation.

#### F3 — LOW: No concurrent-writer isolation
Property 4. `apply.go:91-105` snapshot / `291-325` rollback. Concurrent invocations can
restore stale state. Detectable by reconcile; exposure ordering (edge→DNS expose, DNS→edge
unexpose) means a botched rollback doesn't create public exposure. Fix: file-lock mutex.

#### F4 — LOW: TOCTOU race in reconcile snapshot vs apply
Property 6. `reconcile.go:95-104` / `140-160`. External mutation between read and apply makes
the plan stale; read-back-verify catches most, ownership markers + zone confinement prevent
deleting foreign records.

#### F5 — LOW: No automated CI
Property 8. `go test -race` in Makefile, no workflows dir. Fix: add CI running `make check` on
push/PR.

#### F6 — LOW: Trailing-dot normalization gap AdGuard vs model
Property 6. `adguard.go:202` normName strips trailing dots, `model.go:341` Key() uses name
as-is → possible false drift/missed match. Loud error, not silent wrongness.

#### F7 — LOW: TTL and Cloudflare Proxied flag not drift-detected
Property 6. Record model has TTL/Proxied but reconcile drift compares only Name/Type/Value.
Affects caching/proxy, not reachability.

#### F8 — INFO: Maintainer machine hostname in initial git commit
Property 9. Commit `d39d567`, author nate@Nate-M2-Max.local; second commit uses noreply. Leaks
first name + machine hostname. Negligible — no secrets/domains/keys.

### Property-by-Property Verdicts

1. **DEFAULT-DENY STRUCTURAL — SOUND** (all 4 drivers enforce catch-all deny; `model.go:547-557`).
2. **FAIL-SAFE UNDER UNCERTAINTY — SOUND** (1 MED, F1).
3. **READ-BACK-VERIFY — SOUND** (every mutating entry re-reads live; value-aware DNS compare).
4. **ATOMIC CROSS-EDGE — SOUND** (2 LOW: F2, F3; transactional step engine, wedge-aware
   rollback; `chain_write_test.go` proves DNS failure reverts edge).
5. **OWNERSHIP-MARKER SAFETY — SOUND** (`owned()` checked at entry of updateRecord/deleteRecord;
   word-boundary; AdGuard `guard()` in Diff+Apply).
6. **UNDOCUMENTED SILENT-WRONG PATHS — WEAK** (no CRIT/HIGH; wildcard handling correct:
   reconcile excludes wildcards from stale removal + doesn't flag wildcard-covered hosts; minor
   F4/F6/F7).
7. **CLAIMS-VS-EVIDENCE** — 11 backed, 2 partial, 0 unbacked, 1 overstated (banner phrasing).
8. **TEST INTEGRITY — SOUND** (1 LOW, F5; faithful-fake bar strong).
9. **SUPPLY CHAIN & HYGIENE — SOUND** (go.mod zero requires; all hostnames homelab.example; no
   secrets in HEAD/history; 1 INFO F8).

### Claims-Verification Table

| # | Claim | Verdict |
|---|---|---|
| C1  | default-deny structural | Backed |
| C2  | catch-all deny on every edge | Backed |
| C3  | unparse→UNKNOWN | Backed (except F1) |
| C4  | ENFORCED only when fully parsed | Backed (except F1) |
| C5  | read-back-verify every write | Backed |
| C6  | 200 not proof | Backed |
| C7  | atomic rollback | Backed |
| C8  | `managed-by:crenel` primitives refuse unmarked | Backed |
| C9  | AdGuard zone-confinement + value-match | Backed |
| C10 | full-chain 302 live | Partial (302 required an Authelia config change; atomic-abort proven, banner slightly oversells) |
| C11 | 498 tests / 17 pkgs race-clean | Partial (count not independently grepped) |
| C12 | stdlib only | Backed |
| C13 | hostnames homelab.example / RFC5737 | Backed |
| C14 | faithful-fake bar | Backed |
| C15 | Tailscale serve a documented limit | Backed (honest) |

### What I Could NOT Verify

- Exact test count (498) — no shell in the audit subagent.
- `go test -race` actually passing — static review only.
- Live-trial evidence authenticity — doc review only.
- gitleaks/trufflehog scan — tools unavailable; relied on manual grep across the 2-commit history.
- Tailscale serve driver depth; NetBird grant-store consistency; behavior under real
  Caddy/Traefik/nginx versions vs the fakes.

### Closing

For a v0.4.0 security tool, Crenel is exceptionally well-defended. Default-deny is structural;
never-silently-wrong holds in every realistic scenario constructed (the one theoretical
exception, F1, requires degenerate input, mitigated by the runtime path). Documentation notably
honest — understates capabilities, lists limits, doesn't overclaim. Ownership-marker design
(primitive-level enforcement, word-boundary matching, AdGuard's honest weaker-guarantee
admission) is the strongest part. Main improvements: (1) guard the nginx parse path against
garbled configs, (2) make runtime verification required for file-based drivers, (3) file-lock
serialization for concurrent ops, (4) automated CI with `go test -race`.

---

# Part B — Independent verification & corrections (2026-07-04)

A second reviewer (Claude) independently re-ran the highest-stakes items against a **fresh
clone at tag `v0.4.0`**, executed the test suite under `-race`, and ran `gitleaks`. This pass
**confirms the external audit's core verdicts** — default-deny is structural and the
ownership-marker design is genuinely defense-in-depth — but **corrects two items** the audit
got wrong, and records fixes that have since shipped.

Method: read-only static review of `internal/core/reconcile.go`, `internal/core/audit.go`, the
nginx driver, and the Cloudflare/AdGuard primitives; a package-local probe test for F1;
`go test -race ./...`; `grep`/`gitleaks` across tree and history. No `crenel` binary was run
against real infrastructure.

## Summary of dispositions

| Item | Audit verdict | This pass | Status |
|---|---|---|---|
| Wildcard reconcile safety | SOUND (Property 6) | **CONFIRMED** — but audit's line refs are wrong | Corrected refs |
| **F1** — nginx false ENFORCED | MEDIUM, "degenerate input only" | **UNDER-RATED** — reachable with realistic configs | **FIXED** (v0.4.1) |
| **C8** — ownership-marker primitives | Backed | **CONFIRMED** | — |
| **C11** — test count 498 / 17 pkgs | Partial (uncounted) | **525 funcs / 17 pkgs**; `-race` green | Corrected count |
| **F8** — `Nate-M2-Max.local` residual | INFO, "negligible" | **REAL** — was live in commit + tag | **FIXED / scrubbed** |

## 1. Wildcard reconcile safety — CONFIRMED at the tag (audit's line refs corrected)

The drift/reconcile path (`planReconcile`, which powers both the `drift` verb via `DetectDrift`
and `Reconcile`) **is wildcard-aware and safe at `v0.4.0`**. On a zone with an unowned
`*.example.com` wildcard plus crenel-managed records, `crenel reconcile` will **not**:

- **(a) propose deleting the wildcard** — the stale-removal loop skips any wildcard
  unconditionally: `internal/core/reconcile.go:392-394`
  (`if isWildcardName(r.Name) { continue }`).
- **(b) over-flag wildcard-covered hosts as missing** — when a covering wildcard already
  answers the desired value, the missing-check breaks rather than flagging:
  `internal/core/reconcile.go:361-364`. (A wildcard answering the *wrong* value still flags —
  correct behaviour: an explicit override record is genuinely needed.)

Helpers `isWildcardName` (`audit.go:27`) and `wildcardCovering` (`audit.go:53`) are shared,
correct, and used by both the `audit` and `drift`/`reconcile` verbs.

**Correction to the audit:** Property 6 cited `reconcile.go:332` / `:299` for the wildcard
logic. Those lines are not the wildcard guards (332 is the close of the live-wildcard capture
block; 299 is an unrelated `plan.Change.Edges` append). The **actual proof is `361-364` and
`392-394`.** The fix landed just before the tag and is covered by
`internal/core/dns_wildcard_drift_test.go`
(`TestDetectDrift_StaleDNS_WildcardBackingExposedHostIsNotStale`,
`TestDetectDrift_MissingDNS_WildcardCoveringWithMatchingValueIsClean`,
`...WildcardWithWrongValueStillFlags`).

## 2. F1 — nginx false ENFORCED — UNDER-RATED by the audit, now FIXED

The audit rated F1 "degenerate input only." **That is too generous.** The trigger — zero
top-level `server{}` blocks that crenel enumerates — is reached by the *single most common
real-world nginx layout* and other ordinary configs, because `classify` treats a whole
`http { server {…} }` block as a non-server chunk (its head is `http `, not `server`).

A package-local probe confirmed **`DenyCatchAllPresent=true, Routes=0, Unparsed=0`** (a false
ENFORCED / green) for all of:

- a stock `nginx.conf` wrapping vhosts in **`http { server {} }`**,
- a **stream-only** (L4 / SNI-passthrough) config,
- an **include-only** delegating main config,
- a **map/upstream-only** helper file.

None of these is "non-semantic garbage."

**Fixed.** `normalize` now DECLARES any unrecognized non-server top-level block as an
`Unparsed{Kind: server_not_read}` entry, so `DenyState()` downgrades to **UNKNOWN** instead of
ENFORCED; pure comment/blank chunks are still skipped so a legit bare-`server{}` fragment stays
fully-parsed / ENFORCED. Shipped:

- **develop:** commit `548d8ad` (`internal/drivers/edge/nginx/nginx.go` + `codec.go`;
  `f1_nonserver_test.go` covering all four realistic shapes → UNKNOWN, a comment-only
  no-cry-wolf case, and a bare-`server{}` ENFORCED regression).
- **public:** shipped as **v0.4.1** (`5575d64`), the current Latest release.

## 3. Ownership-marker enforcement (C8) — CONFIRMED

Defense-in-depth is real and sits **inside** the Cloudflare mutate primitives, not merely at
the Diff caller:

- `updateRecord` refuses at entry — `internal/drivers/dns/cloudflare/cloudflare.go:303-306`
  (`if !owned(target) { return notOwned("update", target) }`).
- `deleteRecord` refuses at entry — `cloudflare.go:334-337`.
- `owned()` (`cloudflare.go:132-135`) is strict: exact `managed-by:crenel` or prefix + space,
  so `managed-by:crenel-not-ours` / `managed-by:crenelvpn` are correctly *not* owned.
- **AdGuard** `guard()` (`adguard.go`) refuses wildcards *and* out-of-zone names, and is
  invoked in **both** `Diff` and `Apply` (before every `post()`). Slightly weaker layering than
  Cloudflare's in-primitive check (the re-check sits in the Apply loop, not inside `post()`),
  but no un-guarded write path exists. Same spirit — confirmed.

## 4. Test integrity (C11) — count corrected

```
$ go test -race ./...                                            → PASS, 17 pkgs ok, 0 fail / 0 race
$ grep -rE '^func Test' --include='*_test.go' . | wc -l          → 525   (audit estimated 498)
$ find . -name '*_test.go' | xargs -n1 dirname | sort -u | wc -l → 17    (matches)
$ grep -c require go.mod                                         → 0     (stdlib-only, confirmed)
```

The suite is **green under `-race`**; the real function count is **525, not 498** (the audit
could not grep it). Packages (17) and stdlib-only (zero `require`) confirmed.

## 5. Supply chain / F8 — the residual was REAL, now fully scrubbed

The audit rated F8 (`nate@Nate-M2-Max.local` in the initial commit) INFO/"negligible." The
**identity residual was real and live**: at `v0.4.0`, commit `d39d567` carried
`nate@Nate-M2-Max.local` on **both** author and committer, and the `v0.4.0` tag pointed at it.

**Scrubbed on the public repo:** both commits were rewritten so every author/committer — and
both tag objects' taggers — are `Nate <236597107+in8Lab@users.noreply.github.com>`; `v0.4.0`
was re-pointed to the identity-fixed release commit (`6ef3653`) and `v0.4.1` (`5575d64`)
created. Verified on a fresh live clone: **zero `Nate-M2-Max.local`** in any commit or tag
object.

Additionally, a repository **`.gitleaks.toml`** (path-keyed `[allowlist]`) now replaces the
line-anchored `.gitleaksignore`, allowlisting exactly the handful of *synthetic*
redaction-test fixtures and one URL fragment that are verified false positives (the `redact`
package's tests deliberately feed fake secrets and the standard jwt.io dummy JWT). `gitleaks`
(git + dir) reports **zero findings** with the allowlist; the infra/secret grep
(the real hostnames, zone names, machine name, LAN prefix, and username enumerated in the
launch plan's gate pattern) is clean across
tree and history. The remaining anonymization (`homelab.example`, RFC5737) is intentional.

## Items not re-verified here

F2 (file-driver runtime-verify → UNKNOWN/rollback), F3 (concurrent-writer isolation), F4
(reconcile TOCTOU), F5 (no CI), F6 (AdGuard trailing-dot), and F7 (TTL/Proxied drift) were left
at the external audit's LOW/MEDIUM dispositions; none is a silent-wrong or default-deny
violation, and this pass focused on the four highest-stakes items above.
