# Crenel: Security Model

> Part of the [third-party audit package](../AUDIT.md). This doc states what
> Crenel **guarantees**, and what it **trusts** to be true in order to make
> those guarantees. It is the "what should hold" companion to
> [CLAIMS-TO-VERIFY.md](CLAIMS-TO-VERIFY.md) (which turns each guarantee into
> something to try to break) and [THREAT-MODEL.md](THREAT-MODEL.md) (what it
> defends against).
>
> This doc is about **correctness**: does Crenel ever tell the operator
> something false about what's exposed, or silently fail to enforce what it
> claims. For the **secrecy** axis (credential handling, the loopback-admin
> trust model, output redaction), see `SECURITY.md` in the repo root. That
> document is the authoritative source for anything touching secrets and is
> not restated here.

---

## 1. What Crenel guarantees

Five guarantees, each backed by a specific mechanism in the code. Full
rationale for each lives in `../internal/DESIGN.md`; this is the auditor-facing summary of
*what is promised*, not the design narrative.

### 1a. Live-state-authoritative: nothing to drift from

Crenel keeps **no stored desired state**. There is no `crenel.yaml` that says
"this is what should be exposed." The only intent that exists is the command
currently running (`model.Op`), and it is discarded when the process exits.
Every read command (`status`/`audit`/`drift`) reads the edge live, every time.

**Mechanism:** `ports.EdgeProvider.ReadLiveState` / `ports.DNSProvider.LiveRecords`
are the only source of truth `core` ever consults; there is no persisted-op
type, no cache, no "last known good."

### 1b. Structural default-deny: exposure is opt-in, enforced by an invariant

A host is reachable **iff** an explicit `expose` added a route for it. Every
`EdgeProvider` driver must always render and report a catch-all deny;
`LiveEdgeState.DenyCatchAllPresent` is load-bearing.

**Mechanism:** each driver's `normalize` computes `DenyCatchAllPresent`
independently from its own config shape; `core.DenyState()` derives the
reported verdict from it (see 1c for the ternary refinement); `audit` treats a
missing deny as **critical**.

### 1c. Bounded honesty: never silently misreports (detect-and-declare-unknown)

Crenel's confidence is bounded by what it actually parsed. Anything a driver's
`normalize` cannot fully model (an unrecognized handler, an undescended
subroute, a matcher-conditional route, an indirect backend) becomes a
first-class `Unparsed` entry: counted, surfaced, and **mutation-blocking**.
Never silently dropped.

The load-bearing consequence: **default-deny is reported ENFORCED only when
the entire live config was parsed** (`FullyParsed()`). Any unparsed construct
downgrades the deny verdict to **UNKNOWN**, because an unparsed route could
itself be a permissive catch-all Crenel didn't see. The hard invariant is
`ENFORCED ⟹ FullyParsed`. Deny is never *falsely* certified.

**Mechanism:** `model.LiveEdgeState.{Unparsed,Coverage,FullyParsed}`;
`core`'s ternary `DenyState()`; every driver's `normalize` emits `Unparsed`
instead of dropping anything. Full spec: `../internal/TOPOLOGY-RISK-REGISTER.md` §4
(authoritative).

### 1d. Preview → apply → read-back-verify, all-or-nothing

No mutating verb "just does it." Every one follows: read live → compute the
diff and show it (flagging anything about to go public) → confirm → apply
every provider (edge + internal DNS + public DNS, possibly across multiple
edges/a chain) as **one transaction** → **re-read live and prove the change
took effect**. An admin API returning `200 OK` is never trusted as proof.

If any provider's apply or read-back fails, **every already-applied provider
in that transaction is rolled back**, wedge-safe per edge (a hung admin API on
one edge doesn't block unwinding the others).

**Mechanism:** `core.Apply`'s ordered `buildSteps` → apply → verify →
compensator/rollback pipeline; the exposure-rank ordering (edge <
internal-DNS < public-DNS, extended by chain depth) that makes routes exist
*before* names are announced and removes names *before* routes are torn down.

### 1e. Ownership-marker safety: refuse to manage what it doesn't own

Crenel refuses, **before any driver `Apply` runs**, to mutate a route it
determines is `foreign` (owned by a config generator like a Docker-label
proxy, Nginx Proxy Manager, or Pangolin, where an edit would be silently
reverted) or `unknown` (ownership can't be determined). `--yes` never bypasses
this refusal (it skips the "are you sure?" prompt, not the "this will silently
break" one). `--force` is a documented, human-load-bearing escape for
`unknown` only, **never** for `foreign`: there is no safe force for an edit a
generator will revert regardless.

On DNS, the same principle takes a driver-specific shape. The surgical
Cloudflare driver stamps every record it creates with a `managed-by:crenel`
comment marker, and its low-level update/delete primitives **refuse to act on
any record lacking that marker**. That's enforced at the primitive level, not
just by the caller, so a bug upstream of the primitive still can't touch a
foreign record. The AdGuard driver has no marker field to work with (the
control API doesn't have one), so it substitutes **zone-confinement**: it
refuses to write outside its configured zone or write a bare wildcard, and
refuses to overwrite an existing rewrite that answers a different value.

**Mechanism:** `internal/core/gate.go` (`gateOwnership`/`gateChainOwnership`,
`ErrRefuseToManage`); `internal/drivers/dns/cloudflare` (`updateRecord`/
`deleteRecord` marker checks); `internal/drivers/dns/adguard` (zone guard).

---

## 2. Trust boundaries: what Crenel trusts to be true

Crenel's guarantees are conditional on a few things it does **not**
independently verify:

| Crenel trusts... | Because... | If false, what breaks |
|---|---|---|
| **The edge admin API tells the truth about live config.** | There is no independent oracle for "what's actually routed." Crenel's entire live-state-authoritative model IS "ask the edge." | A compromised or buggy admin API that lies about its own config defeats every read-side guarantee. This is a trust root, not a gap Crenel could close. |
| **A read-back-verify a moment after apply reflects the durable state.** | Read-back-verify confirms the *in-the-moment* state, not necessarily the *durable* one. | On an **ephemeral** edge (Caddy's admin API is in-memory-only unless persistence is configured; see `model.PersistenceModel`), a verified write can be silently reverted by an unrelated `docker restart`. Crenel **declares** this risk (a persistence-model warning) rather than hiding it. See `KNOWN-LIMITS.md`. |
| **The operator's own choices at the CLI are intentional.** | `--auth none`, `--force`, and confirming a preview that shows "ABOUT TO GO PUBLIC" are all explicit, unbypassable opt-ins. Crenel makes the *consequence* visible, but does not second-guess a deliberate choice. | A scripted/automated caller that blindly passes `--auth none` or `--force` on every invocation defeats the guardrail's intent even though the guardrail itself held. |
| **DNS/edge credentials it's handed are valid for the scope claimed.** | Crenel does not independently confirm a Cloudflare token's actual permission scope beyond what the API tells it at call time. | An over-scoped credential (e.g. a token with write access beyond the intended zone) is an operator misconfiguration Crenel can't detect in advance. It will find out at apply time. |
| **The transport channel (SSH) is not already compromised.** | `ssh-exec`/`ssh-tunnel` carry the admin call inside SSH; Crenel does not verify host keys itself. | A MITM on a TOFU-accepted forged host key sees/can-modify the admin traffic. This is `SECURITY.md`'s domain (B2), noted here because it also erodes the correctness guarantees (an attacker on that channel could feed Crenel a fabricated "live state"). |
| **Config generator detection (P2) covers the generator actually in front of it.** | Detection is heuristic (file signatures, middleware markers) for a known, finite list (NPM, Traefik Docker/Swarm/K8s labels, Pangolin, caddy-docker-proxy). | An **undetected** generator's routes read as plain `unmanaged` (mutable) rather than `foreign`. A genuine gap, tracked as a known limit, not a silent one (the unmodeled *shapes* still surface as `Unparsed`, but ownership itself can misclassify). |

**What Crenel explicitly does NOT trust** (and therefore defends against, not
merely hopes for): its own parser being complete (§1c), an admin API's `200`
meaning the change landed (§1d), and a route with no recognized marker being
safe to touch (§1e default posture is refuse, not assume-safe).

---

## 3. Where the two invariants (live-state, default-deny) end and the third
   (bounded honesty) begins

The first two invariants are safe **on the topologies Crenel fully models**.
The third, detect-and-declare-unknown, is what keeps Crenel safe on
everything else: the long tail of real-world edge configs enumerated in
`../internal/TOPOLOGY-RISK-REGISTER.md`. An auditor evaluating "is this tool safe" should
evaluate all three together. A tool that only had the first two would be
safe on a clean greenfield edge and **dangerously overconfident** on anything
it couldn't fully parse. The register's central claim (§4, restated in
Appendix A there) is the one this audit package most wants tested:

> Crenel's confidence is bounded by what it actually parsed and owns. It
> reports unknowns as unknowns, refuses to manage what it can't own, and
> never certifies default-deny over config it didn't read.

If an auditor can find one construct that defeats this (a config shape that
reads as fully understood/ENFORCED/owned but isn't), that is the highest-value
class of finding this package is looking for.
