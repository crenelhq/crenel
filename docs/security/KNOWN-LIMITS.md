# Crenel: Known Limits

> Part of the [third-party audit package](../AUDIT.md). These are **already
> documented, already accepted** gaps. Not hidden, not silent: each one is
> either read-safe-by-default via the detect-and-declare-unknown net, or has an
> explicit documented boundary. Read this before filing a finding. If what
> you found is *already listed here*, it isn't new, unless you found a way
> **around** the stated mitigation, which absolutely is a new finding (say so
> explicitly and cite which mitigation failed).
>
> This list was checked against `internal/core`, `internal/drivers`, and the
> test suite at the time this package was written, not just copied from
> planning docs. A couple of items below correct claims that had gone stale
> in `STATE-OF-CRENEL.md`/`../internal/TOPOLOGY-RISK-REGISTER.md`; where this doc and an
> older planning doc disagree, trust this one and the code, and flag the
> planning doc as stale separately.

---

## 1. AdGuard: no per-record ownership marker → zone-confinement instead of full value-drift detection

The surgical Cloudflare driver stamps every record it creates with a
`managed-by:crenel` comment and can therefore tell its own records from the
operator's at a glance. **AdGuard Home's control API has no comment/metadata
field on a rewrite** (a rewrite is just `{domain, answer}`), so Crenel
structurally cannot stamp or check a marker there.

**What it does instead:** zone-confinement (refuse to write outside the
configured zone or a bare wildcard) and a same-domain/different-answer
conflict refusal (won't silently create an ambiguous second rewrite). What it
does **not** do: run drift detection that would tell a stale Crenel-authored
rewrite apart from one the operator set by hand. Doing so would cry-wolf on
the operator's own intentional rewrites.

**Note (this was previously mis-stated as broader than it is):** this
limitation is **AdGuard-specific**. The surgical Cloudflare driver's owned
records **do** get value-drift detected and corrected by `reconcile`
(`DriftValueDNS` / `dns_value_drift`, see `internal/core/reconcile.go` and
`internal/core/reconcile_value_drift_test.go`). Only the markerless AdGuard
path is excluded, deliberately (`TestReconcile_MarkerlessDNSValueDriftIsNotTouched`).

**Closing this** would need either an upstream AdGuard feature (a metadata
field on rewrites) or a stored manifest, which would reintroduce the stored-
desired-state design Crenel deliberately avoids everywhere else. Not
currently planned.

---

## 2. Path-granular routing: detected, not writable

A route scoped by something other than the hostname (a Caddy `path`/
`method`/`header` matcher, a Traefik `PathPrefix`, multiple nginx `location`
blocks under one `server_name`) is **detected and declared** as
`matcher_conditional`: an `Unparsed` entry, with deny downgraded to UNKNOWN for
that scope, across all three data-plane drivers. This closes the *silent
misread* risk (it used to be dropped/collapsed into a plain host route).

**What's still missing:** Crenel cannot *write* a per-path backend or
per-path auth policy. The model is host-granular
(`(host) → backend`), not `(host, path) → backend`. A host with `/admin`
authenticated and `/` open is invisible as a *distinction* even though its
existence is now flagged. This is tracked as **P5** in
`../internal/TOPOLOGY-RISK-REGISTER.md` and is a real model extension, not a small fix.

---

## 3. Tailscale: read-recovered, not write-supported

Crenel reads a Tailscale `serve.json` to recover per-host public/private
status (funnel = public, tailnet-only `serve` = private, correctly no longer
conflated) for **audit/status purposes**. Crenel does **not** write Tailscale
serve configuration. There is no `expose`/`unexpose` path that provisions a
Tailscale funnel or serve entry. Exposing via Tailscale today means the
operator configures it directly; Crenel can only observe and report on it
afterward.

---

## 4. Config-generator detection covers a finite, named list

`Generator` detection (the mechanism that classifies a route `foreign` when a
generator like Nginx Proxy Manager or a Docker-label proxy owns it; see
`SECURITY-MODEL.md` §1e) currently recognizes: **Nginx Proxy Manager**,
**Traefik Docker/Swarm/Kubernetes-label providers**, **Pangolin**, and
**caddy-docker-proxy**. The last needs either the mounted on-disk
`Caddyfile.autosave` or an operator-declared hint; the Caddy admin API
itself carries no CDP marker, verified against CDP's own docs.

**What's not covered:** any generator outside this list. An undetected
generator's routes read as plain `unmanaged`, i.e. **mutable**, which is the
residual MISMANAGE risk this whole mechanism exists to close. The
*unmodeled shapes* such a generator produces still surface via the general
`Unparsed` net (so a fully-opaque construct is still declared unknown), but
ownership classification specifically can be wrong for a generator Crenel
doesn't recognize. This is inherently an open-ended list; closing individual
gaps as they're identified is the intended long-term posture, not a fixed
scope.

---

## 5. Multi-zone edge: single-zone assumption in per-service derivation

An edge that fronts more than one DNS zone (e.g. `*.zone-a.example` and
`*.zone-b.example` on the same edge) is read without crashing, and both
wildcards are visible, but per-service DNS record derivation and some
audit logic still assume a single `zone`. This is a documented, lower-
prevalence follow-on (`../internal/TOPOLOGY-RISK-REGISTER.md` P6 / axis 7.3), not yet
built.

---

## 6. Chain coordinated WRITE: live-proven for one driver combination, fixture-proven for the model generally

The **read** model (chain follow-through, observed auth) and the underlying
projection/ordering/rollback machinery for the **write** side are
driver-agnostic by construction (they go through the same `EdgeProvider`
port every other feature does). But the **live** proof of the coordinated
cross-chain write (front + downstream + DNS as one transaction, including
the front-leg TLS re-origination fix) was run specifically against a
**Caddy-fronting-Caddy** chain. Other driver combinations for a chain
(Traefik fronting Caddy, a chain through nginx, etc.) are exercised only
against fakes/fixtures in the test suite, not against real edges. Treat a
non-Caddy chain write as fixture-proven, not live-proven, until an equivalent
trial exists.

---

## 7. A pure-front chain (no `downstream_address`) is read-only

If a chain-front edge config omits `downstream_address`, Crenel treats
*every* non-mesh route on that edge as a forward (the "pure relay" case) for
**read** purposes. The write side, though, requires a concrete `host:port` to
dial, so a pure-front chain cannot be written to (`expose`/`unexpose`) until
`downstream_address` is configured. This is a stated precondition, not a
silent failure (the write path errors clearly when the address is absent),
but worth an auditor's awareness since it's easy to construct a config that
looks writable and isn't.

---

## 8. nginx managed-block re-render fidelity

The nginx driver reconstructs a Crenel-owned server block from
`(address, auth)` only when it re-renders one. **If an operator hand-adds an
extra directive inside a Crenel-managed block** (say, a custom header or a
rate-limit directive placed inside the marked block rather than outside it),
that directive is lost the next time Crenel re-renders the block on an
unrelated apply. This is a **documented fidelity boundary, not a safety
hole**: the comment marker's contract is "this block is regenerated," and
nothing outside a marked block is ever touched. But an auditor evaluating
"does Crenel preserve operator intent" should know this asymmetry exists
specifically for nginx. Caddy granular and Traefik's read-modify-write both
preserve additional fields more precisely (verify this claim too, don't
just take the documented asymmetry at face value).

---

## 9. Persistence model: Caddy's admin API is ephemeral by default

Caddy's admin API mutates **in-memory** config; a `docker restart` (or any
process restart) drops anything Crenel wrote unless the operator has opted
into `caddy_persist_path`/the durable wildcard-Caddyfile reconciler. Crenel
**declares** this (`model.PersistenceModel` is surfaced per-edge in
`status`/`audit` as an `ephemeral_writes` warning) rather than silently
letting the operator believe a verified write is durable. This is listed
here not because it's hidden, but because it's the sharpest example of the
"read-back-verify confirms the in-the-moment state, not the durable one"
caveat in `SECURITY-MODEL.md` §2. An auditor should confirm the warning
actually fires for every edge that lacks persistence configured, not just
the ones in the test fixtures.

---

## 10. Long-tail topologies not yet modeled at all

Beyond the items above, `../internal/TOPOLOGY-RISK-REGISTER.md` P6 lists several
topologies with no dedicated modeling yet: HA active-passive edge pairs /
shared-VIP failover, TLS terminated at a layer Crenel can't observe, a
Traefik **KV** provider (Consul/etcd/Redis, where Crenel's file-based driver
reads/writes the wrong substrate entirely), and Kubernetes Ingress/
Gateway API. Each of these is lower-prevalence and, critically, **safe by
default** the moment the detect-and-declare-unknown net applies: an
unmodeled shape in any of these still surfaces as `Unparsed`/`unknown` rather
than a confident wrong answer. Worth an auditor's attention mainly to confirm
that "safe by default" claim actually holds for each (i.e. that Crenel
doesn't, say, crash or produce a nonsensical-but-confident report when
pointed at a Kubernetes Ingress-driven Traefik).

---

## 11. Things that are NOT limitations (verify the code before assuming otherwise)

A couple of items that appear in older planning docs as open concerns but
were confirmed, while writing this package, to already be resolved on
`develop`. They're listed here specifically so an auditor doesn't waste time
"finding" something already fixed:

- **DNS `reconcile` wildcard-awareness.** An earlier design note flagged that
  `reconcile`'s DNS drift checks (`missing_dns_record`/`stale_dns_record`)
  matched by name only and would cry-wolf against a wildcard rewrite (or, worse,
  propose *deleting* a load-bearing wildcard). This is now wildcard-aware:
  `reconcile` never proposes removing a wildcard, and only flags a missing
  record when a covering wildcard doesn't already answer it with the correct
  value (`docs/DNS-DESIGN.md` §12b.iii). Confirmed present on `develop`.
- **`reconcile`'s handling of owned-record DNS value drift.** A stale line in
  `STATE-OF-CRENEL.md` §3 claims `reconcile` is "value-blind" for DNS records
  generally. That's no longer accurate for **owned** (marker-carrying)
  Cloudflare records. See item 1 above for the precise, narrower scope of
  what's actually still unhandled (AdGuard only).
