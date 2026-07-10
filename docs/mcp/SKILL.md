---
name: crenel
description: Drive a crenel edge over MCP — read live exposure/audit/drift, and (in --write mode) make gated two-phase changes (expose/unexpose/set/rename) to routes + split-horizon DNS. Use whenever the task is to see or change what a homelab/edge proxy (Caddy/Traefik/nginx) exposes, its auth posture, or its DNS records.
---

# Crenel over MCP

Crenel is a live-state-authoritative control plane for an edge proxy (Caddy /
Traefik / nginx) plus split-horizon DNS. This skill teaches you to drive it through
the `crenel` MCP server. There is **no stored desired state** — every tool reads or
writes **live** state at call time.

## First: which mode are you in?

Call `tools/list`. If you see only `crenel_status`, `crenel_audit`, `crenel_drift`,
the server is **read-only** — you can inspect but not change anything. If you also
see `crenel_plan` and `crenel_apply`, writes are enabled (the operator started it
with `--write`).

## Read tools (always available, always safe)

- **`crenel_status`** — the live picture: per-edge routes (host → backend, mode,
  attached forward-auth, chain follow-through), the **ternary default-deny** posture
  (`ENFORCED` / `UNKNOWN` / `MISSING`), config coverage (understood vs not),
  durability, off-edge ingress, and managed DNS records. Optional `edge` filters to
  one edge by name. **Start here** to understand the edge before proposing a change.
- **`crenel_audit`** — invariant + consistency findings, each with a severity
  (`critical`/`warning`/`ok`), a machine `code`, and a message: public-without-auth
  hosts, fail-open (missing default-deny) edges, not-understood constructs, chain
  notes.
- **`crenel_drift`** — divergence from the canonical exposed set (missing routes,
  mode mismatches, stale managed DNS) and the corrective change that *would*
  converge. Reports only; applies nothing.

## Write tools (only in `--write` mode) — the two-phase contract

**You cannot write in one step, by design.** Every change is:

1. **`crenel_plan`** — describe the change; get back the exact diff plus a
   **`plan_id`**, and the flags `goes_public` and `auth_required`. *Nothing is
   applied.* Read the diff. Make sure it's what you intend.
2. **`crenel_apply`** — repeat the SAME arguments **plus `confirm_plan_id` = the
   `plan_id` from step 1**. Crenel recomputes the change against current live state
   and refuses unless the id still matches — so you cannot blind-write, and if the
   world changed since your preview, you must re-plan.

If `crenel_apply` returns a **`plan_id mismatch`** error: the live state changed
since you planned (or your arguments differ from what you planned). Call
`crenel_plan` again and use the fresh id. Never guess or reuse an old id.

### Write arguments (keyed on `verb`)

- `verb:"expose"` — `service` (required). Optional: `to` (backend `host:port`),
  `auth` (a policy name like `"authelia"`, or `"none"` to publish unprotected on
  purpose), `mode` (`http`/`passthrough`/`mesh`), `scope`, `dns`, `edges`.
- `verb:"unexpose"` — `service`. Optional `scope`/`dns`/`edges`.
- `verb:"set"` — `service` + `state` (`"on"`/`"off"`). Optional `scope`/`dns`/`edges`.
- `verb:"rename"` — `old_host` + `new_host`.
- `crenel_apply` also requires `confirm_plan_id`.

### Scope + edges (appointing reach)

- `scope:"internal"` — internal DNS only. **No public record, no forced auth.** Use
  for LAN-only services (e.g. Home Assistant). The host is reachable only where an
  internal name resolves.
- `scope:"public"` — the full public chain; **auth is required** (see below).
- `scope:"both"` / omitted — every configured DNS scope (default).
- `dns:"internal|public|both"` — the granular form of `scope` (mutually exclusive
  with `scope`).
- `edges:["home"]` — appoint the route to specific edges by name (omit for every
  edge that fronts the service). Learn valid names from `crenel_status`.

## The safety rules you must respect (crenel enforces them; don't fight them)

- **Never publish without auth by accident.** If `crenel_plan` returns
  `auth_required: true`, `crenel_apply` will refuse until you set `auth`. Publishing
  something to the internet unprotected must be a deliberate `auth:"none"`. Prefer a
  real policy; ask the operator if unsure.
- **Trust the verify, not the apply.** A successful `crenel_apply` has been
  **read-back-verified** against live. If it errors with "runtime verify
  unavailable", the write was **rolled back** — tell the operator to apply from the
  CLI with `--allow-unverified` or configure a runtime probe; do not treat it as
  done.
- **Don't touch what crenel calls foreign/unknown-owned.** Those changes are
  refused by the ownership gate. Surface them to the operator instead.
- **Reads are free; writes are consequential.** Read (`status`/`audit`/`drift`)
  freely. Before any `crenel_apply`, confirm the plan diff matches the operator's
  intent.

## A typical flow

1. `crenel_status` — see what's there.
2. `crenel_plan` `{verb:"expose", service:"ha", to:"10.0.0.19:8123", scope:"internal", auth:"none"}`
   → read the diff (should be one internal edge route + one internal DNS record, no
   public record), note the `plan_id`.
3. `crenel_apply` the same args + `confirm_plan_id`.
4. `crenel_status` again — confirm the route + record are live and default-deny is
   still `ENFORCED`.
