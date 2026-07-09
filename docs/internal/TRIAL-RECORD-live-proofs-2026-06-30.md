# Live-proof record — 2026-06-30 (operator-record)

> **Provenance (read this first).** This file is compiled from the **operator's live-session
> record** (the operator, running from the home-edge host / the bench host against real infrastructure over the operator's private
> tailnet), **not** a fresh byte-logged trial run by the doc pass that wrote this file. It
> exists so the STATE-OF-CRENEL ledger can cite the three live proofs below that closed
> punch-list items but did **not** each get a standalone `TRIAL-RESULT-*.md` at the time.
> Fidelity is exactly what the operator record supports; where a full byte log lives only in
> the operator's notes / `live-backup/`, that is stated. The three fully byte-logged trials
> (durable-persist, chain-write, crenel.sh surgical) keep their own `TRIAL-RESULT-*.md` and
> are only cross-referenced here.
>
> Nothing in this pass touched a live edge, DNS, or the finance service — this is a
> write-up of proofs the operator already executed.
>
> **Anonymized for publication:** hostnames, zones, addresses, and host identifiers
> are consistently pseudonymized (`homelab.example`, RFC 5737/1918 ranges); the
> sequence of operations and results is otherwise as recorded.

---

## 1. Surgical Cloudflare on the **shared** `homelab.example` zone — PROVEN

**Date:** 2026-06-30. **Build:** `v0.3.1-7-gb28b776` (surgical provider on `develop` after PR #11).
**Mode:** `apply_mode: surgical` (native Cloudflare REST per-record CRUD; **no** `dedicated_zone`).

The dedicated-zone shape was already byte-logged on `crenel.sh` (see DNS-DESIGN.md / STATE §0a).
This proof is the **shared production zone** — the one that actually matters, because
`homelab.example` holds foreign records (including the apex wildcard) that must never be touched.

- A 3-provider verify-expose of the throwaway host `crenel-fliptest` created **only** Crenel's
  own record, stamped `comment: managed-by:crenel host=<name>`.
- The pre-existing **wildcard `*.homelab.example` stayed BYTE-IDENTICAL** across expose → unexpose
  (Crenel's `owned()` word-boundary marker match refuses any record it did not create — the
  safety boundary held on the real zone, not just a fake).
- All three providers **restored byte-for-byte**; the zone was left as found (surgical mode left
  enabled afterward).

**Closes:** STATE §6.z bucket A "surgical Cloudflare trial on the shared `homelab.example` zone."
Full request/response byte log: operator record (chat-transited token was shredded/rotated).

## 2. Dual-AdGuard split-horizon parity trial — PROVEN

**Date:** 2026-06-30. Both internal resolvers driven together (`adguard[home]` + `adguard[vps]`,
per-instance labels from PR #12), each with its vantage-correct target.

- The two resolvers were driven and **restored byte-for-byte**.
- The `dns_coverage_parity` audit **caught a real divergence live** between the two resolvers
  (the exact class it was built for in PR #12 / wildcard-aware after #15/#16) — i.e. it fired on
  a genuine cross-resolver gap, not a cry-wolf.

**Closes:** the ref-arch §5 / gated-next-step "live trial against the actual dual-resolver pair."
The single-instance AdGuard live trial (a disposable host) remains separately byte-logged in STATE §0a.
Full log: operator record.

## 3. `finances.homelab.example` full-chain expose from the home-edge host — PROVEN (punch-list #1)

**Date:** 2026-06-30. The first **full coordinated production expose of a real service**
end-to-end through the whole chain, driven by a single Crenel run from the home-edge host.

- All legs of the chain came up coordinated and read-back-verified: the **home edge route**, the
  **VPS edge forward/allowlist**, **both internal AdGuard rewrites**, and the **public Cloudflare
  record** — with default-deny intact and the public host gated.
- The operator reports **all 7 gates green** end-to-end (operator's phrasing for the chain's
  ordered legs + read-back verification).

This is **punch-list #1** from `docs/WHAT-CRENEL-DOES.md` — "run the whole chain as one routine
production expose" — done on the real stack. It also demonstrates the **live cross-chain
coordinated write on the real home + VPS chain** (STATE §6.z bucket A) at production scale, on top
of the config-level chain-write already byte-logged in `TRIAL-RESULT-chain-write-2026-06-28.md`.

**Closes:** STATE §6.z bucket A "live cross-chain coordinated-WRITE trial" (at full production
scale) + punch-list #1. Full step-by-step log: operator record / `live-backup/`.

---

## What remains genuinely live-only after these

- **Tailscale `serve.json` WRITE support** — read side is per-host wildcard-aware; a write path
  still needs a `tailscale serve` exec / local-API integration against a real node.
- Repeat/scale hardening of the full-chain expose as the routine daily-driver path (adoption, not
  a missing capability).

Structural (offline) limits are unchanged and tracked in STATE §6.z bucket B (marker-less AdGuard
value-drift; path-granular WRITE; tailnet-scope axis).
</content>
