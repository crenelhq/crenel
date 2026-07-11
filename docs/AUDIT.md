# Crenel: Third-Party Audit Package

> **Entry point for an external security reviewer.** This package is written for
> someone with no prior context on Crenel: it states what the tool promises, what
> it explicitly does not promise, what to try to break, what is already known to
> be weak, and how to build and reproduce the claims. Read this file first, then
> follow the links.
>
> Every example hostname/IP in this package is fake (`app.example.com`,
> `192.0.2.10`, RFC 5737/1918 ranges). None of it is Crenel's or any operator's
> real infrastructure.

---

## 0. What Crenel is, in one paragraph

Crenel is a CLI that controls which self-hosted services are reachable from the
network by driving a reverse-proxy edge (Caddy / Traefik / nginx / NetBird) and
optionally DNS (Cloudflare / AdGuard Home). It does not replace any of them. It
keeps **no stored desired state**: every command reads the edge's live
configuration, computes a diff against that live state, previews it, applies it,
and then **reads live again to prove the change actually took effect**. Full
plain-language explanation: `docs/WHAT-CRENEL-DOES.md`. Full architecture:
`internal/DESIGN.md`.

Two audit surfaces worth adversarial attention beyond the classic invariants:
a service can be **declared internal-only** (`scope: internal` in the origins
map), and audit then enforces the declaration — an internal-scope host that is
nonetheless publicly reachable (explicit public DNS record, a chain-front
route, a tunnel publication) is a critical `internal_scope_public_exposure`
finding, and the combination of a covering public DNS wildcard *plus* a
covering wildcard forward at the chain front is a warning-severity
`internal_scope_wildcard_covered` (`internal/core/internal_scope_test.go`
anchors both). And routes Crenel cannot model don't dead-end: `crenel triage`
(and the underlying `ack`/`ack --route` markers, `docs/design/ack-marker.md`)
is the operator's remediation path — try to make an ack certify something it
shouldn't.

---

## 1. Package contents

| Doc | Answers |
|---|---|
| **[security/SECURITY-MODEL.md](security/SECURITY-MODEL.md)** | What Crenel guarantees, and what it trusts to be true. Start here for the mental model. |
| **[security/THREAT-MODEL.md](security/THREAT-MODEL.md)** | What Crenel defends against, and what it explicitly is not (not a firewall, not an auth system, not a secrets manager). |
| **[security/CLAIMS-TO-VERIFY.md](security/CLAIMS-TO-VERIFY.md)** | **The heart of this package.** A crisp, testable list of properties to try to BREAK, with pointers into the code for each. |
| **[security/KNOWN-LIMITS.md](security/KNOWN-LIMITS.md)** | The honest, already-documented gaps. Read this before filing a finding. If it's here, it's a known/accepted limit, not a new bug (unless you found a way around the mitigation, which *is* new). |

Companion docs already in the repo that this package leans on (not duplicated
here, cited where relevant):

- `internal/DESIGN.md`: architecture, the two load-bearing invariants, every verb's behavior.
- `internal/AUTH-DESIGN.md`: the forward-auth-by-reference model and its guardrail.
- `internal/TOPOLOGY-RISK-REGISTER.md`: the authoritative long-tail risk analysis (the
  "detect-and-declare-unknown" principle lives here, §4).
- `SECURITY.md`: the **secrecy** axis. It covers what credentials/secrets
  Crenel's process touches, the loopback-admin trust model, and the redaction
  guarantee. This audit package's threat model is about **correctness** (does
  Crenel ever misreport or mismanage exposure); `SECURITY.md`'s is about
  **secrecy** (can a credential leak). They're deliberately separate axes; see
  `internal/TOPOLOGY-RISK-REGISTER.md` §0's "Axis note."
- `STATE-OF-CRENEL.md`: current build status, what's proven live vs. only
  against fakes, PR-by-PR history.

---

## 2. Scope

**In scope:**

- The core engine (`internal/core`): plan/apply/audit/status/reconcile/drift,
  the ownership gate, the transactional rollback machinery.
- The model (`internal/model`), the types the invariants are expressed over.
- Every edge driver (`internal/drivers/edge/{caddy,traefik,nginx,netbird}`).
- Every DNS driver (`internal/drivers/dns/{dnscontrol,adguard,cloudflare,pihole}`).
- The transport layer (`internal/drivers/transport`): `direct`/`ssh-exec`/`ssh-tunnel`.
- The secret redaction layer (`internal/redact`).
- The MCP server (`cmd/crenel/mcp.go`): read-only by default, opt-in two-phase
  gated writes via `--write` (see §6).
- The CLI surface (`cmd/crenel`) and its flag/guardrail handling.

**Out of scope:**

- The reverse-proxy/DNS software Crenel drives (Caddy, Traefik, nginx, NetBird,
  Cloudflare, AdGuard Home). Crenel does not reimplement or patch them.
- Denial-of-service against the operator's own edge (Crenel is a CLI the
  operator runs on demand; it has no listener and no daemon mode other than the
  optional read-only `serve` dashboard).
- The demo/branding assets (`brand/BRANDING.md`, `internal/TEASER-TIMELINE.md`, `.demo/`,
  `examples/`) and the fake-CI TRIAL-RESULT/TRIAL-RECORD narrative docs.
- Supply-chain of the Go toolchain itself. Crenel's own dependency surface is
  worth noting, though: `go.mod` has **zero third-party dependencies**. The
  Caddyfile adapter, nginx tokenizer, Traefik rule parser, and YAML-subset
  decoder are all hand-rolled in-repo, specifically to keep the trusted base
  small. Verify with `cat go.mod` / `go list -m all`.

---

## 3. Build, test, and reproduce

Zero-dependency, offline Go build (no network access required):

```sh
git clone <repo> && cd crenel
make check     # go build ./... && go vet ./... && go test -race ./...
```

`make check` is the same gate every commit must pass. As of this writing it is
green: **155 test files / 788 test functions**, race-clean, and **no test in the suite ever opens a
socket to a real edge or DNS provider**. Every driver is exercised against an
in-repo fake that is built to reject what the real API/service rejects (see
`docs/DNS-DESIGN.md` §6 for the DNS fakes' documented failure-surface fidelity,
and each driver's `*fake` package for the edge-side equivalents). This matters
for the audit: **you can safely run the entire test suite and fuzz/mutate the
driver code without any risk of touching real infrastructure.**

Other useful entry points:

```sh
make build                       # binary in ./dist
crenel -fake-seed status         # run against the built-in fake edge, no real infra
crenel help                      # full verb/flag list
```

To reproduce a specific claim from `CLAIMS-TO-VERIFY.md`, the referenced test
file is the fastest way in, e.g. `go test ./internal/core/ -run TestOwnership`
or `go test ./internal/drivers/edge/caddy/ -run TestFullLoad`. Each claim entry
names the anchoring test(s).

---

## 4. Code access & scrub note (read before sharing externally)

**The `develop` branch as checked out today contains no operator-specific
secrets** (credentials are never committed; see `SECURITY.md` §3) and, as of
the 2026-07 launch-prep pass, the docs, examples, and trial/archive narratives at
HEAD are **anonymized**: the maintainer's hostnames, zones, and addresses were
consistently pseudonymized (`homelab.example`, `smallbiz.example`, RFC 5737/1918
ranges, generic host labels). What still stands before sharing externally:

1. **Grep history, not just HEAD.** Commit messages and pre-scrub revisions still
   carry the maintainer's real hostnames/IPs. For a public release, publish a
   **clean-history snapshot** (fresh repo or orphan branch of `develop` HEAD)
   rather than pushing this history; for a private audit, share under NDA or
   share the snapshot.
2. **Test fixtures under `internal/` and `cmd/` still use the pre-scrub names**
   (they are inert strings in hermetic tests, but they name the original
   topology). Renaming them is a mechanical, test-touching pass that has been
   deliberately left out of the docs scrub. Do it (or accept it) before public.
3. **Check `live-backup/`**: gitignored, but confirm it is not present in
   whatever archive/export is handed over (its snapshots contain **real
   credentials**).
4. **Confirm no `.env`, `creds.json`, or `*.settings.yaml` with real `admin_url`/
   `ssh_identity`/API-token fields is bundled**. These would name real
   infrastructure even though they hold no live credentials themselves.
5. Prefer sharing **`develop` only** (or the snapshot), not feature branches.
   Several in-progress branches track one operator's real deployment shape in
   commit messages and companion docs.

---

## 5. Reporting findings

For each finding: which claim in `CLAIMS-TO-VERIFY.md` (or a new one) it
breaks, the minimal repro (ideally a failing `go test`), and which of the three
verdicts from `internal/TOPOLOGY-RISK-REGISTER.md` §0 it is (**READ-SAFE** /
**READ-CORRECT** / **MANAGEABLE**), plus whether it's a **MISREAD** (Crenel
reports something false) or **MISMANAGE** (a change reverts silently). That
vocabulary is already the project's own severity language, so a finding
triaged in it slots directly into the existing risk register.

---

## 6. The MCP server

The MCP server (`cmd/crenel/mcp.go`) is on `develop`. Its claim (see
`CLAIMS-TO-VERIFY.md` §I) is that the default mode is read-only **by
construction**: the server holds the engine only through the exported
`core.ReadOnlyEngine` interface (`Status`/`Audit`/`DetectDrift` — the same
narrow surface the `serve` dashboard and the audit-target mode hold), so no
mutating method is reachable through it even in principle. The opt-in
`--write` mode adds a two-phase gated write pair (`crenel_plan` computes a
diff + content-hash `plan_id`; `crenel_apply` refuses unless the id re-derives
against current live state), and composes with the engine-level read-only
posture: an engine constructed read-only refuses `crenel_apply` with
`core.ErrReadOnlyEngine` before any planning. That is exactly the kind of
claim this package wants adversarially tested; `cmd/crenel/mcp_test.go` and
`cmd/crenel/mcp_write_test.go` anchor it.
