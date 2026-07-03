# Crenel v0.4.0: initial public release

> **DRAFT, for review.** On approval this becomes (a) the GitHub release body
> for the `v0.4.0` tag and (b) the top entry of `CHANGELOG.md` (then re-cut the
> public snapshot so both carry it). The private pre-history (v0.1.0–v0.3.2) is
> summarized at the bottom; the public repo starts at this release with a clean
> history.

Crenel is a default-deny control plane for the reverse-proxy edge and DNS you
already run. It keeps no stored desired state. Every command reads the live
edge, previews the exact change, applies it across every provider as one
all-or-nothing step, and re-reads the live system to prove the change landed.
A *crenel* (rhymes with fennel) is the gap in a battlement: the wall is solid
by default, and you cut the gaps. The flagship move:

```sh
crenel expose photos --to immich:2283 --auth authelia
```

## What's in the box

**Read-only verbs.** `status` (live "what's exposed right now", terminal HUD
or `--plain`/`--json`), `audit` (safety checks, non-zero exit on critical, so
it drops straight into cron), `drift`, `preview`, and `export` (`--redacted`
for shareable copies).

**Mutating verbs.** Every one runs read-live → plan → confirm → apply →
read-back-verify, with rollback:

- `expose` / `unexpose` / `set`. `expose` takes **`--to <host:port>`** to name
  the backend inline, no pre-edited origins map needed. The target is
  TCP-probed before any route is written (Crenel refuses to expose a dead
  backend; `--no-validate` is the explicit escape hatch), and the origin is
  persisted into settings on a verified apply so `status`, `audit`, `drift`,
  and `reconcile` stay coherent afterwards.
- `rename` (make-before-break, one command, cross-edge).
- `import` (adopt a hand-built setup in place, zero behavior change).
- `apply` (declarative, kubectl-style, with `--adopt`/`--prune`) and
  `reconcile` (converge drift back to the exposed set).
- `resume` (finish or roll back an interrupted apply), plus `init` and `serve`
  (a read-only status dashboard).

**Edges.** Caddy (admin API + durable Caddyfile persistence between managed
markers), Traefik (file provider), nginx, and NetBird groups/policies, all
behind one `EdgeProvider` port. Multi-edge chains (say, a VPS front plus a
home source-of-truth) are coordinated atomically.

**DNS.** Split-horizon internal + public as first-class scopes. Cloudflare
runs whole-zone via dnscontrol on a dedicated zone, or in **surgical
per-record REST mode for shared zones**: records carry a `managed-by:crenel`
marker and the mutate primitives refuse anything not marked. AdGuard Home has
a native control-API driver with per-instance labels and a wildcard-aware
dual-resolver parity audit.

**Auth by reference.** Exposures carry an `auth:` policy rendered per edge
(Caddy `forward_auth`, Traefik middleware, nginx `auth_request`) while you own
the actual auth config. Public-with-no-auth is refused unless you explicitly
say `--auth none`, and `audit` flags any public host without a policy.

**Transports.** `direct` (loopback-only), `ssh-exec`, and `ssh-tunnel`. A
remote edge's plaintext admin API never crosses the network in clear and never
gets network-exposed.

**Safety rails.** Default-deny is structural: a host is reachable only if it
is explicitly exposed AND the catch-all deny is present. Honesty is bounded:
unparseable config becomes a counted, visible declared-unknown, deny reports
ENFORCED only on a fully-parsed config, and foreign or generator-owned routes
are refused rather than adopted. Printed output is secret-redacted by default
(`--show-secrets` to opt out; the apply and verify paths always use real
values).

**Everything else.** Zero third-party Go dependencies; the Caddyfile adapter,
nginx tokenizer, Traefik rule parser, and YAML-subset decoder are all in-repo.
About 500 test functions, race-clean, fully hermetic. No test ever opens a
socket to real infrastructure, and every fake is held to one rule: accept what
the real edge accepts, reject what it rejects. There's a batteries-included
`bundle/` (default-deny Caddy + Crenel + dashboard + demo upstream, one
`docker compose up`) and a security-audit package under `docs/security/`
(security model, threat model, claims-to-verify, known limits) written for
someone trying to break it.

## Proven live, not just tested

The claims that matter ran against real production edges, recorded
byte-for-byte and reverted. Write-ups live in `archive/trials/results/` and
`TRIAL-RECORD-live-proofs-2026-06-30.md`, with hostnames anonymized and
everything else verbatim:

- A durable expose written into an existing wildcard site that **survived a
  full `docker restart`**. The expose → restart → unexpose → restart cycle ran
  green.
- One-command `rename` across a live edge, restart-survival included.
- A coordinated two-edge write that hit a real config rejection and **aborted
  atomically with zero changes to either edge**. Once fixed, it drove the full
  auth chain to the literal `302` redirect.
- Surgical Cloudflare on a real **shared** zone: only Crenel's marked record
  was touched, and the operator's pre-existing wildcard stayed byte-identical
  throughout.
- A **full-chain production expose in one run**: home edge route, VPS edge
  allowlist, both internal resolvers, and the public Cloudflare record, all
  gates green, default-deny intact.

## Known limits (documented, loud, and honest)

- **Path-granular routing is detected, not writable.** A route scoped by
  path/method/header is declared `matcher_conditional` and forces deny to
  UNKNOWN, never silently misread. But Crenel cannot yet write per-path
  backends or per-path auth.
- **AdGuard value-drift detection is deliberately off.** AdGuard rewrites have
  no per-record metadata, so Crenel cannot tell a stale rewrite of its own
  from one you set by hand; value-checking would cry wolf on your intentional
  rewrites. Zone-confinement and refuse-to-clobber still apply.
- **Tailscale serve is read-only.** Funnel entries are recovered per-host;
  writing serve config is future work, and tailnet-only `Web` entries don't
  yet get their own scope axis.
- **Whole-zone Cloudflare push requires a dedicated zone.** Crenel refuses a
  whole-zone `dnscontrol push` against any zone holding foreign records.
  Surgical mode is the shared-zone path.
- Full list with severity framing: `docs/security/KNOWN-LIMITS.md`.

## Install

```sh
go install github.com/crenelhq/crenel/cmd/crenel@latest   # Go 1.22+, stdlib only
# or, no edge yet:
git clone https://github.com/crenelhq/crenel && cd crenel/bundle && docker compose up -d
```

Start with the read-only verbs against your real setup. `status`, `audit`,
and `drift` only read, and where Crenel is unsure it says UNKNOWN.

Docs: [`docs/WHAT-CRENEL-DOES.md`](../WHAT-CRENEL-DOES.md) (plain English) ·
[`DESIGN.md`](../../DESIGN.md) (architecture) · [`SECURITY.md`](../../SECURITY.md)
(threat model + disclosure: `security@crenel.sh`) ·
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) (DCO + CLA, the faithful-fake bar).

---

### Pre-history (for the curious)

v0.4.0 is the first public release; the repo history starts here by design.
Before it: v0.1.x built the core engine, the Caddy driver, and read-only
trust. v0.2.0 was hardening after a live edge-wedge postmortem, with
bounded-timeout guarantees. v0.3.0 added the Traefik/nginx/NetBird drivers,
multi-edge atomic chains, brownfield adoption, auth-by-reference, and the
proving-ground live validations. v0.3.1–2 made DNS real: dnscontrol/Cloudflare
and AdGuard drivers, surgical shared-zone mode, wildcard-aware parity and
drift audits, and the live production proofs above.
