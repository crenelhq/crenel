# Launch announcement drafts for v0.4.0

> **DRAFTS. Do not post until reviewed.** Two variants of the same story: a
> Show HN post (tight, technical, written for a skeptical audience) and an
> r/selfhosted post (warmer, problem-first). Post-day mechanics at the bottom.

---

## Variant A: Show HN

**Title:**

> Show HN: Crenel – one verified command to expose a service across proxy, DNS, and auth

**Body:**

I run a fairly typical self-hosted setup: Caddy at home behind a lean VPS
edge, split-horizon DNS on two AdGuards, Cloudflare for public DNS, Tailscale
in between. Exposing one service means editing four configs that all have to
agree. When they don't, nothing errors. The config says one thing, the live
system does another, and that gap is where you get hurt.

Crenel (rhymes with fennel) closes that gap:

    crenel expose photos --to immich:2283 --auth authelia

One command. The host gets routed on the home edge, allowlisted on the VPS
edge, added to internal and public DNS, and gated behind Authelia. You see the
full diff before anything happens, it applies across every provider as a
single atomic step, and then Crenel re-reads the live edge to prove the change
actually landed. `--to` also TCP-probes the backend before any route is
written; it refuses to expose a dead backend (`--no-validate` if the service
just isn't up yet).

Under the hood it's a control plane, not another proxy or tunnel. It drives
the Caddy / Traefik / nginx / DNS stack you already run and reimplements
nothing. Three design choices do the work:

- **Live state is the only truth.** No stored desired state, no state file, no
  database. Every command reads what the edge is actually serving right now,
  so there's nothing to drift. That's the main difference from Terraform-style
  IaC, and from hand-editing, where the "state file" is your memory.
- **Every change is one atomic, verified step.** Crenel plans across every
  edge and DNS provider, previews the exact diff (anything about to become
  public gets flagged loudly), applies all-or-nothing with rollback, then
  re-reads the live system to confirm. An admin API returning "200 OK" is
  explicitly not trusted as proof.
- **It never pretends to understand.** Config it can't fully parse becomes a
  counted, visible "declared unknown." Default-deny only reads ENFORCED when
  the config was fully parsed, and routes owned by other tools are refused,
  not adopted. Worst case, Crenel tells you it doesn't know. It will not show
  you a false green.

The trust map, honestly:

- The write paths ran against real production edges, recorded byte-for-byte
  and reverted. A durable expose that survived `docker restart`. A one-command
  cross-edge rename. A coordinated two-edge write that aborted atomically when
  one edge rejected the config, which caught a real bug the test suite
  structurally couldn't. A full-chain production expose in a single run: home
  route, VPS allowlist, two internal resolvers, public Cloudflare record.
  Surgical Cloudflare was proven on a real shared zone; only Crenel's marked
  record was touched and the operator's pre-existing wildcard stayed
  byte-identical. Hostnames are anonymized in the published records; the
  commands and results are verbatim.
- Everything else runs against in-repo fakes held to a strict rule: a fake may
  only accept what the real edge accepts. About 500 test functions,
  race-clean, zero third-party Go dependencies, and no test ever touches real
  infrastructure.
- The structural limits are documented, not hidden. Path-granular routes are
  detected and declared but not yet writable. Marker-less AdGuard rewrites
  can't do value-drift detection. Tailscale serve is read-only today. The docs
  include a security model, a threat model, and a "claims to verify" list
  written for someone trying to break it.

Why not Pangolin and friends: they get coherence by replacing your stack.
Crenel bets you'd rather keep the tools you chose. Remove it tomorrow and
everything keeps running.

Go, stdlib only. `go install github.com/crenelhq/crenel/cmd/crenel@latest`, or
`cd bundle && docker compose up -d` for a batteries-included default-deny edge.

https://crenel.sh · https://github.com/crenelhq/crenel · Apache-2.0

---

## Variant B: r/selfhosted (maker post)

> Framed as "I built this, here's the story," not a product pitch. That's the
> tone that clears self-promo rules and gets real feedback.

**Title:**

> I got tired of exposing a service meaning four config edits that fail silently, so I built a CLI that makes my proxy, DNS, and auth agree

**Body:**

The itch: my setup is a home Caddy behind a lean VPS edge, two AdGuards doing
split-horizon internal DNS, Cloudflare for public, Tailscale in between.
Pretty normal around here, I think. Exposing one new service meant touching
all of those, and each edit is easy on its own. The problem is what happens
when they disagree: nothing. No error. A wildcard left open, a forgotten auth
gate, two resolvers answering differently. The config says one thing, the
live system does another, and I'd find out at the worst possible time.

After the third or fourth time I got bitten, I stopped patching my habits and
built a tool instead. It's called Crenel (rhymes with fennel), it's a Go CLI,
and it just went public. The whole thing boils down to one command:

    crenel expose photos --to immich:2283 --auth authelia

That routes the host on my edges, allowlists it on the front edge, adds the
internal rewrites and the public record, and gates it behind Authelia. I see
the full diff before anything happens, it applies everywhere as one
all-or-nothing step, and then it re-reads the live edge to prove the change
actually landed. It even TCP-probes the backend first and refuses to expose
something that isn't answering (`--no-validate` if the service just isn't up
yet). Exposing a host with no auth at all requires typing `--auth none` on
purpose.

Some design decisions that came directly from getting burned:

- It drives the stack you already run (Caddy / Traefik / nginx, Cloudflare,
  AdGuard). It doesn't replace anything. Delete it tomorrow and your edge
  keeps working.
- There's no stored state to drift. Every command reads the live edge.
  `status` answers "what's exposed right now" from reality, and `audit` and
  `drift` exit non-zero when reality disagrees, so cron can nag me.
- It refuses to guess. Config it can't fully parse becomes a counted, visible
  unknown, and default-deny only reads ENFORCED when everything was actually
  understood. Your hand-built routes stay yours until you `import` them.

Being straight about maturity: the write paths have been run against my real
production edges, recorded and reverted (durable expose surviving a container
restart, cross-edge rename, an atomic rollback when one edge rejected a
config, one full-chain expose through everything at once). The write-ups are
in the repo with hostnames anonymized. What it can't do yet: write per-path
routes (it detects them and says so), value-drift detection on AdGuard (no
marker field to trust, so it deliberately doesn't guess), and Tailscale serve
is read-only. The limits are documented as loudly as the features.

It's a zero-dependency Go binary, Apache-2.0:

    go install github.com/crenelhq/crenel/cmd/crenel@latest

Site: https://crenel.sh · Repo: https://github.com/crenelhq/crenel

I'd genuinely like it beaten on. The most useful thing you could tell me is
what happens when it meets *your* weird config, because
detect-and-declare-unknown is the part I care about most. Happy to answer
anything.

---

## Variant C: Mastodon

> One toot, under 500 characters with hashtags. Plain text; the link preview
> carries the visuals.

Exposing one self-hosted service used to mean editing four configs that all
have to agree, and fail silently when they don't. So I built Crenel:

crenel expose photos --to immich:2283 --auth authelia

One command: proxy route, DNS, auth gate. Previewed first, applied
atomically, then verified by re-reading the live edge. Default-deny. Zero-dep
Go, Apache-2.0.

https://crenel.sh

#selfhosted #homelab #golang

---

## Post-day mechanics (not part of either post)

- Show HN: plain-text body, no images; the ASCII banner renders in the repo
  README anyway. Reply fast in the first hour and lead answers with the trust
  map.
- r/selfhosted: check current self-promo rules; flair as "Release". The
  battlement banner screenshot (site or `crenel banner`) makes a good single
  image if one is allowed.
- Both link only to crenel.sh + GitHub. No tracking parameters.
- Timing: after the repo is public, the v0.4.0 release notes are up, and
  `security@crenel.sh` works.
