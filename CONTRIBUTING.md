# Contributing to Crenel

Thanks for your interest. Crenel touches the seam between your machine and the
public internet (what your edge exposes), so the contribution bar is
deliberately about **honesty and proof**, not volume. This guide is the practical
"how"; the legal "what" lives in [`DCO.txt`](DCO.txt) and
[`LICENSE`](LICENSE). Participation is also governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

> **Project status.** Crenel has publicly launched (`v0.4.1`). The repository is
> still developed day-to-day by a solo maintainer, and the testing and trial
> bars below are exactly how the maintainer already works — the DCO
> machinery in this guide is what makes external contribution possible now that
> the project is public.

## TL;DR for a pull request

1. Branch off `develop` (`feat/...`, `fix/...`).
2. Make the change. **Add tests**; see *the faithful-fake bar* below.
3. `make check` must pass (build + `go vet` + `go test -race ./...`), green.
4. **Sign off every commit:** `git commit -s` (DCO, see below).
5. If the change touches an **edge driver or the apply path**, run (or describe)
   a **trial**; see *the trial-before-merge cadence*.
6. Open a PR against `develop` with a clear description and the trial notes.
   First-time contributors: see *Legal: DCO*.

## The two ground rules (read these first)

Crenel's whole value is that it does not lie about what is exposed. Two
invariants protect that, and they shape how you contribute:

- **Bounded honesty.** Anything Crenel cannot fully parse or whose ownership it
  cannot determine must be *declared unknown*, never silently dropped or assumed
  safe. If your change makes Crenel parse something new, make sure the
  *un*-parseable tail still surfaces (counted in `status`/`audit`). See
  `docs/internal/TOPOLOGY-RISK-REGISTER.md` and `docs/internal/DESIGN.md` §3.
- **Live-state-authoritative.** There is no stored desired state. Every mutating
  verb is `read-live → plan → apply → read-back-verify`; an admin-API `200` is
  **not** proof. New mutating behavior must read back and verify.

## Build & test

Zero-dependency, fully-offline Go build (stdlib only; `go.mod` has no third-party
requires). Go 1.22+.

```bash
make build      # -> ./dist/crenel (version-stamped)
make check      # build + go vet + go test -race ./...   <- the commit gate
make test       # go test -race ./...
make fmt        # gofmt -l -w .
make release    # cross-compile static binaries -> ./dist  (does NOT publish)
```

`make check` is the **green-bar gate every commit must pass.** CI (and the
maintainer) will run exactly this. Keep it green and race-clean. The race
detector isn't optional here: the admin-call/transport seam is
concurrency-sensitive.

### The faithful-fake testing bar (the load-bearing rule)

Crenel **never touches real infrastructure in tests.** Everything runs against
in-repo fakes and fixtures: a fake Caddy admin-API HTTP server, Caddyfile/JSON
fixtures, file-provider configs for Traefik/nginx, a mocked `dnscontrol` runner,
and in-process edge fakes. That's what keeps the suite hermetic and fast.

The catch, and the bar your tests must clear, is this:

> **A fake is only allowed to accept what the real edge would accept, and must
> reject what the real edge would reject. Make the fake faithful *first*, then
> fix the code against it.**

This isn't a slogan; it's how real bugs were caught. The Caddy fake was made to
actually *provision* inserted handlers and *reject* a synthetic `forward_auth`
that the real Caddy would reject. Only then did a class of "the fakes happily
round-tripped a bogus config" bugs become visible. So:

- When you add or change a driver behavior, **first** tighten the corresponding
  fake/fixture so it mirrors the real edge's acceptance/rejection, **then** write
  the RED test, **then** make it GREEN. A test that passes only because the fake
  is too lenient is worse than no test.
- Prefer **reproduce-then-fix**: a failing test that demonstrates the real-world
  defect, committed alongside the fix.
- Any code you add that renders or parses edge config needs a negative test too:
  an un-exposed host must remain unreachable, and the catch-all default-deny must
  survive removing the last explicit route.

### Presentation / branding changes

The terminal UI and the SVG assets share one renderer in `internal/ui` so they
cannot visually drift. If you touch wordmark/HUD rendering:

- Add deterministic unit tests in `internal/ui` (the renderers are pure: no I/O
  beyond an `io.Writer`/returned string).
- Keep **color semantic**, never decorative: green = safe/private/verified,
  amber = about-to-go-public/drift, red = fail-open. New fields pick a *role*
  (`ui.Sem`), not a raw color. See [`docs/brand/BRANDING.md`](docs/brand/BRANDING.md).
- Regenerate the committed SVGs from the renderers and commit the result:
  ```bash
  CRENEL_GEN_ASSETS=1 go test ./internal/ui/ -run TestGenerateAssets
  ```
  Do **not** hand-edit `docs/brand/*.svg`; they are generated artifacts.

## The trial-before-merge cadence (edge-touching changes)

Fakes prove logic; they cannot prove Crenel writes a config a *real* edge will
load and serve. For changes to an **edge driver, the apply/chain-write path, or
persistence**, the maintainer runs a **live trial** against real infrastructure
before merging, and records it as a `TRIAL-*.md` (plan) + `TRIAL-RESULT-*.md`
(observed bytes). Examples already in-tree: the 302 chain-write, durable-persist,
and one-command-rename trials.

What this means for a contributor:

- If you **can** run a comparable trial against your own edge, do so and attach
  the plan/result notes (sanitized; see *Secrets* below) to the PR.
- If you **cannot**, say so explicitly in the PR ("fakes only; needs a live
  trial"). That's fine and honest. The maintainer will gate the merge on
  running the trial. Do not claim live verification you did not perform.
- A trial is `read-live → plan/apply → read-back-verify → revert`, leaving
  production byte-for-byte as found. Never run a trial against infra you do not
  own or are not authorized to change.

## Secrets & redaction

Edge configs hold real secrets (auth tokens, upstream creds). Crenel redacts them
in output and `export --redacted`. When you attach logs, diffs, or trial results
to an issue/PR, **scrub real hostnames, tokens, and IPs.** Never paste an
unredacted export or admin-API dump. Tests must not embed real credentials.

## Legal: DCO

**DCO: every commit.** Sign off each commit to certify you wrote it / have the
right to submit it (the [Developer Certificate of Origin](DCO.txt)):

```bash
git commit -s          # appends "Signed-off-by: Your Name <you@example.com>"
```

Your `user.name` / `user.email` must be real and match the sign-off. To sign off
a branch you forgot to sign: `git rebase --signoff develop`.

> **Policy:** the maintainer will not merge a PR until all its commits are
> DCO-signed.

## Open-core boundary

Crenel's core is Apache-2.0 and intends to stay a complete, useful, default-deny
edge-exposure tool on its own. A later, separately-licensed **enterprise**
directory may add things like a compliance/audit ledger. The architecture keeps
that seam clean: `internal/core` and `internal/model` never import a driver, and
concrete drivers are wired only at `cmd/crenel` (asserted by a dependency test).
Contributions to the Apache core are always welcome; see
[`docs/OPEN-CORE.md`](docs/OPEN-CORE.md) for what lives on each side of the line.

## Code style

- `gofmt` (run `make fmt`); idiomatic Go; match the surrounding code's comment
  density and naming. The existing code comments the *why*, not the *what*; do
  the same.
- Keep the hexagonal dependency rule intact: `core`/`model` depend on nothing
  below; drivers depend on `model`/`ports` only; wiring lives in `cmd`.
- Small, reviewable PRs. One concern per PR.

## Reporting security issues

Do **not** open a public issue for a vulnerability (e.g. a way to make Crenel
report default-deny ENFORCED while a host is actually reachable). See
[`SECURITY.md`](SECURITY.md) for the threat model and private disclosure.
