<!-- Thanks! CONTRIBUTING.md is short and is the contract; this is its checklist. -->

## What & why

<!-- One concern per PR. Reference the issue if there is one. -->

## Checklist

- [ ] `make check` green (build + `go vet` + `go test -race ./...`)
- [ ] Tests added; fakes tightened **first** so they reject what the real edge
      rejects (the faithful-fake bar: a test that passes against a lenient fake
      is worse than no test)
- [ ] Invariants hold: structural default-deny, bounded honesty
      (declare-unknown, refuse-to-manage foreign routes), read-back-verify on
      every mutating path
- [ ] Every commit is DCO-signed (`git commit -s`); first-time contributors:
      CLA accepted (see CLA.md)
- [ ] No real hostnames, IPs, or credentials in code, tests, docs, or this PR

## Live-trial note (edge-driver / apply-path / persistence changes only)

<!-- Either: "trialed against my own edge, plan/result attached (sanitized)",
     or honestly: "fakes only; needs a live trial." See CONTRIBUTING.md. -->
