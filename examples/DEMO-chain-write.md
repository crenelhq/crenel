# Demo — cross-chain coordinated WRITE (P4-write)

Captured against `examples/settings-chain-write.json` (two deny-only in-process Caddy
fakes — a public **vps** FRONT and a downstream **home** edge that serves the real
backends + auth, plus mock internal/public DNS). No live infra. Each `crenel` run boots
fresh fakes, so the demo is a single invocation showing the whole transaction.

## 1. Preview — one `expose` projects across the WHOLE chain

```
$ crenel -config examples/settings-chain-write.json preview expose books --auth authelia
Plan: expose books (host=books.homelab.example, auth=authelia)
  EDGE [vps·caddy]
    + route   books.homelab.example             -> 10.0.0.13:443
  EDGE [home·caddy]
    + route   books.homelab.example             -> 10.0.0.9:80  [auth:authelia]
  INTERNAL DNS
    + A      books.homelab.example             10.0.0.13
  PUBLIC DNS
    + A      books.homelab.example             203.0.113.9
  default-deny will remain present on every edge: true

  ⚠ ABOUT TO GO PUBLIC: books.homelab.example
    (these hostnames will be resolvable and reachable from the internet)
```

The single op becomes a **per-participant** changeset: the **vps** front gets a FORWARD
route to the downstream edge (`-> 10.0.0.13:443`, no auth — it is a relay), the
**home** edge gets the REAL route (`-> 10.0.0.9:80`) and the auth policy lands there
(`[auth:authelia]`), and DNS is added. Auth attaches at the edge that SERVES the host.

## 2. Apply — one all-or-nothing, read-back-verified transaction

```
$ crenel -config examples/settings-chain-write.json expose books --auth authelia -yes
applied: expose books (host=books.homelab.example, auth=authelia)
  read-back ✓ [edge[vps·caddy]]    books.homelab.example is now reachable
  read-back ✓ [edge[home·caddy]]   books.homelab.example is now reachable
  read-back ✓ [dnscontrol/internal] records present
  read-back ✓ [dnscontrol/public]   records present
  verified: live state matches intent
```

Applied in the safe order — **downstream → front → public DNS last** — and every
participant is **read-back-verified** (incl. the auth policy at the downstream edge).
ANY failure on either edge or DNS rolls back ALL applied participants (proven in
`internal/core/chain_write_test.go`: front-fail, downstream-fail, public-DNS-fail, and a
silent downstream auth-drop each leave nothing half-applied on either edge).

## 3. Guardrail — chain-wide public-without-auth

```
$ crenel -config examples/settings-chain-write.json expose books -yes
error: refusing to expose books.homelab.example PUBLIC with no auth — pass --auth <policy>
to protect it, or --auth none to publish it unprotected on purpose
```

With no auth anywhere along the chain, the public expose is refused (`--yes` does not
bypass) — the operator must attach a policy (which lands downstream) or opt out with
`--auth none`.
