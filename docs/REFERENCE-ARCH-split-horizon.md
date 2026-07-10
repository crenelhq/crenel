# Crenel Reference Architecture: Split-Horizon, Multi-Vantage Ingress

> The **preferred method** Crenel recommends (and the shape it was built to drive): a
> **public edge in front of a home edge** for ingress, plus **split-horizon DNS across two
> resolvers chosen by client vantage**, all coordinated as **one read-back-verified change** with
> Crenel as the **single source of truth (SOT)**. This doc is the architecture; the driver-level
> mechanics live in **[DNS-DESIGN.md](DNS-DESIGN.md)**, the invariants in **internal/DESIGN.md**, secrets in
> **SECURITY.md**.
>
> **Honesty about status: read [§5](#5-built-vs-roadmap) before quoting capability.** The
> preferred method's load-bearing pieces are **BUILT** and (where applicable) **live-proven**
> (surgical Cloudflare, the coordinated multi-scope expose, the two-edge chain write). The
> **dual-AdGuard split with per-instance labeling + the `dns_coverage_parity` audit + wildcard
> awareness** is **BUILT and test-covered end-to-end through the real driver** (PRs #12 + #15
> + #16 on `develop`); the live trial against the actual dual-resolver pair is now **PROVEN**
> (2026-06-30: both resolvers restored byte-for-byte, `dns_coverage_parity` caught a real
> divergence live; see the repo's `internal/TRIAL-RECORD-live-proofs-2026-06-30.md`). Per-host
> **tunnel/funnel ingress recovery** is BUILT for both cloudflared (§5h)
> and Tailscale serve.json `AllowFunnel` (PR #17). The **Cloudflare-free** variant
> ([§6](#6-the-cloudflare-free-alternative)) is a **roadmap provider**, not something that
> exists yet. Example addresses below are placeholders (`example.com`, `10.0.0.x`,
> `EDGE_PUBLIC_IP`). Substitute your own.

---

## 0. TL;DR

- **Ingress** = a hardened **public edge** (TLS + WAF, e.g. Caddy/CrowdSec on a VPS) that forwards an
  **explicit allowlist** of hostnames over a private tunnel to a **home edge** which is the **SOT**
  for routing. Unknown hosts are dropped at the public edge. No inbound ports at home.
- **Resolution** = **split-horizon across two AdGuard resolvers picked by *client vantage*** (whether
  the client is on the tunnel), each returning the **vantage-correct target**, plus **public DNS**
  (Cloudflare) for the outside world.
- **Crenel coordinates all three on one `expose`**: the edge route, the internal rewrite(s), and the
  public record. Ordered (routes before names), read-back-verified, and **atomically rolled back**
  if any leg fails.
- **"Sync" = same *coverage*, vantage-correct *targets***: both resolvers know the same managed host
  set; each answers with the right address for the clients it serves. The targets **coincide** for
  home-resident hosts (the common case) and **diverge** for hosts that live on the public edge.
- **Crenel is the SOT.** It owns and tracks its records on every provider; an audit asserts coverage
  parity and target correctness so manual drift surfaces instead of festering.

---

## 1. The preferred topology

```
                  ┌──────────────── Public DNS (authoritative) ─────────────────┐
   public client ─► │  *.example.com   A → EDGE_PUBLIC_IP        (Cloudflare)    │
                  └───────────────────────────────┬──────────────────────────────┘
                                                  ▼
                        Public edge  (EDGE_PUBLIC_IP : 443)         ← VPS / cloud
                        · TLS terminate   · WAF / CrowdSec
                        · @allow = generated allowlist of public hostnames
                        · unknown host → abort (dropped at the edge)
                                                  │  forward allowlisted host
                                                  ▼  (private tunnel — WireGuard/Tailscale; SNI = host)
                        Home edge = SOT  (HOME_EDGE_IP : 443)        ← LAN
                        · per-service routes (the only place you edit)
                        · default = internal (public edge never forwards it)
                                                  ▼
                                          services on the LAN

   Internal resolution (split-horizon — no public hop):
     ┌─ client ON the tunnel        ─► VPS AdGuard   (TUNNEL_DNS_IP) ─┐
     │  (every Tailscale client,                                      ├─► host → HOME_EDGE_IP
     │   on- or off-LAN)                                              │   (LAN-direct, or via the
     └─ client OFF the tunnel       ─► home AdGuard  (HOME_DNS_IP) ───┘    accepted subnet route)
        (plain DHCP / IoT / guest)
```

**Components and their roles:**

| Component | Role | In this architecture |
|---|---|---|
| **Public DNS** (Cloudflare) | authoritative public records | `*.example.com A → EDGE_PUBLIC_IP`; the world always transits the edge |
| **Public edge** (Caddy + CrowdSec) | internet-facing front | TLS, WAF, generated `@allow`; forwards known hosts to the home edge, drops the rest |
| **Private tunnel** (WireGuard / Tailscale) | edge↔home transport | the only link between sites; no inbound ports at home |
| **Home edge** (Caddy) | **SOT for routing** | per-service routes; tag a route public to add it to the edge allowlist |
| **VPS AdGuard** | resolver for **tunnel** clients | answers every Tailscale client (on- or off-LAN) |
| **Home AdGuard** | resolver for **non-tunnel** clients | answers plain DHCP/IoT/guest clients |
| **Crenel** | **orchestration SOT** | drives the edge route + both internal rewrites + the public record as one verified change |

> **Why two resolvers, not one.** The split is by **client vantage, not by name.** A device's resolver
> is decided by whether it is on the tunnel (a tunnel-DNS policy such as headscale
> `override_local_dns` forces it), *independent of physical location*. So the two resolvers serve two
> populations with different reachability, which is exactly why a single shared answer set is wrong
> for some hosts (see §2).

---

## 2. The three vantages and the target rule

A **vantage** is the position from which a client resolves and connects. There are three:

1. **Public**: anyone off the tunnel; resolves via Cloudflare; must transit the public edge.
2. **Tunnel**: any client on the private tunnel (on- or off-LAN); resolves via the **VPS AdGuard**.
3. **Non-tunnel LAN**: plain DHCP/IoT/guest with no tunnel; resolves via the **home AdGuard**.

Crenel computes each provider's answer from the host's **residency class** × the provider's
**vantage**, the function `target(class, vantage)`:

| host class | home AdGuard (non-tunnel) | VPS AdGuard (tunnel) | Cloudflare (public) |
|---|---|---|---|
| **home-resident** (the common case) | `HOME_EDGE_IP` (LAN-direct) | `HOME_EDGE_IP`, via the accepted subnet route¹ | `EDGE_PUBLIC_IP` |
| **edge-resident, edge-served** | `EDGE_PUBLIC_IP` (outbound to the edge) | `TUNNEL_VPS_IP` (tunnel-direct; no public bounce) | `EDGE_PUBLIC_IP` |
| **internal-only** (admin, infra) | none (unreachable without the tunnel) | `TUNNEL_VPS_IP` / LAN target | none (not public) |

¹ The tunnel client reaches a private `HOME_EDGE_IP` only if the home subnet route is **advertised and
accepted** (`--accept-routes`, off by default on headless clients). Make that a stated precondition of
the tunnel vantage.

**The honest reading of "vantage-correct targets":**

- For **home-resident** services both resolvers correctly return the **same** `HOME_EDGE_IP`. The
  answers **coincide**, and that's right ("local stays local": tunnel clients still go straight to the
  home edge, not back out through the public edge). The architecture does **not** manufacture a
  difference where the correct answer is the same.
- The targets **genuinely diverge** for **edge-resident / internal-only** hosts: the non-tunnel vantage
  must use the public IP (no tunnel available), while the tunnel vantage should use the tunnel-direct
  IP (shorter path, no public bounce, and the public edge would refuse an internal-only host anyway).
- So it's a real **function evaluated independently per provider**, never one shared value broadcast
  to both resolvers.

**"Sync," precisely:** consistent **coverage** (both resolvers know the same managed host set) with
**vantage-correct targets** (each computed by the rule above), all **tracked as Crenel-owned**. Not
"identical rules" on both boxes; identical *coverage*, differentiated *answers*.

---

## 2.5 The Crenel host must reach every control plane it manages

Crenel is live-state-authoritative: every verb reads live, applies, and re-reads. That only works
if the host running Crenel has **first-class network reachability to every edge admin API and
every DNS control plane in its config** — before writing a provider block, prove each endpoint
with a plain `curl` from that host.

The trap in a multi-node overlay setup (found dogfooding this exact architecture): the Crenel host
usually sits on the LAN, but the overlay-vantage resolver sits on the overlay network — and the
LAN's default gateway knows nothing about the overlay's address space (Tailscale/headscale CGNAT
`100.64.0.0/10`, a WireGuard subnet, …). Symptom: the overlay resolver answers from your laptop
(an overlay client) but times out from the Crenel host.

You do **not** need to enroll the Crenel host in the overlay or run a tunnel shim. If any LAN
machine is already an overlay **subnet router** (advertising the LAN into the overlay), the return
path already exists; the only missing piece is the Crenel host's outbound route:

```sh
# on the Crenel host: send overlay-bound traffic via the LAN's subnet router
ip route add 100.64.0.0/10 via <subnet-router-lan-ip>
# prove it (an overlay-hosted AdGuard admin answers its login redirect):
curl -s -o /dev/null -w '%{http_code}\n' -m5 http://<overlay-resolver>:3000/   # expect 302
# persist it across reboots / managed-interface regeneration:
printf '#!/bin/sh\nip route replace 100.64.0.0/10 via <subnet-router-lan-ip>\n' \
  > /etc/network/if-up.d/overlay-route && chmod +x /etc/network/if-up.d/overlay-route
```

Alternatively add the same static route on the LAN gateway itself — every LAN host gains overlay
reachability, nothing per-host to remember; a network-wide policy call rather than a host-local
one. Either way, **reachability is a topology property, not Crenel's job**: an unreachable
provider is reported honestly, never guessed around.

---

## 3. Crenel as the source of truth

A single `crenel expose <host>` (or a declarative `apply`) coordinates the whole chain:

1. **Edge route** on the home SOT (and, for a fronted chain, a synthesized forward route on the public
   edge so the allowlist admits the host).
2. **Internal DNS**: an exact rewrite on **each** AdGuard, each with its **own** vantage-correct
   target (two `scope: internal` providers, different endpoint + different `edge_addr`).
3. **Public DNS**: a surgical, per-record Cloudflare entry pointing at the public edge.

**Ordering and safety (built):**

- **Make-before-break:** on expose, routes come up before names are announced
  (`edges → internal-DNS → public-DNS`); on unexpose the order reverses (stop announcing first).
- **Read-back verify:** after applying, Crenel re-reads each provider's live state and confirms the
  desired records are present/absent.
- **All-or-nothing:** any failed leg triggers a reverse-order rollback; a wedged edge is *skipped*
  (not re-hit) so rollback can't deepen a wedge.

**Ownership / drift:**

- **Cloudflare** records carry a `managed-by:crenel` marker (word-boundary matched). Crenel updates
  or deletes only what it owns and refuses to shadow a foreign record.
- **AdGuard** rewrites carry no provenance marker, so Crenel owns them by **zone confinement +
  value-match** (it refuses wildcards and out-of-zone names, and refuses to clobber a foreign rewrite
  whose answer differs). Provenance across two instances is tracked by Crenel's own config manifest.
- A **coverage-parity audit** compares the two internal resolvers' managed host sets and each target
  against `target(class, vantage)`, so a host present on one resolver but missing (or mis-targeted) on
  the other surfaces as a finding instead of a silent, vantage-specific outage. *(See §5: this audit
  is **BUILT** and wildcard-aware (PR #12 base + #15/#16), and now **live-proven** on the real
  dual-resolver pair, 2026-06-30.)*

---

## 4. Worked example (placeholders)

`expose grafana` where `grafana` is a **home-resident** service:

```jsonc
{
  "zone": "example.com",
  "edges": [ { "name": "home", "driver": "caddy", "admin_url": "http://127.0.0.1:2019",
               "origins": { "grafana": "10.0.0.5:3000" } } ],
  "dns": { "enabled": true, "providers": [
    { "type": "adguard",    "scope": "internal", "zone": "example.com",
      "edge_addr": "10.0.0.13",                         // home vantage  → home edge
      "endpoint": "http://10.0.0.53:3000", "username": "admin", "password_env": "ADGUARD_HOME_PW" },
    { "type": "adguard",    "scope": "internal", "zone": "example.com",
      "edge_addr": "10.0.0.13",                         // tunnel vantage → home edge (coincides)
      "endpoint": "http://100.100.0.2:3000","username": "admin", "password_env": "ADGUARD_VPS_PW" },
    { "type": "cloudflare", "scope": "public",   "zone": "example.com", "apply_mode": "surgical",
      "edge_addr": "EDGE_PUBLIC_IP",                    // public vantage → public edge
      "api_token_env": "CF_TOKEN" }
  ] }
}
```

Result of `expose grafana`:
- home edge routes `grafana.example.com → 10.0.0.5:3000`;
- home AdGuard rewrites `grafana.example.com → 10.0.0.13`;
- VPS AdGuard rewrites `grafana.example.com → 10.0.0.13`;
- Cloudflare A `grafana.example.com → EDGE_PUBLIC_IP` (marked `managed-by:crenel`).

`unexpose grafana` removes exactly those four, in reverse exposure order, and verifies each is gone
while every foreign record/route stays byte-untouched.

---

## 5. BUILT vs ROADMAP

Accurate as of this writing. "Live-proven" means exercised against a real production edge/provider and
recorded byte-for-byte (see the repo's `TRIAL-RESULT-*.md`).

| Capability | Status |
|---|---|
| **Coordinated multi-scope expose** (edge + internal + public; ordered; read-back-verified; atomic rollback) | **BUILT · live-proven** (cross-chain trial) |
| **Public DNS via Cloudflare, surgical** (per-record REST CRUD; `managed-by:crenel`; shared-zone-safe) | **BUILT · live-proven**: dedicated `crenel.sh` zone (PR #11) **and the shared `homelab.example` zone (2026-06-30):** apex wildcard byte-identical across expose/unexpose, only Crenel's marked record touched (see `internal/TRIAL-RECORD-live-proofs-2026-06-30.md` §1) |
| **Two-edge chain write** (public front → home SOT, atomic across both) | **BUILT · live-proven** |
| **Internal DNS via AdGuard native control-API driver** (single instance; zone-confined; no-wildcard guard) | **BUILT · fake-tested + unit** |
| **Dual-AdGuard split with per-instance labeling** (two `scope:internal` providers, vantage-correct targets; `adguard[home]`/`adguard[vps]` distinguishable in every plan/apply/verify/audit label) | **BUILT** (PR #12, merged on `develop`): per-instance label woven through `dns_wire.go` + driver, per-instance ownership refuses a foreign overwrite on the right instance, end-to-end test through the real driver against `adguardfake`. Live dual-resolver trial now **PROVEN (2026-06-30):** both resolvers restored byte-for-byte, `dns_coverage_parity` caught a real divergence live (see `internal/TRIAL-RECORD-live-proofs-2026-06-30.md` §2). |
| **`dns_coverage_parity` audit** across two internal resolvers | **BUILT** (PR #12 base; **wildcard-aware after PR #15**). Diffs host *sets*, vantage-different *targets* are clean (presence check only); a wildcard rewrite is a CATCH-ALL, not a host, and the union is built from EXPLICIT names only with a value-mismatch guard that still flags `host`→A explicit vs covering `*.zone`→B (B ≠ A). RED→GREEN with stub + real-AdGuard-driver end-to-end. |
| **`dns_value_drift` audit + `DriftValueDNS` reconcile-side correction** (owned-record target drift detected AND corrected) | **BUILT** (PRs #13, #14), scoped via the optional `ports.OwnedRecordReporter` capability. Surgical Cloudflare opts in (its `LiveRecords` is marker-filtered, so every record is provably Crenel's). Marker-less AdGuard deliberately does NOT implement the capability; a value check there would cry wolf on the operator's legitimately-foreign rewrites. Documented limit, not a fix. |
| **Wildcard-aware sibling DNS-vs-edge checks** (`dns_without_edge_route` / `edge_route_without_dns`) | **BUILT** (PR #16). A wildcard `*.zone` is a CATCH-ALL: backed by any exposed host under the zone, so not flagged dangling unless nothing in the zone is exposed; covers any name in the zone for the reverse check. |
| **Tailscale funnel per-host recovery** (parses `serve.json` AllowFunnel keys → public set; per-edge authoritative public for the `public_without_auth` check) | **BUILT** (PR #17): `serve.json` `AllowFunnel` keys (port stripped from `host:port`) become the per-host public set; the conservative `exposed → public` default is now per-edge AUTHORITATIVE for edges with parsed per-host recovery. Tailnet-only `Web` entries (no `AllowFunnel`) are deliberately NOT modeled as a separate scope; the cry-wolf they previously caused is fixed but the affirmative tailnet-scope axis is roadmap. |
| **Cloudflare-free public provider** (self-hosted DNS/tunnel; see §6) | **ROADMAP** (new provider; not built) |

The formerly-gated next steps are now **DONE and PROVEN LIVE (2026-06-30):** (a) the live
**dual-AdGuard trial** (both resolvers restored byte-for-byte, `dns_coverage_parity` caught a
real divergence); (b) the **surgical Cloudflare trial on the shared `homelab.example` zone**
(apex wildcard byte-identical, only Crenel's marked record touched); and (c) the **full-chain
`finances.homelab.example` production expose from the home-edge host**: one Crenel run driving the home edge
route, VPS edge allowlist, both AdGuard rewrites, and the public Cloudflare record, all gates
green (the coordinated multi-scope expose at production scale). See the repo's
`internal/TRIAL-RECORD-live-proofs-2026-06-30.md`. What remains genuinely live-only is Tailscale
`serve.json` WRITE support (read side is per-host wildcard-aware; write path untested).

---

## 6. The Cloudflare-free alternative

The preferred method uses **Cloudflare** for the public/authoritative view because that path is built
and live-proven. The architecture is **vendor-agnostic by design** (the public edge and the public
DNS view are separate provider seams), so an operator who does not want Cloudflare can substitute a
**self-hosted public-ingress provider** and keep everything else (the home-SOT chain, the dual-AdGuard
split, the coordinated verified expose) identical.

The natural substitution is a **self-hosted reverse tunnel / DNS proxy** such as **Pangolin** (or a
WireGuard-based tunnel fronted by a self-managed authoritative zone): a small public node terminates
TLS and tunnels to the home edge, and the public name is published in a zone the operator controls
instead of in Cloudflare. In that variant:

- the **public edge** role is filled by the self-hosted tunnel's ingress node;
- the **public DNS** record is written to the self-hosted authoritative zone (or the tunnel provider's
  own name allocation) rather than to Cloudflare;
- the **internal split-horizon** (dual AdGuard, vantage-correct targets) is **unchanged**;
- **Crenel** coordinates it the same way: one ordered, verified, atomically-rolled-back expose.

> **Status: ROADMAP, stated honestly.** Today Crenel drives **Cloudflare** for the public view
> (built, live-proven); it does **not** yet have a Pangolin / self-hosted-tunnel provider. This variant
> is documented as the **intended off-Cloudflare path and roadmap provider**, not a shipping feature.
> It fits the existing DNS/ingress provider interface cleanly (the same `DNSProvider` seam the
> Cloudflare and AdGuard drivers already implement), so adding it is new-provider work, not a
> re-architecture. Until it lands, off-Cloudflare operators can run the home-SOT + dual-AdGuard half
> of the architecture under Crenel and manage the public-ingress leg by hand.

---

## 7. See also

- **[DNS-DESIGN.md](DNS-DESIGN.md)**: driver-level design. The Cloudflare and AdGuard adapters, the
  control-API contract, credential handling, the safety posture.
- **internal/DESIGN.md**: the two load-bearing invariants + apply ordering this architecture inherits.
- **SECURITY.md**: the secret inventory + redaction (one env-ref per provider; nothing hardcoded).
- The repo's **`TRIAL-RESULT-*.md`**: the byte-for-byte records behind every "live-proven" claim.
