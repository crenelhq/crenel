# Live-proof record — 2026-07-10: Pi-hole provider, first real-API write trial

Operator-record for the gated live trial that took the Pi-hole provider
(`internal/drivers/dns/pihole`) from FIXTURE-PROVEN (driver + fake built against
the captured v6 transcript in `testdata/`) to LIVE-PROVEN: a full
expose → verify → drift → unexpose cycle through the real engine against a real,
throwaway Pi-hole instance. As with the prior trial records, hostnames, zones,
and addresses are anonymized (`trial.example`, RFC 1918 placeholders); command
sequences, outputs, and results are otherwise verbatim. The trial ran on the
disposable build/test sandbox host; every container and file it created was
torn down afterward and the host's pre-existing stacks were verified untouched.

Note: this record lives in its own file (not appended to
`TRIAL-RECORD-live-proofs-2026-07-10.md`) because that file exists only on the
unmerged `docs/state-refresh` branch — merge/rehome as part of that branch's
consolidation if desired.

## 0. Pre-trial gate (code)

The dual-Pi-hole + mixed-resolver WRITE gate
(`internal/core/dual_pihole_write_test.go`, this branch) went green first:
dual-instance fan-out, mixed adguard+pihole coordinated write/unexpose,
mid-transaction 429 rollback naming the failing instance, residency divergence
across two piholes and across the mixed pair, and the OSDoer session
expiry/re-auth contract composed with Apply (no double-write; persistent 401
surfaces honestly and rolls back). Full `go test -race ./...` green.

## 1. Setup — throwaway targets, high ports

- Pi-hole: `docker run -d --name pihole-trial -e TZ=UTC
  -e FTLCONF_webserver_api_password=<pw> -p 8581:80 pihole/pihole:latest`
  — came up as core v6.4.3 / web v6.6 / FTL v6.7, the SAME core/FTL pair the
  fake's fixtures were captured against.
- Edge: a throwaway `caddy:2` container with its admin API published on :8582
  (see finding F1 for why its Caddyfile needed `admin 0.0.0.0:2019` +
  `local_certs`).
- Binary: crenel cross-built linux/amd64 from this branch, scp'd over.
- Settings: real `admin_url` (the trial Caddy), `granular_apply: true`, one DNS
  provider `{type: pihole, scope: internal, zone: trial.example,
  edge_addr: 10.0.0.99, endpoint: http://127.0.0.1:8581, password: <pw>}`.

## 2. The cycle (verbatim results)

```
$ crenel --config settings.json --yes --auth none expose trial-host
applied: expose trial-host (host=trial-host.trial.example)
  read-back ✓ [edge[caddy·caddy]] trial-host.trial.example is now reachable
  read-back ✓ [pihole[trial]/internal] records present
  verified: live state matches intent

$ curl -H "sid: $SID" http://127.0.0.1:8581/api/config/dns/hosts
{"config":{"dns":{"hosts":["10.0.0.99 trial-host.trial.example"]}},...}

$ crenel --config settings.json drift
  (no drift — already consistent)          # exit 0

$ crenel --config settings.json --yes unexpose trial-host
applied: unexpose trial-host (host=trial-host.trial.example)
  read-back ✓ [edge[caddy·caddy]] trial-host.trial.example is no longer exposed
  read-back ✓ [pihole[trial]/internal] records absent
  verified: live state matches intent

$ curl -H "sid: $SID" http://127.0.0.1:8581/api/config/dns/hosts
{"config":{"dns":{"hosts":[]}},...}        # list restored to baseline
```

The session flow ran through the real `pihole.OSDoer` (POST /api/auth → sid
header) against the real FTL webserver — the first non-loopback exercise of
that path.

## 3. Fake-vs-reality probes — ZERO divergences

Every captured contract the driver and `piholefake` encode was re-probed
against the live v6.4.3/v6.7 API and matched exactly:

| probe                          | real API answer                                         | fake |
|--------------------------------|----------------------------------------------------------|------|
| PUT new entry                  | 201                                                      | same |
| PUT exact duplicate            | 400 `"Item already present"` / uniqueness hint           | same |
| PUT non-IP value               | 400 `"neither a valid IPv4 nor IPv6 address"`            | same |
| PUT wildcard hostname          | 400 `"invalid hostname"`                                 | same |
| DELETE present entry           | 204                                                      | same |
| DELETE absent entry            | 404 `{"took":…}`                                         | same |
| bad/expired sid                | 401 `{"error":{"key":"unauthorized",…}}`                 | same |
| wrong password on /api/auth    | 401 `{"session":{"valid":false,"sid":null,…}}`           | same |

No driver or fake changes were needed — the capture-first discipline held.

## 4. Findings (edge-side, not Pi-hole)

- **F1 — full `POST /load` replaces the admin block.** The first expose ran
  with the default full-load apply path; crenel's rendered Caddyfile carries no
  `admin` global, so the loaded config reverted Caddy's admin listener to its
  localhost default — killing the container's port-published admin socket
  mid-apply (the post-load health probe caught it: connection reset). The
  route itself HAD landed. Known posture of the full-load path, but this is a
  crisp reproduction: any Caddy whose admin endpoint is non-default MUST be
  managed with `granular_apply: true` (which patches routes additively and
  never touches the admin block — re-verified: admin socket answered 200
  throughout the granular cycle). Candidate doc note for DEPLOY guidance.
- **F2 — fake-seed edges can't host a multi-invocation drift check.** With
  `fake_seed` (in-process edge), a second CLI invocation re-seeds the edge, so
  `drift` flags the surviving REAL DNS record as `stale_dns_record`. Correct
  behavior, worth remembering when scripting trials: the drift gate needs a
  real (or at least process-external) edge.

## 5. Teardown

`docker rm -f pihole-trial caddy-trial`, trial directory removed; the sandbox
host's pre-existing container set verified identical to the pre-trial baseline.
