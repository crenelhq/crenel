# Deploying & running Crenel ON the VPS edge (loopback admin API)

This is the **safe** way to drive the real Caddy edge: run `crenel` **on the VPS**
against its admin API at `127.0.0.1:2019`. The admin API stays loopback-bound —
we never rebind or expose it, and we never SSH-tunnel it to another host.

## Target (example values — substitute your own)

| Fact | Value |
|------|-------|
| Host | `vps-edge` (e.g. a Tailscale address like `100.100.0.2`), any cloud VPS |
| SSH | `ssh vps-edge` (your VPS user) |
| OS / arch | any Linux the Go toolchain targets (this example: Ubuntu, **ARM64**) |
| Caddy admin | `http://127.0.0.1:2019` — confirmed `GET /config/` → `200` locally |
| Test dir | `~/crenel-test/` on the VPS |

## 1. Build (on the Mac)

```bash
cd ~/src/crenel
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/crenel-linux-arm64 ./cmd/crenel
```

## 2. Deploy (Mac → VPS)

```bash
ssh vps-edge 'mkdir -p ~/crenel-test/live-backup'
scp bin/crenel-linux-arm64      vps-edge:~/crenel-test/crenel
scp examples/vps-config.json    vps-edge:~/crenel-test/config.json
ssh vps-edge 'chmod +x ~/crenel-test/crenel'
```

`examples/vps-config.json` points at the loopback admin API, enables **additive
granular apply**, and maps a throwaway service to a harmless closed port:

```json
{
  "admin_url": "http://127.0.0.1:2019",
  "zone": "homelab.example",
  "granular_apply": true,
  "origins": { "crenel-selftest": "127.0.0.1:9999" }
}
```

## 3. BACKUP FIRST (mandatory before any mutation)

Snapshot the full running config to a timestamped file **on the VPS**, and keep a
copy on the Mac. The snapshot is the exact bytes `GET /config/` returns, so
restoring it is correct by construction.

```bash
# On the VPS:
TS=$(date -u +%Y%m%dT%H%M%SZ)
curl -sS http://127.0.0.1:2019/config/ > ~/crenel-test/live-backup/caddy-config-$TS.json
# sanity: non-empty, valid JSON
python3 -c "import json,sys; json.load(open(sys.argv[1]))" ~/crenel-test/live-backup/caddy-config-$TS.json && echo "backup OK: $TS"

# Optional: copy the backup back to the Mac repo (gitignored — may contain secrets)
scp vps-edge:'~/crenel-test/live-backup/caddy-config-*.json' ~/src/crenel/live-backup/
```

> ⚠️ The live config may contain secrets (Cloudflare token, Authelia config).
> `live-backup/` is **gitignored** — never commit it.

## 4. RESTORE (if anything goes wrong — full revert to the snapshot)

`POST /load` of the captured JSON replaces the running config with the exact
backup. This is the ONE place a full replace is correct: we are restoring the
real captured config verbatim, not a Crenel-rendered approximation.

```bash
# On the VPS — restores to the named backup:
curl -sS -X POST -H "Content-Type: application/json" \
  --data-binary @~/crenel-test/live-backup/caddy-config-<TS>.json \
  http://127.0.0.1:2019/load
# verify it matches the backup byte-for-byte:
curl -sS http://127.0.0.1:2019/config/ > /tmp/after.json
diff <(jq -S . ~/crenel-test/live-backup/caddy-config-<TS>.json) <(jq -S . /tmp/after.json) \
  && echo "RESTORE VERIFIED: live == backup"
```

## 5. READ-ONLY proof (safe — no mutation)

```bash
cd ~/crenel-test
./crenel --config config.json status
./crenel --config config.json preview expose crenel-selftest   # computes diff, does NOT apply
./crenel --config config.json audit
./crenel --config config.json export ~/crenel-test/live-export.json
```

## 6. MUTATING demo — STAGED, requires an explicit operator go

Only after the backup exists and read-only is proven. Uses **additive granular
apply** with a throwaway host; tears down and verifies the edge is byte-for-byte
back to the backup.

```bash
cd ~/crenel-test
# expose (adds ONE @id-tagged route at index 0; touches nothing else):
./crenel --config config.json --granular --yes expose crenel-selftest
./crenel --config config.json status            # confirm present + verified
# tear down:
./crenel --config config.json --granular --yes unexpose crenel-selftest
# prove we're back to the backup:
curl -sS http://127.0.0.1:2019/config/ > /tmp/final.json
diff <(jq -S . live-backup/caddy-config-<TS>.json) <(jq -S . /tmp/final.json) \
  && echo "EDGE RESTORED TO KNOWN-GOOD"
```

## Safety invariants
- Backup-first; restore command is verified-by-construction (re-POST of GET).
- Granular apply is **additive** — never rewrites unmanaged routes.
- Throwaway host (`crenel-selftest.homelab.example`) only; harmless closed-port
  backend; torn down and diff-verified after.
- Admin API never leaves loopback. No rebind, no tunnel, no exposure.
- Healthy edge > finished demo. On any doubt: restore, verify, stop.
