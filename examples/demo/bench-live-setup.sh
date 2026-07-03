#!/usr/bin/env bash
# Bench B — real cross-vendor demo bench (Caddy + Traefik), FAKE hostnames only.
# Downloads throwaway caddy/traefik binaries, boots both daemons with a clean
# default-deny baseline, and writes the crenel configs the reel driver uses.
# Idempotent-ish; tear down with bench-live-teardown.sh. NOTHING here touches
# production — example.com hosts + RFC-1918 placeholder backends only.
set -euo pipefail

DIR="${BENCH_DIR:-/tmp/crenel-demo-bin}"
CADDY_VER="${CADDY_VER:-2.8.4}"
TRAEFIK_VER="${TRAEFIK_VER:-3.1.2}"
OS="$(uname | tr '[:upper:]' '[:lower:]')"           # darwin | linux
ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
CADDY_OS="$OS"; [ "$OS" = "darwin" ] && CADDY_OS=mac  # caddy calls it "mac"

mkdir -p "$DIR"; cd "$DIR"

# --- binaries ---------------------------------------------------------------
[ -x ./caddy-real ] || { curl -fsSL -o caddy.tgz \
  "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VER}/caddy_${CADDY_VER}_${CADDY_OS}_${ARCH}.tar.gz"
  tar xzf caddy.tgz caddy && mv caddy caddy-real && xattr -c caddy-real 2>/dev/null || true; }
[ -x ./traefik ] || { curl -fsSL -o traefik.tgz \
  "https://github.com/traefik/traefik/releases/download/v${TRAEFIK_VER}/traefik_v${TRAEFIK_VER}_${OS}_${ARCH}.tar.gz"
  tar xzf traefik.tgz traefik && xattr -c traefik 2>/dev/null || true; }

# caddy shim: real `validate`, no-op `reload` (admin API already applied live; skipping
# the Caddyfile reload keeps the clean JSON default-deny read intact on the bench).
cat > caddy <<'SHIM'
#!/usr/bin/env bash
case "$1" in reload) exit 0 ;; *) exec "$(dirname "$0")/caddy-real" "$@" ;; esac
SHIM
chmod +x caddy

# --- baseline configs (fake hosts) -----------------------------------------
cat > caddy-init.json <<'JSON'
{ "admin": {"listen": "127.0.0.1:2019"},
  "apps": {"http": {"servers": {"srv0": {
    "listen": [":8443"], "automatic_https": {"disable": true},
    "routes": [
      {"@id":"auth","match":[{"host":["auth.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:9091"}]}]},
      {"@id":"deny-catchall","handle":[{"handler":"static_response","status_code":403}]}
    ] }}}} }
JSON

cat > crenel.json <<'JSON'
{ "http": {
    "routers": {"auth": {"rule": "Host(`auth.example.com`)", "service": "auth-svc", "entryPoints": ["web"]}},
    "services": {"auth-svc": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:9091"}]}}}
} }
JSON

cp -f "$(dirname "$0")/../Caddyfile.base" demo-persist.Caddyfile 2>/dev/null || true

cat > settings-reel.json <<JSON
{ "zone":"example.com","granular_apply":true,"edges":[
  {"name":"caddy-edge","driver":"caddy","admin_url":"http://127.0.0.1:2019",
   "caddy_persist_path":"$DIR/demo-persist.Caddyfile",
   "origins":{"app":"10.0.0.10:8080","grafana":"10.0.0.11:3000","vault":"10.0.0.12:8200"}},
  {"name":"traefik-edge","driver":"traefik","traefik_config_path":"$DIR/crenel.json","traefik_api_url":"http://127.0.0.1:8099",
   "origins":{"app":"10.20.0.10:8080","grafana":"10.20.0.11:3000","vault":"10.20.0.12:8200"}}
]}
JSON
# rollback variant: traefik vault origin invalid (space) → real daemon rejects → rollback
sed 's#"vault": "10.20.0.12:8200"#"vault": "bad host:8200"#' settings-reel.json > settings-reel-rollback.json

# --- boot daemons -----------------------------------------------------------
pkill -f "caddy-real run" 2>/dev/null || true; pkill -f "traefik --api" 2>/dev/null || true; sleep 1
nohup ./caddy-real run --config caddy-init.json > caddy.log 2>&1 &
nohup ./traefik --api.insecure=true --api.dashboard=false --entrypoints.traefik.address=:8099 \
  --providers.file.filename="$DIR/crenel.json" --providers.file.watch=true \
  --entrypoints.web.address=:8000 --log.level=ERROR > traefik.log 2>&1 &
sleep 3
curl -fsS http://127.0.0.1:2019/config/ -o /dev/null && echo "caddy admin up :2019"
curl -fsS http://127.0.0.1:8099/api/http/routers -o /dev/null && echo "traefik api up :8099"
echo "bench ready — drive with:  PATH=\"$DIR:\$PATH\" bash $(dirname "$0")/drive-reel.sh"
