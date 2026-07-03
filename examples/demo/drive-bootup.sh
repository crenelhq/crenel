#!/usr/bin/env bash
# Driver for the crenel boot-up branding clip. FAKE hostnames only.
# Typewriter-effect prompt, then the branded banner + live CORE MATRIX HUD.
set -u
export CLICOLOR_FORCE=1
CRENEL=./bin/crenel
CFG=examples/demo/settings-demo.json
mkdir -p /tmp/crenel-demo-persist
cp -f examples/Caddyfile.base /tmp/crenel-demo-persist/Caddyfile 2>/dev/null || true

# Pretty fake prompt.
PROMPT=$'\033[38;5;84m❯\033[0m '

type_cmd() {
  printf '%s' "$PROMPT"
  local s="$1"
  for ((i=0; i<${#s}; i++)); do
    printf '%s' "${s:$i:1}"
    sleep 0.045
  done
  printf '\n'
  sleep 0.35
}

clear
sleep 0.6
type_cmd "crenel status --banner"
"$CRENEL" -config "$CFG" status --banner
sleep 3.2
printf '\n'
sleep 0.8
