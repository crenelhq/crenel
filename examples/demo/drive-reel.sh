#!/usr/bin/env bash
# crenel capability reel — FAKE hostnames, real Caddy + real Traefik bench.
set -u
export CLICOLOR_FORCE=1
DIR="${BENCH_DIR:-/tmp/crenel-demo-bin}"
export PATH="$DIR:$PATH"                 # so the caddy shim resolves
CR="${CRENEL:-crenel}"                   # crenel binary (on PATH or absolute via $CRENEL)
CFG="$DIR/settings-reel.json"
RBK="$DIR/settings-reel-rollback.json"

GREEN=$'\033[38;2;0;255;102m'; STEEL=$'\033[38;2;120;126;138m'; AMBER=$'\033[38;2;255;176;0m'; R=$'\033[0m'; B=$'\033[1m'
PROMPT="${GREEN}❯${R} "

type_cmd() {
  printf '%s' "$PROMPT"; local s="$1"
  for ((i=0; i<${#s}; i++)); do printf '%s' "${s:$i:1}"; sleep 0.028; done
  printf '\n'; sleep 0.30
}
say() { printf '\n%s%s──%s %s%s%s %s──────────────────────────%s\n\n' "$B" "$STEEL" "$R" "$B" "$1" "$R" "$STEEL" "$R"; sleep 0.7; }

beat() { clear; say "$1"; }

# ── Beat 1: default-deny ────────────────────────────────────────────
beat "01 · DEFAULT-DENY — nothing is exposed until you say so"
type_cmd "crenel status --hud"
"$CR" -config "$CFG" status --hud
sleep 3.2

# ── Beat 2: preview ─────────────────────────────────────────────────
beat "02 · PREVIEW — see the change across BOTH vendors before you apply"
type_cmd "crenel expose grafana --auth none   # preview"
"$CR" -config "$CFG" preview expose grafana --auth none
sleep 3.4

# ── Beat 3: coordinated cross-vendor expose, read-back verified ─────
beat "03 · EXPOSE — one command, Caddy + Traefik, read-back VERIFIED"
type_cmd "crenel expose grafana --auth none --yes"
"$CR" -config "$CFG" expose grafana --auth none --yes
sleep 3.6

# ── Beat 4: one-command atomic rename ───────────────────────────────
beat "04 · RENAME — move a host as ONE atomic, verified transaction"
type_cmd "crenel rename grafana.example.com metrics.example.com --yes"
"$CR" -config "$CFG" rename grafana.example.com metrics.example.com --yes
sleep 3.6

# ── Beat 5: atomic rollback when one edge fails ─────────────────────
beat "05 · ATOMIC — one edge can't accept it → BOTH roll back. Never half-applied."
type_cmd "crenel expose vault --auth none --yes   # traefik origin is broken"
"$CR" -config "$RBK" expose vault --auth none --yes
sleep 0.2; printf '%sEXIT=%s%s\n' "$AMBER" "$?" "$R"
sleep 3.8

# ── Beat 6: final live state ────────────────────────────────────────
beat "06 · LIVE STATE — verified, never silently wrong"
type_cmd "crenel status --hud"
"$CR" -config "$CFG" status --hud
sleep 3.6
printf '\n'; sleep 0.8
