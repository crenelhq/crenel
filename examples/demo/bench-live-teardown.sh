#!/usr/bin/env bash
# Tear down Bench B: kill the throwaway daemons. The bench dir is disposable
# scratch (default /tmp/crenel-demo-bin); remove it too if you want a clean slate.
DIR="${BENCH_DIR:-/tmp/crenel-demo-bin}"
pkill -f "caddy-real run" 2>/dev/null || true
pkill -f "traefik --api" 2>/dev/null || true
echo "daemons stopped. (rm -rf $DIR to discard the bench entirely)"
