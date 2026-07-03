#!/usr/bin/env bash
curl -s -X POST http://127.0.0.1:2019/load -H "Content-Type: application/json" -d @caddy-init.json -o /dev/null
cat > /tmp/crenel-demo-bin/crenel.json <<'JSON'
{
  "http": {
    "routers": {"auth": {"rule": "Host(`auth.example.com`)", "service": "auth-svc", "entryPoints": ["web"]}},
    "services": {"auth-svc": {"loadBalancer": {"servers": [{"url": "http://10.0.0.9:9091"}]}}}
  }
}
JSON
# wait until traefik re-loads auth@file (watch can lag)
for i in $(seq 1 20); do
  if curl -s http://127.0.0.1:8099/api/http/routers | grep -q "auth@file"; then break; fi
  sleep 0.5
done
echo "reset ok — traefik: $(curl -s http://127.0.0.1:8099/api/http/routers | python3 -c 'import sys,json;print(",".join(r["name"] for r in json.load(sys.stdin)))' 2>/dev/null)"
