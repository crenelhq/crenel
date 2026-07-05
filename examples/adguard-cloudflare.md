# Recipe: AdGuard Home (internal) + Cloudflare (public)

Split-horizon DNS: an internal **AdGuard Home** resolver gives LAN/VPN clients a
direct route to the backend, while public **Cloudflare** DNS points the rest of the
internet at the edge. Two providers, one `crenel expose`, both kept in sync — the
usual failure mode this recipe avoids is the internal rewrite and the public record
quietly disagreeing after a manual edit.

All hostnames below are examples (`immich.example`) — swap in your own zone.

## The shape

- One Caddy edge, reachable both from the LAN and the internet.
- AdGuard Home (`scope: internal`) rewrites the hostname straight to the edge's
  LAN address for anyone resolving it from inside the network — skipping the
  public round-trip.
- Cloudflare (`scope: public`) points the same hostname at the edge's public
  address for everyone else, in **surgical** mode so it only manages the one
  record it owns in a zone that may hold other, unrelated records.

## Settings

```json
{
  "edge_driver": "caddy",
  "admin_url": "http://127.0.0.1:2019",
  "zone": "example.com",
  "granular_apply": true,
  "origins": {
    "immich": "10.0.0.20:2283"
  },
  "dns": {
    "enabled": true,
    "providers": [
      {
        "type": "adguard",
        "scope": "internal",
        "zone": "example.com",
        "edge_addr": "10.0.0.1",
        "endpoint": "http://10.0.0.53:3000",
        "username": "crenel",
        "password_env": "ADGUARD_PASSWORD"
      },
      {
        "type": "cloudflare",
        "scope": "public",
        "zone": "example.com",
        "apply_mode": "surgical",
        "edge_addr": "203.0.113.9",
        "api_token_env": "CF_API_TOKEN"
      }
    ]
  }
}
```

- `endpoint` is the AdGuard Home control API base URL, authenticated with the
  Basic-auth credentials on `username`/`password_env` — the password comes from an
  env var, never the file.
- Both providers share `zone: example.com`, but each writes a different kind of
  record from a different vantage: AdGuard rewrites the name for internal
  resolvers, Cloudflare answers it for everyone else.
- Add a second AdGuard provider entry (with its own `instance` label, e.g.
  `"instance": "vps"`) if you run a second internal resolver — say, one for a VPN
  tunnel — that needs the same rewrite from a different vantage point.

## Walkthrough

```bash
export ADGUARD_PASSWORD=...
export CF_API_TOKEN=...

crenel status -config settings.json

# The Cloudflare provider is scope "public", so this creates a public record —
# the same no-auth-by-accident guardrail from the Caddy+Authelia recipe applies.
# immich brings its own authentication, so there's no need for a crenel-managed
# forward-auth gate in front of it — --auth none says that on purpose. For an
# app that doesn't handle its own auth, attach an auth_policies entry instead
# (see the Caddy+Authelia recipe):
crenel expose immich --auth none -config settings.json
# shows the planned change: Caddy route + AdGuard internal rewrite + Cloudflare
# public A record → confirm with 'y'

crenel status -config settings.json
```

`immich.example.com` now resolves two different ways depending on who's asking:
AdGuard hands LAN/VPN clients straight to `10.0.0.1`, Cloudflare hands the public
internet to `203.0.113.9`, and both go through the same Caddy edge and route.

If someone later hand-edits either resolver — flips the AdGuard rewrite, or
touches the Cloudflare record outside crenel — `crenel drift` catches the
disagreement between the live state and what you declared:

```bash
crenel drift -config settings.json   # exits non-zero if either side has drifted
crenel reconcile -config settings.json  # converges both back onto the exposed set
```

To take it down, one command removes the Caddy route, the AdGuard rewrite, and the
Cloudflare record together:

```bash
crenel unexpose immich -config settings.json
```
