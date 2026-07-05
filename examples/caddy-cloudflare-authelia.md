# Recipe: Caddy + Cloudflare + Authelia (the privacy stack)

A common self-hosted shape: **Caddy** as the edge reverse proxy, **Cloudflare** for
public DNS, and **Authelia** doing forward-auth in front of anything that shouldn't
be open to the whole internet. This walks through exposing one new service on that
stack with crenel, from config to a verified public host.

All hostnames below are examples (`photos.example`) — swap in your own zone.

## The shape

- Caddy is the only edge; it terminates TLS and routes by hostname.
- Cloudflare is authoritative for public DNS, in **surgical** (record-level) mode —
  crenel only ever touches the one record it created, so it's safe to point at a
  zone that already has other records in it.
- Authelia sits behind a `forward_auth` gate Caddy calls before proxying to the
  backend. crenel doesn't run or configure Authelia itself — it wires the
  `forward_auth` reference into the route and lets Authelia do the actual auth.

## Settings

```json
{
  "edge_driver": "caddy",
  "admin_url": "http://127.0.0.1:2019",
  "zone": "example.com",
  "granular_apply": true,
  "origins": {
    "photos": "10.0.0.6:2342"
  },
  "auth_policies": {
    "authelia": {
      "caddy_import": "authelia",
      "caddy_forward_auth": "authelia:9091",
      "caddy_forward_auth_verify_uri": "/api/verify?rd=https://auth.example.com",
      "caddy_forward_auth_copy_headers": ["Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email"]
    }
  },
  "dns": {
    "enabled": true,
    "providers": [
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

A few things worth pointing out in that file:

- `caddy_forward_auth` is the authorizer endpoint Caddy's own `forward_auth`
  directive would use — crenel expands it to the exact
  `reverse_proxy` + `handle_response` shape Caddy compiles that directive to. It
  doesn't invent a new mechanism; it emits what Caddy already accepts.
- `apply_mode: surgical` means Cloudflare is managed one record at a time via the
  native REST API. crenel marks the record it creates (`managed-by:crenel`) and
  refuses to touch anything it doesn't own, so a shared zone with other DNS records
  in it is safe.
- The Cloudflare API token is read from `CF_API_TOKEN` (`api_token_env`), never
  written into the config file.

## Walkthrough

```bash
export CF_API_TOKEN=...   # scoped to the zone, DNS edit only

# See what's exposed today (nothing, on a fresh setup):
crenel status -config settings.json

# Show the exact change first — no auth gate, so this gets refused:
crenel expose photos -config settings.json
# refusing to expose photos PUBLIC with no auth — pass --auth <policy> to
# protect it, or --auth none to publish it unprotected on purpose

# Attach the forward-auth policy instead:
crenel expose photos --auth authelia -config settings.json
# shows the planned change: Caddy route + forward_auth gate + Cloudflare A record
# → confirm with 'y', or pass -yes to skip the prompt (the auth refusal above is
#   never skipped by -yes)

# Verify it landed — reads the live edge and DNS, not a cached plan:
crenel status -config settings.json
crenel audit -config settings.json
```

`photos.example.com` now resolves via Cloudflare to the Caddy edge, Caddy routes it
to `10.0.0.6:2342` only after Authelia says yes, and `crenel drift` will flag it the
moment either side (the Caddy route or the DNS record) stops matching what you
declared.

To take it back down:

```bash
crenel unexpose photos -config settings.json
```

That removes both the Caddy route and the Cloudflare record in one all-or-nothing
step, same as the expose.
