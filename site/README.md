# crenel.sh: the landing page

One self-contained static file: [`index.html`](index.html). No JS, no external
assets, no build step. The brand tokens are inlined from
`docs/brand/crenel-tokens.css` and the banner is the canonical battlement block
(byte-identical to the README art). Total weight ≈ 10 KB.

## Deploy: mirrored across both edges

The page is served **identically from the home edge and the VPS edge**, so it
stays up if either is down and is always served from the nearest edge. Because
it is one file with no state, "mirroring" is just copying it to both:

```sh
# from the repo root: push the same bytes to both edges
rsync -az site/index.html home-edge:/srv/crenel.sh/index.html
rsync -az site/index.html vps-edge:/srv/crenel.sh/index.html
```

Each edge serves it with a plain static site block (example, Caddyfile):

```caddyfile
crenel.sh {
    root * /srv/crenel.sh
    file_server
    header Cache-Control "public, max-age=3600"
    encode zstd gzip
}
```

Notes:

- **Expose it with Crenel**, naturally: `crenel expose crenel-site --auth none`
  (a public page with no auth is exactly the loud, deliberate `--auth none`
  case). Public DNS for `crenel.sh` points at the public edge; the page needs
  no split-horizon handling.
- Keep the two copies in lockstep by always deploying from the repo (the rsync
  pair above, or a 3-line deploy script). Never hand-edit on an edge.
- `www.crenel.sh` → redirect to apex; any secondary domains 301 here too
  (crenel.sh is the single canonical domain: site, email, install).
- Update cadence: the page changes when the tagline/install/links change,
  i.e. rarely. It ships from this repo so page and product stay in one history.
