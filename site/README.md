# crenel.sh: the landing page

A small static site: [`index.html`](index.html) (self-contained — no JS, no build
step; brand tokens inlined from `docs/brand/crenel-tokens.css`, banner byte-identical
to the README art) plus the favicon assets it references: `favicon.ico`,
`favicon-32.png`, and `apple-touch-icon.png`.

## Deploy: Cloudflare Pages (direct upload)

`crenel.sh` (and `www.crenel.sh`) is served by the Cloudflare **Pages** project
`crenel` (`crenel.pages.dev`). It is a **direct-upload** project — it is **not**
connected to a git repo, so **pushing to git does NOT deploy the site**. A deploy
only happens when someone uploads the `site/` directory with Wrangler:

```sh
# from the repo root — publishes site/ to production (crenel.sh):
npx wrangler pages deploy site --project-name=crenel --branch=main
```

`--branch=main` matches the project's production branch, so it publishes to
production. Any other `--branch` value creates a preview deployment instead.

**Auth** (either):

- `export CLOUDFLARE_API_TOKEN=…` — a token scoped `Account · Cloudflare Pages ·
  Edit`; also `export CLOUDFLARE_ACCOUNT_ID=<account-id>` if Wrangler asks for it, or
- `npx wrangler login` (interactive browser auth).

Notes:

- **The repo is the source of truth, not the deployment.** Because Pages is
  direct-upload, git and the live site can drift — always deploy from a clean
  checkout so what ships matches what's committed. Never edit a deployment by hand.
- **Get changes into `site/` first**, then deploy. Editing `index.html` or the
  favicon assets and committing does nothing on its own until the Wrangler command
  above runs.
- `www.crenel.sh` and any secondary domains resolve to this same project; `crenel.sh`
  is the single canonical domain (site, email, install).
- Update cadence: the page changes when the tagline / install / links change, i.e.
  rarely. It ships from this repo so page and product stay in one history.
