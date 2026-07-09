# Recording the README demo (asciinema → GIF)

> **Recorded 2026-07-09** via a scripted driver rather than live typing: a bash
> script type-animates each command (randomized 30–140 ms per-char delays, a
> "thinking" pause before flags) and executes the real command over
> `ssh -tt <sandbox> "cd ~/crenel-demo/bundle && docker compose exec keep …"`,
> answering the `Apply this change? [y/N]` prompts with a delayed `y`. Recorded
> with `asciinema rec --window-size 100x30 -c ./driver.sh` — a realistic
> terminal — against the **adaptive HUD** (recorded from a merge of `fix/hud-height-budget` + `docs/bundle-service-keep`; requires the adaptive-HUD
> changes / v0.4.3+), which detects the pty size via ioctl end-to-end through
> `ssh -tt` → `docker compose exec` and renders the compact crowned wall +
> scale-1 wordmark that fit on one screen (no `-width`/`-height` flags passed —
> the auto-detection is the point). The driver still clears the screen
> (`\033[2J\033[H`) before each `status --hud` beat so the crown holds at the
> top of an empty screen, and the recording is
> rendered with `agg --theme monokai --font-size 16 --font-family Menlo` (agg's
> default font mangles the block-element glyphs). The committed
> `docs/brand/crenel-demo.cast` is the source of truth — re-record by re-running
> such a driver against a fresh bundle (clear any stale
> `/etc/crenel/settings.json.lock` if a prior take was killed), then re-render
> the GIF and visually inspect extracted frames before committing.

The README has a `TODO(demo)` placeholder above the static HUD SVG. Replace it
with a ~20-second recording of the core loop, made from the bundle (no real
infrastructure touched).

## One-time setup

```bash
brew install asciinema agg   # agg converts .cast → .gif
cd bundle && docker compose up -d && cd ..
```

## The take (rehearse once, then record)

```bash
asciinema rec docs/brand/crenel-demo.cast --cols 100 --rows 28
# inside the recording, unhurried, ~4s pauses between commands:
docker compose -f bundle/docker-compose.yml exec keep crenel status --hud
docker compose -f bundle/docker-compose.yml exec keep crenel expose demo --auth none
docker compose -f bundle/docker-compose.yml exec keep crenel status --hud
docker compose -f bundle/docker-compose.yml exec keep crenel drift
docker compose -f bundle/docker-compose.yml exec keep crenel unexpose demo
exit
```

Beats that must be visible: the default-deny wall first, the loud
about-to-go-public preview + read-back ✓ on expose, the HUD gaining the host,
drift saying clean, unexpose restoring the wall.

## Convert and wire in

```bash
agg --theme monokai --font-size 16 docs/brand/crenel-demo.cast docs/brand/crenel-demo.gif
```

Then in `README.md`, replace the `crenel-status-hud.svg` image + TODO comment
with the GIF (keep width 760). Commit the .cast alongside the .gif so it can be
re-rendered.
