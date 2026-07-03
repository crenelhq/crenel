package main

import "fmt"

// indexHTML is the dashboard shell. It embeds the HUD SVG and re-fetches it on an
// interval (vanilla JS, no dependencies). The single %d is the refresh interval in
// milliseconds. Colors mirror the brand palette (internal/ui svgBG). The page is
// deliberately read-only: it issues only GET /hud.svg, and the server rejects any
// non-GET request anyway.
const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>crenel — what's exposed right now</title>
<style>
  html,body { margin:0; background:#0C0D12; color:#C8CDD6;
    font-family:'SF Mono','Geist Mono','JetBrains Mono',ui-monospace,monospace; }
  .wrap { max-width:1000px; margin:0 auto; padding:24px 16px; }
  img#hud { width:100%%; height:auto; display:block; border-radius:4px; }
  .foot { color:#6A6F7A; font-size:12px; margin-top:14px; line-height:1.6; }
  .foot code { color:#00FF66; }
  .ro { color:#FFB000; }
</style>
</head>
<body>
  <div class="wrap">
    <img id="hud" src="/hud.svg" alt="crenel status HUD">
    <div class="foot">
      <span class="ro">read-only dashboard</span> — live answer to "what's exposed right now".
      Writes stay on the CLI: <code>crenel expose &lt;svc&gt; --auth none</code>.<br>
      Auto-refreshing from live edge state. The web view cannot mutate the edge.
    </div>
  </div>
<script>
  var refreshMs = %d;
  function tick() {
    var img = document.getElementById('hud');
    var next = new Image();
    next.onload = function(){ img.src = next.src; };
    next.src = '/hud.svg?_=' + Date.now();
  }
  if (refreshMs > 0) { setInterval(tick, refreshMs); }
</script>
</body>
</html>
`

// unreachableSVG renders a degraded HUD when the edge cannot be read (e.g. its
// admin API is still starting). It matches the HUD canvas so the page does not
// reflow, and is honest: it shows a neutral/red "edge unreachable" state, never a
// green ENFORCED it cannot certify.
func unreachableSVG(err error) string {
	msg := err.Error()
	if len(msg) > 90 {
		msg = msg[:90] + "…"
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 560" width="960" height="560" role="img" aria-label="edge unreachable">
  <rect width="960" height="560" fill="#0C0D12"/>
  <text x="56" y="260" font-family="%s" font-size="22" letter-spacing="2" fill="#FF3B30">EDGE UNREACHABLE</text>
  <text x="56" y="296" font-family="%s" font-size="14" fill="#6A6F7A">crenel could not read live edge state — retrying…</text>
  <text x="56" y="324" font-family="%s" font-size="13" fill="#6A6F7A">%s</text>
</svg>
`, fontFamily(), fontFamily(), fontFamily(), escapeXMLLocal(msg))
}

// fontFamily returns the brand monospace stack (kept in sync with internal/ui).
func fontFamily() string {
	return "'SF Mono','Geist Mono','JetBrains Mono',ui-monospace,monospace"
}

// escapeXMLLocal escapes the characters that matter inside SVG text (the ui
// package's escaper is unexported, so the dashboard keeps a tiny local copy for
// the degraded path only — the real HUD escapes its own values).
func escapeXMLLocal(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '&':
			out = append(out, []rune("&amp;")...)
		case '<':
			out = append(out, []rune("&lt;")...)
		case '>':
			out = append(out, []rune("&gt;")...)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
