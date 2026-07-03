package ui

import (
	"fmt"
	"strings"
)

// SVG rendering of the wordmark and the status HUD. These produce the static
// brand assets in docs/brand/ (the README art + variants, and the read-only
// dashboard mock). Letters come from the SAME glyph grid as the terminal
// wordmark; the crenellated CROWN is drawn as crisp vector geometry (a real
// square-tooth battlement) so the SVG can be sharper/fancier than the ANSI grid.
// Regenerate with:
//
//	CRENEL_GEN_ASSETS=1 go test ./internal/ui/ -run TestGenerateAssets

// Brand palette (also documented in BRANDING.md). The semantic trio matches the
// ANSI truecolor constants used for the terminal.
const (
	svgBG    = "#0C0D12" // near-black background
	svgPanel = "#111320" // panel fill, a touch lighter than the bg
	svgGreen = "#00FF66" // safe / private / verified
	svgAmber = "#FFB000" // about to go public / drift
	svgRed   = "#FF3B30" // fail-open / unexpectedly exposed
	svgDim   = "#6A6F7A" // labels, rules, neutral chrome
	svgText  = "#C8CDD6" // neutral value text / monochrome ink on dark
	svgFont  = "'SF Mono','Geist Mono','JetBrains Mono',ui-monospace,monospace"

	// Light-theme tokens (for the light wordmark variants, README on a light page).
	// The radium green (#00FF66) is too bright to read on near-white, so the light
	// crown uses a deeper verified-green; the letters become ink (the dark bg color,
	// reused) so the mark stays one identity across both surfaces.
	svgLightBG    = "#F5F6F8" // soft off-white canvas
	svgInk        = "#0C0D12" // letter body on light (= the dark canvas, reused as ink)
	svgGreenDeep  = "#00A34D" // deeper "verified" green — legible on light
	svgDimOnLight = "#5B616B" // tagline/chrome on light
)

// --- wordmark geometry ---------------------------------------------------------
//
// The battlement crown is its own crisp vector module, intentionally NOT tied to
// the letter spacing: a fine, regular row of square merlons standing on a solid
// parapet, with the negative-space gaps between them being the crenels — the
// deliberate openings in the default-deny wall. Each crenel gap also notches a
// shallow embrasure into the parapet, so the wall reads as "wall with openings."

const (
	wmCell     = 20 // letter cell (matches the glyph grid)
	wmPad      = 48 // canvas padding
	wmMerlonN  = 9  // merlon (tooth) count — odd, so a tooth centers the mark
	wmTooth    = 48 // merlon width
	wmGap      = 36 // crenel gap width
	wmMerlonH  = 44 // merlon height (above the parapet)
	wmParapetH = 16 // solid parapet height
	wmEmbrasue = 8  // embrasure notch depth/half-width cue cut into the parapet
	wmReveal   = 18 // breathing gap between crown and letters
)

// wordmarkTagline is the brand line set beneath the mark in every variant. Locked
// 2026-06-29: the period after "Verified" is intentional — the brand beat. At
// font-size 15 / letter-spacing 3 it fits the 796-wide canvas with margin.
const wordmarkTagline = "Every edge in atomic agreement. Verified."

// letterGridRows returns just the five CRENEL letter rows (the crown rows 0–1 of
// the shared grid are replaced by the vector battlement in SVG).
func letterGridRows() []string { return WordmarkRows()[2:] }

// glyphCols is the letter-grid width in cells (35 for "C R E N E L").
func glyphCols() int { return len([]rune(WordmarkRows()[0])) }

// runRects walks a row of block/space runes and calls emit(startCol, widthCols)
// for each run of filled cells — the shared run-length core.
func runRects(row string, emit func(start, n int)) {
	runes := []rune(row)
	x := 0
	for x < len(runes) {
		if runes[x] != block {
			x++
			continue
		}
		s := x
		for x < len(runes) && runes[x] == block {
			x++
		}
		emit(s, x-s)
	}
}

// letterFillRects renders the five letter rows as solid run-length-merged rects.
func letterFillRects(ox, oy, cs int, fill string) string {
	var b strings.Builder
	for r, row := range letterGridRows() {
		runRects(row, func(s, n int) {
			fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n",
				ox+s*cs, oy+r*cs, n*cs, cs, fill)
		})
	}
	return b.String()
}

// crownWidth is the pixel span of the vector battlement.
func crownWidth() int { return wmMerlonN*wmTooth + (wmMerlonN-1)*wmGap } // 720

// crownMerlons draws the crisp square-tooth battlement: a solid parapet with
// merlons rising from it and an embrasure notch cut into the parapet under each
// crenel gap. x0 is the crown's left edge, topY its top.
func crownMerlons(x0, topY int, fill, bg string) string {
	var b strings.Builder
	parapetY := topY + wmMerlonH
	// Solid parapet wall.
	fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n",
		x0, parapetY, crownWidth(), wmParapetH, fill)
	// Merlons (teeth).
	for i := 0; i < wmMerlonN; i++ {
		tx := x0 + i*(wmTooth+wmGap)
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n",
			tx, topY, wmTooth, wmMerlonH, fill)
	}
	// Embrasure notches: a slot cut into the top of the parapet under each crenel
	// gap — the controlled openings in the wall.
	for i := 0; i < wmMerlonN-1; i++ {
		cx := x0 + i*(wmTooth+wmGap) + wmTooth + wmGap/2
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n",
			cx-wmEmbrasue/2, parapetY, wmEmbrasue, wmEmbrasue, bg)
	}
	return b.String()
}

// scanlines overlays thin background-colored stripes over [x,y,w,h] — a CRT
// raster cutting across the fill (used by the status-HUD's compact wordmark).
func scanlines(x, y, w, h int, bg string) string {
	var b strings.Builder
	for yy := y + 3; yy < y+h; yy += 5 {
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="2" fill="%s"/>`+"\n", x, yy, w, bg)
	}
	return b.String()
}

// WordmarkSVG / WordmarkSVGLight render the canonical mark — refined
// square-tooth merlons + embrasures, semantic-green crown — on the dark or
// light surface.
func WordmarkSVG() string      { return wordmarkSVG(false) }
func WordmarkSVGLight() string { return wordmarkSVG(true) }

func wordmarkSVG(light bool) string {
	cs := wmCell
	pad := wmPad
	lettersW := glyphCols() * cs // 700
	crownX0 := pad - (crownWidth()-lettersW)/2
	topY := pad
	crownH := wmMerlonH + wmParapetH // 60
	lettersTop := topY + crownH + wmReveal
	lettersBottom := lettersTop + len(letterGridRows())*cs
	taglineY := lettersBottom + 34
	w := lettersW + 2*pad // 796
	h := taglineY + 24

	// Resolve the surface colors.
	bg, tagline := svgBG, svgDim
	if light {
		bg, tagline = svgLightBG, svgDimOnLight
	}
	green := svgGreen
	if light {
		green = svgGreenDeep
	}
	crown := green
	letters := svgGreen
	if light {
		letters = svgInk
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="CRENEL">`+"\n", w, h, w, h)
	fmt.Fprintf(&b, `  <rect width="%d" height="%d" fill="%s"/>`+"\n", w, h, bg)
	b.WriteString(crownMerlons(crownX0, topY, crown, bg))
	b.WriteString(letterFillRects(pad, lettersTop, cs, letters))
	fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="15" letter-spacing="3" fill="%s">%s</text>`+"\n",
		pad+2, taglineY, svgFont, tagline, escapeXML(wordmarkTagline))
	b.WriteString("</svg>\n")
	return b.String()
}

// gridMarkSolid draws a compact SOLID wordmark (cell-merlon crown + letters) in
// one fill — used as the small mark inside the status-HUD SVG.
func gridMarkSolid(ox, oy, cs int, fill string) string {
	cols := glyphCols()
	var b strings.Builder
	rect := func(c, r, n int) {
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n",
			ox+c*cs, oy+r*cs, n*cs, cs, fill)
	}
	// Crown: two tooth rows (period-5 merlons) + a solid parapet row.
	for _, rr := range []int{0, 1} {
		c := 0
		for c < cols {
			if c%5 < 3 {
				s := c
				for c < cols && c%5 < 3 {
					c++
				}
				rect(s, rr, c-s)
			} else {
				c++
			}
		}
	}
	rect(0, 2, cols) // parapet
	for r, row := range letterGridRows() {
		runRects(row, func(s, n int) { rect(s, 3+r, n) })
	}
	return b.String()
}

// --- status HUD SVG ------------------------------------------------------------

// hudFieldSVG is one label/value row in the HUD SVG, with the value's semantic
// color resolved.
type hudFieldSVG struct {
	label string
	value string
	fill  string
}

// hudFieldsSVG maps a HUDModel onto colored SVG rows using the SAME semantic
// rules as the terminal renderer.
func hudFieldsSVG(m HUDModel) []hudFieldSVG {
	pubFill := svgGreen
	if m.Public > 0 {
		pubFill = svgAmber
	}
	deny, denyFill := "ENFORCED", svgGreen
	if m.DenyUnknown {
		deny, denyFill = "UNKNOWN", svgAmber
	} else if !m.DenyEnforced {
		deny, denyFill = "FAIL-OPEN", svgRed
	}
	drift, driftFill := "none", svgGreen
	if m.Drift > 0 {
		drift, driftFill = fmt.Sprintf("%d item%s", m.Drift, plural(m.Drift)), svgAmber
	} else if m.Drift < 0 {
		drift, driftFill = "unknown", svgDim
	}
	edges := make([]string, len(m.Edges))
	for i, e := range m.Edges {
		edges[i] = e.Name + "·" + e.Driver
	}
	dns := "(none managed)"
	if len(m.DNSScopes) > 0 {
		dns = strings.Join(m.DNSScopes, " + ")
		if len(m.DNSScopes) > 1 {
			dns = "split-horizon  " + dns
		}
	}
	edgesFill := svgGreen
	if len(m.Edges) == 0 {
		edgesFill = svgDim
	}
	dnsFill := svgGreen
	if len(m.DNSScopes) == 0 {
		dnsFill = svgDim
	}
	return []hudFieldSVG{
		{"EXPOSED", fmt.Sprintf("%d host%s   (%d public)", m.Exposed, plural(m.Exposed), m.Public), pubFill},
		{"DEFAULT-DENY", deny, denyFill},
		{"DRIFT", drift, driftFill},
		{"EDGES", strings.Join(edges, "   "), edgesFill},
		{"DNS", dns, dnsFill},
		{"LAST APPLY", strings.ToLower(m.LastApply), svgDim},
	}
}

// cornerBrackets draws four green L-shaped crops at the corners of a rect — the
// "terminal frame" accent that replaces a generic full border.
func cornerBrackets(x, y, w, h, n, t int, fill string) string {
	var b strings.Builder
	seg := func(rx, ry, rw, rh int) {
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`+"\n", rx, ry, rw, rh, fill)
	}
	corners := [][2]int{{x, y}, {x + w, y}, {x, y + h}, {x + w, y + h}}
	for i, c := range corners {
		hx, hy := c[0], c[1]
		dx, dy := 1, 1 // direction the arms run
		if i == 1 || i == 3 {
			dx = -1
		}
		if i == 2 || i == 3 {
			dy = -1
		}
		ax := hx
		if dx < 0 {
			ax = hx - n
		}
		ay := hy
		if dy < 0 {
			ay = hy - t
		}
		seg(ax, ay, n, t) // horizontal arm
		ax = hx
		if dx < 0 {
			ax = hx - t
		}
		ay = hy
		if dy < 0 {
			ay = hy - n
		}
		seg(ax, ay, t, n) // vertical arm
	}
	return b.String()
}

// StatusHUDSVG renders the read-only status HUD: a framed "CORE MATRIX" panel
// carrying the real domain fields, a left LED rail of semantic status dots, green
// corner crops, and a semantic legend. (The S5 read-only-dashboard mock.)
func StatusHUDSVG(m HUDModel) string {
	const (
		w, h = 960, 560
		mx   = 56
	)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="crenel status HUD">`+"\n", w, h, w, h)
	fmt.Fprintf(&b, `  <rect width="%d" height="%d" fill="%s"/>`+"\n", w, h, svgBG)

	// Compact wordmark, top-left, with a faint scanline raster over it.
	b.WriteString(gridMarkSolid(mx, 30, 9, svgGreen))
	b.WriteString(scanlines(mx, 30, glyphCols()*9, 72, svgBG))
	fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="12" letter-spacing="2" fill="%s">what's exposed right now</text>`+"\n",
		mx+2, 124, svgFont, svgDim)
	fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="12" letter-spacing="3" text-anchor="end" fill="%s">// LIVE · READ-ONLY</text>`+"\n",
		w-mx, 52, svgFont, svgGreen)

	// Panel.
	px, py := mx, 176
	pw, ph := w-mx*2, 320
	fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="%d" height="%d" fill="%s" stroke="%s" stroke-width="0.5"/>`+"\n", px, py, pw, ph, svgPanel, svgDim)
	b.WriteString(cornerBrackets(px, py, pw, ph, 26, 2, svgGreen))

	// Header tab.
	fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="4" height="16" fill="%s"/>`+"\n", px+24, py+24, svgGreen)
	fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="14" letter-spacing="3" fill="%s">CORE MATRIX // EXPOSURE STATE</text>`+"\n",
		px+38, py+37, svgFont, svgGreen)
	fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="0.5"/>`+"\n", px+24, py+52, px+pw-24, py+52, svgDim)

	// Fields with a left LED rail (dot per row, connected by a faint rail).
	fields := hudFieldsSVG(m)
	railX := px + 34
	row0, step := py+92, 36
	fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="0.5"/>`+"\n",
		railX, row0-5, railX, row0+(len(fields)-1)*step-5, svgDim)
	for i, f := range fields {
		ry := row0 + i*step
		fmt.Fprintf(&b, `  <circle cx="%d" cy="%d" r="4" fill="%s"/>`+"\n", railX, ry-5, f.fill)
		fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="15" letter-spacing="2" fill="%s">%s</text>`+"\n",
			px+56, ry, svgFont, svgDim, f.label)
		fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="15" font-weight="600" fill="%s">%s</text>`+"\n",
			px+260, ry, svgFont, f.fill, escapeXML(f.value))
	}

	// Legend strip — the three semantic swatches, documenting the color rule.
	ly := py + ph + 34
	legend := []struct{ fill, text string }{
		{svgGreen, "safe / private / verified"},
		{svgAmber, "about to go public / drift"},
		{svgRed, "fail-open / exposed"},
	}
	lx := px
	for _, item := range legend {
		fmt.Fprintf(&b, `  <rect x="%d" y="%d" width="14" height="14" fill="%s"/>`+"\n", lx, ly-12, item.fill)
		fmt.Fprintf(&b, `  <text x="%d" y="%d" font-family="%s" font-size="13" fill="%s">%s</text>`+"\n", lx+22, ly, svgFont, svgText, item.text)
		lx += 270
	}
	b.WriteString("</svg>\n")
	return b.String()
}

// escapeXML escapes the handful of characters that matter inside SVG text.
func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
