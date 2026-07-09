package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// The brand banner is crenel's hero surface: a crenellated battlement WALL whose
// crenel gaps are exposed hosts in semantic colour (green = verified/private, amber =
// about to go public, red = fail-open) standing over the CRENEL wordmark — the pagga
// half-block logotype with the distinctive ∏-shaped 'n', rendered with a bright→deep
// tube bevel so it reads dimensional WITHOUT a drop-shadow (depth from character
// texture, not extrusion). It is the SAME mark the binary prints for `crenel banner`
// (with crenel.sh demo hosts) and atop `status --hud` (with the LIVE exposed hosts),
// so the terminal output and the brand stills are one source of truth. See docs/brand/BRANDING.md.

// BannerWidth is the default full width used when no terminal width is known —
// sized to the hero wall's natural column span (the demo-host battlement is 121
// cols wide) so the standalone `crenel banner` prints the FULL approved mark by
// default. Genuinely narrow terminals (an explicit COLUMNS/-width below this)
// fall through to writeWall's scaled compact path rather than wrapping.
const BannerWidth = 121

// Texture-tier greens for the wordmark bevel and the wall's stone courses. These are
// PRESENTATION depth only — NOT semantic. The semantic palette (green/amber/red, in
// style.go) is reserved for host state; these greens carve dimension into the letters
// and wall. ansiMint is the lit rim; ansiG2/G3 grade inward to the tube core; G4/G5
// are the deepening stone courses beneath the parapet.
const (
	ansiMint  = "\x1b[38;2;170;255;200m" // #AAFFC8  bevel highlight rim
	ansiG2    = "\x1b[38;2;0;224;96m"    // #00E060  bevel near-highlight
	ansiG3    = "\x1b[38;2;0;176;82m"    // #00B052  bevel mid / first stone course
	ansiG4    = "\x1b[38;2;0;128;64m"    // #008040  deeper stone course / dim separators
	ansiG5    = "\x1b[38;2;0;92;48m"     // #005C30  footing course (deepest)
	ansiValue = "\x1b[38;2;200;205;214m" // #C8CDD6  neutral value text (version, counts)
)

// WallHost is one exposed host shown in a crenel gap, with the semantic role that
// colours it (Safe = green/verified, Warn = amber/about-to-go-public, Fail = red/
// fail-open). The renderer appends a state glyph derived from the role.
type WallHost struct {
	Name string
	Role Sem
}

// demoWallHosts are the crenel.sh placeholder hosts for `crenel banner` standalone —
// crenel's own domain, never real infra. The live path (status --hud) uses the real
// exposed hosts via HUDModel.Hosts instead. These reproduce the approved brand still.
var demoWallHosts = []WallHost{
	{"app.crenel.sh", Safe},
	{"grafana.crenel.sh", Warn},
	{"registry.crenel.sh", Fail},
}

// roleSuffix is the at-a-glance state tag appended to a host name in its gap.
func roleSuffix(role Sem) string {
	switch role {
	case Warn:
		return " ▸ public"
	case Fail:
		return " ✕ open"
	default:
		return " ✓"
	}
}

// roleGlyph is the bare state glyph (no label) shown centred in a compact crenel
// notch, coloured by role — so a narrow-terminal gap still reads as an opened host.
func roleGlyph(role Sem) string {
	switch role {
	case Warn:
		return "▸"
	case Fail:
		return "✕"
	default:
		return "✓"
	}
}

// run is one colored span on a logo row ("" color = plain, for the NO_COLOR path).
type run struct {
	color string
	text  string
}

// emitRow writes a run-row centered in cols, applying color only when enabled.
func (st Style) emitRow(w io.Writer, rows []run, cols int) {
	width := 0
	for _, r := range rows {
		width += len([]rune(r.text))
	}
	if pad := (cols - width) / 2; pad > 0 {
		fmt.Fprint(w, strings.Repeat(" ", pad))
	}
	for _, r := range rows {
		if st.Color && r.color != "" {
			fmt.Fprint(w, r.color+r.text+ansiReset)
		} else {
			fmt.Fprint(w, r.text)
		}
	}
	fmt.Fprintln(w)
}

// ── the CRENEL wordmark, beveled ────────────────────────────────────────────────
//
// wallWord is the pagga CRENEL in half-block glyphs with OPEN counters (the spacing
// is unlit). The N is █▀█/█ █/▀ ▀ — the ∏-shaped 'n'. The renderer lifts this into a
// pixel grid, scales it, shades each pixel by its distance to the edge (a symmetric
// bright-rim→deep-core tube bevel — depth, no shadow), and pairs rows back into
// half-block cells. Deterministic: the same bytes every call.
var wallWord = []string{
	"█▀▀ █▀▄ █▀▀ █▀█ █▀▀ █  ",
	"█   █▀▄ █▀▀ █ █ █▀▀ █  ",
	"▀▀▀ ▀ ▀ ▀▀▀ ▀ ▀ ▀▀▀ ▀▀▀",
}

const wallScale = 5

// tierColor maps an edge-distance ring (1 = outer rim … 4 = core) to its bevel tone.
func tierColor(t int) string {
	switch t {
	case 1:
		return ansiMint
	case 2:
		return ansiG2
	case 3:
		return ansiGreen
	case 4:
		return ansiG3
	}
	return ""
}

// wordmarkBevelRows renders the beveled CRENEL wordmark at the approved scale.
func wordmarkBevelRows() [][]run { return wordmarkBevelRowsScale(wallScale) }

// wordmarkWidth is the rendered column span of the wordmark at the given scale
// (the source word's rune width × scale). Used to fit it to a narrow terminal.
func wordmarkWidth(scale int) int {
	w := 0
	for _, s := range wallWord {
		if n := len([]rune(s)); n > w {
			w = n
		}
	}
	return w * scale
}

// wordmarkScaleFor picks the largest scale (≤ the approved wallScale) whose
// wordmark fits in cols, so a narrow terminal shrinks the mark instead of
// wrapping it. Floors at 1 (the half-block word is 23 cols even then).
func wordmarkScaleFor(cols int) int {
	for s := wallScale; s > 1; s-- {
		if wordmarkWidth(s) <= cols {
			return s
		}
	}
	return 1
}

// hudRowOverhead is every `status --hud` row that is not the wordmark: the
// battlement teeth, the parapet + three stone courses, the two blank
// separators, the CORE MATRIX panel (6 fields + frame), its legend line — AND
// the rows that inevitably follow the banner on the same screen: the blank
// after it, a single-edge detail listing (header/deny/durability/exposed +
// one host), and the shell prompt + typed command. Forgetting the follow-on
// rows is exactly how the crown scrolled off in live testing: the banner fit,
// the command's full output did not.
const (
	hudDetailHeadroom = 9 // blank + minimal edge detail + prompt/command rows
	hudRowOverhead    = wallTeethH + 4 + 2 + 8 + 1 + hudDetailHeadroom
	// heroRowOverhead is the standalone `crenel banner` budget: teeth, courses,
	// blanks, the two footer lines, and the prompt — no panel, no detail listing.
	heroRowOverhead = wallTeethH + 4 + 2 + 2 + 2
)

// heightScaleFor picks the largest wordmark scale (≤ the approved wallScale)
// whose full surface (overhead + wordmark rows) fits in rows, so the battlement
// crown — the first thing the banner draws — is still on-screen when the
// command finishes printing, instead of scrolling off the top of a short
// terminal. rows <= 0 means "unknown" (piped output, tests, asset generation):
// no height constraint, natural size. Returns 0 when not even the scale-1
// wordmark fits: the wall then renders crown-only, no lettering — a stock
// 80x24 terminal keeps the castle and the panel on one screen.
func heightScaleFor(rows, overhead int) int {
	if rows <= 0 {
		return wallScale
	}
	for s := wallScale; s >= 1; s-- {
		if overhead+len(wallWord)*s <= rows {
			return s
		}
	}
	return 0
}

// wordmarkBevelRowsScale renders the beveled CRENEL wordmark as colored run-rows
// at an arbitrary scale. At wallScale it is byte-identical to the approved still
// (the R-bowl rim-wrap fix-up, whose pixel indices are scale-5-specific, applies
// only there); smaller scales drop it gracefully for the compact narrow render.
func wordmarkBevelRowsScale(scale int) [][]run {
	// Below scale 4 there is no room for the bevel: its ring gradient needs ≥4-px
	// strokes, and the ring-pairing below erodes thinner ones (broken stroke tops,
	// washed rims — the C's top read ▀▀▀ instead of █▀▀). The LETTERFORM is the
	// design; the bevel is texture. So small scales render the same pixel grid,
	// nearest-neighbour scaled, in flat brand green — the approved glyphs, just
	// smaller — and the graded bevel is reserved for scales with room for it.
	if scale <= 1 {
		out := make([][]run, len(wallWord))
		for i, s := range wallWord {
			t := 1 + i*4/len(wallWord) // same mint→deep rim-light ramp, 3 rows
			if t > 4 {
				t = 4
			}
			out[i] = []run{{tierColor(t), s}}
		}
		return out
	}
	const bevelMinScale = 4
	// to-pixels: 2 sub-pixel rows per source row (half-block encodes which half is lit).
	W := 0
	for _, s := range wallWord {
		if n := len([]rune(s)); n > W {
			W = n
		}
	}
	H := len(wallWord) * 2
	px := make([][]bool, H)
	for i := range px {
		px[i] = make([]bool, W)
	}
	for r, line := range wallWord {
		rl := []rune(line)
		for x := 0; x < W; x++ {
			ch := ' '
			if x < len(rl) {
				ch = rl[x]
			}
			if ch == '█' || ch == '▀' {
				px[2*r][x] = true
			}
			if ch == '█' || ch == '▄' {
				px[2*r+1][x] = true
			}
		}
	}
	// scale up (nearest-neighbour) so the strokes have room for a graded rim.
	sh, sw := H*scale, W*scale
	sg := make([][]bool, sh)
	for y := 0; y < sh; y++ {
		sg[y] = make([]bool, sw)
		for x := 0; x < sw; x++ {
			sg[y][x] = px[y/scale][x/scale]
		}
	}
	// Small-scale render: the approved letterform with a VERTICAL rim-light
	// gradient — mint at the letter tops grading to the deep bevel-mid at the
	// baseline, the same lit-from-above language as the full bevel and the wall's
	// stone courses. The tone is keyed to the output TERMINAL row (y/2), so both
	// sub-pixels of a cell always share one tone and the pairing below can never
	// erode a stroke — the failure mode that made per-pixel bevel rings unusable
	// under 4-px strokes.
	if scale < bevelMinScale {
		rows := sh / 2
		tier := make([][]int, sh)
		for y := 0; y < sh; y++ {
			tier[y] = make([]int, sw)
			// ramp the 4 bevel tones (mint → g2 → green → g3) down the cell rows.
			t := 1 + (y/2)*4/rows
			if t > 4 {
				t = 4
			}
			for x := 0; x < sw; x++ {
				if sg[y][x] {
					tier[y][x] = t
				}
			}
		}
		return pairTierRows(tier, sh, sw)
	}
	// edge distance: multi-source BFS from the background into the lit pixels, so each
	// lit pixel knows its ring index (1 = touches background … deeper = interior).
	const inf = 1 << 30
	type pt struct{ y, x int }
	dist := make([][]int, sh)
	var q []pt
	for y := 0; y < sh; y++ {
		dist[y] = make([]int, sw)
		for x := 0; x < sw; x++ {
			if sg[y][x] {
				dist[y][x] = inf
			} else {
				q = append(q, pt{y, x})
			}
		}
	}
	for head := 0; head < len(q); head++ {
		c := q[head]
		for _, d := range [4]pt{{1, 0}, {-1, 0}, {0, 1}, {0, -1}} {
			ny, nx := c.y+d.y, c.x+d.x
			if ny >= 0 && ny < sh && nx >= 0 && nx < sw && dist[ny][nx] == inf {
				dist[ny][nx] = dist[c.y][c.x] + 1
				q = append(q, pt{ny, nx})
			}
		}
	}
	// shade by ring (clamped to the 4-tone ramp: mint rim → g2 → green → g3 core).
	tier := make([][]int, sh)
	for y := 0; y < sh; y++ {
		tier[y] = make([]int, sw)
		for x := 0; x < sw; x++ {
			if sg[y][x] {
				ring := dist[y][x]
				if ring > 4 {
					ring = 4
				}
				tier[y][x] = ring
			}
		}
	}
	// R-bowl rim wrap: the R counter box's bottom rim lands on an odd pixel row, so the
	// `▀` pairing would drop its mint to background and the box reads unwrapped. Recolour
	// the bottom-inner ring to mint so that cell renders solid — wraps the box, leaving
	// the central black hole and every other letterform's open negative space intact.
	// The indices are scale-5 (approved-still) specific, so only apply them there.
	if scale == wallScale {
		for _, x := range []int{31, 32, 33} {
			tier[8][x] = 1
		}
	}
	return pairTierRows(tier, sh, sw)
}

// pairTierRows pairs sub-pixel tier rows back into half-block cells, merging
// same-tone runs. A cell with two differently-toned sub-pixels renders `▀` (top
// tone over a background lower half) — this is what keeps horizontal strokes
// thin and the interior counters OPEN in the beveled render; in the flat render
// every lit pixel shares one tone, so cells always merge cleanly.
func pairTierRows(tier [][]int, sh, sw int) [][]run {
	var out [][]run
	for ry := 0; ry < sh; ry += 2 {
		var rowRuns []run
		x := 0
		for x < sw {
			top := tier[ry][x]
			bot := 0
			if ry+1 < sh {
				bot = tier[ry+1][x]
			}
			t, g := cellTierGlyph(top, bot)
			var sb strings.Builder
			sb.WriteRune(g)
			// extend the run while the next cell has the same tone+glyph class
			for x+1 < sw {
				nt := tier[ry][x+1]
				nb := 0
				if ry+1 < sh {
					nb = tier[ry+1][x+1]
				}
				t2, g2 := cellTierGlyph(nt, nb)
				if t2 != t || g2 != g {
					break
				}
				sb.WriteRune(g2)
				x++
			}
			rowRuns = append(rowRuns, run{tierColor(t), sb.String()})
			x++
		}
		out = append(out, rowRuns)
	}
	return out
}

// cellTierGlyph collapses a top/bottom sub-pixel tone pair into one half-block cell:
// the glyph and the tone it is drawn in. Two lit-but-differing sub-pixels render the
// TOP tone as `▀` (lower half = background) — preserving the open negative space.
func cellTierGlyph(top, bot int) (tier int, glyph rune) {
	switch {
	case top != 0 && bot != 0:
		if top == bot {
			return top, '█'
		}
		return top, '▀'
	case top != 0:
		return top, '▀'
	case bot != 0:
		return bot, '▄'
	default:
		return 0, ' '
	}
}

// ── the battlement wall ─────────────────────────────────────────────────────────

const (
	wallMerlonW = 7 // merlon (tooth) width
	wallTeethH  = 3 // rows of teeth above the parapet (odd, so the host label on
	//                 row wallTeethH/2 sits in the VERTICAL CENTRE of its crenel —
	//                 one empty row above and below, a clean labelled notch)
	wallMaxGaps = 5 // most hosts shown as gaps (the panel carries the exact count)
	wallMaxName = 28
)

// writeWall renders the battlement (crenel gaps coloured by host role) over the
// beveled CRENEL wordmark, centered in cols. With footer it adds the status + legend
// lines (the standalone branding hero); the HUD omits them (its CORE MATRIX panel
// follows). With no hosts it draws a solid default-deny wall (empty crenels).
func (st Style) writeWall(w io.Writer, hosts []WallHost, cols int, footer bool) {
	// clean + cap the host list (truncate long names; the panel keeps the true count).
	var hs []WallHost
	for _, h := range hosts {
		name := h.Name
		if rs := []rune(name); len(rs) > wallMaxName {
			name = string(rs[:wallMaxName-1]) + "…"
		}
		hs = append(hs, WallHost{Name: name, Role: h.Role})
		if len(hs) >= wallMaxGaps {
			break
		}
	}

	// Short terminal: the full-scale surface would scroll its own crown off the top
	// before the command finished printing. Render the compact wall at the largest
	// scale the height admits instead. The compact path stacks host labels below the
	// wall, so those rows are charged against the budget too. Rows == 0
	// (unknown/piped/tests) keeps the natural full render. The hero banner (footer)
	// carries no panel or detail listing, so it gets the smaller budget.
	overhead := hudRowOverhead
	if footer {
		overhead = heroRowOverhead
	}
	if hScale := heightScaleFor(st.Rows, overhead); hScale < wallScale {
		stacked := 0
		if len(hs) > 0 {
			// blank + legend + one wall label per host, plus the one detail-listing
			// row per host that follows the panel (the headroom only budgets one).
			stacked = 2*len(hs) + 2
		}
		scale := heightScaleFor(st.Rows-stacked, overhead)
		if ws := wordmarkScaleFor(cols); ws < scale {
			scale = ws
		}
		st.writeWallCompact(w, hs, cols, footer, scale)
		return
	}

	word := wordmarkBevelRows()
	ww := 0
	for _, r := range word {
		n := 0
		for _, rn := range r {
			n += len([]rune(rn.text))
		}
		if n > ww {
			ww = n
		}
	}

	// host tokens ("● name <state>") and gap geometry.
	type token struct {
		runs []run
		n    int
	}
	emptyWall := len(hs) == 0
	displayGaps := len(hs)
	toks := make([]token, len(hs))
	maxtok := 0
	for i, h := range hs {
		text := "● " + h.Name + roleSuffix(h.Role)
		n := len([]rune(text))
		toks[i] = token{[]run{{h.Role.ansi(), text}}, n}
		if n > maxtok {
			maxtok = n
		}
	}
	if emptyWall {
		displayGaps = 3 // a crenellated solid wall: three empty crenels, no hosts
	}
	nm := displayGaps + 1
	var gap int
	if emptyWall {
		gap = (ww - nm*wallMerlonW) / displayGaps
		if gap < wallMerlonW {
			gap = wallMerlonW
		}
	} else {
		gap = maxtok + 2
	}
	wallW := nm*wallMerlonW + displayGaps*gap

	canvas := wallW
	if ww > canvas {
		canvas = ww
	}

	// Narrow terminal: the full labelled wall (canvas cols) would wrap and garble.
	// Render the scaled compact fallback instead. The wide path below is byte-faithful
	// to the approved mark and is reached whenever cols admits the full width (the
	// default BannerWidth does, so the standalone banner is unchanged).
	if cols < canvas {
		st.writeWallCompact(w, hs, cols, footer, wordmarkScaleFor(cols))
		return
	}

	eff := cols
	if eff < canvas {
		eff = canvas
	}

	teeth := func(row int) []run {
		var rr []run
		for i := 0; i < nm; i++ {
			if row == 0 {
				rr = append(rr, run{ansiGreen, strings.Repeat("█", wallMerlonW)})
			} else {
				rr = append(rr,
					run{ansiGreen, "█"},
					run{ansiG3, strings.Repeat("▓", wallMerlonW-2)},
					run{ansiGreen, "█"})
			}
			if i < displayGaps {
				if !emptyWall && row == wallTeethH/2 {
					t := toks[i]
					lead := (gap - t.n) / 2
					if lead < 0 {
						lead = 0
					}
					trail := gap - lead - t.n
					if trail < 0 {
						trail = 0
					}
					if lead > 0 {
						rr = append(rr, run{"", strings.Repeat(" ", lead)})
					}
					rr = append(rr, t.runs...)
					if trail > 0 {
						rr = append(rr, run{"", strings.Repeat(" ", trail)})
					}
				} else {
					rr = append(rr, run{"", strings.Repeat(" ", gap)})
				}
			}
		}
		return rr
	}

	for row := 0; row < wallTeethH; row++ {
		st.emitRow(w, teeth(row), eff)
	}
	st.emitRow(w, []run{{ansiGreen, strings.Repeat("█", wallW)}}, eff) // parapet
	st.emitRow(w, []run{{ansiG3, strings.Repeat("▓", wallW)}}, eff)    // stone course
	st.emitRow(w, []run{{ansiG4, strings.Repeat("▒", wallW)}}, eff)    // deeper course
	st.emitRow(w, []run{{ansiG5, strings.Repeat("░", wallW)}}, eff)    // footing
	fmt.Fprintln(w)
	for _, r := range word {
		st.emitRow(w, r, eff)
	}
	if footer {
		fmt.Fprintln(w)
		st.emitRow(w, st.demoStatusRuns(), eff)
		st.emitRow(w, legendRuns(), eff)
	}
}

// writeWallCompact is the small-terminal fallback for writeWall: a SCALED battlement
// whose crenels carry a single role-coloured state glyph (not the full label), the
// wordmark shrunk to the given scale, then the host labels STACKED below — one clean
// line each. Every emitted row fits within cols, so nothing wraps. Reached when the
// full labelled wall would overflow the terminal's width OR height (the caller picks
// the scale from whichever axis binds); the wide path stays byte-faithful.
// scale 0 drops the wordmark entirely — crown only — for terminals too short to
// keep even the scale-1 lettering plus the panel on one screen (a stock 80x24).
func (st Style) writeWallCompact(w io.Writer, hs []WallHost, cols int, footer bool, scale int) {
	var word [][]run
	if scale >= 1 {
		word = wordmarkBevelRowsScale(scale)
	}

	emptyWall := len(hs) == 0
	gaps := len(hs)
	if emptyWall {
		gaps = 3 // a crenellated solid wall: three empty crenels, no hosts
	}
	nm := gaps + 1

	// fixed merlons with small notches; shrink the merlon if even this won't fit.
	merlonW, gapW := wallMerlonW, 3
	for merlonW > 3 && nm*merlonW+gaps*gapW > cols {
		merlonW--
	}
	wallW := nm*merlonW + gaps*gapW
	eff := cols
	if eff < wallW {
		eff = wallW
	}

	teeth := func(row int) []run {
		var rr []run
		for i := 0; i < nm; i++ {
			if row == 0 {
				rr = append(rr, run{ansiGreen, strings.Repeat("█", merlonW)})
			} else {
				rr = append(rr,
					run{ansiGreen, "█"},
					run{ansiG3, strings.Repeat("▓", merlonW-2)},
					run{ansiGreen, "█"})
			}
			if i < gaps {
				if !emptyWall && row == wallTeethH/2 {
					lead := (gapW - 1) / 2
					rr = append(rr,
						run{"", strings.Repeat(" ", lead)},
						run{hs[i].Role.ansi(), roleGlyph(hs[i].Role)},
						run{"", strings.Repeat(" ", gapW-1-lead)})
				} else {
					rr = append(rr, run{"", strings.Repeat(" ", gapW)})
				}
			}
		}
		return rr
	}

	for row := 0; row < wallTeethH; row++ {
		st.emitRow(w, teeth(row), eff)
	}
	st.emitRow(w, []run{{ansiGreen, strings.Repeat("█", wallW)}}, eff) // parapet
	st.emitRow(w, []run{{ansiG3, strings.Repeat("▓", wallW)}}, eff)    // stone course
	st.emitRow(w, []run{{ansiG4, strings.Repeat("▒", wallW)}}, eff)    // deeper course
	st.emitRow(w, []run{{ansiG5, strings.Repeat("░", wallW)}}, eff)    // footing
	if len(word) > 0 {
		fmt.Fprintln(w)
		for _, r := range word {
			st.emitRow(w, r, eff)
		}
	}
	// the labels the wide wall carries in-gap, stacked one per line so each opened
	// host stays legible at any width (the glyph + colour key back to its crenel).
	if !emptyWall {
		fmt.Fprintln(w)
		st.emitRow(w, legendRuns(), eff)
		for _, h := range hs {
			st.emitRow(w, []run{{h.Role.ansi(), "● " + h.Name + roleSuffix(h.Role)}}, eff)
		}
	}
	if footer {
		fmt.Fprintln(w)
		st.emitRow(w, st.demoStatusRuns(), eff)
	}
}

// demoStatusRuns is the branding-still status line for `crenel banner` standalone.
// The version is the REAL build version (st.Version, ldflags/git-describe derived);
// the rest (EDGES 3 / ✓) are illustrative demo state — the LIVE numbers are shown by
// the CORE MATRIX panel under `status --hud`, not invented here.
func (st Style) demoStatusRuns() []run {
	ver := st.Version
	if ver == "" {
		ver = "dev"
	}
	return []run{
		{ansiDim, "crenel "}, {ansiValue, ver}, {ansiG4, "  ·  "},
		{ansiDim, "EDGES "}, {ansiValue, "3"}, {ansiG4, "  ·  "},
		{ansiDim, "DEFAULT-DENY "}, {ansiGreen, "✓"},
	}
}

// legendRuns keys the crenel-gap colours to their meaning.
func legendRuns() []run {
	return []run{
		{ansiGreen, "✓ verified"}, {ansiG4, "   "},
		{ansiAmber, "▸ about-to-go-public"}, {ansiG4, "   "},
		{ansiRed, "✕ fail-open"},
	}
}

// WriteHeroBanner draws the full hero wall — battlement (crenel.sh demo hosts) over
// the beveled wordmark, with the status + legend footer. This is what `crenel banner`
// prints, and is byte-faithful to the approved brand still.
func (st Style) WriteHeroBanner(w io.Writer, cols int) {
	st.writeWall(w, demoWallHosts, cols, true)
}

// SortWallHosts orders hosts most-severe first (fail-open, then public, then verified),
// then by name — so a capped wall surfaces the hosts that matter, deterministically.
func SortWallHosts(hosts []WallHost) {
	sev := func(r Sem) int {
		switch r {
		case Fail:
			return 0
		case Warn:
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if si, sj := sev(hosts[i].Role), sev(hosts[j].Role); si != sj {
			return si < sj
		}
		return hosts[i].Name < hosts[j].Name
	})
}
