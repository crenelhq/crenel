package ui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestWordmarkBevel_ByteFaithful pins the beveled CRENEL wordmark to the APPROVED
// brand still byte-for-byte. The fingerprint is computed over the per-cell glyph grid
// plus the per-cell tone grid (mint/g2/green/g3/none), exactly as the design tool that
// produced crenel-opt-wall.png does. If the renderer drifts (a changed glyph, a shifted
// bevel ring, a lost R-bowl rim wrap), this fails — the mark is no longer the one the maintainer
// approved. Regenerate the still and update the constant deliberately, never casually.
func TestWordmarkBevel_ByteFaithful(t *testing.T) {
	tierChar := map[string]byte{"": '.', ansiMint: 'M', ansiG2: '2', ansiGreen: 'R', ansiG3: '3'}
	var glyphs, tiers strings.Builder
	for _, row := range wordmarkBevelRows() {
		for _, rn := range row {
			tc, ok := tierChar[rn.color]
			if !ok {
				t.Fatalf("unexpected wordmark run color %q (not a bevel tone)", rn.color)
			}
			for _, g := range rn.text {
				glyphs.WriteRune(g)
				tiers.WriteByte(tc)
			}
		}
	}
	sum := sha256.Sum256([]byte(glyphs.String() + tiers.String()))
	got := hex.EncodeToString(sum[:])[:16]
	const want = "c310d5e74d236013" // the approved crenel-opt-wall.png wordmark
	if got != want {
		t.Errorf("beveled wordmark drifted from the approved still: fingerprint %s != %s", got, want)
	}
}

// TestWordmarkBevel_Deterministic guards the renderer's purity (same bytes every call).
func TestWordmarkBevel_Deterministic(t *testing.T) {
	var a, b bytes.Buffer
	Style{Color: true}.writeWall(&a, demoWallHosts, 130, true)
	Style{Color: true}.writeWall(&b, demoWallHosts, 130, true)
	if a.String() != b.String() {
		t.Fatal("the wall renderer must be deterministic")
	}
}

// TestWall_PlainHasNoANSI: the plain/NO_COLOR path must emit zero ANSI, yet still draw
// the battlement (block runes) and the host names as legible text.
func TestWall_PlainHasNoANSI(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.writeWall(&b, demoWallHosts, 130, true)
	out := b.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain wall must contain no ANSI:\n%q", out)
	}
	for _, want := range []string{"█", "app.crenel.sh", "DEFAULT-DENY", "✓ verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain wall missing %q", want)
		}
	}
}

// TestWall_SemanticHostColors: each gap is painted by its host's role — green for
// verified, amber for about-to-go-public, red for fail-open (color CARRIES meaning).
func TestWall_SemanticHostColors(t *testing.T) {
	hosts := []WallHost{
		{"safe.example", Safe},
		{"warn.example", Warn},
		{"fail.example", Fail},
	}
	var b bytes.Buffer
	Style{Color: true}.writeWall(&b, hosts, 200, false)
	out := b.String()
	for role, color := range map[string]string{"green": ansiGreen, "amber": ansiAmber, "red": ansiRed} {
		if !strings.Contains(out, color) {
			t.Errorf("a host gap must render %s for its role", role)
		}
	}
	// The state suffixes encode the role at a glance.
	for _, want := range []string{"safe.example ✓", "warn.example ▸ public", "fail.example ✕ open"} {
		if !strings.Contains(out, want) {
			t.Errorf("wall missing host token %q", want)
		}
	}
}

// TestWall_NoHostsSolidWall: with nothing exposed the wall is a SOLID default-deny
// battlement — empty crenels, no host bullets.
func TestWall_NoHostsSolidWall(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.writeWall(&b, nil, 130, false)
	out := b.String()
	if strings.Contains(out, "●") {
		t.Errorf("an empty wall must have no host bullets:\n%s", out)
	}
	if !strings.Contains(out, "█") {
		t.Error("an empty wall must still draw the battlement")
	}
}

// TestHeroBanner_DemoWall: `crenel banner` standalone shows the crenel.sh demo hosts
// (its own domain — never real infra) with the full status + legend footer, and the
// status line prints the REAL build version passed via Style.Version (not a literal).
func TestHeroBanner_DemoWall(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false, Version: "v9.9.9"}.WriteHeroBanner(&b, 130)
	out := b.String()
	for _, want := range []string{"app.crenel.sh", "grafana.crenel.sh", "registry.crenel.sh", "crenel v9.9.9", "✕ fail-open"} {
		if !strings.Contains(out, want) {
			t.Errorf("hero banner missing %q", want)
		}
	}
	if strings.Contains(out, "example.com") || strings.Contains(out, "shrimp") {
		t.Errorf("the demo wall must not contain real/foreign infra:\n%s", out)
	}
	// the version must come from Style.Version — never a stale hardcoded literal.
	if strings.Contains(out, "v0.3.0") {
		t.Errorf("banner must not contain a hardcoded version literal:\n%s", out)
	}
}

// visualWidth is the rendered column span of a line: rune count after the ANSI SGR
// escapes (ESC[…m) are stripped (each glyph is one terminal cell here). The wall must
// keep every line within the terminal width or it wraps and garbles.
func visualWidth(line string) int {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] == '\x1b' {
			for i < len(line) && line[i] != 'm' {
				i++
			}
			if i < len(line) {
				i++ // skip the closing 'm'
			}
			continue
		}
		r, sz := utf8.DecodeRuneInString(line[i:])
		b.WriteRune(r)
		i += sz
	}
	return utf8.RuneCountInString(b.String())
}

// TestWall_NarrowWidthFits pins BUG 1 (width-wrap): the wall is 121 cols at the demo
// hosts, so on a narrower terminal it must scale to a compact render where NO line
// exceeds the width — never the old garble. Checked at 80/100/110 in both color and
// plain, and the opened hosts must still be legible (stacked below the wordmark).
func TestWall_NarrowWidthFits(t *testing.T) {
	for _, cols := range []int{80, 100, 110} {
		for _, color := range []bool{false, true} {
			var b bytes.Buffer
			Style{Color: color}.writeWall(&b, demoWallHosts, cols, true)
			for _, line := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
				if w := visualWidth(line); w > cols {
					t.Errorf("cols=%d color=%v: line of width %d overflows (wraps/garbles):\n%q", cols, color, w, line)
				}
			}
			out := b.String()
			for _, want := range []string{"app.crenel.sh", "grafana.crenel.sh", "registry.crenel.sh", "█"} {
				if !strings.Contains(out, want) {
					t.Errorf("cols=%d color=%v: compact wall missing %q", cols, color, want)
				}
			}
		}
	}
}

// TestWall_NarrowEmptyNoPanic: an empty (default-deny) wall must also render compact
// on a narrow terminal — a battlement, no host bullets, no panic.
func TestWall_NarrowEmptyNoPanic(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.writeWall(&b, nil, 80, false)
	out := b.String()
	if !strings.Contains(out, "█") {
		t.Error("a narrow empty wall must still draw the battlement")
	}
	if strings.Contains(out, "●") {
		t.Errorf("a narrow empty wall must have no host bullets:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if w := visualWidth(line); w > 80 {
			t.Errorf("narrow empty wall line of width %d overflows 80:\n%q", w, line)
		}
	}
}

// TestWall_LabelCenteredInNotch pins BUG 2 (merlon-label layout): in the full wall the
// host label must sit in the VERTICAL CENTRE of its crenel — equal teeth rows above and
// below — so each gap reads as a clean labelled notch, not floating text. (The old 4-row
// wall drew the label on row 2 of 4: two empty rows above, one below — sparse.)
func TestWall_LabelCenteredInNotch(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.writeWall(&b, demoWallHosts, 130, false) // wide path
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	// teeth rows are everything above the first solid parapet (all-█) line.
	parapet := -1
	for i, ln := range lines {
		if t := strings.TrimSpace(ln); t != "" && strings.Trim(t, "█") == "" {
			parapet = i // first solid all-█ row (ignoring centring pad)
			break
		}
	}
	if parapet < 0 {
		t.Fatalf("no parapet row found:\n%s", b.String())
	}
	if parapet != wallTeethH {
		t.Errorf("expected %d teeth rows above the parapet, got %d", wallTeethH, parapet)
	}
	label := -1
	for i := 0; i < parapet; i++ {
		if strings.Contains(lines[i], "app.crenel.sh") {
			label = i
		}
	}
	if label < 0 {
		t.Fatalf("host label not found in the teeth rows:\n%s", b.String())
	}
	above, below := label, parapet-1-label
	if above != below {
		t.Errorf("label not vertically centred in its notch: %d rows above, %d below (teeth=%d)", above, below, wallTeethH)
	}
}

// TestHeroBanner_VersionFallback: with no Style.Version the banner status line falls
// back to "dev" (the same default as main's ldflags var) — never blank, never stale.
func TestHeroBanner_VersionFallback(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.WriteHeroBanner(&b, 130)
	if !strings.Contains(b.String(), "crenel dev") {
		t.Errorf("empty Version should fall back to 'crenel dev':\n%s", b.String())
	}
}

// TestSortWallHosts: most-severe first (fail-open, then public, then verified), then
// by name — so a capped wall surfaces what matters, deterministically.
func TestSortWallHosts(t *testing.T) {
	hosts := []WallHost{
		{"z.safe", Safe}, {"a.fail", Fail}, {"m.warn", Warn}, {"a.safe", Safe}, {"b.fail", Fail},
	}
	SortWallHosts(hosts)
	want := []string{"a.fail", "b.fail", "m.warn", "a.safe", "z.safe"}
	for i, w := range want {
		if hosts[i].Name != w {
			t.Errorf("sorted[%d] = %s, want %s", i, hosts[i].Name, w)
		}
	}
}
