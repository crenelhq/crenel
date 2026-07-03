package ui

import (
	"bytes"
	"strings"
	"testing"
)

func sampleModel() HUDModel {
	return HUDModel{
		Exposed: 3, Public: 2, DenyEnforced: true, Drift: 0,
		Edges:     []EdgeRef{{Name: "home", Driver: "caddy"}, {Name: "vps", Driver: "traefik"}},
		DNSScopes: []string{"internal", "public"},
		LastApply: "unknown",
	}
}

// hasANSI reports whether s contains any ANSI escape sequence.
func hasANSI(s string) bool { return strings.Contains(s, "\x1b[") }

func TestWordmark_DeterministicAndUniformWidth(t *testing.T) {
	rows := WordmarkRows()
	if len(rows) != 7 {
		t.Fatalf("want 7 rows (merlons + parapet + 5 letter rows), got %d", len(rows))
	}
	w := len([]rune(rows[0]))
	for i, r := range rows {
		if got := len([]rune(r)); got != w {
			t.Errorf("row %d width %d != %d (grid must be rectangular)", i, got, w)
		}
	}
	// Row 0 is the crenellation: it must contain BOTH merlons (blocks) and crenel
	// gaps (spaces) — that is what makes the top edge a battlement.
	if !strings.ContainsRune(rows[0], block) || !strings.ContainsRune(rows[0], ' ') {
		t.Errorf("merlon band must alternate blocks and gaps: %q", rows[0])
	}
	// Row 1 is the solid parapet (no gaps).
	if strings.ContainsRune(strings.TrimRight(rows[1], ""), ' ') {
		t.Errorf("parapet row must be solid: %q", rows[1])
	}
}

func TestColorGating(t *testing.T) {
	on := Style{Color: true}
	off := Style{Color: false}
	if got := off.Safe("x"); got != "x" {
		t.Errorf("color disabled must pass text through unchanged, got %q", got)
	}
	if got := on.Safe("x"); !hasANSI(got) || !strings.Contains(got, ansiGreen) {
		t.Errorf("color enabled must wrap in green ANSI, got %q", got)
	}
	if got := on.Fail("x"); !strings.Contains(got, ansiRed) {
		t.Errorf("Fail must use red, got %q", got)
	}
	if got := on.Warn("x"); !strings.Contains(got, ansiAmber) {
		t.Errorf("Warn must use amber, got %q", got)
	}
}

func TestWordmark_PlainHasNoANSI(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.WriteWordmark(&b, "")
	if hasANSI(b.String()) {
		t.Errorf("plain wordmark must contain no ANSI:\n%q", b.String())
	}
	if !strings.ContainsRune(b.String(), block) {
		t.Error("wordmark must be drawn with block runes")
	}
}

func TestHeader_PlainFallback(t *testing.T) {
	var b bytes.Buffer
	Style{Color: false}.WriteHeader(&b, sampleModel())
	out := b.String()
	if hasANSI(out) {
		t.Errorf("plain header must contain no ANSI:\n%s", out)
	}
	for _, want := range []string{"CRENEL", "EXPOSED", "ENFORCED", "none", "home·caddy", "internal + public"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain header missing %q:\n%s", want, out)
		}
	}
}

// TestHUD_SemanticColorMeaning asserts color CARRIES MEANING: enforced deny is
// green, a public surface is amber, fail-open is red, drift is amber.
func TestHUD_SemanticColorMeaning(t *testing.T) {
	st := Style{Color: true}

	var safe bytes.Buffer
	st.WriteHeader(&safe, HUDModel{Exposed: 2, Public: 1, DenyEnforced: true, Drift: 0, LastApply: "unknown"})
	s := safe.String()
	// The "(1 public)" token must be amber; "ENFORCED" must be green.
	if !strings.Contains(s, ansiAmber+"(1 public)") {
		t.Errorf("a public surface must render amber:\n%s", s)
	}
	if !strings.Contains(s, ansiGreen+"ENFORCED") {
		t.Errorf("enforced default-deny must render green:\n%s", s)
	}

	var bad bytes.Buffer
	st.WriteHeader(&bad, HUDModel{Exposed: 1, Public: 1, DenyEnforced: false, Drift: 2, LastApply: "unknown"})
	d := bad.String()
	if !strings.Contains(d, ansiRed) {
		t.Errorf("FAIL-OPEN must render red:\n%s", d)
	}
	if !strings.Contains(d, ansiAmber+"2 items") {
		t.Errorf("drift must render amber:\n%s", d)
	}
}

// TestHUD_PanelAlignment asserts the boxed panel's lines are all the same visual
// width (so the right border is flush) — deterministic layout. Both the healthy
// model and the FAIL-OPEN one (whose value carries a ✗) must stay aligned, since
// padding is computed from the plain value's visible width.
func TestHUD_PanelAlignment(t *testing.T) {
	for name, m := range map[string]HUDModel{
		"healthy":  sampleModel(),
		"failopen": {Exposed: 0, Public: 0, DenyEnforced: false, Drift: 1, Edges: []EdgeRef{{Name: "caddy", Driver: "caddy"}}, LastApply: "unknown"},
	} {
		var b bytes.Buffer
		Style{Color: false}.WriteHUD(&b, m)
		var widths []int
		for _, line := range strings.Split(b.String(), "\n") {
			if strings.HasPrefix(line, "  ╭") || strings.HasPrefix(line, "  │") || strings.HasPrefix(line, "  ╰") {
				widths = append(widths, len([]rune(line)))
			}
		}
		if len(widths) != 8 { // top + 6 fields + bottom
			t.Fatalf("%s: expected 8 panel lines, got %d", name, len(widths))
		}
		for i, w := range widths {
			if w != widths[0] {
				t.Errorf("%s: panel line %d width %d != %d (border not flush)", name, i, w, widths[0])
			}
		}
	}
}

func TestWordmarkSVG(t *testing.T) {
	s := WordmarkSVG()
	for _, want := range []string{"<svg", "</svg>", svgBG, svgGreen, "<rect", "atomic agreement"} {
		if !strings.Contains(s, want) {
			t.Errorf("wordmark SVG missing %q", want)
		}
	}
}

// TestWordmarkSVG_Deterministic guards the committed asset against drift: the
// renderer must be pure (same bytes every call). The committed docs/brand SVGs
// are regenerated from exactly this output.
func TestWordmarkSVG_Deterministic(t *testing.T) {
	if WordmarkSVG() != WordmarkSVG() || WordmarkSVGLight() != WordmarkSVGLight() {
		t.Fatal("wordmark SVG renderer must be deterministic")
	}
	if !strings.HasPrefix(WordmarkSVG(), "<svg") || !strings.HasSuffix(WordmarkSVG(), "</svg>\n") {
		t.Error("WordmarkSVG must be well-formed SVG")
	}
	if !strings.Contains(WordmarkSVG(), "atomic agreement") {
		t.Error("WordmarkSVG missing tagline")
	}
	if !strings.Contains(WordmarkSVG(), svgGreen) {
		t.Error("WordmarkSVG must carry the dark-surface crown green")
	}
	if !strings.Contains(WordmarkSVGLight(), svgGreenDeep) {
		t.Error("WordmarkSVGLight must carry the light-surface crown green")
	}
}

// TestWordmarkSVGLight asserts the light variant uses the light surface tokens
// (off-white canvas, deep-green crown, ink letters) and shares the dark mark's
// geometry — same viewBox and tagline, only the fills differ.
func TestWordmarkSVGLight(t *testing.T) {
	light := WordmarkSVGLight()
	for _, want := range []string{"<svg", "</svg>", svgLightBG, svgGreenDeep, svgInk, "atomic agreement"} {
		if !strings.Contains(light, want) {
			t.Errorf("light wordmark SVG missing %q", want)
		}
	}
	// The canvas (the first full-bleed <rect>) must differ between surfaces: the
	// light variant paints the off-white canvas, the dark variant the near-black
	// one. (The light letters deliberately reuse the dark color as ink, so we
	// check the canvas rect specifically, not mere color presence.)
	canvasFill := func(s string) string {
		i := strings.Index(s, "<rect width=")
		line := s[i : i+strings.Index(s[i:], "\n")]
		f := strings.Index(line, `fill="`) + len(`fill="`)
		return line[f : f+strings.Index(line[f:], `"`)]
	}
	if got := canvasFill(light); got != svgLightBG {
		t.Errorf("light wordmark canvas = %s, want %s", got, svgLightBG)
	}
	if got := canvasFill(WordmarkSVG()); got != svgBG {
		t.Errorf("dark wordmark canvas = %s, want %s", got, svgBG)
	}
	// Same geometry: identical viewBox.
	vb := func(s string) string {
		i := strings.Index(s, "viewBox=")
		return s[i : i+24]
	}
	if vb(light) != vb(WordmarkSVG()) {
		t.Errorf("light and dark wordmarks must share geometry (viewBox)")
	}
}

func TestStatusHUDSVG_FieldsAndSemanticColor(t *testing.T) {
	s := StatusHUDSVG(sampleModel())
	for _, want := range []string{"CORE MATRIX // EXPOSURE STATE", "EXPOSED", "DEFAULT-DENY", "DRIFT", "EDGES", "DNS", "LAST APPLY"} {
		if !strings.Contains(s, want) {
			t.Errorf("HUD SVG missing field %q", want)
		}
	}
	// Healthy model: deny is green, public count is amber.
	if !strings.Contains(s, svgAmber) || !strings.Contains(s, svgGreen) {
		t.Errorf("HUD SVG must use semantic colors (green + amber)")
	}
	// Fail-open model must surface red.
	bad := StatusHUDSVG(HUDModel{Exposed: 1, Public: 1, DenyEnforced: false, Drift: 1, LastApply: "unknown"})
	if !strings.Contains(bad, svgRed) {
		t.Errorf("fail-open HUD SVG must use red for the FAIL-OPEN value")
	}
}
