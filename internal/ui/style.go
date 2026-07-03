// Package ui renders Crenel's branded terminal surfaces: the crenellated CRENEL
// wordmark and the status HUD. It is a PRESENTATION layer — it depends only on
// core's view types (never the reverse) and performs no I/O beyond writing to an
// io.Writer, so rendering is deterministic and unit-testable.
//
// Color is SEMANTIC here (see BRANDING.md), never decoration:
//
//	green  = safe / private / verified
//	amber  = about to go public / drift detected
//	red    = fail-open / unexpectedly exposed
//
// Color is emitted only when explicitly enabled (a TTY with NO_COLOR unset, as
// decided by the caller). With color disabled every helper returns its input
// unchanged — that is the plain/NO_COLOR/non-TTY path.
package ui

import "strings"

// ANSI truecolor foregrounds for the semantic palette plus a neutral steel for
// labels and chrome. Truecolor keeps the radium-green (#00FF66) exact; terminals
// that lack it approximate to their nearest color gracefully.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"

	ansiGreen = "\x1b[38;2;0;255;102m"   // safe / private / verified
	ansiAmber = "\x1b[38;2;255;176;0m"   // about to go public / drift detected
	ansiRed   = "\x1b[38;2;255;59;48m"   // fail-open / unexpectedly exposed
	ansiDim   = "\x1b[38;2;120;126;138m" // labels, rules, neutral chrome
)

// Sem is a semantic color role. Rendering maps it to an ANSI code (or nothing,
// when color is disabled). Working in roles rather than raw colors keeps the
// "color carries meaning" rule in exactly one place.
type Sem int

const (
	Neutral Sem = iota // dim/steel — labels and chrome
	Safe               // green  — safe / private / verified
	Warn               // amber  — about to go public / drift
	Fail               // red    — fail-open / unexpectedly exposed
)

func (s Sem) ansi() string {
	switch s {
	case Safe:
		return ansiGreen
	case Warn:
		return ansiAmber
	case Fail:
		return ansiRed
	default:
		return ansiDim
	}
}

// Style wraps text in semantic color when Color is enabled, and is a no-op
// (returns text unchanged) when it is not — the plain/NO_COLOR/non-TTY path.
type Style struct {
	Color bool
	// Cols is the terminal width used to draw the full-width scanline banner. 0 means
	// "unknown" — the banner falls back to BannerWidth. Other surfaces ignore it.
	Cols int
	// Version is the build version (ldflags / git-describe derived) shown in the
	// standalone `crenel banner` status line. Empty falls back to "dev".
	Version string
}

// paint wraps s in the role's color (and optional bold) when color is enabled.
func (st Style) paint(role Sem, bold bool, s string) string {
	if !st.Color {
		return s
	}
	var b strings.Builder
	if bold {
		b.WriteString(ansiBold)
	}
	b.WriteString(role.ansi())
	b.WriteString(s)
	b.WriteString(ansiReset)
	return b.String()
}

// Paint colors s in the given role (no bold).
func (st Style) Paint(role Sem, s string) string { return st.paint(role, false, s) }

func (st Style) Safe(s string) string { return st.paint(Safe, false, s) }
func (st Style) Warn(s string) string { return st.paint(Warn, false, s) }
func (st Style) Fail(s string) string { return st.paint(Fail, false, s) }
func (st Style) Dim(s string) string  { return st.paint(Neutral, false, s) }

// Bold colors s in the given role with bold weight (used for the wordmark and
// headline values).
func (st Style) Bold(role Sem, s string) string { return st.paint(role, true, s) }
