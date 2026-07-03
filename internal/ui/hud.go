package ui

import (
	"fmt"
	"io"
	"strings"
)

// EdgeRef is one edge in the topology for the HUD's EDGES field.
type EdgeRef struct {
	Name   string // topology name, e.g. "home", "vps"
	Driver string // driver, e.g. "caddy", "traefik", "nginx", "netbird"
}

// HUDModel is the render-ready view of `crenel status`. It is DERIVED (in cmd)
// from the read-only status read plus drift detection; ui only renders it. Every
// field maps to a real Crenel domain concept — there are no invented metrics.
type HUDModel struct {
	// Exposed is the number of hosts exposed across all edges; Public is how many
	// of those are reachable from the internet (have a public-scope DNS record, or
	// — when no public DNS is managed — are non-mesh edge routes).
	Exposed int
	Public  int
	// DenyEnforced is true iff the catch-all default-deny is present AND certifiable
	// (fully parsed) on EVERY edge. False with DenyUnknown=false is FAIL-OPEN: a
	// critical invariant violation.
	DenyEnforced bool
	// DenyUnknown is true when the catch-all deny is present but the config is NOT
	// fully parsed on some edge, so default-deny CANNOT be certified (an unparsed
	// route could be a permissive catch-all). It renders amber UNKNOWN — never green
	// ENFORCED, never red FAIL-OPEN. Takes precedence over DenyEnforced for display.
	// See TOPOLOGY-RISK-REGISTER §4.4.
	DenyUnknown bool
	// Unparsed is the total count of routes/constructs crenel saw but could not fully
	// understand across all edges (the coverage gap). 0 = full coverage.
	Unparsed int
	// Drift counts items diverging from the canonical exposed set (what reconcile
	// would change). -1 means "not computed" (rendered as "?").
	Drift int
	// Edges is the configured edge topology (name·driver per edge).
	Edges []EdgeRef
	// DNSScopes are the managed DNS scopes, e.g. ["internal","public"] for the
	// split-horizon case.
	DNSScopes []string
	// LastApply is "verified" or, in the usual live-state-authoritative case where
	// nothing is persisted, "unknown" — there is no stored apply record to verify.
	LastApply string
	// Hosts is the per-host exposure list painted into the battlement banner's crenel
	// gaps (each with its semantic role). Derived from the same live status read as the
	// counts above; empty means nothing exposed → a solid default-deny wall.
	Hosts []WallHost
}

// exposedValue renders "EXPOSED" as "<n> host(s)  (<m> public)". The public count
// is the watched surface, so it is amber when non-zero, green when zero.
func (st Style) exposedValue(m HUDModel) (plain, colored string) {
	hosts := fmt.Sprintf("%d host%s", m.Exposed, plural(m.Exposed))
	pubPlain := fmt.Sprintf("(%d public)", m.Public)
	pub := st.Safe(pubPlain)
	if m.Public > 0 {
		pub = st.Warn(pubPlain) // a public surface exists — keep an eye on it
	}
	plain = hosts + "  " + pubPlain
	colored = st.Dim(hosts) + "  " + pub
	return plain, colored
}

func (st Style) denyValue(m HUDModel) (plain, colored string) {
	// UNKNOWN takes precedence: a present-but-uncertifiable deny must never read green
	// ENFORCED nor red FAIL-OPEN — it is amber (register §4.4).
	if m.DenyUnknown {
		p := "UNKNOWN"
		if m.Unparsed > 0 {
			p = fmt.Sprintf("UNKNOWN (%d unparsed)", m.Unparsed)
		}
		return p, st.Warn(p)
	}
	if m.DenyEnforced {
		return "ENFORCED", st.Safe("ENFORCED")
	}
	// plain and colored must share the same visible width so the panel border
	// stays flush (the ✗ counts as one column in both).
	return "FAIL-OPEN ✗", st.Fail("FAIL-OPEN ✗")
}

func (st Style) driftValue(m HUDModel) (plain, colored string) {
	switch {
	case m.Drift < 0:
		return "unknown", st.Dim("unknown")
	case m.Drift == 0:
		return "none", st.Safe("none")
	default:
		p := fmt.Sprintf("%d item%s", m.Drift, plural(m.Drift))
		return p, st.Warn(p) // diverged from canonical — reconcile would change it
	}
}

func (st Style) edgesValue(m HUDModel) (plain, colored string) {
	if len(m.Edges) == 0 {
		return "(none)", st.Dim("(none)")
	}
	parts := make([]string, len(m.Edges))
	cparts := make([]string, len(m.Edges))
	for i, e := range m.Edges {
		label := e.Name
		if e.Driver != "" && e.Driver != e.Name {
			label = e.Name + "·" + e.Driver
		}
		parts[i] = label
		cparts[i] = st.Safe(label)
	}
	return strings.Join(parts, "  "), strings.Join(cparts, "  ")
}

func (st Style) dnsValue(m HUDModel) (plain, colored string) {
	if len(m.DNSScopes) == 0 {
		return "(none managed)", st.Dim("(none managed)")
	}
	joined := strings.Join(m.DNSScopes, " + ")
	if len(m.DNSScopes) > 1 {
		// internal + public = split-horizon, the healthy steady state.
		return "split-horizon  " + joined, st.Dim("split-horizon  ") + st.Safe(joined)
	}
	return joined, st.Safe(joined)
}

func (st Style) lastApplyValue(m HUDModel) (plain, colored string) {
	if strings.EqualFold(m.LastApply, "verified") {
		return "verified", st.Safe("verified")
	}
	// No stored desired state means there is nothing persisted to verify against:
	// live is the only source of truth. That is by design, not an error — dim.
	return "unknown — live is the only source of truth",
		st.Dim("unknown — live is the only source of truth")
}

// field is one label/value pair for the HUD panel and compact header, plus the
// semantic role its value carries (so the panel can draw a colored status dot).
type field struct {
	label   string
	plain   string
	colored string
	role    Sem
}

// roleEnforced/etc. derive the semantic role of each field from the model, using
// the SAME rules as the per-value colorers above (kept in lock-step by eye).
func (m HUDModel) denyRole() Sem {
	switch {
	case m.DenyUnknown:
		return Warn
	case m.DenyEnforced:
		return Safe
	default:
		return Fail
	}
}

func (st Style) fields(m HUDModel) []field {
	exP, exC := st.exposedValue(m)
	dnP, dnC := st.denyValue(m)
	drP, drC := st.driftValue(m)
	edP, edC := st.edgesValue(m)
	dsP, dsC := st.dnsValue(m)
	laP, laC := st.lastApplyValue(m)

	exposedRole := Safe
	if m.Public > 0 {
		exposedRole = Warn
	}
	driftRole := Safe
	if m.Drift > 0 {
		driftRole = Warn
	} else if m.Drift < 0 {
		driftRole = Neutral
	}
	edgesRole := Safe
	if len(m.Edges) == 0 {
		edgesRole = Neutral
	}
	dnsRole := Safe
	if len(m.DNSScopes) == 0 {
		dnsRole = Neutral
	}
	applyRole := Neutral
	if strings.EqualFold(m.LastApply, "verified") {
		applyRole = Safe
	}
	return []field{
		{"EXPOSED", exP, exC, exposedRole},
		{"DEFAULT-DENY", dnP, dnC, m.denyRole()},
		{"DRIFT", drP, drC, driftRole},
		{"EDGES", edP, edC, edgesRole},
		{"DNS", dsP, dsC, dnsRole},
		{"LAST APPLY", laP, laC, applyRole}, // Neutral unless verified
	}
}

// WriteHeader renders the compact one-block status header: a small CRENEL tag and
// the six domain fields, colored semantically. Suitable above the detailed
// status listing on an interactive terminal.
func (st Style) WriteHeader(w io.Writer, m HUDModel) {
	tag := st.Bold(Safe, "CRENEL")
	bar := st.Dim("▌")
	fmt.Fprintf(w, "%s %s what's exposed right now\n", tag, bar)
	for _, f := range st.fields(m) {
		fmt.Fprintf(w, "  %s %s %s\n", st.Dim(padRight(f.label, 12)), bar, f.colored)
	}
}

// panelWidth is the fixed inner width of the HUD panel (visible columns between
// the side borders). The sample fields fit; an over-long value simply runs to a
// ragged right edge rather than corrupting alignment.
const panelWidth = 60

// WriteHUD renders the full HUD banner: the crenellated wordmark above a
// rounded-frame "CORE MATRIX // EXPOSURE STATE" panel. Each row leads with a
// semantic status dot (an at-a-glance LED rail) followed by the label and its
// colored value. This is the read-only dashboard, drawn in the terminal.
func (st Style) WriteHUD(w io.Writer, m HUDModel) {
	// The battlement banner with the LIVE exposed hosts in its crenel gaps (no footer —
	// the CORE MATRIX panel below carries the status line and legend).
	st.writeWall(w, m.Hosts, st.Cols, false)
	fmt.Fprintln(w)

	// Rounded header with a colored title; dashes fill to the panel width.
	title := " CORE MATRIX // EXPOSURE STATE "
	dashes := panelWidth - visualLen(title)
	if dashes < 0 {
		dashes = 0
	}
	fmt.Fprintf(w, "  %s%s%s%s\n",
		st.Dim("╭"), st.Bold(Safe, title), st.Dim(strings.Repeat("─", dashes)), st.Dim("╮"))

	for _, f := range st.fields(m) {
		dot := st.Paint(f.role, "●")
		label := padRight(f.label, 12)
		// inner = " " + dot + " " + label + " " + value + pad + " " == panelWidth
		visible := 1 + 1 + 1 + len(label) + 1 + visualLen(f.plain)
		pad := panelWidth - 1 - visible
		if pad < 0 {
			pad = 0
		}
		line := " " + dot + " " + st.Dim(label) + " " + f.colored + strings.Repeat(" ", pad) + " "
		fmt.Fprintf(w, "  %s%s%s\n", st.Dim("│"), line, st.Dim("│"))
	}

	fmt.Fprintf(w, "  %s%s%s\n", st.Dim("╰"), st.Dim(strings.Repeat("─", panelWidth)), st.Dim("╯"))
	fmt.Fprintf(w, "  %s\n",
		st.Dim("legend: ")+st.Safe("● safe/private")+st.Dim(" · ")+st.Warn("● public/drift")+st.Dim(" · ")+st.Fail("● fail-open"))
}

// --- small layout helpers (pure, deterministic) ---

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// visualLen counts the visible columns of a string, ignoring any ANSI SGR
// escape sequences (so colored values pad correctly). The fields fed here are
// plain, but this keeps padding correct regardless.
func visualLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			n++
		}
	}
	return n
}
