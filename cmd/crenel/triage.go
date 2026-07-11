package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
)

// `crenel triage` — the operator-guided walk through every route crenel could
// not understand. A brownfield first audit almost always reports "N route(s)
// not understood … deny UNKNOWN, not ENFORCED"; before this verb the remedy
// was archaeology (curl the admin API, read raw JSON, hand-build `crenel
// ack`). Triage shows each not-understood route as a bounded evidence card —
// edge, structural path, what crenel DID understand, the raw route JSON — and
// prompts for a properly-reasoned ack, written through the SAME engine ack
// path (`AckRoute`, read-back-verified) as the non-interactive equivalent
// `crenel ack --route '<locator>' --reason <slug>`.

// triageExcerptMax bounds the route JSON shown on the evidence card; the [o]
// action prints the whole thing. Cards must stay skimmable — a huge nested
// block would defeat the guided flow.
const triageExcerptMax = 600

func (c *cli) cmdTriage(ctx context.Context, args []string) error {
	// Verb-local flags: --edge <name> narrows to one edge; --dry-run walks the
	// full flow but prints what WOULD be acked instead of writing (the global
	// dry-run convention import/apply follow).
	var edgeName string
	dryRun := false
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		switch name {
		case "edge":
			if !hasVal {
				i++
				if i >= len(args) {
					return fmt.Errorf("usage: triage [--edge <name>] [--dry-run]")
				}
				val = args[i]
			}
			edgeName = val
		case "dry-run":
			dryRun = true
		default:
			return fmt.Errorf("triage: unknown argument %q (usage: triage [--edge <name>] [--dry-run])", args[i])
		}
	}
	// Interactivity gate: triage is a prompt loop, so a non-TTY stdin (a pipe,
	// CI, an agent) gets refused with the scriptable equivalent named — same
	// spirit as the HUD's TIOCGWINSZ-backed TTY detection.
	if !c.stdinIsTTY() {
		return fmt.Errorf("triage is interactive; stdin is not a terminal — use `crenel ack --route '<locator>' --reason <slug>` (or `crenel ack <host> --reason <slug>`) in scripts")
	}

	items, err := c.engine.NotUnderstood(ctx, edgeName)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Fprintln(c.out, "nothing to triage: every route is understood or already acknowledged")
		return nil
	}
	fmt.Fprintf(c.out, "%d route(s) not understood — each one keeps default-deny UNKNOWN until understood or acknowledged\n", len(items))
	if dryRun {
		fmt.Fprintln(c.out, "dry-run: no marker will be written")
	}

	// c.in is the test seam; the production cli constructors leave it nil, which
	// stdinIsTTY above already tolerates by falling back to the real os.Stdin —
	// the prompt reader must fall back the same way or the first live keystroke
	// dereferences nil (the panic the v0.5.2 live debut hit).
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	reader := bufio.NewReader(in)
	acked, skipped := 0, 0
	quit := false
	for i, it := range items {
		c.printTriageCard(ctx, i+1, len(items), it)
	prompt:
		for {
			fmt.Fprint(c.out, "  [a]ck with reason / [s]kip / [o]pen full JSON / [q]uit > ")
			choice, rerr := readLine(reader)
			if rerr != nil {
				return fmt.Errorf("triage: read choice: %w", rerr)
			}
			switch strings.ToLower(strings.TrimSpace(choice)) {
			case "a":
				if !it.RouteAckable {
					fmt.Fprintf(c.out, "  cannot ack: edge %q has no path-addressed ack support (LocatorAcker) — write the marker manually per docs/design/ack-marker.md §4a\n", it.Edge)
					continue
				}
				done, aerr := c.triageAck(ctx, reader, it, dryRun)
				if aerr != nil {
					return aerr
				}
				if done {
					acked++
					break prompt
				}
				// reason entry cancelled — back to the menu for this card
			case "s", "":
				skipped++
				break prompt
			case "o":
				c.printTriageFullJSON(ctx, it)
			case "q":
				quit = true
				remaining := len(items) - i
				fmt.Fprintf(c.out, "quit: %d route(s) left untriaged; everything already acked stays acked (unack with `crenel unack --route '<locator>'`)\n", remaining)
			default:
				fmt.Fprintln(c.out, "  please answer a, s, o, or q")
			}
			if quit {
				break prompt
			}
		}
		if quit {
			break
		}
	}

	// Summary + what audit will now say: re-enumerate so the number is the
	// VERIFIED post-triage state, not arithmetic over what we think we did.
	verb := "acked"
	if dryRun {
		verb = "would be acked (dry-run)"
	}
	fmt.Fprintf(c.out, "\ntriage summary: %d %s, %d skipped\n", acked, verb, skipped)
	after, err := c.engine.NotUnderstood(ctx, edgeName)
	if err != nil {
		return fmt.Errorf("triage: post-triage re-read: %w", err)
	}
	if len(after) == 0 {
		fmt.Fprintln(c.out, "audit will no longer count not-understood routes here — default-deny can now certify ENFORCED (absent other findings); acked routes stay listed as ACK")
	} else {
		fmt.Fprintf(c.out, "audit will still report %d route(s) not understood — default-deny stays UNKNOWN until they are understood or acknowledged\n", len(after))
	}
	return nil
}

// triageAck runs the reason sub-prompt for one card and (unless dry-run)
// writes the ack through engine.AckRoute — the exact path `crenel ack --route`
// uses — reporting the read-back verification. Returns done=false when the
// operator cancelled with an empty reason (back to the card menu). A write
// failure is printed and returns done=false so the operator can retry or skip;
// only I/O errors on the prompt itself abort triage.
func (c *cli) triageAck(ctx context.Context, reader *bufio.Reader, it core.TriageItem, dryRun bool) (done bool, err error) {
	// The reason is the operator's RECORDED JUDGMENT — "I looked, this is fine
	// because X" — which the tool cannot know. But it can offer a descriptive
	// starting point derived from the evidence (host + why-unparsed kind) so the
	// operator isn't staring at a blank line inventing a format.
	suggested := suggestAckReason(it, c.triageRouteJSON(ctx, it))
	fmt.Fprintln(c.out, "  the reason becomes part of the permanent ack marker — say why this route is acceptable, in a slug future-you will understand in `status`")
	for {
		fmt.Fprintf(c.out, "  reason slug [enter = %s / type your own / 'q' to cancel]: ", suggested)
		reason, rerr := readLine(reader)
		if rerr != nil {
			return false, fmt.Errorf("triage: read reason: %w", rerr)
		}
		reason = strings.TrimSpace(reason)
		if reason == "q" {
			return false, nil // cancelled — back to the card menu
		}
		if reason == "" {
			reason = suggested
		}
		if !model.ValidAckReason(reason) {
			// The marker grammar forbids colons/slashes/spaces/uppercase — a bad
			// slug would stamp a marker the read side cannot round-trip.
			fmt.Fprintf(c.out, "  invalid reason %q: must match [a-z0-9-]+ (no spaces, colons, or slashes — it becomes part of the crenel-ack:<qualifier>:<reason> marker)\n", reason)
			continue
		}
		if dryRun {
			fmt.Fprintf(c.out, "  dry-run: would run `crenel ack --route '%s' --reason %s` on edge %s\n", it.Unparsed.Locator, reason, it.Edge)
			return true, nil
		}
		if aerr := c.engine.AckRoute(ctx, it.Edge, it.Unparsed.Locator, reason); aerr != nil {
			fmt.Fprintf(c.out, "  ack failed: %v\n", aerr)
			return false, nil // back to the menu — the operator can retry or skip
		}
		fmt.Fprintf(c.out, "  acked (read-back verified): %s — no longer blocks default-deny; still listed as ACK in status/audit\n", it.Unparsed.Locator)
		return true, nil
	}
}

// printTriageCard renders one bounded evidence card: where the route lives,
// why crenel could not model it, what it DID understand (host matcher and
// handler types recovered from the raw JSON), and a truncated pretty JSON view.
func (c *cli) printTriageCard(ctx context.Context, n, total int, it core.TriageItem) {
	fmt.Fprintf(c.out, "\n[%d/%d] edge %q — %s\n", n, total, it.Edge, it.Unparsed.Locator)
	fmt.Fprintf(c.out, "  kind: %s\n", it.Unparsed.Kind)
	fmt.Fprintf(c.out, "  why:  %s\n", it.Unparsed.Reason)
	raw := c.triageRouteJSON(ctx, it)
	if host, handlers := routeGlance(raw); host != "" || len(handlers) > 0 {
		var understood []string
		if host != "" {
			understood = append(understood, "host matcher "+host)
		}
		if len(handlers) > 0 {
			understood = append(understood, "handler(s): "+strings.Join(handlers, ", "))
		}
		fmt.Fprintf(c.out, "  understood: %s\n", strings.Join(understood, "; "))
	}
	if raw != "" {
		pretty := prettyJSON(raw)
		if len(pretty) > triageExcerptMax {
			pretty = pretty[:triageExcerptMax] + "\n  … (truncated — [o] shows the full route JSON)"
		}
		fmt.Fprintf(c.out, "  route JSON:\n%s\n", indentLines(pretty, "    "))
	}
	if !it.RouteAckable {
		fmt.Fprintf(c.out, "  note: edge %q cannot stamp a path-addressed ack marker (manual marker only — docs/design/ack-marker.md)\n", it.Edge)
	}
}

// printTriageFullJSON handles the [o]pen action: the FULL raw route JSON from
// the driver when the locator resolves, else whatever bounded excerpt the read
// retained (declared as such — never silently the wrong thing).
func (c *cli) printTriageFullJSON(ctx context.Context, it core.TriageItem) {
	if s, err := c.engine.RouteJSON(ctx, it.Edge, it.Unparsed.Locator); err == nil {
		fmt.Fprintf(c.out, "%s\n", indentLines(s, "  "))
		return
	}
	if it.Unparsed.RawExcerpt != "" {
		fmt.Fprintf(c.out, "  (full JSON unavailable for this locator; bounded excerpt retained at read time:)\n%s\n", indentLines(prettyJSON(it.Unparsed.RawExcerpt), "  "))
		return
	}
	fmt.Fprintln(c.out, "  (no JSON evidence retained for this entry)")
}

// suggestAckReason derives a descriptive DEFAULT reason slug from the card's
// evidence: the recovered host's first label (when there is one) plus the
// why-unparsed kind, e.g. `vpn-matcher-conditional`. It is a starting point,
// not a judgment — the prompt invites the operator to replace it with WHY the
// route is acceptable; accepting the default still leaves a marker that names
// what was acked. Always returns a model.ValidAckReason-clean slug.
func suggestAckReason(it core.TriageItem, raw string) string {
	kind := strings.ToLower(strings.NewReplacer("_", "-", " ", "-").Replace(string(it.Unparsed.Kind)))
	if kind == "" {
		kind = "unmodeled-route"
	}
	host, _ := routeGlance(raw)
	if host == "" {
		return kind
	}
	label := strings.ToLower(strings.SplitN(host, ".", 2)[0])
	// A wildcard first label ("*") or anything else outside the marker grammar
	// falls back to the bare kind rather than emitting an invalid slug.
	if !model.ValidAckReason(label) {
		return kind
	}
	return label + "-" + kind
}

// triageRouteJSON prefers the driver's full raw route JSON (locator-resolved)
// and falls back to the entry's bounded RawExcerpt for edges/locators the
// driver cannot re-resolve.
func (c *cli) triageRouteJSON(ctx context.Context, it core.TriageItem) string {
	if s, err := c.engine.RouteJSON(ctx, it.Edge, it.Unparsed.Locator); err == nil {
		return s
	}
	return it.Unparsed.RawExcerpt
}

// routeGlance recovers the parts of a raw route crenel DOES understand — the
// first host matcher and the handler type names — so the card can anchor the
// operator ("this is your Jellyfin php_fastcgi block") before showing raw JSON.
// Best-effort: a truncated/invalid excerpt yields nothing, never an error.
func routeGlance(rawJSON string) (host string, handlers []string) {
	var rt struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
		Handle []struct {
			Handler string `json:"handler"`
		} `json:"handle"`
	}
	if json.Unmarshal([]byte(rawJSON), &rt) != nil {
		return "", nil
	}
	for _, m := range rt.Match {
		if len(m.Host) > 0 {
			host = strings.Join(m.Host, ",")
			break
		}
	}
	for _, h := range rt.Handle {
		if h.Handler != "" {
			handlers = append(handlers, h.Handler)
		}
	}
	return host, handlers
}

// prettyJSON re-indents a JSON string for display; input that is not valid
// JSON (e.g. a truncated excerpt ending in "…") is returned unchanged.
func prettyJSON(s string) string {
	var buf bytes.Buffer
	if json.Indent(&buf, []byte(s), "", "  ") != nil {
		return s
	}
	return buf.String()
}

// indentLines prefixes every line of s with prefix (card body indentation).
func indentLines(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// readLine reads one operator line, tolerating a final unterminated line at
// EOF (a scripted reader in tests, or a closed terminal).
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err == io.EOF {
		return line, nil
	}
	return line, err
}

// stdinIsTTY reports whether stdin is an interactive terminal — the gate that
// keeps triage out of pipes/CI. The stdinTTY seam lets tests script the flow;
// nil means the real check (mirroring the HUD's TTY detection: the kernel is
// asked, not the environment — ttySize's TIOCGWINSZ path is stdout-shaped, so
// stdin uses the same char-device stat isTTY() the color/header path trusts).
func (c *cli) stdinIsTTY() bool {
	if c.stdinTTY != nil {
		return c.stdinTTY()
	}
	if f, ok := c.in.(*os.File); ok {
		return isTTY(f)
	}
	return isTTY(os.Stdin)
}
