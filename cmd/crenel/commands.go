package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/redact"
	"github.com/crenelhq/crenel/internal/ui"
)

// dialTo is the net.Dial used by guardToReachable's pre-flight TCP probe. It is
// a var so tests can swap in a deterministic dialer (a table lookup) without
// touching real sockets. See guardToReachable.
var dialTo = func(addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial("tcp", addr)
}

// toReachableTimeout bounds the TCP probe. Short by design — this is the
// verify principle applied PRE-FLIGHT, not a health check; we only want to
// know a SYN gets answered. See guardToReachable.
const toReachableTimeout = 2 * time.Second

type cli struct {
	engine *core.Engine
	gf     *globalFlags
	// settings is the loaded settings snapshot, retained so the CLI can persist
	// operator-supplied origins from `expose --to <host:port>` back to the file
	// that produced them (settingsPath) — keeping the origins map coherent with
	// live for later `status`/`audit`/`drift`/`reconcile`. Empty settingsPath =>
	// no config file (`--to` cannot persist and refuses to apply).
	settings     config.Settings
	settingsPath string
	out          io.Writer
	errOut       io.Writer
	// in is the source for confirmation prompts; defaults to os.Stdin.
	in io.Reader
	// color enables ANSI color in branded output; tty reports whether stdout is
	// an interactive terminal (drives whether the status header shows by default).
	// Both default false, so non-interactive callers and tests get plain output.
	color bool
	tty   bool
}

func (c *cli) dispatch(ctx context.Context, verb string, args []string) error {
	if mutatingVerbs[verb] {
		unlock, err := acquireLock(lockPath(c.settingsPath))
		if err != nil {
			return err
		}
		defer unlock()
	}
	switch verb {
	case "status":
		return c.cmdStatus(ctx, args)
	case "audit":
		return c.cmdAudit(ctx)
	case "export":
		return c.cmdExport(ctx, args)
	case "preview":
		return c.cmdPreview(ctx, args)
	case "resume":
		return c.cmdResume(ctx, args)
	case "drift":
		return c.cmdDrift(ctx)
	case "reconcile":
		return c.cmdReconcile(ctx)
	case "import":
		return c.cmdImport(ctx, args)
	case "apply":
		return c.cmdApply(ctx, args)
	case "init":
		return c.cmdInit(args)
	case "expose":
		return c.cmdMutate(ctx, model.Expose, args)
	case "unexpose":
		return c.cmdMutate(ctx, model.Unexpose, args)
	case "set":
		return c.cmdSet(ctx, args)
	case "rename", "move":
		return c.cmdRename(ctx, args)
	case "ack":
		return c.cmdAck(ctx, args)
	case "unack":
		return c.cmdUnack(ctx, args)
	case "serve", "dashboard":
		return c.cmdServe(ctx, args)
	case "version", "-v", "--version":
		fmt.Fprintf(c.out, "%s %s\n", config.ToolName, version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `%s help`)", verb, "crenel")
	}
}

func (c *cli) cmdStatus(ctx context.Context, args []string) error {
	// Accept the status-surface flags after the verb too (`status --hud`), the
	// natural ordering, in addition to before it (`-hud status`).
	c.applyStatusFlags(args)
	rep, err := c.engine.Status(ctx)
	if err != nil {
		return err
	}
	// Redact secret bytes a declared-unknown excerpt may carry (an unmodeled
	// basic_auth/handler/server block is captured verbatim in RawExcerpt) before any
	// display, unless --show-secrets. The text listing does not print RawExcerpt, but
	// `status --json` serializes it — so the JSON path is the leak surface. The engine
	// builds a fresh report per call, so in-place redaction is safe. See SECURITY.md §6.
	c.redactStatus(&rep)
	if c.gf.jsonOut {
		return c.writeJSON(rep)
	}
	// Branded surface: the full HUD when requested, a compact colored header by
	// default on a terminal. Suppressed for -plain and when piped (no TTY), so
	// scriptable output stays clean. The detailed listing always follows.
	if !c.gf.plain && (c.tty || c.gf.showHUD()) {
		c.writeStatusBanner(ctx, rep)
	}
	c.writeStatusDetail(rep)
	return nil
}

// applyStatusFlags lets the status-surface flags appear after the verb
// (`status --hud`), matching the documented usage, since the global flag parser
// only sees flags before the verb.
func (c *cli) applyStatusFlags(args []string) {
	for _, a := range args {
		switch a {
		case "-hud", "--hud", "-banner", "--banner":
			c.gf.hud = true
		case "-plain", "--plain":
			c.gf.plain = true
		case "-json", "--json":
			c.gf.jsonOut = true
		}
	}
}

// writeStatusBanner draws the HUD header (compact) or full banner (-hud/-banner),
// wired to real status data. Drift is read live (read-only); if that read fails,
// the field degrades to "unknown" rather than failing the whole status.
func (c *cli) writeStatusBanner(ctx context.Context, rep core.StatusReport) {
	drift := -1
	if plan, derr := c.engine.DetectDrift(ctx); derr == nil {
		drift = len(plan.Drift)
	}
	m := hudModelFromStatus(rep, drift)
	st := ui.Style{Color: c.color, Cols: termCols(c.gf)}
	if c.gf.showHUD() {
		st.WriteHUD(c.out, m)
	} else {
		st.WriteHeader(c.out, m)
	}
	fmt.Fprintln(c.out)
}

// writeStatusDetail prints the per-edge + per-scope listing (the scriptable body).
func (c *cli) writeStatusDetail(rep core.StatusReport) {
	for _, es := range rep.Edges {
		// Header — annotate a foreign-managed edge / off-edge ingress so a partial,
		// not-fully-ownable edge can never read as an ordinary clean one.
		header := fmt.Sprintf("Edge [%s·%s]", es.Name, es.Driver)
		if es.Generator != "" {
			header += fmt.Sprintf("   ⚠ FOREIGN-MANAGED (%s)", es.Generator)
		}
		if es.IngressKind.External() {
			header += fmt.Sprintf("   INGRESS: %s", es.IngressKind)
		}
		fmt.Fprintln(c.out, header)

		// Coverage line — never present a partial parse as a complete one (register §4.2).
		// An operator-ACKNOWLEDGED unknown (docs/design/ack-marker.md) does not count
		// against coverage — it's excluded from both the "not understood" count here and
		// FullyParsed/DenyState.
		understood, total := es.Coverage()
		acked := es.Acknowledged()
		if !es.FullyParsed() {
			fmt.Fprintf(c.out, "  Coverage: read %d/%d routes — %d NOT UNDERSTOOD — exposure status INCOMPLETE\n",
				understood, total-len(acked), len(es.Unparsed)-len(acked))
		}

		// Default-deny — TERNARY (register §4.4): ENFORCED only when fully parsed.
		switch es.DenyState() {
		case model.DenyEnforced:
			fmt.Fprintln(c.out, "  Default-deny catch-all: ENFORCED")
		case model.DenyUnknown:
			fmt.Fprintf(c.out, "  Default-deny catch-all: UNKNOWN (config not fully parsed — %d unparsed)\n", len(es.Unparsed)-len(acked))
		default:
			fmt.Fprintln(c.out, "  Default-deny catch-all: MISSING  ⚠ FAIL-OPEN")
		}

		// Durability — declare whether a write to this edge survives a control-plane
		// restart (the persistence-model net). Surfaced for any classified edge; an
		// ephemeral edge is flagged so a write is never silently lost on restart.
		if es.Persistence.Classified() {
			if es.Persistence.EphemeralWrites() {
				fmt.Fprintf(c.out, "  Durability: %s  ⚠ writes are LIVE-only — a control-plane restart DROPS them (no durable persist configured)\n", es.Persistence)
			} else {
				fmt.Fprintf(c.out, "  Durability: %s (writes survive a restart)\n", es.Persistence)
			}
		}

		if len(es.Routes) == 0 {
			fmt.Fprintln(c.out, "  Exposed: (nothing)")
		} else {
			label := "Exposed"
			if !es.FullyParsed() {
				label = "Exposed (understood)"
			}
			fmt.Fprintf(c.out, "  %s (%d):\n", label, len(es.Routes))
			for _, r := range es.Routes {
				fmt.Fprintf(c.out, "    %-32s -> %s%s%s\n", r.Host, chainDest(r), modeTag(r.Upstream.Mode), authTag(r.Upstream.Auth))
			}
		}

		// ⚠ Not understood — the first-class unknowns section (register §4.2). An
		// acknowledged unknown (docs/design/ack-marker.md) gets its own ACK line
		// instead — a third state: not verified-green, not an unaddressed unknown.
		var notUnderstood []model.Unparsed
		for _, u := range es.Unparsed {
			if u.Kind != model.UnknownAcknowledged {
				notUnderstood = append(notUnderstood, u)
			}
		}
		if len(notUnderstood) > 0 {
			fmt.Fprintf(c.out, "  ⚠ Not understood (%d):\n", len(notUnderstood))
			for _, u := range notUnderstood {
				fmt.Fprintf(c.out, "    %-44s %s — %s\n", u.Locator, u.Kind, u.Reason)
			}
		}
		if len(acked) > 0 {
			fmt.Fprintf(c.out, "  ACK — acknowledged by operator (%d, not blocking default-deny):\n", len(acked))
			for _, u := range acked {
				fmt.Fprintf(c.out, "    %-44s %s\n", u.Locator, u.Reason)
			}
		}
		if es.Generator != "" {
			fmt.Fprintf(c.out, "  ⚠ Not crenel-ownable: edge is generated by %s — manage it at the source.\n", es.Generator)
		}
		if es.IngressKind.External() {
			reach := string(es.IngressKind)
			if es.IngressKind == model.IngressUnknown {
				reach = "an EXTERNAL ingress crenel could not classify"
			}
			fmt.Fprintf(c.out, "  ⚠ Reachability via %s — a host may be PUBLIC even if the proxy binds localhost; public/private is UNKNOWN to crenel.\n", reach)
		}
	}
	for _, sr := range rep.DNS {
		fmt.Fprintf(c.out, "DNS [%s/%s] (%d records):\n", sr.Provider, sr.Scope, len(sr.Records))
		for _, rec := range sr.Records {
			fmt.Fprintf(c.out, "  %-8s %-32s %s\n", rec.Type, rec.Name, rec.Value)
		}
	}
}

// hudModelFromStatus derives the HUD view-model from a read-only StatusReport (+
// a drift count). Every field maps to a real domain concept; the "public" count
// mirrors core's notion of publicness (a public-scope DNS record, or — when no
// public DNS is managed — a non-mesh edge route).
func hudModelFromStatus(rep core.StatusReport, drift int) ui.HUDModel {
	exposed := map[string]bool{}
	mesh := map[string]bool{}
	failOpen := map[string]bool{} // host sits on an edge whose default-deny is MISSING
	denyEnforced := len(rep.Edges) > 0
	denyUnknown := false
	unparsed := 0
	var edges []ui.EdgeRef
	for _, es := range rep.Edges {
		edges = append(edges, ui.EdgeRef{Name: es.Name, Driver: es.Driver})
		unparsed += len(es.Unparsed)
		// Ternary deny across edges: any MISSING => not enforced (FAIL-OPEN wins, red);
		// else any UNKNOWN => UNKNOWN (amber); else ENFORCED (green). A present-but-
		// uncertifiable edge must never let the HUD read green ENFORCED.
		edgeFailOpen := es.DenyState() == model.DenyMissing
		switch es.DenyState() {
		case model.DenyMissing:
			denyEnforced = false
		case model.DenyUnknown:
			denyUnknown = true
		}
		for _, r := range es.Routes {
			h := strings.ToLower(r.Host)
			exposed[h] = true
			if r.Upstream.Mode == model.ModeMeshGrant {
				mesh[h] = true
			}
			if edgeFailOpen {
				failOpen[h] = true
			}
		}
	}
	// UNKNOWN only displaces ENFORCED, never FAIL-OPEN: if some edge is fail-open the
	// HUD must show red, so suppress the amber when deny is genuinely missing.
	if !denyEnforced {
		denyUnknown = false
	}

	seenScope := map[model.Scope]bool{}
	hasPublicDNS := false
	for _, sr := range rep.DNS {
		seenScope[sr.Scope] = true
		if sr.Scope == model.ScopePublic {
			hasPublicDNS = true
		}
	}
	var scopes []string
	for _, sc := range []model.Scope{model.ScopeInternal, model.ScopePublic} {
		if seenScope[sc] {
			scopes = append(scopes, string(sc))
		}
	}

	public := map[string]bool{}
	if hasPublicDNS {
		for _, sr := range rep.DNS {
			if sr.Scope != model.ScopePublic {
				continue
			}
			for _, rec := range sr.Records {
				if h := strings.ToLower(rec.Name); exposed[h] {
					public[h] = true
				}
			}
		}
	} else {
		// No public DNS managed: the edge is the public boundary, so every non-mesh
		// edge route is a public exposure (mirrors core.computeNewPublic).
		for h := range exposed {
			if !mesh[h] {
				public[h] = true
			}
		}
	}

	// Per-host rows for the battlement banner's crenel gaps, classified with the SAME
	// rules as the counts: fail-open (red) wins, else public (amber), else private/safe
	// (green). Sorted by severity then name in the ui layer for a deterministic wall.
	var hosts []ui.WallHost
	for h := range exposed {
		role := ui.Safe
		switch {
		case failOpen[h]:
			role = ui.Fail
		case public[h]:
			role = ui.Warn
		}
		hosts = append(hosts, ui.WallHost{Name: h, Role: role})
	}
	ui.SortWallHosts(hosts)

	return ui.HUDModel{
		Exposed:      len(exposed),
		Public:       len(public),
		DenyEnforced: denyEnforced,
		DenyUnknown:  denyUnknown,
		Unparsed:     unparsed,
		Drift:        drift,
		Edges:        edges,
		DNSScopes:    scopes,
		LastApply:    "unknown", // no persisted desired state — live is the only truth
		Hosts:        hosts,
	}
}

func (c *cli) cmdAudit(ctx context.Context) error {
	rep, err := c.engine.Audit(ctx)
	if err != nil {
		return err
	}
	if c.gf.jsonOut {
		if err := c.writeJSON(rep); err != nil {
			return err
		}
	} else {
		for _, f := range rep.Findings {
			mark := map[string]string{"ok": "✓", "warning": "▲", "critical": "✗"}[f.Severity]
			fmt.Fprintf(c.out, "%s [%s] %s\n", mark, strings.ToUpper(f.Severity), f.Message)
		}
	}
	if rep.HasCritical() {
		return fmt.Errorf("audit found critical findings")
	}
	return nil
}

func (c *cli) cmdExport(ctx context.Context, args []string) error {
	var file string
	redacted := false
	for _, a := range args {
		switch a {
		case "-redacted", "--redacted":
			redacted = true
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("export: unknown flag %q", a)
			}
			file = a
		}
	}
	if file == "" {
		return fmt.Errorf("export requires a destination file (usage: export <file> [--redacted])")
	}

	snap, err := c.engine.ExportSnapshotData(ctx)
	if err != nil {
		return err
	}
	// --redacted writes a secret-FREE copy for sharing: scrub the secret-bearing
	// declared-unknown excerpts. The DEFAULT export keeps REAL values so it is a
	// faithful record (a redacted snapshot is not a restore-grade backup). See
	// SECURITY.md §6.
	if redacted {
		redactSnapshot(&snap)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("export: marshal snapshot: %w", err)
	}
	// 0600: an export can hold REAL secrets (an excerpt may carry an auth header/hash),
	// so it is operator-readable only — never world/group readable.
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	note := "contains REAL secrets — keep private (0600)"
	if redacted {
		note = "secrets redacted — safe to share"
	}
	fmt.Fprintf(c.out, "exported live state to %s (%d bytes, mode 0600) — throwaway snapshot, never read back; %s\n", file, len(data), note)
	return nil
}

func (c *cli) cmdPreview(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: preview <expose|unexpose> <service>  |  preview rename <old-host> <new-host>")
	}
	// preview rename <old> <new>: show the atomic move without applying.
	if args[0] == "rename" || args[0] == "move" {
		if len(args) < 3 {
			return fmt.Errorf("usage: preview rename <old-host> <new-host>")
		}
		cs, err := c.engine.PlanRename(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		if c.gf.jsonOut {
			return c.writeJSON(cs)
		}
		c.printChangeSet(cs)
		return nil
	}
	verb, err := parseVerb(args[0])
	if err != nil {
		return err
	}
	op, err := c.buildOp(verb, args[1])
	if err != nil {
		return err
	}
	cs, err := c.engine.Plan(ctx, op)
	if err != nil {
		return err
	}
	if c.gf.jsonOut {
		return c.writeJSON(cs)
	}
	c.printChangeSet(cs)
	return nil
}

// buildOp constructs the op and applies the -mode / -param intent from flags.
func (c *cli) buildOp(verb model.Verb, service string) (model.Op, error) {
	op := c.engine.BuildOp(verb, service)
	mode, err := parseMode(c.gf.mode)
	if err != nil {
		return op, err
	}
	op.Mode = mode
	op.Auth = c.gf.auth
	if c.gf.to != "" {
		if verb != model.Expose {
			return op, fmt.Errorf("--to is only valid with `expose` (got %s)", verb)
		}
		op.To = c.gf.to
	}
	if len(c.gf.params) > 0 {
		op.Params = map[string]string{}
		for _, kv := range c.gf.params {
			k, v, _ := strings.Cut(kv, "=")
			op.Params[k] = v
		}
	}
	return op, nil
}

// cmdResume re-drives an interrupted apply: it diagnoses which providers already
// match the intended state and completes the rest (or rolls back cleanly).
func (c *cli) cmdResume(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: resume <expose|unexpose> <service>")
	}
	verb, err := parseVerb(args[0])
	if err != nil {
		return err
	}
	op, err := c.buildOp(verb, args[1])
	if err != nil {
		return err
	}
	rr, err := c.engine.Resume(ctx, op, c.confirmFunc())
	if err != nil {
		c.printResume(rr)
		return err
	}
	c.printResume(rr)
	return nil
}

func (c *cli) printResume(rr core.ResumeReport) {
	fmt.Fprintf(c.out, "Resume: %s\n", rr.Op)
	if len(rr.Already) > 0 {
		fmt.Fprintf(c.out, "  already in intended state: %s\n", strings.Join(rr.Already, ", "))
	}
	if rr.NothingToDo {
		fmt.Fprintln(c.out, "  nothing to resume — every provider is already consistent")
		return
	}
	fmt.Fprintf(c.out, "  completing: %s\n", strings.Join(rr.Pending, ", "))
	c.printApplyReport(rr.Apply)
}

// cmdDrift is the read-only counterpart of reconcile: it reports divergence from
// the canonical exposed set without mutating anything, and exits non-zero when
// drift exists — so it slots into CI/cron (`crenel drift || alert`).
func (c *cli) cmdDrift(ctx context.Context) error {
	plan, err := c.engine.DetectDrift(ctx)
	if err != nil {
		return err
	}
	if c.gf.jsonOut {
		if err := c.writeJSON(plan); err != nil {
			return err
		}
	} else {
		c.printReconcilePlan(plan)
	}
	if !plan.Empty() {
		return fmt.Errorf("drift detected: %d item(s) diverge from the canonical exposed set (run `reconcile` to converge)", len(plan.Drift))
	}
	return nil
}

// cmdReconcile detects and fixes ALL drift across every edge + DNS provider,
// converging them onto the canonical currently-exposed set. Preview-then-confirm
// like the other mutating verbs (honors --yes).
func (c *cli) cmdReconcile(ctx context.Context) error {
	rep, err := c.engine.Reconcile(ctx, c.reconcileConfirm())
	if err != nil && c.confirmUnverifiedOverride(err) {
		c.engine.AllowUnverified = true
		rep, err = c.engine.Reconcile(ctx, core.AlwaysYesReconcile)
	}
	if c.gf.jsonOut && err == nil {
		return c.writeJSON(rep)
	}
	c.printReconcile(rep)
	return err
}

// reconcileConfirm returns AlwaysYesReconcile when --yes, else an interactive
// prompt that previews the drift + corrective change and reads y/N.
func (c *cli) reconcileConfirm() core.ReconcileConfirmFunc {
	if c.gf.yes {
		return core.AlwaysYesReconcile
	}
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	reader := bufio.NewReader(in)
	return func(p core.ReconcilePlan) (bool, error) {
		c.printReconcilePlan(p)
		fmt.Fprint(c.out, "\nApply this reconcile? [y/N]: ")
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		return ans == "y" || ans == "yes", nil
	}
}

// printReconcilePlan renders the detected drift and the corrective change.
func (c *cli) printReconcilePlan(p core.ReconcilePlan) {
	fmt.Fprintln(c.out, "Reconcile — converge every edge + DNS onto the canonical exposed set:")
	if p.Empty() {
		fmt.Fprintln(c.out, "  (no drift — already consistent)")
		return
	}
	for _, d := range p.Drift {
		fmt.Fprintf(c.out, "  drift [%s] %s @ %s — %s\n", d.Kind, d.Host, d.Target, d.Detail)
	}
	for _, ep := range p.Change.Edges {
		if ep.Change.Empty() {
			continue
		}
		fmt.Fprintf(c.out, "  EDGE [%s·%s]\n", ep.Edge, ep.Driver)
		for _, h := range ep.Change.RemoveHosts {
			fmt.Fprintf(c.out, "    - route   %s\n", h)
		}
		for _, r := range ep.Change.AddRoutes {
			fmt.Fprintf(c.out, "    + route   %-32s -> %s%s%s\n", r.Host, r.Upstream.Address, modeTag(r.Upstream.Mode), authTag(r.Upstream.Auth))
		}
	}
	c.printDNSScope(p.Change, model.ScopeInternal, "INTERNAL DNS")
	c.printDNSScope(p.Change, model.ScopePublic, "PUBLIC DNS")
}

// printReconcile renders the outcome of a reconcile run.
func (c *cli) printReconcile(rep core.ReconcileReport) {
	if rep.Converged {
		fmt.Fprintln(c.out, "reconcile: already consistent — no drift across edges or DNS")
		return
	}
	if rep.RolledBack {
		fmt.Fprintln(c.out, "ROLLED BACK: reconcile reverted to prior live state")
		for _, e := range c.redactLines(rep.RollbackErrors) {
			fmt.Fprintf(c.out, "  ⚠ rollback error: %s\n", e)
		}
		if rep.RecoveryHint != "" {
			fmt.Fprintf(c.out, "  hint: %s\n", rep.RecoveryHint)
		}
		return
	}
	if !rep.Applied {
		fmt.Fprintln(c.out, "aborted: no changes applied")
		return
	}
	fmt.Fprintf(c.out, "reconciled: fixed %d drift item(s)\n", len(rep.Plan.Drift))
	for _, v := range rep.Verify {
		mark := "✓"
		if !v.OK {
			mark = "✗"
		}
		fmt.Fprintf(c.out, "  read-back %s [%s] %s\n", mark, v.Provider, v.Detail)
	}
	if rep.Verified() {
		fmt.Fprintln(c.out, "  verified: live state matches the canonical exposed set")
	}
	c.printPersistWarnings(rep.PersistWarnings)
}

// starterSettings is the scaffold written by `crenel init` for the providers /
// topology file (the -config file).
const starterSettings = `# crenel settings — providers & topology.
# This is NOT desired state: what is exposed is always read LIVE. These fields
# only say WHERE the providers are and how to talk to them.
edge_driver: caddy            # caddy | traefik | nginx | netbird
granular_apply: true          # additive admin-API writes (required for a real edge)
admin_url: http://127.0.0.1:2019
zone: example.com

# Origins: the service -> backend map. A service here is also what crenel will
# adopt/manage; "import" brings any existing route for one of these under management.
origins:
  grafana: 10.0.0.5:3000
  # photos: 10.0.0.6:2342

# Survive a Caddy restart by mirroring managed routes to the mounted Caddyfile:
# caddy_persist_path: /etc/caddy/Caddyfile

# Forward-auth policies (attach with --auth <name> or auth: in exposures). crenel
# renders a REFERENCE per edge; YOU own the snippet/middleware/location. Defaults
# apply when omitted (Caddy import <name>, Traefik <name>@file, nginx /<name>).
# auth_policies:
#   authelia:
#     caddy_forward_auth: authelia:9091    # or caddy_import: authelia
#     traefik_middleware: authelia@file
#     nginx_auth_request: /authelia

# Split-horizon DNS (optional). "mock: true" is the safe, no-infra demo path.
# dns:
#   enabled: true
#   providers:
#     - {scope: internal, zone: example.com, edge_addr: 10.0.0.1, mock: true}
#     - {scope: public, zone: example.com, edge_addr: 203.0.113.10, mock: true}
`

// starterExposures is the scaffold written by `crenel init` for the declarative
// apply file.
const starterExposures = `# crenel apply file — desired exposures.
# A point-in-time assertion (applied on demand with "crenel apply <file>"), NOT a
# watched mirror: live stays the truth and nothing here is stored as source-of-truth.
zone: example.com
exposures:
  - host: grafana.example.com
    service: grafana
    # auth: authelia           # attach a forward-auth policy (see auth_policies)
  # - service: photos          # host derived as photos.<zone>
  #   auth: none               # publish unprotected ON PURPOSE (required if public)
`

// cmdInit scaffolds a starter settings + exposures file to bootstrap a new setup.
// It refuses to overwrite existing files. An optional arg sets the directory.
func (c *cli) cmdInit(args []string) error {
	dir := "."
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			dir = a
		}
	}
	files := []struct {
		path, body string
	}{
		{filepath.Join(dir, "crenel.settings.yaml"), starterSettings},
		{filepath.Join(dir, "crenel.exposures.yaml"), starterExposures},
	}
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			return fmt.Errorf("init: %s already exists (refusing to overwrite)", f.path)
		}
		if err := os.WriteFile(f.path, []byte(f.body), 0o644); err != nil {
			return fmt.Errorf("init: write %s: %w", f.path, err)
		}
		fmt.Fprintf(c.out, "wrote %s\n", f.path)
	}
	fmt.Fprintf(c.out, `
Next steps (brownfield-safe):
  1. Edit crenel.settings.yaml — set edge_driver, admin_url/path, and your origins.
  2. crenel -config crenel.settings.yaml status        # see what's live right now
  3. crenel -config crenel.settings.yaml import --dry-run   # what crenel would adopt
  4. crenel -config crenel.settings.yaml import        # adopt your existing setup
  5. crenel -config crenel.settings.yaml apply crenel.exposures.yaml --dry-run
  6. crenel -config crenel.settings.yaml apply crenel.exposures.yaml
`)
	return nil
}

// applyDoc is the declarative apply file: an optional zone plus the desired
// exposures set. It decodes from JSON or YAML (config.DecodeFile picks).
type applyDoc struct {
	Zone      string          `json:"zone,omitempty"`
	Exposures []core.Exposure `json:"exposures"`
}

// cmdApply applies a declarative exposures file (kubectl-style): diff vs live →
// preview ("about to go public" highlighted) → all-or-nothing apply → read-back-
// verify. Flags (after the file): --adopt (adopt matching unmanaged hosts inline),
// --prune (unexpose owned hosts absent from the file), --dry-run (preview only).
// See USABILITY-DESIGN.md §C.
func (c *cli) cmdApply(ctx context.Context, args []string) error {
	var file string
	var opts core.DeclarativeOptions
	dryRun := false
	for _, a := range args {
		switch a {
		case "-adopt", "--adopt":
			opts.Adopt = true
		case "-prune", "--prune":
			opts.Prune = true
		case "-dry-run", "--dry-run":
			dryRun = true
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("apply: unknown flag %q", a)
			}
			file = a
		}
	}
	if file == "" {
		return fmt.Errorf("usage: apply <file.yaml> [--adopt] [--prune] [--dry-run]")
	}
	var doc applyDoc
	if err := config.DecodeFile(file, &doc); err != nil {
		return fmt.Errorf("apply: read %s: %w", file, err)
	}
	if len(doc.Exposures) == 0 {
		return fmt.Errorf("apply: %s declares no exposures", file)
	}

	if dryRun {
		plan, err := c.engine.PlanDeclarative(ctx, doc.Exposures, opts)
		if err != nil {
			return err
		}
		if c.gf.jsonOut {
			return c.writeJSON(plan)
		}
		c.printDeclarativePlan(plan)
		return nil
	}

	if err := c.guardDeclarativePublicAuth(ctx, doc.Exposures, opts); err != nil {
		return err
	}
	rep, err := c.engine.ApplyDeclarative(ctx, doc.Exposures, opts, c.confirmFunc())
	if err != nil && c.confirmUnverifiedOverride(err) {
		c.engine.AllowUnverified = true
		rep, err = c.engine.ApplyDeclarative(ctx, doc.Exposures, opts, core.AlwaysYes)
	}
	if c.gf.jsonOut && err == nil {
		return c.writeJSON(rep)
	}
	c.printDeclarative(rep)
	return err
}

// guardDeclarativePublicAuth applies the same public-without-auth guardrail to a
// declarative apply: any exposure that would make its host PUBLIC must carry an
// explicit auth choice (a policy, or auth: none) in the file. Mirrors
// guardPublicAuth; the explicit choice lives in the exposure's `auth:` field.
func (c *cli) guardDeclarativePublicAuth(ctx context.Context, exposures []core.Exposure, opts core.DeclarativeOptions) error {
	plan, err := c.engine.PlanDeclarative(ctx, exposures, opts)
	if err != nil {
		return nil // let ApplyDeclarative re-plan and surface the error
	}
	if len(plan.NewPublic) == 0 {
		return nil
	}
	authByHost := map[string]string{}
	for _, ex := range exposures {
		host := ex.Host
		if host == "" {
			host = c.engine.BuildOp(model.Expose, ex.Service).Host
		}
		authByHost[strings.ToLower(host)] = ex.Auth
	}
	var offenders []string
	for _, h := range plan.NewPublic {
		if authByHost[strings.ToLower(h)] == "" {
			offenders = append(offenders, h)
		}
	}
	if len(offenders) > 0 {
		return fmt.Errorf("refusing to expose %s PUBLIC with no auth — set `auth: <policy>` on the exposure to protect it, "+
			"or `auth: none` to publish it unprotected on purpose", strings.Join(offenders, ", "))
	}
	return nil
}

// printDeclarativePlan renders the declarative diff: adoptions, the layered
// change (reusing printChangeSet), prunes, and any blocking conflicts.
func (c *cli) printDeclarativePlan(p core.DeclarativePlan) {
	fmt.Fprintln(c.out, "Apply — converge the managed set to the file (a point-in-time assertion):")
	for _, a := range p.Adopt {
		fmt.Fprintf(c.out, "  ~ adopt   %-32s -> %s%s   [%s·%s]\n", a.Host, a.Address, modeTag(a.Mode), a.Edge, a.Driver)
	}
	for _, h := range p.Prune {
		fmt.Fprintf(c.out, "  - prune   %s\n", h)
	}
	if len(p.Blocked) > 0 {
		for _, b := range p.Blocked {
			fmt.Fprintf(c.out, "  ✗ blocked %-31s [%s·%s] %s — %s\n", b.Host, b.Edge, b.Driver, b.Reason, b.Detail)
		}
		fmt.Fprintln(c.out, "  (run `crenel import` first, or apply --adopt, to proceed)")
	}
	cs := p.Change
	cs.NewPublic = p.NewPublic
	if cs.Empty() && len(p.Adopt) == 0 && len(p.Prune) == 0 {
		fmt.Fprintln(c.out, "  (already converged — live matches the file)")
		return
	}
	c.printChangeBody(cs)
}

// printDeclarative renders the outcome of an apply run.
func (c *cli) printDeclarative(rep core.DeclarativeReport) {
	if rep.RolledBack {
		fmt.Fprintln(c.out, "ROLLED BACK: apply reverted to prior live state")
		for _, e := range c.redactLines(rep.RollbackErrors) {
			fmt.Fprintf(c.out, "  ⚠ rollback error: %s\n", e)
		}
		if rep.RecoveryHint != "" {
			fmt.Fprintf(c.out, "  hint: %s\n", rep.RecoveryHint)
		}
		return
	}
	if !rep.Applied {
		if rep.Plan.Empty() {
			fmt.Fprintln(c.out, "apply: already converged — live matches the file")
		} else {
			fmt.Fprintln(c.out, "aborted: no changes applied")
		}
		return
	}
	fmt.Fprintf(c.out, "applied: %d adopted, %d edge-change(s), %d pruned\n",
		len(rep.Plan.Adopt), len(rep.Plan.Change.Edges), len(rep.Plan.Prune))
	for _, v := range rep.Verify {
		mark := "✓"
		if !v.OK {
			mark = "✗"
		}
		fmt.Fprintf(c.out, "  read-back %s [%s] %s\n", mark, v.Provider, v.Detail)
	}
	if rep.Verified() {
		fmt.Fprintln(c.out, "  verified: live state matches the file")
	}
	c.printPersistWarnings(rep.PersistWarnings)
}

// cmdImport adopts a pre-existing (brownfield) setup: it scans live, previews the
// unmanaged-but-matching routes it would bring under management, and (on confirm,
// or --yes) stamps ownership markers in-place without changing behavior. With
// --dry-run it only previews (and exits non-zero if anything is adoptable, for
// CI). See USABILITY-DESIGN.md §A.
func (c *cli) cmdImport(ctx context.Context, args []string) error {
	dryRun := false
	for _, a := range args {
		if a == "-dry-run" || a == "--dry-run" {
			dryRun = true
		}
	}
	if dryRun {
		plan, err := c.engine.DetectImport(ctx)
		if err != nil {
			return err
		}
		if c.gf.jsonOut {
			if err := c.writeJSON(plan); err != nil {
				return err
			}
		} else {
			c.printImportPlan(plan)
		}
		if !plan.Empty() {
			return fmt.Errorf("import dry-run: %d route(s) are adoptable (run `crenel import` to adopt)", len(plan.Adopt))
		}
		return nil
	}
	rep, err := c.engine.Import(ctx, c.importConfirm())
	if c.gf.jsonOut && err == nil {
		return c.writeJSON(rep)
	}
	c.printImport(rep)
	return err
}

// importConfirm returns AlwaysYesImport when --yes, else an interactive prompt
// that previews the adoptions and reads y/N.
func (c *cli) importConfirm() core.ImportConfirmFunc {
	if c.gf.yes {
		return core.AlwaysYesImport
	}
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	reader := bufio.NewReader(in)
	return func(p core.ImportPlan) (bool, error) {
		c.printImportPlan(p)
		fmt.Fprint(c.out, "\nAdopt these routes (ownership only — no behavior change)? [y/N]: ")
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		return ans == "y" || ans == "yes", nil
	}
}

// printImportPlan renders the import scan: what would be adopted, conflicts, and
// already-managed hosts.
func (c *cli) printImportPlan(p core.ImportPlan) {
	fmt.Fprintln(c.out, "Import — bring a pre-existing setup under management (ownership only, no behavior change):")
	if len(p.Adopt) == 0 && len(p.Conflicts) == 0 {
		if len(p.AlreadyManaged) > 0 {
			fmt.Fprintf(c.out, "  (nothing to adopt — %d host(s) already managed)\n", len(p.AlreadyManaged))
		} else {
			fmt.Fprintln(c.out, "  (nothing to adopt — no unmanaged routes in the managed domain)")
		}
		return
	}
	for _, a := range p.Adopt {
		fmt.Fprintf(c.out, "  + adopt   %-32s -> %s%s   [%s·%s]\n", a.Host, a.Address, modeTag(a.Mode), a.Edge, a.Driver)
	}
	for _, cf := range p.Conflicts {
		fmt.Fprintf(c.out, "  ⚠ conflict %-31s [%s·%s] %s — %s\n", cf.Host, cf.Edge, cf.Driver, cf.Reason, cf.Detail)
	}
	if len(p.AlreadyManaged) > 0 {
		fmt.Fprintf(c.out, "  (%d already managed: %s)\n", len(p.AlreadyManaged), strings.Join(p.AlreadyManaged, ", "))
	}
}

// printImport renders the outcome of an import run.
func (c *cli) printImport(rep core.ImportReport) {
	if rep.Plan.Empty() && !rep.Adopted {
		c.printImportPlan(rep.Plan)
		return
	}
	if !rep.Adopted {
		fmt.Fprintln(c.out, "aborted: nothing adopted")
		return
	}
	fmt.Fprintf(c.out, "imported: adopted %d route(s) under management\n", len(rep.Plan.Adopt))
	for _, v := range rep.Verify {
		mark := "✓"
		if !v.OK {
			mark = "✗"
		}
		fmt.Fprintf(c.out, "  read-back %s [%s] %s\n", mark, v.Provider, v.Detail)
	}
	if rep.Verified() {
		fmt.Fprintln(c.out, "  verified: routes now managed, runtime behavior unchanged")
	}
}

func (c *cli) cmdMutate(ctx context.Context, verb model.Verb, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s <service>", verb)
	}
	op, err := c.buildOp(verb, args[0])
	if err != nil {
		return err
	}
	return c.applyOp(ctx, op)
}

// cmdRename moves a service from <old-host> to <new-host> as ONE atomic, durable,
// read-back-verified transaction (add new + remove old), copying the source route's exact
// backend / mode / upstream-TLS / auth. See core.Rename.
func (c *cli) cmdRename(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: rename <old-host> <new-host>")
	}
	rep, err := c.engine.Rename(ctx, args[0], args[1], c.confirmFunc())
	if err != nil && c.confirmUnverifiedOverride(err) {
		c.engine.AllowUnverified = true
		rep, err = c.engine.Rename(ctx, args[0], args[1], core.AlwaysYes)
	}
	if err != nil {
		c.printApplyReport(rep)
		return err
	}
	c.printApplyReport(rep)
	return nil
}

// cmdAck stamps the operator's crenel-ack:<reason> marker (docs/design/
// ack-marker.md) onto a declared-unknown route for host, in the live config
// itself — no sidecar store, generalizing the crenel-route ownership marker.
// Requires --reason. Only the Caddy driver implements ports.Acker today;
// Traefik/nginx recognize a hand-written marker on read but crenel cannot yet
// stamp it for them — the error says so.
func (c *cli) cmdAck(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: ack <host> --reason <slug>")
	}
	if c.gf.reason == "" {
		return fmt.Errorf("ack %s: --reason is required (the crenel-ack:<reason> slug — see docs/design/ack-marker.md)", args[0])
	}
	if err := c.engine.Ack(ctx, args[0], c.gf.reason); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "acknowledged: %s (reason: %s) — no longer blocks default-deny; still listed as ACK in status/audit\n", args[0], c.gf.reason)
	return nil
}

// cmdUnack removes the crenel-ack marker from host's route, reverting it to
// whatever Unparsed kind it would otherwise classify as. A no-op if host was
// not currently ack'd.
func (c *cli) cmdUnack(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: unack <host>")
	}
	if err := c.engine.Unack(ctx, args[0]); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "unacknowledged: %s\n", args[0])
	return nil
}

func (c *cli) cmdSet(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: set <service> <on|off>")
	}
	var verb model.Verb
	switch strings.ToLower(args[1]) {
	case "on", "true", "expose", "1":
		verb = model.Expose
	case "off", "false", "unexpose", "0":
		verb = model.Unexpose
	default:
		return fmt.Errorf("set: state must be on|off, got %q", args[1])
	}
	op, err := c.buildOp(verb, args[0])
	if err != nil {
		return err
	}
	return c.applyOp(ctx, op)
}

func (c *cli) applyOp(ctx context.Context, op model.Op) error {
	if err := c.guardPublicAuth(ctx, op); err != nil {
		return err
	}
	if err := c.guardPersistOrigin(op); err != nil {
		return err
	}
	if err := c.guardToReachable(op); err != nil {
		return err
	}
	confirm := c.confirmFunc()
	rep, err := c.engine.Apply(ctx, op, confirm)
	if err != nil && c.confirmUnverifiedOverride(err) {
		c.engine.AllowUnverified = true
		rep, err = c.engine.Apply(ctx, op, core.AlwaysYes)
	}
	if err != nil {
		// Even on verification failure, show what we attempted.
		c.printApplyReport(rep)
		return err
	}
	c.printApplyReport(rep)
	if op.Verb == model.Expose && op.To != "" {
		if perr := config.SetTopLevelOrigin(c.settingsPath, op.Service, op.To); perr != nil {
			return fmt.Errorf("route applied but origins persistence failed: %w — add `%s: %s` to origins in %s manually so status/drift/reconcile stay coherent",
				perr, op.Service, op.To, c.settingsPath)
		}
		fmt.Fprintf(c.out, "persisted origin: %s -> %s in %s\n", op.Service, op.To, c.settingsPath)
	}
	return nil
}

// guardToReachable is the VERIFY PRINCIPLE APPLIED PRE-FLIGHT: before we write
// a route pointing at the operator-supplied --to address, do a bounded TCP
// probe and refuse to apply if nothing answers. This is not a health check
// (no L7 probe, no auth), just "is something listening at this host:port".
// The address the operator typed is the ONLY thing we probe — no discovery,
// no enumeration, no suggestions from crenel's own view of the network.
//
// The guiding error names the three common shapes operators get wrong (a
// container name on the proxy's docker network vs. a LAN IP vs. loopback)
// so a fresh-config first-run doesn't dead-end on a cryptic dial error.
// `--no-validate` skips the probe for the legit case where the backend is
// known-correct but not up yet (validate by default, allow override). See
// AUTH-DESIGN's default-deny discipline sibling: crenel never writes a route
// to a silently-wrong backend.
func (c *cli) guardToReachable(op model.Op) error {
	if op.Verb != model.Expose || op.To == "" || c.gf.noValidate {
		return nil
	}
	conn, err := dialTo(op.To, toReachableTimeout)
	if err != nil {
		return fmt.Errorf("can't reach --to backend %q: %w\n"+
			"  if your backend is a container on the proxy's docker network, use its `service-name:port` (e.g. `immich:2283`);\n"+
			"  if it is another host on your LAN, use its `LAN-IP:port` (e.g. `10.0.0.6:2283`);\n"+
			"  same host as the proxy, try `127.0.0.1:port`.\n"+
			"  If the address is correct but the backend is not up yet, pass --no-validate to skip this probe",
			op.To, err)
	}
	_ = conn.Close()
	return nil
}

// guardPersistOrigin fails BEFORE apply when `--to` is set but the operator's
// config cannot receive the persisted origins entry: no settings file (Defaults
// path) or a multi-edge topology. Failing early keeps live state coherent with
// the file (either both change or neither does).
func (c *cli) guardPersistOrigin(op model.Op) error {
	if op.Verb != model.Expose || op.To == "" {
		return nil
	}
	if c.settingsPath == "" {
		return fmt.Errorf("--to requires a settings file to persist the origins entry into (pass -config <path>)")
	}
	if len(c.settings.Edges) > 0 {
		return fmt.Errorf("--to is not supported with a multi-edge config (%q has `edges`) — add `%s: %s` to the fronting edge's origins map manually",
			c.settingsPath, op.Service, op.To)
	}
	return nil
}

// guardPublicAuth is the SAFETY GUARDRAIL: refuse to expose a host PUBLIC with no
// auth policy unless it was an explicit choice (--auth none, or a real policy).
// `--yes` does NOT bypass it — it skips the are-you-sure, not the did-you-mean-to-
// leave-this-open. Wired to the same publicness notion as the amber "about to go
// public" highlight (cs.NewPublic). A planning error is left for the real apply to
// surface. See AUTH-DESIGN.md §6.
func (c *cli) guardPublicAuth(ctx context.Context, op model.Op) error {
	if op.Verb != model.Expose || op.Auth != "" {
		return nil // unexpose never publishes; any explicit --auth (policy or none) is a choice
	}
	cs, err := c.engine.Plan(ctx, op)
	if err != nil {
		return nil // let applyOp's Apply re-plan and surface the error
	}
	if len(cs.NewPublic) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to expose %s PUBLIC with no auth — pass --auth <policy> to protect it, "+
		"or --auth none to publish it unprotected on purpose", strings.Join(cs.NewPublic, ", "))
}

// confirmUnverifiedOverride is the F2 gate's "(or interactive confirm)"
// alternative to --allow-unverified: if err is a *core.UnverifiedWriteError,
// asks the operator directly whether to accept the unconfirmed write. `--yes`
// implies non-interactive, so it does NOT trigger this prompt — a scripted run
// must pass --allow-unverified explicitly. Returns false (no prompt, no accept)
// for any other error.
func (c *cli) confirmUnverifiedOverride(err error) bool {
	var uerr *core.UnverifiedWriteError
	if !errors.As(err, &uerr) || c.gf.yes {
		return false
	}
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	fmt.Fprintf(c.out, "\n%v\nAccept this unconfirmed write anyway? [y/N]: ", uerr)
	reader := bufio.NewReader(in)
	line, rerr := reader.ReadString('\n')
	if rerr != nil && rerr != io.EOF {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

// confirmFunc returns AlwaysYes when --yes, else an interactive prompt that
// prints the ChangeSet (highlighting NewPublic) and reads y/N.
func (c *cli) confirmFunc() core.ConfirmFunc {
	if c.gf.yes {
		return core.AlwaysYes
	}
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	reader := bufio.NewReader(in)
	return func(cs model.ChangeSet) (bool, error) {
		c.printChangeSet(cs)
		fmt.Fprint(c.out, "\nApply this change? [y/N]: ")
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		return ans == "y" || ans == "yes", nil
	}
}

// printChangeSet renders the unified plan as a layered diff — EDGE, then
// INTERNAL DNS, then PUBLIC DNS — so a human sees the whole "what's about to go
// public" picture in one view, from the data plane outward to the global name.
func (c *cli) printChangeSet(cs model.ChangeSet) {
	if cs.Op.Verb == "" {
		fmt.Fprintln(c.out, "Plan (declarative):")
	} else {
		fmt.Fprintf(c.out, "Plan: %s\n", cs.Op)
	}
	c.printChangeBody(cs)
}

// printChangeBody renders the layered diff (edges → internal DNS → public DNS →
// deny → ABOUT TO GO PUBLIC) without the leading "Plan:" line, so callers that
// print their own header (declarative apply) can reuse it.
func (c *cli) printChangeBody(cs model.ChangeSet) {
	if cs.Empty() {
		fmt.Fprintln(c.out, "  (no changes — already in the desired state)")
		return
	}

	// EDGE sections — one per participating edge in the topology.
	for _, ep := range cs.Edges {
		if ep.Change.Empty() {
			continue
		}
		fmt.Fprintf(c.out, "  EDGE [%s·%s]\n", ep.Edge, ep.Driver)
		for _, r := range ep.Change.AddRoutes {
			fmt.Fprintf(c.out, "    + route   %-32s -> %s%s%s\n", r.Host, r.Upstream.Address, modeTag(r.Upstream.Mode), authTag(r.Upstream.Auth))
		}
		for _, h := range ep.Change.RemoveHosts {
			fmt.Fprintf(c.out, "    - route   %s\n", h)
		}
	}

	// DNS sections, internal before public (least → most public).
	c.printDNSScope(cs, model.ScopeInternal, "INTERNAL DNS")
	c.printDNSScope(cs, model.ScopePublic, "PUBLIC DNS")

	denyRemains := true
	for _, ep := range cs.Edges {
		if !ep.Change.Empty() && !ep.Change.DenyCatchAllWillBePresent {
			denyRemains = false
		}
	}
	fmt.Fprintf(c.out, "  default-deny will remain present on every edge: %v\n", denyRemains)
	if len(cs.NewPublic) > 0 {
		fmt.Fprintf(c.out, "\n  ⚠ ABOUT TO GO PUBLIC: %s\n", strings.Join(cs.NewPublic, ", "))
		fmt.Fprintln(c.out, "    (these hostnames will be resolvable and reachable from the internet)")
	}
}

// printDNSScope prints the add/remove records for one scope across all DNS
// providers in the changeset (nothing is printed if there are none).
func (c *cli) printDNSScope(cs model.ChangeSet, scope model.Scope, header string) {
	printed := false
	for _, d := range cs.DNS {
		if d.Scope != scope || d.Empty() {
			continue
		}
		if !printed {
			fmt.Fprintf(c.out, "  %s\n", header)
			printed = true
		}
		for _, rec := range d.Add {
			fmt.Fprintf(c.out, "    + %-6s %-32s %s\n", rec.Type, rec.Name, rec.Value)
		}
		for _, rec := range d.Remove {
			fmt.Fprintf(c.out, "    - %-6s %-32s %s\n", rec.Type, rec.Name, rec.Value)
		}
	}
}

func (c *cli) printApplyReport(rep core.ApplyReport) {
	if rep.NoOp {
		fmt.Fprintf(c.out, "no-op: %s is already in the desired state\n", rep.Op.Service)
		return
	}
	if rep.RolledBack {
		fmt.Fprintf(c.out, "ROLLED BACK: %s — partial apply reverted to prior live state\n", rep.Op)
		for _, e := range c.redactLines(rep.RollbackErrors) {
			fmt.Fprintf(c.out, "  ⚠ rollback error: %s\n", e)
		}
		return
	}
	if !rep.Applied {
		fmt.Fprintln(c.out, "aborted: no changes applied")
		return
	}
	fmt.Fprintf(c.out, "applied: %s\n", rep.Op)
	for _, v := range rep.Verify {
		// Mark per result: ✓ confirmed, ⚠ written-but-not-runtime-confirmed, ✗ failed.
		mark := "✓"
		switch {
		case !v.OK:
			mark = "✗"
		case v.RuntimeUnconfirmed():
			mark = "⚠"
		}
		fmt.Fprintf(c.out, "  read-back %s [%s] %s\n", mark, v.Provider, v.Detail)
		// For a file edge that WAS runtime-probed, append what the daemon said (or why
		// it could not be reached) — never let the file re-read stand in for the daemon.
		if v.RuntimeChecked && v.RuntimeDetail != "" {
			switch v.Runtime {
			case model.RuntimeVerifyConfirmed:
				fmt.Fprintf(c.out, "      ↳ runtime: %s\n", v.RuntimeDetail)
			case model.RuntimeVerifyUnavailable:
				fmt.Fprintf(c.out, "      ↳ runtime verify UNAVAILABLE: %s\n", v.RuntimeDetail)
			}
		}
	}
	switch {
	case rep.FullyVerified():
		fmt.Fprintln(c.out, "  verified: live state matches intent")
	case rep.Verified():
		// Written + re-read OK, but at least one file edge's daemon could not be
		// confirmed. Say so honestly — NEVER print "verified" here.
		var hosts []string
		for _, v := range rep.RuntimeUnconfirmed() {
			hosts = append(hosts, v.Provider)
		}
		fmt.Fprintf(c.out, "  ⚠ written to config but NOT runtime-verified on %s — the change is on disk; configure the edge's runtime surface (traefik_api_url / nginx reload+probe) to confirm the daemon accepted it\n",
			strings.Join(hosts, ", "))
	}
	c.printPersistWarnings(rep.PersistWarnings)
}

// printPersistWarnings notes any non-fatal on-disk persistence failures. The
// apply itself succeeded + verified; only durability across a restart is affected.
func (c *cli) printPersistWarnings(warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(c.out, "  ⚠ persist (durability) warning: %s\n", w)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(c.out, "    (the running state is correct + verified; on-disk persistence did not complete)")
	}
}

func (c *cli) writeJSON(v any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// redactStatus masks any secret bytes carried in the declared-unknown excerpts of a
// status report (in place), unless --show-secrets. RawExcerpt is display-only — never
// read back for apply logic — so redacting it here cannot affect any mutation path.
func (c *cli) redactStatus(rep *core.StatusReport) {
	if c.gf.showSecrets {
		return
	}
	for i := range rep.Edges {
		for j := range rep.Edges[i].Unparsed {
			rep.Edges[i].Unparsed[j].RawExcerpt = redact.Snippet(rep.Edges[i].Unparsed[j].RawExcerpt)
		}
	}
}

// redactSnapshot masks the secret-bearing declared-unknown excerpts of an export
// snapshot in place — the scrub `export --redacted` applies for a shareable copy.
// The default export keeps real values (a redacted snapshot is not restore-grade).
func redactSnapshot(snap *core.ExportSnapshot) {
	for i := range snap.Edges {
		for j := range snap.Edges[i].Unparsed {
			snap.Edges[i].Unparsed[j].RawExcerpt = redact.Snippet(snap.Edges[i].Unparsed[j].RawExcerpt)
		}
	}
}

// redactLines masks secret bytes that rollback/error strings may echo from an admin
// API response (a Caddy /load rejection echoes the offending config), unless
// --show-secrets. Applied to the operator-facing error lists at the print boundary.
func (c *cli) redactLines(ss []string) []string {
	if c.gf.showSecrets {
		return ss
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = redact.Snippet(s)
	}
	return out
}

// modeTag annotates a route line with its mode when it is not the default
// HTTP-proxy (so the common case stays uncluttered).
// chainDest renders a route's destination, FOLLOWING a chain forward THROUGH to its
// real downstream backend (P4). A non-chain route shows its plain backend; a RESOLVED
// chain forward shows "front-dial → downstream-edge:real-backend" (the observed true
// destination one hop down); an UNRESOLVED forward shows "front-dial → downstream-edge
// (downstream, not observed)" so a host crenel forwards but cannot follow is honestly
// declared, never shown as a plain terminal.
func chainDest(r model.Route) string {
	if r.Chain == nil {
		return r.Upstream.Address
	}
	if r.Chain.Resolved {
		return fmt.Sprintf("%s → %s:%s", r.Upstream.Address, r.Chain.DownstreamEdge, r.Chain.DownstreamAddress)
	}
	return fmt.Sprintf("%s → %s (downstream, not observed)", r.Upstream.Address, r.Chain.DownstreamEdge)
}

func modeTag(m model.RouteMode) string {
	if m == model.ModeHTTPProxy {
		return ""
	}
	return "  [" + m.String() + "]"
}

// authTag annotates a route line with its attached forward-auth policy, if any
// (the no-auth common case stays uncluttered).
func authTag(auth string) string {
	if auth == "" {
		return ""
	}
	return "  [auth:" + auth + "]"
}

func parseVerb(s string) (model.Verb, error) {
	switch model.Verb(s) {
	case model.Expose:
		return model.Expose, nil
	case model.Unexpose:
		return model.Unexpose, nil
	default:
		return "", fmt.Errorf("unknown verb %q (want expose|unexpose)", s)
	}
}
