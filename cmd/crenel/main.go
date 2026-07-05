// Command crenel is the CLI entry point and composition root.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/redact"
	"github.com/crenelhq/crenel/internal/ui"
)

// version is the build version, injected via -ldflags "-X main.version=…" by the
// Makefile (defaults to "dev" for a plain `go build`/`go install`).
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

// globalFlags are shared by all subcommands.
type globalFlags struct {
	settingsPath string
	adminURL     string
	zone         string
	fakeSeed     string
	yes          bool
	force        bool
	// allowUnverified accepts an apply/rename whose read-back matched but whose
	// file-driver runtime probe was unavailable (audit F2) — without it, such a
	// write is rolled back rather than left as a silent green. See
	// core.UnverifiedWriteError.
	allowUnverified bool
	jsonOut      bool
	granular     bool
	layer4       bool
	caddyPersist string
	mode         string
	auth         string
	// reason is the operator's crenel-ack:<reason> slug for `ack` (see
	// docs/design/ack-marker.md) — required, never inferred.
	reason string
	// to is the explicit backend override for `expose` (host:port). When set, it
	// bypasses the per-edge OriginResolver for THIS op and is persisted into the
	// settings-file origins map on a verified apply so `status`/`audit`/`drift`/
	// `reconcile` stay coherent. Alias: --upstream. See internal/model Op.To.
	to string
	// noValidate suppresses the pre-flight TCP reachability probe of the --to
	// address. Off by default (validate every --to backend before writing a
	// route to it — the verify principle applied pre-flight). Set for the
	// legit case where the backend is known-correct but not up yet (e.g. a
	// container that will start after the proxy). See guardToReachable.
	noValidate bool
	params     kvFlag
	// showSecrets disables Crenel's default secret redaction in OUTPUT (status/audit
	// JSON, error echoes, declared-unknown excerpts, redacted export). Off by default
	// so a stray status/error never leaks a Cloudflare token or auth hash; the
	// operator opts in deliberately on a trusted terminal. See SECURITY.md §6.
	showSecrets bool
	// hud/banner force the full status HUD banner; plain suppresses all branded
	// chrome (the scriptable path). See cmdStatus.
	hud    bool
	banner bool
	plain  bool
	// width overrides the terminal width used to draw the full-width scanline banner.
	// 0 = auto-detect (the COLUMNS env, else a default). Lets a recording pin an exact
	// banner width deterministically.
	width int
}

// showHUD reports whether the user asked for the full HUD banner (either flag).
func (g *globalFlags) showHUD() bool { return g.hud || g.banner }

// kvFlag collects repeatable -param key=value flags.
type kvFlag []string

func (k *kvFlag) String() string { return strings.Join(*k, ",") }
func (k *kvFlag) Set(s string) error {
	if !strings.Contains(s, "=") {
		return fmt.Errorf("param must be key=value, got %q", s)
	}
	*k = append(*k, s)
	return nil
}

func run(args []string) int {
	color := colorEnabled(os.Stdout)

	// No command: show the branded landing (wordmark + tagline + command list)
	// rather than a bare usage error. This is the friendly default surface.
	if len(args) == 0 {
		printLanding(os.Stdout, color)
		return 0
	}

	// Parse global flags that may appear before the verb.
	gf := &globalFlags{}
	fs := flag.NewFlagSet(config.ToolName, flag.ContinueOnError)
	bindGlobals(fs, gf)
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		printLanding(os.Stdout, color)
		return 0
	}

	verb, verbArgs := rest[0], rest[1:]

	// Go's flag package stops parsing at the first positional, so a user-natural
	// `expose grafana --auth authelia --yes` (and the README's `import --yes`,
	// `expose <svc> --auth none`) would otherwise silently drop those flags. Absorb
	// the post-settings-load global flags wherever they appear after the verb; the
	// per-verb handlers keep their own local flags (--dry-run/--adopt/--prune, and
	// the status surface flags). Settings-affecting flags (-config/-granular/…) must
	// still precede the verb (settings are loaded next).
	var aerr error
	if verbArgs, aerr = absorbPostVerbFlags(gf, verbArgs); aerr != nil {
		fmt.Fprintln(os.Stderr, "error:", aerr)
		return 1
	}

	// `crenel banner` is pure branding — print the hero banner with no settings/engine.
	if verb == "banner" {
		ui.Style{Color: color, Cols: termCols(gf), Version: version}.WriteHeroBanner(os.Stdout, termCols(gf))
		return 0
	}

	settings, err := loadSettings(gf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	w, err := build(settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer w.cleanup()
	// The --force escape hatch lets the ownership gate proceed on an UNKNOWN-owned
	// route (never a FOREIGN one). It is load-bearing-on-the-human, hence opt-in.
	w.engine.Force = gf.force
	// The --allow-unverified escape hatch lets a file-driver write with no runtime
	// probe stand instead of being rolled back (audit F2). Load-bearing-on-the-human,
	// same spirit as Force.
	w.engine.AllowUnverified = gf.allowUnverified

	ctx := context.Background()
	c := &cli{
		engine:       w.engine,
		gf:           gf,
		settings:     settings,
		settingsPath: gf.settingsPath,
		out:          os.Stdout,
		errOut:       os.Stderr,
		color:        color,
		tty:          isTTY(os.Stdout),
	}

	if err := c.dispatch(ctx, verb, verbArgs); err != nil {
		printError(gf, err)
		return 1
	}
	return 0
}

// printError writes a command error to stderr, REDACTING any secret bytes the error
// echoes (a Caddy /load rejection echoes the offending config; a GET /config/ non-2xx
// echoes the body) unless --show-secrets. Redaction is at this print boundary so the
// driver/core error values stay real for programmatic callers and tests. See
// SECURITY.md §6.
func printError(gf *globalFlags, err error) {
	fmt.Fprintln(os.Stderr, "error:", errMessage(gf, err))
}

// errMessage returns an error's text with secret bytes masked unless --show-secrets.
func errMessage(gf *globalFlags, err error) string {
	msg := err.Error()
	if !gf.showSecrets {
		msg = redact.Snippet(msg)
	}
	return msg
}

// isTTY reports whether f is an interactive terminal (a character device). Used
// to decide whether to draw the branded status header by default.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// colorEnabled reports whether ANSI color should be emitted: a terminal with
// NO_COLOR unset. Honors the https://no-color.org/ convention.
func colorEnabled(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return isTTY(f)
}

// termCols resolves the terminal width for the full-width banner: an explicit
// -width wins; else the COLUMNS env (exported by some shells / set by a recorder);
// else the ui default. Kept dependency-free — no ioctl — so the ui stays portable.
func termCols(gf *globalFlags) int {
	if gf != nil && gf.width > 0 {
		return gf.width
	}
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return ui.BannerWidth
}

func bindGlobals(fs *flag.FlagSet, gf *globalFlags) {
	fs.StringVar(&gf.settingsPath, "config", os.Getenv("CRENEL_CONFIG"), "path to settings JSON")
	fs.StringVar(&gf.adminURL, "admin-url", os.Getenv("CRENEL_ADMIN_URL"), "Caddy admin API base URL")
	fs.StringVar(&gf.zone, "zone", os.Getenv("CRENEL_ZONE"), "DNS zone for host derivation")
	fs.StringVar(&gf.fakeSeed, "fake-seed", os.Getenv("CRENEL_FAKE_SEED"), "seed an in-process fake Caddy admin API from this fixture file (safe demo mode)")
	fs.BoolVar(&gf.yes, "yes", false, "skip confirmation prompt for mutating commands")
	fs.BoolVar(&gf.force, "force", false, "ownership escape hatch: permit mutating a route whose ownership is UNKNOWN (never a FOREIGN/generator-owned one); use only after verifying ownership out-of-band")
	fs.BoolVar(&gf.allowUnverified, "allow-unverified", false, "accept a file-driver write whose runtime probe is unavailable (no runtime URL configured) instead of rolling it back; the report still won't claim \"verified\"")
	fs.BoolVar(&gf.jsonOut, "json", false, "machine-readable JSON output where supported")
	fs.BoolVar(&gf.granular, "granular", false, "additive structured-admin-API apply (required for rich/production edges)")
	fs.BoolVar(&gf.layer4, "layer4", false, "Caddy edge has the caddy-l4 plugin: render --mode passthrough via the layer4 app (requires -granular)")
	fs.StringVar(&gf.caddyPersist, "caddy-persist", os.Getenv("CRENEL_CADDY_PERSIST"), "Caddy on-disk persistence: mirror managed routes into this mounted Caddyfile after a verified apply")
	fs.StringVar(&gf.mode, "mode", "", "route mode: http (default) | passthrough | mesh")
	fs.StringVar(&gf.auth, "auth", "", "forward-auth policy to attach (e.g. authelia); 'none' to publish unprotected on purpose")
	fs.StringVar(&gf.reason, "reason", "", "ack: the crenel-ack:<reason> slug to stamp (required)")
	fs.StringVar(&gf.to, "to", "", "expose: explicit backend address for this service (host:port); persists into the settings-file origins map on apply")
	fs.StringVar(&gf.to, "upstream", "", "alias for --to")
	fs.BoolVar(&gf.noValidate, "no-validate", false, "expose: skip the pre-flight TCP probe of --to (use when the backend is not up yet but the address is known-correct)")
	fs.Var(&gf.params, "param", "mode-specific intent as key=value (repeatable), e.g. -param group=admins")
	fs.BoolVar(&gf.hud, "hud", false, "status: draw the full HUD banner (wordmark + CORE MATRIX panel)")
	fs.BoolVar(&gf.banner, "banner", false, "status: alias for -hud")
	fs.BoolVar(&gf.plain, "plain", false, "status: suppress the branded header/HUD (scriptable output only)")
	fs.IntVar(&gf.width, "width", 0, "status: terminal width for the full-width scanline banner (0 = auto: COLUMNS env, else default)")
	fs.BoolVar(&gf.showSecrets, "show-secrets", false, "show raw secret values in output (default: masked). Reveals tokens/keys/hashes — use only on a trusted terminal")
}

// parseMode maps the -mode flag to a model.RouteMode.
func parseMode(s string) (model.RouteMode, error) {
	switch s {
	case "", "http", "http_proxy", "proxy":
		return model.ModeHTTPProxy, nil
	case "passthrough", "tcp", "tcp_passthrough", "sni":
		return model.ModeTCPPassthrough, nil
	case "mesh", "mesh_grant", "grant":
		return model.ModeMeshGrant, nil
	default:
		return "", fmt.Errorf("unknown -mode %q (want http|passthrough|mesh)", s)
	}
}

// absorbPostVerbFlags pulls recognized GLOBAL flags out of the post-verb args and
// applies them to gf, returning the remaining (positional + verb-local) args. Only
// flags that take effect AFTER settings are loaded are absorbed here — the toggles
// (-yes/-force/-json/-show-secrets) and the per-op intent (-mode/-auth/-param). Settings-affecting
// flags (-config/-admin-url/-zone/-granular/-layer4/-caddy-persist/-fake-seed) and
// the status-surface flags (-hud/-banner/-plain, handled by applyStatusFlags) are
// deliberately NOT absorbed, so they keep their existing meaning. Unknown flags are
// left in place so each verb handler can accept or reject them as before. Supports
// -flag, --flag, --flag=value, and --flag value forms.
func absorbPostVerbFlags(gf *globalFlags, args []string) ([]string, error) {
	setBool := func(name string) bool {
		switch name {
		case "yes":
			gf.yes = true
		case "force":
			gf.force = true
		case "allow-unverified":
			gf.allowUnverified = true
		case "json":
			gf.jsonOut = true
		case "show-secrets":
			gf.showSecrets = true
		case "no-validate":
			gf.noValidate = true
		default:
			return false
		}
		return true
	}
	setValue := func(name, val string) bool {
		switch name {
		case "mode":
			gf.mode = val
		case "auth":
			gf.auth = val
		case "to", "upstream":
			gf.to = val
		case "param":
			gf.params = append(gf.params, val)
		case "reason":
			gf.reason = val
		default:
			return false
		}
		return true
	}
	isValueFlag := func(name string) bool {
		return name == "mode" || name == "auth" || name == "param" || name == "to" || name == "upstream" || name == "reason"
	}

	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			out = append(out, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if k, v, ok := strings.Cut(name, "="); ok { // --flag=value
			if !setValue(k, v) {
				out = append(out, a) // unknown or bool-with-= — leave for the verb handler
			}
			continue
		}
		if setBool(name) {
			continue
		}
		if isValueFlag(name) { // --flag value (space-separated)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag -%s needs a value", name)
			}
			setValue(name, args[i+1])
			i++
			continue
		}
		out = append(out, a) // not a recognized global flag — leave it
	}
	return out, nil
}

// loadSettings layers file settings under flag/env overrides.
func loadSettings(gf *globalFlags) (config.Settings, error) {
	s, err := config.Load(gf.settingsPath)
	if err != nil {
		return s, err
	}
	if gf.adminURL != "" {
		s.AdminURL = gf.adminURL
	}
	if gf.zone != "" {
		s.Zone = gf.zone
	}
	if gf.fakeSeed != "" {
		s.FakeSeed = gf.fakeSeed
	}
	if gf.granular {
		s.GranularApply = true
	}
	if gf.layer4 {
		s.CaddyLayer4 = true
	}
	if gf.caddyPersist != "" {
		s.CaddyPersistPath = gf.caddyPersist
	}
	return s, nil
}

// printLanding renders the branded landing surface for the no-command case: the
// crenellated wordmark, the tagline, and the command list.
func printLanding(w io.Writer, color bool) {
	st := ui.Style{Color: color}
	st.WriteWordmark(w, "")
	fmt.Fprintf(w, "\n%s\n", config.ToolTagline)
	fmt.Fprintf(w, "Run `%s status` to see what's exposed right now.\n\n", config.ToolName)
	writeUsage(w)
}

func usage() { writeUsage(os.Stderr) }

func writeUsage(w io.Writer) {
	fmt.Fprintf(w, `%s — %s

Usage:
  %s [global flags] <command> [args]

Getting started:
  init [dir]             Scaffold starter crenel.settings.yaml + crenel.exposures.yaml

Read-only commands:
  status                 Show what is exposed right now (reads live state)
  audit                  Live-only invariant + cross-provider consistency checks
  preview expose <svc>   Show the change for exposing a service (no apply)
  preview unexpose <svc> Show the change for unexposing a service (no apply)
  preview rename <old-host> <new-host>
                         Show the atomic move for renaming a host (no apply)
  drift                  Report divergence from the canonical exposed set (no
                         apply); exits non-zero when drift exists (CI/cron)
  export <file> [--redacted]
                         Dump current live state to a file (throwaway, 0600).
                         Holds REAL secrets by default; --redacted scrubs them
                         for a shareable copy
  serve [--addr :8080] [--refresh 5]
                         Run the READ-ONLY status dashboard: live 'status' as the
                         branded HUD over HTTP, auto-refreshing. Never mutates —
                         all writes stay on the CLI (alias: dashboard)

Mutating commands (preview -> confirm -> apply -> read-back-verify):
  expose <svc> [--to host:port]
                         Expose a service through the edge. Pass --to to name
                         the backend inline (persisted into origins on apply)
                         instead of pre-declaring it in config
  unexpose <svc>         Remove a service's exposure
  rename <old-host> <new-host>
                         Move a service to a new hostname as ONE atomic, durable
                         transaction (add new + remove old), copying the source
                         route's exact backend / mode / auth. Make-before-break
                         (zero-downtime), read-back-verified, rolled back as a unit
  set <svc> <on|off>     Set exposure state explicitly
  resume <expose|unexpose> <svc>
                         Re-drive an interrupted apply: complete the remaining
                         delta from live state (or roll back cleanly)
  reconcile              Detect + fix ALL drift: converge every edge + DNS onto
                         the canonical exposed set (re-add missing routes, fix
                         mode mismatches, drop stale managed DNS records)
  import [--dry-run]     Adopt a pre-existing (brownfield) setup: bring existing
                         UNMANAGED routes that match your origins under management
                         in-place (ownership only — no behavior change)
  apply <file> [flags]   Declaratively converge to an exposures file (JSON/YAML):
                         diff vs live -> preview -> all-or-nothing apply -> verify.
                         Flags: --adopt (adopt matching unmanaged hosts inline),
                         --prune (unexpose owned hosts absent from the file),
                         --dry-run (preview only)
  ack <host> --reason <slug>
                         Acknowledge an intentionally-unmodeled route (the
                         crenel-ack marker, docs/design/ack-marker.md): stamps
                         it in the live config so audit/status show ACK instead
                         of a recurring UNKNOWN, without weakening default-deny
                         or making the route reachable. Caddy only for now.
  unack <host>           Remove the crenel-ack marker, reverting the route to
                         whatever it would otherwise be declared as

Global flags:
  -config <path>     settings JSON (env CRENEL_CONFIG)
  -admin-url <url>   Caddy admin API base URL (env CRENEL_ADMIN_URL)
  -zone <zone>       DNS zone for host derivation (env CRENEL_ZONE)
  -fake-seed <file>  run against an in-process fake Caddy seeded from a fixture
  -granular          additive structured-admin-API apply (rich/production edges)
  -layer4            Caddy caddy-l4 plugin present: render passthrough via layer4
  -mode <m>          route mode: http (default) | passthrough | mesh
  -auth <policy>     forward-auth policy to attach (e.g. authelia); 'none' to
                     publish unprotected on purpose (required to expose public
                     with no auth)
  -reason <slug>     ack: the crenel-ack:<reason> slug to stamp (required)
  -to host:port      expose: explicit backend for this service (alias: -upstream).
                     Persists into the settings-file origins map on apply, so
                     status/audit/drift/reconcile stay coherent. Skips the "edit
                     config first" step; still gated by -auth. Pre-flight TCP
                     probe validates the address before any write; pass
                     -no-validate to skip when the backend is not up yet.
  -no-validate       expose: skip the pre-flight TCP probe of -to
  -param key=value   mode-specific intent (repeatable), e.g. -param group=admins
  -yes               skip confirmation for mutating commands
  -json              JSON output where supported
  -show-secrets      show raw secret values (default: masked tokens/keys/hashes)

Status surface:
  -hud, -banner      draw the full HUD banner (wordmark + CORE MATRIX panel)
  -plain             suppress the branded header/HUD (scriptable output only)

By default 'status' prints a compact colored header on a terminal and plain,
scriptable output when piped. Color follows NO_COLOR / TTY detection.
`, config.ToolName, config.ToolTagline, config.ToolName)
}
