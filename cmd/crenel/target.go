package main

// target.go is the zero-config AUDIT TARGET bootstrap (audit-any-edge §2, M-A2):
// `crenel audit <target>` with NO settings file. Composition-root logic — the
// target sniffer, the synthesized one-edge engine, and the forced read-only
// posture all live in cmd, never in core.
//
// Sniffing is POSITIVE-SIGNATURE ONLY (risk A.5): a target is wired to a driver
// only when it affirmatively matches one known shape; anything ambiguous or
// unrecognized is refused LOUDLY with exit 2 — never parsed as a best fit, never
// an empty-but-green report. Network contract (risk A.6): a URL target triggers
// at most TWO requests, both to the URL the user pasted — GET /config/ (the Caddy
// admin signature) and, only when that is not a positive Caddy match, GET
// /api/version (the Traefik API signature). No other socket is ever opened; the
// /api/* paths under the pasted target count as the pasted target (§9 decision 3).
// The ONE exception is opt-in: `--probe` (M-A6) may GET /config/ at the admin
// address the target config ITSELF declares, to upgrade CONFIG evidence to RUNTIME.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/nginx"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// Target kinds the sniffer recognizes (M-A2..M-A5) — each behind its own
// positive signature.
const (
	targetCaddyAdmin = "caddy-admin" // http(s) URL answering GET /config/ with Caddy JSON
	targetCaddyfile  = "caddyfile"   // file whose content positively matches a Caddyfile
	targetNPMTree    = "npm-tree"    // directory with the NPM layout signature (proxy_host/*.conf)
	targetTraefikAPI = "traefik-api" // http(s) URL answering GET /api/version with Traefik-shaped JSON
	targetCDPDir     = "cdp-dir"     // directory carrying caddy-docker-proxy's Caddyfile.autosave (M-A5)
)

// sniffProbeTimeout bounds the single sniff probe — the never-hang lesson applies
// to the very first request a new user's crenel ever makes.
const sniffProbeTimeout = 10 * time.Second

// sniffHTTP is the client for the sniff probe; a var so tests can shrink its
// timeout. It exists ONLY for the one GET /config/ against the pasted URL.
var sniffHTTP = &http.Client{Timeout: sniffProbeTimeout}

// sniffedTarget is a positively identified audit target.
type sniffedTarget struct {
	kind string
	arg  string // the URL or path exactly as pasted
}

// sniffTarget classifies a positional audit target. Every non-match is a loud,
// enumerated refusal (what was tried, why it did not match) — the caller exits 2.
func sniffTarget(arg string) (sniffedTarget, error) {
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return sniffURLTarget(arg)
	}
	return sniffFileTarget(arg)
}

// sniffURLTarget decides Caddy-vs-Traefik by POSITIVE SIGNATURE, never by
// elimination (risk A.5): at most two probes, both under the pasted URL (A.6).
//
//  1. GET <url>/config/ — a Caddy admin API answers 200 with the running config
//     as JSON ("null"/empty when nothing is loaded). A Traefik API 404s it.
//  2. Only if (1) was not a positive Caddy match: GET <url>/api/version — a
//     Traefik API answers 200 with {"Version":"3.x","Codename":…}. A Caddy
//     admin API 404s it.
//
// Neither signature matching => refuse loudly, enumerating BOTH probes tried —
// a web app answering HTML, a bare 404 server, anything ambiguous is never
// guessed into a driver.
func sniffURLTarget(url string) (sniffedTarget, error) {
	base := strings.TrimSuffix(url, "/")
	caddyReason := probeCaddyAdmin(url, base)
	if caddyReason == "" {
		return sniffedTarget{kind: targetCaddyAdmin, arg: url}, nil
	}
	traefikReason := probeTraefikAPI(base)
	if traefikReason == "" {
		return sniffedTarget{kind: targetTraefikAPI, arg: url}, nil
	}
	return sniffedTarget{}, fmt.Errorf("target %s matched no known API signature:\n"+
		"  - GET /config/ (Caddy admin API): %s\n"+
		"  - GET /api/version (Traefik API): %s",
		url, caddyReason, traefikReason)
}

// probeCaddyAdmin makes the single Caddy-signature probe (GET /config/) and
// returns "" on a positive match, else the reason it did not match.
func probeCaddyAdmin(url, base string) string {
	resp, err := sniffHTTP.Get(base + "/config/")
	if err != nil {
		return fmt.Sprintf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("got %d", resp.StatusCode)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) != 0 && string(trimmed) != "null" && !json.Valid(trimmed) {
		return "answered 200 but the body is not JSON"
	}
	if len(trimmed) > 0 && trimmed[0] != '{' && string(trimmed) != "null" {
		return "answered 200 but the body is not a JSON config object"
	}
	return ""
}

// probeTraefikAPI makes the single Traefik-signature probe (GET /api/version)
// and returns "" on a positive match, else the reason. The signature is the
// version DOCUMENT shape (a JSON object carrying both Version and Codename —
// what every Traefik release answers), not merely a 200: a generic app serving
// JSON at /api/version must not be misread as Traefik.
func probeTraefikAPI(base string) string {
	resp, err := sniffHTTP.Get(base + "/api/version")
	if err != nil {
		return fmt.Sprintf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("got %d", resp.StatusCode)
	}
	var v struct {
		Version  string `json:"Version"`
		Codename string `json:"Codename"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &v); err != nil {
		return "answered 200 but the body is not JSON"
	}
	if v.Version == "" || v.Codename == "" {
		return "answered 200 JSON without the Traefik Version/Codename shape"
	}
	return ""
}

// sniffFileTarget classifies a filesystem target. Files: exactly one shape, a
// Caddyfile (positive content signature via caddy.SniffCaddyfile). Directories:
// the NPM tree (M-A3) and the cdp autosave dir (M-A5) layouts. Caddy JSON
// configs, nginx brace DSL, and Traefik YAML files are refused with a pointer to
// what WAS tried.
func sniffFileTarget(path string) (sniffedTarget, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return sniffedTarget{}, fmt.Errorf("target %q: not an http(s) URL and not a readable path: %w", path, err)
	}
	if fi.IsDir() {
		// Directory shapes are matched by POSITIVE SIGNATURE only (risk A.5): the NPM
		// data-dir layout (proxy_host/*.conf, M-A3) and the caddy-docker-proxy dir
		// (Caddyfile.autosave, M-A5). A directory carrying BOTH signatures is
		// genuinely ambiguous — refused loudly, never ranked into a best fit; a
		// generic directory of confs matches neither and is refused too.
		npm, cdp := nginx.SniffNPMTree(path), caddy.SniffCDPDir(path)
		switch {
		case npm && cdp:
			return sniffedTarget{}, fmt.Errorf("target %s matches TWO directory signatures — the NPM layout (proxy_host/*.conf) AND "+
				"caddy-docker-proxy's Caddyfile.autosave — genuinely ambiguous; point crenel at the specific substrate instead "+
				"(the proxy_host tree, or the Caddyfile.autosave file's directory alone). Refusing to guess", path)
		case cdp:
			return sniffedTarget{kind: targetCDPDir, arg: path}, nil
		case npm:
			return sniffedTarget{kind: targetNPMTree, arg: path}, nil
		}
		return sniffedTarget{}, fmt.Errorf("target %s is a directory matching no known layout signature — supported: "+
			"an Nginx Proxy Manager data dir (proxy_host/*.conf, e.g. /data/nginx) or a caddy-docker-proxy config dir "+
			"(containing Caddyfile.autosave). Refusing to guess", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return sniffedTarget{}, fmt.Errorf("target %s: %w", path, err)
	}
	if t := bytes.TrimSpace(b); len(t) > 0 && (t[0] == '{' || t[0] == '[') && json.Valid(t) {
		return sniffedTarget{}, fmt.Errorf("target %s: content is JSON, not a Caddyfile — if this is a Caddy JSON config, "+
			"point crenel at the RUNNING admin API instead (e.g. http://127.0.0.1:2019): the live process is stronger evidence than a file", path)
	}
	if !caddy.SniffCaddyfile(b) {
		return sniffedTarget{}, fmt.Errorf("target %s: tried the Caddyfile content signature (a top-level site block) — no positive match; "+
			"refusing to guess (nginx/Traefik file targets land in later milestones). Supported targets today: "+
			"a Caddy admin URL (http://…:2019) or a Caddyfile path", path)
	}
	return sniffedTarget{kind: targetCaddyfile, arg: path}, nil
}

// extractTargetArg pulls the first positional (non-flag) argument out of the
// post-verb args — the audit target, when present. Flags are left for the normal
// path (they were already absorbed by absorbPostVerbFlags).
func extractTargetArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// runAuditTarget is the whole zero-config target flow: sniff → synthesize a
// one-edge, DNS-less, origins-less engine → FORCE read-only → run the ordinary
// Audit → print the ordinary report behind the target header. Exit codes: 2 on a
// sniff refusal (nothing was audited), 1 on critical findings or a read error,
// 0 otherwise — same contract as the settings-file audit.
//
// Read-only is STRUCTURAL, not advisory (§3.2): beyond engine.ReadOnly (the belt),
// this function narrows the engine to core.ReadOnlyEngine immediately — from that
// point mutation is unreachable BY TYPE, the same construction the MCP server's
// read-only-by-construction claim rests on.
func runAuditTarget(gf *globalFlags, target string, out, errOut io.Writer) int {
	// Boundary declaration gate (M-A6, §9 decision 5 — the --auth none pattern):
	// a zero-config target audit has NO DNS topology, so crenel cannot know
	// whether this edge is the public boundary. Guessing either cries wolf on a
	// LAN-only edge or stays silent on a public one (risk A.4) — so the audit
	// REFUSES until the operator says the boundary out loud. Checked before the
	// sniff so a mis-scoped run never even probes the target.
	if gf.internalScope && gf.assumePublicBoundary {
		fmt.Fprintln(errOut, "error: --internal and --assume-public-boundary contradict each other — say ONE boundary out loud")
		return 2
	}
	if !gf.internalScope && !gf.assumePublicBoundary {
		fmt.Fprintln(errOut, "error: zero-config target audit has no DNS topology — crenel cannot know whether this edge is the public boundary, and refuses to guess")
		fmt.Fprintln(errOut, "  say the boundary out loud (the --auth none rule):")
		fmt.Fprintln(errOut, "    --assume-public-boundary   audit as if this edge faces the internet (every exposed host is treated PUBLIC; public_without_auth fires)")
		fmt.Fprintln(errOut, "    --internal                 declare this edge is NOT internet-facing (public_without_auth downgrades to exposure_unscoped, severity ok)")
		return 2
	}

	st, err := sniffTarget(target)
	if err != nil {
		fmt.Fprintln(errOut, "error:", errMessage(gf, err))
		fmt.Fprintln(errOut, "audit target: refusing to guess — nothing was audited (an ambiguous target must never yield an empty-but-green report)")
		return 2
	}

	// Synthesize the one-edge engine. No zone, no DNS, no origins — the audit
	// needs none of them; the Scope block declares the reductions.
	var engine *core.Engine
	var targetLine string
	var extraLines []string
	switch st.kind {
	case targetCaddyAdmin:
		engine = core.New(caddy.New(st.arg, static.New(nil)), "")
		targetLine = fmt.Sprintf("Target: caddy admin API @ %s — evidence: RUNTIME (the running process, not a file)", st.arg)
		// The admin API carries NO caddy-docker-proxy marker (§4.1): a generated
		// edge reads as unmanaged here, and that reduction is DECLARED, never
		// implied as hand-written (M-A5).
		extraLines = append(extraLines,
			"Scope: generator detection unavailable over the Caddy admin API (it carries no caddy-docker-proxy marker) — a generated edge reads as unmanaged here; point crenel at the directory containing Caddyfile.autosave to detect caddy-docker-proxy")
	case targetCaddyfile:
		engine = core.New(caddy.NewFileReader(st.arg), "")
		targetLine = fmt.Sprintf("Target: Caddyfile %s — evidence: CONFIG (a file on disk; the running daemon may differ)", st.arg)
	case targetNPMTree:
		engine = core.New(nginx.NewTreeReader(st.arg), "")
		targetLine = fmt.Sprintf("Target: NPM tree %s — evidence: CONFIG (a generated tree on disk; the running daemon may differ)", st.arg)
	case targetTraefikAPI:
		engine = core.New(traefik.NewAPIReader(st.arg), "")
		targetLine = fmt.Sprintf("Target: traefik API @ %s — evidence: RUNTIME (the running process, not a file)", st.arg)
	case targetCDPDir:
		// The autosave FILENAME is the generator signal, so the FileReader over it
		// auto-detects Generator=caddy-docker-proxy (M-A5) — foreign edge-wide,
		// CONFIG evidence, config_evidence_only caveat, all via existing machinery.
		engine = core.New(caddy.NewFileReader(caddy.CDPAutosavePath(st.arg)), "")
		targetLine = fmt.Sprintf("Target: caddy-docker-proxy dir %s — evidence: CONFIG (CDP's generated Caddyfile.autosave on disk; the running daemon may differ)", st.arg)
	}

	// Opt-in --probe (M-A6): upgrade CONFIG evidence toward RUNTIME where an API
	// exists. Off by default (risk A.6: only the pasted target is ever contacted);
	// when off, the report says what WOULD have been probeable.
	if line, upgraded := probeTarget(gf, st, &engine); line != "" {
		extraLines = append(extraLines, line)
		if upgraded {
			targetLine = strings.Replace(targetLine, "evidence: CONFIG", "evidence: RUNTIME (probed)", 1)
		}
	}

	engine.ReadOnly = true // belt: every mutating verb refuses before planning
	engine.TargetMode = true
	engine.DeclaredInternal = gf.internalScope
	// Braces (§3.2): from here on the target path holds ONLY the narrow read
	// interface — Status/Audit/DetectDrift. No mutating method is reachable by type.
	var ro core.ReadOnlyEngine = engine

	rep, err := ro.Audit(context.Background())
	if err != nil {
		fmt.Fprintln(errOut, "error:", errMessage(gf, err))
		return 1
	}

	c := &cli{gf: gf, out: out, errOut: errOut}
	if gf.jsonOut {
		if err := c.writeJSON(rep); err != nil {
			fmt.Fprintln(errOut, "error:", errMessage(gf, err))
			return 1
		}
	} else {
		fmt.Fprintln(out, "crenel audit — READ-ONLY EXPOSURE AUDIT (zero-config target)")
		fmt.Fprintln(out, targetLine)
		for _, l := range extraLines {
			fmt.Fprintln(out, l)
		}
		c.printAuditScope(rep.Scope)
		for _, f := range rep.Findings {
			mark := map[string]string{"ok": "✓", "warning": "▲", "critical": "✗"}[f.Severity]
			fmt.Fprintf(out, "%s [%s] %s\n", mark, strings.ToUpper(f.Severity), f.Message)
		}
	}
	if rep.HasCritical() {
		fmt.Fprintln(errOut, "error: audit found critical findings")
		return 1
	}
	return 0
}

// Compile-time guard that the file reader satisfies the evidence capability the
// target path depends on (a silent regression here would drop the CONFIG caveat).
var _ interface{ ReadEvidence() model.ReadEvidence } = (*caddy.FileReader)(nil)

// probeTarget implements the opt-in `--probe` RUNTIME upgrade (M-A6, §5). It is
// deliberately minimal and enumerable:
//
//   - RUNTIME targets (admin/API URLs) have nothing to upgrade — --probe says so.
//   - Caddyfile / cdp-dir targets: the probe URL is what the Caddyfile ITSELF
//     declares (global options `admin`, else Caddy's documented default
//     localhost:2019). With --probe, crenel makes the one documented request —
//     GET <admin>/config/ — and on a positive Caddy signature swaps the engine to
//     the admin driver, so the audit reads the RUNNING process (RUNTIME evidence).
//     A cdp dir keeps its generator detection via the autosave path hint.
//   - NPM trees: no runtime API exists (nginx has no admin API; `nginx -t` is a
//     write-adjacent exec) — --probe declares that honestly; evidence stays CONFIG.
//
// Probe OFF returns the "what would have been probeable" line for CONFIG targets
// (never opening a socket); risk A.6 stays executable — the only socket beyond the
// pasted target is this flag-gated, documented GET.
func probeTarget(gf *globalFlags, st sniffedTarget, engine **core.Engine) (line string, upgraded bool) {
	switch st.kind {
	case targetCaddyAdmin, targetTraefikAPI:
		if gf.probe {
			return "Probe: evidence is already RUNTIME (the pasted target IS the running process) — nothing to upgrade", false
		}
		return "", false
	case targetNPMTree:
		if gf.probe {
			return "Probe: no runtime API exists for an NPM tree (nginx has no admin API) — evidence remains CONFIG", false
		}
		return "", false
	}

	// Caddyfile / cdp dir: resolve the config-declared admin URL.
	cfgPath := st.arg
	if st.kind == targetCDPDir {
		cfgPath = caddy.CDPAutosavePath(st.arg)
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", false // the read path itself will surface the error
	}
	adminURL, reason := caddy.AdminAddressFromCaddyfile(b)
	if !gf.probe {
		if reason != "" {
			return "Probe: unavailable — " + reason, false
		}
		return fmt.Sprintf("Probe: off — pass --probe to cross-check the running process at the config-declared admin API %s (one request: GET /config/); evidence stays CONFIG until then", adminURL), false
	}
	if reason != "" {
		return "Probe: unavailable — " + reason + "; evidence remains CONFIG", false
	}
	if why := probeCaddyAdmin(adminURL, strings.TrimSuffix(adminURL, "/")); why != "" {
		return fmt.Sprintf("Probe: FAILED — admin API %s did not answer the Caddy signature (GET /config/: %s); evidence remains CONFIG (is the daemon running / the admin API reachable from here?)", adminURL, why), false
	}
	// Positive Caddy signature: audit the RUNNING process instead of the file. A
	// cdp dir keeps its generator detection via the autosave-path hint (the admin
	// API carries no CDP marker).
	var opts []caddy.Option
	if st.kind == targetCDPDir {
		opts = append(opts, caddy.WithGeneratorConfigPath(cfgPath))
	}
	*engine = core.New(caddy.New(adminURL, static.New(nil), opts...), "")
	return fmt.Sprintf("Probe: admin API %s answered the Caddy signature — auditing the RUNNING process (evidence upgraded CONFIG → RUNTIME); the file at %s was used only to locate it", adminURL, cfgPath), true
}
