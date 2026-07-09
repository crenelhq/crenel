package caddy

// caddyfile_read.go is the Caddyfile READ adapter (audit-any-edge M-A2): a
// read-only ports.EdgeProvider whose substrate is a Caddyfile ON DISK, for the
// zero-config audit target (`crenel audit ./Caddyfile`). It reuses the brace-aware
// walking the durable reconciler already trusts (findSiteBlock/matchClose/
// stripComment) but reads the OPERATOR'S whole file, not crenel's sentinel region.
//
// Honesty contract (register §4, risk A.5): this is NOT a full Caddyfile parser.
// Every directive it cannot positively model is DECLARED as model.Unparsed —
// never dropped, never best-fit — so coverage counts it and the deny ternary
// downgrades to UNKNOWN (ENFORCED requires FullyParsed, exactly as on the admin
// path). Evidence is CONFIG: a file declared this state; the daemon may differ
// (ports.EvidenceReporter carries the mtime for the A.2 staleness hint).
//
// Default-deny model mirrors the admin driver's: Caddy denies any host matching
// NO site via an implicit 404/TLS-mismatch, so the structural deny holds UNLESS a
// host-less catch-all site (`:443`, `*`) forwards traffic (a reverse_proxy there
// is fail-open). An explicit `:443 { respond 403 }` is a stricter spelling of the
// same deny and keeps it present.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// FileReader is a READ-ONLY EdgeProvider over a Caddyfile path. It exists for the
// audit/status read path only: Plan and Apply refuse structurally (belt), and the
// target bootstrap additionally holds the engine behind core.ReadOnlyEngine
// (braces) — a Caddyfile is never a write target (writes go through the admin API
// or the durable reconciler, both of which validate + reload; blind file edits
// would be an unverifiable mutation).
type FileReader struct {
	path string
}

// NewFileReader builds the Caddyfile read adapter for path. The file is re-read on
// every ReadLiveState — live (well, on-disk) truth, nothing cached.
func NewFileReader(path string) *FileReader { return &FileReader{path: path} }

// Name reports the driver family — the routes read here are Caddy routes.
func (f *FileReader) Name() string { return "caddy" }

// Validate confirms the file exists, is readable, and carries a POSITIVE Caddyfile
// signature (never a best fit — risk A.5).
func (f *FileReader) Validate(context.Context) error {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("caddyfile read %s: %w", f.path, err)
	}
	if !SniffCaddyfile(b) {
		return fmt.Errorf("caddyfile read %s: content does not positively match a Caddyfile (no site block found)", f.path)
	}
	return nil
}

// ReadLiveState reads and normalizes the Caddyfile. "Live" here is the FILE, not
// the daemon — the CONFIG-evidence caveat is carried by ReadEvidence and surfaced
// by audit's config_evidence_only finding; this method never claims more.
func (f *FileReader) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return model.LiveEdgeState{}, fmt.Errorf("caddyfile read %s: %w", f.path, err)
	}
	state := parseCaddyfileState(string(b))
	// Generator detection reuses the CDP autosave signal (filename or content
	// marker): a generated Caddyfile target reads FOREIGN edge-wide, same as the
	// admin path with a generator hint.
	if g := detectGeneratorFile(f.path); g != "" {
		state.Generator = g
		for i := range state.Routes {
			state.Routes[i].Ownership = model.OwnForeign
			state.Routes[i].Managed = false
		}
	}
	// The file IS the boot config: whatever it declares survives a restart.
	state.Persistence = model.PersistDurableConfig
	return state, nil
}

// Plan refuses: the Caddyfile read adapter is a read source, never a write target.
func (f *FileReader) Plan(model.Op, model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{}, fmt.Errorf("caddyfile target %s is READ-ONLY: crenel audits a Caddyfile but never edits one blind "+
		"(no validate/reload channel to verify the write) — manage this edge via its admin API or a settings file", f.path)
}

// Apply refuses for the same reason as Plan (belt-and-braces: the target engine is
// also constructed ReadOnly, so this is unreachable in practice).
func (f *FileReader) Apply(context.Context, model.ChangeSet) error {
	return fmt.Errorf("caddyfile target %s is READ-ONLY: refusing to write", f.path)
}

// ReadEvidence implements ports.EvidenceReporter: CONFIG — a file on disk declared
// this state; the running daemon may differ. ModTime feeds the staleness hint
// (risk A.2). Stat failure leaves ModTime zero (hint simply omitted), never an error.
func (f *FileReader) ReadEvidence() model.ReadEvidence {
	ev := model.ReadEvidence{Kind: model.EvidenceConfig, Source: f.path}
	if fi, err := os.Stat(f.path); err == nil {
		ev.ModTime = fi.ModTime()
	}
	return ev
}

// SniffCaddyfile reports whether content POSITIVELY matches a Caddyfile: not JSON
// (a Caddy JSON config or Traefik dynamic JSON must not best-fit here), balanced
// braces, and at least one top-level SITE block whose address looks like a site
// address (a dotted/wildcard hostname, localhost, or a bare :port). Used by the
// cmd target sniffer (risk A.5: a positive signature, never a best fit — anything
// ambiguous is refused loudly upstream).
func SniffCaddyfile(content []byte) bool {
	text := string(content)
	// JSON rejection: a JSON document's first non-space byte is '{' or '['
	// immediately followed by a quote/brace on the same token stream; a Caddyfile
	// global-options block is `{` alone on its line. Cheap positive split: any file
	// whose first non-space rune is '{' NOT alone on its line, or '[', is not a
	// Caddyfile.
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "[") {
		return false
	}
	if strings.HasPrefix(trimmed, "{") {
		firstLine := strings.TrimSpace(strings.SplitN(trimmed, "\n", 2)[0])
		if firstLine != "{" {
			return false // `{"apps": …` — JSON, not a global-options block
		}
	}
	sites, _, ok := topLevelCaddyfileBlocks(text)
	if !ok {
		return false
	}
	for _, s := range sites {
		for _, a := range splitSiteAddrs(s.addr) {
			if plausibleSiteAddr(a) {
				return true
			}
		}
	}
	return false
}

// plausibleSiteAddr reports whether one address token is a shape only a Caddyfile
// site address takes: a bare :port, a wildcard, localhost, or a dotted hostname
// (optionally scheme-prefixed). An nginx `server` keyword or a YAML key never
// matches — that is what keeps the sniff positive, not best-fit.
func plausibleSiteAddr(a string) bool {
	a = strings.TrimPrefix(strings.TrimPrefix(a, "https://"), "http://")
	if a == "" {
		return false
	}
	if strings.HasPrefix(a, ":") { // :443 — port-only site
		return len(a) > 1 && strings.Trim(a[1:], "0123456789") == ""
	}
	host := a
	if i := strings.LastIndex(a, ":"); i > 0 {
		host = a[:i]
	}
	return host == "*" || host == "localhost" || strings.Contains(host, ".")
}

// caddyBlock is one top-level `<header> { … }` entry of a Caddyfile.
type caddyBlock struct {
	addr string // header text before the `{` (site address(es), or "(name)" for a snippet)
	body string
}

// topLevelCaddyfileBlocks walks every top-level block of a Caddyfile — the same
// brace-aware walk as findSiteBlock, but returning ALL sites plus the `(name)`
// snippet bodies (needed to resolve `import <name>` positively). The global
// options block (`{` alone) is skipped: it configures the process (admin, email,
// servers options), never routes traffic, so ignoring it cannot hide exposure.
// ok=false on unbalanced braces — refuse rather than guess.
func topLevelCaddyfileBlocks(text string) (sites []caddyBlock, snippets map[string]string, ok bool) {
	snippets = map[string]string{}
	i := 0
	for i < len(text) {
		lineEnd := strings.IndexByte(text[i:], '\n')
		line := text[i:]
		next := len(text)
		if lineEnd >= 0 {
			line = text[i : i+lineEnd]
			next = i + lineEnd + 1
		}
		header := stripComment(line)
		trimmed := strings.TrimSpace(header)
		if strings.HasSuffix(trimmed, "{") {
			bodyStart := i + strings.LastIndexByte(header, '{') + 1
			bodyEnd, closed := matchClose(text, bodyStart)
			if !closed {
				return nil, nil, false
			}
			addr := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
			body := text[bodyStart:bodyEnd]
			switch {
			case addr == "": // global options block — process config, no routes
			case strings.HasPrefix(addr, "(") && strings.HasSuffix(addr, ")"):
				snippets[strings.Trim(addr, "()")] = body
			default:
				sites = append(sites, caddyBlock{addr: addr, body: body})
			}
			i = bodyEnd + 1
			continue
		}
		if trimmed != "" {
			// A top-level non-block line (a stray directive outside any site) is not a
			// well-formed Caddyfile shape crenel models — tolerated for the walk (the
			// parser will not see it), but it never contributes a site.
		}
		i = next
	}
	return sites, snippets, true
}

// splitSiteAddrs splits a site header's address list ("a.com, b.com:8443") into
// individual address tokens.
func splitSiteAddrs(addr string) []string {
	var out []string
	for _, part := range strings.Split(addr, ",") {
		for _, tok := range strings.Fields(part) {
			out = append(out, tok)
		}
	}
	return out
}

// addrHost extracts the HOST a site address exposes: scheme stripped, port
// stripped. "" means host-less (a :port / * catch-all — matches every host).
func addrHost(a string) string {
	a = strings.TrimPrefix(strings.TrimPrefix(a, "https://"), "http://")
	if strings.HasPrefix(a, ":") {
		return ""
	}
	host := a
	if i := strings.LastIndex(a, ":"); i > 0 {
		host = a[:i]
	}
	if host == "*" {
		return ""
	}
	return host
}

// bodyParse is the result of scanning one block body (a site, a handle, or an
// imported snippet): what the block positively models, plus everything it could not.
type bodyParse struct {
	dial        string // first site/handle-level reverse_proxy upstream ("" = none)
	upstreamTLS bool
	auth        string           // forward_auth seen (model.AuthDetected) — inherited by leaves
	denied      bool             // an understood non-forwarding terminal (respond/abort/error/redir)
	handles     []hostHandle     // per-host `@label host X` + `handle @label` pairs
	unparsed    []model.Unparsed // everything not positively modeled — NEVER dropped
}

// hostHandle is one per-host handle inside a (typically wildcard) site: the
// real-shape idiom `@name host a.example.com` + `handle @name { … }`.
type hostHandle struct {
	hosts   []string
	managed bool // matcher label carries crenel's on-disk marker (@crenel_*)
	parse   bodyParse
}

// benignDirectives are directives that cannot change WHAT is exposed or WHERE it
// forwards — TLS/cert config, compression, logging, header mutation, listener
// binding. They are understood (not Unparsed) but contribute nothing to the model.
var benignDirectives = map[string]bool{
	"tls": true, "encode": true, "log": true, "header": true, "bind": true,
}

// denyDirectives are understood NON-FORWARDING terminals: they close/answer the
// request locally, exposing no backend. `respond 403`/`abort` are the canonical
// Caddyfile default-deny spellings; a redirect forwards the CLIENT, not traffic.
var denyDirectives = map[string]bool{
	"respond": true, "abort": true, "error": true, "redir": true,
}

// parseBlockBody scans one block body directive-by-directive (brace-aware: a
// directive's own sub-block — reverse_proxy transport, forward_auth uri, tls dns —
// is consumed WITH it, never scanned as sibling directives). snippets resolves
// `import <name>` POSITIVELY: a defined snippet is parsed recursively (visited
// guards cycles); an unresolvable import is DECLARED unknown, never assumed to be
// auth or anything else.
func parseBlockBody(body, loc string, snippets map[string]string, visited map[string]bool) bodyParse {
	var p bodyParse
	matcherHosts := map[string][]string{} // @label -> hosts (host matchers only)
	nonHostMatcher := map[string]bool{}   // @label defined with a non-host matcher

	lines := strings.Split(body, "\n")
	for i := 0; i < len(lines); i++ {
		f := strings.Fields(stripComment(lines[i]))
		if len(f) == 0 {
			continue
		}
		// Consume this directive's sub-block (if it opens one) as a unit; sub points
		// at its body lines for the few directives that recurse (handle/route).
		var sub []string
		depth := strings.Count(stripComment(lines[i]), "{") - strings.Count(stripComment(lines[i]), "}")
		if depth > 0 {
			start := i + 1
			for i++; i < len(lines) && depth > 0; i++ {
				depth += strings.Count(stripComment(lines[i]), "{") - strings.Count(stripComment(lines[i]), "}")
			}
			i--
			sub = lines[start:i]
		}

		name := f[0]
		switch {
		case strings.HasPrefix(name, "@"):
			// Named matcher definition. Only the single-line `@label host <h…>` form is
			// a host matcher crenel models; any other matcher (path/method/…, or a block
			// form) marks the label non-host so handles gated by it are DECLARED.
			label := strings.TrimPrefix(name, "@")
			if len(f) >= 3 && f[1] == "host" && len(sub) == 0 {
				matcherHosts[label] = f[2:]
			} else {
				nonHostMatcher[label] = true
			}
		case name == "reverse_proxy":
			args := f[1:]
			if len(args) > 0 && (strings.HasPrefix(args[0], "@") || strings.HasPrefix(args[0], "/")) {
				// Matcher-scoped proxy: path/method-granular routing crenel does not model
				// at host granularity (mirrors the admin driver's matcher_conditional).
				p.unparsed = append(p.unparsed, model.Unparsed{
					Locator: loc, Kind: model.UnknownMatcher,
					Reason:     fmt.Sprintf("reverse_proxy scoped by matcher %s — path/method-granular routing is not represented at host granularity", args[0]),
					RawExcerpt: excerptLine(f),
				})
				continue
			}
			if len(args) == 0 {
				p.unparsed = append(p.unparsed, model.Unparsed{
					Locator: loc, Kind: model.UnknownBackend,
					Reason: "reverse_proxy with no inline upstream (upstreams declared in a form crenel does not model)",
				})
				continue
			}
			dial := args[0]
			if strings.HasPrefix(dial, "https://") {
				p.dial, p.upstreamTLS = strings.TrimPrefix(dial, "https://"), true
			} else {
				p.dial = strings.TrimPrefix(dial, "http://")
			}
		case name == "forward_auth":
			// A forward-auth gate: auth is ENFORCED here. The policy NAME is not
			// recoverable from a hand-written gate — same as the admin read path —
			// so it reads back as the recognized-but-unnamed AuthDetected.
			p.auth = model.AuthDetected
		case name == "import":
			if len(f) < 2 {
				continue
			}
			snip := f[1]
			if body, ok := snippets[snip]; ok && !visited[snip] {
				visited[snip] = true
				child := parseBlockBody(body, loc+".import("+snip+")", snippets, visited)
				delete(visited, snip)
				mergeBody(&p, child)
				continue
			}
			// Unresolvable import (a file path, a glob, an undefined name): its effect
			// on exposure/auth is unknown — DECLARE it (register §4), never best-fit.
			p.unparsed = append(p.unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason: fmt.Sprintf("imports %q which crenel cannot resolve in this file — its routing/auth effect is unknown", snip),
			})
		case name == "handle" || name == "route":
			if len(f) >= 2 && strings.HasPrefix(f[1], "@") {
				label := strings.TrimPrefix(f[1], "@")
				if hosts, ok := matcherHosts[label]; ok {
					child := parseBlockBody(strings.Join(sub, "\n"), loc+".handle[@"+label+"]", snippets, visited)
					p.handles = append(p.handles, hostHandle{
						hosts:   hosts,
						managed: strings.HasPrefix(label, "crenel_"),
						parse:   child,
					})
					continue
				}
				// Gated by a non-host (or undefined) matcher: scope crenel cannot model.
				p.unparsed = append(p.unparsed, model.Unparsed{
					Locator: loc, Kind: model.UnknownMatcher,
					Reason: fmt.Sprintf("handle gated by matcher @%s which is not a plain host matcher — its scope is not represented at host granularity", label),
				})
				continue
			}
			// Un-matched handle/route: applies to the SAME hosts as this block — descend.
			child := parseBlockBody(strings.Join(sub, "\n"), loc+"."+name, snippets, visited)
			mergeBody(&p, child)
		case benignDirectives[name]:
			// understood, no exposure effect
		case denyDirectives[name]:
			p.denied = true
		default:
			// Anything else — php_fastcgi, file_server, rewrite, handle_path, map, … —
			// is an unmodeled directive: DECLARED, so coverage drops and the deny
			// ternary downgrades to UNKNOWN (never a silent drop, never a guess).
			p.unparsed = append(p.unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason:     fmt.Sprintf("directive %q is not modeled by the Caddyfile read adapter — its exposure effect is unknown", name),
				RawExcerpt: excerptLine(f),
			})
		}
	}
	return p
}

// mergeBody folds a child block's parse (an import or an un-matched handle) into
// the parent: the child's dial/auth/deny apply at the parent's scope; unparsed and
// per-host handles are carried through verbatim.
func mergeBody(p *bodyParse, child bodyParse) {
	if p.dial == "" {
		p.dial, p.upstreamTLS = child.dial, child.upstreamTLS
	}
	if p.auth == "" {
		p.auth = child.auth
	}
	p.denied = p.denied || child.denied
	p.handles = append(p.handles, child.handles...)
	p.unparsed = append(p.unparsed, child.unparsed...)
}

// excerptLine renders a bounded one-line excerpt for an Unparsed entry.
func excerptLine(fields []string) string {
	s := strings.Join(fields, " ")
	const max = 120
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// parseCaddyfileState normalizes a whole Caddyfile into a LiveEdgeState — the
// file-substrate analogue of the admin path's normalize(). Deterministic: sites in
// source order, handles in source order.
func parseCaddyfileState(text string) model.LiveEdgeState {
	state := model.LiveEdgeState{Raw: text}
	sites, snippets, ok := topLevelCaddyfileBlocks(text)
	if !ok {
		// Unbalanced braces: refuse to model ANYTHING — one declared unknown for the
		// whole file, deny stays present-but-UNKNOWN is wrong here (nothing was read),
		// so deny reads MISSING? No: nothing understood means nothing certified —
		// declare the file unparsed and keep deny UNPROVEN (present=false would claim
		// fail-open, which is also unproven). present+unparsed => DenyUnknown, the
		// honest verdict for "could not parse".
		state.DenyCatchAllPresent = true
		state.Unparsed = append(state.Unparsed, model.Unparsed{
			Locator: "caddyfile", Kind: model.UnknownServerBlock,
			Reason: "unbalanced braces — the file could not be walked; nothing about this edge is certified",
		})
		return state
	}
	permissive := false
	for _, s := range sites {
		loc := "caddyfile:" + s.addr
		p := parseBlockBody(s.body, loc, snippets, map[string]bool{})

		// Attribute the parse per address token: host sites yield routes; a host-less
		// catch-all that FORWARDS is fail-open (mirrors the admin driver's model).
		var hosts []string
		hostless := false
		for _, a := range splitSiteAddrs(s.addr) {
			if h := addrHost(a); h != "" {
				hosts = append(hosts, h)
			} else {
				hostless = true
			}
		}

		// Per-host handles (the wildcard-site idiom) yield one route per matched host.
		for _, hh := range p.handles {
			emitHandleRoutes(&state, hh, p.auth, loc)
		}

		if hostless {
			if p.dial != "" {
				permissive = true // host-less forward — anything reaches the backend
			}
			// A host-less deny/benign site keeps the default-deny; its unparsed
			// entries (if any) still count below.
		}
		for _, h := range hosts {
			if p.dial != "" {
				state.Routes = append(state.Routes, model.Route{
					Host: h, Ownership: model.OwnUnmanaged,
					Upstream: model.Upstream{
						Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy,
						Address: p.dial, ServerName: h, Auth: p.auth, UpstreamTLS: p.upstreamTLS,
					},
				})
			}
		}
		// A host site with NO modeled forward, NO understood terminal, NO per-host
		// handles and nothing declared unknown serves… nothing crenel can name.
		// Declare it rather than silently skip a site that plainly intends to serve.
		if len(hosts) > 0 && p.dial == "" && !p.denied && len(p.handles) == 0 && len(p.unparsed) == 0 &&
			strings.TrimSpace(s.body) != "" {
			p.unparsed = append(p.unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason: "site body yielded no modeled backend, terminal, or per-host handle",
			})
		}
		state.Unparsed = append(state.Unparsed, p.unparsed...)
	}
	state.DenyCatchAllPresent = !permissive
	return state
}

// emitHandleRoutes turns one per-host handle into routes (one per matched host),
// inheriting site-level auth when the handle carries none, and propagating the
// handle's own unparsed entries. A handle with no modeled backend and no terminal
// is declared unknown for its hosts — never silently dropped.
func emitHandleRoutes(state *model.LiveEdgeState, hh hostHandle, siteAuth, loc string) {
	auth := hh.parse.auth
	if auth == "" {
		auth = siteAuth
	}
	for _, h := range hh.hosts {
		if hh.parse.dial != "" {
			state.Routes = append(state.Routes, model.Route{
				Host:      h,
				Managed:   hh.managed,
				Ownership: model.OwnershipFromMarker(hh.managed),
				Upstream: model.Upstream{
					Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy,
					Address: hh.parse.dial, ServerName: h, Auth: auth, UpstreamTLS: hh.parse.upstreamTLS,
				},
			})
		} else if !hh.parse.denied && len(hh.parse.unparsed) == 0 {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason: fmt.Sprintf("handle for %s yielded no modeled backend or terminal", h),
			})
		}
	}
	state.Unparsed = append(state.Unparsed, hh.parse.unparsed...)
}
