package nginx

// tree_read.go is the NPM TREE read adapter (audit-any-edge M-A3): a read-only
// ports.EdgeProvider whose substrate is an Nginx Proxy Manager data directory —
// the `/data/nginx` tree NPM regenerates from its DB on every UI save. The
// zero-config target (`crenel audit /data/nginx`) wires it on the positive
// layout signature `proxy_host/*.conf` (risk A.5: signature, never best fit).
//
// What NPM actually generates (captured fixture, testdata/npm-tree, from a real
// jc21/nginx-proxy-manager container — provenance per design §9 decision 7):
//
//   proxy_host/<id>.conf   one file per proxy host: a top-level `map` block plus
//                          one server block. The backend is NOT a literal
//                          proxy_pass — it is `set $forward_scheme/$server/$port`
//                          variables consumed by `include conf.d/include/proxy.conf`
//                          inside `location /` (proxy.conf lives OUTSIDE the tree,
//                          under nginx's /etc/nginx prefix).
//   default_host/site.conf ONLY when the operator changed NPM's "Default Site"
//                          setting. The 444 flavor is `listen 80 default;` (the
//                          legacy alias of default_server) + `location / { return
//                          444; }` — a non-forwarding catch-all. With the setting
//                          untouched there is NO default server in the tree at
//                          all: the catch-all lives in /etc/nginx/conf.d/default.conf
//                          inside the container (port 80 serves the "Congratulations"
//                          page, port 443 is ssl_reject_handshake + return 444).
//
// Honesty contract (register §4, risks A.1/A.2/A.5):
//   - every proxy_host/*.conf is read in deterministic (sorted) order and folded
//     into ONE LiveEdgeState; a file that cannot be read is DECLARED Unparsed,
//     never silently skipped — deleting a file visibly shrinks coverage.
//   - `include` directives are followed ONLY when they resolve INSIDE the tree
//     root; an include pointing outside the root is DECLARED Unparsed — except
//     NPM's own fixed template includes under conf.d/include/ (see
//     npmStockIncludes), which are positively recognized parts of the generator's
//     template, not guesses.
//   - the deny ternary is decided against NPM's real shapes: a non-forwarding
//     `listen … default` server in default_host certifies the catch-all; an
//     ABSENT default_host means the default server lives outside the tree and is
//     declared Unparsed, so deny reads UNKNOWN (the honest verdict — the real
//     catch-all was not read).
//   - evidence is CONFIG (a tree on disk, not the running daemon): ReadEvidence
//     names the substrate ("N config file(s) under <root>…", risk A.1) and
//     carries the newest mtime for the staleness hint (risk A.2).
//
// Explicitly out of scope (design §4.2): NPM's SQLite DB (zero-dep Go takes no
// sqlite driver; the generated tree is the closer-to-live substrate anyway).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// npmGenerator is the generator name the whole tree reads as — matches
// detectGenerator's content signature so the gate/report vocabulary is one name.
const npmGenerator = "nginx-proxy-manager"

// treeIncludeDepthMax bounds recursive in-root include splicing — a cycle or a
// pathological chain terminates as a declared unknown, never a hang.
const treeIncludeDepthMax = 4

// npmStockIncludes is NPM's fixed template include set under conf.d/include/
// (outside the tree root, under nginx's /etc/nginx prefix — enumerated from the
// captured container). These are positively recognized as parts of the NPM
// template, NOT best-fit guesses: none of them can add a vhost or change what a
// host forwards where. proxy.conf is special-cased in resolveNPMProxyIdiom (it
// carries the proxy_pass that consumes the set-variables); the rest are
// filter/header/log/TLS plumbing. Any OTHER outside-root include — an operator's
// advanced_config `include /etc/nginx/…` — is foreign and is DECLARED Unparsed.
var npmStockIncludes = map[string]bool{
	"conf.d/include/assets.conf":                     true,
	"conf.d/include/block-exploits.conf":             true,
	"conf.d/include/force-ssl.conf":                  true,
	"conf.d/include/ip_ranges.conf":                  true,
	"conf.d/include/letsencrypt-acme-challenge.conf": true,
	"conf.d/include/log-proxy.conf":                  true,
	"conf.d/include/log-stream.conf":                 true,
	"conf.d/include/proxy.conf":                      true,
	"conf.d/include/resolvers.conf":                  true,
	"conf.d/include/ssl-cache-stream.conf":           true,
	"conf.d/include/ssl-cache.conf":                  true,
	"conf.d/include/ssl-ciphers.conf":                true,
}

var (
	includeRE = regexp.MustCompile(`(?m)^\s*include\s+([^;]+);`)
	// setVarRE captures NPM's backend variables: `set $server "10.0.0.5";`,
	// `set $port 3000;`, `set $forward_scheme http;` (quotes optional).
	setVarRE = regexp.MustCompile(`(?m)^\s*set\s+\$(\w+)\s+"?([^";\s]+)"?\s*;`)
	// mapHeadRE recognizes a top-level `map $var $newvar {` block. nginx's grammar
	// forbids server{} inside map{} — a map defines request-time variables and can
	// neither serve traffic nor hide a vhost/catch-all, so it is understood-benign
	// for exposure purposes (unlike http{}/stream{}/include chunks, which CAN hide
	// vhosts and stay declared-unknown in the base driver).
	mapHeadRE = regexp.MustCompile(`^\s*map\s+\S+\s+\S+\s*\{`)
)

// TreeReader is a READ-ONLY EdgeProvider over an NPM data-directory tree. It
// exists for the audit/status read path only: Plan and Apply refuse structurally
// (belt), and the target bootstrap additionally holds the engine behind
// core.ReadOnlyEngine (braces). A crenel write into this tree would be wiped on
// NPM's next regeneration — the refuse-to-manage gate's whole point.
type TreeReader struct {
	root string
}

// NewTreeReader builds the NPM tree read adapter rooted at dir. The tree is
// re-enumerated and re-read on every ReadLiveState — nothing cached, no state,
// so the type is trivially race-clean.
func NewTreeReader(root string) *TreeReader { return &TreeReader{root: root} }

// Name reports the driver family — the routes read here are nginx routes.
func (t *TreeReader) Name() string { return "nginx" }

// SniffNPMTree reports whether dir POSITIVELY matches the NPM data-directory
// layout: at least one proxy_host/*.conf. Used by the cmd target sniffer — an
// arbitrary directory of .conf files does NOT match (risk A.5: positive
// signature only; the generic-nginx-directory case is refused loudly upstream).
func SniffNPMTree(dir string) bool {
	m, err := filepath.Glob(filepath.Join(dir, "proxy_host", "*.conf"))
	return err == nil && len(m) > 0
}

// Validate confirms the layout signature still holds at read time.
func (t *TreeReader) Validate(context.Context) error {
	if !SniffNPMTree(t.root) {
		return fmt.Errorf("npm tree %s: no proxy_host/*.conf found — not an NPM data directory", t.root)
	}
	return nil
}

// Plan refuses: the tree is NPM's regeneration target, never a crenel write target.
func (t *TreeReader) Plan(model.Op, model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{}, fmt.Errorf("npm tree %s is READ-ONLY: this config is regenerated by nginx-proxy-manager from its DB — "+
		"a crenel edit would be wiped on the next UI save; manage these routes in the NPM UI", t.root)
}

// Apply refuses for the same reason as Plan (belt-and-braces: the target engine
// is also constructed ReadOnly, so this is unreachable in practice).
func (t *TreeReader) Apply(context.Context, model.ChangeSet) error {
	return fmt.Errorf("npm tree %s is READ-ONLY: refusing to write", t.root)
}

// ReadEvidence implements ports.EvidenceReporter: CONFIG — a tree on disk
// declared this state; the running daemon may differ. The Source string NAMES
// THE SUBSTRATE READ (risk A.1: "read N files under <root> — the running daemon
// may load more") and ModTime is the NEWEST mtime across the files (risk A.2
// staleness hint). Stat failures just shrink the hint — never an error.
func (t *TreeReader) ReadEvidence() model.ReadEvidence {
	files := t.enumerate()
	ev := model.ReadEvidence{
		Kind:   model.EvidenceConfig,
		Source: fmt.Sprintf("%d config file(s) under %s (an NPM tree — the running daemon may load more, e.g. its /etc/nginx defaults)", len(files), t.root),
	}
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(ev.ModTime) {
			ev.ModTime = fi.ModTime()
		}
	}
	return ev
}

// enumerate lists the tree files this reader parses, in deterministic sorted
// order: every proxy_host/*.conf plus every default_host/*.conf. (Other NPM
// dirs — redirection_host, dead_host, stream — are handled separately in
// ReadLiveState: each of their files is DECLARED, not parsed and not dropped.)
func (t *TreeReader) enumerate() []string {
	var files []string
	for _, sub := range []string{"proxy_host", "default_host"} {
		m, _ := filepath.Glob(filepath.Join(t.root, sub, "*.conf"))
		files = append(files, m...)
	}
	sort.Strings(files)
	return files
}

// ReadLiveState reads the whole tree and folds it into ONE LiveEdgeState.
// "Live" here is the TREE, not the daemon — the CONFIG-evidence caveat is
// carried by ReadEvidence and surfaced by audit's config_evidence_only finding.
//
// The deny model is TREE-WIDE (unlike the base driver's single-file normalize):
// nginx assembles all these files into one http{} context, so a denying
// default server in default_host/site.conf covers the ports the proxy_host
// files forward on. Per-port judgment is otherwise identical to the base
// driver (bench gap N4 semantics).
func (t *TreeReader) ReadLiveState(context.Context) (model.LiveEdgeState, error) {
	state := model.LiveEdgeState{}
	forwardingPorts := map[int]bool{}
	denyPorts := map[int]bool{}
	permissiveCatchAll := false
	sawDefaultServer := false
	var rawAll []string

	files := t.enumerate()
	for _, path := range files {
		rel, _ := filepath.Rel(t.root, path)
		b, err := os.ReadFile(path)
		if err != nil {
			// A file that vanished/broke between enumerate and read is DECLARED —
			// deny can no longer be certified over a tree crenel did not fully read.
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: rel, Kind: model.UnknownServerBlock,
				Reason: fmt.Sprintf("file could not be read: %v", err),
			})
			continue
		}
		text, incUnparsed := t.resolveIncludes(string(b), rel, 0)
		state.Unparsed = append(state.Unparsed, incUnparsed...)
		rawAll = append(rawAll, "# --- "+rel+" ---\n"+text)

		for _, c := range parseChunks(text) {
			if !c.isServer {
				// A top-level `map` block is understood-benign here (see mapHeadRE:
				// grammar-level, it cannot contain or hide a server). NPM emits one per
				// proxy_host file, so declaring it unknown would make EVERY NPM audit
				// read coverage-incomplete for a chunk that cannot affect exposure.
				// Anything ELSE non-server keeps the base driver's declared-unknown
				// posture — it could hide vhosts.
				if blankOrComment(c.raw) || mapHeadRE.MatchString(strings.TrimSpace(firstConfigLine(c.raw))) {
					continue
				}
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: rel + ": " + nonServerLocator(c.raw), Kind: model.UnknownServerBlock,
					Reason:     "top-level block is not a server{} crenel can model — any vhosts and their catch-all are not visible, so default-deny cannot be certified",
					RawExcerpt: boundedExcerpt(c.raw),
				})
				continue
			}
			if c.catchAll {
				sawDefaultServer = true
				if c.forwards {
					permissiveCatchAll = true
					for _, p := range portsOf(c) {
						forwardingPorts[p] = true
					}
				} else {
					// NPM's "444" default site: `listen 80 default;` + `return 444` —
					// a non-forwarding catch-all, structurally the same deny as
					// crenel's own rendered default_server.
					for _, p := range portsOf(c) {
						denyPorts[p] = true
					}
				}
				continue
			}
			if c.host == "" {
				if c.forwards {
					state.Unparsed = append(state.Unparsed, model.Unparsed{
						Locator: rel + ": server (no server_name)", Kind: model.UnknownMatcher,
						Reason:     "server block proxies traffic but has no server_name crenel can attribute it to",
						RawExcerpt: boundedExcerpt(c.raw),
					})
				}
				continue
			}
			if !c.forwards {
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: rel + ": server " + c.host, Kind: model.UnknownHandler,
					Reason:     fmt.Sprintf("server block for %s has no proxy_pass crenel can model (non-reverse-proxy vhost)", c.host),
					RawExcerpt: boundedExcerpt(c.raw),
				})
				continue
			}
			if c.pathScoped {
				// NPM "custom locations": extra `location <path> { proxy_pass … }`
				// blocks. The host-granular model cannot represent them — reading
				// host->firstBackend would silently drop the other paths' distinct
				// backends — so the host is DECLARED matcher_conditional (detected,
				// never misread), per M-A1 semantics.
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: rel + ": server " + c.host, Kind: model.UnknownMatcher,
					Reason: fmt.Sprintf("server block for %s routes by location path(s) crenel does not model (%s) — an NPM custom location; path-granular routing is not represented at host granularity",
						c.host, strings.Join(c.extraPaths, ", ")),
					RawExcerpt: boundedExcerpt(c.raw),
				})
				continue
			}
			// Auth on an NPM proxy host is an ACCESS LIST: auth_basic (+ allow/deny
			// client rules). Recognized-but-unnamed — AuthDetected, never
			// public_without_auth. An auth_request (custom advanced config) reads the
			// same way; nothing here is a crenel policy name (the tree is foreign).
			auth := ""
			if c.authURI != "" || c.authBasic {
				auth = model.AuthDetected
			}
			for _, p := range portsOf(c) {
				forwardingPorts[p] = true
			}
			state.Routes = append(state.Routes, model.Route{
				Host: c.host,
				// The whole tree is generator-owned: foreign per route, per M-A1
				// ownership semantics (set below edge-wide as well).
				Managed:   false,
				Ownership: model.OwnForeign,
				Upstream: model.Upstream{
					Kind:       model.ForwardToOrigin,
					Mode:       model.ModeHTTPProxy,
					Address:    c.addr,
					ServerName: c.host,
					Auth:       auth,
				},
			})
		}
	}

	// Other NPM host dirs (redirection_host, dead_host, stream) are not modeled by
	// this milestone — but their files are never silently dropped: each is DECLARED.
	for _, sub := range []string{"redirection_host", "dead_host", "stream"} {
		m, _ := filepath.Glob(filepath.Join(t.root, sub, "*.conf"))
		sort.Strings(m)
		for _, f := range m {
			rel, _ := filepath.Rel(t.root, f)
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: rel, Kind: model.UnknownServerBlock,
				Reason: fmt.Sprintf("NPM %s config is not modeled by the tree reader — its exposure effect is unknown", sub),
			})
		}
	}

	// Deny verdict, decided against NPM's REAL default-server behavior:
	//   - default_host present + non-forwarding catch-all => structural deny for its
	//     ports (checked per forwarding port below, bench gap N4 semantics).
	//   - NO default server anywhere in the tree => the catch-all lives OUTSIDE the
	//     tree (/etc/nginx/conf.d/default.conf in the container) — crenel did not
	//     read it, so it is DECLARED and the ternary honestly reads UNKNOWN, never a
	//     guessed ENFORCED (the container default is in fact non-forwarding, but a
	//     tree copied out of a container carries no proof of that).
	if !sawDefaultServer {
		state.DenyCatchAllPresent = true // fail-open is NOT proven either — see caddyfile_read's unbalanced-braces note
		state.Unparsed = append(state.Unparsed, model.Unparsed{
			Locator: "default server", Kind: model.UnknownServerBlock,
			Reason: "no default server in the tree (NPM's 'Default Site' setting is unchanged) — the catch-all lives outside the tree in the container's /etc/nginx/conf.d/default.conf, which this audit did not read; default-deny cannot be certified",
		})
	} else {
		state.DenyCatchAllPresent = !permissiveCatchAll
		for p := range forwardingPorts {
			if !denyPorts[p] {
				state.DenyCatchAllPresent = false
				break
			}
		}
	}

	// The tree IS the generator's output: foreign edge-wide. Layout signature is
	// the primary detection (this reader is only wired onto an NPM-shaped dir);
	// detectGenerator over the concatenated text corroborates from content.
	state.Generator = npmGenerator
	if g := detectGenerator(strings.Join(rawAll, "\n")); g != "" {
		state.Generator = g
	}
	state.Raw = strings.Join(rawAll, "\n")
	// The tree is what nginx boots from (NPM's nginx.conf includes it): durable.
	state.Persistence = model.PersistDurableConfig
	return state, nil
}

// firstConfigLine returns the first non-blank, non-comment line of a chunk —
// what mapHeadRE classifies against (NPM prefixes each map with a comment banner).
func firstConfigLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t
	}
	return ""
}

// resolveIncludes processes every `include` directive in one file's text,
// returning the effective text plus the declared unknowns. Three cases:
//
//  1. IN-ROOT include (absolute path under — or NPM-container-absolute
//     `/data/nginx/…` mapped into — the tree root): followed. Glob matches are
//     spliced in place (recursively, depth-bounded); a glob matching nothing is
//     understood-empty (nginx semantics: a wildcard include with no match is not
//     an error — NPM emits `include /data/nginx/custom/server_proxy[.]conf;` in
//     every file, usually matching nothing); a LITERAL in-root include whose file
//     is missing is DECLARED (nginx would refuse to load that config).
//  2. NPM stock template include (`conf.d/include/*.conf`, outside the root under
//     the nginx prefix): positively recognized. proxy.conf is rewritten to the
//     literal proxy_pass it implements (resolveNPMProxyIdiom); the rest are benign
//     template plumbing and are dropped as understood.
//  3. Anything else — a foreign/outside-root include — is DECLARED Unparsed
//     (never silently skipped, the P0 rule): its routing/auth effect is unknown.
func (t *TreeReader) resolveIncludes(text, rel string, depth int) (string, []model.Unparsed) {
	var unparsed []model.Unparsed
	vars := setVars(text)
	out := includeRE.ReplaceAllStringFunc(text, func(line string) string {
		m := includeRE.FindStringSubmatch(line)
		inc := strings.TrimSpace(m[1])
		switch {
		case npmStockIncludes[inc]:
			if inc == "conf.d/include/proxy.conf" {
				// The NPM proxy idiom: proxy.conf (outside the tree) carries
				// `proxy_pass $forward_scheme://$server:$port` — the variables are set
				// in THIS file's server block. Rewrite to the literal proxy_pass so the
				// shared classifier sees the forward. Positive recognition of the
				// generator's fixed template, not a guess: unresolvable variables mean
				// the idiom did NOT match and the include is declared instead.
				if s, ok := npmProxyPass(vars); ok {
					return s
				}
				unparsed = append(unparsed, model.Unparsed{
					Locator: rel, Kind: model.UnknownBackend,
					Reason: "NPM proxy include without resolvable $forward_scheme/$server/$port variables — the backend is unknown",
				})
				return "# crenel: declared-unknown include " + inc
			}
			// Stock filter/header/log/TLS plumbing from NPM's fixed template: cannot
			// add a vhost or change a forward — understood, contributes nothing.
			return "# crenel: understood NPM template include " + inc
		default:
			resolved, inRoot := t.rootRelative(inc)
			if !inRoot {
				unparsed = append(unparsed, model.Unparsed{
					Locator: rel, Kind: model.UnknownHandler,
					Reason:     fmt.Sprintf("includes %q which points OUTSIDE the audited tree — its routing/auth effect is unknown (this audit reads only the tree)", inc),
					RawExcerpt: strings.TrimSpace(line),
				})
				return "# crenel: declared-unknown include " + inc
			}
			if depth >= treeIncludeDepthMax {
				unparsed = append(unparsed, model.Unparsed{
					Locator: rel, Kind: model.UnknownHandler,
					Reason: fmt.Sprintf("include %q exceeds the include-nesting bound (%d) — possible cycle; not followed", inc, treeIncludeDepthMax),
				})
				return "# crenel: declared-unknown include " + inc
			}
			matches, _ := filepath.Glob(resolved)
			sort.Strings(matches)
			if len(matches) == 0 {
				if !strings.ContainsAny(inc, "*?[") {
					// A literal include whose target is missing: nginx would refuse to
					// load this config at all — declared, not ignored.
					unparsed = append(unparsed, model.Unparsed{
						Locator: rel, Kind: model.UnknownHandler,
						Reason: fmt.Sprintf("includes %q which does not exist in the tree", inc),
					})
					return "# crenel: declared-unknown include " + inc
				}
				// Wildcard with no match: valid, loads nothing (NPM's custom-snippet
				// include is exactly this shape on a stock install).
				return "# crenel: empty wildcard include " + inc
			}
			var spliced []string
			for _, mf := range matches {
				mb, err := os.ReadFile(mf)
				if err != nil {
					unparsed = append(unparsed, model.Unparsed{
						Locator: rel, Kind: model.UnknownHandler,
						Reason: fmt.Sprintf("include %q matched %s which could not be read: %v", inc, mf, err),
					})
					continue
				}
				mrel, _ := filepath.Rel(t.root, mf)
				childText, childUnparsed := t.resolveIncludes(string(mb), mrel, depth+1)
				unparsed = append(unparsed, childUnparsed...)
				spliced = append(spliced, childText)
			}
			return strings.Join(spliced, "\n")
		}
	})
	return out, unparsed
}

// rootRelative maps an include path to an on-disk path under the tree root and
// reports whether it stays INSIDE the root. Absolute paths using the container's
// canonical mount (`/data/nginx/…`) are re-rooted onto the audited copy (the
// fixture/an exported tree lives elsewhere on disk); other absolute paths are
// in-root only if they already point under the root. Relative paths resolve
// against nginx's prefix (/etc/nginx), never the tree — outside by definition.
// The cleaned result is prefix-checked so `..` segments cannot escape the root.
func (t *TreeReader) rootRelative(inc string) (string, bool) {
	if !strings.HasPrefix(inc, "/") {
		return "", false
	}
	var candidate string
	if i := strings.Index(inc, "/data/nginx/"); i == 0 {
		candidate = filepath.Join(t.root, inc[len("/data/nginx/"):])
	} else {
		candidate = filepath.Clean(inc)
	}
	rootAbs, err := filepath.Abs(t.root)
	if err != nil {
		return "", false
	}
	candAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", false
	}
	if candAbs != rootAbs && !strings.HasPrefix(candAbs, rootAbs+string(filepath.Separator)) {
		return "", false
	}
	return candAbs, true
}

// setVars extracts `set $name value;` assignments from a file's text (NPM sets
// exactly one backend per server block, so file scope is safe for its template).
func setVars(text string) map[string]string {
	vars := map[string]string{}
	for _, m := range setVarRE.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[2]
	}
	return vars
}

// npmProxyPass renders the literal proxy_pass NPM's proxy.conf would execute for
// the file's set-variables. ok=false when any variable is missing or itself a
// variable reference (unresolvable => the idiom did not match).
func npmProxyPass(vars map[string]string) (string, bool) {
	scheme, server, port := vars["forward_scheme"], vars["server"], vars["port"]
	if scheme == "" || server == "" || port == "" ||
		strings.Contains(scheme+server+port, "$") {
		return "", false
	}
	return fmt.Sprintf("proxy_pass %s://%s:%s;", scheme, server, port), true
}

// mtime staleness + config_evidence_only are core's job (M-A2 machinery) — the
// reader only reports ReadEvidence; see internal/core/audit.go.
var _ interface{ ReadEvidence() model.ReadEvidence } = (*TreeReader)(nil)
