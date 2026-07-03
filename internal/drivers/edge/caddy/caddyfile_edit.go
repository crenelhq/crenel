package caddy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// caddyfile_edit.go holds the LOW-LEVEL, brace-aware surgery the durable reconciler
// uses to maintain crenel's managed region INSIDE the operator's hand-written Caddyfile
// — without a full Caddyfile parser and without disturbing a single operator byte.
//
// The real home edge routes EVERY service through wildcard site blocks
// (`*.homelab.example { … }`) with per-host `@name host X` matchers + `handle @name {
// reverse_proxy … }` pairs. So the durable form of an admin-API write is a per-host
// handle INSIDE the covering wildcard site, where it inherits that site's TLS
// (`dns cloudflare …`) and listener — NOT a new top-level `host {}` site, which would
// be MORE specific than the wildcard, shadow it, and (lacking the wildcard's tls block)
// fail cert issuance. That shadowing hazard is exactly why the flat top-level persister
// (persist.go) is unsafe on a wildcard edge; this file is the wildcard-faithful path.
//
// crenel owns ONLY a sentinel-delimited region inside the covering site; everything
// else (the operator's own handles, the tls block, comments, formatting) is preserved
// byte-for-byte. Managed handles carry the `@crenel_<host>` label — the Caddyfile
// analogue of the admin-JSON `@id crenel-route-<host>` marker.

// crenelLabel returns the matcher label crenel uses for a managed handle of host. It is
// the on-disk ownership marker: crenel inserts/removes ONLY `@crenel_<host>` handles and
// never touches an operator-labeled one. Dots/dashes → underscores (a Caddyfile matcher
// label is a single token).
func crenelLabel(host string) string {
	r := strings.NewReplacer(".", "_", "-", "_", "*", "wild")
	return "crenel_" + r.Replace(strings.ToLower(host))
}

// renderInSiteHandles renders crenel's managed per-host handles in the operator's
// in-wildcard idiom — `@crenel_<host> host <host>` + `handle @crenel_<host> { … }` —
// indented one level (inside a site block). A route with a forward-auth policy emits
// `import <snippet>` before the backend (the canonical Caddyfile auth-by-reference, the
// exact form the home edge uses); a route dialing an HTTPS upstream emits the
// `https://` + Host-preservation + transport.tls shape (faithful to the cctv/front-leg
// idiom). Sorted for stable, idempotent output.
func renderInSiteHandles(routes []model.Route, snippetFor func(string) string) string {
	sorted := append([]model.Route(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })
	var b strings.Builder
	for _, r := range sorted {
		label := crenelLabel(r.Host)
		fmt.Fprintf(&b, "\t@%s host %s\n", label, r.Host)
		fmt.Fprintf(&b, "\thandle @%s {\n", label)
		if policy := r.Upstream.Auth; policy != "" && policy != model.AuthNone && policy != model.AuthDetected {
			fmt.Fprintf(&b, "\t\timport %s\n", snippetFor(policy))
		}
		if r.Upstream.UpstreamTLS {
			fmt.Fprintf(&b, "\t\treverse_proxy https://%s {\n", r.Upstream.Address)
			fmt.Fprintf(&b, "\t\t\theader_up Host {http.request.host}\n")
			fmt.Fprintf(&b, "\t\t\ttransport http {\n\t\t\t\ttls_insecure_skip_verify\n\t\t\t}\n")
			fmt.Fprintf(&b, "\t\t}\n")
		} else {
			fmt.Fprintf(&b, "\t\treverse_proxy %s\n", r.Upstream.Address)
		}
		fmt.Fprintf(&b, "\t}\n")
	}
	return b.String()
}

// parseInSiteRegion parses crenel's managed region back OUT of a site body — the
// inverse of renderInSiteHandles. It is the load-bearing self-check input: after
// rendering a candidate, the reconciler parses its own region back and asserts it
// reproduces exactly the managed routes (so a render bug fails BEFORE any disk write).
// It reads only crenel's own `@crenel_*`/`handle` pairs between the sentinels; operator
// handles outside the region are ignored.
func parseInSiteRegion(siteBody string) []model.Route {
	region, ok := extractRegion(siteBody)
	if !ok {
		return nil
	}
	return parseHandles(region)
}

// parseHandles parses `@label host <h>` + `handle @label { [import S] reverse_proxy
// [https://]A … }` pairs from a block of Caddyfile text into routes. Tolerant of
// indentation. Used by the self-check (crenel's own region) and the faithful fake
// adapter (operator + crenel handles within a site).
func parseHandles(text string) []model.Route {
	lines := strings.Split(text, "\n")
	hostOf := map[string]string{} // matcher label -> host
	for _, ln := range lines {
		f := strings.Fields(stripComment(ln))
		// @label host <host>
		if len(f) == 3 && strings.HasPrefix(f[0], "@") && f[1] == "host" {
			hostOf[strings.TrimPrefix(f[0], "@")] = f[2]
		}
	}
	var out []model.Route
	for i := 0; i < len(lines); i++ {
		f := strings.Fields(stripComment(lines[i]))
		if len(f) < 2 || f[0] != "handle" || !strings.HasPrefix(f[1], "@") {
			continue
		}
		label := strings.TrimPrefix(f[1], "@")
		host, ok := hostOf[label]
		if !ok {
			continue
		}
		// Scan the handle body to its closing brace for import/reverse_proxy.
		depth := strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		r := model.Route{Host: host, Managed: true, Ownership: model.OwnCrenel,
			Upstream: model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, ServerName: host}}
		for j := i + 1; j < len(lines) && depth > 0; j++ {
			bf := strings.Fields(stripComment(lines[j]))
			if len(bf) >= 2 && bf[0] == "import" {
				r.Upstream.Auth = bf[1]
			}
			if len(bf) >= 2 && bf[0] == "reverse_proxy" {
				addr := bf[1]
				if strings.HasPrefix(addr, "https://") {
					r.Upstream.Address = strings.TrimPrefix(addr, "https://")
					r.Upstream.UpstreamTLS = true
				} else {
					r.Upstream.Address = addr
				}
			}
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			if depth <= 0 {
				i = j
				break
			}
		}
		if r.Upstream.Address != "" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// extractRegion returns the text BETWEEN the crenel sentinels (exclusive), and whether
// a well-formed region exists.
func extractRegion(text string) (string, bool) {
	bi := strings.Index(text, persistBegin)
	if bi < 0 {
		return "", false
	}
	rest := text[bi+len(persistBegin):]
	ei := strings.Index(rest, persistEnd)
	if ei < 0 {
		return "", false
	}
	return rest[:ei], true
}

// mergeInSiteRegion replaces (or inserts) crenel's managed region INSIDE the site block
// whose address satisfies addrMatch, preserving every operator byte outside the region.
// block is the rendered handles (already tab-indented; may be empty to clear the
// region). It returns the new Caddyfile text and ok=false if no matching site exists
// (the caller then refuses rather than guess where to write). Idempotent: a second call
// with the same block yields identical output.
func mergeInSiteRegion(caddyfile string, addrMatch func(addr string) bool, block string) (string, bool) {
	site, found := findSiteBlock(caddyfile, addrMatch)
	if !found {
		return caddyfile, false
	}
	body := caddyfile[site.bodyStart:site.bodyEnd] // between the site's { and }

	region := "\t" + persistBegin + "\n" + strings.TrimRight(block, "\n") + "\n\t" + persistEnd + "\n"
	if strings.TrimSpace(block) == "" {
		region = "" // clearing: drop the region entirely (no empty sentinels left behind)
	}

	var newBody string
	if bi := strings.Index(body, persistBegin); bi >= 0 {
		// Replace from the indentation before persistBegin through persistEnd's line end.
		lineStart := strings.LastIndex(body[:bi], "\n") + 1
		after := body[bi:]
		ei := strings.Index(after, persistEnd)
		endIdx := bi + ei + len(persistEnd)
		// consume to end of that line
		if nl := strings.IndexByte(caddyfile[site.bodyStart+endIdx:], '\n'); nl >= 0 {
			endIdx += nl + 1
		}
		newBody = body[:lineStart] + region + body[endIdx:]
	} else {
		// No region yet — insert just before the site's closing brace, preserving the
		// operator's trailing newline/indentation of the `}` line.
		trimmed := strings.TrimRight(body, " \t")
		sep := ""
		if !strings.HasSuffix(trimmed, "\n") {
			sep = "\n"
		}
		newBody = trimmed + sep + region
	}
	return caddyfile[:site.bodyStart] + newBody + caddyfile[site.bodyEnd:], true
}

// siteSpan locates a top-level site block: bodyStart is the byte just after the opening
// `{`, bodyEnd the byte of the closing `}`.
type siteSpan struct {
	addr               string
	bodyStart, bodyEnd int
}

// findSiteBlock finds the FIRST top-level site block whose address token satisfies
// addrMatch. It walks top-level entries one at a time: when a line at the top level ends
// in `{` it is a block opener, whose matching close is found via matchClose (brace-
// counted, comment-aware) so the whole block is consumed as a unit. A global `{ … }`
// block and `(snippet) { … }` blocks are NOT sites and are skipped. Returning a span
// only on an addr match means a non-site block can never be mistaken for the target.
func findSiteBlock(text string, addrMatch func(addr string) bool) (siteSpan, bool) {
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
			// A top-level block opener. Consume the WHOLE block as a unit (so a global
			// `{ … }` or `(snippet) { … }` body is never scanned as if it held sites). Only
			// a real SITE block — not global `{`, not `(snippet)` — is a candidate to return.
			bodyStart := i + strings.LastIndexByte(header, '{') + 1
			bodyEnd, ok := matchClose(text, bodyStart)
			if !ok {
				return siteSpan{}, false // unbalanced — refuse rather than guess
			}
			isSite := trimmed != "{" && !strings.HasPrefix(trimmed, "(")
			if isSite {
				addr := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
				if addrMatch(addr) {
					return siteSpan{addr: addr, bodyStart: bodyStart, bodyEnd: bodyEnd}, true
				}
			}
			i = bodyEnd + 1 // skip past the consumed block
			continue
		}
		i = next
	}
	return siteSpan{}, false
}

// matchClose walks from bodyStart (just inside an opening `{`, depth 1) to the byte
// index of its matching `}`, ignoring braces inside `#` comments. ok=false if the brace
// never balances.
func matchClose(text string, bodyStart int) (int, bool) {
	d := 1
	for j := bodyStart; j < len(text); j++ {
		switch text[j] {
		case '#':
			if nl := strings.IndexByte(text[j:], '\n'); nl >= 0 {
				j += nl // for-loop's j++ then lands past the newline
				continue
			}
			return 0, false
		case '{':
			d++
		case '}':
			d--
			if d == 0 {
				return j, true
			}
		}
	}
	return 0, false
}

// stripComment removes a `#` comment from a line (best-effort: ignores `#` inside
// quotes, which Caddyfiles essentially never use in the constructs crenel edits).
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}
