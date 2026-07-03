// Package yaml is a MINIMAL YAML-subset decoder, scoped to exactly the shapes
// Crenel's config and apply files use. Crenel is a deliberately zero-dependency,
// fully-offline build (it hand-rolls its nginx/Caddyfile/Traefik parsers rather
// than take a dep); a full YAML module would break that, so this small,
// schema-bounded decoder lives in-repo in the same spirit.
//
// SUPPORTED: block mappings (`key: value`), block sequences (`- item`), nested
// indentation (spaces; 2-space is conventional but any consistent step works),
// `# ` comments (whole-line and trailing), quoted scalars ("..." / '...'),
// integers, booleans, and flow lists (`[a, b, c]`). Sequence items may be scalars
// or maps whose first key is inline after the dash.
//
// NOT SUPPORTED (out of scope; rejected or ignored): tabs for indentation, flow
// maps ({a: b}), anchors/aliases, multi-document streams, multiline/folded
// scalars, explicit tags. The schema never needs them.
//
// Implementation: parse into a generic tree (map[string]any / []any / scalars,
// the SAME shape encoding/json produces) then JSON-roundtrip into the target
// struct, so struct mapping reuses the existing `json:` tags — no second tag set.
package yaml

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Unmarshal decodes the YAML-subset document in b into v (any json-tagged type).
func Unmarshal(b []byte, v any) error {
	tree, err := Parse(b)
	if err != nil {
		return err
	}
	js, err := json.Marshal(tree)
	if err != nil {
		return fmt.Errorf("yaml: re-encode: %w", err)
	}
	if err := json.Unmarshal(js, v); err != nil {
		return fmt.Errorf("yaml: map into %T: %w", v, err)
	}
	return nil
}

// Parse decodes the document into a generic tree (map[string]any, []any, or a
// scalar). An empty document yields a nil tree.
func Parse(b []byte) (any, error) {
	toks, err := tokenize(string(b))
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, nil
	}
	val, next, err := parseBlock(toks, 0)
	if err != nil {
		return nil, err
	}
	if next != len(toks) {
		return nil, fmt.Errorf("yaml: trailing content at line %d (%q)", toks[next].line, toks[next].text)
	}
	return val, nil
}

// token is one significant line: its indentation, its comment-stripped text, and
// the source line number (for errors).
type token struct {
	indent int
	text   string
	line   int
}

// tokenize splits the source into significant tokens (dropping blank lines and
// comments) and computes each line's indentation. Tabs in indentation are an
// error (ambiguous).
func tokenize(src string) ([]token, error) {
	var out []token
	for n, raw := range strings.Split(src, "\n") {
		// Indentation first (before stripping comments), tabs rejected.
		indent := 0
		for indent < len(raw) {
			switch raw[indent] {
			case ' ':
				indent++
				continue
			case '\t':
				return nil, fmt.Errorf("yaml: tab indentation at line %d (use spaces)", n+1)
			}
			break
		}
		content := strings.TrimRight(raw[indent:], " \r\t")
		if content == "" || strings.HasPrefix(content, "#") {
			continue // blank or whole-line comment
		}
		if content == "---" {
			continue // tolerate a leading document marker
		}
		text := stripComment(content)
		if strings.TrimSpace(text) == "" {
			continue
		}
		out = append(out, token{indent: indent, text: text, line: n + 1})
	}
	return out, nil
}

// stripComment removes a trailing ` # comment` that is outside any quotes. A `#`
// at column 0 of the text (whole-line comment) is already handled by tokenize via
// the blank check; here we only trim inline comments preceded by whitespace.
func stripComment(s string) string {
	var inS, inD bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return s
}

// parseBlock parses the block beginning at toks[i] (a mapping or a sequence,
// decided by whether the first line is a `- ` item). Returns the value and the
// index of the first token NOT consumed.
func parseBlock(toks []token, i int) (any, int, error) {
	if isSeqItem(toks[i].text) {
		return parseSeq(toks, i)
	}
	return parseMap(toks, i)
}

// parseMap parses a block mapping: consecutive `key: …` lines at one indent.
func parseMap(toks []token, i int) (any, int, error) {
	result := map[string]any{}
	indent := toks[i].indent
	for i < len(toks) && toks[i].indent == indent && !isSeqItem(toks[i].text) {
		key, rest, ok := splitKey(toks[i].text)
		if !ok {
			return nil, i, fmt.Errorf("yaml: expected `key: value` at line %d (%q)", toks[i].line, toks[i].text)
		}
		i++
		if rest != "" {
			v, err := parseScalar(rest)
			if err != nil {
				return nil, i, fmt.Errorf("yaml: line %d: %w", toks[i-1].line, err)
			}
			result[key] = v
			continue
		}
		// Empty value => a nested block on following lines: either more-indented
		// (conventional) or a same-indent sequence (YAML allows `- ` under a key).
		if i < len(toks) && (toks[i].indent > indent || (toks[i].indent == indent && isSeqItem(toks[i].text))) {
			v, next, err := parseBlock(toks, i)
			if err != nil {
				return nil, next, err
			}
			result[key] = v
			i = next
		} else {
			result[key] = nil
		}
	}
	return result, i, nil
}

// parseSeq parses a block sequence: consecutive `- …` items at one indent.
func parseSeq(toks []token, i int) (any, int, error) {
	list := []any{}
	indent := toks[i].indent
	for i < len(toks) && toks[i].indent == indent && isSeqItem(toks[i].text) {
		inline := strings.TrimSpace(strings.TrimPrefix(toks[i].text, "-"))
		line := i
		i++
		switch {
		case inline == "":
			// Item is a nested block on following more-indented lines.
			if i < len(toks) && toks[i].indent > indent {
				v, next, err := parseBlock(toks, i)
				if err != nil {
					return nil, next, err
				}
				list = append(list, v)
				i = next
			} else {
				list = append(list, nil)
			}
		case isMapInline(inline):
			// Map item whose first key is inline after the dash; following
			// more-indented lines belong to the same item. Build a synthetic block
			// (virtual first line + the deeper continuation lines) and parse it.
			virtIndent := toks[line].indent + 2
			sub := []token{{indent: virtIndent, text: inline, line: toks[line].line}}
			for i < len(toks) && toks[i].indent > indent {
				sub = append(sub, toks[i])
				i++
			}
			v, _, err := parseBlock(sub, 0)
			if err != nil {
				return nil, i, err
			}
			list = append(list, v)
		default:
			v, err := parseScalar(inline)
			if err != nil {
				return nil, i, fmt.Errorf("yaml: line %d: %w", toks[line].line, err)
			}
			list = append(list, v)
		}
	}
	return list, i, nil
}

// isSeqItem reports whether a line is a sequence item ("- x" or a bare "-").
func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// isMapInline reports whether an inline value (after a dash) begins a mapping —
// i.e. it has a `key:`-shaped head — rather than being a scalar that merely
// contains a colon (like a host:port).
func isMapInline(s string) bool {
	_, _, ok := splitKey(s)
	return ok
}

// splitKey splits a `key: value` line on the first `: ` separator (or a trailing
// `:`), so values containing colons (URLs, host:port) are not mis-split. Returns
// ok=false when the line is not a mapping entry.
func splitKey(s string) (key, value string, ok bool) {
	if idx := strings.Index(s, ": "); idx >= 0 {
		return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+2:]), true
	}
	if strings.HasSuffix(s, ":") {
		return strings.TrimSpace(s[:len(s)-1]), "", true
	}
	return "", "", false
}

// parseScalar parses a scalar (or flow list) value: a quoted string, a flow list
// [a, b], a bool, an int, or a bare string.
func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "~" || s == "null" {
		return nil, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return parseFlowList(s)
	}
	if q, ok := unquote(s); ok {
		return q, nil
	}
	switch s {
	case "true", "True", "TRUE", "yes":
		return true, nil
	case "false", "False", "FALSE", "no":
		return false, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	return s, nil
}

// parseFlowList parses `[a, b, c]` into a []any of scalars.
func parseFlowList(s string) (any, error) {
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := []any{}
	if inner == "" {
		return out, nil
	}
	for _, part := range strings.Split(inner, ",") {
		v, err := parseScalar(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// unquote unwraps a "double" or 'single' quoted scalar. Double quotes honor \"
// and \\ escapes; single quotes are literal. Returns ok=false if s is not quoted.
func unquote(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u, true
		}
		// Fall back to a naive strip for non-Go-escaped content.
		return s[1 : len(s)-1], true
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1], true
	}
	return "", false
}
