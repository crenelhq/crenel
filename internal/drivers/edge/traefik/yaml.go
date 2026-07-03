package traefik

import (
	"fmt"
	"strconv"
	"strings"
)

// yaml.go is a DELIBERATELY MINIMAL, ZERO-DEPENDENCY YAML-SUBSET decoder, scoped to
// exactly the shape of a Traefik file-provider dynamic config (the http/tcp/udp →
// routers/services/middlewares maps and the nested fields crenel reads). It exists
// because real Traefik dynamic files are YAML/TOML while crenel stays zero-dependency by
// design (supply chain + brand). It is NOT a general YAML engine.
//
// Supported subset (enough to faithfully read a real dynamic.yml):
//   - block mappings (indentation, `key: value` / `key:` + indented block)
//   - block sequences (`- item`, including `- key: val` mappings with continuation)
//   - flow sequences (`[a, b]`) and flow mappings (`{a: b}`)
//   - plain / single-quoted / double-quoted scalars (incl. backticks in a Host(`x`) rule)
//   - `#` comments (quote-aware), `---` / `...` document markers, blank lines
//   - scalar typing: int, float, bool, null/~, else string
//
// Explicitly OUT OF SCOPE (errors loudly rather than mis-parsing): TOML; YAML anchors/
// aliases/tags, multi-document streams, and block scalars (`|` `>`). None appear in a
// Traefik dynamic config crenel reads. The output is a generic map[string]any/[]any/
// scalar tree that decode() marshals to JSON and unmarshals into dynamicConfig, sharing
// the struct-tag shape mapping with the JSON path.

type yamlLine struct {
	indent int
	text   string // content, leading indentation and trailing comment stripped
}

type yamlParser struct {
	lines []yamlLine
	pos   int
}

// parseYAMLSubset parses a Traefik dynamic config (YAML subset) into a generic tree.
func parseYAMLSubset(text string) (any, error) {
	var lines []yamlLine
	for _, raw := range strings.Split(text, "\n") {
		content := stripYAMLComment(raw)
		if strings.TrimSpace(content) == "" {
			continue // blank or comment-only
		}
		ts := strings.TrimSpace(content)
		if ts == "---" || ts == "..." {
			continue // document markers (single doc only)
		}
		if strings.HasPrefix(ts, "|") || strings.HasPrefix(ts, ">") {
			return nil, fmt.Errorf("block scalars (|, >) are unsupported in crenel's Traefik YAML subset: %q", ts)
		}
		indent := 0
		for _, r := range content {
			if r == ' ' {
				indent++
				continue
			}
			if r == '\t' {
				return nil, fmt.Errorf("tab in indentation (YAML forbids tabs for indentation): %q", raw)
			}
			break
		}
		lines = append(lines, yamlLine{indent: indent, text: ts})
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	p := &yamlParser{lines: lines}
	base := lines[0].indent
	if isSeqLine(lines[0].text) {
		return p.parseSequence(base)
	}
	return p.parseMapping(base)
}

func isSeqLine(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// parseMapping consumes consecutive lines at exactly `indent` as `key: value` entries.
func (p *yamlParser) parseMapping(indent int) (map[string]any, error) {
	m := map[string]any{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			break // dedent: end of this mapping
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("unexpected indentation in mapping at %q", ln.text)
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			break // not a mapping line (caller handles, e.g. a sequence)
		}
		p.pos++
		if rest != "" {
			v, err := parseScalarOrFlow(rest)
			if err != nil {
				return nil, err
			}
			m[key] = v
			continue
		}
		// `key:` with no inline value → nested block (mapping or sequence) below.
		if p.pos >= len(p.lines) {
			m[key] = nil
			break
		}
		next := p.lines[p.pos]
		switch {
		case isSeqLine(next.text) && next.indent >= indent:
			// A block sequence value may sit at the SAME indent as its key, or deeper.
			seq, err := p.parseSequence(next.indent)
			if err != nil {
				return nil, err
			}
			m[key] = seq
		case next.indent > indent:
			child, err := p.parseMapping(next.indent)
			if err != nil {
				return nil, err
			}
			m[key] = child
		default:
			m[key] = nil
		}
	}
	return m, nil
}

// parseSequence consumes consecutive `- ...` items at exactly `indent`.
func (p *yamlParser) parseSequence(indent int) ([]any, error) {
	var seq []any
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || !isSeqLine(ln.text) {
			break
		}
		content := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		if content == "" {
			// `-` alone: the element is a block on the following deeper lines.
			p.pos++
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				next := p.lines[p.pos]
				if isSeqLine(next.text) {
					v, err := p.parseSequence(next.indent)
					if err != nil {
						return nil, err
					}
					seq = append(seq, v)
				} else {
					v, err := p.parseMapping(next.indent)
					if err != nil {
						return nil, err
					}
					seq = append(seq, v)
				}
			} else {
				seq = append(seq, nil)
			}
			continue
		}
		if k, _, ok := splitKey(content); ok && k != "" {
			// `- key: val` mapping element. Rewrite this line as a mapping line whose
			// keys align at indent+2 (the column after "- "), so continuation keys of
			// THIS item (also at indent+2) are consumed and the next dash at `indent`
			// terminates the item.
			p.lines[p.pos].text = content
			p.lines[p.pos].indent = indent + 2
			mp, err := p.parseMapping(indent + 2)
			if err != nil {
				return nil, err
			}
			seq = append(seq, mp)
			continue
		}
		// Scalar element.
		p.pos++
		v, err := parseScalarOrFlow(content)
		if err != nil {
			return nil, err
		}
		seq = append(seq, v)
	}
	return seq, nil
}

// splitKey splits a `key: value` line at the first quote/flow-aware separator colon
// (a colon followed by a space or end of line). Returns ok=false when there is no such
// separator (e.g. a bare scalar). A quoted key is unquoted.
func splitKey(s string) (key, val string, ok bool) {
	inS, inD := false, false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
		case c == ':' && depth == 0:
			if i+1 >= len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
				key = unquoteScalarKey(strings.TrimSpace(s[:i]))
				val = strings.TrimSpace(s[i+1:])
				return key, val, key != ""
			}
		}
	}
	return "", "", false
}

func unquoteScalarKey(k string) string {
	if v, ok := parseScalar(k).(string); ok {
		return v
	}
	return k
}

// parseScalarOrFlow parses an inline value: a flow sequence/map, or a scalar.
func parseScalarOrFlow(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '[':
		return parseFlowSeq(s)
	case '{':
		return parseFlowMap(s)
	default:
		return parseScalar(s), nil
	}
}

func parseFlowSeq(s string) (any, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("malformed flow sequence (missing ]): %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []any{}, nil
	}
	parts, err := splitTopLevelCommas(inner)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		v, err := parseScalarOrFlow(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func parseFlowMap(s string) (any, error) {
	if !strings.HasSuffix(s, "}") {
		return nil, fmt.Errorf("malformed flow mapping (missing }): %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := map[string]any{}
	if inner == "" {
		return out, nil
	}
	parts, err := splitTopLevelCommas(inner)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		k, v, ok := splitKey(strings.TrimSpace(p))
		if !ok {
			return nil, fmt.Errorf("malformed flow-mapping entry: %q", p)
		}
		val, err := parseScalarOrFlow(v)
		if err != nil {
			return nil, err
		}
		out[k] = val
	}
	return out, nil
}

// splitTopLevelCommas splits on commas not inside quotes or nested flow brackets.
func splitTopLevelCommas(s string) ([]string, error) {
	var parts []string
	var b strings.Builder
	inS, inD := false, false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	parts = append(parts, b.String())
	return parts, nil
}

// parseScalar converts a bare/quoted YAML scalar to a typed Go value.
func parseScalar(s string) any {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unquoteDouble(s[1 : len(s)-1])
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	switch s {
	case "true", "True", "TRUE":
		return true
	case "false", "False", "FALSE":
		return false
	case "null", "Null", "NULL", "~":
		return nil
	}
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

// unquoteDouble unescapes the common escapes of a YAML double-quoted scalar body
// (without the surrounding quotes). A backtick is an ordinary character — so a
// "Host(`x`)" rule round-trips unchanged.
func unquoteDouble(inner string) string {
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' && i+1 < len(inner) {
			i++
			switch inner[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case '/':
				b.WriteByte('/')
			default:
				b.WriteByte('\\')
				b.WriteByte(inner[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// stripYAMLComment removes a trailing `#` comment, treating `#` as a comment start only
// at line start or after whitespace and only outside quotes (so a `#` inside a quoted
// scalar or a URL fragment is preserved).
func stripYAMLComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			}
		case inD:
			if c == '"' {
				inD = false
			}
		case c == '\'':
			inS = true
		case c == '"':
			inD = true
		case c == '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}
