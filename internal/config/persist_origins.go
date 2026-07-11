package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SetTopLevelOrigin writes an entry (service -> backend) into the top-level
// `origins:` map of the settings file at path. It is the persistence path for
// the `crenel expose <svc> --to <host:port>` shape: after a verified apply
// lands the route live, the CLI records the same (service, backend) into the
// file so `status`/`audit`/`drift`/`reconcile` stay coherent on later runs
// (they read origins to know which service crenel fronts and to re-derive the
// upstream address on a reconcile add).
//
// Multi-edge topology (top-level `edges:` non-empty) is REFUSED: origins there
// live per-edge and this helper cannot unambiguously pick which edge should
// front the service. The caller must have already validated that.
//
// scope, when set to OriginScopeInternal, persists the STRUCTURED entry form
// ({addr, scope: internal}) so the declared internal-only intent survives the
// invocation and drives later drift/reconcile/audit demands — the `expose <svc>
// --scope internal --to <addr>` shape. Empty scope keeps the plain-string form
// byte-compatibly.
//
// Format is chosen by extension (.json vs .yaml/.yml). JSON goes through a
// standard encoding/json round-trip. YAML uses a surgical text-insert that
// preserves the operator's comments and layout — the yaml-subset decoder in
// this package is decode-only, and a full re-emit would strip formatting.
func SetTopLevelOrigin(path, service, backend, scope string) error {
	if path == "" {
		return fmt.Errorf("no settings file to persist into (pass -config <path>)")
	}
	if service == "" || backend == "" {
		return fmt.Errorf("service and backend are required")
	}
	switch scope {
	case OriginScopeDefault, OriginScopeInternal:
	default:
		return fmt.Errorf("cannot persist origins entry with unknown scope %q", scope)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read settings %q: %w", path, err)
	}
	if isYAML(path, b) {
		return writeOriginYAML(path, b, service, backend, scope)
	}
	return writeOriginJSON(path, b, service, backend, scope)
}

// writeOriginJSON updates the top-level `origins` object via a full JSON round-trip.
// Existing entries decode through the polymorphic Origin form, so a config that
// already carries structured (scoped) entries round-trips them intact.
func writeOriginJSON(path string, src []byte, service, backend, scope string) error {
	var raw map[string]json.RawMessage
	if len(strings.TrimSpace(string(src))) == 0 {
		raw = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(src, &raw); err != nil {
		return fmt.Errorf("parse settings JSON %q: %w", path, err)
	}
	if _, ok := raw["edges"]; ok {
		return fmt.Errorf("multi-edge config (%q has `edges`): --to cannot pick a target edge — add `%s: %s` to the edge's origins map manually", path, service, backend)
	}
	origins := Origins{}
	if r, ok := raw["origins"]; ok && len(r) > 0 {
		if err := json.Unmarshal(r, &origins); err != nil {
			return fmt.Errorf("parse origins in %q: %w", path, err)
		}
	}
	origins[service] = Origin{Addr: backend, Scope: scope}
	enc, err := json.Marshal(origins)
	if err != nil {
		return fmt.Errorf("encode origins: %w", err)
	}
	raw["origins"] = enc
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o600)
}

// writeOriginYAML surgically inserts (or replaces) the service's entry under the
// top-level `origins:` block, preserving everything else byte-for-byte. A
// default-scope entry is the historical one-liner (`svc: "addr"`); an
// internal-scope entry is a nested BLOCK map — the shape the yaml-subset
// decoder supports (flow maps `{...}` are deliberately out of its scope):
//
//	ha:
//	  addr: "10.0.0.19:8123"
//	  scope: internal
//
// Refuses multi-edge (top-level `edges:`) — the operator must edit the
// per-edge origins manually there.
func writeOriginYAML(path string, src []byte, service, backend, scope string) error {
	text := string(src)
	if hasTopLevelKey(text, "edges") {
		return fmt.Errorf("multi-edge config (%q has `edges`): --to cannot pick a target edge — add `%s: %s` to the edge's origins map manually", path, service, backend)
	}

	updated, ok := replaceOrInsertOriginYAML(text, service, backend, scope)
	if !ok {
		// No top-level `origins:` key found — append a fresh block at end of file.
		var sb strings.Builder
		sb.WriteString(text)
		if len(text) > 0 && !strings.HasSuffix(text, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("origins:\n")
		sb.WriteString(strings.Join(originEntryLines(service, backend, scope, 2), "\n"))
		sb.WriteString("\n")
		updated = sb.String()
	}
	return os.WriteFile(path, []byte(updated), 0o600)
}

// originEntryLines renders the YAML lines for one origins entry at the given
// child indent: a single quoted-scalar line for the default scope, or the
// nested block map for a scoped entry (child fields one extra level in).
func originEntryLines(service, backend, scope string, indent int) []string {
	pad := strings.Repeat(" ", indent)
	if scope == OriginScopeDefault {
		return []string{fmt.Sprintf("%s%s: %q", pad, service, backend)}
	}
	sub := strings.Repeat(" ", indent+2)
	return []string{
		pad + service + ":",
		fmt.Sprintf("%saddr: %q", sub, backend),
		sub + "scope: " + scope,
	}
}

// replaceOrInsertOriginYAML edits the top-level `origins:` mapping. If service
// is already present, its entry — INCLUDING any nested block-map children of a
// previously-structured entry — is replaced; else the new entry is appended at
// the end of the mapping. Returns ok=false when no top-level `origins:` key
// exists in text.
func replaceOrInsertOriginYAML(text, service, backend, scope string) (string, bool) {
	lines := strings.Split(text, "\n")
	// Find the top-level `origins:` header (indent 0, key exactly "origins").
	headerIdx := -1
	for i, ln := range lines {
		if leadingSpaces(ln) != 0 {
			continue
		}
		trim := strings.TrimSpace(ln)
		if trim == "origins:" || strings.HasPrefix(trim, "origins:") && strings.TrimSpace(strings.TrimPrefix(trim, "origins:")) == "" {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return "", false
	}
	// Determine the block indent from the first non-blank child line, else default to 2.
	blockIndent := 0
	blockEnd := headerIdx + 1
	for j := headerIdx + 1; j < len(lines); j++ {
		trim := strings.TrimSpace(lines[j])
		if trim == "" || strings.HasPrefix(trim, "#") {
			blockEnd = j + 1
			continue
		}
		ind := leadingSpaces(lines[j])
		if ind == 0 {
			break // next top-level key
		}
		if blockIndent == 0 {
			blockIndent = ind
		}
		if ind < blockIndent {
			break
		}
		// A child line at the block indent.
		key := strings.TrimSpace(lines[j])
		if idx := strings.Index(key, ":"); idx >= 0 {
			key = strings.TrimSpace(key[:idx])
		}
		if key == service {
			// Replace this entry at its own indent — and swallow any DEEPER-indented
			// child lines (a previously structured entry's addr:/scope: block), so a
			// scope change never strands stale children under the new entry.
			end := j + 1
			for end < len(lines) {
				trimEnd := strings.TrimSpace(lines[end])
				if trimEnd == "" || strings.HasPrefix(trimEnd, "#") {
					break // preserve blank/comment lines after the entry
				}
				if leadingSpaces(lines[end]) <= ind {
					break
				}
				end++
			}
			out := append([]string{}, lines[:j]...)
			out = append(out, originEntryLines(service, backend, scope, ind)...)
			out = append(out, lines[end:]...)
			return strings.Join(out, "\n"), true
		}
		blockEnd = j + 1
	}
	if blockIndent == 0 {
		blockIndent = 2
	}
	insertAt := blockEnd
	inserted := append([]string{}, lines[:insertAt]...)
	inserted = append(inserted, originEntryLines(service, backend, scope, blockIndent)...)
	inserted = append(inserted, lines[insertAt:]...)
	return strings.Join(inserted, "\n"), true
}

// hasTopLevelKey reports whether text (a YAML-subset document) contains a
// top-level (indent 0) mapping entry named key.
func hasTopLevelKey(text, key string) bool {
	for _, ln := range strings.Split(text, "\n") {
		if leadingSpaces(ln) != 0 {
			continue
		}
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if idx := strings.Index(trim, ":"); idx >= 0 {
			if strings.TrimSpace(trim[:idx]) == key {
				return true
			}
		}
	}
	return false
}

// leadingSpaces counts the run of ASCII spaces at the start of s. A tab returns
// -1 (the yaml-subset decoder rejects tabs; we treat one as "not a normal line").
func leadingSpaces(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			continue
		case '\t':
			return -1
		default:
			return i
		}
	}
	return len(s)
}
