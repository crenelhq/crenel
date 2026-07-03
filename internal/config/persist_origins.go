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
// Format is chosen by extension (.json vs .yaml/.yml). JSON goes through a
// standard encoding/json round-trip. YAML uses a surgical text-insert that
// preserves the operator's comments and layout — the yaml-subset decoder in
// this package is decode-only, and a full re-emit would strip formatting.
func SetTopLevelOrigin(path, service, backend string) error {
	if path == "" {
		return fmt.Errorf("no settings file to persist into (pass -config <path>)")
	}
	if service == "" || backend == "" {
		return fmt.Errorf("service and backend are required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read settings %q: %w", path, err)
	}
	if isYAML(path, b) {
		return writeOriginYAML(path, b, service, backend)
	}
	return writeOriginJSON(path, b, service, backend)
}

// writeOriginJSON updates the top-level `origins` object via a full JSON round-trip.
func writeOriginJSON(path string, src []byte, service, backend string) error {
	var raw map[string]json.RawMessage
	if len(strings.TrimSpace(string(src))) == 0 {
		raw = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(src, &raw); err != nil {
		return fmt.Errorf("parse settings JSON %q: %w", path, err)
	}
	if _, ok := raw["edges"]; ok {
		return fmt.Errorf("multi-edge config (%q has `edges`): --to cannot pick a target edge — add `%s: %s` to the edge's origins map manually", path, service, backend)
	}
	origins := map[string]string{}
	if r, ok := raw["origins"]; ok && len(r) > 0 {
		if err := json.Unmarshal(r, &origins); err != nil {
			return fmt.Errorf("parse origins in %q: %w", path, err)
		}
	}
	origins[service] = backend
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

// writeOriginYAML surgically inserts (or replaces) `<service>: "<backend>"` under
// the top-level `origins:` block, preserving everything else byte-for-byte.
// Refuses multi-edge (top-level `edges:`) — the operator must edit the per-edge
// origins manually there.
func writeOriginYAML(path string, src []byte, service, backend string) error {
	text := string(src)
	if hasTopLevelKey(text, "edges") {
		return fmt.Errorf("multi-edge config (%q has `edges`): --to cannot pick a target edge — add `%s: %s` to the edge's origins map manually", path, service, backend)
	}
	line := fmt.Sprintf("%s: %q", service, backend)

	updated, ok := replaceOrInsertOriginYAML(text, service, line)
	if !ok {
		// No top-level `origins:` key found — append a fresh block at end of file.
		var sb strings.Builder
		sb.WriteString(text)
		if len(text) > 0 && !strings.HasSuffix(text, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("origins:\n  ")
		sb.WriteString(line)
		sb.WriteString("\n")
		updated = sb.String()
	}
	return os.WriteFile(path, []byte(updated), 0o600)
}

// replaceOrInsertOriginYAML edits the top-level `origins:` mapping. If service
// is already present, its value line is replaced; else the new entry is
// appended at the end of the mapping. Returns ok=false when no top-level
// `origins:` key exists in text.
func replaceOrInsertOriginYAML(text, service, newLine string) (string, bool) {
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
			// Replace this line, preserving its indent.
			pad := strings.Repeat(" ", ind)
			lines[j] = pad + newLine
			return strings.Join(lines, "\n"), true
		}
		blockEnd = j + 1
	}
	if blockIndent == 0 {
		blockIndent = 2
	}
	pad := strings.Repeat(" ", blockIndent)
	insertAt := blockEnd
	inserted := append([]string{}, lines[:insertAt]...)
	inserted = append(inserted, pad+newLine)
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
