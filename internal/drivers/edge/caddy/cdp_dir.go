package caddy

// cdp_dir.go is the caddy-docker-proxy DIRECTORY signature + the Caddyfile admin-
// address reader (audit-any-edge M-A5/M-A6). CDP's readable on-disk signal is its
// generated `Caddyfile.autosave` inside Caddy's config dir (see cdpAutosaveName in
// caddy.go — the admin API itself carries NO cdp marker); a directory carrying that
// file is a POSITIVE target signature for the cmd sniffer (risk A.5: signatures,
// never best fits). The admin-address reader feeds the opt-in `--probe` upgrade:
// what URL WOULD the running process answer on, per the Caddyfile's own global
// options — declared by the config, never guessed beyond Caddy's documented default.

import (
	"os"
	"path/filepath"
	"strings"
)

// SniffCDPDir reports whether dir carries the caddy-docker-proxy directory
// signature: a regular `Caddyfile.autosave` file directly inside it. Purely a
// stat — never reads content, never errors (an unreadable dir simply does not
// match; the sniffer's loud refusal happens upstream).
func SniffCDPDir(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, cdpAutosaveName))
	return err == nil && fi.Mode().IsRegular()
}

// CDPAutosavePath returns the path of the cdp-generated Caddyfile inside dir.
// The FILENAME is the generator signal detectGeneratorFile keys on, so a
// FileReader over this path auto-detects Generator=caddy-docker-proxy.
func CDPAutosavePath(dir string) string { return filepath.Join(dir, cdpAutosaveName) }

// defaultAdminAddress is Caddy's documented default admin endpoint, used when the
// Caddyfile's global options declare no `admin` directive.
const defaultAdminAddress = "http://localhost:2019"

// AdminAddressFromCaddyfile resolves the admin-API URL a running Caddy loaded
// from this Caddyfile WOULD answer on (the M-A6 `--probe` target): the global
// options block's `admin` directive when present, else Caddy's documented default
// (localhost:2019). Returns url="" with a human reason when the config makes the
// admin API unprobeable over HTTP (`admin off`, a unix socket). Never guesses
// beyond what the file (or Caddy's documented default) declares.
func AdminAddressFromCaddyfile(content []byte) (url, reason string) {
	addr := ""
	if body, ok := caddyfileGlobalBody(string(content)); ok {
		for _, line := range strings.Split(body, "\n") {
			f := strings.Fields(stripComment(line))
			if len(f) >= 2 && f[0] == "admin" {
				addr = f[1]
				break
			}
			if len(f) == 1 && f[0] == "admin" {
				// `admin { … }` block form: sub-options only tune the endpoint; the
				// address defaults. Treat as default.
				addr = ""
				break
			}
		}
	}
	switch {
	case addr == "":
		return defaultAdminAddress, ""
	case addr == "off":
		return "", "the Caddyfile disables the admin API (admin off) — nothing to probe"
	case strings.HasPrefix(addr, "unix/"), strings.HasPrefix(addr, "unix//"):
		return "", "the Caddyfile binds the admin API to a unix socket — not probeable over HTTP"
	case strings.HasPrefix(addr, "http://"), strings.HasPrefix(addr, "https://"):
		return addr, ""
	case strings.HasPrefix(addr, ":"):
		return "http://localhost" + addr, ""
	default:
		return "http://" + addr, ""
	}
}

// caddyfileGlobalBody returns the body of the Caddyfile's global options block —
// the first top-level block whose header is a bare `{` — when one exists. Same
// brace-aware walk as topLevelCaddyfileBlocks (which deliberately SKIPS this
// block: it configures the process, never routes), reused here because the admin
// address is exactly process config.
func caddyfileGlobalBody(text string) (string, bool) {
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
				return "", false
			}
			if strings.TrimSpace(strings.TrimSuffix(trimmed, "{")) == "" {
				return text[bodyStart:bodyEnd], true
			}
			i = bodyEnd + 1
			continue
		}
		i = next
	}
	return "", false
}
