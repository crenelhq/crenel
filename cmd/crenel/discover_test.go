package main

// discover_test.go covers XDG default-config discovery (first-touch UX): the
// resolution order flag/env > $XDG_CONFIG_HOME > ~/.config > bare defaults, the
// discovered path behaving identically to -config, loud failure on an invalid
// discovered file, and the discovery hint on connection-class errors.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// isolateConfigEnv points HOME and XDG_CONFIG_HOME at empty temp dirs so a test
// never discovers the developer's real ~/.config/crenel config. Returns the two
// dirs for tests that want to plant files in them.
func isolateConfigEnv(t *testing.T) (xdg, home string) {
	t.Helper()
	xdg = t.TempDir()
	home = t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)
	t.Setenv("CRENEL_CONFIG", "")
	t.Setenv("CRENEL_ADMIN_URL", "")
	return xdg, home
}

// writeConfigAt plants a minimal valid settings file and returns its path.
func writeConfigAt(t *testing.T, dir, name, adminURL string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	body := `{"admin_url": "` + adminURL + `", "zone": "discovered.example"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDiscoverSettingsPath_ResolutionOrder proves the probe order: an explicit
// -config path always wins (discovery never runs), $XDG_CONFIG_HOME/crenel beats
// ~/.config/crenel, and with neither present nothing is discovered (bare
// defaults). CRENEL_CONFIG shares the flag path (it is the flag's default), so
// flag>env ordering is the flag package's own guarantee.
func TestDiscoverSettingsPath_ResolutionOrder(t *testing.T) {
	xdg, home := isolateConfigEnv(t)

	// Nothing anywhere: bare defaults, no discovered path.
	gf := &globalFlags{}
	s, err := loadSettings(gf)
	if err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != "" {
		t.Errorf("nothing to discover, but settingsPath = %q", gf.settingsPath)
	}
	if s.AdminURL != "http://127.0.0.1:2019" {
		t.Errorf("bare defaults admin_url = %q", s.AdminURL)
	}

	// Home file only: discovered.
	homePath := writeConfigAt(t, filepath.Join(home, ".config", "crenel"), "config.json", "http://home:2019")
	gf = &globalFlags{}
	s, err = loadSettings(gf)
	if err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != homePath || s.AdminURL != "http://home:2019" {
		t.Errorf("home discovery: path=%q admin=%q", gf.settingsPath, s.AdminURL)
	}

	// XDG file appears: it wins over the home file.
	xdgPath := writeConfigAt(t, filepath.Join(xdg, "crenel"), "config.json", "http://xdg:2019")
	gf = &globalFlags{}
	s, err = loadSettings(gf)
	if err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != xdgPath || s.AdminURL != "http://xdg:2019" {
		t.Errorf("xdg discovery: path=%q admin=%q", gf.settingsPath, s.AdminURL)
	}

	// Explicit -config wins over both.
	flagPath := writeConfigAt(t, t.TempDir(), "explicit.json", "http://flag:2019")
	gf = &globalFlags{settingsPath: flagPath}
	s, err = loadSettings(gf)
	if err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != flagPath || s.AdminURL != "http://flag:2019" {
		t.Errorf("explicit -config: path=%q admin=%q", gf.settingsPath, s.AdminURL)
	}
}

// TestDiscoverSettingsPath_YAMLNames proves the yaml/yml base names are probed
// (config.Load accepts both formats) and json wins within one directory.
func TestDiscoverSettingsPath_YAMLNames(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	dir := filepath.Join(xdg, "crenel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	yml := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yml, []byte("admin_url: http://yaml:2019\nzone: y.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gf := &globalFlags{}
	s, err := loadSettings(gf)
	if err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != yml || s.AdminURL != "http://yaml:2019" {
		t.Errorf("yaml discovery: path=%q admin=%q", gf.settingsPath, s.AdminURL)
	}
	// config.json in the same dir takes precedence.
	jsonPath := writeConfigAt(t, dir, "config.json", "http://json:2019")
	gf = &globalFlags{}
	if _, err := loadSettings(gf); err != nil {
		t.Fatal(err)
	}
	if gf.settingsPath != jsonPath {
		t.Errorf("config.json should beat config.yaml, got %q", gf.settingsPath)
	}
}

// TestDiscoverSettingsPath_SkippedForInlineWiring proves -admin-url / -fake-seed
// invocations keep their inline wiring: a machine-local XDG config must not be
// picked up by surprise (demos, CI, the bundled fixtures).
func TestDiscoverSettingsPath_SkippedForInlineWiring(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	writeConfigAt(t, filepath.Join(xdg, "crenel"), "config.json", "http://xdg:2019")
	for _, gf := range []*globalFlags{
		{adminURL: "http://inline:2019"},
		{fakeSeed: "seed.json"},
	} {
		if _, err := loadSettings(gf); err != nil {
			t.Fatal(err)
		}
		if gf.settingsPath != "" {
			t.Errorf("inline wiring %+v must skip discovery, got %q", gf, gf.settingsPath)
		}
	}
}

// TestRun_DiscoveredConfigIsUsed drives the REAL run() entry point with no
// -config / CRENEL_CONFIG: a config planted at $XDG_CONFIG_HOME/crenel/config.json
// (pointing fake_seed at a fixture) must be loaded and behave exactly like
// -config — status runs against the seeded fake and exits 0.
func TestRun_DiscoveredConfigIsUsed(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	seed := filepath.Join(t.TempDir(), "seed.caddyfile")
	if err := os.WriteFile(seed, []byte(":443 {\n\trespond 403\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(xdg, "crenel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	seedJSON, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"fake_seed": ` + string(seedJSON) + `, "zone": "example.com", "origins": {}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"status", "-plain"}); code != 0 {
		t.Errorf("status with discovered config: exit %d, want 0", code)
	}
}

// TestRun_InvalidDiscoveredConfigErrorsLoudly proves a discovered-but-broken
// config is a LOUD error (exit 1), never a silent fall-through to bare defaults.
func TestRun_InvalidDiscoveredConfigErrorsLoudly(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	dir := filepath.Join(xdg, "crenel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"status", "-plain"}); code != 1 {
		t.Errorf("invalid discovered config: exit %d, want 1", code)
	}
}

// TestDiscoveryHint proves the connection-failure hint appears ONLY on the bare-
// defaults path: never when a config was loaded (flag, env, or discovered — all
// set settingsPath), never with inline wiring, and never on a non-connection error.
func TestDiscoveryHint(t *testing.T) {
	connMsg := `Get "http://127.0.0.1:2019/config/": dial tcp 127.0.0.1:2019: connect: connection refused`
	cases := []struct {
		name string
		gf   *globalFlags
		msg  string
		want bool
	}{
		{"bare defaults + connection refused", &globalFlags{}, connMsg, true},
		{"bare defaults + timeout", &globalFlags{}, "probe: i/o timeout", true},
		{"config loaded", &globalFlags{settingsPath: "/x/config.json"}, connMsg, false},
		{"inline admin-url", &globalFlags{adminURL: "http://x:2019"}, connMsg, false},
		{"fake seed", &globalFlags{fakeSeed: "s.json"}, connMsg, false},
		{"non-connection error", &globalFlags{}, "route grafana.example.com not owned", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discoveryHint(tc.gf, tc.msg)
			if (got != "") != tc.want {
				t.Errorf("discoveryHint(%+v, %q) = %q, want present=%v", tc.gf, tc.msg, got, tc.want)
			}
			if tc.want && got != noConfigDiscoveryHint {
				t.Errorf("hint text = %q", got)
			}
		})
	}
}

// writeBogusCredsConfig plants a discovered config at $XDG_CONFIG_HOME/crenel/
// config.json whose DNS provider names an UNSET creds env — the exact prod shape
// that made build() fail with "missing API token". Any verb that loads settings
// dies on it; config-free verbs must never see it.
func writeBogusCredsConfig(t *testing.T, xdg string) {
	t.Helper()
	dir := filepath.Join(xdg, "crenel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"admin_url": "http://127.0.0.1:1", "zone": "example.com", "origins": {},
		"dns": {"providers": [{"type": "cloudflare", "scope": "public", "zone": "example.com",
		"edge_addr": "203.0.113.5", "api_token_env": "CRENEL_TEST_TOKEN_DEFINITELY_UNSET"}]}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CRENEL_TEST_TOKEN_DEFINITELY_UNSET", "")
	os.Unsetenv("CRENEL_TEST_TOKEN_DEFINITELY_UNSET")
}

// TestRun_ConfigFreeVerbsIgnoreDiscoveredConfig is the live-found 2026-07-10
// regression guard: `crenel version` (and help, and init) on a box whose
// discovered ~/.config/crenel/config.json has bogus creds must succeed — they
// short-circuit before loadSettings/discovery, never attempting provider wiring.
// A settings-loading verb (`status`) against the same config must still fail,
// proving the fixture really is poisonous.
func TestRun_ConfigFreeVerbsIgnoreDiscoveredConfig(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	writeBogusCredsConfig(t, xdg)

	if code := run([]string{"version"}); code != 0 {
		t.Errorf("version with bogus discovered config: exit %d, want 0", code)
	}
	// (`crenel --version` is NOT covered: the global flag parser rejects it before
	// the verb switch — pre-existing behavior, unchanged by discovery.)
	if code := run([]string{"help"}); code != 0 {
		t.Errorf("help with bogus discovered config: exit %d, want 0", code)
	}
	initDir := t.TempDir()
	if code := run([]string{"init", initDir}); code != 0 {
		t.Errorf("init with bogus discovered config: exit %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(initDir, "crenel.settings.yaml")); err != nil {
		t.Errorf("init did not scaffold: %v", err)
	}
	// Control: a settings-loading verb DOES die on this config (the fixture is real).
	if code := run([]string{"status", "-plain"}); code != 1 {
		t.Errorf("status with bogus discovered config: exit %d, want 1", code)
	}
}

// TestRun_AuditTargetIgnoresDiscoveredConfig pins the M-A2 design under
// discovery: zero-config `audit <target>` synthesizes its own one-edge settings
// and must be untouched by a discovered config with bogus creds.
func TestRun_AuditTargetIgnoresDiscoveredConfig(t *testing.T) {
	xdg, _ := isolateConfigEnv(t)
	writeBogusCredsConfig(t, xdg)
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	fake.SeedCaddyfile("grafana.example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n:443 {\n\trespond 403\n}\n")
	if code := run([]string{"audit", fake.URL(), "--assume-public-boundary"}); code != 0 {
		t.Errorf("audit <target> with bogus discovered config: exit %d, want 0", code)
	}
}

// TestUsage_DocumentsAuditTargetKinds pins the v0.5.0 help text: all five
// zero-config audit target kinds and the forced boundary declaration must appear
// (the audit line described only Caddy targets until the 2026-07-10 dogfood).
func TestUsage_DocumentsAuditTargetKinds(t *testing.T) {
	out := &strings.Builder{}
	writeUsage(out)
	s := out.String()
	for _, want := range []string{
		"Caddy admin URL",
		"Caddyfile path",
		"Nginx Proxy",
		"proxy_host/*.conf",
		"caddy-docker-proxy",
		"Caddyfile.autosave",
		"Traefik API URL",
		"--assume-public-boundary",
		"--internal",
		"--probe",
		"XDG_CONFIG_HOME/crenel/config",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("usage text should document %q", want)
		}
	}
}
