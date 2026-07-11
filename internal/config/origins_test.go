package config_test

// origins_test.go pins the polymorphic origins entry (plain string vs
// structured {addr, scope}) across BOTH config formats, the loud-parse-error
// contract, and the scope-aware persistence path.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
)

func decodeSettings(t *testing.T, name, body string) (config.Settings, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var s config.Settings
	err := config.DecodeFile(p, &s)
	return s, err
}

// TestOrigins_PlainAndStructured_JSON: the mixed map — a plain-string entry
// keeps today's semantics exactly (default scope) alongside a structured
// internal-scope entry.
func TestOrigins_PlainAndStructured_JSON(t *testing.T) {
	s, err := decodeSettings(t, "s.json", `{
	  "zone": "example.com",
	  "origins": {
	    "grafana": "10.0.0.7:3000",
	    "ha": {"addr": "10.0.0.19:8123", "scope": "internal"}
	  }
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Origins["grafana"]; got.Addr != "10.0.0.7:3000" || got.Internal() {
		t.Errorf("plain entry must be default-scope, got %+v", got)
	}
	if got := s.Origins["ha"]; got.Addr != "10.0.0.19:8123" || !got.Internal() {
		t.Errorf("structured entry must be internal-scope, got %+v", got)
	}
	if want := []string{"ha"}; len(s.Origins.InternalServices()) != 1 || s.Origins.InternalServices()[0] != want[0] {
		t.Errorf("InternalServices = %v, want %v", s.Origins.InternalServices(), want)
	}
	if a := s.Origins.Addrs(); a["ha"] != "10.0.0.19:8123" || a["grafana"] != "10.0.0.7:3000" {
		t.Errorf("Addrs flattening wrong: %v", a)
	}
}

// TestOrigins_PlainAndStructured_YAML: the identical mixed map through the
// yaml-subset decoder — the structured entry uses the nested BLOCK-map form
// (the subset deliberately does not parse flow maps `{...}`).
func TestOrigins_PlainAndStructured_YAML(t *testing.T) {
	s, err := decodeSettings(t, "s.yaml", strings.Join([]string{
		"zone: example.com",
		"origins:",
		"  grafana: 10.0.0.7:3000",
		"  ha:",
		"    addr: 10.0.0.19:8123",
		"    scope: internal",
		"",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Origins["grafana"]; got.Addr != "10.0.0.7:3000" || got.Internal() {
		t.Errorf("plain YAML entry must be default-scope, got %+v", got)
	}
	if got := s.Origins["ha"]; got.Addr != "10.0.0.19:8123" || !got.Internal() {
		t.Errorf("structured YAML entry must be internal-scope, got %+v", got)
	}
}

// TestOrigins_ScopeAllNormalizes: the explicit "all" spelling is the default.
func TestOrigins_ScopeAllNormalizes(t *testing.T) {
	s, err := decodeSettings(t, "s.json", `{"origins": {"x": {"addr": "a:1", "scope": "all"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Origins["x"]; got.Internal() || got.Scope != config.OriginScopeDefault {
		t.Errorf("scope 'all' must normalize to default, got %+v", got)
	}
}

// TestOrigins_LoudParseErrors: a security-relevant declaration must never be
// silently defaulted — unknown scope values, a missing addr, and unknown keys
// (a typo'd "scop") all refuse the config load.
func TestOrigins_LoudParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown scope": `{"origins": {"x": {"addr": "a:1", "scope": "publicish"}}}`,
		"missing addr":  `{"origins": {"x": {"scope": "internal"}}}`,
		"unknown key":   `{"origins": {"x": {"addr": "a:1", "scop": "internal"}}}`,
		"wrong type":    `{"origins": {"x": 42}}`,
	}
	for name, body := range cases {
		if _, err := decodeSettings(t, "s.json", body); err == nil {
			t.Errorf("%s: expected a loud parse error, got nil", name)
		}
	}
}

// TestOrigins_EdgeSettingsStructured: per-edge origins carry the same
// polymorphic form (the multi-edge split-horizon shape).
func TestOrigins_EdgeSettingsStructured(t *testing.T) {
	s, err := decodeSettings(t, "s.json", `{
	  "edges": [
	    {"name": "home", "driver": "caddy",
	     "origins": {"ha": {"addr": "10.0.0.19:8123", "scope": "internal"}, "grafana": "10.0.0.7:3000"}}
	  ]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Edges[0].Origins["ha"]; !got.Internal() {
		t.Errorf("per-edge structured entry must decode, got %+v", got)
	}
}

// TestSetTopLevelOrigin_ScopeInternal_JSON: the expose --to --scope internal
// persistence path writes the structured entry, and it round-trips through Load.
func TestSetTopLevelOrigin_ScopeInternal_JSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"zone": "example.com", "origins": {"grafana": "10.0.0.7:3000"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.SetTopLevelOrigin(p, "ha", "10.0.0.19:8123", config.OriginScopeInternal); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if o := got.Origins["ha"]; o.Addr != "10.0.0.19:8123" || !o.Internal() {
		t.Errorf("persisted structured entry wrong: %+v", o)
	}
	if o := got.Origins["grafana"]; o.Addr != "10.0.0.7:3000" || o.Internal() {
		t.Errorf("plain sibling must survive untouched: %+v", o)
	}
}

// TestSetTopLevelOrigin_ScopeInternal_YAML: the YAML surgical insert writes the
// flow-map form and the yaml-subset decoder reads it back.
func TestSetTopLevelOrigin_ScopeInternal_YAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte("zone: example.com\norigins:\n  grafana: \"10.0.0.7:3000\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.SetTopLevelOrigin(p, "ha", "10.0.0.19:8123", config.OriginScopeInternal); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if o := got.Origins["ha"]; o.Addr != "10.0.0.19:8123" || !o.Internal() {
		t.Errorf("persisted YAML structured entry wrong: %+v", o)
	}
}

// TestSetTopLevelOrigin_UnknownScopeRefused: the persistence path enforces the
// same scope vocabulary as the decoder.
func TestSetTopLevelOrigin_UnknownScopeRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.SetTopLevelOrigin(p, "ha", "a:1", "publicish"); err == nil {
		t.Fatal("unknown scope must refuse persistence")
	}
}
