package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSetTopLevelOrigin_JSON_Insert: a fresh service is added to the origins
// map and Load() round-trips it back — the coherence guarantee that lets
// status/audit/drift see the newly-exposed service after --to.
func TestSetTopLevelOrigin_JSON_Insert(t *testing.T) {
	p := writeTemp(t, "settings.json", `{
  "admin_url": "http://127.0.0.1:2019",
  "zone": "example.com",
  "origins": {"grafana": "10.0.0.5:3000"}
}
`)
	if err := config.SetTopLevelOrigin(p, "immich", "10.0.0.99:2283"); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origins["immich"] != "10.0.0.99:2283" {
		t.Errorf("origins[immich] = %q, want 10.0.0.99:2283 (all: %v)", got.Origins["immich"], got.Origins)
	}
	if got.Origins["grafana"] != "10.0.0.5:3000" {
		t.Errorf("pre-existing origins[grafana] lost: %v", got.Origins)
	}
	if got.Zone != "example.com" {
		t.Errorf("zone regressed: %q", got.Zone)
	}
}

// TestSetTopLevelOrigin_JSON_UpsertReplaces: exposing the same service again
// with a new --to updates the value (does not create a duplicate).
func TestSetTopLevelOrigin_JSON_UpsertReplaces(t *testing.T) {
	p := writeTemp(t, "settings.json", `{"origins":{"immich":"old:1"}}`)
	if err := config.SetTopLevelOrigin(p, "immich", "new:2"); err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(p)
	if got.Origins["immich"] != "new:2" {
		t.Errorf("expected replace, got %v", got.Origins)
	}
}

// TestSetTopLevelOrigin_JSON_MissingOriginsIsCreated: a settings file with no
// origins key still gets one.
func TestSetTopLevelOrigin_JSON_MissingOriginsIsCreated(t *testing.T) {
	p := writeTemp(t, "settings.json", `{"admin_url":"http://x"}`)
	if err := config.SetTopLevelOrigin(p, "immich", "immich:2283"); err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(p)
	if got.Origins["immich"] != "immich:2283" {
		t.Errorf("origins not created: %v", got.Origins)
	}
}

// TestSetTopLevelOrigin_YAML_Insert: same coherence guarantee via YAML.
// The yaml-subset decoder in this package is decode-only, so writing goes
// through a surgical text insert. It must preserve unrelated content.
func TestSetTopLevelOrigin_YAML_Insert(t *testing.T) {
	body := `admin_url: http://127.0.0.1:2019
zone: example.com
# operator's origins map — hand-edited
origins:
  grafana: 10.0.0.5:3000
`
	p := writeTemp(t, "settings.yaml", body)
	if err := config.SetTopLevelOrigin(p, "immich", "10.0.0.99:2283"); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origins["immich"] != "10.0.0.99:2283" {
		t.Errorf("origins[immich] = %q, want 10.0.0.99:2283 (all: %v)", got.Origins["immich"], got.Origins)
	}
	if got.Origins["grafana"] != "10.0.0.5:3000" {
		t.Errorf("pre-existing origins[grafana] lost: %v", got.Origins)
	}
	// Comment preservation — the surgical path exists precisely to keep the
	// operator's file byte-faithful outside the inserted line.
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "# operator's origins map — hand-edited") {
		t.Errorf("expected operator's comment to survive; file now:\n%s", raw)
	}
}

// TestSetTopLevelOrigin_YAML_UpsertReplaces: repeat exposure with new --to
// rewrites the existing service line in place.
func TestSetTopLevelOrigin_YAML_UpsertReplaces(t *testing.T) {
	body := "origins:\n  immich: old:1\n"
	p := writeTemp(t, "settings.yaml", body)
	if err := config.SetTopLevelOrigin(p, "immich", "new:2"); err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(p)
	if got.Origins["immich"] != "new:2" {
		t.Errorf("expected replace, got %v", got.Origins)
	}
}

// TestSetTopLevelOrigin_YAML_MissingOriginsIsAppended: a YAML file with no
// origins block gets one appended at the tail.
func TestSetTopLevelOrigin_YAML_MissingOriginsIsAppended(t *testing.T) {
	body := "admin_url: http://x\nzone: example.com\n"
	p := writeTemp(t, "settings.yaml", body)
	if err := config.SetTopLevelOrigin(p, "immich", "immich:2283"); err != nil {
		t.Fatal(err)
	}
	got, _ := config.Load(p)
	if got.Origins["immich"] != "immich:2283" {
		t.Errorf("origins block not appended: %v", got.Origins)
	}
}

// TestSetTopLevelOrigin_RefusesMultiEdge: a multi-edge topology has per-edge
// origins; the persistence path cannot pick unambiguously, so --to is refused
// with a clear message pointing at the file the operator must edit.
func TestSetTopLevelOrigin_RefusesMultiEdge_JSON(t *testing.T) {
	p := writeTemp(t, "settings.json", `{"edges":[{"name":"home","driver":"caddy","origins":{}}]}`)
	err := config.SetTopLevelOrigin(p, "immich", "immich:2283")
	if err == nil {
		t.Fatal("expected multi-edge JSON refusal")
	}
	if !strings.Contains(err.Error(), "multi-edge") {
		t.Errorf("error should name the multi-edge case, got %v", err)
	}
}

func TestSetTopLevelOrigin_RefusesMultiEdge_YAML(t *testing.T) {
	body := "edges:\n  - name: home\n    driver: caddy\n"
	p := writeTemp(t, "settings.yaml", body)
	err := config.SetTopLevelOrigin(p, "immich", "immich:2283")
	if err == nil {
		t.Fatal("expected multi-edge YAML refusal")
	}
	if !strings.Contains(err.Error(), "multi-edge") {
		t.Errorf("error should name the multi-edge case, got %v", err)
	}
}

// TestSetTopLevelOrigin_EmptyPath: refusing an empty path prevents a silent
// data-loss where the operator's --to never lands anywhere.
func TestSetTopLevelOrigin_EmptyPath(t *testing.T) {
	if err := config.SetTopLevelOrigin("", "immich", "x:1"); err == nil {
		t.Fatal("expected empty-path error")
	}
}
