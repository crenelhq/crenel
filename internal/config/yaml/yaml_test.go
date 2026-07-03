package yaml

import (
	"reflect"
	"testing"
)

func TestParse_NestedMapsSeqsScalars(t *testing.T) {
	src := `# a comment
zone: example.com
granular_apply: true
admin_read_timeout_seconds: 10
edges:
  - name: home
    driver: caddy
    origins:
      grafana: 10.0.0.5:3000   # trailing comment
      photos: 10.0.0.6:2342
  - name: vps
    driver: traefik
dns:
  enabled: true
  scopes: [internal, public]
`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"zone":                       "example.com",
		"granular_apply":             true,
		"admin_read_timeout_seconds": 10,
		"edges": []any{
			map[string]any{
				"name":   "home",
				"driver": "caddy",
				"origins": map[string]any{
					"grafana": "10.0.0.5:3000",
					"photos":  "10.0.0.6:2342",
				},
			},
			map[string]any{"name": "vps", "driver": "traefik"},
		},
		"dns": map[string]any{
			"enabled": true,
			"scopes":  []any{"internal", "public"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree mismatch:\n got=%#v\nwant=%#v", got, want)
	}
}

func TestUnmarshal_IntoStruct(t *testing.T) {
	type exposure struct {
		Host    string   `json:"host"`
		Service string   `json:"service"`
		Mode    string   `json:"mode,omitempty"`
		Edges   []string `json:"edges,omitempty"`
		DNS     []string `json:"dns,omitempty"`
	}
	type doc struct {
		Zone      string     `json:"zone"`
		Exposures []exposure `json:"exposures"`
	}
	src := `zone: example.com
exposures:
  - host: grafana.example.com
    service: grafana
    edges: [home, vps]
    dns: [internal, public]
  - service: vault
`
	var d doc
	if err := Unmarshal([]byte(src), &d); err != nil {
		t.Fatal(err)
	}
	if d.Zone != "example.com" || len(d.Exposures) != 2 {
		t.Fatalf("unexpected doc: %+v", d)
	}
	e0 := d.Exposures[0]
	if e0.Host != "grafana.example.com" || e0.Service != "grafana" ||
		!reflect.DeepEqual(e0.Edges, []string{"home", "vps"}) ||
		!reflect.DeepEqual(e0.DNS, []string{"internal", "public"}) {
		t.Fatalf("exposure[0] wrong: %+v", e0)
	}
	if d.Exposures[1].Service != "vault" || d.Exposures[1].Host != "" {
		t.Fatalf("exposure[1] wrong: %+v", d.Exposures[1])
	}
}

func TestParse_URLValueWithColonsNotMisSplit(t *testing.T) {
	got, err := Parse([]byte("admin_url: http://127.0.0.1:2019\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["admin_url"] != "http://127.0.0.1:2019" {
		t.Fatalf("URL value mis-split: %q", m["admin_url"])
	}
}

func TestParse_QuotedScalars(t *testing.T) {
	got, err := Parse([]byte(`a: "443"` + "\n" + `b: 'two words'` + "\n" + `c: "with: colon"` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["a"] != "443" { // quoted => stays a string, not int
		t.Fatalf("a: want string 443, got %#v", m["a"])
	}
	if m["b"] != "two words" {
		t.Fatalf("b: %#v", m["b"])
	}
	if m["c"] != "with: colon" {
		t.Fatalf("c: %#v", m["c"])
	}
}

func TestParse_SameIndentSequenceUnderKey(t *testing.T) {
	// YAML allows `- ` items at the SAME indent as their parent key.
	got, err := Parse([]byte("edges:\n- home\n- vps\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if !reflect.DeepEqual(m["edges"], []any{"home", "vps"}) {
		t.Fatalf("same-indent seq: %#v", m["edges"])
	}
}

func TestParse_TabIndentRejected(t *testing.T) {
	if _, err := Parse([]byte("a:\n\tb: 1\n")); err == nil {
		t.Fatal("tab indentation should be rejected")
	}
}

func TestParse_Empty(t *testing.T) {
	for _, src := range []string{"", "# only a comment\n", "\n\n"} {
		v, err := Parse([]byte(src))
		if err != nil || v != nil {
			t.Fatalf("empty %q => %#v, %v", src, v, err)
		}
	}
}
