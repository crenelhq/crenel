package traefik

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// benchYAML mirrors the SHAPE of a real Traefik file-provider dynamic config (anchored
// on the CT 110 bench operator.yml): block mappings, quoted Host(`...`) rules, flow
// sequences, a block sequence of server mappings, a nested tls block, and an
// http.middlewares section crenel does not model (must be skipped, not error on).
const benchYAML = `# operator-owned dynamic config
http:
  routers:
    blog:
      rule: "Host(` + "`blog.bench.local`" + `)"
      service: blog-svc
      entryPoints: ["web"]
    secure-app:
      rule: "Host(` + "`app.bench.local`" + `)"
      service: app-svc
      entryPoints: ["web"]
      middlewares: ["authelia@file"]
      priority: 23
      tls:
        certResolver: cloudflare
  services:
    blog-svc:
      loadBalancer:
        servers:
          - url: "http://whoami:80"
    app-svc:
      loadBalancer:
        servers:
          - url: "http://whoami:80"
  middlewares:
    authelia:
      forwardAuth:
        address: "http://authelia:9080/api/verify?rd=https://auth.bench.local"
        authResponseHeaders: ["Remote-User","Remote-Groups"]
`

// TestDecode_YAMLWasRedBeforeFix locks the regression: the YAML content is NOT valid
// JSON, so the OLD json-only decode failed with exactly the bench's `invalid character
// 'h'` error. (The 'h' is the `http:` key.) This is the RED the T1 fix turns green.
func TestDecode_YAMLWasRedBeforeFix(t *testing.T) {
	var cfg dynamicConfig
	err := json.Unmarshal([]byte(benchYAML), &cfg)
	if err == nil {
		t.Fatal("precondition: a real YAML dynamic config must not parse as JSON")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("expected the historical JSON-parse failure, got: %v", err)
	}
}

// TestDecode_RealTraefikYAML: the YAML-subset decoder faithfully reads a real dynamic
// config — routers (rule/service/entryPoints/middlewares/priority/tls) and services
// (loadBalancer servers) — and skips the unmodeled http.middlewares section.
func TestDecode_RealTraefikYAML(t *testing.T) {
	cfg, err := decode([]byte(benchYAML))
	if err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	blog := cfg.HTTP.Routers["blog"]
	if blog == nil || blog.Rule != "Host(`blog.bench.local`)" || blog.Service != "blog-svc" {
		t.Fatalf("blog router parsed wrong: %+v", blog)
	}
	if len(blog.EntryPoints) != 1 || blog.EntryPoints[0] != "web" {
		t.Errorf("blog entryPoints wrong: %+v", blog.EntryPoints)
	}
	app := cfg.HTTP.Routers["secure-app"]
	if app == nil || app.Rule != "Host(`app.bench.local`)" || app.Priority != 23 {
		t.Fatalf("secure-app router parsed wrong: %+v", app)
	}
	if len(app.Middlewares) != 1 || app.Middlewares[0] != "authelia@file" {
		t.Errorf("secure-app middlewares wrong: %+v", app.Middlewares)
	}
	if app.TLS == nil || app.TLS.CertResolver != "cloudflare" {
		t.Errorf("secure-app tls wrong: %+v", app.TLS)
	}
	if svc := cfg.HTTP.Services["blog-svc"]; svc == nil || svc.firstUpstream() != "http://whoami:80" {
		t.Errorf("blog-svc loadBalancer server wrong: %+v", svc)
	}
}

// TestDecode_YAMLNormalizesLikeReal: the whole driver reads a YAML edge correctly —
// both hosts surface, the forward-auth middleware is detected, and default-deny holds.
func TestDecode_YAMLNormalizesLikeReal(t *testing.T) {
	d := newDriver(tempConfig(t, benchYAML))
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatalf("ReadLiveState over YAML: %v", err)
	}
	if !live.HasHost("blog.bench.local") || !live.HasHost("app.bench.local") {
		t.Errorf("expected both YAML hosts, got %v", live.Hosts())
	}
	if !live.DenyCatchAllPresent {
		t.Error("Host()-scoped YAML routers => native-404 default-deny should hold")
	}
	for _, r := range live.Routes {
		if r.Host == "app.bench.local" && r.Upstream.Auth == "" {
			t.Error("the authelia@file middleware on app should be detected as auth")
		}
	}
}

// TestDecode_JSONYAMLParity: the same logical config in JSON and in YAML decodes to an
// IDENTICAL dynamicConfig — auto-detection picks the right parser and both share the
// struct mapping.
func TestDecode_JSONYAMLParity(t *testing.T) {
	yamlDoc := `http:
  routers:
    r1:
      rule: "Host(` + "`a.example.com`" + `)"
      service: s1
      entryPoints: ["websecure"]
  services:
    s1:
      loadBalancer:
        servers:
          - url: "http://10.0.0.5:3000"
`
	jsonDoc := `{"http":{"routers":{"r1":{"rule":"Host(` + "`a.example.com`" + `)","service":"s1","entryPoints":["websecure"]}},` +
		`"services":{"s1":{"loadBalancer":{"servers":[{"url":"http://10.0.0.5:3000"}]}}}}}`
	fromYAML, err := decode([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	fromJSON, err := decode([]byte(jsonDoc))
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Errorf("JSON and YAML of the same config must decode equal:\n yaml=%+v\n json=%+v", fromYAML, fromJSON)
	}
}

// TestDecode_TCPPassthroughYAML: a TCP router (HostSNI + tls.passthrough) and its TCP
// service (address, not url) read back from YAML.
func TestDecode_TCPPassthroughYAML(t *testing.T) {
	doc := `tcp:
  routers:
    crenel-tcp-stream:
      rule: "HostSNI(` + "`stream.example.com`" + `)"
      service: crenel-tcp-stream
      tls:
        passthrough: true
  services:
    crenel-tcp-stream:
      loadBalancer:
        servers:
          - address: "10.0.0.6:2342"
`
	cfg, err := decode([]byte(doc))
	if err != nil {
		t.Fatalf("decode TCP YAML: %v", err)
	}
	r := cfg.TCP.Routers["crenel-tcp-stream"]
	if r == nil || r.TLS == nil || !r.TLS.Passthrough || r.Rule != "HostSNI(`stream.example.com`)" {
		t.Fatalf("tcp router parsed wrong: %+v", r)
	}
	if svc := cfg.TCP.Services["crenel-tcp-stream"]; svc == nil || svc.firstAddress() != "10.0.0.6:2342" {
		t.Errorf("tcp service address wrong: %+v", svc)
	}
}

// TestDecode_UnsupportedConstructsErrorLoudly: a YAML construct outside the subset
// (a block scalar) is rejected with a clear error, not silently mis-parsed.
func TestDecode_UnsupportedConstructsErrorLoudly(t *testing.T) {
	doc := "http:\n  routers:\n    note: |\n      multi\n      line\n"
	if _, err := decode([]byte(doc)); err == nil {
		t.Error("a block scalar (|) must be rejected, not silently mis-parsed")
	}
}

// TestDecode_EmptyAndCommentOnlyYAML: an empty / comment-only / null doc reads as an
// empty config (not an error).
func TestDecode_EmptyAndCommentOnlyYAML(t *testing.T) {
	for _, doc := range []string{"", "  ", "# just a comment\n", "null", "~", "---\n"} {
		cfg, err := decode([]byte(doc))
		if err != nil {
			t.Errorf("decode(%q) should be empty, got error: %v", doc, err)
		}
		if len(cfg.HTTP.Routers) != 0 {
			t.Errorf("decode(%q) should have no routers", doc)
		}
	}
}
