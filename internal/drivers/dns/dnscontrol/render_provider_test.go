package dnscontrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// stubShell records calls and captures the files the driver wrote into the working
// dir DURING the call (the dir is cleaned up after), so a test can inspect creds.json
// without relying on it persisting.
type stubShell struct {
	out     string
	err     error
	lastDir string
	calls   [][]string

	credsSeen   string
	credsPerm   os.FileMode
	configExist bool
}

func (s *stubShell) Run(_ context.Context, dir string, args ...string) (string, error) {
	s.lastDir = dir
	s.calls = append(s.calls, args)
	if b, err := os.ReadFile(filepath.Join(dir, "creds.json")); err == nil {
		s.credsSeen = string(b)
		if info, e := os.Stat(filepath.Join(dir, "creds.json")); e == nil {
			s.credsPerm = info.Mode().Perm()
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "dnsconfig.js")); err == nil {
		s.configExist = true
	}
	return s.out, s.err
}

// The render used to HARDCODE NewDnsProvider("mock") / NewRegistrar("none"). The mock
// path must stay byte-identical so every existing mock test is unaffected.
func TestRenderMockByteIdentical(t *testing.T) {
	js := renderConfigJS("example.com", model.ScopeInternal, Provider{}, []model.Record{
		{Name: "grafana.example.com", Type: "A", Value: "10.0.0.1", Scope: model.ScopeInternal},
	})
	if !strings.Contains(js, `var REG = NewRegistrar("none");`) {
		t.Errorf("mock render must keep NewRegistrar(\"none\"): %q", js)
	}
	if !strings.Contains(js, `var DSP = NewDnsProvider("mock");`) {
		t.Errorf("mock render must keep NewDnsProvider(\"mock\"): %q", js)
	}
}

// RED->GREEN: a configured Cloudflare provider must make the render emit the REAL
// provider, not the hardcoded mock.
func TestRenderEmitsCloudflareProvider(t *testing.T) {
	p := Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI"}
	js := renderConfigJS("example.com", model.ScopePublic, p, []model.Record{
		{Name: "vault.example.com", Type: "A", Value: "203.0.113.5", Scope: model.ScopePublic},
	})
	if !strings.Contains(js, `var DSP = NewDnsProvider("cloudflare");`) {
		t.Errorf("expected NewDnsProvider(\"cloudflare\"), got: %q", js)
	}
	if strings.Contains(js, `NewDnsProvider("mock")`) {
		t.Errorf("real provider render must NOT contain the mock provider: %q", js)
	}
	// The SECRET is never rendered into dnsconfig.js — only the provider key is.
	if strings.Contains(js, "apitoken") || strings.Contains(js, "CLOUDFLAREAPI") {
		t.Errorf("dnsconfig.js must not carry credentials/TYPE: %q", js)
	}
}

// fqdn treats a name as already-FQDN only when it equals the zone or ends with
// ".<zone>" — a name merely ENDING in the bare zone string must still be expanded.
func TestFqdnRequiresDotSeparator(t *testing.T) {
	cases := []struct{ name, zone, want string }{
		{"www", "example.com", "www.example.com"},
		{"@", "example.com", "example.com"},
		{"example.com", "example.com", "example.com"},
		{"www.example.com", "example.com", "www.example.com"},
		{"notexample.com", "example.com", "notexample.com.example.com"}, // the bug case
	}
	for _, c := range cases {
		if got := fqdn(c.name, c.zone); got != c.want {
			t.Errorf("fqdn(%q,%q)=%q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

// unrenderableRefusal (the fidelity half of guardPush) must refuse both multi-FIELD
// types (MX/SRV/CAA/SOA) AND multi-VALUE sets (round-robin A, multi-TXT, non-apex
// multi-NS) that the value-blind round-trip would collapse — while allowing a single-
// value zone and the provider-managed apex NS/SOA set.
func TestUnrenderableRefusal(t *testing.T) {
	const apex = "example.com"
	rec := func(name, typ, val string) model.Record {
		return model.Record{Name: name, Type: typ, Value: val, Scope: model.ScopeInternal}
	}

	// Allowed: single-value zone + apex NS set + apex SOA.
	allowed := []model.Record{
		rec("grafana.example.com", "A", "10.0.0.1"),
		rec("vault.example.com", "CNAME", "edge.example.net"),
		rec("example.com", "NS", "ns1.example.com"),
		rec("example.com", "NS", "ns2.example.com"), // apex NS set: provider-managed
		rec("example.com", "SOA", "ns1.example.com. host. 1 7200 3600 1209600 300"),
	}
	if err := unrenderableRefusal(apex, allowed); err != nil {
		t.Errorf("a single-value zone + apex NS/SOA must be allowed, got: %v", err)
	}

	refusals := map[string][]model.Record{
		"multi-field MX":          {rec("example.com", "MX", "10 aspmx.l.google.com")},
		"multi-field SRV":         {rec("_sip._tcp.example.com", "SRV", "10 5 5060 sip.example.com")},
		"round-robin A":           {rec("www.example.com", "A", "1.1.1.1"), rec("www.example.com", "A", "2.2.2.2")},
		"multi TXT (spf+verify)":  {rec("example.com", "TXT", "v=spf1 -all"), rec("example.com", "TXT", "google-site-verification=x")},
		"non-apex multi-NS deleg": {rec("sub.example.com", "NS", "a.ns.net"), rec("sub.example.com", "NS", "b.ns.net")},
	}
	for name, live := range refusals {
		if err := unrenderableRefusal(apex, live); err == nil || !strings.Contains(err.Error(), "refusing to push") {
			t.Errorf("%s must be refused, got: %v", name, err)
		}
	}
}

func TestCredsJSONMockIsStub(t *testing.T) {
	if got := string(credsJSON(Provider{})); got != "{}" {
		t.Errorf("mock creds.json should be the stub {}, got %q", got)
	}
}

func TestCredsJSONCloudflareCarriesToken(t *testing.T) {
	p := Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": "tok-secret-123"}}
	var doc map[string]map[string]string
	if err := json.Unmarshal(credsJSON(p), &doc); err != nil {
		t.Fatal(err)
	}
	entry := doc["cloudflare"]
	if entry["TYPE"] != "CLOUDFLAREAPI" || entry["apitoken"] != "tok-secret-123" {
		t.Errorf("creds.json shape wrong: %+v", doc)
	}
}

// A real provider must get a creds.json on EVERY call (reads included), at 0600, with
// the correct get-zones argument contract — so dnscontrol can authenticate the read.
func TestRealProviderWritesCredsOnReadPath(t *testing.T) {
	sh := &stubShell{out: ""} // get-zones returns no records
	d := New(Config{
		ZoneName: "example.com",
		Scope:    model.ScopePublic,
		EdgeAddr: "203.0.113.5",
		Shell:    sh,
		Provider: Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": "tok"}},
	})

	if _, err := d.LiveRecords(context.Background()); err != nil {
		t.Fatal(err)
	}

	// creds.json present (carrying the token) on the READ path, at 0600.
	if !strings.Contains(sh.credsSeen, "tok") || !strings.Contains(sh.credsSeen, "CLOUDFLAREAPI") {
		t.Fatalf("creds.json must carry the token+TYPE on a real-provider read: %q", sh.credsSeen)
	}
	if sh.credsPerm != 0o600 {
		t.Errorf("creds.json must be 0600 (a secret file), got %o", sh.credsPerm)
	}
	// No dnsconfig.js on the read path (records were nil).
	if sh.configExist {
		t.Errorf("read path must not write dnsconfig.js")
	}
	// get-zones must pass the creds key + TYPE + zone (the real dnscontrol contract).
	want := []string{"get-zones", "--format=tsv", "cloudflare", "CLOUDFLAREAPI", "example.com"}
	if len(sh.calls) == 0 || !reflect.DeepEqual(sh.calls[0], want) {
		t.Errorf("get-zones args = %v, want %v", sh.calls, want)
	}
}

// A real provider's secret-bearing creds.json must NEVER persist in a caller-supplied
// WorkDir (it is forced into a private temp dir that is cleaned up).
func TestRealProviderIgnoresWorkDirForSecret(t *testing.T) {
	work := t.TempDir()
	sh := &stubShell{out: ""}
	d := New(Config{
		ZoneName: "example.com", Scope: model.ScopePublic, EdgeAddr: "203.0.113.5",
		WorkDir: work, Shell: sh,
		Provider: Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI", Creds: map[string]string{"apitoken": "tok"}},
	})
	if _, err := d.LiveRecords(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "creds.json")); !os.IsNotExist(err) {
		t.Errorf("a real provider's creds.json must NOT be written into the caller WorkDir")
	}
	if sh.lastDir == work {
		t.Errorf("a real provider must use a private temp dir, not the caller WorkDir")
	}
}
