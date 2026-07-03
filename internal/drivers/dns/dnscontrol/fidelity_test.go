package dnscontrol

import (
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// parseTSV must read the REAL dnscontrol get-zones --format=tsv layout
// (NameFQDN, ShortName, TTL, IN, Type, Target [, Properties]) — NOT the old 4-column
// shape. The value is column 5 (not "IN"), TTL is column 2, and Cloudflare's proxied
// state is the trailing `cloudflare_proxy=true` token.
func TestParseTSVRealDnscontrolFormat(t *testing.T) {
	out := strings.Join([]string{
		"grafana.example.com\tgrafana\t300\tIN\tA\t10.0.0.1",                                // pinned TTL, grey
		"*.example.com\t*\t1\tIN\tA\t203.0.113.9\tcloudflare_proxy=true",                    // auto TTL, PROXIED
		"example.com\t@\t1\tIN\tNS\tcarmelo.ns.cloudflare.com",                              // apex NS
		"WARNING: the PROVIDER argument is deprecated; omit it (read TYPE from creds.json)", // stderr noise -> skipped
		"",
	}, "\n")
	recs := parseTSV(out, "example.com", model.ScopePublic)
	if len(recs) != 3 {
		t.Fatalf("expected 3 records (warning line skipped), got %d: %+v", len(recs), recs)
	}
	if recs[0].Name != "grafana.example.com" || recs[0].Value != "10.0.0.1" || recs[0].TTL != 300 || recs[0].Proxied {
		t.Errorf("grafana misparsed (value must be col5, not 'IN'): %+v", recs[0])
	}
	if recs[1].Name != "*.example.com" || recs[1].Value != "203.0.113.9" || recs[1].TTL != 1 || !recs[1].Proxied {
		t.Errorf("wildcard misparsed (must read proxied + auto TTL): %+v", recs[1])
	}
	if recs[2].Type != "NS" {
		t.Errorf("apex NS misparsed: %+v", recs[2])
	}
}

// renderConfigJS must carry a record's TTL + Cloudflare proxied state through unchanged
// so a whole-zone push doesn't reset them.
func TestRenderPreservesTTLAndProxied(t *testing.T) {
	cf := Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI"}
	recs := []model.Record{
		{Name: "orange.example.com", Type: "A", Value: "1.2.3.4", Scope: model.ScopePublic, TTL: 300, Proxied: true},
		{Name: "grey.example.com", Type: "A", Value: "5.6.7.8", Scope: model.ScopePublic, TTL: 0, Proxied: false},
	}
	js := renderConfigJS("example.com", model.ScopePublic, cf, recs)
	if !strings.Contains(js, `A("orange", "1.2.3.4", {"scope":"!outside"}, TTL(300), CF_PROXY_ON)`) {
		t.Errorf("a proxied, pinned-TTL record must render TTL(300)+CF_PROXY_ON:\n%s", js)
	}
	if !strings.Contains(js, `A("grey", "5.6.7.8", {"scope":"!outside"}),`) {
		t.Errorf("a grey, auto-TTL record must render bare (no TTL/proxy):\n%s", js)
	}
	if strings.Count(js, "CF_PROXY_ON") != 1 {
		t.Errorf("exactly one CF_PROXY_ON expected:\n%s", js)
	}
}

// The mock provider must NEVER emit the Cloudflare-specific CF_PROXY modifier, even if a
// record carries Proxied=true; TTL (provider-agnostic) is still preserved.
func TestRenderNoCloudflareModifierForMock(t *testing.T) {
	recs := []model.Record{{Name: "x.example.com", Type: "A", Value: "1.2.3.4", Scope: model.ScopeInternal, TTL: 300, Proxied: true}}
	js := renderConfigJS("example.com", model.ScopeInternal, Provider{}, recs)
	if strings.Contains(js, "CF_PROXY") {
		t.Errorf("mock provider must not emit CF_PROXY:\n%s", js)
	}
	if !strings.Contains(js, "TTL(300)") {
		t.Errorf("TTL must still be preserved for the mock provider:\n%s", js)
	}
}

// A value with an embedded double-quote (a multi-string / DKIM-style TXT) cannot
// round-trip faithfully, so it must be REFUSED rather than silently corrupted.
func TestUnrenderableRefusesQuotedValue(t *testing.T) {
	live := []model.Record{{Name: "dkim.example.com", Type: "TXT", Value: `v=DKIM1; p=AB"CD`, Scope: model.ScopePublic}}
	if err := unrenderableRefusal("example.com", live); err == nil || !strings.Contains(err.Error(), "refusing to push") {
		t.Fatalf("a quote-bearing TXT must be refused, got %v", err)
	}
}

// Proxied is only meaningful for A/AAAA/CNAME — a TXT must never get CF_PROXY_ON.
func TestRenderProxyOnlyForAddressTypes(t *testing.T) {
	cf := Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI"}
	recs := []model.Record{{Name: "x.example.com", Type: "TXT", Value: "v=spf1 -all", Scope: model.ScopePublic, Proxied: true}}
	js := renderConfigJS("example.com", model.ScopePublic, cf, recs)
	if strings.Contains(js, "CF_PROXY") {
		t.Errorf("TXT must not be proxied:\n%s", js)
	}
}

// The zone's own apex NS/SOA are provider-managed — declaring them in the pushed zone
// would fight the provider, so render must EXCLUDE them.
func TestRenderExcludesApexNSSOA(t *testing.T) {
	cf := Provider{CredsKey: "cloudflare", Type: "CLOUDFLAREAPI"}
	recs := []model.Record{
		{Name: "edge.example.com", Type: "A", Value: "1.2.3.4", Scope: model.ScopePublic},
		{Name: "example.com", Type: "NS", Value: "carmelo.ns.cloudflare.com", Scope: model.ScopePublic},
		{Name: "example.com", Type: "SOA", Value: "ns. host. 1 7200 3600 1209600 300", Scope: model.ScopePublic},
		{Name: "sub.example.com", Type: "NS", Value: "a.iana-servers.net", Scope: model.ScopePublic}, // NON-apex NS: a real delegation, kept
	}
	js := renderConfigJS("example.com", model.ScopePublic, cf, recs)
	if strings.Contains(js, "SOA(") {
		t.Errorf("apex SOA must be excluded:\n%s", js)
	}
	if strings.Contains(js, `NS("@"`) {
		t.Errorf("apex NS must be excluded:\n%s", js)
	}
	if !strings.Contains(js, `A("edge"`) {
		t.Errorf("a normal A must still render:\n%s", js)
	}
	if !strings.Contains(js, `NS("sub"`) {
		t.Errorf("a NON-apex delegation NS must be kept:\n%s", js)
	}
}
