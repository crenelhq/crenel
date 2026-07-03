package caddy

import (
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/model"
)

// TestFindSiteBlock_SkipsGlobalAndSnippets proves the brace-aware scanner consumes the
// global `{ … }` and `(snippet) { … }` blocks as units — their bodies (which contain
// `{`-opening directives like forward_auth) are never mistaken for site blocks — and
// that nested braces inside a site body do not confuse the boundary.
func TestFindSiteBlock_SkipsGlobalAndSnippets(t *testing.T) {
	if got := siteAddresses(operatorWildcardCaddyfile); len(got) != 1 || got[0] != "*.homelab.example" {
		t.Fatalf("siteAddresses should see only the wildcard site, got %v", got)
	}
	site, ok := findSiteBlock(operatorWildcardCaddyfile, func(a string) bool { return a == "*.homelab.example" })
	if !ok {
		t.Fatal("wildcard site not found")
	}
	body := operatorWildcardCaddyfile[site.bodyStart:site.bodyEnd]
	if !strings.Contains(body, "@git host") || strings.Contains(body, "email a@b.com") {
		t.Fatalf("site body bounds wrong:\n%s", body)
	}
}

// TestFindSiteBlock_CommentBracesIgnored proves a `{`/`}` inside a `#` comment does not
// shift the block boundary.
func TestFindSiteBlock_CommentBracesIgnored(t *testing.T) {
	in := "*.x.com {\n\t# a brace } in a comment {\n\t@a host a.x.com\n\thandle @a {\n\t\treverse_proxy h:1\n\t}\n}\n"
	site, ok := findSiteBlock(in, func(a string) bool { return a == "*.x.com" })
	if !ok {
		t.Fatal("site not found")
	}
	if !strings.Contains(in[site.bodyStart:site.bodyEnd], "reverse_proxy h:1") {
		t.Fatalf("comment brace truncated the body:\n%s", in[site.bodyStart:site.bodyEnd])
	}
}

// TestCoveringZone proves the single-label wildcard coverage rule and exact-site conflict.
func TestCoveringZone(t *testing.T) {
	addrs := []string{"*.homelab.example", "auth.homelab.example", "*.smallbiz.example"}
	cases := []struct {
		host      string
		wantZone  string
		wantConfl bool
	}{
		{"files.homelab.example", "*.homelab.example", false},
		{"auth.homelab.example", "", true}, // exact operator site => conflict
		{"a.b.homelab.example", "", false}, // two labels — not covered by *.
		{"x.smallbiz.example", "*.smallbiz.example", false},
		{"elsewhere.net", "", false},
	}
	for _, c := range cases {
		z, confl := coveringZone(c.host, addrs)
		if z != c.wantZone || confl != c.wantConfl {
			t.Errorf("coveringZone(%q) = (%q,%v), want (%q,%v)", c.host, z, confl, c.wantZone, c.wantConfl)
		}
	}
}

// TestMergeInSiteRegion_RoundTrip proves render → merge → parse-back reproduces the
// routes, the region lands inside the site, and a re-merge is idempotent.
func TestMergeInSiteRegion_RoundTrip(t *testing.T) {
	routes := []model.Route{
		{Host: "files.homelab.example", Upstream: model.Upstream{Address: "filebrowser:80"}},
		{Host: "home.homelab.example", Upstream: model.Upstream{Address: "homepage:3000", Auth: "authelia"}},
	}
	block := renderInSiteHandles(routes, func(p string) string { return p })
	merged, ok := mergeInSiteRegion(operatorWildcardCaddyfile, func(a string) bool { return a == "*.homelab.example" }, block)
	if !ok {
		t.Fatal("merge failed")
	}
	site, _ := findSiteBlock(merged, func(a string) bool { return a == "*.homelab.example" })
	parsed := parseInSiteRegion(merged[site.bodyStart:site.bodyEnd])
	if err := sameRouteSet(routes, parsed); err != nil {
		t.Fatalf("round-trip mismatch: %v\n%s", err, merged)
	}
	// Operator's @git survives.
	if !strings.Contains(merged, "@git host git.homelab.example") {
		t.Fatalf("operator handle lost:\n%s", merged)
	}
	// Idempotent re-merge: same block => byte-identical, still one region.
	again, _ := mergeInSiteRegion(merged, func(a string) bool { return a == "*.homelab.example" }, block)
	if again != merged {
		t.Fatalf("re-merge not idempotent:\n--- first ---\n%s\n--- again ---\n%s", merged, again)
	}
	if n := strings.Count(again, persistBegin); n != 1 {
		t.Fatalf("want one region, got %d", n)
	}
	// Clearing (empty block) removes the region but keeps the operator handle.
	cleared, _ := mergeInSiteRegion(merged, func(a string) bool { return a == "*.homelab.example" }, "")
	if strings.Contains(cleared, persistBegin) {
		t.Fatalf("region not cleared:\n%s", cleared)
	}
	if !strings.Contains(cleared, "@git host git.homelab.example") {
		t.Fatalf("operator handle lost on clear:\n%s", cleared)
	}
}

// TestParseHandles_UpstreamTLS proves the HTTPS upstream form round-trips (address +
// UpstreamTLS), so a TLS-backed managed route persists faithfully.
func TestParseHandles_UpstreamTLS(t *testing.T) {
	routes := []model.Route{{Host: "cctv.homelab.example", Upstream: model.Upstream{Address: "10.0.0.5:8971", UpstreamTLS: true}}}
	block := renderInSiteHandles(routes, func(p string) string { return p })
	parsed := parseHandles(block)
	if len(parsed) != 1 || parsed[0].Upstream.Address != "10.0.0.5:8971" || !parsed[0].Upstream.UpstreamTLS {
		t.Fatalf("upstream-TLS handle did not round-trip: %+v\n%s", parsed, block)
	}
}
