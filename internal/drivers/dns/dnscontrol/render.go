package dnscontrol

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// scopeTag maps a Crenel scope to the dnscontrol split-horizon tag.
func scopeTag(s model.Scope) string {
	if s == model.ScopePublic {
		return "!outside"
	}
	return "!inside"
}

// relName converts an FQDN to a name relative to zone (dnscontrol style), or
// "@" for the apex.
func relName(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if strings.EqualFold(fqdn, zone) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(zone)) {
		return fqdn[:len(fqdn)-len(zone)-1]
	}
	return fqdn // already relative
}

// fqdn expands a relative name back to an FQDN under zone. A name is already an FQDN
// only when it equals the zone or ends with ".<zone>" — the dot matters, so a name
// that merely ends with the zone STRING (e.g. "notexample.com" under "example.com")
// is still expanded. Mirrors relName/adguard.underZone.
func fqdn(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if name == "@" || name == "" {
		return zone
	}
	n, z := strings.ToLower(name), strings.ToLower(zone)
	if n == z || strings.HasSuffix(n, "."+z) {
		return name
	}
	return name + "." + zone
}

// providerKey returns the NewDnsProvider() argument for p, defaulting to the legacy
// "mock" when no real provider is configured.
func providerKey(p Provider) string {
	if p.CredsKey == "" {
		return "mock"
	}
	return p.CredsKey
}

// registrarKey returns the NewRegistrar() argument for p, defaulting to "none".
func registrarKey(p Provider) string {
	if p.Registrar == "" {
		return "none"
	}
	return p.Registrar
}

// providerTypeArg returns the dnscontrol get-zones <provider> argument: the explicit
// TYPE when known, else "-" (read the TYPE from creds.json). The mock provider has no
// TYPE, so it yields "-" — a sentinel the fake shell ignores.
func providerTypeArg(p Provider) string {
	if p.Type == "" {
		return "-"
	}
	return p.Type
}

// isCloudflare reports whether the provider is the Cloudflare API provider, gating the
// Cloudflare-specific CF_PROXY_ON modifier so it is never emitted for the mock provider.
func isCloudflare(p Provider) bool {
	return strings.EqualFold(p.Type, "CLOUDFLAREAPI") || strings.EqualFold(p.CredsKey, "cloudflare")
}

// proxyableType reports whether a record TYPE can carry the Cloudflare proxied flag.
func proxyableType(t string) bool {
	switch strings.ToUpper(t) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
}

// renderConfigJS produces a dnsconfig.js for the given records, scoped with
// !inside / !outside tags. This is the desired-state document handed to
// dnscontrol push transiently — Crenel never persists it as a source of truth.
//
// The DNS provider + registrar come from p: a zero Provider renders the legacy
// NewDnsProvider("mock") + NewRegistrar("none") (byte-identical to before); a real
// provider (e.g. Cloudflare) renders NewDnsProvider("cloudflare") etc. The credential
// is NEVER rendered here — only the provider KEY is, which dnscontrol resolves against
// the sibling creds.json.
//
// FIDELITY: a record's TTL and Cloudflare proxied state are carried through unchanged so
// a whole-zone push does not silently reset them — `TTL(n)` when a non-auto TTL is set,
// and `CF_PROXY_ON` for a proxied Cloudflare A/AAAA/CNAME. The zone's own apex NS/SOA are
// provider-managed and EXCLUDED (declaring them would fight the provider).
func renderConfigJS(zone string, scope model.Scope, p Provider, records []model.Record) string {
	cf := isCloudflare(p)
	recs := make([]model.Record, 0, len(records))
	for _, r := range records {
		if isApexProviderManaged(r, zone) {
			continue // apex NS/SOA are provider-managed; never declare them
		}
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Name < recs[j].Name })

	var b strings.Builder
	fmt.Fprintf(&b, "// crenel-generated dnsconfig.js — scope=%s — do not hand-edit\n", scope)
	fmt.Fprintf(&b, "var REG = NewRegistrar(%q);\n", registrarKey(p))
	fmt.Fprintf(&b, "var DSP = NewDnsProvider(%q);\n\n", providerKey(p))
	fmt.Fprintf(&b, "D(%q, REG, DnsProvider(DSP),\n", strings.TrimSuffix(zone, "."))
	for _, r := range recs {
		fmt.Fprintf(&b, "    %s(%q, %q, {\"scope\":%q}",
			r.Type, relName(r.Name, zone), r.Value, scopeTag(r.Scope))
		// Preserve a pinned (non-auto) TTL; 0/1 mean auto, left to the provider default.
		if r.TTL > 1 {
			fmt.Fprintf(&b, ", TTL(%d)", r.TTL)
		}
		// Preserve the Cloudflare orange-cloud state so a reproduced record is never
		// silently un-proxied. Only ON is emitted (grey/OFF is the provider default).
		if cf && r.Proxied && proxyableType(r.Type) {
			b.WriteString(", CF_PROXY_ON")
		}
		b.WriteString("),\n")
	}
	b.WriteString(");\n")
	return b.String()
}
