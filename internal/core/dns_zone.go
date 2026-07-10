package core

import (
	"strings"

	"github.com/crenelhq/crenel/internal/ports"
)

// dns_zone.go — zone-aware DNS provider routing (the multi-zone edge case).
//
// One edge can serve hosts under SEVERAL apex zones (the production shape that
// motivated this: a single Caddy edge fronting *.homelab.example AND
// *.smallbiz.example, with a separate zone-confined provider entry per zone —
// two AdGuard instances × two zones internal, plus one public Cloudflare for
// only one of the zones). Zone-confined drivers rightly REFUSE an out-of-zone
// write and FILTER out-of-zone records from LiveRecords, so core must route
// each host to only the providers whose zone covers it:
//
//   - plan/apply/verify (engine.go, apply.go): an op's host is planned/verified
//     against a provider only when that provider's zone covers it; a skipped
//     provider contributes an EMPTY, positionally-aligned DNSChange.
//   - reconcile (reconcile.go): a canonical host produces desired records only
//     on covering providers (an out-of-zone "missing record" is not drift — it
//     is a record the provider is FORBIDDEN to hold).
//   - audit (audit.go): coverage parity is grouped by zone (resolvers of
//     different zones must never be compared against each other), and a host
//     outside EVERY managed zone gets the quiet "no provider configured for
//     this zone" declaration instead of the cry-wolf "missing record" warning.
//
// The zone is a DECLARED capability (ports.ZoneReporter). A provider that does
// not declare one covers everything — the pre-multi-zone behavior, preserved
// for stubs and any driver whose confinement core cannot see.

// dnsZone returns a provider's declared managed zone, normalized (lowercase, no
// trailing dot). "" means unconfined — the provider covers every host.
func dnsZone(dp ports.DNSProvider) string {
	zr, ok := dp.(ports.ZoneReporter)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(zr.ManagedZone(), "."))
}

// zoneCovers reports whether a host lies within zone: the zone apex itself or
// any name under it. An empty zone covers everything (unconfined provider).
func zoneCovers(zone, host string) bool {
	if zone == "" {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == zone || strings.HasSuffix(h, "."+zone)
}

// dnsCoversHost reports whether this provider's declared zone covers host —
// i.e. whether crenel should plan/verify/reconcile host's records HERE at all.
func dnsCoversHost(dp ports.DNSProvider, host string) bool {
	return zoneCovers(dnsZone(dp), host)
}

// providerZones returns the deduped, normalized set of zones DECLARED by the
// configured DNS providers (ports.ZoneReporter), in provider order. Unconfined
// providers ("" zone) contribute nothing. Together with the top-level
// Engine.Zone these are crenel's MANAGED zones — the domain host derivation
// (ResolveOp) and serviceOf reason over.
func (e *Engine) providerZones() []string {
	var out []string
	seen := map[string]bool{}
	for _, dp := range e.DNS {
		z := dnsZone(dp)
		if z == "" || seen[z] {
			continue
		}
		seen[z] = true
		out = append(out, z)
	}
	return out
}

// explicitlyFronts reports whether some edge with an EXPLICIT Fronts predicate
// (a real origins map, not the nil fronts-everything default) fronts name. It
// is the EVIDENCE test behind multi-zone name handling: a nil predicate says
// yes to everything and therefore proves nothing about how the operator keyed
// a service, so it never counts here.
func (e *Engine) explicitlyFronts(name string) bool {
	for _, b := range e.Edges {
		if b.Fronts != nil && b.Fronts(name) {
			return true
		}
	}
	return false
}

// anyManagedZoneCovers reports whether ANY configured DNS provider's zone
// covers host. False means the host's domain is outside crenel's DNS remit
// entirely — audit then declares "no provider configured for this zone"
// (quiet, informational) rather than "missing record" (actionable drift).
func (e *Engine) anyManagedZoneCovers(host string) bool {
	for _, dp := range e.DNS {
		if dnsCoversHost(dp, host) {
			return true
		}
	}
	return false
}
