// Package pihole is a DNSProvider adapter for Pi-hole (v6 API) — the INTERNAL
// split-horizon resolver, sibling of the adguard driver. Pi-hole is NOT an
// authoritative DNS server: its "Local DNS" feature (dns.hosts — dnsmasq "IP host"
// lines) overrides answers for specific names on the LAN side. So it gets its own
// adapter that speaks the Pi-hole v6 REST API over an injectable Doer seam (mocked
// in tests — no socket is opened in the suite).
//
// The API contract this driver (and piholefake) encodes was captured live against
// the official pihole/pihole Docker image (core v6.4.3 / FTL v6.7) — see
// testdata/capture-transcript.txt. Endpoints:
//
//	GET    /api/config/dns/hosts                     -> {"config":{"dns":{"hosts":["IP host",...]}}}
//	PUT    /api/config/dns/hosts/<esc "IP host">     -> 201 (400 duplicate/invalid)
//	DELETE /api/config/dns/hosts/<esc "IP host">     -> 204 (404 absent — tolerated no-op)
//
// Auth is SESSION-based (POST /api/auth {password} -> sid header), handled entirely
// in OSDoer so the driver stays auth-agnostic like adguard's.
//
// Safety: Pi-hole has no notion of zones and will HAPPILY accept a host entry for
// any domain — the same hijack trap as an AdGuard rewrite. This driver REFUSES to
// touch a name outside its configured zone.
//
// Two Pi-hole-specific divergences from the adguard pattern, both forced by the API:
//   - dns.hosts values MUST be IP addresses (400 otherwise, captured) — so EdgeAddr
//     must be an IP; a CNAME-style EdgeAddr is refused at DesiredRecords rather than
//     bounced off the API mid-apply.
//   - Wildcard hostnames are REJECTED by the endpoint itself (400 "invalid hostname",
//     captured); wildcard answers live in custom dnsmasq confs (address=/.../) OUTSIDE
//     the API. The driver refuses wildcards loudly and says where they actually live.
package pihole

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// Config configures the Pi-hole driver.
type Config struct {
	Zone     string      // the zone this provider is confined to, e.g. "homelab.example"
	Scope    model.Scope // always internal in practice; defaults to internal
	EdgeAddr string      // the IP host entries point at (the INTERNAL edge); MUST be an IP
	Doer     Doer        // injected API channel; defaults to a real OSDoer

	// Targets maps a host's RESIDENCY class (model.Op.Residency — operator-declared,
	// e.g. "vps" for an edge-resident host) to the address THIS instance answers for
	// hosts of that class — the per-HOST half of the reference architecture's
	// `target(class, vantage)` rule (docs/REFERENCE-ARCH-split-horizon.md §2), same
	// semantics as adguard.Config.Targets. EdgeAddr remains the home-resident DEFAULT
	// (class ""), so a config without targets behaves byte-identically to before. A
	// class with no entry is REFUSED loudly (ResidencyTarget); every target MUST be an
	// IP (dns.hosts entries are dnsmasq "IP host" lines — the API 400s otherwise),
	// checked at DesiredRecords like EdgeAddr is, never mid-apply.
	Targets map[string]string

	// Instance is an OPTIONAL stable label distinguishing THIS Pi-hole instance from
	// another provider managed in the same scope+zone (e.g. adguard[home] + pihole[vps]
	// in a mixed dual-resolver split-horizon). It is woven into Name() so every
	// plan/apply/verify/audit label and guard/conflict error names WHICH resolver a
	// finding belongs to. Empty is fine for the single-instance case.
	//
	// Ownership note: a dns.hosts entry is a bare "IP host" string — the v6 API has NO
	// per-entry comment/metadata field, so crenel CANNOT stamp a record-level ownership
	// marker the way the Cloudflare surgical driver does. Ownership here is therefore
	// PER-INSTANCE zone-confinement + value-match (same posture as adguard), which is
	// also why this driver deliberately does NOT implement ports.OwnedRecordReporter:
	// LiveRecords cannot prove an in-zone entry is crenel's rather than the operator's,
	// and a value-drift check would cry wolf on every legitimately-foreign entry.
	Instance string

	// ZoneInName, when set, appends "/<zone>" to Name() — set by wiring ONLY when
	// this instance came from a multi-entry `zones:` list, so the otherwise
	// identical per-zone siblings (same type, same instance label) stay
	// distinguishable in every plan/apply/verify/audit label. Single-zone
	// instances keep their exact pre-zones-list name (byte-identical output).
	ZoneInName bool
}

// Driver implements ports.DNSProvider against the Pi-hole v6 API.
type Driver struct {
	cfg  Config
	doer Doer
}

// New builds a Pi-hole driver. Scope defaults to internal — Pi-hole can never be
// public-authoritative, so a public scope is a configuration error surfaced at wiring.
func New(cfg Config) *Driver {
	if cfg.Scope == "" {
		cfg.Scope = model.ScopeInternal
	}
	d := &Driver{cfg: cfg, doer: cfg.Doer}
	if d.doer == nil {
		d.doer = &OSDoer{}
	}
	return d
}

// Name identifies the driver, qualified by Instance when set — "pihole[vps]" vs a
// bare "pihole" — mirroring adguard's per-instance labeling so mixed multi-resolver
// setups stay legible in every report and error.
func (d *Driver) Name() string {
	name := "pihole"
	if d.cfg.Instance != "" {
		name = "pihole[" + d.cfg.Instance + "]"
	}
	// A `zones:`-list sibling carries its zone in the label — otherwise a
	// two-zone expansion would print two indistinguishable "pihole[vps]" lines.
	if d.cfg.ZoneInName {
		name += "/" + d.cfg.Zone
	}
	return name
}
func (d *Driver) Scope() model.Scope { return d.cfg.Scope }

// ManagedZone implements ports.ZoneReporter: the zone this provider instance is
// confined to. core uses it to route each host to only the providers whose zone
// covers it (multi-zone topologies) and to group audit coverage-parity by zone.
func (d *Driver) ManagedZone() string { return d.cfg.Zone }

// hostsPath is the v6 config endpoint carrying the "Local DNS" entries.
const hostsPath = "/api/config/dns/hosts"

// hostsResponse is the captured GET shape: {"config":{"dns":{"hosts":[...]}}}.
type hostsResponse struct {
	Config struct {
		DNS struct {
			Hosts []string `json:"hosts"`
		} `json:"dns"`
	} `json:"config"`
}

// DesiredRecords returns the single internal record the op concerns: the op's host
// pointed at the internal edge IP. A non-IP EdgeAddr is refused HERE (not mid-apply):
// dns.hosts entries are dnsmasq host lines and the captured API 400s on any non-IP
// value ("neither a valid IPv4 nor IPv6 address") — CNAME-style targets live at a
// different endpoint this driver deliberately does not manage.
func (d *Driver) DesiredRecords(op model.Op) ([]model.Record, error) {
	if op.Host == "" {
		return nil, fmt.Errorf("pihole: op has no host")
	}
	target, err := d.ResidencyTarget(op.Residency)
	if err != nil {
		return nil, err
	}
	rtype, err := d.recordTypeFor(target)
	if err != nil {
		return nil, err
	}
	return []model.Record{{
		Name:  op.Host,
		Type:  rtype,
		Value: target,
		Scope: d.cfg.Scope,
	}}, nil
}

// ResidencyTarget implements ports.ResidencyTargeter: it resolves an operator-
// declared residency class to THIS instance's vantage-correct answer. "" (the
// home-resident default) is the configured EdgeAddr — unchanged, back-compat. A
// non-default class must have an explicit entry in Targets; a missing one is a LOUD,
// instance-naming refusal (surfaced by core at plan time, before any write) — a
// vantage target is never guessed. Mirrors adguard's contract exactly.
func (d *Driver) ResidencyTarget(class string) (string, error) {
	if class == "" {
		return d.cfg.EdgeAddr, nil
	}
	if addr, ok := d.cfg.Targets[class]; ok && addr != "" {
		return addr, nil
	}
	return "", fmt.Errorf("%s: no target configured for residency class %q — add targets: {%s: <IP>} to this provider (a vantage target is never guessed)",
		d.Name(), class, class)
}

// LiveRecords reads the current dns.hosts entries and returns only those whose name
// is under this provider's zone (so status/audit show exactly what crenel could
// manage, never the operator's unrelated entries). Entries that do not parse as
// "IP host" are skipped — they are dnsmasq lines crenel does not model.
func (d *Driver) LiveRecords(ctx context.Context) ([]model.Record, error) {
	status, body, err := d.doer.Do(ctx, "GET", hostsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("pihole hosts list: %w", err)
	}
	if err := httpErr("hosts list", status, body); err != nil {
		return nil, err
	}
	var hr hostsResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &hr); err != nil {
			return nil, fmt.Errorf("pihole hosts list: decode: %w", err)
		}
	}
	var recs []model.Record
	for _, line := range hr.Config.DNS.Hosts {
		ip, host, ok := parseHostLine(line)
		if !ok {
			continue // not an "IP host" pair we model; leave it alone.
		}
		if !underZone(host, d.cfg.Zone) {
			continue // not ours to manage; ignore for a clean, scoped view.
		}
		rtype := "A"
		if ip.To4() == nil {
			rtype = "AAAA"
		}
		recs = append(recs, model.Record{
			Name:  host,
			Type:  rtype,
			Value: ip.String(),
			Scope: d.cfg.Scope,
		})
	}
	return recs, nil
}

// Diff computes the change to realize op against the live entries. It enforces the
// zone guardrail on every desired record and detects a same-name/different-IP
// CONFLICT (an ambiguous split-horizon — Pi-hole would happily hold BOTH entries,
// captured live) rather than silently stacking a second answer.
func (d *Driver) Diff(ctx context.Context, op model.Op, desired []model.Record) (model.DNSChange, error) {
	for _, r := range desired {
		if err := d.guard(r.Name); err != nil {
			return model.DNSChange{}, err
		}
	}
	live, err := d.LiveRecords(ctx)
	if err != nil {
		return model.DNSChange{}, err
	}
	liveByName := map[string]model.Record{}
	for _, r := range live {
		liveByName[normName(r.Name)] = r
	}

	change := model.DNSChange{Scope: d.cfg.Scope}
	switch op.Verb {
	case model.Expose:
		for _, r := range desired {
			cur, ok := liveByName[normName(r.Name)]
			switch {
			case !ok:
				change.Add = append(change.Add, r)
			case strings.EqualFold(cur.Value, r.Value):
				// already present, exactly right — idempotent no-op.
			default:
				return model.DNSChange{}, fmt.Errorf(
					"%s: conflicting host entry for %s — live answer %q != desired %q; "+
						"refusing to stack a second ambiguous entry on this instance (remove the existing one first)",
					d.Name(), r.Name, cur.Value, r.Value)
			}
		}
	case model.Unexpose:
		for _, r := range desired {
			cur, ok := liveByName[normName(r.Name)]
			if ok && strings.EqualFold(cur.Value, r.Value) {
				change.Remove = append(change.Remove, r)
			}
			// A name absent, or pointing elsewhere, is not ours to remove — no-op.
		}
	default:
		return change, fmt.Errorf("pihole diff: unknown verb %q", op.Verb)
	}

	change.Rendered = renderPreview(change)
	return change, nil
}

// Apply realizes a DNSChange by adding/removing host entries. Removes go first so a
// replace never leaves both answers live. Each record is re-checked against the zone
// guardrail (defense in depth). The API is entry-addressed (PUT/DELETE on the escaped
// "IP host" string) — no read-modify-write of the whole list, so two crenel instances
// can never clobber each other's unrelated entries.
func (d *Driver) Apply(ctx context.Context, change model.DNSChange) error {
	for _, r := range change.Remove {
		if err := d.guard(r.Name); err != nil {
			return err
		}
		status, body, err := d.doer.Do(ctx, "DELETE", entryPath(r), nil)
		if err != nil {
			return fmt.Errorf("pihole hosts delete: %w", err)
		}
		// 404 = already absent — the outcome we wanted; tolerate it so a rollback
		// of a half-applied change (or a racing manual delete) stays idempotent.
		if status == 404 {
			continue
		}
		if err := httpErr("hosts delete", status, body); err != nil {
			return err
		}
	}
	for _, r := range change.Add {
		if err := d.guard(r.Name); err != nil {
			return err
		}
		status, body, err := d.doer.Do(ctx, "PUT", entryPath(r), nil)
		if err != nil {
			return fmt.Errorf("pihole hosts add: %w", err)
		}
		if err := httpErr("hosts add", status, body); err != nil {
			return err
		}
	}
	return nil
}

// entryPath renders the entry-addressed API path: PUT/DELETE take the whole
// url-escaped "IP host" string as the final path element (captured contract).
func entryPath(r model.Record) string {
	return hostsPath + "/" + url.PathEscape(r.Value+" "+r.Name)
}

// guard enforces the safety rule that protects against the "any domain" trap: the
// name must be the zone or a subdomain of it, and never a wildcard. Wildcards are
// doubly impossible here: crenel only writes exact host records, AND the captured
// v6 API itself 400s a wildcard in dns.hosts ("invalid hostname") — Pi-hole keeps
// wildcard answers in custom dnsmasq conf files (address=/.../) outside this API.
func (d *Driver) guard(name string) error {
	if strings.Contains(name, "*") {
		return fmt.Errorf("%s: refusing wildcard host %q — Pi-hole's dns.hosts API rejects wildcards; wildcard answers live in custom dnsmasq confs (address=/…/) outside the API, and crenel only writes exact host records (see docs/DNS-DESIGN.md §5)", d.Name(), name)
	}
	if !underZone(name, d.cfg.Zone) {
		return fmt.Errorf("%s: refusing to write host entry for %q — outside the managed zone %q (would hijack an unrelated domain)", d.Name(), name, d.cfg.Zone)
	}
	return nil
}

// recordType validates EdgeAddr is an IP and returns A/AAAA. A non-IP EdgeAddr is a
// configuration error: dns.hosts cannot carry it (captured 400) and the CNAME
// endpoint is out of this driver's scope.
func (d *Driver) recordType() (string, error) { return d.recordTypeFor(d.cfg.EdgeAddr) }

// recordTypeFor classifies a resolved target address (the default EdgeAddr or a
// residency target) as A/AAAA, refusing any non-IP value here rather than mid-apply
// (dns.hosts entries are dnsmasq "IP host" lines — the captured API 400s otherwise).
func (d *Driver) recordTypeFor(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("%s: target %q is not an IP address — Pi-hole dns.hosts entries are \"IP host\" lines and the API rejects non-IP values; use an A/AAAA-style internal edge address", d.Name(), addr)
	}
	if ip.To4() != nil {
		return "A", nil
	}
	return "AAAA", nil
}

// --- helpers ---

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// underZone reports whether name is the zone itself or a subdomain of it.
func underZone(name, zone string) bool {
	n, z := normName(name), normName(zone)
	if z == "" {
		return false
	}
	return n == z || strings.HasSuffix(n, "."+z)
}

// parseHostLine splits a dnsmasq "IP host" line. Extra whitespace tolerated; a line
// with more than one hostname (dnsmasq allows aliases) is modeled as its FIRST host
// only — crenel never writes such lines, and partial modeling would misattribute.
func parseHostLine(line string) (net.IP, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, "", false
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return nil, "", false
	}
	return ip, fields[1], true
}

func renderPreview(change model.DNSChange) string {
	var b strings.Builder
	for _, r := range change.Add {
		fmt.Fprintf(&b, "+ ADD host entry %s -> %s\n", r.Name, r.Value)
	}
	for _, r := range change.Remove {
		fmt.Fprintf(&b, "- DELETE host entry %s -> %s\n", r.Name, r.Value)
	}
	if b.Len() == 0 {
		return "No changes.\n"
	}
	return b.String()
}

// apiError is the captured v6 error envelope: {"error":{"key","message","hint"}}.
type apiError struct {
	Error struct {
		Key     string `json:"key"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
	} `json:"error"`
}

// httpErr maps a non-2xx API status to a descriptive error (nil on 2xx). The v6 API
// returns 401 {"error":{"key":"unauthorized"}} for a missing/expired sid, 400
// {"error":{"key":"bad_request", message, hint}} for duplicate/invalid entries, and
// a fronting proxy may return 429. The JSON envelope's message+hint are surfaced so
// the operator sees Pi-hole's own diagnosis, not just a bare status.
func httpErr(op string, status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	msg := strings.TrimSpace(string(body))
	var ae apiError
	if json.Unmarshal(body, &ae) == nil && ae.Error.Message != "" {
		msg = ae.Error.Message
		if ae.Error.Hint != "" {
			msg += " (" + ae.Error.Hint + ")"
		}
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	switch {
	case status == 401 || status == 403:
		return fmt.Errorf("pihole %s: authentication failed (HTTP %d): %s", op, status, msg)
	case status == 429:
		return fmt.Errorf("pihole %s: rate limited (HTTP %d): %s", op, status, msg)
	default:
		return fmt.Errorf("pihole %s: HTTP %d: %s", op, status, msg)
	}
}
