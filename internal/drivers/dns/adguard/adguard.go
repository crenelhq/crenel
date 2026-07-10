// Package adguard is a DNSProvider adapter for AdGuard Home — the INTERNAL split-
// horizon resolver. AdGuard is NOT an authoritative DNS server and NOT a dnscontrol
// provider: it is a recursive resolver whose "rewrites" feature overrides answers for
// specific names on the LAN/Tailscale side. So it gets its own adapter that speaks the
// AdGuard control API over an injectable Doer seam (mocked in tests — no socket is
// opened in the suite).
//
// The split-horizon model: a homelab host (e.g. auth.homelab.example) resolves to the
// public VPS edge for the world (Cloudflare) but to the LOCAL home Caddy for on-network
// clients (this driver's rewrite). See docs/DNS-DESIGN.md.
//
// Safety: AdGuard has no notion of zones and will HAPPILY accept a rewrite for any
// domain — including www.smallbiz.example, hijacking the public marketing site (the
// exact trap the homelab runbook warns about). Crenel is the guardrail AdGuard lacks:
// this driver REFUSES to touch a domain outside its configured zone, or a wildcard.
package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// Config configures the AdGuard driver.
type Config struct {
	Zone     string      // the zone this provider is confined to, e.g. "homelab.example"
	Scope    model.Scope // always internal in practice; defaults to internal
	EdgeAddr string      // the address rewrites point at (the INTERNAL edge, e.g. home Caddy)
	Doer     Doer        // injected control-API channel; defaults to a real OSDoer

	// Targets maps a host's RESIDENCY class (model.Op.Residency — operator-declared,
	// e.g. "vps" for an edge-resident host) to the address THIS instance answers for
	// hosts of that class: the per-HOST half of the reference architecture's
	// `target(class, vantage)` rule (docs/REFERENCE-ARCH-split-horizon.md §2). The
	// instance IS the vantage (home instance = non-tunnel clients, vps instance =
	// tunnel clients), so each instance carries its own map — e.g. the home resolver
	// maps "vps" to the PUBLIC edge IP (LAN clients must route via the internet edge)
	// while the vps resolver maps "vps" to the tunnel-direct address. EdgeAddr remains
	// the home-resident DEFAULT (class ""), so a config without targets behaves
	// byte-identically to before. A class with no entry here is REFUSED loudly
	// (ResidencyTarget) — a vantage target is never guessed.
	Targets map[string]string

	// Instance is an OPTIONAL stable label distinguishing THIS AdGuard instance from
	// another managed in the same scope+zone — e.g. "home" and "vps" for a dual-resolver
	// split-horizon where one resolver answers tunnel clients and the other answers
	// non-tunnel clients (each with its own vantage-correct EdgeAddr; see
	// docs/REFERENCE-ARCH-split-horizon.md). It is woven into Name() so two same-scope
	// AdGuard providers are DISTINGUISHABLE in every plan/apply/verify/audit label and in
	// the conflict/guard errors below — without it both render as a bare "adguard" and an
	// operator cannot tell WHICH resolver a finding belongs to. Empty is fine for the
	// single-instance case (the label stays the bare "adguard").
	//
	// Ownership note: AdGuard rewrites are {domain, answer} only — the control API has NO
	// per-record comment/metadata field, so crenel CANNOT stamp a record-level ownership
	// marker the way the Cloudflare surgical driver does. Ownership here is therefore
	// PER-INSTANCE zone-confinement + value-match (this driver's existing guarantee),
	// evaluated independently against THIS instance's endpoint; Instance only makes that
	// per-instance attribution legible. It is not a marker stored on the instance.
	Instance string

	// ZoneInName, when set, appends "/<zone>" to Name() — set by wiring ONLY when
	// this instance came from a multi-entry `zones:` list, so the otherwise
	// identical per-zone siblings (same type, same instance label) stay
	// distinguishable in every plan/apply/verify/audit label. Single-zone
	// instances keep their exact pre-zones-list name (byte-identical output).
	ZoneInName bool
}

// Driver implements ports.DNSProvider against the AdGuard Home control API.
type Driver struct {
	cfg  Config
	doer Doer
}

// New builds an AdGuard driver. Scope defaults to internal — AdGuard can never be
// public-authoritative, so a public scope is a configuration error surfaced at use.
func New(cfg Config) *Driver {
	if cfg.Scope == "" {
		cfg.Scope = model.ScopeInternal
	}
	d := &Driver{cfg: cfg, doer: cfg.Doer}
	if d.doer == nil {
		d.doer = OSDoer{}
	}
	return d
}

// Name identifies the driver, qualified by Instance when set so two same-scope AdGuard
// providers (a dual-resolver split-horizon) are distinguishable everywhere a provider
// label is built — "adguard[home]" vs "adguard[vps]" rather than a colliding "adguard".
func (d *Driver) Name() string {
	name := "adguard"
	if d.cfg.Instance != "" {
		name = "adguard[" + d.cfg.Instance + "]"
	}
	// A `zones:`-list sibling carries its zone in the label — otherwise a
	// two-zone expansion would print two indistinguishable "adguard[home]" lines.
	if d.cfg.ZoneInName {
		name += "/" + d.cfg.Zone
	}
	return name
}
func (d *Driver) Scope() model.Scope { return d.cfg.Scope }

// ManagedZone implements ports.ZoneReporter: the zone this instance is confined to.
// core uses it to route each host to only the providers whose zone covers it (the
// multi-zone edge case) — the read-side twin of the guard() write confinement below.
func (d *Driver) ManagedZone() string { return d.cfg.Zone }

// rewrite is the AdGuard control-API rewrite shape (GET list / POST add / POST delete).
type rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// ResidencyTarget implements ports.ResidencyTargeter: it resolves an operator-
// declared residency class to THIS instance's vantage-correct answer. "" (the
// home-resident default) is the configured EdgeAddr — unchanged, back-compat. A
// non-default class must have an explicit entry in Targets; a missing one is a LOUD,
// instance-naming refusal (surfaced by core at plan time, before any write) because
// answering the default EdgeAddr for an edge-resident host would misdirect this
// whole vantage — the exact silent-wrong-target failure crenel exists to prevent.
func (d *Driver) ResidencyTarget(class string) (string, error) {
	if class == "" {
		return d.cfg.EdgeAddr, nil
	}
	if addr, ok := d.cfg.Targets[class]; ok && addr != "" {
		return addr, nil
	}
	return "", fmt.Errorf("%s: no target configured for residency class %q — add targets: {%s: <address>} to this provider (a vantage target is never guessed)",
		d.Name(), class, class)
}

// DesiredRecords returns the single internal record the op concerns: the op's host
// rewritten to this instance's residency-resolved target — EdgeAddr for the
// home-resident default, the instance's Targets[class] for a declared class.
func (d *Driver) DesiredRecords(op model.Op) ([]model.Record, error) {
	if op.Host == "" {
		return nil, fmt.Errorf("adguard: op has no host")
	}
	target, err := d.ResidencyTarget(op.Residency)
	if err != nil {
		return nil, err
	}
	return []model.Record{{
		Name:  op.Host,
		Type:  recordType(target),
		Value: target,
		Scope: d.cfg.Scope,
	}}, nil
}

// LiveRecords reads the current rewrites via GET /control/rewrite/list and returns
// only those whose domain is under this provider's zone (so status/audit show exactly
// what crenel could manage, never the operator's unrelated rewrites).
func (d *Driver) LiveRecords(ctx context.Context) ([]model.Record, error) {
	status, body, err := d.doer.Do(ctx, "GET", "/control/rewrite/list", nil)
	if err != nil {
		return nil, fmt.Errorf("adguard rewrite/list: %w", err)
	}
	if err := httpErr("rewrite/list", status, body); err != nil {
		return nil, err
	}
	var rws []rewrite
	if len(body) > 0 {
		if err := json.Unmarshal(body, &rws); err != nil {
			return nil, fmt.Errorf("adguard rewrite/list: decode: %w", err)
		}
	}
	var recs []model.Record
	for _, rw := range rws {
		if !underZone(rw.Domain, d.cfg.Zone) {
			continue // not ours to manage; ignore for a clean, scoped view.
		}
		recs = append(recs, model.Record{
			Name:  rw.Domain,
			Type:  recordType(rw.Answer),
			Value: rw.Answer,
			Scope: d.cfg.Scope,
		})
	}
	return recs, nil
}

// Diff computes the change to realize op against the live rewrites. It enforces the
// zone guardrail on every desired record and detects a same-domain/different-answer
// CONFLICT (an ambiguous split-horizon) rather than silently overwriting it.
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
					"%s: conflicting rewrite for %s — live answer %q != desired %q; "+
						"refusing to overwrite an ambiguous split-horizon entry on this instance (remove the existing rewrite first)",
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
		return change, fmt.Errorf("adguard diff: unknown verb %q", op.Verb)
	}

	change.Rendered = renderPreview(change)
	return change, nil
}

// Apply realizes a DNSChange by adding/removing rewrites. Removes go first so a
// replace (remove+add of the same domain) never leaves a duplicate. Each desired
// record is re-checked against the zone guardrail (defense in depth).
func (d *Driver) Apply(ctx context.Context, change model.DNSChange) error {
	for _, r := range change.Remove {
		if err := d.guard(r.Name); err != nil {
			return err
		}
		if err := d.post(ctx, "/control/rewrite/delete", r); err != nil {
			return err
		}
	}
	for _, r := range change.Add {
		if err := d.guard(r.Name); err != nil {
			return err
		}
		if err := d.post(ctx, "/control/rewrite/add", r); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) post(ctx context.Context, path string, r model.Record) error {
	body, err := json.Marshal(rewrite{Domain: r.Name, Answer: r.Value})
	if err != nil {
		return fmt.Errorf("adguard %s: encode: %w", path, err)
	}
	status, resp, err := d.doer.Do(ctx, "POST", path, body)
	if err != nil {
		return fmt.Errorf("adguard %s: %w", path, err)
	}
	return httpErr(path, status, resp)
}

// guard enforces the safety rule that protects against the AdGuard "any domain"
// trap: the name must be the zone or a subdomain of it, and never a wildcard.
func (d *Driver) guard(name string) error {
	if strings.Contains(name, "*") {
		return fmt.Errorf("%s: refusing wildcard rewrite %q — crenel only writes exact host rewrites (see docs/DNS-DESIGN.md §5)", d.Name(), name)
	}
	if !underZone(name, d.cfg.Zone) {
		return fmt.Errorf("%s: refusing to write rewrite for %q — outside the managed zone %q (would hijack an unrelated domain)", d.Name(), name, d.cfg.Zone)
	}
	return nil
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

// recordType infers the record type from an answer: an IP => A/AAAA, else CNAME.
func recordType(answer string) string {
	if ip := net.ParseIP(answer); ip != nil {
		if ip.To4() != nil {
			return "A"
		}
		return "AAAA"
	}
	return "CNAME"
}

func renderPreview(change model.DNSChange) string {
	var b strings.Builder
	for _, r := range change.Add {
		fmt.Fprintf(&b, "+ ADD rewrite %s -> %s\n", r.Name, r.Value)
	}
	for _, r := range change.Remove {
		fmt.Fprintf(&b, "- DELETE rewrite %s -> %s\n", r.Name, r.Value)
	}
	if b.Len() == 0 {
		return "No changes.\n"
	}
	return b.String()
}

// httpErr maps a non-2xx control-API status to a descriptive error (nil on 2xx). The
// AdGuard control API returns 401/403 for auth, 400 for a bad/duplicate request, and a
// fronting proxy may return 429.
func httpErr(op string, status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	switch {
	case status == 401 || status == 403:
		return fmt.Errorf("adguard %s: authentication failed (HTTP %d): %s", op, status, msg)
	case status == 429:
		return fmt.Errorf("adguard %s: rate limited (HTTP %d): %s", op, status, msg)
	default:
		return fmt.Errorf("adguard %s: HTTP %d: %s", op, status, msg)
	}
}
