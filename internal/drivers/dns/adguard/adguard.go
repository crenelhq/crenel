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
	if d.cfg.Instance != "" {
		return "adguard[" + d.cfg.Instance + "]"
	}
	return "adguard"
}
func (d *Driver) Scope() model.Scope { return d.cfg.Scope }

// rewrite is the AdGuard control-API rewrite shape (GET list / POST add / POST delete).
type rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// DesiredRecords returns the single internal record the op concerns: the op's host
// rewritten to the internal edge address.
func (d *Driver) DesiredRecords(op model.Op) ([]model.Record, error) {
	if op.Host == "" {
		return nil, fmt.Errorf("adguard: op has no host")
	}
	return []model.Record{{
		Name:  op.Host,
		Type:  recordType(d.cfg.EdgeAddr),
		Value: d.cfg.EdgeAddr,
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
