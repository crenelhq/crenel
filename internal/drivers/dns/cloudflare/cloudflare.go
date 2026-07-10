// Package cloudflare is a DNSProvider adapter that drives the Cloudflare REST API
// DIRECTLY for SURGICAL, per-record DNS management — the non-destructive sibling of
// the whole-zone `dnscontrol push` path (internal/drivers/dns/dnscontrol).
//
// Why a second Cloudflare path. `dnscontrol push` is WHOLE-ZONE authoritative: it
// renders the entire desired zone and deletes anything not in the render. Crenel's
// narrow Name/Type/Value model can't faithfully re-render a zone it doesn't fully own,
// so that path REQUIRES a dedicated, all-crenel zone (the `dedicated_zone` gate). This
// driver is the opposite posture: it issues per-record CREATE / UPDATE / DELETE against
// the Cloudflare API and NEVER reads-to-overwrite the zone. It can therefore safely
// manage a single host inside a SHARED zone (e.g. the real homelab.example) without ever
// touching a record it did not create.
//
// The safety boundary is an OWNERSHIP MARKER. Every record crenel creates carries a
// Cloudflare `comment` of the form "managed-by:crenel ...". The driver only ever
// UPDATEs or DELETEs a record carrying that marker; the low-level mutate primitives
// REFUSE to act on any record lacking it (defense in depth). On expose, a foreign
// (unmarked) record already sitting at crenel's exact name+type is AMBIGUOUS, so the
// driver default-DENIES rather than overwrite or shadow it.
//
// The HTTP channel is an injectable Doer seam (mocked in tests), so the suite contacts
// no real Cloudflare. See docs/DNS-DESIGN.md "Surgical (record-level) Cloudflare mode".
package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// MarkerPrefix is the ownership boundary. A Cloudflare record is crenel's to manage
// IFF its `comment` begins with this exact prefix. It is the single load-bearing
// safety invariant of surgical mode: crenel never UPDATEs or DELETEs a record whose
// comment lacks it.
const MarkerPrefix = "managed-by:crenel"

// Config configures the surgical Cloudflare driver.
type Config struct {
	// ZoneName is the Cloudflare zone, e.g. "crenel.sh". Records are confined to it.
	ZoneName string
	// ZoneID is the Cloudflare zone id. Optional: resolved from ZoneName via the API
	// (GET /zones?name=) on first use when empty.
	ZoneID string
	// Scope is internal | public; defaults to public (Cloudflare is authoritative).
	Scope model.Scope
	// EdgeAddr is the address records point at (the edge), e.g. the VPS public IP.
	EdgeAddr string
	// Proxied sets the Cloudflare orange-cloud state on records crenel CREATES.
	// Default false (grey-cloud / DNS-only) — the safe, audit-friendly default.
	Proxied bool
	// TTL is the TTL crenel sets on records it CREATES (seconds); 0/1 mean auto.
	TTL int
	// Doer is the injected API channel; defaults to a real OSDoer.
	Doer Doer
	// ZoneInName, when set, appends "/<zone>" to Name() — set by wiring ONLY when
	// this instance came from a multi-entry `zones:` list, so per-zone siblings
	// stay distinguishable in every label. Single-zone instances keep the exact
	// pre-zones-list name (byte-identical output).
	ZoneInName bool
}

// Driver implements ports.DNSProvider against the Cloudflare REST API, surgically.
type Driver struct {
	cfg    Config
	doer   Doer
	zoneID string // resolved lazily; cached
}

// New builds a surgical Cloudflare driver. Scope defaults to public.
func New(cfg Config) *Driver {
	if cfg.Scope == "" {
		cfg.Scope = model.ScopePublic
	}
	d := &Driver{cfg: cfg, doer: cfg.Doer, zoneID: cfg.ZoneID}
	if d.doer == nil {
		d.doer = OSDoer{}
	}
	return d
}

func (d *Driver) Name() string {
	// A `zones:`-list sibling carries its zone in the label — otherwise a
	// two-zone expansion would print two indistinguishable "cloudflare-api" lines.
	if d.cfg.ZoneInName {
		return "cloudflare-api/" + d.cfg.ZoneName
	}
	return "cloudflare-api"
}
func (d *Driver) Scope() model.Scope { return d.cfg.Scope }

// ManagedZone implements ports.ZoneReporter: the zone this provider instance is
// confined to. core uses it to route each host to only the providers whose zone
// covers it (multi-zone topologies) and to group audit coverage-parity by zone.
func (d *Driver) ManagedZone() string { return d.cfg.ZoneName }

// OwnsAllLiveRecords implements ports.OwnedRecordReporter: this driver's LiveRecords is
// marker-filtered (only records carrying MarkerPrefix), so every record it reports is
// crenel's — which lets audit value-check it for target drift without crying wolf on a
// foreign record. See ports.OwnedRecordReporter.
func (d *Driver) OwnsAllLiveRecords() bool { return true }

// cfRecord is the Cloudflare API record shape (subset crenel reads/writes).
type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"` // FQDN
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

// cfEnvelope is the standard Cloudflare API response envelope.
type cfEnvelope struct {
	Success    bool              `json:"success"`
	Errors     []cfAPIError      `json:"errors"`
	Messages   []json.RawMessage `json:"messages"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo *cfResultInfo     `json:"result_info,omitempty"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// owned reports whether a Cloudflare record carries crenel's ownership marker. This is
// THE safety predicate: only an owned record may be updated or deleted.
//
// The match REQUIRES a word boundary after the prefix — the comment must be EXACTLY the
// marker, or the marker immediately followed by a space (which is what markerFor always
// emits: "managed-by:crenel host=..."). A bare HasPrefix would misclassify a FOREIGN
// comment that merely starts with the same bytes — "managed-by:crenel-not-ours",
// "managed-by:crenelvpn" — as crenel's, letting a malicious or coincidental zone
// co-tenant get its record updated/deleted. The boundary closes that.
func owned(r cfRecord) bool {
	c := strings.TrimSpace(r.Comment)
	return c == MarkerPrefix || strings.HasPrefix(c, MarkerPrefix+" ")
}

// markerFor builds the comment crenel stamps onto a record it creates: the ownership
// prefix plus the host, for auditability ("who/what created this?").
func markerFor(name string) string {
	return MarkerPrefix + " host=" + normName(name)
}

// DesiredRecords returns the single public record the op concerns: the op's host as an
// exact A record pointing at the edge. NEVER a wildcard.
func (d *Driver) DesiredRecords(op model.Op) ([]model.Record, error) {
	if op.Host == "" {
		return nil, fmt.Errorf("cloudflare: op has no host")
	}
	return []model.Record{{
		// Fully-qualify under the zone so the desired Key matches LiveRecords' FQDN-
		// normalized Key — otherwise a bare-label host (key "public/A/app") would never
		// match the live record ("public/A/app.crenel.sh") and read-back verify would
		// spuriously roll back crenel's own just-created record.
		Name:  fqdn(op.Host, d.cfg.ZoneName),
		Type:  "A",
		Value: d.cfg.EdgeAddr,
		Scope: d.cfg.Scope,
	}}, nil
}

// LiveRecords reports the records crenel MANAGES in this zone — i.e. only those
// carrying the ownership marker (and under the zone). status/audit/read-back see
// exactly crenel's footprint, never the operator's foreign records. (The full-zone
// read used to detect foreign conflicts lives in Diff/Apply, not here.)
func (d *Driver) LiveRecords(ctx context.Context) ([]model.Record, error) {
	all, err := d.listZone(ctx)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for _, r := range all {
		if owned(r) && underZone(r.Name, d.cfg.ZoneName) {
			recs = append(recs, toModel(r, d.cfg.Scope))
		}
	}
	return recs, nil
}

// Diff computes the surgical change to realize op. It reads the FULL live zone to
// reason about foreign records at crenel's name, but the change it emits only ever
// concerns crenel-owned records.
func (d *Driver) Diff(ctx context.Context, op model.Op, desired []model.Record) (model.DNSChange, error) {
	for _, r := range desired {
		if err := d.guard(r.Name); err != nil {
			return model.DNSChange{}, err
		}
	}
	all, err := d.listZone(ctx)
	if err != nil {
		return model.DNSChange{}, err
	}

	change := model.DNSChange{Scope: d.cfg.Scope, Managed: desired}
	switch op.Verb {
	case model.Expose:
		for _, want := range desired {
			ours, foreign := d.partition(all, want.Name, want.Type)
			switch {
			case len(ours) == 0 && len(foreign) > 0:
				// A record crenel does NOT own already sits at this exact name+type.
				// Creating a second A would shadow/round-robin it; updating it would
				// overwrite a foreign record. Default-deny on the ambiguity.
				return model.DNSChange{}, foreignConflict(want, foreign)
			case len(ours) == 0:
				change.Add = append(change.Add, want) // CREATE
			case len(ours) == 1 && strings.EqualFold(ours[0].Content, want.Value):
				// already present, exactly right, and ours — idempotent no-op.
			case len(ours) == 1:
				change.Add = append(change.Add, want) // UPDATE (re-assert our value)
			default:
				// >1 owned record at one name+type: an ambiguous prior state crenel
				// won't guess at. Refuse rather than pick one to mutate.
				return model.DNSChange{}, fmt.Errorf(
					"cloudflare: refusing expose of %s %s — %d crenel-owned records already exist at that name; resolve manually",
					want.Type, want.Name, len(ours))
			}
		}
	case model.Unexpose:
		for _, want := range desired {
			ours, _ := d.partition(all, want.Name, want.Type)
			// Tear down ONLY crenel's own records at the name. A foreign record at the
			// same name is never removed. Value is not matched: an owned record is ours
			// to remove even if its value drifted out-of-band.
			for _, o := range ours {
				change.Remove = append(change.Remove, toModel(o, d.cfg.Scope))
			}
		}
	default:
		return change, fmt.Errorf("cloudflare diff: unknown verb %q", op.Verb)
	}

	change.Rendered = renderPreview(change)
	return change, nil
}

// Apply realizes the change by per-record API calls. It RE-READS live state (the zone
// may have drifted since Diff) and re-derives every mutation, so the ownership guard is
// enforced against current reality. Removes precede adds (a replace is clean).
func (d *Driver) Apply(ctx context.Context, change model.DNSChange) error {
	all, err := d.listZone(ctx)
	if err != nil {
		return err
	}

	for _, rem := range change.Remove {
		ours, _ := d.partition(all, rem.Name, rem.Type)
		for _, o := range ours {
			if err := d.deleteRecord(ctx, o); err != nil {
				return err
			}
		}
		// A foreign-only or absent name yields no owned matches — nothing to delete.
	}

	for _, add := range change.Add {
		ours, foreign := d.partition(all, add.Name, add.Type)
		switch {
		case len(ours) == 0 && len(foreign) > 0:
			return foreignConflict(add, foreign) // re-check: live may have changed
		case len(ours) == 0:
			if err := d.createRecord(ctx, add); err != nil {
				return err
			}
		case len(ours) == 1:
			if err := d.updateRecord(ctx, ours[0], add); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cloudflare: refusing to update %s %s — %d crenel-owned records exist", add.Type, add.Name, len(ours))
		}
	}
	return nil
}

// --- mutate primitives (the hard safety boundary) ---

// createRecord POSTs a new record stamped with crenel's ownership marker. Always
// crenel's own, so it carries no ownership precondition.
func (d *Driver) createRecord(ctx context.Context, r model.Record) error {
	zid, err := d.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	if err := validateContent(r); err != nil {
		return err
	}
	body, _ := json.Marshal(cfRecord{
		Type:    strings.ToUpper(r.Type),
		Name:    fqdn(r.Name, d.cfg.ZoneName),
		Content: r.Value,
		// Cloudflare REQUIRES TTL=auto (1) on a proxied record (else it rejects with code
		// 9207); a non-proxied record honors the configured TTL.
		TTL:     ttlForProxied(d.cfg.TTL, d.cfg.Proxied),
		Proxied: d.cfg.Proxied,
		Comment: markerFor(r.Name),
	})
	_, _, err = d.api(ctx, "POST", "/zones/"+zid+"/dns_records", body)
	return err
}

// updateRecord PUTs new content onto an EXISTING owned record (preserving the marker).
// It REFUSES if the target record is not crenel-owned — the defense-in-depth boundary.
func (d *Driver) updateRecord(ctx context.Context, target cfRecord, r model.Record) error {
	if !owned(target) {
		return notOwned("update", target)
	}
	zid, err := d.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	if err := validateContent(r); err != nil {
		return err
	}
	comment := target.Comment
	if comment == "" {
		comment = markerFor(r.Name)
	}
	body, _ := json.Marshal(cfRecord{
		Type:    strings.ToUpper(r.Type),
		Name:    fqdn(r.Name, d.cfg.ZoneName),
		Content: r.Value,
		// Preserve the live record's TTL/proxied, but keep CF's proxied⇒TTL=auto invariant.
		TTL:     ttlForProxied(target.TTL, target.Proxied),
		Proxied: target.Proxied,
		Comment: comment,
	})
	_, _, err = d.api(ctx, "PUT", "/zones/"+zid+"/dns_records/"+target.ID, body)
	return err
}

// deleteRecord DELETEs an owned record by id. It REFUSES if the target is not
// crenel-owned — the defense-in-depth boundary that makes it impossible to delete a
// foreign record even if upstream logic had a bug.
func (d *Driver) deleteRecord(ctx context.Context, target cfRecord) error {
	if !owned(target) {
		return notOwned("delete", target)
	}
	zid, err := d.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	_, _, err = d.api(ctx, "DELETE", "/zones/"+zid+"/dns_records/"+target.ID, nil)
	return err
}

// --- zone + listing ---

// resolveZoneID returns the zone id, resolving it from ZoneName once and caching it.
func (d *Driver) resolveZoneID(ctx context.Context) (string, error) {
	if d.zoneID != "" {
		return d.zoneID, nil
	}
	if d.cfg.ZoneName == "" {
		return "", fmt.Errorf("cloudflare: no zone configured")
	}
	_, result, err := d.api(ctx, "GET", "/zones?name="+url.QueryEscape(normName(d.cfg.ZoneName)), nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(result, &zones); err != nil {
		return "", fmt.Errorf("cloudflare: decode zones: %w", err)
	}
	for _, z := range zones {
		if strings.EqualFold(normName(z.Name), normName(d.cfg.ZoneName)) {
			d.zoneID = z.ID
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: zone %q not found for this token (check the token's zone scope)", d.cfg.ZoneName)
}

// listZone reads ALL records in the zone, paginating. Internal: returns cfRecords with
// ids + comments so ownership and conflicts can be reasoned about.
func (d *Driver) listZone(ctx context.Context) ([]cfRecord, error) {
	zid, err := d.resolveZoneID(ctx)
	if err != nil {
		return nil, err
	}
	var all []cfRecord
	page := 1
	for {
		path := fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", zid, page)
		info, result, err := d.api(ctx, "GET", path, nil)
		if err != nil {
			return nil, err
		}
		var recs []cfRecord
		if err := json.Unmarshal(result, &recs); err != nil {
			return nil, fmt.Errorf("cloudflare: decode records: %w", err)
		}
		all = append(all, recs...)
		if info == nil || info.TotalPages <= page || len(recs) == 0 {
			break
		}
		page++
	}
	return all, nil
}

// api issues one Cloudflare API call, decodes the envelope, and maps a non-2xx /
// success=false response to a descriptive error. Returns the result_info (for
// pagination) and the raw result.
func (d *Driver) api(ctx context.Context, method, path string, body []byte) (*cfResultInfo, json.RawMessage, error) {
	status, respBody, err := d.doer.Do(ctx, method, path, body)
	if err != nil {
		return nil, nil, fmt.Errorf("cloudflare %s %s: %w", method, pathHead(path), err)
	}
	var env cfEnvelope
	if len(respBody) > 0 {
		if jerr := json.Unmarshal(respBody, &env); jerr != nil {
			if status >= 200 && status < 300 {
				return nil, nil, fmt.Errorf("cloudflare %s %s: decode response: %w", method, pathHead(path), jerr)
			}
			return nil, nil, fmt.Errorf("cloudflare %s %s: HTTP %d: %s", method, pathHead(path), status, truncate(string(respBody)))
		}
	}
	if status < 200 || status >= 300 || !env.Success {
		return nil, nil, apiError(method, pathHead(path), status, env.Errors)
	}
	return env.ResultInfo, env.Result, nil
}

// --- guards + helpers ---

// guard enforces the host invariants on a desired record name: under the zone, and
// never a wildcard. (The ownership boundary is enforced separately on every mutation.)
func (d *Driver) guard(name string) error {
	if strings.Contains(name, "*") {
		return fmt.Errorf("cloudflare: refusing wildcard record %q — surgical mode writes exact host records only", name)
	}
	nf := normName(name)
	// Accept a name that is already under the zone, OR a bare single label (which fqdn()
	// qualifies under the zone). Refuse a multi-label FQDN that is NOT under the zone — a
	// foreign domain crenel must never write to.
	if underZone(nf, d.cfg.ZoneName) || !strings.Contains(nf, ".") {
		return nil
	}
	return fmt.Errorf("cloudflare: refusing record for %q — outside the managed zone %q", name, d.cfg.ZoneName)
}

// partition splits the zone's records at a given name+type into crenel-owned and
// foreign (unowned). Both sides are compared as fully-qualified names under the zone,
// so a desired record carrying a SHORT name matches Cloudflare's FQDN (and idempotency
// holds). Matching is case-insensitive on name and type.
func (d *Driver) partition(all []cfRecord, name, typ string) (ours, foreign []cfRecord) {
	wantName := fqdn(name, d.cfg.ZoneName)
	wantType := strings.ToUpper(typ)
	for _, r := range all {
		if fqdn(r.Name, d.cfg.ZoneName) != wantName || strings.ToUpper(r.Type) != wantType {
			continue
		}
		if owned(r) {
			ours = append(ours, r)
		} else {
			foreign = append(foreign, r)
		}
	}
	return ours, foreign
}

func foreignConflict(want model.Record, foreign []cfRecord) error {
	vals := make([]string, 0, len(foreign))
	for _, f := range foreign {
		vals = append(vals, f.Content)
	}
	return fmt.Errorf(
		"cloudflare: refusing to expose %s %s — a record crenel does NOT own already exists there (value %s); "+
			"surgical mode never overwrites or shadows a foreign record. Remove it manually or choose another name. "+
			"See docs/DNS-DESIGN.md",
		want.Type, want.Name, strings.Join(vals, ", "))
}

func notOwned(action string, r cfRecord) error {
	return fmt.Errorf(
		"cloudflare: refusing to %s %s %s (id %s) — it does not carry crenel's ownership marker %q; "+
			"surgical mode only mutates records it created",
		action, r.Type, r.Name, r.ID, MarkerPrefix)
}

// validateContent rejects what the Cloudflare API rejects up front: a non-IP value for
// an A/AAAA record (CF code 9005/1004).
func validateContent(r model.Record) error {
	switch strings.ToUpper(r.Type) {
	case "A":
		if ip := net.ParseIP(r.Value); ip == nil || ip.To4() == nil {
			return fmt.Errorf("cloudflare: %q is not a valid IPv4 address for an A record", r.Value)
		}
	case "AAAA":
		if ip := net.ParseIP(r.Value); ip == nil || ip.To4() != nil {
			return fmt.Errorf("cloudflare: %q is not a valid IPv6 address for an AAAA record", r.Value)
		}
	}
	return nil
}

func toModel(r cfRecord, scope model.Scope) model.Record {
	return model.Record{
		Name:    normName(r.Name),
		Type:    strings.ToUpper(r.Type),
		Value:   r.Content,
		Scope:   scope,
		TTL:     r.TTL,
		Proxied: r.Proxied,
	}
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// fqdn returns name as a fully-qualified name under zone (CF wants the FQDN).
func fqdn(name, zone string) string {
	n, z := normName(name), normName(zone)
	if z == "" || n == z || strings.HasSuffix(n, "."+z) {
		return n
	}
	return n + "." + z
}

func underZone(name, zone string) bool {
	n, z := normName(name), normName(zone)
	if z == "" {
		return false
	}
	return n == z || strings.HasSuffix(n, "."+z)
}

func ttlOrAuto(ttl int) int {
	if ttl <= 0 {
		return 1 // Cloudflare's "automatic" sentinel
	}
	return ttl
}

// ttlForProxied enforces Cloudflare's rule that a PROXIED record must have TTL=auto (1):
// CF rejects a proxied record carrying any other TTL with error 9207. A non-proxied
// record honors the requested TTL (auto when unset).
func ttlForProxied(ttl int, proxied bool) int {
	if proxied {
		return 1
	}
	return ttlOrAuto(ttl)
}

func renderPreview(change model.DNSChange) string {
	var b strings.Builder
	for _, r := range change.Add {
		fmt.Fprintf(&b, "+ CREATE/UPDATE %s %s -> %s [%s]\n", r.Type, r.Name, r.Value, MarkerPrefix)
	}
	for _, r := range change.Remove {
		fmt.Fprintf(&b, "- DELETE %s %s -> %s [owned]\n", r.Type, r.Name, r.Value)
	}
	if b.Len() == 0 {
		return "No changes.\n"
	}
	return b.String()
}

func apiError(method, path string, status int, errs []cfAPIError) error {
	var parts []string
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d %s", e.Code, e.Message))
	}
	detail := strings.Join(parts, "; ")
	switch {
	case status == 403 || hasCode(errs, 10000):
		return fmt.Errorf("cloudflare %s %s: authentication failed (HTTP %d): %s", method, path, status, detail)
	case status == 429 || hasCode(errs, 971):
		return fmt.Errorf("cloudflare %s %s: rate limited (HTTP %d): %s", method, path, status, detail)
	default:
		return fmt.Errorf("cloudflare %s %s: HTTP %d: %s", method, path, status, detail)
	}
}

func hasCode(errs []cfAPIError, code int) bool {
	for _, e := range errs {
		if e.Code == code {
			return true
		}
	}
	return false
}

func pathHead(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
