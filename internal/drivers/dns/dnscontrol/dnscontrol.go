// Package dnscontrol is a DNSProvider adapter that delegates record
// reconciliation to the `dnscontrol` tool. It generates a dnsconfig.js using
// !inside / !outside scope tags and shells out to `dnscontrol preview` / `push`.
//
// Live-state-authoritative note: dnscontrol is itself a desired-state tool, but
// Crenel uses it transiently. Each Apply reads LIVE records, applies the op's
// delta, renders the resulting zone as a throwaway dnsconfig.js, and pushes it.
// No dnsconfig.js is persisted as a source of truth.
//
// The shell is injected (Shell interface) and mocked in tests, so no real DNS
// provider is ever contacted by this repo's test suite.
package dnscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// Provider describes the REAL dnscontrol DNS provider to emit + authenticate. The
// zero value means the legacy mock provider (NewDnsProvider("mock") + a stub
// creds.json) — byte-identical to Crenel's original behavior, so every mock test is
// unaffected. A populated Provider (e.g. Cloudflare) makes render.go emit the real
// NewDnsProvider() and makes workdir write a real creds.json carrying the credential.
//
// The credential lives ONLY in the throwaway creds.json (0600, in a per-call 0700
// temp dir) and the process — it is never written into the rendered dnsconfig.js
// (which references the provider KEY, not the secret) and never persisted.
type Provider struct {
	// CredsKey is BOTH the dnsconfig.js NewDnsProvider() argument and the creds.json
	// top-level key, e.g. "cloudflare". Empty => the mock provider.
	CredsKey string
	// Type is the dnscontrol provider TYPE written into creds.json, e.g.
	// "CLOUDFLAREAPI". Empty when CredsKey is empty (mock).
	Type string
	// Registrar is the NewRegistrar() argument. Empty defaults to "none".
	Registrar string
	// Creds are the credential key/values written into creds.json under CredsKey
	// alongside TYPE, e.g. {"apitoken": "<token>"}. Secret-bearing; never logged or
	// rendered into dnsconfig.js.
	Creds map[string]string
}

// Config configures the dnscontrol driver.
type Config struct {
	ZoneName string      // DNS zone, e.g. "example.com"
	Scope    model.Scope // internal | public
	EdgeAddr string      // address A records point at (the edge)
	Shell    Shell       // injected; defaults to OSShell
	// Provider selects the real dnscontrol provider to emit + the credential to write
	// into creds.json. Zero value => the legacy mock provider (back-compat).
	Provider Provider
	// DedicatedZone is the operator's explicit assertion that crenel OWNS the entire
	// zone (every record is crenel-managed). Because `dnscontrol push` is whole-zone
	// authoritative, crenel REFUSES by default to push a zone that holds pre-existing
	// records it did not author (it would become authoritative over a shared zone — the
	// lone-wildcard homelab.example trap). Setting this true opts into whole-zone
	// management; the multi-field/multi-value fidelity refusals still apply. Default
	// false (safe). See guardPush + docs/DNS-DESIGN.md.
	DedicatedZone bool
	// WorkDir is where dnsconfig.js is written. Defaults to a temp dir per call.
	WorkDir string
}

// Driver implements ports.DNSProvider via dnscontrol.
type Driver struct {
	cfg   Config
	shell Shell
}

// New builds a dnscontrol Driver.
func New(cfg Config) *Driver {
	sh := cfg.Shell
	if sh == nil {
		sh = OSShell{}
	}
	if cfg.Scope == "" {
		cfg.Scope = model.ScopeInternal
	}
	return &Driver{cfg: cfg, shell: sh}
}

func (d *Driver) Name() string       { return "dnscontrol" }
func (d *Driver) Scope() model.Scope { return d.cfg.Scope }

// DesiredRecords returns the record(s) the op concerns for this scope: a single
// A record mapping the op's host to the edge address.
func (d *Driver) DesiredRecords(op model.Op) ([]model.Record, error) {
	if op.Host == "" {
		return nil, fmt.Errorf("dnscontrol: op has no host")
	}
	return []model.Record{{
		Name:  op.Host,
		Type:  "A",
		Value: d.cfg.EdgeAddr,
		Scope: d.cfg.Scope,
	}}, nil
}

// LiveRecords reads the records currently live in this scope by shelling out to
// dnscontrol get-zones and parsing TSV output.
func (d *Driver) LiveRecords(ctx context.Context) ([]model.Record, error) {
	dir, cleanup, err := d.workdir(nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	// dnscontrol get-zones contract: `get-zones <credkey> <provider> <zone>`. The
	// provider arg is the TYPE (or "-" to read it from creds.json). For the mock
	// provider these are sentinels the fake shell ignores; for a real provider they
	// are what authenticates the read. creds.json is written by workdir for a real
	// provider so the read can authenticate.
	out, err := d.shell.Run(ctx, dir, "get-zones", "--format=tsv", providerKey(d.cfg.Provider), providerTypeArg(d.cfg.Provider), d.cfg.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("dnscontrol get-zones: %w", err)
	}
	return parseTSV(out, d.cfg.ZoneName, d.cfg.Scope), nil
}

// Diff computes the DNSChange to realize op against live records.
func (d *Driver) Diff(ctx context.Context, op model.Op, desired []model.Record) (model.DNSChange, error) {
	live, err := d.LiveRecords(ctx)
	if err != nil {
		return model.DNSChange{}, err
	}
	// Safety gate (see guardPush): `dnscontrol push` is whole-zone authoritative, so it
	// would corrupt/delete records crenel can't faithfully render, AND make crenel
	// authoritative over any pre-existing record it doesn't own. `desired` is crenel's
	// managed record set for this op — a live record matching it by name/type AND value
	// is recognized as crenel's own (so unexpose / idempotent re-expose are never
	// blocked). Refuse at plan time.
	if err := guardPush(d.cfg.ZoneName, live, desired, d.cfg.DedicatedZone); err != nil {
		return model.DNSChange{}, err
	}
	// Carry the managed set through to Apply so the apply-time gate uses the SAME
	// ownership basis as here (not the bare Add/Remove delta, which would flag an
	// already-correct managed record as foreign).
	change := model.DNSChange{Scope: d.cfg.Scope, Managed: desired}
	liveByKey := indexByKey(live)

	switch op.Verb {
	case model.Expose:
		// Value-AWARE: a record present at the same name/type but a DIFFERENT value is
		// an UPDATE, not a no-op. Re-assert it so the rendered zone carries the new
		// value (applyChange replaces by key). Without this, a stale public IP would
		// never be corrected and read-back would falsely pass.
		for _, r := range desired {
			cur, ok := liveByKey[r.Key()]
			switch {
			case !ok:
				change.Add = append(change.Add, r)
			case !strings.EqualFold(cur.Value, r.Value):
				// Value update: the op changes only the target; PRESERVE the live record's
				// TTL + proxied state so a value change doesn't reset them to defaults.
				r.TTL, r.Proxied = cur.TTL, cur.Proxied
				change.Add = append(change.Add, r)
			}
		}
	case model.Unexpose:
		for _, r := range desired {
			if _, ok := liveByKey[r.Key()]; ok {
				change.Remove = append(change.Remove, r)
			}
		}
	default:
		return change, fmt.Errorf("dnscontrol diff: unknown verb %q", op.Verb)
	}

	// Capture the human-facing preview by rendering the target zone and asking
	// dnscontrol to preview it. This is best-effort (display only).
	target := applyChange(live, change)
	if rendered, err := d.previewText(ctx, target); err == nil {
		change.Rendered = rendered
	}
	return change, nil
}

// Apply realizes a DNSChange by reading live, applying the delta, rendering the
// resulting zone as a throwaway dnsconfig.js, and pushing it via dnscontrol.
func (d *Driver) Apply(ctx context.Context, change model.DNSChange) error {
	live, err := d.LiveRecords(ctx)
	if err != nil {
		return err
	}
	// Defense in depth: re-check the gate at apply time (live state may have changed
	// since Diff). The owned set is the managed canonical records (carried from
	// Diff/reconcile/declarative) PLUS the records this change adds or removes — a record
	// crenel is deleting (a stale/pruned managed record) is its OWN, not foreign. With
	// Managed unset (legacy/hand-built change) this degrades to the Add∪Remove delta.
	owned := append([]model.Record(nil), change.Managed...)
	owned = append(owned, change.Add...)
	owned = append(owned, change.Remove...)
	if err := guardPush(d.cfg.ZoneName, live, owned, d.cfg.DedicatedZone); err != nil {
		return err
	}
	target := applyChange(live, change)
	dir, cleanup, err := d.workdir(target)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := d.shell.Run(ctx, dir, "push", "--config", "dnsconfig.js"); err != nil {
		return fmt.Errorf("dnscontrol push: %w", err)
	}
	return nil
}

func (d *Driver) previewText(ctx context.Context, target []model.Record) (string, error) {
	dir, cleanup, err := d.workdir(target)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return d.shell.Run(ctx, dir, "preview", "--config", "dnsconfig.js")
}

// workdir creates a temp dir containing a generated dnsconfig.js (if records is
// non-nil) plus a stub creds.json. Returns the dir and a cleanup func.
//
// A REAL provider's creds.json carries a live secret, so it ALWAYS lands in a private,
// per-call 0700 temp dir that is removed on cleanup — never in a caller-supplied
// WorkDir (which may persist or be group/other-readable). WorkDir is only honored for
// the mock provider, as a debug convenience.
func (d *Driver) workdir(records []model.Record) (string, func(), error) {
	dir := d.cfg.WorkDir
	cleanup := func() {}
	if dir == "" || d.cfg.Provider.CredsKey != "" {
		var err error
		dir, err = os.MkdirTemp("", "crenel-dnscontrol-*")
		if err != nil {
			return "", cleanup, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
	}
	if records != nil {
		js := renderConfigJS(d.cfg.ZoneName, d.cfg.Scope, d.cfg.Provider, records)
		if err := os.WriteFile(filepath.Join(dir, "dnsconfig.js"), []byte(js), 0o644); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	// creds.json carries the real credential (0600 — it is a secret file). A REAL
	// provider needs it for EVERY call (reads included, so get-zones can authenticate);
	// the mock provider keeps the historical behavior of a `{}` stub only on the
	// write path (records != nil).
	if records != nil || d.cfg.Provider.CredsKey != "" {
		if err := os.WriteFile(filepath.Join(dir, "creds.json"), credsJSON(d.cfg.Provider), 0o600); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return dir, cleanup, nil
}

// credsJSON renders the dnscontrol creds.json for the configured provider. A zero
// Provider yields the historical empty document `{}` (mock). A real provider yields
// {"<key>": {"TYPE": "<type>", "<cred>": "<value>", ...}} — the exact shape
// dnscontrol reads. The secret values appear ONLY here (a 0600 throwaway file).
func credsJSON(p Provider) []byte {
	if p.CredsKey == "" {
		return []byte("{}")
	}
	entry := map[string]string{"TYPE": p.Type}
	for k, v := range p.Creds {
		entry[k] = v
	}
	doc := map[string]map[string]string{p.CredsKey: entry}
	b, err := json.Marshal(doc)
	if err != nil { // map[string]string never fails to marshal; defensive.
		return []byte("{}")
	}
	return b
}

// --- helpers ---

func keySet(recs []model.Record) map[string]bool {
	m := make(map[string]bool, len(recs))
	for _, r := range recs {
		m[r.Key()] = true
	}
	return m
}

func indexByKey(recs []model.Record) map[string]model.Record {
	m := make(map[string]model.Record, len(recs))
	for _, r := range recs {
		m[r.Key()] = r
	}
	return m
}

// applyChange returns live with change's removes taken out and adds put in. An Add
// REPLACES any live record with the same key (a value update), rather than producing
// two records at the same name/type — so the rendered zone carries the new value.
// Order is stable: live order first, new names appended.
func applyChange(live []model.Record, change model.DNSChange) []model.Record {
	remove := keySet(change.Remove)
	add := indexByKey(change.Add)
	// Non-nil even when the result is empty: unexposing the last record yields an EMPTY
	// zone that must still render + push a (record-less) dnsconfig.js — a nil target would
	// be read by workdir as the read path and skip writing the file. workdir(nil) from
	// LiveRecords stays the read path.
	out := make([]model.Record, 0, len(live)+len(change.Add))
	seen := map[string]bool{}
	for _, r := range live {
		if remove[r.Key()] {
			continue
		}
		if repl, ok := add[r.Key()]; ok { // value update: live record replaced in place
			out = append(out, repl)
		} else {
			out = append(out, r)
		}
		seen[r.Key()] = true
	}
	for _, r := range change.Add {
		if !seen[r.Key()] {
			out = append(out, r)
			seen[r.Key()] = true
		}
	}
	return out
}

// renderableTypes are the DNS record types renderConfigJS emits CORRECTLY with the
// single-value form TYPE(name, value, {scope}). Multi-field types (MX preference, SRV
// priority/weight/port, CAA flags/tag, SOA, etc.) are NOT in this set: round-tripping
// them through Crenel's narrow Name/Type/Value model is lossy.
var renderableTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true, "NS": true, "PTR": true,
}

// isApexProviderManaged reports whether r is the zone's own apex NS/SOA — records the
// DNS provider manages and dnscontrol never purges. They are excepted from every push
// guard and excluded from the rendered zone.
func isApexProviderManaged(r model.Record, zone string) bool {
	t := strings.ToUpper(r.Type)
	if t != "NS" && t != "SOA" {
		return false
	}
	zn := strings.TrimSuffix(strings.ToLower(zone), ".")
	return strings.EqualFold(strings.TrimSuffix(r.Name, "."), zn)
}

// guardPush is the whole-zone-push safety gate, run at plan AND apply time. It refuses
// two distinct classes:
//
//  1. FIDELITY (always, even on a dedicated zone): a live record crenel cannot
//     faithfully re-render — a multi-FIELD type (MX/SRV/CAA/SOA…) or a multi-VALUE set
//     (>1 record at one name+type, which Key() collapses). A push would corrupt/delete
//     them. See unrenderableRefusal.
//  2. OWNERSHIP (default-deny, unless DedicatedZone): a pre-existing record crenel does
//     NOT own. Because push is whole-zone authoritative and model.Record carries no
//     ownership marker, crenel cannot statelessly tell its own prior records from
//     foreign ones — so by default it refuses to push a zone that holds ANY pre-existing
//     data record other than the op's own (this is what catches the lone-wildcard
//     homelab.example case). `owned` is the op's record set (excluded so unexpose /
//     idempotent re-expose of a crenel host always work). Setting DedicatedZone asserts
//     crenel owns the ENTIRE zone and skips this check. See foreignRefusal.
func guardPush(zone string, live, managed []model.Record, dedicated bool) error {
	if err := unrenderableRefusal(zone, live); err != nil {
		return err
	}
	if dedicated {
		return nil
	}
	return foreignRefusal(zone, managed, live)
}

// unrenderableRefusal is the FIDELITY half of guardPush (see guardPush). Apex NS/SOA are
// provider-managed and excepted.
func unrenderableRefusal(zone string, live []model.Record) error {
	counts := map[string]int{}
	for _, r := range live {
		counts[r.Key()]++
	}
	var bad []string
	flagged := map[string]bool{}
	for _, r := range live {
		t := strings.ToUpper(r.Type)
		apex := isApexProviderManaged(r, zone)
		switch {
		case !renderableTypes[t]:
			if apex { // provider-managed apex SOA/NS
				continue
			}
			bad = append(bad, r.Type+" "+r.Name)
		case strings.Contains(r.Value, `"`):
			// A value with an embedded double-quote — a multi-string TXT (`"a" "b"`) or a
			// DKIM key with quotes — does NOT round-trip faithfully through crenel's %q
			// render + the fakes' simple parse. Refuse rather than silently corrupt it.
			if !flagged[r.Key()] {
				bad = append(bad, "quoted "+r.Type+" "+r.Name)
				flagged[r.Key()] = true
			}
		case counts[r.Key()] > 1 && !apex:
			if !flagged[r.Key()] {
				bad = append(bad, fmt.Sprintf("%d×%s %s", counts[r.Key()], r.Type, r.Name))
				flagged[r.Key()] = true
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf(
		"dnscontrol: refusing to push zone %q — it contains %d record(s)/set(s) crenel cannot faithfully re-render (%s); "+
			"a whole-zone push would corrupt or DELETE them. Manage a DEDICATED zone (all crenel-owned), "+
			"or extend the record model first. See docs/DNS-DESIGN.md",
		zone, len(bad), strings.Join(bad, ", "))
}

// foreignRefusal is the OWNERSHIP half of guardPush (see guardPush): on a non-dedicated
// zone, refuse if any pre-existing data record is NOT one crenel manages. A live record
// is "managed" only when it matches a managed record by Key() AND value — a record at a
// managed name but a value crenel did not author (a foreign production record, or a
// drift crenel can't prove it owns) is treated as foreign and refused, never silently
// overwritten by the whole-zone push. Apex NS/SOA are excepted (provider-managed).
func foreignRefusal(zone string, managed, live []model.Record) error {
	want := make(map[string]string, len(managed)) // Key() -> expected value
	for _, r := range managed {
		want[r.Key()] = r.Value
	}
	var foreign []string
	for _, r := range live {
		if isApexProviderManaged(r, zone) {
			continue
		}
		if v, ok := want[r.Key()]; ok && strings.EqualFold(v, r.Value) {
			continue // a managed record, present with the expected value
		}
		foreign = append(foreign, r.Type+" "+r.Name)
	}
	if len(foreign) == 0 {
		return nil
	}
	return fmt.Errorf(
		"dnscontrol: refusing to push zone %q — it has %d pre-existing record(s) crenel does not own (%s); "+
			"a whole-zone push would make crenel authoritative over them. Set this DNS provider's "+
			"`dedicated_zone: true` ONLY if crenel owns the ENTIRE zone, or use a dedicated zone. "+
			"See docs/DNS-DESIGN.md",
		zone, len(foreign), strings.Join(foreign, ", "))
}

// parseTSV parses `dnscontrol get-zones --format=tsv` output. The REAL dnscontrol row
// (StackExchange/dnscontrol) is tab-separated:
//
//	NameFQDN \t ShortName \t TTL \t IN \t Type \t Target [\t Properties]
//
// Crenel reads NameFQDN (col 0), TTL (col 2), Type (col 4) and Target (col 5); the
// optional Properties column (col 6) carries Cloudflare's proxied state as the token
// `cloudflare_proxy=true` (emitted ONLY when proxied ON — grey-cloud emits nothing).
// Lines with fewer than 6 fields (blanks, a `#` comment, a CLI deprecation warning that
// the OSShell merges from stderr) are skipped.
func parseTSV(out, zone string, scope model.Scope) []model.Record {
	var recs []model.Record
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		ttl, _ := strconv.Atoi(strings.TrimSpace(f[2]))
		rec := model.Record{
			Name:  fqdn(strings.TrimSpace(f[0]), zone),
			Type:  strings.TrimSpace(f[4]),
			Value: strings.Trim(strings.TrimSpace(f[5]), `"`),
			Scope: scope,
			TTL:   ttl,
		}
		if len(f) >= 7 && strings.Contains(f[6], "cloudflare_proxy=true") {
			rec.Proxied = true
		}
		recs = append(recs, rec)
	}
	return recs
}
