package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// parseConfig decodes admin/adapted JSON into a Config (an empty/"null" payload is a
// valid empty config — nothing loaded).
func parseConfig(b []byte) (Config, error) {
	var cfg Config
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return cfg, nil
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// persist_caddyfile.go is the DURABLE reconciler for a wildcard-site Caddyfile edge (the
// real home edge): it makes an admin-API write SURVIVE a control-plane restart by
// reconciling the live admin JSON into the on-disk boot Caddyfile, read-back-verified so
// a restart reproduces exactly what is live. There is NO second source of truth — the
// Caddyfile edit is PROVEN to re-adapt to the live managed state before it is committed.
//
// Why this exists alongside the flat persister (persist.go): the home Caddyfile routes
// every service through wildcard sites (`*.homelab.example { … }`). A managed host's
// durable form is a per-host `@crenel_<host> host …` + `handle { reverse_proxy … }`
// INSIDE the covering wildcard (inheriting its TLS), NOT a top-level `host {}` site —
// which would be more specific than the wildcard, SHADOW it, and (lacking the wildcard's
// `tls { dns cloudflare }`) break cert issuance. The flat persister is the greenfield/
// simple-edge path; this is the wildcard-faithful path, dispatched to from Persist.
//
// The reconcile pipeline (a bad candidate NEVER touches the live boot file):
//  1. partition managed routes by covering wildcard zone (+ a flat group for any host
//     no wildcard covers); REFUSE a host an operator block already owns on disk.
//  2. render the candidate: replace/insert crenel's sentinel region inside each zone.
//  3. SELF-CHECK: parse crenel's own region back out and assert it reproduces the managed
//     routes (a render bug fails here, before any disk write).
//  4. VALIDATE the candidate (`caddy validate`).
//  5. ADAPT cross-check (if an Adapter is wired): `caddy adapt` the candidate → normalize
//     → assert every managed host resolves to the SAME backend + auth as live. THIS is
//     the "a restart reproduces the same state" proof; it makes the on-disk config a
//     verified mirror of live, not an independently-authored SOT.
//  6. write the candidate to the boot path + reload ONCE.

// ConfigStore reads and writes the on-disk boot config over whatever channel reaches it.
// For an on-box (direct) edge it is the local filesystem; for a remote (ssh-exec) edge —
// the home edge, whose Caddyfile lives on the LXC host — it is a transport-backed store
// wired at cmd (the channel mirrors the admin transport). Abstracting it keeps the
// reconciler identical whether the boot file is local or one `pct exec` away.
type ConfigStore interface {
	// Read returns the current boot-config bytes.
	Read(ctx context.Context) ([]byte, error)
	// WriteCandidate stages b at the boot path's sibling candidate location (boot +
	// ".crenel-candidate") so the CLI can validate it WITHOUT touching the live boot
	// file. Staging through the store (not crenel's local fs) is what makes validate-
	// before-commit work for a REMOTE edge: the candidate lands where the caddy binary
	// can see it (e.g. the LXC host dir that ro-mounts into the container), not on
	// crenel's laptop. The caddy-visible candidate path is bootPath+".crenel-candidate".
	WriteCandidate(ctx context.Context, b []byte) error
	// RemoveCandidate deletes the staged candidate (best-effort cleanup).
	RemoveCandidate(ctx context.Context) error
	// Write atomically commits b as the new boot config (only after validate+adapt pass).
	Write(ctx context.Context, b []byte) error
}

// candidateSuffix is appended to the boot path for the staged, to-be-validated candidate.
const candidateSuffix = ".crenel-candidate"

// Adapter adapts a candidate Caddyfile to admin JSON — `caddy adapt` — so the reconciler
// can prove the candidate re-adapts to the live managed state BEFORE committing it. The
// real OSAdapter shells out; tests inject a faithful fake (and the live trial exercises
// the real one). nil => the adapt cross-check is skipped (durability is self-checked
// only, surfaced honestly).
type Adapter interface {
	Adapt(ctx context.Context, configBytes []byte) (jsonBytes []byte, err error)
}

// localConfigStore is the default ConfigStore: the boot Caddyfile on the local
// filesystem at path (the on-box / direct-transport case).
type localConfigStore struct{ path string }

func (s localConfigStore) Read(context.Context) ([]byte, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read on-disk Caddyfile %s (it must exist and be mounted): %w", s.path, err)
	}
	return b, nil
}
func (s localConfigStore) WriteCandidate(_ context.Context, b []byte) error {
	return os.WriteFile(s.path+candidateSuffix, b, 0o644)
}
func (s localConfigStore) RemoveCandidate(context.Context) error {
	return os.Remove(s.path + candidateSuffix)
}
func (s localConfigStore) Write(_ context.Context, b []byte) error {
	// Atomic commit: write a temp then rename over the boot file.
	tmp := s.path + ".crenel-commit"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// WithConfigStore injects the boot-config read/write channel (default: local FS at the
// persist path). A remote (ssh-exec) edge passes a transport-backed store.
func WithConfigStore(s ConfigStore) Option { return func(d *Driver) { d.configStore = s } }

// WithAdapter injects the `caddy adapt` cross-check seam used by the durable reconciler.
// Absent, the reconcile still self-checks + validates, but skips the re-adaptation proof.
func WithAdapter(a Adapter) Option { return func(d *Driver) { d.adapter = a } }

// configStoreOrDefault returns the configured store, or the local-FS default at the
// persist path.
func (d *Driver) configStoreOrDefault() ConfigStore {
	if d.configStore != nil {
		return d.configStore
	}
	return localConfigStore{path: d.persistPath}
}

// inSiteReconcile reports whether ANY managed host is covered by a wildcard site block
// in the boot Caddyfile — the signal to use the wildcard-faithful reconciler rather than
// the flat top-level persister.
func (d *Driver) inSiteReconcile(caddyfile string, managed []model.Route) bool {
	addrs := siteAddresses(caddyfile)
	for _, r := range managed {
		if zone, _ := coveringZone(r.Host, addrs); zone != "" {
			return true
		}
	}
	// Also reconcile in-site when a wildcard site ALREADY holds a crenel region — so an
	// unexpose that empties the managed set CLEARS the region rather than leaving a stale
	// handle behind (and never falls through to the flat path, which would ignore it).
	for _, addr := range addrs {
		if !strings.HasPrefix(addr, "*.") {
			continue
		}
		addrCopy := addr
		if site, ok := findSiteBlock(caddyfile, func(a string) bool { return a == addrCopy }); ok &&
			strings.Contains(caddyfile[site.bodyStart:site.bodyEnd], persistBegin) {
			return true
		}
	}
	return false
}

// persistInSite is the wildcard-site durable reconcile (see file header). It partitions
// the managed routes, renders + self-checks + validates + (optionally) adapt-verifies a
// candidate, then writes it and reloads. Every operator byte outside crenel's sentinel
// regions is preserved.
func (d *Driver) persistInSite(ctx context.Context, existing string, managed []model.Route, liveHosts []string) error {
	addrs := siteAddresses(existing)

	// 1. Partition by covering zone; collect flat (uncovered) hosts; refuse conflicts.
	byZone := map[string][]model.Route{}
	var flat []model.Route
	for _, r := range managed {
		zone, conflict := coveringZone(r.Host, addrs)
		if conflict {
			return fmt.Errorf("persist: host %s is owned by an operator site block on disk — adopt it (crenel import) "+
				"or edit the Caddyfile; crenel will not shadow an operator-owned host", r.Host)
		}
		if zone == "" {
			flat = append(flat, r)
			continue
		}
		// An operator handle already routing this host inside the wildcard would shadow a
		// crenel duplicate — refuse rather than write a dead handle.
		if operatorOwnsHostInSite(existing, zone, r.Host) {
			return fmt.Errorf("persist: host %s is already handled by an operator block inside %s — adopt it "+
				"(crenel import) or edit the Caddyfile; crenel will not add a shadowed duplicate", r.Host, zone)
		}
		byZone[zone] = append(byZone[zone], r)
	}

	// 2. Render the candidate. Every zone that has managed hosts OR currently holds a
	//    crenel region is (re)written — so an unexpose that empties a zone CLEARS its
	//    region rather than leaving a stale handle.
	candidate := existing
	for _, zone := range zonesToWrite(existing, byZone) {
		block := renderInSiteHandles(byZone[zone], d.authSnippet)
		zoneCopy := zone
		merged, ok := mergeInSiteRegion(candidate, func(a string) bool { return a == zoneCopy }, block)
		if !ok {
			return fmt.Errorf("persist: covering site %s vanished mid-reconcile", zone)
		}
		candidate = merged
	}
	if len(flat) > 0 {
		candidate = mergeManagedRegion(candidate, renderManagedBlocks(flat, d.authSnippet))
	}

	// 3. Self-check: crenel's own region must parse back to exactly the managed routes.
	if err := d.selfCheckRegions(candidate, byZone, flat); err != nil {
		return err
	}

	// 4/5/6: validate, adapt cross-check (+ no-drift-loss gate), write + reload.
	return d.validateAdaptWriteReload(ctx, candidate, managed, liveHosts)
}

// selfCheckRegions parses crenel's rendered regions back out of the candidate and
// asserts they reproduce exactly the managed routes (host → address/auth/tls). It is the
// deterministic render read-back: a drop, a wrong address, or a stale leftover fails HERE
// — before any disk write or external process.
func (d *Driver) selfCheckRegions(candidate string, byZone map[string][]model.Route, flat []model.Route) error {
	for zone, want := range byZone {
		zoneCopy := zone
		site, ok := findSiteBlock(candidate, func(a string) bool { return a == zoneCopy })
		if !ok {
			return fmt.Errorf("persist self-check: site %s missing from candidate", zone)
		}
		got := parseInSiteRegion(candidate[site.bodyStart:site.bodyEnd])
		if err := sameRouteSet(want, got); err != nil {
			return fmt.Errorf("persist self-check (zone %s): %w", zone, err)
		}
	}
	if len(flat) > 0 {
		// The flat top-level region renders `host { … }` site blocks (not @host/handle
		// pairs), so it is host-presence checked.
		if err := flatRegionHasHosts(candidate, flat); err != nil {
			return fmt.Errorf("persist self-check (flat): %w", err)
		}
	}
	return nil
}

// validateAdaptWriteReload runs the external pipeline shared by the durable paths: write
// a candidate the CLI can see, validate it, optionally adapt-cross-check it against live,
// then commit (write the boot path) and reload ONCE. A failure at any step leaves the
// live boot file UNTOUCHED.
func (d *Driver) validateAdaptWriteReload(ctx context.Context, candidate string, managed []model.Route, liveHosts []string) error {
	cli := d.persistCaddyCLI()
	adapter := d.persistAdapter()
	store := d.configStoreOrDefault()
	to := d.writeTimeout
	if to <= 0 {
		to = defaultWriteTimeout
	}

	// Stage the candidate through the STORE at the boot-path sibling, so the caddy binary
	// can validate it whether it runs locally or one `pct exec` away (a local os.WriteFile
	// would be invisible to an in-container caddy). The live boot file is never touched.
	if err := store.WriteCandidate(ctx, []byte(candidate)); err != nil {
		return fmt.Errorf("persist: stage candidate: %w", err)
	}
	defer store.RemoveCandidate(context.WithoutCancel(ctx))
	candidatePath := d.persistPath + candidateSuffix

	vctx, vcancel := context.WithTimeout(ctx, to)
	defer vcancel()
	if err := cli.Validate(vctx, candidatePath); err != nil {
		return fmt.Errorf("persist: %w", err)
	}

	// Adapt cross-check: prove the candidate re-adapts to the live managed state, so a
	// restart reproduces it. Skipped only when no Adapter is wired (durability is then
	// self-checked + validated, but not adapt-verified — an honest, lesser guarantee).
	if adapter != nil {
		actx, acancel := context.WithTimeout(ctx, to)
		defer acancel()
		jsonBytes, err := adapter.Adapt(actx, []byte(candidate))
		if err != nil {
			return fmt.Errorf("persist: adapt candidate: %w", err)
		}
		if err := assertAdaptedMatchesLive(jsonBytes, d.server, managed); err != nil {
			return fmt.Errorf("persist: re-adaptation read-back FAILED (the on-disk config would reload to a DIFFERENT "+
				"state than is live — refusing to persist): %w", err)
		}
		// No-drift-loss gate (safe-by-construction durability): the persist's reload — and
		// any later control-plane restart — re-derives the WHOLE live config from this
		// Caddyfile, so a host that is live NOW but absent from the candidate's adaptation
		// would be DROPPED. Refuse rather than clobber it. This is the trial's manual
		// pre-flight drift check, folded into the reconciler.
		if err := assertNoDriftLoss(jsonBytes, d.server, liveHosts); err != nil {
			return fmt.Errorf("persist: ON-DISK DRIFT — refusing to reload (it would DROP a live route the Caddyfile "+
				"does not reproduce; reconcile the edge first): %w", err)
		}
	}

	// Commit + reload only after validate + adapt pass.
	if err := store.Write(ctx, []byte(candidate)); err != nil {
		return fmt.Errorf("persist: write boot config: %w", err)
	}
	rctx, rcancel := context.WithTimeout(ctx, to)
	defer rcancel()
	if err := cli.Reload(rctx, d.persistPath); err != nil {
		return fmt.Errorf("persist: reload: %w", err)
	}
	return nil
}

// assertAdaptedMatchesLive normalizes the adapted candidate JSON and asserts every
// managed host resolves to the SAME backend address + auth posture as the live managed
// route. A missing or mismatched host means a restart would NOT reproduce live — the
// reconcile refuses. This is the no-second-SOT guarantee made concrete.
func assertAdaptedMatchesLive(adaptedJSON []byte, serverKey string, managed []model.Route) error {
	cfg, err := parseConfig(adaptedJSON)
	if err != nil {
		return fmt.Errorf("parse adapted JSON: %w", err)
	}
	adapted := normalize(cfg, serverKey, string(adaptedJSON))
	byHost := map[string]model.Route{}
	for _, r := range adapted.Routes {
		byHost[strings.ToLower(r.Host)] = r
	}
	for _, want := range managed {
		got, ok := byHost[strings.ToLower(want.Host)]
		if !ok {
			return fmt.Errorf("managed host %s absent from the re-adapted config", want.Host)
		}
		if got.Upstream.Address != want.Upstream.Address {
			return fmt.Errorf("host %s backend drift: live %q vs on-disk %q", want.Host, want.Upstream.Address, got.Upstream.Address)
		}
		if !sameAuthPosture(want.Upstream.Auth, got.Upstream.Auth) {
			return fmt.Errorf("host %s auth drift: live %q vs on-disk %q", want.Host, want.Upstream.Auth, got.Upstream.Auth)
		}
	}
	return nil
}

// assertNoDriftLoss asserts every host that is LIVE right now is reproduced by the
// candidate's adaptation — so the durable reload (and any restart) re-derives them all
// rather than dropping one. A live host MISSING from the adapted candidate is live-only
// drift (a route added via the admin API but never written to the Caddyfile); reloading
// the Caddyfile would silently clobber it. crenel refuses. This makes durability
// safe-by-construction, not merely safe-by-trial-discipline.
func assertNoDriftLoss(adaptedJSON []byte, serverKey string, liveHosts []string) error {
	cfg, err := parseConfig(adaptedJSON)
	if err != nil {
		return fmt.Errorf("parse adapted JSON: %w", err)
	}
	adapted := normalize(cfg, serverKey, string(adaptedJSON))
	have := map[string]bool{}
	for _, r := range adapted.Routes {
		have[strings.ToLower(r.Host)] = true
	}
	var missing []string
	for _, h := range liveHosts {
		if !have[strings.ToLower(h)] {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%d live host(s) absent from the on-disk config: %s", len(missing), strings.Join(missing, ", "))
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

// existingRegionHostSet returns the lowercased set of hosts crenel ALREADY persisted into
// the Caddyfile — collected from every in-site crenel region (a `@crenel_<host>`+handle
// inside a wildcard site) AND the flat top-level region. It is the load-bearing input to
// TRIAL-FIX-DURABLE-2: a route whose host is here is crenel's even though, after a durable
// reload, it carries no @id — so the persist mirror keeps it instead of dropping it.
func existingRegionHostSet(caddyfile string) map[string]bool {
	out := map[string]bool{}
	// In-site regions: the @crenel_<host>+handle pairs inside each site's sentinel region.
	for _, addr := range siteAddresses(caddyfile) {
		a := addr
		site, ok := findSiteBlock(caddyfile, func(s string) bool { return s == a })
		if !ok {
			continue
		}
		body := caddyfile[site.bodyStart:site.bodyEnd]
		if !strings.Contains(body, persistBegin) {
			continue
		}
		for _, r := range parseInSiteRegion(body) {
			out[strings.ToLower(r.Host)] = true
		}
	}
	// Flat top-level region: `host { … }` site blocks between UN-INDENTED sentinels (the
	// flat persister writes the begin sentinel at column 0; an in-site region is tab-
	// indented, so `\n# crenel-managed-begin` matches only the flat one).
	if reg, ok := flatRegionText(caddyfile); ok {
		for _, ln := range strings.Split(reg, "\n") {
			t := strings.TrimSpace(stripComment(ln))
			if strings.HasSuffix(t, "{") {
				h := strings.TrimSpace(strings.TrimSuffix(t, "{"))
				if h != "" && !strings.HasPrefix(h, "*") && !strings.HasPrefix(h, "(") && strings.Contains(h, ".") {
					out[strings.ToLower(h)] = true
				}
			}
		}
	}
	return out
}

// flatRegionText returns the text inside a TOP-LEVEL (un-indented) crenel region, if one
// exists — selecting only the flat persister's region (its begin sentinel is at column 0;
// an in-site region is tab-indented).
func flatRegionText(caddyfile string) (string, bool) {
	begin := -1
	if strings.HasPrefix(caddyfile, persistBegin) {
		begin = 0
	} else if i := strings.Index(caddyfile, "\n"+persistBegin); i >= 0 {
		begin = i + 1
	}
	if begin < 0 {
		return "", false
	}
	rest := caddyfile[begin+len(persistBegin):]
	end := strings.Index(rest, persistEnd)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// siteAddresses returns the top-level site addresses in a Caddyfile (skipping the global
// block and `(snippet)` blocks), in source order.
func siteAddresses(caddyfile string) []string {
	var addrs []string
	rest := caddyfile
	offset := 0
	for {
		span, ok := findSiteBlock(rest[offset:], func(string) bool { return true })
		if !ok {
			break
		}
		addrs = append(addrs, span.addr)
		// advance past this block
		offset = offset + span.bodyEnd + 1
		if offset >= len(rest) {
			break
		}
	}
	return addrs
}

// coveringZone returns the wildcard site `*.zone` that covers host (host is a single
// label under the wildcard), or "" if none. conflict is true when an EXACT operator site
// for the host exists (the operator owns that host as its own site block — crenel must
// not shadow it).
func coveringZone(host string, addrs []string) (zone string, conflict bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	best := ""
	for _, a := range addrs {
		la := strings.ToLower(a)
		if la == host {
			return "", true
		}
		if strings.HasPrefix(la, "*.") {
			suffix := la[1:] // ".zone"
			if strings.HasSuffix(host, suffix) {
				label := strings.TrimSuffix(host, suffix)
				if label != "" && !strings.Contains(label, ".") { // exactly one extra label
					if len(la) > len(best) {
						best = a
					}
				}
			}
		}
	}
	return best, false
}

// operatorOwnsHostInSite reports whether an OPERATOR handle (a `host <h>` matcher whose
// label is not crenel's) inside the zone site already routes host — which would shadow a
// crenel duplicate. It reads the site body OUTSIDE crenel's region.
func operatorOwnsHostInSite(caddyfile, zone, host string) bool {
	zoneCopy := zone
	site, ok := findSiteBlock(caddyfile, func(a string) bool { return a == zoneCopy })
	if !ok {
		return false
	}
	body := caddyfile[site.bodyStart:site.bodyEnd]
	// Strip crenel's own region so we only see operator handles.
	if bi := strings.Index(body, persistBegin); bi >= 0 {
		if ei := strings.Index(body[bi:], persistEnd); ei >= 0 {
			body = body[:bi] + body[bi+ei+len(persistEnd):]
		}
	}
	host = strings.ToLower(host)
	for _, ln := range strings.Split(body, "\n") {
		f := strings.Fields(stripComment(ln))
		if len(f) == 3 && strings.HasPrefix(f[0], "@") && f[1] == "host" && strings.ToLower(f[2]) == host {
			if !strings.HasPrefix(strings.TrimPrefix(f[0], "@"), "crenel_") {
				return true
			}
		}
	}
	return false
}

// zonesToWrite is the set of zones whose region must be (re)written: those with managed
// hosts now, UNION those that currently hold a crenel region (so emptied zones get
// cleared). Sorted for deterministic output.
func zonesToWrite(existing string, byZone map[string][]model.Route) []string {
	set := map[string]bool{}
	for z := range byZone {
		set[z] = true
	}
	for _, addr := range siteAddresses(existing) {
		if !strings.HasPrefix(addr, "*.") {
			continue
		}
		addrCopy := addr
		site, ok := findSiteBlock(existing, func(a string) bool { return a == addrCopy })
		if ok && strings.Contains(existing[site.bodyStart:site.bodyEnd], persistBegin) {
			set[addr] = true
		}
	}
	out := make([]string, 0, len(set))
	for z := range set {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// sameRouteSet asserts two route sets match on host → (address, auth posture, upstream
// TLS) — the durable-relevant fields. Order-independent.
func sameRouteSet(want, got []model.Route) error {
	if len(want) != len(got) {
		return fmt.Errorf("route count mismatch: want %d, got %d", len(want), len(got))
	}
	gi := map[string]model.Route{}
	for _, r := range got {
		gi[strings.ToLower(r.Host)] = r
	}
	for _, w := range want {
		g, ok := gi[strings.ToLower(w.Host)]
		if !ok {
			return fmt.Errorf("host %s missing", w.Host)
		}
		if g.Upstream.Address != w.Upstream.Address {
			return fmt.Errorf("host %s address: want %q got %q", w.Host, w.Upstream.Address, g.Upstream.Address)
		}
		if !sameAuthPosture(w.Upstream.Auth, g.Upstream.Auth) {
			return fmt.Errorf("host %s auth: want %q got %q", w.Host, w.Upstream.Auth, g.Upstream.Auth)
		}
		if g.Upstream.UpstreamTLS != w.Upstream.UpstreamTLS {
			return fmt.Errorf("host %s upstream-tls: want %v got %v", w.Host, w.Upstream.UpstreamTLS, g.Upstream.UpstreamTLS)
		}
	}
	return nil
}

// sameAuthPosture compares two auth values for durability equality. The durable
// question is whether auth is ENFORCED, not whether the exact policy NAME round-trips:
// crenel's LIVE managed route carries the policy name (its vars marker), but the on-disk
// `import <snippet>` re-adapts to the canonical forward-auth gate that reads back as
// AuthDetected (a recognized hand-built gate, name not recovered) — legitimately the
// SAME posture. So a real policy name and AuthDetected both count as enforced; only ""
// and the explicit AuthNone are unprotected. A managed route that is protected live but
// reads UNPROTECTED on disk (auth dropped) is the real drift this catches.
func sameAuthPosture(live, disk string) bool {
	enforced := func(s string) bool { return s != "" && s != model.AuthNone }
	return enforced(live) == enforced(disk)
}

// flatRegionHasHosts is the host-presence fallback self-check for the flat top-level
// region (whose render is `host { … }` site blocks, not @host/handle pairs).
func flatRegionHasHosts(candidate string, flat []model.Route) error {
	region, ok := extractRegion(candidate)
	if !ok {
		return fmt.Errorf("flat region missing")
	}
	for _, r := range flat {
		if !strings.Contains(region, r.Host+" {") {
			return fmt.Errorf("host %s missing from flat region", r.Host)
		}
	}
	return nil
}
