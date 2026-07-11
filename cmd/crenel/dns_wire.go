package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol"
	"github.com/crenelhq/crenel/internal/drivers/dns/dnscontrol/dnscontrolfake"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole/piholefake"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// buildDNS constructs DNS providers from settings. DNS is opt-in (disabled by
// default). When enabled, each provider is dispatched on its `type`:
//
//   - "" / "mock" / "dnscontrol": the dnscontrol adapter (the mock fake when mock is
//     set — the safe demo path).
//   - "cloudflare": the dnscontrol adapter with the real CLOUDFLAREAPI provider, for
//     the PUBLIC authoritative zone. Shells out to the real dnscontrol binary unless
//     mock is set.
//   - "adguard": the native AdGuard Home control-API driver, for the INTERNAL resolver
//     rewrites. Talks real HTTP unless mock is set.
//   - "pihole": the native Pi-hole v6 API driver, for the INTERNAL resolver's Local
//     DNS host entries (session auth by password only — no username). Talks real HTTP
//     unless mock is set.
//
// Credentials are NEVER hardcoded: an env-var reference (*_env) is read at wiring time
// (the secret never lands on disk); a literal is accepted but redacted at every output
// boundary. A real provider whose credential resolves empty fails the build loudly
// rather than sending an unauthenticated request. See docs/DNS-DESIGN.md §4/§7.
//
// When DNS.Providers is non-empty, one provider is built per entry (M3: internal
// AdGuard !inside + public Cloudflare !outside managed together). Otherwise a single
// provider is built from the top-level DNS fields (back-compat).
func buildDNS(s config.Settings) ([]ports.DNSProvider, error) {
	if !s.DNS.Enabled {
		return nil, nil
	}
	specs := s.DNS.Providers
	if len(specs) == 0 {
		// Back-compat: the single top-level provider.
		specs = []config.DNSProviderSettings{{
			Type:          s.DNS.Type,
			Scope:         s.DNS.Scope,
			Zone:          s.DNS.Zone,
			EdgeAddr:      s.DNS.EdgeAddr,
			Targets:       s.DNS.Targets,
			Mock:          s.DNS.Mock,
			DedicatedZone: s.DNS.DedicatedZone,
			ApplyMode:     s.DNS.ApplyMode,
			ZoneID:        s.DNS.ZoneID,
			Proxied:       s.DNS.Proxied,
			TTL:           s.DNS.TTL,
			APIToken:      s.DNS.APIToken,
			APITokenEnv:   s.DNS.APITokenEnv,
			Endpoint:      s.DNS.Endpoint,
			Username:      s.DNS.Username,
			Password:      s.DNS.Password,
			PasswordEnv:   s.DNS.PasswordEnv,
		}}
	}
	var out []ports.DNSProvider
	for _, spec := range specs {
		ps, err := buildDNSProviders(s, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}

// zoneExpansion carries the cross-zone SHARED state of one `zones:`-list provider
// entry while buildDNSProviders expands it into per-zone driver instances. The
// drivers themselves stay strictly zone-confined (their battle-tested shape);
// what the zones should share is shared here instead:
//
//   - multi: the entry declares 2+ zones — weave each instance's zone into its
//     display name so labels never collide as N identical "adguard[home]" lines.
//     A single-zone entry (or a plain `zone:`) leaves names byte-identical.
//   - pihole: the ONE session-authenticated channel reused by every zone's
//     driver instance. Pi-hole sessions are a finite server-side seat pool and
//     the endpoint/credential are identical across the expansion, so N drivers
//     doing N logins against the same box would be pure waste; OSDoer is
//     mutex-guarded, making the shared pointer safe under concurrent calls.
//     (adguard is stateless Basic-auth and cloudflare a stateless bearer token —
//     nothing to share there beyond the copied config values.)
type zoneExpansion struct {
	multi  bool
	pihole *pihole.OSDoer
}

// buildDNSProviders expands one provider entry into its driver instance(s): one
// zone-confined instance per declared zone. `zones: [a]` ≡ `zone: a`; setting
// both fields is refused loudly (never a silent precedence pick), as are
// empty and duplicate list entries.
func buildDNSProviders(s config.Settings, spec config.DNSProviderSettings) ([]ports.DNSProvider, error) {
	zones := spec.Zones
	if len(zones) > 0 && spec.Zone != "" {
		return nil, fmt.Errorf("dns provider %s: set `zone` OR `zones`, not both (zone %q vs zones %v) — `zones` alone declares every managed zone", spec.Type, spec.Zone, spec.Zones)
	}
	if len(zones) == 0 {
		// The single-zone shape, unchanged ("" defaults to the top-level zone below).
		zones = []string{spec.Zone}
	} else {
		seen := map[string]bool{}
		for _, z := range zones {
			key := strings.ToLower(strings.TrimSpace(z))
			if key == "" {
				return nil, fmt.Errorf("dns provider %s: `zones` contains an empty entry — every managed zone must be named explicitly", spec.Type)
			}
			if seen[key] {
				return nil, fmt.Errorf("dns provider %s: `zones` lists %q twice", spec.Type, key)
			}
			seen[key] = true
		}
		// A pinned Cloudflare zone_id names exactly ONE zone — it cannot apply to a
		// multi-zone list (each expanded zone resolves its own id by name instead).
		if len(zones) > 1 && spec.ZoneID != "" {
			return nil, fmt.Errorf("dns provider %s: `zone_id` pins a single zone and cannot be combined with a multi-entry `zones` list — drop it (ids resolve per zone by name)", spec.Type)
		}
	}
	exp := &zoneExpansion{multi: len(zones) > 1}
	var out []ports.DNSProvider
	for _, z := range zones {
		one := spec // copy: same endpoint/creds/instance/targets — ONLY the zone differs
		one.Zone = z
		one.Zones = nil
		p, err := buildDNSProvider(s, one, exp)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func buildDNSProvider(s config.Settings, spec config.DNSProviderSettings, exp *zoneExpansion) (ports.DNSProvider, error) {
	scope := model.ScopeInternal
	if spec.Scope == string(model.ScopePublic) {
		scope = model.ScopePublic
	}
	zone := spec.Zone
	if zone == "" {
		zone = s.Zone
	}

	// Residency targets (per-class vantage answers, REFERENCE-ARCH §2) are an
	// INTERNAL-resolver capability: only adguard/pihole resolve them. Refusing them
	// on any other type here keeps the never-silently-ignore-config rule — a
	// `targets:` block on a public/whole-zone provider would otherwise be dead
	// config the operator believes is live.
	switch t := strings.ToLower(spec.Type); t {
	case "adguard", "pihole":
		// supported — plumbed into the driver config below.
	default:
		if len(spec.Targets) > 0 {
			return nil, fmt.Errorf("dns provider %s (zone %q): `targets` (residency classes) is only supported on internal resolver types adguard|pihole — the public answer is class-invariant (edge_addr)", t, zone)
		}
	}

	switch strings.ToLower(spec.Type) {
	case "", "mock", "dnscontrol":
		cfg := dnscontrol.Config{ZoneName: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, DedicatedZone: spec.DedicatedZone, ZoneInName: exp.multi}
		if spec.Mock || strings.EqualFold(spec.Type, "mock") {
			// Safe demo: in-process fake shell, never touches real DNS.
			cfg.Shell = dnscontrolfake.New(zone)
		}
		return dnscontrol.New(cfg), nil

	case "cloudflare":
		// apply_mode selects the apply PATH for Cloudflare: surgical per-record CRUD via
		// the native REST API (safe on a SHARED zone — touches only owned records), or the
		// legacy whole-zone dnscontrol push (requires dedicated_zone). See docs/DNS-DESIGN.md.
		if surgicalMode(spec.ApplyMode) {
			ccfg := cloudflare.Config{
				ZoneName:   zone,
				ZoneInName: exp.multi,
				ZoneID:     spec.ZoneID,
				Scope:      scope,
				EdgeAddr:   spec.EdgeAddr,
				Proxied:    spec.Proxied,
				TTL:        spec.TTL,
			}
			if spec.Mock {
				// Safe demo: in-process fake Cloudflare API, no real token needed.
				ccfg.Doer = cfapifake.New(zone, spec.ZoneID)
				return cloudflare.New(ccfg), nil
			}
			token := resolveSecret(spec.APIToken, spec.APITokenEnv)
			if token == "" {
				return nil, fmt.Errorf("dns provider cloudflare/surgical (zone %q): missing API token — set api_token_env (preferred) or api_token", zone)
			}
			ccfg.Doer = cloudflare.OSDoer{Token: token}
			return cloudflare.New(ccfg), nil
		}
		cfg := dnscontrol.Config{ZoneName: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, DedicatedZone: spec.DedicatedZone, ZoneInName: exp.multi}
		if spec.Mock {
			// Safe demo: in-process fake shell, no real token needed.
			cfg.Shell = dnscontrolfake.New(zone)
			return dnscontrol.New(cfg), nil
		}
		token := resolveSecret(spec.APIToken, spec.APITokenEnv)
		if token == "" {
			return nil, fmt.Errorf("dns provider cloudflare (zone %q): missing API token — set api_token_env (preferred) or api_token", zone)
		}
		cfg.Provider = dnscontrol.Provider{
			CredsKey: "cloudflare",
			Type:     "CLOUDFLAREAPI",
			Creds:    map[string]string{"apitoken": token},
		}
		return dnscontrol.New(cfg), nil

	case "adguard":
		if scope == model.ScopePublic {
			return nil, fmt.Errorf("dns provider adguard (zone %q): scope must be internal — AdGuard is a resolver, never public-authoritative", zone)
		}
		acfg := adguard.Config{Zone: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, Targets: spec.Targets, Instance: spec.Instance, ZoneInName: exp.multi}
		if spec.Mock {
			// Safe demo: in-process fake control API, no real endpoint needed.
			acfg.Doer = adguardfake.New()
			return adguard.New(acfg), nil
		}
		if spec.Endpoint == "" {
			return nil, fmt.Errorf("dns provider adguard (zone %q): missing endpoint (the AdGuard control API base URL)", zone)
		}
		// Fail fast on a missing control credential (parity with the cloudflare check):
		// a referenced-but-unset env var, or no credential at all, would send an
		// UNAUTHENTICATED request — which a permissive AdGuard/front-proxy could act on.
		password := resolveSecret(spec.Password, spec.PasswordEnv)
		if spec.PasswordEnv != "" && password == "" {
			return nil, fmt.Errorf("dns provider adguard (zone %q): password_env %q is not set", zone, spec.PasswordEnv)
		}
		if spec.Username == "" && password == "" {
			return nil, fmt.Errorf("dns provider adguard (zone %q): missing control credentials — set username + password_env (preferred) or password", zone)
		}
		acfg.Doer = adguard.OSDoer{
			BaseURL:  spec.Endpoint,
			Username: spec.Username,
			Password: password,
		}
		return adguard.New(acfg), nil

	case "pihole":
		if scope == model.ScopePublic {
			return nil, fmt.Errorf("dns provider pihole (zone %q): scope must be internal — Pi-hole is a resolver, never public-authoritative", zone)
		}
		pcfg := pihole.Config{Zone: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, Targets: spec.Targets, Instance: spec.Instance, ZoneInName: exp.multi}
		if spec.Mock {
			// Safe demo: in-process fake v6 API, no real endpoint needed.
			pcfg.Doer = piholefake.New()
			return pihole.New(pcfg), nil
		}
		if spec.Endpoint == "" {
			return nil, fmt.Errorf("dns provider pihole (zone %q): missing endpoint (the Pi-hole v6 API base URL)", zone)
		}
		// Fail fast on a missing API password (parity with the adguard/cloudflare
		// checks): a referenced-but-unset env var, or no credential at all, would send
		// an UNAUTHENTICATED request. Pi-hole v6 auth is session-by-password only — no
		// username, so password alone is the credential.
		password := resolveSecret(spec.Password, spec.PasswordEnv)
		if spec.PasswordEnv != "" && password == "" {
			return nil, fmt.Errorf("dns provider pihole (zone %q): password_env %q is not set", zone, spec.PasswordEnv)
		}
		if password == "" {
			return nil, fmt.Errorf("dns provider pihole (zone %q): missing API password — set password_env (preferred) or password", zone)
		}
		// A `zones:`-list expansion shares ONE session channel across its per-zone
		// instances (same endpoint, same credential): the first zone builds it, the
		// rest reuse it — one login instead of N against the same finite seat pool.
		if exp.pihole == nil {
			exp.pihole = &pihole.OSDoer{BaseURL: spec.Endpoint, Password: password}
		}
		pcfg.Doer = exp.pihole
		return pihole.New(pcfg), nil

	default:
		return nil, fmt.Errorf("dns provider (zone %q): unknown type %q (want mock|dnscontrol|cloudflare|adguard|pihole)", zone, spec.Type)
	}
}

// surgicalMode reports whether the cloudflare provider should use the native REST API
// per-record path. "surgical"/"record" select it; ""/"whole-zone" keep the legacy push.
func surgicalMode(applyMode string) bool {
	switch strings.ToLower(strings.TrimSpace(applyMode)) {
	case "surgical", "record", "record-level", "per-record":
		return true
	default:
		return false
	}
}

// resolveSecret returns a credential value, preferring an env-var REFERENCE over a
// literal: when envName is set the value is read from the environment (so the secret
// never lives in a config file); otherwise the literal is used. An unset referenced
// env var resolves empty, which the caller treats as a missing credential.
func resolveSecret(literal, envName string) string {
	if envName != "" {
		return os.Getenv(envName)
	}
	return literal
}
