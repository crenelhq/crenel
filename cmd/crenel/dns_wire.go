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
		p, err := buildDNSProvider(s, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func buildDNSProvider(s config.Settings, spec config.DNSProviderSettings) (ports.DNSProvider, error) {
	scope := model.ScopeInternal
	if spec.Scope == string(model.ScopePublic) {
		scope = model.ScopePublic
	}
	zone := spec.Zone
	if zone == "" {
		zone = s.Zone
	}

	switch strings.ToLower(spec.Type) {
	case "", "mock", "dnscontrol":
		cfg := dnscontrol.Config{ZoneName: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, DedicatedZone: spec.DedicatedZone}
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
				ZoneName: zone,
				ZoneID:   spec.ZoneID,
				Scope:    scope,
				EdgeAddr: spec.EdgeAddr,
				Proxied:  spec.Proxied,
				TTL:      spec.TTL,
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
		cfg := dnscontrol.Config{ZoneName: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, DedicatedZone: spec.DedicatedZone}
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
		acfg := adguard.Config{Zone: zone, Scope: scope, EdgeAddr: spec.EdgeAddr, Instance: spec.Instance}
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

	default:
		return nil, fmt.Errorf("dns provider (zone %q): unknown type %q (want mock|cloudflare|adguard)", zone, spec.Type)
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
