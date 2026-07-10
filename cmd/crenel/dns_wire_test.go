package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/redact"
)

func dnsSettings(providers ...config.DNSProviderSettings) config.Settings {
	return config.Settings{Zone: "example.com", DNS: config.DNSSettings{Enabled: true, Providers: providers}}
}

func TestBuildDNSDisabledIsNil(t *testing.T) {
	got, err := buildDNS(config.Settings{DNS: config.DNSSettings{Enabled: false}})
	if err != nil || got != nil {
		t.Fatalf("disabled DNS should yield (nil, nil), got (%v, %v)", got, err)
	}
}

func TestBuildDNSDispatchCloudflare(t *testing.T) {
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "cloudflare", Scope: "public", EdgeAddr: "203.0.113.5", Zone: "example.com",
		APIToken: "literal-token-value",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name() != "dnscontrol" || ps[0].Scope() != model.ScopePublic {
		t.Fatalf("expected one public dnscontrol provider, got %+v", ps)
	}
}

func TestBuildDNSDispatchAdguard(t *testing.T) {
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", EdgeAddr: "10.0.0.13",
		Endpoint: "http://10.0.0.53:3000", Username: "admin", Password: "pw",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name() != "adguard" || ps[0].Scope() != model.ScopeInternal {
		t.Fatalf("expected one internal adguard provider, got %+v", ps)
	}
}

func TestBuildDNSMockDefault(t *testing.T) {
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{Type: "mock", Scope: "internal", EdgeAddr: "10.0.0.1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name() != "dnscontrol" {
		t.Fatalf("mock should build a dnscontrol provider, got %+v", ps)
	}
}

func TestBuildDNSCloudflareMissingTokenErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{Type: "cloudflare", Scope: "public", EdgeAddr: "203.0.113.5"}))
	if err == nil || !strings.Contains(err.Error(), "missing API token") {
		t.Fatalf("expected missing-token error, got %v", err)
	}
}

func TestBuildDNSAdguardMissingEndpointErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{Type: "adguard", Scope: "internal", EdgeAddr: "10.0.0.13"}))
	if err == nil || !strings.Contains(err.Error(), "missing endpoint") {
		t.Fatalf("expected missing-endpoint error, got %v", err)
	}
}

// Parity with the cloudflare missing-credential check: an adguard provider with no
// usable control credential must fail the build, never send an unauthenticated request.
func TestBuildDNSAdguardMissingCredsErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", EdgeAddr: "10.0.0.13", Endpoint: "http://x:3000",
	}))
	if err == nil || !strings.Contains(err.Error(), "missing control credentials") {
		t.Fatalf("expected missing-creds error, got %v", err)
	}
}

func TestBuildDNSAdguardPasswordEnvUnsetErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "adguard", Scope: "internal", EdgeAddr: "10.0.0.13", Endpoint: "http://x:3000",
		Username: "admin", PasswordEnv: "CRENEL_TEST_AG_PW_UNSET",
	}))
	if err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("expected env-unset error, got %v", err)
	}
}

func TestBuildDNSAdguardPublicScopeRejected(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "adguard", Scope: "public", EdgeAddr: "10.0.0.13", Endpoint: "http://x:3000",
	}))
	if err == nil || !strings.Contains(err.Error(), "scope must be internal") {
		t.Fatalf("expected public-scope rejection, got %v", err)
	}
}

func TestBuildDNSDispatchPihole(t *testing.T) {
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "pihole", Scope: "internal", EdgeAddr: "10.0.0.13", Instance: "vps",
		Endpoint: "http://10.0.0.54:8080", Password: "pw",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name() != "pihole[vps]" || ps[0].Scope() != model.ScopeInternal {
		t.Fatalf("expected one internal pihole[vps] provider, got %+v", ps)
	}
}

func TestBuildDNSPiholeMissingEndpointErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{Type: "pihole", Scope: "internal", EdgeAddr: "10.0.0.13"}))
	if err == nil || !strings.Contains(err.Error(), "missing endpoint") {
		t.Fatalf("expected missing-endpoint error, got %v", err)
	}
}

// Parity with the adguard/cloudflare missing-credential checks: a pihole provider
// with no API password must fail the build, never send an unauthenticated request.
func TestBuildDNSPiholeMissingPasswordErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "pihole", Scope: "internal", EdgeAddr: "10.0.0.13", Endpoint: "http://x:8080",
	}))
	if err == nil || !strings.Contains(err.Error(), "missing API password") {
		t.Fatalf("expected missing-password error, got %v", err)
	}
}

func TestBuildDNSPiholePasswordEnvUnsetErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "pihole", Scope: "internal", EdgeAddr: "10.0.0.13", Endpoint: "http://x:8080",
		PasswordEnv: "CRENEL_TEST_PH_PW_UNSET",
	}))
	if err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("expected env-unset error, got %v", err)
	}
}

func TestBuildDNSPiholePublicScopeRejected(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "pihole", Scope: "public", EdgeAddr: "10.0.0.13", Endpoint: "http://x:8080", Password: "pw",
	}))
	if err == nil || !strings.Contains(err.Error(), "scope must be internal") {
		t.Fatalf("expected public-scope rejection, got %v", err)
	}
}

func TestBuildDNSPiholeMockNeedsNoCreds(t *testing.T) {
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "pihole", Scope: "internal", EdgeAddr: "10.0.0.13", Mock: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name() != "pihole" {
		t.Fatalf("mock pihole should build without creds, got %+v", ps)
	}
}

func TestBuildDNSUnknownTypeErrors(t *testing.T) {
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{Type: "route53", Scope: "public"}))
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("expected unknown-type error, got %v", err)
	}
}

// Env-var REFERENCE is preferred over a literal: the token never lives in the config
// file. A set env var resolves; an unset one is treated as a missing credential.
func TestBuildDNSCloudflareEnvRef(t *testing.T) {
	t.Setenv("CRENEL_TEST_CF_TOKEN", "from-env")
	ps, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "cloudflare", Scope: "public", EdgeAddr: "203.0.113.5", APITokenEnv: "CRENEL_TEST_CF_TOKEN",
	}))
	if err != nil || len(ps) != 1 {
		t.Fatalf("env-ref token should build a provider, got (%v, %v)", ps, err)
	}
}

func TestBuildDNSCloudflareEnvRefUnsetErrors(t *testing.T) {
	// The referenced env var is not set -> missing credential.
	_, err := buildDNS(dnsSettings(config.DNSProviderSettings{
		Type: "cloudflare", Scope: "public", EdgeAddr: "203.0.113.5", APITokenEnv: "CRENEL_TEST_CF_TOKEN_UNSET",
	}))
	if err == nil || !strings.Contains(err.Error(), "missing API token") {
		t.Fatalf("expected missing-token error when env var unset, got %v", err)
	}
}

// A literal credential in config is accepted but must be REDACTED at every output
// boundary (its JSON key is in redact.secretKeyParts). This proves the new credential
// fields inherit the secret-redaction pattern.
func TestDNSProviderSettingsSecretsRedacted(t *testing.T) {
	spec := config.DNSProviderSettings{
		Type: "cloudflare", Scope: "public",
		APIToken: "cf-supersecret-token-AAAA",
		Password: "adguard-supersecret-pw-BBBB",
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	out := redact.Snippet(string(raw))
	if strings.Contains(out, "cf-supersecret-token-AAAA") {
		t.Errorf("api_token must be redacted in output: %s", out)
	}
	if strings.Contains(out, "adguard-supersecret-pw-BBBB") {
		t.Errorf("password must be redacted in output: %s", out)
	}
	if !strings.Contains(out, "••••") {
		t.Errorf("expected masked values in redacted output: %s", out)
	}
}
