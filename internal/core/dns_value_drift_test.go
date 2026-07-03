package core_test

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare"
	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// dns_value_drift: a crenel-OWNED DNS record whose live value diverged from what crenel
// would set (DesiredRecords) is a silent misdirect — the name resolves, every name-only
// check reads clean, but it points at the WRONG target. Audit value-checks owned records
// (via ports.OwnedRecordReporter, which the surgical Cloudflare driver implements because
// its LiveRecords are marker-filtered) and never cries wolf on a marker-less provider.

func cfDriftEngine(t *testing.T, fake *cfapifake.Server) *core.Engine {
	t.Helper()
	drv := cloudflare.New(cloudflare.Config{
		ZoneName: "crenel.sh", ZoneID: "zone1", Scope: model.ScopePublic,
		EdgeAddr: "203.0.113.9", Doer: fake,
	})
	cfake := caddyfake.New()
	t.Cleanup(cfake.Close)
	cfake.SeedCaddyfile(seedGrafana)
	edge := caddy.New(cfake.URL(), static.New(map[string]string{"grafana": "10.0.0.5:3000"}))
	return core.New(edge, "example.com", []ports.DNSProvider{drv}...)
}

// TestAudit_DNSValueDrift_OwnedRecordDriftIsCritical is the RED→GREEN headline: a
// crenel-owned (marked) public record pointing at 203.0.113.99 while the configured edge
// is 203.0.113.9 must surface as a CRITICAL drift — the public name misdirects traffic.
func TestAudit_DNSValueDrift_OwnedRecordDriftIsCritical(t *testing.T) {
	fake := cfapifake.New("crenel.sh", "zone1", cfapifake.Record{
		Type: "A", Name: "app.crenel.sh", Content: "203.0.113.99", // DRIFTED target
		Comment: cloudflare.MarkerPrefix + " host=app", // crenel-owned
	})
	rep, err := cfDriftEngine(t, fake).Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findCode(rep, "dns_value_drift")
	if !ok || f.Severity != "critical" {
		t.Fatalf("expected critical dns_value_drift for a public owned record, got %+v", rep.Findings)
	}
	if !strings.Contains(f.Message, "app.crenel.sh") ||
		!strings.Contains(f.Message, "203.0.113.99") || // the wrong live target
		!strings.Contains(f.Message, "203.0.113.9") { // the configured target
		t.Errorf("drift message should name the host, the wrong value, and the desired value: %q", f.Message)
	}
}

// TestAudit_DNSValueDrift_CorrectValueNoFinding: an owned record already at the configured
// edge value is clean — no drift finding.
func TestAudit_DNSValueDrift_CorrectValueNoFinding(t *testing.T) {
	fake := cfapifake.New("crenel.sh", "zone1", cfapifake.Record{
		Type: "A", Name: "app.crenel.sh", Content: "203.0.113.9", // matches EdgeAddr
		Comment: cloudflare.MarkerPrefix + " host=app",
	})
	rep, err := cfDriftEngine(t, fake).Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_value_drift"); ok {
		t.Errorf("owned record is at the configured target; no drift expected, got %q", f.Message)
	}
}

// TestAudit_DNSValueDrift_MarkerlessProviderNoCryWolf proves the scoping: a provider that
// does NOT implement ports.OwnedRecordReporter (it cannot prove a record is its own — the
// AdGuard case) is never value-checked, so a legitimately-foreign record whose value
// differs from the provider's DesiredRecords does NOT raise a false drift. stubDNS's
// DesiredRecords returns 1.2.3.4; its live record is 9.9.9.9 — and stays silent.
func TestAudit_DNSValueDrift_MarkerlessProviderNoCryWolf(t *testing.T) {
	markerless := &stubDNS{name: "adguard[home]", scope: model.ScopeInternal, live: []model.Record{
		{Name: "vault.example.com", Type: "A", Value: "9.9.9.9", Scope: model.ScopeInternal},
	}}
	// Guard the premise: stubDNS must NOT implement the ownership capability.
	if _, ok := ports.DNSProvider(markerless).(ports.OwnedRecordReporter); ok {
		t.Fatal("test premise broken: stubDNS must not implement OwnedRecordReporter")
	}
	e := auditEngine(t, seedGrafana, markerless)
	rep, err := e.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findCode(rep, "dns_value_drift"); ok {
		t.Errorf("a marker-less provider must not raise value drift (no cry-wolf), got %q", f.Message)
	}
}
