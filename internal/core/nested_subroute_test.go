package core_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

// nestedFixture is the shared faithful mirror of the real VPS nested-subroute edge
// (two wildcard zones, mixed managed/unmanaged per-host leaves, one with auth).
const nestedFixture = "../drivers/edge/caddy/testdata/nested-subroute-prod.json"

// TestNestedSubroute_StatusImportAudit is the core-level proof that the recursion
// fix makes status/import/audit work at SERVICE granularity on the real nested
// edge shape — the central misread the read-only trial surfaced (~25 services
// collapsing to 2 wildcards; import a no-op; audit blind).
func TestNestedSubroute_StatusImportAudit(t *testing.T) {
	ctx := context.Background()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	seed, err := os.ReadFile(nestedFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.SeedJSON(string(seed)); err != nil {
		t.Fatal(err)
	}

	// Origins mirror the trial: per-host Tailscale dials. cloud's configured backend
	// differs from the live leaf dial (a deliberate origin conflict).
	origins := map[string]string{
		"vault":  "100.100.0.10:8200",
		"git":    "100.100.0.11:3000",
		"photos": "100.100.0.12:2342",
		"jelly":  "100.100.0.13:8096",
		"cloud":  "100.100.0.14:80",
	}
	edge := core.EdgeBinding{
		Name:     "vps",
		Provider: caddy.New(fake.URL(), static.New(origins), caddy.WithGranularApply()),
		Fronts:   frontsFor(origins),
	}
	// zone homelab.example: the *.smallbiz.example leaves are out of the single-zone
	// managed domain (the two-zone gap, documented as follow-on) — they are still
	// ENUMERATED in status but not adoptable.
	e := core.NewMulti([]core.EdgeBinding{edge}, "homelab.example")

	// --- status: enumerates the real per-host services, not 2 opaque wildcards. ---
	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	es := st.Edges[0]
	if !es.DenyCatchAllPresent {
		t.Fatal("status: default-deny must read PRESENT on the nested edge")
	}
	got := map[string]bool{}
	for _, r := range es.Routes {
		got[r.Host] = true
	}
	for _, h := range []string{
		"jelly.homelab.example", "vault.homelab.example", "git.homelab.example",
		"photos.homelab.example", "cloud.homelab.example", "status.smallbiz.example",
	} {
		if !got[h] {
			t.Errorf("status should enumerate per-host service %s; got %v", h, keysOf(got))
		}
	}
	if got["*.homelab.example"] || got["*.smallbiz.example"] {
		t.Errorf("status should not surface opaque wildcards: %v", keysOf(got))
	}

	// --- import --dry-run: SEES the adoptable per-host routes (service ∈ origins,
	// backend matches), flags the origin conflict, and recognizes already-managed —
	// while refusing the second-zone leaf (out of single-zone domain). ---
	plan, err := e.DetectImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adopt := map[string]bool{}
	for _, a := range plan.Adopt {
		adopt[a.Host] = true
	}
	if !adopt["vault.homelab.example"] || !adopt["photos.homelab.example"] {
		t.Errorf("vault+photos should be adoptable, got %+v", plan.Adopt)
	}
	if len(plan.Adopt) != 2 {
		t.Errorf("exactly vault+photos adoptable, got %d: %+v", len(plan.Adopt), plan.Adopt)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Host != "cloud.homelab.example" || plan.Conflicts[0].Reason != "origin_mismatch" {
		t.Errorf("cloud should be the lone origin_mismatch conflict, got %+v", plan.Conflicts)
	}
	already := map[string]bool{}
	for _, h := range plan.AlreadyManaged {
		already[h] = true
	}
	if !already["jelly.homelab.example"] || !already["git.homelab.example"] {
		t.Errorf("jelly+git already managed, got %v", plan.AlreadyManaged)
	}
	for _, a := range plan.Adopt {
		if a.Host == "status.smallbiz.example" {
			t.Error("second-zone leaf is out of the single-zone domain; must never be adoptable")
		}
	}

	// --- audit: warns public_without_auth only where appropriate (the auth-bearing
	// photos leaf is excluded; the no-auth leaves warn). default-deny holds. ---
	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.HasCritical() {
		t.Fatalf("nested edge must not produce a critical finding: %+v", rep.Findings)
	}
	warnedNoAuth := map[string]bool{}
	denyOK := false
	for _, f := range rep.Findings {
		switch f.Code {
		case "public_without_auth":
			warnedNoAuth[hostInMessage(f.Message)] = true
		case "deny_catchall_present":
			denyOK = true
		}
	}
	if !denyOK {
		t.Error("audit should report deny_catchall_present")
	}
	if !warnedNoAuth["vault.homelab.example"] || !warnedNoAuth["git.homelab.example"] {
		t.Errorf("audit should warn public_without_auth on the no-auth leaves, got %v", keysOf(warnedNoAuth))
	}
	if warnedNoAuth["photos.homelab.example"] {
		t.Error("audit must NOT warn public_without_auth on the auth-bearing photos leaf")
	}
}

// TestNestedSubroute_AsDownstreamAuthFrontEdge is the faithful end-to-end trial
// topology: the nested VPS edge is the FRONT of a chain (auth enforced one hop
// downstream at the home edge), so it carries no auth itself. With auth_downstream
// set, audit must NOT spuriously warn public_without_auth on the no-auth leaves,
// and status must label them `auth: downstream` — while the auth-bearing photos
// leaf keeps its recognized auth.
func TestNestedSubroute_AsDownstreamAuthFrontEdge(t *testing.T) {
	ctx := context.Background()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	seed, err := os.ReadFile(nestedFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.SeedJSON(string(seed)); err != nil {
		t.Fatal(err)
	}
	origins := map[string]string{
		"vault": "100.100.0.10:8200", "git": "100.100.0.11:3000",
		"photos": "100.100.0.12:2342", "jelly": "100.100.0.13:8096", "cloud": "100.100.0.14:80",
	}
	edge := core.EdgeBinding{
		Name:           "vps",
		Provider:       caddy.New(fake.URL(), static.New(origins), caddy.WithGranularApply()),
		Fronts:         frontsFor(origins),
		AuthDownstream: true, // front edge: auth lives at the downstream home edge
	}
	e := core.NewMulti([]core.EdgeBinding{edge}, "homelab.example")

	rep, err := e.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Code == "public_without_auth" {
			t.Errorf("front edge must not warn public_without_auth: %q", f.Message)
		}
	}
	if _, ok := findCode(rep, "auth_downstream"); !ok {
		t.Errorf("expected an auth_downstream informational finding, got %+v", rep.Findings)
	}

	st, err := e.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{}
	for _, r := range st.Edges[0].Routes {
		auth[r.Host] = r.Upstream.Auth
	}
	if auth["vault.homelab.example"] != "downstream" {
		t.Errorf("vault should be labeled auth: downstream, got %q", auth["vault.homelab.example"])
	}
	// photos has a recognized hand-built auth handler -> keeps its own recognition.
	if auth["photos.homelab.example"] != "(detected)" {
		t.Errorf("photos should keep its recognized auth, got %q", auth["photos.homelab.example"])
	}
}

// keysOf returns a set's keys (test diagnostics only).
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// hostInMessage extracts the "host X is PUBLIC" hostname from a public_without_auth
// message ("host <h> is PUBLIC with no forward-auth policy ...").
func hostInMessage(msg string) string {
	const pre = "host "
	i := strings.Index(msg, pre)
	if i < 0 {
		return ""
	}
	return strings.Fields(msg[i+len(pre):])[0]
}
