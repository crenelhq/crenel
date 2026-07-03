package caddyfake_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
)

// wildcardSeed is a faithful mirror of the real edge shape: per-host routing lives
// INSIDE a *.zone wildcard subroute, never flat at the top level.
const wildcardSeed = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	{"match":[{"host":["*.homelab.example"]}],"handle":[{"handler":"subroute","routes":[
		{"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}]},
	{"match":[{"host":["*.smallbiz.example"]}],"handle":[{"handler":"subroute","routes":[
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}]}
]}}}}}`

func do(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// topLevelRoutes returns the count of routes in srv0.routes[] and the inner routes of
// the first top-level route's subroute handler (the *.homelab.example zone).
func zoneShape(t *testing.T, fake *caddyfake.Fake) (topN int, innerN int) {
	t.Helper()
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []struct {
							Handler string           `json:"handler"`
							Routes  []map[string]any `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(fake.CurrentJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.Apps.HTTP.Servers["srv0"]
	topN = len(srv.Routes)
	if topN > 0 && len(srv.Routes[0].Handle) > 0 {
		innerN = len(srv.Routes[0].Handle[0].Routes)
	}
	return topN, innerN
}

// TestFake_NestedInsertAndGlobalID proves the fake faithfully models real Caddy's
// path-addressed nested PUT and GLOBAL @id index: a per-host route PUT into a wildcard
// subroute lands at that depth (top-level count unchanged), is readable + deletable by
// its @id from there, and the config restores byte-for-byte after the nested delete.
func TestFake_NestedInsertAndGlobalID(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(wildcardSeed); err != nil {
		t.Fatal(err)
	}
	before := fake.CurrentJSON()

	topN, innerN := zoneShape(t, fake)
	if topN != 2 || innerN != 2 {
		t.Fatalf("seed shape wrong: top=%d inner=%d", topN, innerN)
	}

	// NESTED insert at routes/0/handle/0/routes/0 (front of the *.homelab.example zone).
	route := `{"@id":"crenel-route-vault.homelab.example","match":[{"host":["vault.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.7:8200"}]}]}`
	if code, msg := do(t, http.MethodPut, fake.URL()+"/config/apps/http/servers/srv0/routes/0/handle/0/routes/0", route); code != http.StatusOK {
		t.Fatalf("nested PUT failed: %d %s", code, msg)
	}

	// It landed INSIDE the zone subroute (inner grew), NOT at the top level (top same).
	if topN, innerN := zoneShape(t, fake); topN != 2 || innerN != 3 {
		t.Fatalf("nested insert misplaced: top=%d (want 2) inner=%d (want 3)", topN, innerN)
	}
	if !strings.Contains(fake.CurrentJSON(), `"vault.homelab.example"`) {
		t.Fatal("nested route not present after insert")
	}

	// GLOBAL @id GET finds the nested route by id.
	code, body := do(t, http.MethodGet, fake.URL()+"/id/crenel-route-vault.homelab.example", "")
	if code != http.StatusOK || !strings.Contains(body, "10.0.0.7:8200") {
		t.Fatalf("GET /id of nested route failed: %d %s", code, body)
	}

	// GLOBAL @id DELETE removes it from the nested location → byte-for-byte restore.
	if code, msg := do(t, http.MethodDelete, fake.URL()+"/id/crenel-route-vault.homelab.example", ""); code != http.StatusOK {
		t.Fatalf("DELETE /id of nested route failed: %d %s", code, msg)
	}
	if fake.CurrentJSON() != before {
		t.Errorf("config not restored after nested delete\nbefore: %s\nafter:  %s", before, fake.CurrentJSON())
	}

	// A missing id is an idempotent 404.
	if code, _ := do(t, http.MethodDelete, fake.URL()+"/id/crenel-route-nope.homelab.example", ""); code != http.StatusNotFound {
		t.Errorf("missing id should be 404, got %d", code)
	}
}

// TestFake_RejectsSyntheticForwardAuthHandler REPRODUCES the live cross-chain trial
// abort: real Caddy PROVISIONS every handler in an inserted route and rejects an
// unknown module with "unknown module: http.handlers.<name>". crenel emitting a
// synthetic {"handler":"forward_auth"} aborted the trial at exactly this validation.
// The fake now models that rejection (it previously round-tripped the bogus handler,
// which is why the suite missed the bug). After the renderer fix crenel never emits
// it again — but this guard keeps the suite faithful to real Caddy forever.
func TestFake_RejectsSyntheticForwardAuthHandler(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(wildcardSeed); err != nil {
		t.Fatal(err)
	}
	// The exact shape crenel used to emit on the granular auth path.
	bogus := `{"@id":"crenel-route-x.homelab.example","match":[{"host":["x.homelab.example"]}],"handle":[` +
		`{"handler":"forward_auth","crenel_policy":"authelia","upstreams":[{"dial":"authelia:9080"}]},` +
		`{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.9:80"}]}]}`
	code, msg := do(t, http.MethodPut, fake.URL()+"/config/apps/http/servers/srv0/routes/0/handle/0/routes/0", bogus)
	if code != http.StatusInternalServerError {
		t.Fatalf("synthetic forward_auth must be REJECTED (500) like real Caddy, got %d: %s", code, msg)
	}
	if !strings.Contains(msg, "unknown module: http.handlers.forward_auth") {
		t.Errorf("rejection should mirror Caddy's unknown-module error, got: %s", msg)
	}
	// And it must not have mutated the config (atomic rejection, like real Caddy).
	if strings.Contains(fake.CurrentJSON(), "x.homelab.example") {
		t.Error("a rejected insert must leave the running config untouched")
	}
}

// TestFake_AcceptsCanonicalForwardAuthGate proves the COMPLEMENT: the VALID gate crenel
// now renders — a vars policy marker + a reverse_proxy with a handle_response subrequest
// (the shape Caddy's forward_auth directive compiles to) + the backend — is ACCEPTED by
// the faithful fake and lands at the nested location.
func TestFake_AcceptsCanonicalForwardAuthGate(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(wildcardSeed); err != nil {
		t.Fatal(err)
	}
	valid := `{"@id":"crenel-route-vault.homelab.example","match":[{"host":["vault.homelab.example"]}],"handle":[` +
		`{"handler":"vars","crenel_policy":"authelia"},` +
		`{"handler":"reverse_proxy","upstreams":[{"dial":"authelia:9080"}],` +
		`"handle_response":[{"match":{"status_code":[2]},"routes":[` +
		`{"handle":[{"handler":"vars"}]},` +
		`{"handle":[{"handler":"headers","request":{"delete":["Remote-User"]}}]}]}]},` +
		`{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.7:8200"}]}]}`
	code, msg := do(t, http.MethodPut, fake.URL()+"/config/apps/http/servers/srv0/routes/0/handle/0/routes/0", valid)
	if code != http.StatusOK {
		t.Fatalf("the canonical forward-auth gate (valid modules) must be ACCEPTED, got %d: %s", code, msg)
	}
	if !strings.Contains(fake.CurrentJSON(), "vault.homelab.example") || !strings.Contains(fake.CurrentJSON(), "handle_response") {
		t.Error("the valid gated route should have landed in the running config")
	}
}
