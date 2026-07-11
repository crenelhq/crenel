package caddy_test

// Trial finding F1 (TRIAL-RECORD-pihole-2026-07-10 §4): a full `POST /load` is a
// whole-config REPLACE, so a rendered Caddyfile with no `admin` global reverts a
// custom admin listener to Caddy's localhost default — silently cutting off the
// very socket crenel manages the edge through, mid-apply. These tests prove the
// guard: a listen-only custom admin block is CARRIED THROUGH the full-load render
// and read-back-verified; a richer admin block is REFUSED loudly; the default
// endpoint and the granular path are untouched.

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// seedWithAdmin is a minimal fully-parsed edge (one route + catch-all deny) whose
// admin block is the given JSON fragment (empty => no admin block).
func seedWithAdmin(t *testing.T, fake *caddyfake.Fake, adminJSON string) {
	t.Helper()
	admin := ""
	if adminJSON != "" {
		admin = `"admin":` + adminJSON + `,`
	}
	seed := `{` + admin + `"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
		{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:80"}]}]},
		{"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
}

// exposeGrafana plans a plain expose (the op every test applies).
func exposeGrafana(t *testing.T, d *caddy.Driver) model.ChangeSet {
	t.Helper()
	live, err := d.ReadLiveState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cs, err := d.Plan(model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana.example.com"}, live)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// TestFullLoad_CarriesCustomAdminListen proves the F1 fix: a live config whose
// admin block is a custom LISTEN-ONLY address survives a full-config load — the
// renderer emits the `{ admin <listen> }` global, the loaded config keeps the
// listener, and the route lands too.
func TestFullLoad_CarriesCustomAdminListen(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedWithAdmin(t, fake, `{"listen":"0.0.0.0:2019"}`)
	d := caddy.New(fake.URL(), resolver()) // full-load path

	if err := d.Apply(context.Background(), exposeGrafana(t, d)); err != nil {
		t.Fatalf("full-load with a listen-only custom admin block must carry it through, got %v", err)
	}
	if len(fake.Loads) != 1 || !strings.Contains(fake.Loads[0], "admin 0.0.0.0:2019") {
		t.Errorf("rendered Caddyfile must carry the admin global:\n%v", fake.Loads)
	}
	got := fake.CurrentJSON()
	if !strings.Contains(got, `"admin":{"listen":"0.0.0.0:2019"}`) {
		t.Errorf("custom admin listener must survive the full replace:\n%s", got)
	}
	if !strings.Contains(got, "grafana.example.com") {
		t.Errorf("the exposed route must land alongside the carried admin block:\n%s", got)
	}
}

// TestFullLoad_DefaultAdminUnaffected proves the guard changes nothing for the
// common case: no admin block (and, equivalently, an explicit default) renders no
// admin global and applies exactly as before.
func TestFullLoad_DefaultAdminUnaffected(t *testing.T) {
	for name, adminJSON := range map[string]string{
		"absent":          "",
		"explicitDefault": `{"listen":"localhost:2019"}`,
		"emptyObject":     `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := caddyfake.New()
			defer fake.Close()
			seedWithAdmin(t, fake, adminJSON)
			d := caddy.New(fake.URL(), resolver())

			if err := d.Apply(context.Background(), exposeGrafana(t, d)); err != nil {
				t.Fatalf("default-admin full-load must apply, got %v", err)
			}
			if len(fake.Loads) != 1 || strings.Contains(fake.Loads[0], "admin") {
				t.Errorf("no admin global must be rendered for a default admin endpoint:\n%v", fake.Loads)
			}
			if got := fake.CurrentJSON(); !strings.Contains(got, "grafana.example.com") {
				t.Errorf("route must land:\n%s", got)
			}
		})
	}
}

// TestFullLoad_RefusesRichAdminBlock proves the refusal half of the guard: an
// admin block carrying anything beyond a plain listen address (origins here) has
// no faithful Caddyfile rendering, so the full-load is refused LOUDLY — naming
// the fields at risk and the granular escape hatch — and live is untouched.
func TestFullLoad_RefusesRichAdminBlock(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedWithAdmin(t, fake, `{"listen":"0.0.0.0:2019","origins":["caddy:2019"],"enforce_origin":true}`)
	d := caddy.New(fake.URL(), resolver())

	err := d.Apply(context.Background(), exposeGrafana(t, d))
	if err == nil {
		t.Fatal("full-load with a rich admin block must refuse")
	}
	for _, want := range []string{"refusing full-config load", "enforce_origin", "origins", "--granular"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must mention %q, got: %v", want, err)
		}
	}
	if len(fake.Loads) != 0 {
		t.Errorf("a refused full-load must not POST /load at all, got %d load(s)", len(fake.Loads))
	}
	if got := fake.CurrentJSON(); !strings.Contains(got, "enforce_origin") {
		t.Errorf("a refused full-load must leave the live admin block intact:\n%s", got)
	}
}

// TestFullLoad_AdminReadBackCatchesDrop proves the verification half of the
// carry-through: if the edge accepts the load but the custom admin listener does
// NOT survive (DropAdminOnLoad models the F1 failure shape), Apply reports it
// loudly instead of returning green — a 200 from /load is not proof.
func TestFullLoad_AdminReadBackCatchesDrop(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	fake.DropAdminOnLoad = true
	seedWithAdmin(t, fake, `{"listen":"0.0.0.0:2019"}`)
	d := caddy.New(fake.URL(), resolver())

	err := d.Apply(context.Background(), exposeGrafana(t, d))
	if err == nil || !strings.Contains(err.Error(), "did NOT preserve the custom admin listener") {
		t.Fatalf("a dropped admin block must fail the post-load read-back, got %v", err)
	}
}

// TestGranular_IgnoresAdminBlock proves granular apply is untouched by the guard:
// a rich admin block that full-load refuses is simply left alone by the additive
// per-route path — the route lands and the admin block survives verbatim.
func TestGranular_IgnoresAdminBlock(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedWithAdmin(t, fake, `{"listen":"0.0.0.0:2019","origins":["caddy:2019"],"enforce_origin":true}`)
	d := caddy.New(fake.URL(), resolver(), caddy.WithGranularApply())

	if err := d.Apply(context.Background(), exposeGrafana(t, d)); err != nil {
		t.Fatalf("granular apply must be unaffected by the admin block, got %v", err)
	}
	got := fake.CurrentJSON()
	if !strings.Contains(got, "grafana.example.com") {
		t.Errorf("granular route must land:\n%s", got)
	}
	if !strings.Contains(got, `"origins":["caddy:2019"]`) || !strings.Contains(got, "enforce_origin") {
		t.Errorf("granular apply must leave the admin block verbatim:\n%s", got)
	}
}
