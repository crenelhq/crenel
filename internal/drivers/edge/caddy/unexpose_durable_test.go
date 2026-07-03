package caddy

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// liveNoIDNested models the POST-RELOAD state of a durable-persisted route: after the
// durable persist's `caddy reload --config Caddyfile`, the live config is re-derived from
// the on-disk Caddyfile, so the crenel route is a per-host route nested inside the
// `*.homelab.example` wildcard subroute and carries NO JSON `@id` (a Caddyfile `handle`
// block has none). This is exactly what the live durable-persist trial observed — and what
// made `unexpose` roll back, because the `/id/` delete could not find an `@id`-less route.
const liveNoIDNested = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
 {"match":[{"host":["*.homelab.example"]}],"terminal":true,"handle":[{"handler":"subroute","routes":[
   {"match":[{"host":["git.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.13:3030"}]}]}]}]},
   {"match":[{"host":["crenel-durable-test.homelab.example"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"homepage:3000"}]}]}]}]}
 ]}]},
 {"handle":[{"handler":"static_response","abort":true}]}
]}}}}}`

func unexposeChangeSet(host string) model.ChangeSet {
	return model.ChangeSet{
		Op:   model.Op{Verb: model.Unexpose, Host: host},
		Edge: model.EdgeChange{DenyCatchAllWillBePresent: true, RemoveHosts: []string{host}},
	}
}

// TestUnexposeDurable_RemovesNoIDNestedRoute is the live-faithful reproduction of the
// trial rollback. The crenel route is live with NO `@id` (Caddyfile-derived, nested in the
// wildcard subroute). On a DURABLE-FILE edge, unexpose now removes it by host match — the
// fix. On a NON-durable edge the same `@id`-less route is LEFT untouched (the pre-fix
// behavior: `/id/` delete is a no-op), which is the contrast proving the fix is the
// durable host-match sweep, scoped so it never changes non-durable behavior. A second host
// (git) must survive in both cases.
func TestUnexposeDurable_RemovesNoIDNestedRoute(t *testing.T) {
	const host = "crenel-durable-test.homelab.example"
	res := static.New(map[string]string{})
	ctx := context.Background()

	t.Run("durable-file edge: host-match removes the @id-less route", func(t *testing.T) {
		fake := caddyfake.New()
		t.Cleanup(fake.Close)
		if err := fake.SeedJSON(liveNoIDNested); err != nil {
			t.Fatal(err)
		}
		// persistPath set => durable-file => the host-match sweep engages.
		d := New(fake.URL(), res, WithGranularApply(), WithPersistPath("/etc/caddy/Caddyfile"))
		if err := d.Apply(ctx, unexposeChangeSet(host)); err != nil {
			t.Fatalf("unexpose apply: %v", err)
		}
		st, err := d.ReadLiveState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.HasHost(host) {
			t.Fatalf("durable unexpose must remove the @id-less route, still present: %v", st.Hosts())
		}
		if !st.HasHost("git.homelab.example") {
			t.Fatalf("the other host must survive, hosts: %v", st.Hosts())
		}
	})

	t.Run("non-durable edge: @id-less route is left (unchanged pre-fix behavior)", func(t *testing.T) {
		fake := caddyfake.New()
		t.Cleanup(fake.Close)
		if err := fake.SeedJSON(liveNoIDNested); err != nil {
			t.Fatal(err)
		}
		// No persist path => non-durable => @id delete only (no structural read / sweep).
		d := New(fake.URL(), res, WithGranularApply())
		if err := d.Apply(ctx, unexposeChangeSet(host)); err != nil {
			t.Fatalf("unexpose apply: %v", err)
		}
		st, _ := d.ReadLiveState(ctx)
		// The @id-less route is NOT removed by the @id delete — a non-durable edge never
		// produces such a route, so behavior is intentionally unchanged here.
		if !st.HasHost(host) {
			t.Fatalf("non-durable @id delete should be a no-op on an @id-less route; host unexpectedly gone")
		}
	})
}

// TestUnexposeDurable_FullCycleClearsLiveAndDisk is the capstone: on a durable-file edge
// whose route is in the post-reload steady state (live with NO @id + an on-disk crenel
// region), a full unexpose removes it from BOTH the live admin (host-match delete) AND the
// on-disk Caddyfile (region clear) — the complete teardown the trial's byte-restore had to
// do by hand. The operator's own host (git) survives in both representations.
func TestUnexposeDurable_FullCycleClearsLiveAndDisk(t *testing.T) {
	const host = "crenel-durable-test.homelab.example"
	res := static.New(map[string]string{})
	ctx := context.Background()

	// Boot Caddyfile already carries a crenel region for the host (a prior persisted expose).
	bootWithRegion := strings.Replace(operatorWildcardCaddyfile,
		"\t@git host git.homelab.example\n\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n",
		"\t@git host git.homelab.example\n\thandle @git {\n\t\treverse_proxy 10.0.0.13:3030\n\t}\n"+
			"\t"+persistBegin+"\n\t@crenel_crenel_durable_test_homelab_example host "+host+"\n\thandle @crenel_crenel_durable_test_homelab_example {\n\t\treverse_proxy homepage:3000\n\t}\n\t"+persistEnd+"\n", 1)
	boot := writeBoot(t, bootWithRegion)

	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	if err := fake.SeedJSON(liveNoIDNested); err != nil { // live: git + host (no @id), nested
		t.Fatal(err)
	}
	d := New(fake.URL(), res, WithGranularApply(),
		WithPersistPath("/etc/caddy/Caddyfile"),
		WithConfigStore(localConfigStore{path: boot}),
		WithAdapter(caddyfileAdapter{server: "srv0"}),
		WithCaddyCLI(&fakeReloadCLI{}))

	// 1) live removal via host-match delete.
	if err := d.Apply(ctx, unexposeChangeSet(host)); err != nil {
		t.Fatalf("unexpose apply: %v", err)
	}
	// 2) durable removal via the region clear (managed set now empty).
	if err := d.Persist(ctx); err != nil {
		t.Fatalf("persist (region clear): %v", err)
	}

	st, _ := d.ReadLiveState(ctx)
	if st.HasHost(host) {
		t.Fatalf("host must be gone from live after the full cycle")
	}
	if !st.HasHost("git.homelab.example") {
		t.Fatalf("operator host git must survive")
	}
	out, _ := os.ReadFile(boot)
	if strings.Contains(string(out), "# crenel-managed-begin") {
		t.Fatalf("on-disk crenel region must be cleared:\n%s", out)
	}
	if !strings.Contains(string(out), "@git host git.homelab.example") {
		t.Fatalf("operator @git handle must survive on disk")
	}
}

// TestUnexposeDurable_IDTaggedStillDeletedFirst proves the @id fast-path is unchanged on a
// durable edge: a freshly-inserted crenel route (carrying its `@id`, before any persist
// reload) is removed by the `/id/` delete WITHOUT a host-match read (so the common
// expose→unexpose path costs no extra round-trip and never reads on a wedge).
func TestUnexposeDurable_IDTaggedStillDeletedFirst(t *testing.T) {
	const host = "crenel-durable-test.homelab.example"
	res := static.New(map[string]string{})
	ctx := context.Background()
	seed := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"@id":"crenel-route-crenel-durable-test.homelab.example","match":[{"host":["crenel-durable-test.homelab.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"homepage:3000"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	if err := fake.SeedJSON(seed); err != nil {
		t.Fatal(err)
	}
	d := New(fake.URL(), res, WithGranularApply(), WithPersistPath("/etc/caddy/Caddyfile"))
	if err := d.Apply(ctx, unexposeChangeSet(host)); err != nil {
		t.Fatalf("unexpose apply: %v", err)
	}
	st, _ := d.ReadLiveState(ctx)
	if st.HasHost(host) {
		t.Fatalf("@id-tagged route must be removed by the /id/ delete, still present")
	}
}
