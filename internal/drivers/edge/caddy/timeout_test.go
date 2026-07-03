package caddy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/model"
)

// These tests prove the property that was MISSING when the live edge wedged:
// crenel must NEVER hang on a slow or wedged admin API. Every admin call is
// bounded by a per-operation timeout, and a timeout is classified as
// ErrAdminUnresponsive (not a silent hang). See POSTMORTEM.md.

const wedgeHost = "crenel-selftest.homelab.example"

// exposeCS builds the edge ChangeSet for exposing wedgeHost by hand, so a test
// can stall the fake's READ path without first hanging on Plan's ReadLiveState.
func exposeCS() model.ChangeSet {
	return model.ChangeSet{
		Op: model.Op{Verb: model.Expose, Service: "photos", Host: wedgeHost},
		Edge: model.EdgeChange{
			DenyCatchAllWillBePresent: true,
			AddRoutes: []model.Route{{
				Host:     wedgeHost,
				Upstream: model.Upstream{Kind: model.ForwardToOrigin, Address: "127.0.0.1:9999", ServerName: wedgeHost},
			}},
		},
	}
}

// unexposeCS builds the edge ChangeSet for unexposing wedgeHost by hand. A remove
// deletes by @id (DELETE /id/...) and needs NO structural config read, so the
// post-mutation settle (GET /config/) is the first read in the flow — faithfully
// modelling the real incident "DELETE returned, then the reload wedged GET /config/".
func unexposeCS() model.ChangeSet {
	return model.ChangeSet{
		Op: model.Op{Verb: model.Unexpose, Service: "photos", Host: wedgeHost},
		Edge: model.EdgeChange{
			DenyCatchAllWillBePresent: true,
			RemoveHosts:               []string{wedgeHost},
		},
	}
}

func seedRich(t *testing.T, f *caddyfake.Fake) {
	t.Helper()
	if err := f.SeedJSON(mustRead(t, "testdata/rich-prod.json")); err != nil {
		t.Fatal(err)
	}
}

// assertBounded fails if fn takes longer than limit — i.e. if crenel hung.
func assertBounded(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() { fn(); close(done) }()
	select {
	case <-done:
		if el := time.Since(start); el > limit {
			t.Fatalf("operation took %s, exceeding bound %s (crenel hung)", el, limit)
		}
	case <-time.After(limit):
		t.Fatalf("operation did not return within %s — crenel HUNG on a wedged admin API", limit)
	}
}

// TestApply_GranularWriteWedged_NoHang: the write (route insert) never responds.
// crenel must return a classified unresponsive error quickly, not hang.
func TestApply_GranularWriteWedged_NoHang(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedRich(t, fake)
	fake.WriteDelay = time.Hour // the mutation wedges forever

	d := caddy.New(fake.URL(), resolver(),
		caddy.WithGranularApply(),
		caddy.WithTimeouts(200*time.Millisecond, 300*time.Millisecond))

	var err error
	assertBounded(t, 3*time.Second, func() {
		err = d.Apply(context.Background(), exposeCS())
	})
	if err == nil {
		t.Fatal("expected an error from a wedged write, got nil")
	}
	if !caddy.IsUnresponsive(err) {
		t.Fatalf("expected ErrAdminUnresponsive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "docker restart") {
		t.Errorf("error should carry a recovery hint, got: %v", err)
	}
}

// TestSettle_CatchesPostMutationWedge: the write SUCCEEDS, but the reload it
// triggers wedges the admin API (modelled as a stalled READ). The settle step
// after each granular op must catch this and report it — this is exactly the
// real-edge shape (DELETE returned, then the reload wedged GET /config/). Modelled
// as an UNEXPOSE so the delete-by-@id (no structural read) returns and the settle
// GET is the read that wedges.
func TestSettle_CatchesPostMutationWedge(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedRich(t, fake)
	fake.ReadDelay = time.Hour // the post-mutation reload wedges the read path

	d := caddy.New(fake.URL(), resolver(),
		caddy.WithGranularApply(),
		caddy.WithTimeouts(200*time.Millisecond, 2*time.Second))

	var err error
	assertBounded(t, 3*time.Second, func() {
		err = d.Apply(context.Background(), unexposeCS())
	})
	if err == nil || !caddy.IsUnresponsive(err) {
		t.Fatalf("expected settle to surface ErrAdminUnresponsive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "health") {
		t.Errorf("expected the post-mutation health check to be named in the error, got: %v", err)
	}
}

// TestReadLiveState_Wedged_NoHang: a stalled read must time out cleanly so even
// status/audit/preview can never hang (the prior session's failure mode).
func TestReadLiveState_Wedged_NoHang(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedRich(t, fake)
	fake.ReadDelay = time.Hour

	d := caddy.New(fake.URL(), resolver(), caddy.WithTimeouts(200*time.Millisecond, time.Second))

	var err error
	assertBounded(t, 3*time.Second, func() {
		_, err = d.ReadLiveState(context.Background())
	})
	if err == nil || !caddy.IsUnresponsive(err) {
		t.Fatalf("expected ErrAdminUnresponsive from a wedged read, got: %v", err)
	}
}

// TestHealthy_ReportsUnresponsive: the bounded health probe is what core uses to
// decide not to pile compensating reloads onto a wedged edge.
func TestHealthy_ReportsUnresponsive(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedRich(t, fake)
	fake.ReadDelay = time.Hour

	d := caddy.New(fake.URL(), resolver(), caddy.WithTimeouts(150*time.Millisecond, time.Second))

	var err error
	assertBounded(t, 2*time.Second, func() { err = d.Healthy(context.Background()) })
	if err == nil || !caddy.IsUnresponsive(err) {
		t.Fatalf("Healthy should report ErrAdminUnresponsive when wedged, got: %v", err)
	}

	// And when responsive (a separate, non-stalled fake), it returns nil promptly.
	ok := caddyfake.New()
	defer ok.Close()
	seedRich(t, ok)
	dok := caddy.New(ok.URL(), resolver(), caddy.WithTimeouts(150*time.Millisecond, time.Second))
	if err := dok.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy should pass on a responsive admin API, got: %v", err)
	}
}

// TestApply_SlowReloadWithinBudget_Succeeds: a reload slower than the fake but
// well within the write budget must SUCCEED — we must not abort a legitimately
// slow reload (aborting mid-reload can itself worsen a wedge).
func TestApply_SlowReloadWithinBudget_Succeeds(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	seedRich(t, fake)
	fake.WriteDelay = 120 * time.Millisecond // slow, but legitimate

	d := caddy.New(fake.URL(), resolver(),
		caddy.WithGranularApply(),
		caddy.WithTimeouts(2*time.Second, 2*time.Second))

	if err := d.Apply(context.Background(), exposeCS()); err != nil {
		t.Fatalf("slow-but-within-budget reload should succeed, got: %v", err)
	}
	if !strings.Contains(fake.CurrentJSON(), "crenel-route-"+wedgeHost) {
		t.Error("route should have been inserted by the (slow) apply")
	}
}
