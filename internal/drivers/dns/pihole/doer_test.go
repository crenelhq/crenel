package pihole_test

import (
	"context"
	"strings"
	"testing"

	"net/http/httptest"

	"github.com/crenelhq/crenel/internal/drivers/dns/pihole"
	"github.com/crenelhq/crenel/internal/drivers/dns/pihole/piholefake"
)

// These tests exercise the REAL OSDoer HTTP channel (the one path the driver tests
// skip by injecting the fake directly) against a loopback httptest server — proving
// the v6 SESSION flow: acquire a sid via POST /api/auth, attach it as the sid
// header, REUSE it across calls, and re-authenticate once on expiry — WITHOUT
// contacting any real Pi-hole.

func TestOSDoerSessionLoginAndApplies(t *testing.T) {
	fake := piholefake.New()
	fake.Password = "s3cret" // server requires session auth on the HTTP path
	srv := httptest.NewServer(fake)
	defer srv.Close()

	d := pihole.New(pihole.Config{
		Zone: zone, EdgeAddr: edge,
		Doer: &pihole.OSDoer{BaseURL: srv.URL, Password: "s3cret"},
	})
	ctx := context.Background()
	op := exposeOp()
	desired, _ := d.DesiredRecords(op)
	change, err := d.Diff(ctx, op, desired)
	if err != nil {
		t.Fatalf("diff over real OSDoer: %v", err)
	}
	if err := d.Apply(ctx, change); err != nil {
		t.Fatalf("apply over real OSDoer: %v", err)
	}
	if got := fake.List()["grafana."+zone]; got != edge {
		t.Errorf("host entry not applied through OSDoer: %v", fake.List())
	}
	// Sessions are a finite server-side resource: the whole diff+apply sequence must
	// have REUSED one sid, not logged in per request.
	if fake.Logins != 1 {
		t.Errorf("expected exactly 1 login for the whole sequence (sid reuse), got %d", fake.Logins)
	}
}

// The expiry path: the server invalidates the sid mid-flight (validity is 1800s in
// the captured contract); the next call gets 401 and OSDoer must transparently
// re-authenticate ONCE and retry — no error surfaces to the driver.
func TestOSDoerReauthenticatesOnExpiredSession(t *testing.T) {
	fake := piholefake.New("grafana."+zone, edge)
	fake.Password = "s3cret"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	d := pihole.New(pihole.Config{
		Zone: zone, EdgeAddr: edge,
		Doer: &pihole.OSDoer{BaseURL: srv.URL, Password: "s3cret"},
	})
	ctx := context.Background()
	if _, err := d.LiveRecords(ctx); err != nil {
		t.Fatalf("first read: %v", err)
	}
	fake.ExpireSessions() // server-side expiry between calls
	recs, err := d.LiveRecords(ctx)
	if err != nil {
		t.Fatalf("read after expiry should transparently re-auth, got %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected the seeded record after re-auth, got %+v", recs)
	}
	if fake.Logins != 2 {
		t.Errorf("expected exactly 2 logins (initial + one re-auth), got %d", fake.Logins)
	}
}

func TestOSDoerWrongPasswordFailsLoudly(t *testing.T) {
	fake := piholefake.New()
	fake.Password = "s3cret"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	d := pihole.New(pihole.Config{
		Zone: zone, EdgeAddr: edge,
		Doer: &pihole.OSDoer{BaseURL: srv.URL, Password: "WRONG"},
	})
	if _, err := d.LiveRecords(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected loud auth failure with the wrong password, got %v", err)
	}
}

func TestOSDoerNoEndpointErrors(t *testing.T) {
	d := pihole.New(pihole.Config{Zone: zone, EdgeAddr: edge, Doer: &pihole.OSDoer{}})
	if _, err := d.LiveRecords(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("expected a no-endpoint configuration error, got %v", err)
	}
}
