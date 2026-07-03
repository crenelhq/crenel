package adguard_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/adguard"
	"github.com/crenelhq/crenel/internal/drivers/dns/adguard/adguardfake"
	"github.com/crenelhq/crenel/internal/model"
)

// These tests exercise the REAL OSDoer HTTP channel (the one path the driver tests
// skip by injecting the fake directly) against a loopback httptest server — proving
// it sends Basic auth, the right method/path/body, and maps statuses, WITHOUT
// contacting any real AdGuard.

func TestOSDoerSendsBasicAuthAndApplies(t *testing.T) {
	fake := adguardfake.New()
	fake.User, fake.Pass = "admin", "s3cret" // server requires these on the HTTP path
	srv := httptest.NewServer(fake)
	defer srv.Close()

	d := adguard.New(adguard.Config{
		Zone: zone, EdgeAddr: edge,
		Doer: adguard.OSDoer{BaseURL: srv.URL, Username: "admin", Password: "s3cret"},
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
		t.Errorf("rewrite not applied through OSDoer: %v", fake.List())
	}
}

func TestOSDoerWrongPasswordIs401(t *testing.T) {
	fake := adguardfake.New()
	fake.User, fake.Pass = "admin", "s3cret"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	d := adguard.New(adguard.Config{
		Zone: zone, EdgeAddr: edge,
		Doer: adguard.OSDoer{BaseURL: srv.URL, Username: "admin", Password: "WRONG"},
	})
	if _, err := d.LiveRecords(context.Background()); err == nil {
		t.Fatal("expected auth failure with the wrong password")
	}
}

func TestOSDoerNoEndpointErrors(t *testing.T) {
	d := adguard.New(adguard.Config{Zone: zone, EdgeAddr: edge, Doer: adguard.OSDoer{}})
	op := model.Op{Verb: model.Expose, Service: "grafana", Host: "grafana." + zone}
	desired, _ := d.DesiredRecords(op)
	if _, err := d.Diff(context.Background(), op, desired); err == nil {
		t.Fatal("expected an error when no control endpoint is configured")
	}
}

var _ http.Handler = (*adguardfake.Server)(nil)
