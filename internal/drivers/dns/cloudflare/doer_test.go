package cloudflare

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/dns/cloudflare/cfapifake"
	"github.com/crenelhq/crenel/internal/model"
)

// TestOSDoer_RealBearerAuth exercises the REAL OSDoer HTTP path (Bearer header, URL
// joining, envelope decode) against a loopback httptest server wrapping the faithful
// fake — the one place the production channel is run, still touching no real Cloudflare.
func TestOSDoer_RealBearerAuth(t *testing.T) {
	fake := cfapifake.New(zone, "", foreignSeed()...)
	fake.AcceptToken = "good-token"
	srv := httptest.NewServer(fake)
	defer srv.Close()

	// Good token: full expose succeeds through the real HTTP channel.
	good := New(Config{ZoneName: zone, Scope: model.ScopePublic, EdgeAddr: edge, Doer: OSDoer{BaseURL: srv.URL, Token: "good-token"}})
	if err := applyOp(t, good, exposeOp("app."+zone)); err != nil {
		t.Fatalf("expose over real OSDoer: %v", err)
	}
	if fake.Creates != 1 {
		t.Fatalf("want 1 create via OSDoer, got %d", fake.Creates)
	}

	// Bad token: the server rejects with 403 and the driver surfaces an auth error.
	bad := New(Config{ZoneName: zone, Scope: model.ScopePublic, EdgeAddr: edge, Doer: OSDoer{BaseURL: srv.URL, Token: "wrong"}})
	if _, err := bad.LiveRecords(context.Background()); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want auth failure with a bad bearer token, got: %v", err)
	}
}

// TestOSDoer_NoToken fails fast rather than sending an unauthenticated request.
func TestOSDoer_NoToken(t *testing.T) {
	_, _, err := OSDoer{BaseURL: "http://127.0.0.1:1"}.Do(context.Background(), "GET", "/zones", nil)
	if err == nil || !strings.Contains(err.Error(), "no API token") {
		t.Fatalf("want no-token error, got: %v", err)
	}
}
