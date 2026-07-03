package transport_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/drivers/transport"
)

// TestDirect_RoundTrip proves the Direct transport carries method, path, content
// type, and body to the server and returns the status + body — the wire semantics
// the Caddy driver relies on, now behind the port.
func TestDirect_RoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotCT = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok-body"))
	}))
	defer srv.Close()

	d := transport.NewDirect(srv.URL + "/") // trailing slash must be trimmed
	status, body, err := d.Do(context.Background(), http.MethodPut, "/config/apps/http/servers/srv0/routes/0", "application/json", []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want 201", status)
	}
	if string(body) != "ok-body" {
		t.Errorf("body = %q, want ok-body", body)
	}
	if gotMethod != http.MethodPut || gotPath != "/config/apps/http/servers/srv0/routes/0" {
		t.Errorf("server saw %s %s", gotMethod, gotPath)
	}
	if gotCT != "application/json" || gotBody != `{"x":1}` {
		t.Errorf("server saw ct=%q body=%q", gotCT, gotBody)
	}
}

// TestDirect_Non2xx_NoError: a non-2xx HTTP response is returned with its status and
// body and a NIL error — "reached the admin, it answered" — so the driver decides.
func TestDirect_Non2xx_NoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad caddyfile", http.StatusBadRequest)
	}))
	defer srv.Close()

	d := transport.NewDirect(srv.URL)
	status, body, err := d.Do(context.Background(), http.MethodPost, "/load", "text/caddyfile", []byte("x"))
	if err != nil {
		t.Fatalf("non-2xx must not be a transport error, got: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	if len(body) == 0 {
		t.Error("expected an error body")
	}
}

// TestDirect_HonorsContextDeadline: a stalled server must surface a deadline error
// (which the driver maps to ErrAdminUnresponsive), never a hang.
func TestDirect_HonorsContextDeadline(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond within the deadline
	}))
	// Defers run LIFO: release the stuck handler (close) BEFORE srv.Close(), or
	// srv.Close() would block forever waiting on the in-flight request.
	defer srv.Close()
	defer close(block)

	d := transport.NewDirect(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := d.Do(ctx, http.MethodGet, "/config/", "", nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a deadline error from a stalled server")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do hung past the context deadline")
	}
}
