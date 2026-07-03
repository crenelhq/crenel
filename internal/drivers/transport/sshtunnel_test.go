package transport_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/transport"
)

// fakeForwarder stands in for `ssh -N -L`: Open returns a fixed local address (an
// in-process admin) and a close func, recording open/close counts so the lifecycle
// can be asserted without real ssh.
type fakeForwarder struct {
	mu        sync.Mutex
	addr      string
	openErr   error
	openCount int
	closed    int
}

func (f *fakeForwarder) Open(ctx context.Context) (string, func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openCount++
	if f.openErr != nil {
		return "", nil, f.openErr
	}
	return f.addr, func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.closed++
		return nil
	}, nil
}

func (f *fakeForwarder) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openCount, f.closed
}

// TestSSHTunnel_OpenUseClose proves the lifecycle: the forward opens lazily on first
// use (once across multiple Do), traffic flows as Direct over it, Close tears it
// down, and a later Do re-opens.
func TestSSHTunnel_OpenUseClose(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("via-tunnel"))
	}))
	defer srv.Close()

	fwd := &fakeForwarder{addr: transport.LocalAddr(srv.URL)}
	tun := &transport.SSHTunnel{Forwarder: fwd}

	for i := 0; i < 3; i++ {
		status, body, err := tun.Do(context.Background(), http.MethodGet, "/config/", "", nil)
		if err != nil || status != 200 || string(body) != "via-tunnel" {
			t.Fatalf("Do #%d: status=%d body=%q err=%v", i, status, body, err)
		}
	}
	if gotPath != "/config/" {
		t.Errorf("admin saw path %q", gotPath)
	}
	if opens, closes := fwd.counts(); opens != 1 || closes != 0 {
		t.Fatalf("expected lazy single open, none closed; got opens=%d closes=%d", opens, closes)
	}

	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tun.Close(); err != nil { // idempotent
		t.Fatalf("second Close should be a no-op, got: %v", err)
	}
	if opens, closes := fwd.counts(); opens != 1 || closes != 1 {
		t.Fatalf("expected exactly one close; got opens=%d closes=%d", opens, closes)
	}

	// Re-open on the next use (reusable, not one-shot).
	if _, _, err := tun.Do(context.Background(), http.MethodGet, "/config/", "", nil); err != nil {
		t.Fatalf("Do after Close should re-open: %v", err)
	}
	if opens, _ := fwd.counts(); opens != 2 {
		t.Fatalf("expected re-open after Close; got opens=%d", opens)
	}
	_ = tun.Close()
}

// TestSSHTunnel_OpenError_Unreachable: a failed tunnel open is transport-unreachable.
func TestSSHTunnel_OpenError_Unreachable(t *testing.T) {
	fwd := &fakeForwarder{openErr: errors.New("ssh: permission denied (publickey)")}
	tun := &transport.SSHTunnel{Forwarder: fwd}

	_, _, err := tun.Do(context.Background(), http.MethodGet, "/config/", "", nil)
	if !transport.IsUnreachable(err) {
		t.Fatalf("expected ErrTransportUnreachable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should carry the ssh diagnostic, got: %v", err)
	}
}

// TestSSHTunnel_NoForwarder: a misconfigured tunnel is unreachable, not a panic.
func TestSSHTunnel_NoForwarder(t *testing.T) {
	tun := &transport.SSHTunnel{}
	if _, _, err := tun.Do(context.Background(), http.MethodGet, "/config/", "", nil); !transport.IsUnreachable(err) {
		t.Fatalf("expected ErrTransportUnreachable, got: %v", err)
	}
}

func TestLocalAddr(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:12019": "127.0.0.1:12019",
		"https://10.0.0.1:2019":  "10.0.0.1:2019",
		"127.0.0.1:2019":         "127.0.0.1:2019",
	} {
		if got := transport.LocalAddr(in); got != want {
			t.Errorf("LocalAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
