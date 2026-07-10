package pihole

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Doer is the seam for one Pi-hole API call. It is mocked in tests so the suite
// contacts no real Pi-hole (driver tests inject an in-process fake; the real OSDoer
// is exercised only against a loopback httptest server). It mirrors ports.Transport:
// a nil error with a non-2xx status means "the API was reached and answered
// <status>" (the driver interprets it); a non-nil error means NO response was
// obtained at all.
type Doer interface {
	// Do issues ONE request to <base><path> with the given JSON body (nil for
	// GET/PUT/DELETE — the hosts endpoints are entry-addressed, no body). It MUST
	// honor ctx's deadline and never hang (the never-hang lesson applies to every
	// control-plane call).
	Do(ctx context.Context, method, path string, body []byte) (status int, resp []byte, err error)
}

// OSDoer is the real API channel: a session-authenticated HTTP client against the
// Pi-hole v6 API. It is NEVER exercised by the test suite over a real network (tests
// use httptest loopback only), preserving the guarantee that Crenel touches no real
// infrastructure in this repo.
//
// v6 auth is SESSION-based, not Basic (captured contract, testdata/):
//
//	POST /api/auth {"password": ...} -> 200 {"session":{"sid": ...,"validity":1800}}
//	subsequent requests carry the header  sid: <sid>
//	an expired/invalidated sid answers 401 {"error":{"key":"unauthorized"}}
//
// OSDoer acquires the sid lazily on first use, REUSES it across calls (sessions are
// a finite server-side resource; a fresh login per request would exhaust the seat
// limit), and on a 401 discards it, re-authenticates ONCE, and retries the request —
// the expiry path (validity 1800s) an hours-apart status/apply sequence will hit.
type OSDoer struct {
	// BaseURL is the Pi-hole API base, e.g. "http://10.0.0.53:8080" (the /api prefix
	// is part of each path, not the base).
	BaseURL string
	// Password is the Pi-hole web/API password (or an app password).
	Password string
	// Client is the HTTP client; a bounded-timeout default is used when nil.
	Client *http.Client

	mu  sync.Mutex // guards sid across concurrent driver calls
	sid string
}

// defaultTimeout bounds an API call so crenel never hangs on a wedged Pi-hole.
const defaultTimeout = 10 * time.Second

func (d *OSDoer) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if d.BaseURL == "" {
		return 0, nil, fmt.Errorf("pihole: no API endpoint configured (set dns provider `endpoint`)")
	}
	sid, err := d.session(ctx)
	if err != nil {
		return 0, nil, err
	}
	status, resp, err := d.do(ctx, method, path, body, sid)
	if err != nil {
		return 0, nil, err
	}
	if status != http.StatusUnauthorized {
		return status, resp, nil
	}
	// The sid expired or was invalidated server-side: drop it, re-auth once, retry.
	// A second 401 is returned as-is — that is a real credential failure, and the
	// driver surfaces it (no retry loop, no hang).
	d.invalidate(sid)
	sid, err = d.session(ctx)
	if err != nil {
		return 0, nil, err
	}
	return d.do(ctx, method, path, body, sid)
}

// do issues one raw request with the given sid attached.
func (d *OSDoer) do(ctx context.Context, method, path string, body []byte, sid string) (int, []byte, error) {
	url := strings.TrimSuffix(d.BaseURL, "/") + "/" + strings.TrimPrefix(path, "/")
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sid != "" {
		req.Header.Set("sid", sid)
	}
	resp, err := d.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// session returns the cached sid, authenticating if none is held. The lock spans the
// login so concurrent first calls perform ONE login, not a stampede.
func (d *OSDoer) session(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sid != "" {
		return d.sid, nil
	}
	payload, err := json.Marshal(map[string]string{"password": d.Password})
	if err != nil {
		return "", err
	}
	status, body, err := d.do(ctx, http.MethodPost, "/api/auth", payload, "")
	if err != nil {
		return "", fmt.Errorf("pihole auth: %w", err)
	}
	if status != http.StatusOK {
		// Captured: wrong password -> 401 {"session":{"valid":false,"sid":null,...}}.
		return "", fmt.Errorf("pihole auth: authentication failed (HTTP %d) — check the API password", status)
	}
	var ar struct {
		Session struct {
			Valid bool   `json:"valid"`
			SID   string `json:"sid"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		return "", fmt.Errorf("pihole auth: decode: %w", err)
	}
	if !ar.Session.Valid || ar.Session.SID == "" {
		return "", fmt.Errorf("pihole auth: no session granted — check the API password")
	}
	d.sid = ar.Session.SID
	return d.sid, nil
}

// invalidate clears the cached sid, but only if it is still the one that failed —
// a concurrent goroutine may already have re-authenticated.
func (d *OSDoer) invalidate(sid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sid == sid {
		d.sid = ""
	}
}

func (d *OSDoer) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Timeout: defaultTimeout}
}
