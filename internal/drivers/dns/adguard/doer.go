package adguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Doer is the seam for one AdGuard control-API call. It is mocked in tests so the
// suite contacts no real AdGuard (the driver tests inject an in-process fake; the
// real OSDoer is exercised only against a loopback httptest server). It mirrors
// ports.Transport: a
// nil error with a non-2xx status means "the control API was reached and answered
// <status>" (the driver interprets it); a non-nil error means NO response was
// obtained at all.
type Doer interface {
	// Do issues ONE request to <base><path> with the given JSON body (nil for GET).
	// It MUST honor ctx's deadline and never hang (the never-hang lesson applies to
	// every control-plane call).
	Do(ctx context.Context, method, path string, body []byte) (status int, resp []byte, err error)
}

// OSDoer is the real control-API channel: an authenticated HTTP client against the
// AdGuard Home control endpoint. It is NEVER exercised by the test suite (tests inject
// a fake), preserving the guarantee that Crenel touches no real infrastructure in this
// repo.
type OSDoer struct {
	// BaseURL is the AdGuard control API base, e.g. "http://10.0.0.53:3000".
	BaseURL string
	// Username / Password are the Basic-auth control credentials.
	Username string
	Password string
	// Client is the HTTP client; a bounded-timeout default is used when nil.
	Client *http.Client
}

// defaultTimeout bounds a control call so crenel never hangs on a wedged AdGuard.
const defaultTimeout = 10 * time.Second

func (d OSDoer) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if d.BaseURL == "" {
		return 0, nil, fmt.Errorf("adguard: no control endpoint configured (set dns provider `endpoint`)")
	}
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
	if d.Username != "" || d.Password != "" {
		req.SetBasicAuth(d.Username, d.Password)
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
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
