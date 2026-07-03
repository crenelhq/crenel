package cloudflare

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Doer is the seam for one Cloudflare REST API call. It is mocked in tests so the
// suite contacts no real Cloudflare (driver tests inject an in-process fake; the real
// OSDoer is exercised only against a loopback httptest server). It mirrors
// adguard.Doer / ports.Transport: a nil error with a non-2xx status means "the API was
// reached and answered <status>" (the driver interprets the Cloudflare error body); a
// non-nil error means NO HTTP response could be obtained at all (the channel failed).
type Doer interface {
	// Do issues ONE request to <base><path> with the given JSON body (nil for GET/
	// DELETE without a body). It MUST honor ctx's deadline and never hang (the
	// never-hang lesson applies to every control-plane call).
	Do(ctx context.Context, method, path string, body []byte) (status int, resp []byte, err error)
}

// OSDoer is the real Cloudflare API channel: an authenticated HTTPS client carrying a
// Bearer API token. It is NEVER exercised by the test suite against the real endpoint
// (tests inject a fake or a loopback httptest server), preserving the guarantee that
// Crenel touches no real infrastructure in this repo.
type OSDoer struct {
	// BaseURL is the Cloudflare API base; defaults to the v4 production endpoint.
	BaseURL string
	// Token is the Cloudflare API token, sent as `Authorization: Bearer <token>`.
	Token string
	// Client is the HTTP client; a bounded-timeout default is used when nil.
	Client *http.Client
}

// CloudflareAPIBase is the production Cloudflare REST API v4 base URL.
const CloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// defaultTimeout bounds a call so crenel never hangs on a wedged endpoint.
const defaultTimeout = 20 * time.Second

func (d OSDoer) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	base := d.BaseURL
	if base == "" {
		base = CloudflareAPIBase
	}
	url := strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
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
	if d.Token == "" {
		return 0, nil, fmt.Errorf("cloudflare: no API token configured (set api_token_env or api_token)")
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}
