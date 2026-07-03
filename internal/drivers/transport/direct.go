// Package transport implements the pluggable connection channels an admin-API edge
// driver (Caddy) uses to physically reach its control plane. Each type implements
// ports.Transport. They are wired at cmd; core/model never import this package.
//
//   - Direct     — real HTTP to a configured admin_url (default; today's behavior).
//   - SSHExec    — run the admin call as a nested-exec curl against a loopback admin.
//   - SSHTunnel  — crenel opens a local-forward SSH tunnel, then talks Direct over it.
//
// Every transport honors the caller's context deadline (the driver bounds each call
// by its read/write timeout) so crenel can never hang on a slow or wedged admin API,
// regardless of how the call travels. See DESIGN.md "Transport / Connection".
package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
)

// Direct is the default Transport: a real HTTP client to a configured admin URL.
// It is today's Caddy admin-call code moved verbatim behind the port, so an edge
// configured only with an admin_url behaves byte-for-byte as before.
type Direct struct {
	// BaseURL is the admin API base, e.g. "http://127.0.0.1:2019" (no trailing /).
	BaseURL string
	// Client is the HTTP client. It carries NO client-level Timeout — every call is
	// bounded by the per-operation context deadline the driver sets, so timeouts are
	// precise and classifiable rather than one blunt cap.
	Client *http.Client
}

// NewDirect builds a Direct to baseURL with a default HTTP client.
func NewDirect(baseURL string) *Direct { return NewDirectWithClient(baseURL, nil) }

// NewDirectWithClient builds a Direct to baseURL with a caller-supplied client
// (nil => a fresh default client). The Caddy driver uses this so its WithHTTPClient
// option still threads through to the default transport.
func NewDirectWithClient(baseURL string, c *http.Client) *Direct {
	if c == nil {
		c = &http.Client{}
	}
	return &Direct{BaseURL: strings.TrimRight(baseURL, "/"), Client: c}
}

// Do issues the request over HTTP, bounded by ctx. A transport error (connection
// refused, ctx deadline) is returned as-is for the driver to classify; an HTTP
// response — including a non-2xx — returns its status + body with a nil error.
func (d *Direct) Do(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, msg, nil
}
