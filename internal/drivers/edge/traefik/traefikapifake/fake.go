// Package traefikapifake is an in-repo fake of Traefik's read-only HTTP API for
// tests — the same discipline as caddyfake/cfapifake: the fake only accepts what
// the real API accepts, and serves payloads CAPTURED from real Traefik v3.6
// instances (internal/drivers/edge/traefik/testdata/api-docker and api-pangolin,
// captured on CT120 per design §9 decision 7).
//
// Faithfulness contract (checked against the real API while capturing):
//   - the api port serves GET only for the /api/* data endpoints; a mutating
//     method gets 405 — Traefik's API is read-only by construction, which is
//     exactly the property M-A4's "mutation refused" tests lean on.
//   - an unknown /api/* path (and /config/ — the CADDY signature the sniffer
//     probes first) gets 404. This 404 is load-bearing: it is what pushes the
//     zero-config sniffer past the Caddy probe to the Traefik probe.
//   - every list endpoint returns a JSON ARRAY; /api/version and /api/overview
//     return objects.
//
// Requests are recorded (method + path) so tests can assert the A.6 network
// contract: only the pasted target — and only these documented endpoints — is
// ever contacted.
package traefikapifake

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
)

// endpointFiles maps each served API path to its fixture filename inside a
// capture directory (the `tr / -` convention the capture script used). Paths not
// in this map 404 — the fake never invents an endpoint the capture did not
// witness. tcp/services was empty on both captured systems; a missing fixture
// file for an ARRAY endpoint serves the honest empty array.
var endpointFiles = map[string]string{
	"/api/version":          "version.json",
	"/api/overview":         "overview.json",
	"/api/entrypoints":      "entrypoints.json",
	"/api/http/routers":     "http-routers.json",
	"/api/http/services":    "http-services.json",
	"/api/http/middlewares": "http-middlewares.json",
	"/api/tcp/routers":      "tcp-routers.json",
	"/api/tcp/services":     "tcp-services.json",
}

// objectEndpoints are the two non-array endpoints (no empty-array default).
var objectEndpoints = map[string]bool{"/api/version": true, "/api/overview": true}

// Fake serves a captured Traefik API payload set.
type Fake struct {
	mu       sync.Mutex
	payloads map[string][]byte
	requests []string // "METHOD /path", in order
	ts       *httptest.Server
}

// NewFromDir starts a fake serving the capture at dir (a testdata/api-* dir).
// A missing file for an array endpoint serves "[]"; a missing file for
// /api/version or /api/overview is an error — a Traefik API always answers them,
// so a fixture set without them is not a faithful capture.
func NewFromDir(dir string) (*Fake, error) {
	f := &Fake{payloads: map[string][]byte{}}
	for path, name := range endpointFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) && !objectEndpoints[path] {
				f.payloads[path] = []byte("[]")
				continue
			}
			return nil, fmt.Errorf("traefikapifake: fixture %s: %w", name, err)
		}
		f.payloads[path] = b
	}
	f.ts = httptest.NewServer(http.HandlerFunc(f.handle))
	return f, nil
}

// URL is the fake API's base URL.
func (f *Fake) URL() string { return f.ts.URL }

// Close shuts the fake down.
func (f *Fake) Close() { f.ts.Close() }

// Requests returns every request seen so far ("METHOD /path", in order) — the
// A.6 recording surface.
func (f *Fake) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *Fake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	body, known := f.payloads[r.URL.Path]
	f.mu.Unlock()

	// Real Traefik's API surface is read-only: any mutating method is refused.
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !known {
		// Includes /config/ (the Caddy admin signature): a real Traefik 404s it,
		// and the sniffer depends on that refusal to try the Traefik probe next.
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
