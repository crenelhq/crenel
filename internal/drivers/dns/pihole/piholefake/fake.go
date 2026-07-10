// Package piholefake is a FAITHFUL in-repo fake of the Pi-hole v6 API — the exact
// surface captured live against pihole/pihole (core v6.4.3 / FTL v6.7); every status
// code and body shape below mirrors a fixture in ../testdata/ and its
// capture-transcript.txt. The fake may only accept what that real API accepts.
//
// It is two things at once:
//   - a pihole.Doer (used directly in driver tests — no socket), and
//   - an http.Handler (wrap it in httptest to exercise the REAL pihole.OSDoer,
//     including the session login/expiry/re-auth flow, over loopback).
//
// It REJECTS what the real API rejects — a missing/bad/expired sid (401
// unauthorized envelope), a wrong password on login (401), an exact-duplicate PUT
// (400 "Item already present"), a non-IP value (400 "neither a valid IPv4 nor IPv6
// address"), a wildcard hostname (400 "invalid hostname"), and a DELETE of an
// absent entry (404) — so tests prove Crenel handles the real failure surface.
//
// The TWO things it deliberately does NOT reject, because the real API does not:
//   - an out-of-zone hostname (Pi-hole has no zone concept — the hijack trap the
//     driver's guard exists for; tests assert refusal happens BEFORE any call
//     lands here, Puts stays 0);
//   - a second entry for the SAME host with a DIFFERENT IP (captured: 201, both
//     coexist — the ambiguity the driver's conflict check refuses to create).
package piholefake

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Server is a faithful fake of the Pi-hole v6 API.
type Server struct {
	mu    sync.Mutex
	hosts []string // "IP host" lines, order-preserving like the real config list

	// Password, when set, is required by POST /api/auth on the HTTP (ServeHTTP)
	// path; a granted sid must then accompany every other call. Direct Doer calls
	// carry no session, so they are governed by the Unauthorized knob instead.
	Password string
	sessions map[string]bool
	seq      int

	// Unauthorized forces 401 on every call (models a server-side auth rejection
	// on the session-less Doer path). RateLimited forces 429.
	Unauthorized bool
	RateLimited  bool

	// Counters for assertions.
	Puts    int
	Deletes int
	Logins  int
}

// New builds a fake seeded with host entries (pass "host", "ip" pairs, mirroring
// adguardfake's seeding order).
func New(seed ...string) *Server {
	s := &Server{sessions: map[string]bool{}}
	for i := 0; i+1 < len(seed); i += 2 {
		s.hosts = append(s.hosts, seed[i+1]+" "+seed[i])
	}
	return s
}

// ExpireSessions invalidates every granted sid — the server-side expiry (validity
// 1800s) that OSDoer's re-auth path must survive.
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}

// Do implements pihole.Doer (the session-less, socket-free path).
func (s *Server) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	status, resp := s.handle(method, path, body, true /* authed: no session to check here */)
	return status, resp, nil
}

// ServeHTTP implements http.Handler (the loopback path that exercises the real
// OSDoer session flow: POST /api/auth grants a sid; every other call must carry a
// live one in the sid header — the captured contract).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	// EscapedPath preserves the %20/%2A encoding of entry-addressed paths so the
	// fake decodes exactly what a real mux would.
	path := r.URL.EscapedPath()

	if r.Method == http.MethodPost && path == "/api/auth" {
		status, resp := s.login(body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(resp)
		return
	}

	status, resp := s.handle(r.Method, path, body, s.checkSID(r.Header.Get("sid")))
	if len(resp) > 0 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

// login models POST /api/auth: correct password -> 200 with a fresh sid (fixture
// auth-success.json); wrong -> 401 with valid:false and a null sid
// (auth-wrong-password.json).
func (s *Server) login(body []byte) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Password != s.Password {
		return http.StatusUnauthorized,
			[]byte(`{"session":{"valid":false,"totp":false,"sid":null,"validity":-1,"message":"password incorrect"},"took":0.01}`)
	}
	s.seq++
	sid := fmt.Sprintf("fake-sid-%d", s.seq)
	s.sessions[sid] = true
	s.Logins++
	resp, _ := json.Marshal(map[string]any{
		"session": map[string]any{
			"valid": true, "totp": false, "sid": sid,
			"csrf": "fake-csrf", "validity": 1800, "message": "password correct",
		},
		"took": 0.01,
	})
	return http.StatusOK, resp
}

func (s *Server) checkSID(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Password == "" {
		return true // no auth required (auth-disabled Pi-hole)
	}
	return s.sessions[sid]
}

// unauthorizedBody is the captured 401 envelope (error-unauthorized.json).
const unauthorizedBody = `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.01}`

func badRequest(message, hint string) (int, []byte) {
	resp, _ := json.Marshal(map[string]any{
		"error": map[string]any{"key": "bad_request", "message": message, "hint": hint},
		"took":  0.01,
	})
	return http.StatusBadRequest, resp
}

const hostsPrefix = "/api/config/dns/hosts"

func (s *Server) handle(method, path string, _ []byte, authed bool) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Unauthorized || !authed {
		return http.StatusUnauthorized, []byte(unauthorizedBody)
	}
	if s.RateLimited {
		return http.StatusTooManyRequests, []byte(`{"error":{"key":"rate_limited","message":"Too Many Requests","hint":null},"took":0.01}`)
	}

	switch {
	case method == http.MethodGet && strings.HasSuffix(path, hostsPrefix):
		resp, _ := json.Marshal(map[string]any{
			"config": map[string]any{"dns": map[string]any{"hosts": append([]string{}, s.hosts...)}},
			"took":   0.01,
		})
		return http.StatusOK, resp

	case method == http.MethodPut && strings.Contains(path, hostsPrefix+"/"):
		entry, ok := entryFromPath(path)
		if !ok {
			return badRequest("Invalid value", "could not decode item")
		}
		// Validation order mirrors the captured API: value must be an IP, hostname
		// must be a plain name (no wildcard/metachars), and the exact string must
		// be unique. Same host + different IP is ACCEPTED (captured 201).
		fields := strings.Fields(entry)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			return badRequest("Invalid value",
				fmt.Sprintf("dns.hosts[%d]: neither a valid IPv4 nor IPv6 address (%q)", len(s.hosts), entry))
		}
		if strings.ContainsAny(fields[1], "*/") {
			return badRequest("Invalid value",
				fmt.Sprintf("dns.hosts[%d]: invalid hostname (%q)", len(s.hosts), fields[1]))
		}
		for _, h := range s.hosts {
			if h == entry {
				return badRequest("Item already present", "Uniqueness of items is enforced")
			}
		}
		s.hosts = append(s.hosts, entry)
		s.Puts++
		return http.StatusCreated, []byte(`{"took":0.01}`)

	case method == http.MethodDelete && strings.Contains(path, hostsPrefix+"/"):
		entry, ok := entryFromPath(path)
		if !ok {
			return badRequest("Invalid value", "could not decode item")
		}
		for i, h := range s.hosts {
			if h == entry {
				s.hosts = append(s.hosts[:i], s.hosts[i+1:]...)
				s.Deletes++
				return http.StatusNoContent, nil
			}
		}
		// Captured: deleting an absent entry answers 404 {"took":...}.
		return http.StatusNotFound, []byte(`{"took":0.01}`)

	default:
		return http.StatusNotFound, []byte(`{"error":{"key":"not_found","message":"Not found","hint":null},"took":0.01}`)
	}
}

// entryFromPath extracts and url-decodes the "IP host" entry from an
// entry-addressed path like /api/config/dns/hosts/10.0.0.5%20grafana....
func entryFromPath(path string) (string, bool) {
	i := strings.Index(path, hostsPrefix+"/")
	if i < 0 {
		return "", false
	}
	raw := path[i+len(hostsPrefix)+1:]
	entry, err := url.PathUnescape(raw)
	if err != nil || entry == "" {
		return "", false
	}
	return entry, true
}

// List returns a snapshot of the current entries as host->IP pairs (for assertions).
func (s *Server) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, line := range s.hosts {
		if fields := strings.Fields(line); len(fields) >= 2 {
			out[fields[1]] = fields[0]
		}
	}
	return out
}

// Count returns the number of live entries.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hosts)
}
