// Package adguardfake is a FAITHFUL in-repo fake of the AdGuard Home control API.
//
// It is two things at once:
//   - an adguard.Doer (used directly in driver tests — no socket), and
//   - an http.Handler (wrap it in httptest to exercise the REAL adguard.OSDoer,
//     including Basic-auth, over loopback).
//
// It REJECTS what the real control API rejects — bad/absent Basic auth (401), a
// duplicate rewrite add (400), rate limiting (429), and malformed bodies (400) — so
// tests prove Crenel handles the real failure surface. No real AdGuard is contacted.
//
// Note the ONE thing it does NOT reject: an out-of-zone domain. Real AdGuard happily
// accepts a rewrite for ANY domain (it has no zone concept) — that is precisely the
// hijack trap the driver's zone guardrail exists to prevent. Tests assert the driver
// refuses such a domain BEFORE any add reaches this fake (Adds stays 0).
package adguardfake

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

type rw struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// Server is a faithful fake of the AdGuard control API.
type Server struct {
	mu       sync.Mutex
	rewrites []rw

	// User/Pass, when set, are the Basic-auth credentials required on the HTTP
	// (ServeHTTP) path. Direct Doer calls carry no header, so they are governed by
	// the Unauthorized knob instead.
	User string
	Pass string

	// Unauthorized forces 401 on every call (models a server-side auth rejection on
	// the header-less Doer path). RateLimited forces 429. RejectDuplicate (default
	// true) makes an exact-duplicate add return 400, matching recent AdGuard.
	Unauthorized    bool
	RateLimited     bool
	RejectDuplicate bool

	// Counters for assertions.
	Adds    int
	Deletes int
}

// New builds a fake seeded with domain->answer rewrites (pass "domain", "answer"
// pairs). RejectDuplicate defaults to true.
func New(seed ...string) *Server {
	s := &Server{RejectDuplicate: true}
	for i := 0; i+1 < len(seed); i += 2 {
		s.rewrites = append(s.rewrites, rw{Domain: seed[i], Answer: seed[i+1]})
	}
	return s
}

// Do implements adguard.Doer (the header-less, socket-free path).
func (s *Server) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	status, resp := s.handle(method, path, body, true /* authed: no header to check here */)
	return status, resp, nil
}

// ServeHTTP implements http.Handler (the loopback path that exercises real OSDoer
// Basic auth).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	authed := s.checkBasic(r)
	status, resp := s.handle(r.Method, r.URL.Path, body, authed)
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

func (s *Server) checkBasic(r *http.Request) bool {
	if s.User == "" && s.Pass == "" {
		return true // no creds required
	}
	u, p, ok := r.BasicAuth()
	return ok && u == s.User && p == s.Pass
}

func (s *Server) handle(method, path string, body []byte, authed bool) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Unauthorized || !authed {
		return http.StatusUnauthorized, []byte("Unauthorized\n")
	}
	if s.RateLimited {
		return http.StatusTooManyRequests, []byte("Too Many Requests\n")
	}

	switch {
	case method == http.MethodGet && strings.HasSuffix(path, "/control/rewrite/list"):
		out, _ := json.Marshal(s.rewrites)
		return http.StatusOK, out
	case method == http.MethodPost && strings.HasSuffix(path, "/control/rewrite/add"):
		var e rw
		if err := json.Unmarshal(body, &e); err != nil || e.Domain == "" || e.Answer == "" {
			return http.StatusBadRequest, []byte("bad rewrite request\n")
		}
		if s.RejectDuplicate {
			for _, x := range s.rewrites {
				if strings.EqualFold(x.Domain, e.Domain) && x.Answer == e.Answer {
					return http.StatusBadRequest, []byte("rewrite already exists\n")
				}
			}
		}
		s.rewrites = append(s.rewrites, e)
		s.Adds++
		return http.StatusOK, []byte("{}")
	case method == http.MethodPost && strings.HasSuffix(path, "/control/rewrite/delete"):
		var e rw
		if err := json.Unmarshal(body, &e); err != nil || e.Domain == "" {
			return http.StatusBadRequest, []byte("bad rewrite request\n")
		}
		kept := s.rewrites[:0]
		for _, x := range s.rewrites {
			if strings.EqualFold(x.Domain, e.Domain) && x.Answer == e.Answer {
				s.Deletes++
				continue
			}
			kept = append(kept, x)
		}
		s.rewrites = append([]rw(nil), kept...)
		return http.StatusOK, []byte("{}")
	default:
		return http.StatusNotFound, []byte("not found\n")
	}
}

// List returns a snapshot of the current rewrites as domain->answer pairs (for
// assertions).
func (s *Server) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, x := range s.rewrites {
		out[x.Domain] = x.Answer
	}
	return out
}

// Count returns the number of live rewrites.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rewrites)
}
