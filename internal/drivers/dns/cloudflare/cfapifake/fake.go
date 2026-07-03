// Package cfapifake is a FAITHFUL in-repo fake of the Cloudflare REST API (v4) DNS
// surface that the surgical cloudflare driver drives.
//
// It is two things at once:
//   - a cloudflare.Doer (used directly in driver tests — no socket), and
//   - an http.Handler (wrap it in httptest to exercise the REAL cloudflare.OSDoer,
//     including the Bearer-token auth header, over loopback).
//
// It REJECTS what the real Cloudflare API rejects — a bad/absent token (403/10000), a
// non-IPv4 A content (400/9005), an identical-duplicate record (409/81058), an A/CNAME
// type collision at one name (400/81053), an unknown record id on PUT/DELETE
// (404/81044), and rate limiting (429/971) — so tests prove Crenel handles the real
// failure surface, not a happy path. No real Cloudflare endpoint is ever contacted.
//
// Crucially, it does NOT itself enforce crenel's OWNERSHIP marker: real Cloudflare
// would happily let a token overwrite or delete ANY record in its zone, marker or not.
// That a foreign record is never touched is the DRIVER's guarantee — tests assert the
// foreign records in this fake are byte-identical before/after, and that no mutating
// call ever reaches a foreign id.
package cfapifake

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Record is the Cloudflare API record shape the fake stores and serves.
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

// Server is a faithful fake of the Cloudflare DNS API for one zone.
type Server struct {
	mu sync.Mutex

	zoneID   string
	zoneName string
	records  []Record
	nextID   int

	// AcceptToken, when set, is the only Bearer token that authenticates on the HTTP
	// (ServeHTTP) path. Empty => any non-empty token authenticates. Direct Doer calls
	// carry no header, so they are governed by the Unauthorized knob instead.
	AcceptToken string
	// Unauthorized forces 403 on every call (models a server-side auth rejection on the
	// header-less Doer path). RateLimited forces 429.
	Unauthorized bool
	RateLimited  bool

	// Counters for assertions.
	Creates int
	Updates int
	Deletes int
	// Touched records every record id that a PUT or DELETE was issued against — so a
	// test can assert NO foreign id was ever the target of a mutation.
	Touched []string
}

// New builds a fake for the given zone, seeded with foreign/pre-existing records (the
// caller supplies their Comment — leave it empty for a genuinely foreign record).
func New(zoneName, zoneID string, seed ...Record) *Server {
	s := &Server{zoneName: normName(zoneName), zoneID: zoneID}
	if s.zoneID == "" {
		s.zoneID = "zone-" + s.zoneName
	}
	for _, r := range seed {
		s.nextID++
		if r.ID == "" {
			r.ID = fmt.Sprintf("rec%03d", s.nextID)
		}
		r.Name = normName(r.Name)
		r.Type = strings.ToUpper(r.Type)
		if r.TTL == 0 {
			r.TTL = 1
		}
		s.records = append(s.records, r)
	}
	return s
}

// Do implements cloudflare.Doer (the header-less, socket-free path).
func (s *Server) Do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	status, resp := s.handle(method, path, body, true /* authed: no header to check here */)
	return status, resp, nil
}

// ServeHTTP implements http.Handler (the loopback path that exercises real OSDoer
// Bearer auth).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	authed := s.checkBearer(r)
	status, resp := s.handle(r.Method, r.URL.RequestURI(), body, authed)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

func (s *Server) checkBearer(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return false
	}
	if s.AcceptToken == "" {
		return true // any non-empty token authenticates
	}
	return tok == s.AcceptToken
}

func (s *Server) handle(method, rawpath string, body []byte, authed bool) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Unauthorized || !authed {
		return s.fail(http.StatusForbidden, 10000, "Authentication error")
	}
	if s.RateLimited {
		return s.fail(http.StatusTooManyRequests, 971, "More than 1200 requests per 300 seconds")
	}

	u, err := url.Parse(rawpath)
	if err != nil {
		return s.fail(http.StatusBadRequest, 0, "bad path")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")

	switch {
	// GET /zones?name=
	case method == http.MethodGet && len(parts) == 1 && parts[0] == "zones":
		return s.listZones(u.Query().Get("name"))
	// GET/POST /zones/{id}/dns_records
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records":
		if parts[1] != s.zoneID {
			return s.fail(http.StatusNotFound, 7003, "Could not route to zone")
		}
		switch method {
		case http.MethodGet:
			return s.listRecords(u.Query())
		case http.MethodPost:
			return s.createRecord(body)
		}
	// PUT/DELETE /zones/{id}/dns_records/{recID}
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records":
		if parts[1] != s.zoneID {
			return s.fail(http.StatusNotFound, 7003, "Could not route to zone")
		}
		switch method {
		case http.MethodPut:
			return s.updateRecord(parts[3], body)
		case http.MethodDelete:
			return s.deleteRecord(parts[3])
		}
	}
	return s.fail(http.StatusNotFound, 7000, "No route for that URI")
}

func (s *Server) listZones(name string) (int, []byte) {
	var result []map[string]string
	if normName(name) == s.zoneName || name == "" {
		result = []map[string]string{{"id": s.zoneID, "name": s.zoneName}}
	}
	return ok(result, &resultInfo{Page: 1, PerPage: 50, Count: len(result), TotalCount: len(result), TotalPages: 1})
}

func (s *Server) listRecords(q url.Values) (int, []byte) {
	perPage := atoiDefault(q.Get("per_page"), 100)
	page := atoiDefault(q.Get("page"), 1)
	// Apply optional name/type filters the real API supports (driver doesn't use them,
	// but model them for fidelity).
	var filtered []Record
	for _, r := range s.records {
		if n := q.Get("name"); n != "" && normName(n) != normName(r.Name) {
			continue
		}
		if t := q.Get("type"); t != "" && strings.ToUpper(t) != r.Type {
			continue
		}
		filtered = append(filtered, r)
	}
	total := len(filtered)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	pageRecs := append([]Record(nil), filtered[start:end]...)
	return ok(pageRecs, &resultInfo{Page: page, PerPage: perPage, Count: len(pageRecs), TotalCount: total, TotalPages: totalPages})
}

func (s *Server) createRecord(body []byte) (int, []byte) {
	var in Record
	if err := json.Unmarshal(body, &in); err != nil || in.Type == "" || in.Name == "" || in.Content == "" {
		return s.fail(http.StatusBadRequest, 1004, "DNS Validation Error")
	}
	in.Name = normName(in.Name)
	in.Type = strings.ToUpper(in.Type)
	if msg, code, bad := validate(in); bad {
		return s.fail(http.StatusBadRequest, code, msg)
	}
	// A/CNAME collision: a CNAME cannot coexist with any other record at the same name.
	for _, r := range s.records {
		if normName(r.Name) != in.Name {
			continue
		}
		if (in.Type == "CNAME" && r.Type != "CNAME") || (r.Type == "CNAME" && in.Type != "CNAME") {
			return s.fail(http.StatusBadRequest, 81053, "An A, AAAA, or CNAME record with that host already exists")
		}
		// Identical duplicate.
		if r.Type == in.Type && strings.EqualFold(r.Content, in.Content) {
			return s.fail(http.StatusConflict, 81058, "An identical record already exists")
		}
	}
	s.nextID++
	in.ID = fmt.Sprintf("rec%03d", s.nextID)
	if in.TTL == 0 {
		in.TTL = 1
	}
	s.records = append(s.records, in)
	s.Creates++
	return ok(in, nil)
}

func (s *Server) updateRecord(id string, body []byte) (int, []byte) {
	s.Touched = append(s.Touched, id)
	idx := s.indexOf(id)
	if idx < 0 {
		return s.fail(http.StatusNotFound, 81044, "Record does not exist")
	}
	var in Record
	if err := json.Unmarshal(body, &in); err != nil || in.Type == "" || in.Content == "" {
		return s.fail(http.StatusBadRequest, 1004, "DNS Validation Error")
	}
	in.Name = normName(in.Name)
	in.Type = strings.ToUpper(in.Type)
	if msg, code, bad := validate(in); bad {
		return s.fail(http.StatusBadRequest, code, msg)
	}
	in.ID = id
	if in.TTL == 0 {
		in.TTL = 1
	}
	s.records[idx] = in
	s.Updates++
	return ok(in, nil)
}

func (s *Server) deleteRecord(id string) (int, []byte) {
	s.Touched = append(s.Touched, id)
	idx := s.indexOf(id)
	if idx < 0 {
		return s.fail(http.StatusNotFound, 81044, "Record does not exist")
	}
	s.records = append(s.records[:idx], s.records[idx+1:]...)
	s.Deletes++
	return ok(map[string]string{"id": id}, nil)
}

// --- snapshot / assertion helpers ---

// Records returns a sorted snapshot of all records (for byte-identical before/after
// comparison). Sorted by id for determinism.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Record(nil), s.records...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Snapshot returns a stable JSON encoding of all records (for an exact diff in tests).
func (s *Server) Snapshot() string {
	b, _ := json.MarshalIndent(s.Records(), "", "  ")
	return string(b)
}

// ZoneID exposes the fake's zone id (for constructing a driver with a pre-known id).
func (s *Server) ZoneID() string { return s.zoneID }

func (s *Server) indexOf(id string) int {
	for i, r := range s.records {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// --- envelope helpers ---

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type envelope struct {
	Success    bool        `json:"success"`
	Errors     []apiErr    `json:"errors"`
	Messages   []string    `json:"messages"`
	Result     interface{} `json:"result"`
	ResultInfo *resultInfo `json:"result_info,omitempty"`
}

type apiErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func ok(result interface{}, info *resultInfo) (int, []byte) {
	b, _ := json.Marshal(envelope{Success: true, Errors: []apiErr{}, Messages: []string{}, Result: result, ResultInfo: info})
	return http.StatusOK, b
}

func (s *Server) fail(status, code int, msg string) (int, []byte) {
	b, _ := json.Marshal(envelope{Success: false, Errors: []apiErr{{Code: code, Message: msg}}, Messages: []string{}})
	return status, b
}

// validate mirrors the Cloudflare content validation crenel cares about.
func validate(r Record) (msg string, code int, bad bool) {
	switch r.Type {
	case "A":
		if ip := net.ParseIP(r.Content); ip == nil || ip.To4() == nil {
			return "Content for A record is invalid. Must be a valid IPv4 address", 9005, true
		}
	case "AAAA":
		if ip := net.ParseIP(r.Content); ip == nil || ip.To4() != nil {
			return "Content for AAAA record is invalid. Must be a valid IPv6 address", 9005, true
		}
	}
	// Cloudflare requires a PROXIED record to use TTL=auto (1); any other TTL is rejected.
	// TTL 0 is treated as auto (the API default), so only an explicit non-1 TTL is bad.
	if r.Proxied && r.TTL != 0 && r.TTL != 1 {
		return "TTL must be set to 1 (automatic) for proxied records", 9207, true
	}
	return "", 0, false
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
