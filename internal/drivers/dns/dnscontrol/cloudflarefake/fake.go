// Package cloudflarefake is a FAITHFUL in-repo fake of `dnscontrol` driving the
// Cloudflare API (CLOUDFLAREAPI). It implements dnscontrol.Shell, so it slots in
// exactly where the real OSShell would, but it REJECTS what the real Cloudflare API
// rejects — bad token, a zone the token can't see, an A/CNAME conflict, non-IP A
// content, and rate limiting — so tests prove Crenel handles the real failure
// surface, not a happy path. No real Cloudflare endpoint is ever contacted.
//
// It reads the same throwaway dir the driver hands the real shell: creds.json (the
// token) and dnsconfig.js (the desired zone). It understands exactly the dialect
// dnscontrol/render.go emits.
package cloudflarefake

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/crenelhq/crenel/internal/model"
)

// Shell is a faithful fake Cloudflare-via-dnscontrol shell.
type Shell struct {
	mu sync.Mutex

	// AcceptToken is the only API token that authenticates. Empty => any NON-EMPTY
	// token authenticates (an empty/missing token always fails, like the real API).
	AcceptToken string
	// RateLimited, when true, makes every API-touching call return a 429-style error
	// (Cloudflare code 971), until cleared.
	RateLimited bool
	// Pushes counts successful pushes (for assertions).
	Pushes int

	zone string                  // the single zone this account owns
	live map[string]model.Record // key -> record, the live zone state
}

// New builds a faithful Cloudflare fake whose account owns zone, optionally seeded
// with live records.
func New(zone string, seed ...model.Record) *Shell {
	s := &Shell{zone: strings.TrimSuffix(zone, "."), live: map[string]model.Record{}}
	for _, r := range seed {
		s.live[r.Key()] = r
	}
	return s
}

// recRE matches the record CALL PREFIX up to the {"scope":…} map (no closing paren), so
// trailing fidelity modifiers (`, TTL(300)`, `, CF_PROXY_ON`) don't break the match.
var recRE = regexp.MustCompile(`(\w+)\("([^"]+)",\s*"([^"]+)",\s*\{"scope":"([^"]+)"\}`)
var ttlRE = regexp.MustCompile(`TTL\((\d+)\)`)
var zoneRE = regexp.MustCompile(`D\("([^"]+)"`)

func (s *Shell) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("cloudflarefake: no command")
	}
	if err := ctx.Err(); err != nil { // honor cancellation like a real exec.
		return "", err
	}
	// Auth FIRST: the real Cloudflare API authenticates the bearer token before any
	// other check, so a bad/absent token always yields 10000 regardless of rate-limit
	// state. creds.json is present for reads AND writes when a real provider is wired.
	if err := s.checkAuth(dir); err != nil {
		return "", err
	}
	if s.RateLimited {
		return "", fmt.Errorf("cloudflare API error: Rate limited. (Code: 971) — More than 1200 requests per 300 seconds")
	}

	switch args[0] {
	case "get-zones":
		if err := s.checkZoneArg(args); err != nil {
			return "", err
		}
		return s.getZones(), nil
	case "preview", "push":
		desired, zone, err := s.readDesired(dir)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(zone, s.zone) {
			return "", zoneMismatch(zone)
		}
		if err := s.validate(desired); err != nil {
			return "", err
		}
		if args[0] == "preview" {
			return s.diffText(desired), nil
		}
		s.apply(desired)
		return "pushed", nil
	default:
		return "", fmt.Errorf("cloudflarefake: unknown command %q", args[0])
	}
}

// checkAuth reads creds.json and validates the Cloudflare token.
func (s *Shell) checkAuth(dir string) error {
	tok := readToken(dir)
	if tok == "" {
		return fmt.Errorf("cloudflare API error: Invalid request headers (Code: 10000) — missing or empty API token")
	}
	if s.AcceptToken != "" && tok != s.AcceptToken {
		return fmt.Errorf("cloudflare API error: Invalid request headers (Code: 10000) — Authentication error")
	}
	return nil
}

// checkZoneArg validates the zone positional of a get-zones invocation
// (`get-zones --format=tsv <credkey> <provider> <zone>`): the last arg.
func (s *Shell) checkZoneArg(args []string) error {
	zone := strings.TrimSuffix(args[len(args)-1], ".")
	if !strings.EqualFold(zone, s.zone) {
		return zoneMismatch(zone)
	}
	return nil
}

// validate enforces the Cloudflare record constraints dnscontrol surfaces:
//   - an A/AAAA and a CNAME cannot coexist at the same name (CF code 81053);
//   - an A record value must be a valid IP (CF code 9005 / 1004).
func (s *Shell) validate(desired []model.Record) error {
	byName := map[string][]model.Record{}
	for _, r := range desired {
		n := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		byName[n] = append(byName[n], r)
		if strings.EqualFold(r.Type, "A") {
			if ip := net.ParseIP(r.Value); ip == nil || ip.To4() == nil {
				return fmt.Errorf("cloudflare API error: Content for A record is invalid (Code: 9005) — %q is not an IPv4 address", r.Value)
			}
		}
	}
	for name, recs := range byName {
		hasCNAME, hasOther := false, false
		for _, r := range recs {
			if strings.EqualFold(r.Type, "CNAME") {
				hasCNAME = true
			} else {
				hasOther = true
			}
		}
		if hasCNAME && hasOther {
			return fmt.Errorf("cloudflare API error: An A, AAAA, or CNAME record with that host already exists. (Code: 81053) — %s", name)
		}
	}
	return nil
}

// getZones emits the REAL dnscontrol `get-zones --format=tsv` layout
// (NameFQDN, ShortName, TTL, IN, Type, Target [, Properties]) so parseTSV is exercised
// against the true shape; the optional Properties column carries `cloudflare_proxy=true`.
func (s *Shell) getZones() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, r := range sortedRecords(s.live) {
		ttl := r.TTL
		if ttl == 0 {
			ttl = 1 // auto
		}
		props := ""
		if r.Proxied {
			props = "\tcloudflare_proxy=true"
		}
		fmt.Fprintf(&b, "%s\t%s\t%d\tIN\t%s\t%s%s\n", r.Name, shortName(r.Name, s.zone), ttl, r.Type, r.Value, props)
	}
	return b.String()
}

// shortName returns the zone-relative label dnscontrol prints in TSV col 1 ("@" for
// apex). Crenel reads the FQDN (col 0), so this is faithfulness only.
func shortName(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if strings.EqualFold(fqdn, zone) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(zone)) {
		return fqdn[:len(fqdn)-len(zone)-1]
	}
	return fqdn
}

func (s *Shell) apply(desired []model.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live = map[string]model.Record{}
	for _, r := range desired {
		s.live[r.Key()] = r
	}
	s.Pushes++
}

func (s *Shell) diffText(desired []model.Record) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]model.Record{}
	for _, r := range desired {
		want[r.Key()] = r
	}
	var b strings.Builder
	for k, r := range want {
		if _, ok := s.live[k]; !ok {
			fmt.Fprintf(&b, "+ CREATE %s %s %s\n", r.Name, r.Type, r.Value)
		}
	}
	for k, r := range s.live {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "- DELETE %s %s %s\n", r.Name, r.Type, r.Value)
		}
	}
	if b.Len() == 0 {
		return "No changes.\n"
	}
	return b.String()
}

// LiveCount returns the number of live records (for assertions).
func (s *Shell) LiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

func zoneMismatch(zone string) error {
	return fmt.Errorf("cloudflare: could not find zone %q in account (the token cannot manage it)", zone)
}

// readDesired parses dir/dnsconfig.js into the desired record set + zone.
func (s *Shell) readDesired(dir string) ([]model.Record, string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "dnsconfig.js"))
	if err != nil {
		return nil, "", fmt.Errorf("cloudflarefake: read dnsconfig.js: %w", err)
	}
	content := string(b)
	zone := ""
	if m := zoneRE.FindStringSubmatch(content); m != nil {
		zone = strings.TrimSuffix(m[1], ".")
	}
	var recs []model.Record
	for _, line := range strings.Split(content, "\n") {
		m := recRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rec := model.Record{
			Name:  expandFQDN(m[2], zone),
			Type:  m[1],
			Value: m[3],
			Scope: scopeFromTag(m[4]),
		}
		if tm := ttlRE.FindStringSubmatch(line); tm != nil {
			rec.TTL, _ = strconv.Atoi(tm[1])
		}
		if strings.Contains(line, "CF_PROXY_ON") {
			rec.Proxied = true
		}
		recs = append(recs, rec)
	}
	return recs, zone, nil
}

// readToken extracts the apitoken from dir/creds.json (the first provider entry).
func readToken(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "creds.json"))
	if err != nil {
		return ""
	}
	var doc map[string]map[string]string
	if err := json.Unmarshal(b, &doc); err != nil {
		return ""
	}
	for _, entry := range doc {
		for _, key := range []string{"apitoken", "apikey", "token", "api_token"} {
			if v := entry[key]; v != "" {
				return v
			}
		}
	}
	return ""
}

func expandFQDN(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if name == "@" || name == "" {
		return zone
	}
	if zone != "" && strings.HasSuffix(strings.ToLower(name), strings.ToLower(zone)) {
		return name
	}
	if zone == "" {
		return name
	}
	return name + "." + zone
}

func scopeFromTag(tag string) model.Scope {
	if tag == "!outside" {
		return model.ScopePublic
	}
	return model.ScopeInternal
}

func sortedRecords(m map[string]model.Record) []model.Record {
	out := make([]model.Record, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
