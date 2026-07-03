// Package dnscontrolfake is an in-repo fake of the dnscontrol shell for tests.
//
// It models a provider's live DNS state in memory. `push` reads the generated
// dnsconfig.js from the working dir and replaces the zone's live records with
// it; `get-zones` dumps live records as TSV; `preview` reports a textual diff.
// No real DNS provider is ever contacted.
package dnscontrolfake

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/crenelhq/crenel/internal/model"
)

// Shell is a fake dnscontrol shell holding live records keyed by record Key().
type Shell struct {
	mu   sync.Mutex
	live map[string]model.Record
	zone string

	// FailPush, when true, makes push return an error.
	FailPush bool
	// Pushes counts successful pushes (for assertions).
	Pushes int
}

// New builds a fake shell for zone, optionally seeded with records.
func New(zone string, seed ...model.Record) *Shell {
	s := &Shell{live: map[string]model.Record{}, zone: zone}
	for _, r := range seed {
		s.live[r.Key()] = r
	}
	return s
}

// recRE matches the record CALL PREFIX up to the {"scope":…} map (no closing paren), so
// optional trailing modifiers — `, TTL(300)`, `, CF_PROXY_ON` — don't break the match.
var recRE = regexp.MustCompile(`(\w+)\("([^"]+)",\s*"([^"]+)",\s*\{"scope":"([^"]+)"\}`)
var ttlRE = regexp.MustCompile(`TTL\((\d+)\)`)

func (s *Shell) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("dnscontrolfake: no command")
	}
	switch args[0] {
	case "get-zones":
		return s.getZones(), nil
	case "preview":
		return s.diffText(readConfig(dir)), nil
	case "push":
		if s.FailPush {
			return "push failed", fmt.Errorf("dnscontrolfake: push error")
		}
		s.applyConfig(readConfig(dir))
		return "pushed", nil
	default:
		return "", fmt.Errorf("dnscontrolfake: unknown command %q", args[0])
	}
}

// getZones emits the REAL dnscontrol `get-zones --format=tsv` layout:
//
//	NameFQDN \t ShortName \t TTL \t IN \t Type \t Target [\t Properties]
//
// matching the binary so parseTSV is exercised against the true shape. The optional
// Properties column carries Cloudflare's proxied state as `cloudflare_proxy=true`.
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

func (s *Shell) applyConfig(records []model.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live = map[string]model.Record{}
	for _, r := range records {
		s.live[r.Key()] = r
	}
	s.Pushes++
}

func (s *Shell) diffText(desired []model.Record) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	desiredSet := map[string]model.Record{}
	for _, r := range desired {
		desiredSet[r.Key()] = r
	}
	var b strings.Builder
	for k, r := range desiredSet {
		if _, ok := s.live[k]; !ok {
			fmt.Fprintf(&b, "+ CREATE %s %s %s\n", r.Name, r.Type, r.Value)
		}
	}
	for k, r := range s.live {
		if _, ok := desiredSet[k]; !ok {
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

// readConfig is overridden via the file the driver wrote. Because the fake does
// not have the dir contents without reading the file, we re-parse dnsconfig.js.
var readConfig = func(dir string) []model.Record {
	return parseConfigFile(dir)
}

func sortedRecords(m map[string]model.Record) []model.Record {
	out := make([]model.Record, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
