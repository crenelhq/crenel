package dnscontrolfake

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

var zoneRE = regexp.MustCompile(`D\("([^"]+)"`)

// parseConfigFile reads dir/dnsconfig.js and reconstructs the records it declares,
// INCLUDING the TTL(n) + CF_PROXY_ON fidelity modifiers. Parsed line-by-line so the
// trailing modifiers (which contain their own parens) round-trip. It is the fake's
// "adapter": it understands exactly the dialect renderConfigJS emits.
func parseConfigFile(dir string) []model.Record {
	b, err := os.ReadFile(filepath.Join(dir, "dnsconfig.js"))
	if err != nil {
		return nil
	}
	content := string(b)

	zone := ""
	if m := zoneRE.FindStringSubmatch(content); m != nil {
		zone = m[1]
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
	return recs
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
