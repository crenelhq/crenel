package caddy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// renderCaddyfile produces the managed Caddyfile text for a desired set of
// routes. The catch-all default-deny block is ALWAYS emitted last — this is the
// structural enforcement of the default-deny invariant: there is no code path
// that renders a managed config without it.
func renderCaddyfile(routes []model.Route) string {
	sorted := append([]model.Route(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })

	var b strings.Builder
	b.WriteString("# crenel-managed v1 — do not hand-edit\n")
	for _, r := range sorted {
		b.WriteString(fmt.Sprintf("%s {\n\treverse_proxy %s\n}\n", r.Host, r.Upstream.Address))
	}
	// Catch-all default-deny: a host-less site block that denies everything not
	// explicitly exposed above. Always present.
	b.WriteString(fmt.Sprintf("%s {\n\trespond %d\n}\n", defaultListen, denyStatusCode))
	return b.String()
}

// targetRoutes applies an EdgeChange to a live route set, returning the desired
// route set after the change.
func targetRoutes(live model.LiveEdgeState, ec model.EdgeChange) []model.Route {
	remove := make(map[string]bool, len(ec.RemoveHosts))
	for _, h := range ec.RemoveHosts {
		remove[strings.ToLower(h)] = true
	}
	var out []model.Route
	for _, r := range live.Routes {
		// Passthrough (layer4) routes live in a different app and are rendered
		// separately; the full-load http renderer must not emit them as reverse_proxy.
		if r.Upstream.Mode == model.ModeTCPPassthrough {
			continue
		}
		if !remove[strings.ToLower(r.Host)] {
			out = append(out, r)
		}
	}
	out = append(out, ec.AddRoutes...)
	return out
}
