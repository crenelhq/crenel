package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// This file implements ports.LocatorAcker for the Caddy driver: acking a
// declared-unknown route by the STRUCTURAL PATH (model.Unparsed.Locator) the
// read side reported for it, instead of by host. It exists because the routes
// that most need acking — a brownfield operator's host-less carve-outs, the
// `routes[1].handle[subroute].routes[5]` shapes a first audit flags — often
// have NO recoverable host, so Ack/ackWalk (host-addressed, first-match)
// cannot reach them at all. The locator grammar here mirrors EXACTLY how
// normalizeServer/collectLeaves mint locators on read:
//
//	apps.http.servers.<server>.routes[i](.handle[subroute].routes[j])*
//
// so an operator (or `crenel triage`) can paste an audit/status locator back
// verbatim. Descent at each level enters the FIRST subroute handler — the same
// rule as JSONRoute.subroutes(), which is what produced the locator — while the
// PATCH path records the handler's REAL index so unmodeled sibling handlers are
// never disturbed.

// ackLocatorPrefix is the fixed head of every route locator this driver mints.
const ackLocatorPrefix = "apps.http.servers."

// parseLocator splits a route locator into its server key and the chain of
// route indexes (one per nesting level). It rejects anything that is not a
// ROUTE locator — e.g. the whole-sibling-server form "apps.http.servers.<key>"
// (no routes[...] step), which has no single route to stamp.
func parseLocator(locator string) (server string, idxs []int, err error) {
	rest, ok := strings.CutPrefix(locator, ackLocatorPrefix)
	if !ok {
		return "", nil, fmt.Errorf("locator %q is not a caddy route locator (want %s<server>.routes[i]...)", locator, ackLocatorPrefix)
	}
	server, rest, ok = strings.Cut(rest, ".routes[")
	if !ok || server == "" {
		return "", nil, fmt.Errorf("locator %q addresses a whole server block, not a single route — path-addressed ack needs a routes[i] step", locator)
	}
	// rest now starts inside the first bracket: "1].handle[subroute].routes[5]".
	for {
		numStr, tail, ok := strings.Cut(rest, "]")
		if !ok {
			return "", nil, fmt.Errorf("locator %q: unterminated routes[ index", locator)
		}
		n, cerr := strconv.Atoi(numStr)
		if cerr != nil || n < 0 {
			return "", nil, fmt.Errorf("locator %q: bad route index %q", locator, numStr)
		}
		idxs = append(idxs, n)
		if tail == "" {
			return server, idxs, nil
		}
		// The only legal continuation is one subroute descent step.
		tail, ok = strings.CutPrefix(tail, ".handle[subroute].routes[")
		if !ok {
			return "", nil, fmt.Errorf("locator %q: unexpected trailing %q (want .handle[subroute].routes[j])", locator, tail)
		}
		rest = tail
	}
}

// locatorQualifier renders the marker qualifier for a path-addressed ack:
// the locator with its fixed prefix stripped and every character outside the
// marker grammar's qualifier charset ([a-z0-9.*-], see model.ParseAckMarker)
// folded to '-' ('[' → '-', ']' dropped, case lowered). Example:
//
//	apps.http.servers.srv0.routes[1].handle[subroute].routes[5]
//	→ srv0.routes-1.handle-subroute.routes-5
//
// The qualifier is unique per route position (the locator is), so two
// path-acked routes never collide on Caddy's GLOBAL @id index — the same
// property AckMarkerFor's host qualifier provides for host-addressed acks.
func locatorQualifier(locator string) string {
	s := strings.ToLower(strings.TrimPrefix(locator, ackLocatorPrefix))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '*':
			b.WriteRune(r)
		case r == ']':
			// drop — the preceding '[' already became the separator
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// locatorMarker is the full @id stamped by AckLocator:
// crenel-ack:<qualifier>:<reason>. It parses under model.ParseAckMarker's
// host-qualified grammar (the qualifier charset is a superset of a hostname's),
// so the READ side needs no changes — ackAware classifies it acknowledged
// exactly like a host-qualified marker.
func locatorMarker(locator, reason string) string {
	return model.AckMarkerPrefix + locatorQualifier(locator) + ":" + reason
}

// resolveLocator navigates the RAW config (unmodeled fields intact, like
// Adopt/ackWalk) to the route a locator addresses. It returns the raw route
// map and the admin-API PATCH path for it. Descent mirrors subroutes():
// the locator's ".handle[subroute]" step means "the FIRST subroute handler",
// but the returned path uses that handler's real index.
func resolveLocator(cfg map[string]any, locator string) (rm map[string]any, patchPath string, err error) {
	server, idxs, err := parseLocator(locator)
	if err != nil {
		return nil, "", err
	}
	routes := rawRoutes(cfg, server)
	path := fmt.Sprintf("/config/apps/http/servers/%s/routes", server)
	for depth, i := range idxs {
		if i >= len(routes) {
			return nil, "", fmt.Errorf("locator %q: routes[%d] does not exist in the live config (only %d route(s) at this level) — the config may have changed since the audit; re-run and use a fresh locator", locator, i, len(routes))
		}
		m, ok := routes[i].(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("locator %q: routes[%d] is not a route object", locator, i)
		}
		path = fmt.Sprintf("%s/%d", path, i)
		rm = m
		if depth == len(idxs)-1 {
			break
		}
		// Descend into the FIRST subroute handler — the read-side rule that
		// minted the ".handle[subroute]" step (JSONRoute.subroutes()).
		descended := false
		handlers, _ := m["handle"].([]any)
		for hidx, h := range handlers {
			hm, ok := h.(map[string]any)
			if !ok || hm["handler"] != handlerSubroute {
				continue
			}
			routes, _ = hm["routes"].([]any)
			path = fmt.Sprintf("%s/handle/%d/routes", path, hidx)
			descended = true
			break
		}
		if !descended {
			return nil, "", fmt.Errorf("locator %q: routes[%d] has no subroute handler to descend into — the config may have changed since the audit", locator, i)
		}
	}
	return rm, path, nil
}

// AckLocator stamps the crenel-ack:<qualifier>:<reason> marker onto the route
// at locator via PATCH — same match/handlers/backend, only the @id changes —
// then settles. Idempotent (exact re-ack is a no-op); refuses a crenel-managed
// route (its @id is the OWNERSHIP marker, which means something else).
// Implements ports.LocatorAcker.
func (d *Driver) AckLocator(ctx context.Context, locator, reason string) error {
	return d.patchLocatorID(ctx, locator, locatorMarker(locator, reason))
}

// UnackLocator removes any crenel-ack marker (host-qualified, path-qualified,
// or legacy bare) from the route at locator, reverting it to whatever Unparsed
// kind it would otherwise classify as. A no-op if the route is not currently
// ack'd. Implements ports.LocatorAcker.
func (d *Driver) UnackLocator(ctx context.Context, locator string) error {
	return d.patchLocatorID(ctx, locator, "")
}

// patchLocatorID is the shared write path for AckLocator/UnackLocator: resolve
// the locator against the live raw config, adjust the route's @id (marker, or
// removal when marker == ""), PATCH the single route in place, settle.
func (d *Driver) patchLocatorID(ctx context.Context, locator, marker string) error {
	_, raw, err := d.fetchConfigRaw(ctx)
	if err != nil {
		return fmt.Errorf("caddy ack --route: read live: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("caddy ack --route: parse config: %w", err)
	}
	rm, patchPath, err := resolveLocator(cfg, locator)
	if err != nil {
		return err
	}
	id, _ := rm["@id"].(string)
	if strings.HasPrefix(id, "crenel-route-") {
		return fmt.Errorf("route at %s is crenel-managed (@id %s), not a declared-unknown carve-out — ack does not apply", locator, id)
	}
	if id == marker {
		return nil // idempotent: already in the desired state
	}
	if marker == "" {
		if !strings.HasPrefix(id, model.AckMarkerPrefix) {
			return nil // not currently ack'd — unack is a tolerated no-op
		}
		delete(rm, "@id")
	} else {
		rm["@id"] = marker
	}
	body, err := json.Marshal(rm)
	if err != nil {
		return fmt.Errorf("marshal route at %s: %w", locator, err)
	}
	if err := d.adminWrite(ctx, http.MethodPatch, patchPath, body); err != nil {
		return fmt.Errorf("stamp route at %s: %w", locator, err)
	}
	return d.settle(ctx)
}

// RouteRawJSON returns the FULL pretty-printed raw JSON of the route at
// locator — the unbounded evidence view for `crenel triage`'s [o]pen action
// (Unparsed.RawExcerpt is truncated at read time). Implements
// ports.LocatorAcker.
func (d *Driver) RouteRawJSON(ctx context.Context, locator string) (string, error) {
	_, raw, err := d.fetchConfigRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("caddy route json: read live: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", fmt.Errorf("caddy route json: parse config: %w", err)
	}
	rm, _, err := resolveLocator(cfg, locator)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(rm, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
