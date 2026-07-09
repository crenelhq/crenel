package traefik

// api_read.go is the Traefik API READ source (audit-any-edge M-A4): a read-only
// ports.EdgeProvider whose substrate is Traefik's own read-only HTTP API
// (`GET /api/http/routers` etc.) — the RUNNING process, not a file. It exists
// because the file is not the whole truth for generator-owned Traefik edges:
// Pangolin serves dynamic config to Traefik over the HTTP provider from
// `pangolin:3001`, and docker-label routes never touch disk at all — the API is
// the only honest read for both (design §4.3/§4.4, risk A.1).
//
// What the real API answers (captured fixtures, testdata/api-docker and
// testdata/api-pangolin, from real Traefik v3.6 instances on CT120 — provenance
// per design §9 decision 7):
//
//   - every /api/* list endpoint returns a JSON ARRAY (not the file provider's
//     name-keyed map); each element carries a fully-qualified "name" with a
//     `@provider` suffix (`grafana@docker`, `1-vault-router@http`, `api@internal`)
//     plus a separate "provider" field.
//   - a router's "service" REFERENCE may be UNqualified ("apionly") while the
//     service's own "name" is qualified ("apionly@docker") — resolution must try
//     the router's own provider suffix (resolveService).
//   - middlewares are first-class objects with a "type" ("forwardauth",
//     "basicauth", plugin middlewares like Pangolin's "badger") — STRONGER auth
//     evidence than the file read's name-contains-"auth" heuristic.
//   - Traefik's own plumbing surfaces as provider "internal" routers
//     (api@internal, dashboard@internal, ping@internal) whose services carry NO
//     loadBalancer; they fall out of the generic rules below (host-less, no
//     resolvable upstream => benign, never a permissive catch-all).
//
// Default-deny over the API: Traefik's API says NOTHING explicit about a
// catch-all — the structural deny is the platform's native 404 for an unmatched
// host, exactly as on the file read. The verdict is therefore decided the same
// way normalize() decides it: DenyCatchAllPresent unless some ENABLED router
// forwards ALL hosts to a real backend; any router this reader could not model
// is DECLARED Unparsed, so core's ternary downgrades ENFORCED -> UNKNOWN rather
// than ever claiming a deny over an unread route.
//
// Mutation is refused STRUCTURALLY (belt): Plan and Apply error — the API is
// read-only upstream anyway, and every generator-owned substrate here is
// regenerated from its source. The zero-config target additionally holds the
// engine behind core.ReadOnlyEngine (braces), so mutation is unreachable by type.
//
// Zero-config reach (design §9 decision 6): this reader talks PLAIN HTTP to a
// plainly reachable API only. No ssh transport, no auth flag surface — a
// loopback-bound or authed API (common in hardened Pangolin deployments) is the
// line where the user writes a settings file.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/model"
)

// apiReadTimeout bounds every API GET — the never-hang rule applies to a
// zero-config audit's very first read.
const apiReadTimeout = 10 * time.Second

// apiRouter is one element of GET /api/http/routers (fields this reader uses;
// the API sends more — priority, entryPoints, observability — none of which
// changes what a host forwards where).
type apiRouter struct {
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
	Middlewares []string `json:"middlewares"`
	Status      string   `json:"status"`
	Name        string   `json:"name"`     // fully qualified: <name>@<provider>
	Provider    string   `json:"provider"` // file | docker | http | internal | …
}

// apiService is one element of GET /api/http/services. Internal services
// (api@internal…) carry no loadBalancer at all.
type apiService struct {
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	LoadBalancer *struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	} `json:"loadBalancer"`
}

// apiMiddleware is one element of GET /api/http/middlewares. Type is the
// middleware's registered kind ("forwardauth", "basicauth", "badger" for
// Pangolin's plugin) — positive evidence, unlike a name heuristic.
type apiMiddleware struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Type     string `json:"type"`
}

// apiTCPRouter / apiTCPService mirror the TCP trees (HostSNI passthrough).
type apiTCPRouter struct {
	Rule     string `json:"rule"`
	Service  string `json:"service"`
	Status   string `json:"status"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	TLS      *struct {
		Passthrough bool `json:"passthrough"`
	} `json:"tls"`
}

type apiTCPService struct {
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	LoadBalancer *struct {
		Servers []struct {
			Address string `json:"address"`
		} `json:"servers"`
	} `json:"loadBalancer"`
}

// APIReader is a READ-ONLY EdgeProvider over Traefik's HTTP API. It holds no
// state beyond the base URL and re-reads the API on every ReadLiveState, so the
// type is trivially race-clean.
type APIReader struct {
	base   string
	client *http.Client
}

// NewAPIReader builds the API read source for the Traefik API at base
// (e.g. "http://127.0.0.1:8080"). Only plain reachability — no auth, no ssh.
func NewAPIReader(base string) *APIReader {
	return &APIReader{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: apiReadTimeout},
	}
}

// Name reports the driver family — the routes read here are Traefik routes.
func (a *APIReader) Name() string { return "traefik" }

// Validate confirms the target still answers the Traefik API signature.
func (a *APIReader) Validate(ctx context.Context) error {
	var v struct {
		Version string `json:"Version"`
	}
	if err := a.getJSON(ctx, "/api/version", &v); err != nil {
		return fmt.Errorf("traefik api %s: %w", a.base, err)
	}
	if v.Version == "" {
		return fmt.Errorf("traefik api %s: /api/version answered without a Version — not a Traefik API", a.base)
	}
	return nil
}

// Plan refuses: the API is Traefik's read-only runtime view; there is nothing
// to write to, and the substrates it reflects (Pangolin's DB, container labels)
// are regenerated from their sources — the refuse-to-manage gate's whole point.
func (a *APIReader) Plan(model.Op, model.LiveEdgeState) (model.ChangeSet, error) {
	return model.ChangeSet{}, fmt.Errorf("traefik api %s is READ-ONLY: the API reflects state generated elsewhere "+
		"(Pangolin's DB, container labels, provider files) — manage routes at that source; crenel audits this edge read-only", a.base)
}

// Apply refuses for the same reason as Plan (belt-and-braces: the target engine
// is also constructed ReadOnly, so this is unreachable in practice).
func (a *APIReader) Apply(context.Context, model.ChangeSet) error {
	return fmt.Errorf("traefik api %s is READ-ONLY: refusing to write", a.base)
}

// ReadEvidence implements ports.EvidenceReporter: RUNTIME — the running process
// reported this state, the strongest read evidence (§5). No mtime: there is no
// file to be stale.
func (a *APIReader) ReadEvidence() model.ReadEvidence {
	return model.ReadEvidence{
		Kind:   model.EvidenceRuntime,
		Source: a.base + " (Traefik API — the running process, not a file)",
	}
}

// getJSON GETs base+path and decodes the JSON body. Every read this driver makes
// funnels through here: only GETs, only under the configured base URL (risk A.6 —
// the /api/* paths under the pasted target count as the pasted target).
func (a *APIReader) getJSON(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("GET %s: read body: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("GET %s: parse: %w", path, err)
	}
	return nil
}

// ReadLiveState reads the running Traefik's routers/services/middlewares (+ the
// TCP trees) and folds them into one LiveEdgeState. Evidence is RUNTIME; a read
// failure on ANY endpoint fails the whole read (a partial read would silently
// shrink coverage — the P0 rule is declare, and an endpoint crenel cannot read
// at all cannot even be declared route-by-route).
func (a *APIReader) ReadLiveState(ctx context.Context) (model.LiveEdgeState, error) {
	var (
		routers  []apiRouter
		services []apiService
		mws      []apiMiddleware
		tcpRs    []apiTCPRouter
		tcpSs    []apiTCPService
	)
	for _, ep := range []struct {
		path string
		into any
	}{
		{"/api/http/routers", &routers},
		{"/api/http/services", &services},
		{"/api/http/middlewares", &mws},
		{"/api/tcp/routers", &tcpRs},
		{"/api/tcp/services", &tcpSs},
	} {
		if err := a.getJSON(ctx, ep.path, ep.into); err != nil {
			return model.LiveEdgeState{}, fmt.Errorf("traefik api %s: %w", a.base, err)
		}
	}
	return a.normalizeAPI(routers, services, mws, tcpRs, tcpSs), nil
}

// mwIndex indexes middlewares by their fully-qualified name AND base name, so a
// router's reference resolves whether it is qualified ("badger@http") or not.
func mwIndex(mws []apiMiddleware) map[string]apiMiddleware {
	idx := make(map[string]apiMiddleware, len(mws)*2)
	for _, m := range mws {
		idx[m.Name] = m
		// Base-name entry: last writer wins on a collision, which is fine — auth
		// classification below keys on TYPE, and two same-named middlewares of
		// different types across providers would be a pathological config.
		idx[middlewareBaseName(m.Name)] = m
	}
	return idx
}

// authForAPIRouter classifies a router's auth from its middleware OBJECTS — the
// API's typed view, stronger than the file read's name heuristic:
//   - type "forwardauth" / "basicauth" / "digestauth" => AuthDetected
//     (recognized-but-unnamed; the tree is foreign, nothing here is a crenel
//     policy name).
//   - type "badger" (Pangolin's access-control plugin) => AuthDetected. Caveat,
//     documented not hidden: badger is attached to EVERY Pangolin-generated
//     router; whether a given resource's policy actually challenges (SSO on/off)
//     lives in Pangolin's DB, which crenel does not read. Detected-attached is
//     the honest maximum the API supports.
//   - fallback: a middleware name containing "auth" (parity with the file read)
//     for middlewares the API did not enumerate.
func authForAPIRouter(r apiRouter, idx map[string]apiMiddleware) string {
	for _, ref := range r.Middlewares {
		m, ok := idx[ref]
		if !ok {
			m, ok = idx[middlewareBaseName(ref)]
		}
		if ok {
			switch m.Type {
			case "forwardauth", "basicauth", "digestauth", pangolinMiddleware:
				return model.AuthDetected
			}
			continue
		}
		if strings.Contains(strings.ToLower(ref), "auth") {
			return model.AuthDetected
		}
	}
	return ""
}

// resolveService finds the service a router references. The API qualifies every
// service NAME with its provider but router REFERENCES may be bare (a docker
// router's "service":"apionly" vs the service "apionly@docker"), so resolution
// tries: exact name; name@<router's provider>; then a UNIQUE base-name match
// (ambiguity resolves to nothing — a wrong upstream is a MISREAD, a missing one
// is a declared unknown).
func resolveService(ref, provider string, byName map[string]*apiService, byBase map[string][]*apiService) *apiService {
	if s, ok := byName[ref]; ok {
		return s
	}
	if s, ok := byName[ref+"@"+provider]; ok {
		return s
	}
	if cands := byBase[middlewareBaseName(ref)]; len(cands) == 1 {
		return cands[0]
	}
	return nil
}

// detectAPIGenerator is the API-side generator detection: Pangolin first (the
// badger middleware type is its low-false-positive signature, same key as the
// file codec), then the provider FIELD of any router — the API's first-class
// version of the file read's name-suffix scan. A plain `http` or `file` provider
// alone is NOT a generator signal (both are hand-authorable).
func detectAPIGenerator(routers []apiRouter, tcpRs []apiTCPRouter, mws []apiMiddleware) string {
	for _, m := range mws {
		if m.Type == pangolinMiddleware || middlewareBaseName(m.Name) == pangolinMiddleware {
			return "pangolin"
		}
	}
	providers := make([]string, 0, len(routers)+len(tcpRs))
	for _, r := range routers {
		providers = append(providers, r.Provider)
	}
	for _, r := range tcpRs {
		providers = append(providers, r.Provider)
	}
	sort.Strings(providers)
	for _, p := range providers {
		switch strings.ToLower(p) {
		case "docker":
			return "traefik-docker-labels"
		case "swarm":
			return "traefik-swarm-labels"
		case "kubernetes", "kubernetescrd", "kubernetesingress", "kubernetesgateway":
			return "traefik-kubernetes"
		case "nomad":
			return "traefik-nomad-labels"
		case "consulcatalog":
			return "traefik-consul-catalog"
		case "ecs":
			return "traefik-ecs"
		}
	}
	return ""
}

// normalizeAPI folds the API's runtime view into a LiveEdgeState under the same
// honesty rules as the file read's normalize():
//   - deterministic order (sorted by fully-qualified router name);
//   - a router whose effect crenel cannot model — disabled, conditional beyond
//     host granularity, or with an unresolvable backend — is DECLARED Unparsed,
//     never dropped and never misread as a plain host route;
//   - internal plumbing (api/dashboard/ping) falls out benign via the generic
//     host-less + no-upstream rule, with no special-casing to get wrong.
func (a *APIReader) normalizeAPI(routers []apiRouter, services []apiService, mws []apiMiddleware, tcpRs []apiTCPRouter, tcpSs []apiTCPService) model.LiveEdgeState {
	state := model.LiveEdgeState{}
	permissiveCatchAll := false

	byName := make(map[string]*apiService, len(services))
	byBase := make(map[string][]*apiService, len(services))
	for i := range services {
		s := &services[i]
		byName[s.Name] = s
		base := middlewareBaseName(s.Name)
		byBase[base] = append(byBase[base], s)
	}
	idx := mwIndex(mws)

	sort.Slice(routers, func(i, j int) bool { return routers[i].Name < routers[j].Name })
	for _, r := range routers {
		loc := "http.routers." + r.Name
		// A router the running Traefik has NOT enabled ("disabled"/"warning") is
		// not routing as read — but its rule could start routing on the next
		// provider sync, so it is declared, never dropped.
		if r.Status != "enabled" {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason:     fmt.Sprintf("router %q has status %q (not enabled) — its runtime effect is unknown", r.Name, r.Status),
				RawExcerpt: r.Rule,
			})
			continue
		}
		svc := resolveService(r.Service, r.Provider, byName, byBase)
		hasUpstream := svc != nil && svc.LoadBalancer != nil && len(svc.LoadBalancer.Servers) > 0 && svc.LoadBalancer.Servers[0].URL != ""
		hosts := parseHosts(r.Rule)
		if len(hosts) == 0 {
			// Host-less rule: fail-open ONLY if it forwards somewhere. Traefik's own
			// api@internal / dashboard@internal / ping@internal land here with no
			// loadBalancer upstream => benign (they never open the data edge), same
			// rule as the file read's crenel-deny.
			if isCatchAll(r.Rule) && hasUpstream {
				permissiveCatchAll = true
				continue
			}
			if hasUpstream {
				state.Unparsed = append(state.Unparsed, model.Unparsed{
					Locator: loc, Kind: model.UnknownMatcher,
					Reason:     fmt.Sprintf("router %q forwards traffic via a host-less rule crenel cannot model as a host", r.Name),
					RawExcerpt: r.Rule,
				})
			}
			continue
		}
		// Host + non-host predicates (PathPrefix / negations / …): DECLARE
		// matcher_conditional rather than claim the whole host — identical
		// register-§4 semantics to the file read (Pangolin's own dashboard routers
		// `Host(..) && !PathPrefix(/api/v1)` land here).
		if keys := nonHostPredicates(r.Rule); len(keys) > 0 {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownMatcher,
				Reason: fmt.Sprintf("router %q matches %s but is also scoped by non-host predicate(s) crenel does not model (%s) — path/method/header-granular routing is not represented at host granularity",
					r.Name, strings.Join(hosts, ", "), strings.Join(keys, ", ")),
				RawExcerpt: r.Rule,
			})
			continue
		}
		if !hasUpstream {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownBackend,
				Reason:     fmt.Sprintf("router %q matches %s but its service %q has no resolvable upstream (absent, or a weighted/mirroring service crenel does not model)", r.Name, strings.Join(hosts, ", "), r.Service),
				RawExcerpt: r.Rule,
			})
			continue
		}
		// First upstream only (parity with the file read): a multi-server LB reads
		// as its first server. serverStatus (UP/DOWN) is runtime health, not
		// exposure — ignored on purpose.
		addr := stripScheme(svc.LoadBalancer.Servers[0].URL)
		auth := authForAPIRouter(r, idx)
		for _, h := range hosts {
			state.Routes = append(state.Routes, model.Route{
				Host: h,
				// Nothing read over the API is crenel-managed: crenel's file writes
				// carry crenel-* keys, but ownership over a runtime view of foreign
				// substrates is settled edge-wide below.
				Managed:   false,
				Ownership: model.OwnUnmanaged,
				Upstream:  model.Upstream{Kind: model.ForwardToOrigin, Mode: model.ModeHTTPProxy, Address: addr, ServerName: h, Auth: auth},
			})
		}
	}

	// TCP passthrough routers: HostSNI + a TCP service address.
	tcpByName := make(map[string]*apiTCPService, len(tcpSs))
	tcpByBase := make(map[string][]*apiTCPService, len(tcpSs))
	for i := range tcpSs {
		s := &tcpSs[i]
		tcpByName[s.Name] = s
		base := middlewareBaseName(s.Name)
		tcpByBase[base] = append(tcpByBase[base], s)
	}
	sort.Slice(tcpRs, func(i, j int) bool { return tcpRs[i].Name < tcpRs[j].Name })
	for _, r := range tcpRs {
		loc := "tcp.routers." + r.Name
		if r.Status != "enabled" {
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownHandler,
				Reason:     fmt.Sprintf("tcp router %q has status %q (not enabled) — its runtime effect is unknown", r.Name, r.Status),
				RawExcerpt: r.Rule,
			})
			continue
		}
		var addr string
		if s, ok := tcpByName[r.Service]; ok {
			addr = firstTCPAddress(s)
		} else if s, ok := tcpByName[r.Service+"@"+r.Provider]; ok {
			addr = firstTCPAddress(s)
		} else if cands := tcpByBase[middlewareBaseName(r.Service)]; len(cands) == 1 {
			addr = firstTCPAddress(cands[0])
		}
		hosts := parseHostSNI(r.Rule)
		if len(hosts) == 0 || addr == "" {
			// A TCP router crenel cannot attribute (no exact HostSNI, or no resolvable
			// address) still moves raw traffic: declared, never dropped.
			state.Unparsed = append(state.Unparsed, model.Unparsed{
				Locator: loc, Kind: model.UnknownMatcher,
				Reason:     fmt.Sprintf("tcp router %q has no exact HostSNI/resolvable service address crenel can model", r.Name),
				RawExcerpt: r.Rule,
			})
			continue
		}
		for _, h := range hosts {
			state.Routes = append(state.Routes, model.Route{
				Host:      h,
				Managed:   false,
				Ownership: model.OwnUnmanaged,
				Upstream: model.Upstream{
					Kind:           model.ForwardToOrigin,
					Mode:           model.ModeTCPPassthrough,
					Address:        addr,
					TLSPassthrough: true,
					ServerName:     h,
				},
			})
		}
	}

	state.DenyCatchAllPresent = !permissiveCatchAll

	// Generator detection from API data (the design's "provider suffixes fall out
	// of the API response" bonus): pangolin via badger, else any orchestrator
	// provider. A detected generator marks the edge + every route FOREIGN, per
	// M-A1 ownership semantics — read, reported, never mutated.
	if g := detectAPIGenerator(routers, tcpRs, mws); g != "" {
		state.Generator = g
		for i := range state.Routes {
			state.Routes[i].Ownership = model.OwnForeign
			state.Routes[i].Managed = false
		}
	}
	// The API is a VIEW: what persists across a Traefik restart is each provider's
	// own substrate (files, labels, Pangolin's DB), not this endpoint. Durable in
	// practice (the providers re-feed on boot), but crenel writes nothing here so
	// persistence semantics never gate anything; report the substrate truthfully.
	state.Persistence = model.PersistDurableConfig
	return state
}

// firstTCPAddress returns a TCP service's first server address ("" when none).
func firstTCPAddress(s *apiTCPService) string {
	if s == nil || s.LoadBalancer == nil || len(s.LoadBalancer.Servers) == 0 {
		return ""
	}
	return s.LoadBalancer.Servers[0].Address
}

// Compile-time guard: the API reader must keep declaring RUNTIME evidence (a
// silent regression here would drop the evidence header the target path prints).
var _ interface{ ReadEvidence() model.ReadEvidence } = (*APIReader)(nil)
