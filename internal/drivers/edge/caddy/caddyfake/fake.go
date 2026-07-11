// Package caddyfake is an in-repo fake of the Caddy admin API for tests.
//
// It implements just enough of the admin surface that Crenel exercises:
//   - GET  /config/   -> returns the current config as Caddy-style JSON
//   - POST /load       -> accepts a Caddyfile (text/caddyfile), "adapts" it into
//     JSON, and (normally) updates the running config
//
// It can model real footguns so tests can assert Crenel handles them:
//   - SilentReload: /load returns 200 but does NOT change the running config
//     (the silent-reload footgun — caught only by read-back verification).
//   - RejectReload: /load returns 4xx.
//
// This is NOT real Caddy. The Caddyfile "adapter" understands only the small
// dialect Crenel renders (host blocks with reverse_proxy, and a host-less block
// with respond). That is sufficient and faithful for the flows under test.
package caddyfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake is a controllable fake Caddy admin API.
type Fake struct {
	mu     sync.Mutex
	config map[string]any // current running config (Caddy JSON shape)
	server string         // managed server key

	// SilentReload, when true, makes POST /load return 200 without applying.
	SilentReload bool
	// RejectReload, when non-empty, makes POST /load return 400 with this msg.
	RejectReload string
	// DropAdminOnLoad, when true, applies /load but STRIPS any admin block the
	// Caddyfile carried — modelling an edge that does not honor the carried
	// admin global (the F1 failure shape), so tests can prove the driver's
	// post-load admin read-back verification catches it loudly.
	DropAdminOnLoad bool

	// WriteDelay and ReadDelay, when > 0, make mutating (/load, PUT/DELETE /config,
	// /id) and read (GET /config/) handlers stall for that long before responding —
	// modelling a slow or WEDGED admin API (the real-edge failure). The stall is
	// cancellable: if the client's request context is cancelled (its bounded
	// timeout fires), the handler returns immediately, so a hung op never blocks
	// the test or Close. Use a large delay (e.g. time.Hour) to model a hard wedge.
	WriteDelay time.Duration
	ReadDelay  time.Duration

	// Loads records every Caddyfile body received by /load, in order.
	Loads []string

	ts   *httptest.Server
	done chan struct{} // closed by Close to release any in-flight stall
}

// stall blocks for d, or returns early if the client cancelled the request OR the
// fake is being closed. Returns false if it was released early (handler should
// stop). Releasing on f.done makes Close deterministic — it never has to wait out
// a long stall for an outstanding request to drain.
func (f *Fake) stall(r *http.Request, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-r.Context().Done():
		return false
	case <-f.done:
		return false
	}
}

// New starts a fake admin API with an empty config. Call Close when done.
func New() *Fake {
	f := &Fake{config: map[string]any{}, server: "srv0", done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", f.handleConfig)
	mux.HandleFunc("/load", f.handleLoad)
	mux.HandleFunc("/id/", f.handleID)
	f.ts = httptest.NewServer(mux)
	return f
}

// URL is the base URL of the fake admin API.
func (f *Fake) URL() string { return f.ts.URL }

// Close shuts the fake down. It first releases any in-flight stall so the
// underlying test server can drain immediately (no waiting out a long delay).
func (f *Fake) Close() {
	close(f.done)
	f.ts.Close()
}

// SeedJSON sets the running config directly from a JSON document (a fixture).
func (f *Fake) SeedJSON(jsonDoc string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonDoc), &cfg); err != nil {
		return err
	}
	f.config = cfg
	return nil
}

// SeedCaddyfile sets the running config by adapting a Caddyfile (as if loaded).
func (f *Fake) SeedCaddyfile(caddyfile string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = adapt(caddyfile, f.server)
}

// CurrentJSON returns the current running config as JSON (for assertions).
func (f *Fake) CurrentJSON() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.config)
	return string(b)
}

func (f *Fake) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !f.stall(r, f.ReadDelay) {
			return // client cancelled (its bounded timeout fired)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.config)
	case http.MethodPut, http.MethodPost:
		f.handlePutRoute(w, r)
	case http.MethodPatch:
		f.handlePatchRoute(w, r)
	case http.MethodDelete:
		f.handleDeletePath(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeletePath models Caddy's DELETE on a config PATH:
//
//	DELETE /config/apps/<app>/servers/<srv>/routes/<idx>                       (top-level)
//	DELETE /config/apps/http/servers/<srv>/routes/<w>/handle/<h>/routes/<idx>  (NESTED)
//
// It removes the addressed array element (or map key), mirroring real Caddy's
// path-addressed admin DELETE. This is how crenel removes a route that has NO @id — a
// durable route re-derived from the on-disk Caddyfile (a Caddyfile `handle` block carries
// no JSON `@id`), which the `/id/` delete cannot find. A bad path / out-of-range index is
// rejected (404) the way Caddy rejects an unaddressable node.
func (f *Fake) handleDeletePath(w http.ResponseWriter, r *http.Request) {
	if !f.stall(r, f.WriteDelay) {
		return // client cancelled (its bounded timeout fired)
	}
	path := strings.TrimPrefix(r.URL.Path, "/config/")
	tokens := strings.Split(strings.Trim(path, "/"), "/")
	if len(tokens) < 6 || tokens[0] != "apps" || tokens[2] != "servers" || tokens[4] != "routes" {
		http.Error(w, "unsupported config path: "+r.URL.Path, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := deleteByPath(f.config, tokens); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// deleteByPath removes the node addressed by tokens. A trailing numeric index removes
// that element from its parent routes slice (rewriting the slice in its grandparent map,
// since a delete reallocates); otherwise it deletes the named key from its parent map.
// Out-of-range / unaddressable paths error (the caller maps that to 404).
func deleteByPath(root map[string]any, tokens []string) error {
	last := tokens[len(tokens)-1]
	if idx, err := strconv.Atoi(last); err == nil && len(tokens) >= 2 {
		arrayKey := tokens[len(tokens)-2]
		gp, gerr := navigate(root, tokens[:len(tokens)-2])
		if gerr == nil {
			if gpm, ok := gp.(map[string]any); ok {
				if slice, ok := gpm[arrayKey].([]any); ok {
					if idx < 0 || idx >= len(slice) {
						return fmt.Errorf("delete index %d out of range (len %d)", idx, len(slice))
					}
					out := make([]any, 0, len(slice)-1)
					out = append(out, slice[:idx]...)
					out = append(out, slice[idx+1:]...)
					gpm[arrayKey] = out
					return nil
				}
			}
		}
	}
	parent, err := navigate(root, tokens[:len(tokens)-1])
	if err != nil {
		return err
	}
	pm, ok := parent.(map[string]any)
	if !ok {
		return fmt.Errorf("cannot delete at %q", last)
	}
	if _, exists := pm[last]; !exists {
		return fmt.Errorf("no node at %q", last)
	}
	delete(pm, last)
	return nil
}

// handlePatchRoute models Caddy's PATCH on a route path:
//
//	PATCH /config/apps/<app>/servers/<srv>/routes/<idx>
//	PATCH /config/apps/<app>/servers/<srv>/routes/<idx>/handle/<h>/routes/<k>[...]
//
// It REPLACES the addressed route with the JSON body, leaving every other route
// untouched — the primitive adoption uses to stamp an @id onto an existing
// unmanaged route in-place (without disturbing the deny or other routes). The
// NESTED form lets adoption stamp a per-host route that lives inside a wildcard
// subroute. Caddy's real admin API addresses config by an arbitrary path; the
// fake mirrors that map/slice traversal (setByPath) rather than only the flat case.
func (f *Fake) handlePatchRoute(w http.ResponseWriter, r *http.Request) {
	if !f.stall(r, f.WriteDelay) {
		return // client cancelled (its bounded timeout fired)
	}
	path := strings.TrimPrefix(r.URL.Path, "/config/")
	tokens := strings.Split(strings.Trim(path, "/"), "/")
	if len(tokens) < 6 || tokens[0] != "apps" || tokens[2] != "servers" || tokens[4] != "routes" {
		http.Error(w, "unsupported config path: "+r.URL.Path, http.StatusBadRequest)
		return
	}
	var route map[string]any
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		http.Error(w, "bad route json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Real Caddy's @id index is GLOBAL: loading a config where two nodes carry
	// the same @id is rejected by the admin API. Mirror that here so anything
	// that stamps @ids (adoption, ack markers) collides in tests exactly the way
	// it collides live. The node being REPLACED may of course already hold the
	// id (idempotent restamp) — only a duplicate elsewhere in the tree is fatal.
	if id, _ := route["@id"].(string); id != "" {
		curID := ""
		if cur, err := navigate(f.config, tokens); err == nil {
			if cm, ok := cur.(map[string]any); ok {
				curID, _ = cm["@id"].(string)
			}
		}
		if curID != id && countIDs(f.config, id) > 0 {
			http.Error(w, fmt.Sprintf("@id %q already in use elsewhere in the config; @id values must be globally unique", id), http.StatusBadRequest)
			return
		}
	}
	if err := setByPath(f.config, tokens, route); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// countIDs walks the whole config tree counting nodes whose "@id" equals id —
// the global-uniqueness check handlePatchRoute enforces (mirroring real Caddy).
func countIDs(node any, id string) int {
	n := 0
	switch v := node.(type) {
	case map[string]any:
		if got, _ := v["@id"].(string); got == id {
			n++
		}
		for _, child := range v {
			n += countIDs(child, id)
		}
	case []any:
		for _, child := range v {
			n += countIDs(child, id)
		}
	}
	return n
}

// navigate walks root by tokens (map keys or slice indices) and returns the
// addressed node. Maps and slices are reference types, so the returned node shares
// storage with the config tree — mutating it (or a child) mutates the tree in place.
// It is the shared traversal primitive for setByPath / insertByPath, mirroring
// Caddy's path-addressed admin API at any nesting depth.
func navigate(root map[string]any, tokens []string) (any, error) {
	var cur any = root
	for _, tok := range tokens {
		switch node := cur.(type) {
		case map[string]any:
			cur = node[tok]
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, fmt.Errorf("bad path index %q", tok)
			}
			cur = node[idx]
		default:
			return nil, fmt.Errorf("cannot descend into %q", tok)
		}
		if cur == nil {
			return nil, fmt.Errorf("no node at %q", tok)
		}
	}
	return cur, nil
}

// setByPath navigates root to the parent of the final token and REPLACES the value
// there (the primitive adoption's PATCH uses to stamp an @id at any nesting depth).
func setByPath(root map[string]any, tokens []string, value any) error {
	parent, err := navigate(root, tokens[:len(tokens)-1])
	if err != nil {
		return err
	}
	last := tokens[len(tokens)-1]
	switch p := parent.(type) {
	case map[string]any:
		p[last] = value
	case []any:
		idx, err := strconv.Atoi(last)
		if err != nil || idx < 0 || idx >= len(p) {
			return fmt.Errorf("bad path index %q", last)
		}
		p[idx] = value
	default:
		return fmt.Errorf("cannot set at %q", last)
	}
	return nil
}

// insertByPath INSERTS value into the routes slice addressed by tokens
// (…/<arrayKey>/<idx>), shifting existing elements right — the primitive a NESTED
// granular insert uses to add a per-host route inside a wildcard subroute. The
// slice's parent must be a map (it always is: the array key is "routes" on a server
// or a subroute handler), so the grown slice is written back in place. Mirrors real
// Caddy's path-addressed PUT at any depth; the structure must already exist (no
// path-creating semantics here — only the simple top-level form creates).
func insertByPath(root map[string]any, tokens []string, value any) error {
	idx, err := strconv.Atoi(tokens[len(tokens)-1])
	if err != nil {
		return fmt.Errorf("bad insert index %q", tokens[len(tokens)-1])
	}
	arrayKey := tokens[len(tokens)-2]
	parent, err := navigate(root, tokens[:len(tokens)-2])
	if err != nil {
		return err
	}
	pm, ok := parent.(map[string]any)
	if !ok {
		return fmt.Errorf("cannot insert: parent of %q is not an object", arrayKey)
	}
	pm[arrayKey] = insertAt(pm[arrayKey], idx, value)
	return nil
}

// insertAt returns the []any in slot with value inserted at idx (clamped to
// [0,len]); a nil/absent slot starts a fresh slice.
func insertAt(slot any, idx int, value any) []any {
	routes, _ := slot.([]any)
	if idx < 0 || idx > len(routes) {
		idx = len(routes)
	}
	out := make([]any, 0, len(routes)+1)
	out = append(out, routes[:idx]...)
	out = append(out, value)
	out = append(out, routes[idx:]...)
	return out
}

// handlePutRoute models the structured admin API for inserting a single route:
//
//	PUT /config/apps/<app>/servers/<srv>/routes/<idx>                       (top-level)
//	PUT /config/apps/http/servers/<srv>/routes/<w>/handle/<h>/routes/<idx>  (NESTED)
//
// It inserts the JSON body (a route object) at the addressed index WITHOUT disturbing
// any other route — the additive primitive that makes Crenel safe on a rich edge. The
// NESTED form lets a granular insert add a per-host route INSIDE a wildcard *.zone
// subroute (where the real edges keep per-host routing), mirroring Caddy's
// path-addressed PUT at any depth. For the top-level layer4 app (SNI passthrough) the
// app/server are CREATED if absent, mirroring Caddy's path-creating PUT semantics; the
// http app (and any nested structure) is required to already exist.
func (f *Fake) handlePutRoute(w http.ResponseWriter, r *http.Request) {
	if !f.stall(r, f.WriteDelay) {
		return // client cancelled (its bounded timeout fired)
	}
	path := strings.TrimPrefix(r.URL.Path, "/config/")
	tokens := strings.Split(strings.Trim(path, "/"), "/")
	// A route-array insert addresses a routes slice then an index: it must start
	// apps/<app>/servers/<srv>/routes/… and END in routes/<idx>.
	if len(tokens) < 6 || tokens[0] != "apps" || tokens[2] != "servers" || tokens[4] != "routes" ||
		tokens[len(tokens)-2] != "routes" {
		http.Error(w, "unsupported config path: "+r.URL.Path, http.StatusBadRequest)
		return
	}
	var route map[string]any
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		http.Error(w, "bad route json", http.StatusBadRequest)
		return
	}
	// FAITHFULNESS: real Caddy PROVISIONS every handler in an inserted route, failing
	// the load with "unknown module" for a handler name it does not register. crenel
	// emitting a synthetic {"handler":"forward_auth"} aborted the live trial exactly
	// here. Reject it the way Caddy does so a wrong auth render fails the test suite.
	if err := validateModules(tokens[1], route); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(tokens) == 6 {
		// Top-level form: http servers must pre-exist; layer4 servers are created on
		// demand (the path-creating PUT).
		app, srv := tokens[1], tokens[3]
		idx, err := strconv.Atoi(tokens[5])
		if err != nil {
			http.Error(w, "bad route index", http.StatusBadRequest)
			return
		}
		server := f.serverFor(app, srv, app == "layer4")
		if server == nil {
			http.Error(w, "no such server: "+srv, http.StatusNotFound)
			return
		}
		server["routes"] = insertAt(server["routes"], idx, route)
		w.WriteHeader(http.StatusOK)
		return
	}
	// Nested form: insert into the existing routes slice addressed by the full path.
	if err := insertByPath(f.config, tokens, route); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleID models DELETE /id/<id> (and GET for read-back): it finds the route
// tagged with @id ANYWHERE in the tree and removes it. Caddy's @id index is GLOBAL —
// a route tagged inside a nested wildcard subroute is addressable by id just like a
// top-level one — so the search RECURSES into subroute handlers. This is what lets a
// granular insert that nested a per-host route be read back and unexposed by id at
// that depth. Missing id => 404 (so removal is idempotent).
func (f *Fake) handleID(w http.ResponseWriter, r *http.Request) {
	delay := f.WriteDelay
	if r.Method == http.MethodGet {
		delay = f.ReadDelay
	}
	if !f.stall(r, delay) {
		return // client cancelled (its bounded timeout fired)
	}
	id := strings.TrimPrefix(r.URL.Path, "/id/")
	f.mu.Lock()
	defer f.mu.Unlock()

	// Search every server across BOTH the http and layer4 apps so a passthrough
	// route (tagged with a crenel-l4 @id) can be read back and deleted too.
	for _, sv := range f.allServers() {
		server, ok := sv.(map[string]any)
		if !ok {
			continue
		}
		routes, _ := server["routes"].([]any)
		body, newRoutes, found := actOnID(routes, id, r.Method)
		if !found {
			continue
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		case http.MethodDelete:
			server["routes"] = newRoutes // top-level slice rebuilt; nested deletes mutate in place
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.Error(w, "id not found: "+id, http.StatusNotFound)
}

// actOnID searches routes (and nested subroute handlers) for the route tagged @id.
// It returns the matched route body, the possibly-rebuilt top-level slice (for a
// DELETE of a TOP-LEVEL match), and whether it was found. A nested DELETE rebuilds
// the containing subroute's "routes" slice IN PLACE (the handler map is a reference),
// so the returned top-level slice is unchanged for a nested hit.
func actOnID(routes []any, id, method string) (body map[string]any, newRoutes []any, found bool) {
	for i, rt := range routes {
		rm, ok := rt.(map[string]any)
		if !ok {
			continue
		}
		if rm["@id"] == id {
			if method == http.MethodDelete {
				return rm, append(append([]any{}, routes[:i]...), routes[i+1:]...), true
			}
			return rm, routes, true
		}
		// Descend into any subroute handlers to reach nested per-host routes.
		handlers, _ := rm["handle"].([]any)
		for _, h := range handlers {
			hm, ok := h.(map[string]any)
			if !ok || hm["handler"] != "subroute" {
				continue
			}
			sub, _ := hm["routes"].([]any)
			if b, newSub, ok2 := actOnID(sub, id, method); ok2 {
				if method == http.MethodDelete {
					hm["routes"] = newSub
				}
				return b, routes, true
			}
		}
	}
	return nil, routes, false
}

// servers returns the apps.http.servers map (value type any per server).
func (f *Fake) servers() map[string]any { return f.appServers("http") }

// appServers returns the apps.<app>.servers map (value type any per server).
func (f *Fake) appServers(app string) map[string]any {
	apps, _ := f.config["apps"].(map[string]any)
	a, _ := apps[app].(map[string]any)
	servers, _ := a["servers"].(map[string]any)
	return servers
}

// allServers returns every server map across the http and layer4 apps.
func (f *Fake) allServers() []any {
	var out []any
	for _, app := range []string{"http", "layer4"} {
		for _, sv := range f.appServers(app) {
			out = append(out, sv)
		}
	}
	return out
}

// serverFor returns the server map for apps.<app>.servers.<srv>, creating the
// app/server chain when create is true (for the path-creating layer4 PUT).
func (f *Fake) serverFor(app, srv string, create bool) map[string]any {
	apps, _ := f.config["apps"].(map[string]any)
	if apps == nil {
		if !create {
			return nil
		}
		apps = map[string]any{}
		f.config["apps"] = apps
	}
	a, _ := apps[app].(map[string]any)
	if a == nil {
		if !create {
			return nil
		}
		a = map[string]any{}
		apps[app] = a
	}
	servers, _ := a["servers"].(map[string]any)
	if servers == nil {
		if !create {
			return nil
		}
		servers = map[string]any{}
		a["servers"] = servers
	}
	server, ok := servers[srv].(map[string]any)
	if !ok {
		if !create {
			return nil
		}
		server = map[string]any{"listen": []any{":443"}, "routes": []any{}}
		servers[srv] = server
	}
	return server
}

func (f *Fake) handleLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !f.stall(r, f.WriteDelay) {
		return // client cancelled (its bounded timeout fired)
	}
	buf := make([]byte, r.ContentLength)
	if r.ContentLength > 0 {
		_, _ = r.Body.Read(buf)
	} else {
		// Fallback: read all.
		var sb strings.Builder
		tmp := make([]byte, 4096)
		for {
			n, err := r.Body.Read(tmp)
			sb.Write(tmp[:n])
			if err != nil {
				break
			}
		}
		buf = []byte(sb.String())
	}
	body := string(buf)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.Loads = append(f.Loads, body)

	if f.RejectReload != "" {
		http.Error(w, f.RejectReload, http.StatusBadRequest)
		return
	}
	if f.SilentReload {
		// Footgun: report success but do not change the running config.
		w.WriteHeader(http.StatusOK)
		return
	}
	f.config = adapt(body, f.server)
	if f.DropAdminOnLoad {
		delete(f.config, "admin")
	}
	w.WriteHeader(http.StatusOK)
}

// adapt converts the small Caddyfile dialect Crenel renders into Caddy JSON.
//
// Recognized blocks:
//
//	<host> {
//	    reverse_proxy <addr>
//	}
//	:443 {
//	    respond <code>
//	}
func adapt(caddyfile, serverKey string) map[string]any {
	routes := []any{}
	var (
		curAddr     string
		inBlock     bool
		directives  []string
		adminListen string // from a global options block: `{ admin <listen> }`
	)

	flush := func() {
		if curAddr == "" {
			return
		}
		route := buildRoute(curAddr, directives)
		if route != nil {
			routes = append(routes, route)
		}
		curAddr = ""
		directives = nil
	}

	for _, raw := range strings.Split(caddyfile, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "{") {
			curAddr = strings.TrimSpace(strings.TrimSuffix(line, "{"))
			inBlock = true
			continue
		}
		if line == "}" {
			flush()
			inBlock = false
			continue
		}
		if inBlock {
			// A GLOBAL options block (bare `{`, no site address) is where real
			// Caddy's adapter reads the admin endpoint: `admin <listen>` becomes
			// top-level JSON `{"admin":{"listen":"<listen>"}}`. Mirroring that here
			// is what lets tests prove the F1 carry-through survives a full /load
			// — and, just as faithfully, that a Caddyfile WITHOUT the global
			// reverts the admin block (the /load replace drops the seeded one).
			if curAddr == "" {
				if l, ok := strings.CutPrefix(line, "admin "); ok {
					adminListen = strings.TrimSpace(l)
				}
				continue
			}
			directives = append(directives, line)
		}
	}
	flush()

	cfg := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					serverKey: map[string]any{
						"listen": []any{":443"},
						"routes": routes,
					},
				},
			},
		},
	}
	if adminListen != "" {
		cfg["admin"] = map[string]any{"listen": adminListen}
	}
	return cfg
}

func buildRoute(addr string, directives []string) map[string]any {
	hostless := strings.HasPrefix(addr, ":")
	for _, dir := range directives {
		fields := strings.Fields(dir)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "reverse_proxy":
			if len(fields) < 2 {
				continue
			}
			handler := map[string]any{
				"handler":   "reverse_proxy",
				"upstreams": []any{map[string]any{"dial": fields[1]}},
			}
			if hostless {
				// Host-less reverse_proxy = catch-all forward (fail-open).
				return map[string]any{"handle": []any{handler}}
			}
			return map[string]any{
				"match":  []any{map[string]any{"host": []any{addr}}},
				"handle": []any{handler},
			}
		case "respond":
			code := 403
			if len(fields) >= 2 {
				if c, err := strconv.Atoi(fields[1]); err == nil {
					code = c
				}
			}
			// host-less denying route (catch-all default-deny)
			return map[string]any{
				"handle": []any{map[string]any{
					"handler":     "static_response",
					"status_code": code,
				}},
			}
		}
	}
	return nil
}

// knownHTTPHandlers is the set of http.handlers module names this fake "registers"
// — a faithful subset of real Caddy's, covering every handler crenel renders or reads
// across the suite + the real edges. A handler NOT in this set is rejected on insert,
// the way real Caddy rejects an unknown module. Crucially `forward_auth` is ABSENT: it
// is a Caddyfile DIRECTIVE, not a JSON handler module — the bug the live trial caught.
var knownHTTPHandlers = map[string]bool{
	"reverse_proxy": true, "static_response": true, "subroute": true, "vars": true,
	"headers": true, "encode": true, "file_server": true, "authentication": true,
	"rewrite": true, "handle": true, "error": true, "templates": true, "map": true,
	"request_body": true, "push": true, "intercept": true, "acme_server": true,
}

// knownLayer4Handlers is the analogous set for the caddy-l4 app (a different module
// namespace), so an SNI-passthrough insert validates too.
var knownLayer4Handlers = map[string]bool{
	"proxy": true, "subroute": true, "tls": true, "echo": true,
}

// validateModules walks a route (recursing through nested handle / routes /
// handle_response) and returns a Caddy-style "unknown module" error for the first
// handler whose module name this fake does not register. Returns nil when every
// handler is known. app selects the module namespace (http vs layer4).
func validateModules(app string, route map[string]any) error {
	known, ns := knownHTTPHandlers, "http.handlers"
	if app == "layer4" {
		known, ns = knownLayer4Handlers, "layer4.handlers"
	}
	for _, name := range collectHandlerNames(route) {
		if !known[name] {
			// Mirror Caddy's admin-API error text so callers/tests recognize it.
			return fmt.Errorf("loading module '%s': unknown module: %s.%s", name, ns, name)
		}
	}
	return nil
}

// collectHandlerNames recursively gathers every value stored at a "handler" key
// anywhere within v (handle lists, nested subroute routes, handle_response routes).
// In Caddy JSON the key "handler" appears ONLY on handler objects (matchers never use
// it), so this faithfully enumerates the modules a load would provision.
func collectHandlerNames(v any) []string {
	var out []string
	switch node := v.(type) {
	case map[string]any:
		if h, ok := node["handler"].(string); ok {
			out = append(out, h)
		}
		for _, child := range node {
			out = append(out, collectHandlerNames(child)...)
		}
	case []any:
		for _, child := range node {
			out = append(out, collectHandlerNames(child)...)
		}
	}
	return out
}

// MustJSON is a tiny helper for tests building fixture configs.
func MustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("caddyfake.MustJSON: %v", err))
	}
	return string(b)
}
