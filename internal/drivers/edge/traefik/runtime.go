package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/model"
)

// apiRouter is the subset of a Traefik /api/http/routers entry crenel reads to confirm
// a route is live: its name (e.g. "crenel-foo.example.com@file"), the rule, and the
// runtime status ("enabled" when Traefik accepted and is serving it).
type apiRouter struct {
	Name   string `json:"name"`
	Rule   string `json:"rule"`
	Status string `json:"status"`
}

// VerifyRuntime probes the RUNNING Traefik (its HTTP API), not crenel's written file,
// to confirm op's change is actually live — implementing ports.RuntimeVerifier (bench
// gap T4/N2: the file re-read is hollow because it re-reads what crenel just wrote). The
// file provider hot-reloads asynchronously, so it polls briefly for the watcher to pick
// up the write. With no API URL it returns Unavailable so the report says "written;
// runtime verify unavailable" — never a false "verified".
func (d *Driver) VerifyRuntime(ctx context.Context, op model.Op, ec model.EdgeChange) model.RuntimeVerification {
	if d.apiURL == "" {
		return model.RuntimeVerification{
			Status: model.RuntimeVerifyUnavailable,
			Detail: "no traefik api_url configured — set the edge's traefik_api_url to confirm routes against the running daemon's /api/http/routers",
		}
	}
	hosts := affectedHosts(ec)
	// Poll: the file provider's watcher reload is asynchronous (seconds), so give it a
	// bounded window to converge rather than racing the write.
	deadline := d.verifyDeadline
	interval := d.verifyInterval
	if interval <= 0 {
		interval = 400 * time.Millisecond
	}
	var lastErr error
	for waited := time.Duration(0); ; waited += interval {
		routers, err := d.fetchRouters(ctx)
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			if detail, converged := routersMatch(op, hosts, routers); converged {
				return model.RuntimeVerification{Status: model.RuntimeVerifyConfirmed, Detail: detail}
			} else if waited >= deadline {
				return model.RuntimeVerification{Status: model.RuntimeVerifyFailed, Detail: detail}
			}
		}
		if waited >= deadline {
			break
		}
		select {
		case <-ctx.Done():
			return model.RuntimeVerification{Status: model.RuntimeVerifyFailed, Detail: fmt.Sprintf("context cancelled while polling traefik api: %v", ctx.Err())}
		case <-time.After(interval):
		}
	}
	return model.RuntimeVerification{Status: model.RuntimeVerifyFailed, Detail: fmt.Sprintf("traefik api unreachable: %v", lastErr)}
}

// fetchRouters reads /api/http/routers from the running Traefik, bounded by a short
// timeout so a wedged API can never hang crenel.
func (d *Driver) fetchRouters(ctx context.Context) ([]apiRouter, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, d.apiURL+"/api/http/routers", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("traefik api returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var routers []apiRouter
	if err := json.Unmarshal(body, &routers); err != nil {
		return nil, fmt.Errorf("decode traefik routers: %w", err)
	}
	return routers, nil
}

// routersMatch checks whether the live router set reflects op for every affected host:
// expose => crenel's managed router for the host is present AND enabled; unexpose =>
// it is gone. Returns a human-readable detail and whether the world has converged.
func routersMatch(op model.Op, hosts []string, routers []apiRouter) (string, bool) {
	for _, h := range hosts {
		live := managedRouterLive(h, routers)
		switch op.Verb {
		case model.Expose:
			if !live {
				return fmt.Sprintf("traefik API does not list an enabled router for %s — the daemon has not accepted the route (rejected config, or not yet reloaded)", h), false
			}
		case model.Unexpose:
			if live {
				return fmt.Sprintf("traefik API still lists an enabled router for %s after unexpose", h), false
			}
		}
	}
	return fmt.Sprintf("traefik API confirms %s for %s on the running daemon", op.Verb, strings.Join(hosts, ", ")), true
}

// managedRouterLive reports whether the running Traefik has crenel's managed router for
// host, enabled. crenel's router is keyed crenel-<host> and surfaces in the API as
// "crenel-<host>@file"; it matches on that name AND an enabled status.
func managedRouterLive(host string, routers []apiRouter) bool {
	want := managedRouterID(host) // "crenel-<host>"
	for _, r := range routers {
		name := r.Name
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i] // strip the @file/@docker provider suffix
		}
		if name == want && strings.EqualFold(r.Status, "enabled") {
			return true
		}
	}
	return false
}

// affectedHosts returns the hosts an edge change touched (added ∪ removed).
func affectedHosts(ec model.EdgeChange) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, r := range ec.AddRoutes {
		add(r.Host)
	}
	for _, h := range ec.RemoveHosts {
		add(h)
	}
	return out
}
