package nginx

import (
	"context"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/model"
)

// run executes one operator-declared command (nginx -t / nginx -s reload) verbatim,
// bounded by ctx, returning combined output. An empty command is a tolerated no-op.
// Commands are the operator's own (e.g. `docker exec <ctr> nginx -t`), mirroring the
// Caddy transport's operator-declared exec chains — crenel never invents them.
func (rc *runtimeConfig) run(ctx context.Context, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", nil
	}
	// Bound every daemon command so a hung reload can never hang crenel (never-hang).
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, cmd[0], cmd[1:]...).CombinedOutput()
	return string(out), err
}

// probeHost issues one HTTP GET to the running nginx (ProbeBaseURL) with Host set to
// host, and reports whether nginx SERVED it. The deny block returns 444 — nginx closes
// the connection with no HTTP response, which surfaces as a transport error; that is a
// definitive "not served" (code 0), NOT a probe failure. A context error (deadline) is a
// real failure. Any received HTTP response (2xx/3xx/401/403/404…) means a server block
// handled the request, i.e. the host is live.
func (rc *runtimeConfig) probeHost(ctx context.Context, host string) (served bool, code int, err error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rc.ProbeBaseURL+"/", nil)
	if err != nil {
		return false, 0, err
	}
	req.Host = host // route by Host header through the shared listener
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// A context deadline/cancel is a genuine probe failure; any other transport
		// error (connection reset/closed — how nginx's `return 444` deny manifests) is a
		// definitive "not served".
		if cctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return false, 0, err
		}
		return false, 0, nil
	}
	defer resp.Body.Close()
	return true, resp.StatusCode, nil
}

// affectedHosts returns the hosts an edge change touched (added ∪ removed), so
// VerifyRuntime probes exactly the hosts whose runtime state should have changed.
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

// tail returns a bounded trailing snippet of command output for an error message
// (so nginx -t's diagnostic is surfaced without flooding), prefixed with ": ".
func tail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	const max = 300
	if len(s) > max {
		s = "…" + s[len(s)-max:]
	}
	return ": " + s
}
