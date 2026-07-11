package core

import (
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// chain_write.go is the WRITE dual of chain.go's read model: it builds the
// CROSS-CHAIN COORDINATED WRITE (P4-write). A single expose/unexpose on a CHAIN
// topology projects into one EdgePlan PER PARTICIPANT — the downstream (terminal)
// edge that actually SERVES the host AND the front edge that FORWARDS to it — so the
// coordinated entries land across both edges + DNS as ONE all-or-nothing,
// read-back-verified transaction (ordered + rolled back by apply.go). Where chain.go
// recognizes a front leaf that dials the downstream, this synthesizes that leaf.
// Driver-free, like the rest of core. See docs/internal/DESIGN.md "Cross-chain coordinated WRITE".

// chainRole classifies an edge's responsibility for a service in a (possibly chain)
// write projection.
type chainRole int

const (
	roleNone     chainRole = iota // the edge does not participate in this op
	roleTerminal                  // the edge directly fronts the service (it SERVES the host)
	roleForward                   // the edge is a chain front whose downstream participates
)

// roleFor classifies edge b's role for service. It SERVES the service terminally when
// it directly fronts it (the service is in its origins); else it FORWARDS the service
// when it is a chain front whose downstream edge (transitively) participates. A direct
// origin on the front wins — the front serves it itself — so an edge is never both
// terminal and forward for the same service. A non-chain topology never yields
// roleForward, so single-edge / parallel multi-edge projection is unchanged.
func (e *Engine) roleFor(b EdgeBinding, service string) chainRole {
	if b.fronts(service) {
		return roleTerminal
	}
	// INTERNAL-SCOPE gate (split-horizon): a service declared internal-only must
	// never be forwarded through a chain FRONT — the front is the public ingress,
	// and a forward there is exactly the public reachability the declaration
	// forbids. Yielding roleNone here gates every roleForward consumer at once:
	// Plan never synthesizes the forward, reconcile never DEMANDS it (the
	// missing_route "half-present chain" check skips it — the prod false demand
	// this feature exists to kill), and verifyReconcile never expects it. The
	// DOWNSTREAM edge still fronts the service terminally (the branch above), so
	// its route and internal DNS stay fully managed and verified. A forward that
	// nonetheless EXISTS at the front is not torn down by unexpose (the front no
	// longer participates); audit flags it critical
	// (internal_scope_public_exposure) with removal instructions instead.
	if e.internalScoped(service) {
		return roleNone
	}
	if b.isChainFront() && e.downstreamParticipates(b, service, map[string]bool{}) {
		return roleForward
	}
	return roleNone
}

// downstreamParticipates reports whether b's downstream edge (transitively) SERVES or
// forwards service — i.e. whether forwarding to it actually reaches an edge that
// serves the host. It walks the chain so a multi-hop front (front → mid → home)
// forwards as long as some edge down the line fronts the service. visited guards a
// misconfigured chain cycle.
func (e *Engine) downstreamParticipates(b EdgeBinding, service string, visited map[string]bool) bool {
	if b.DownstreamEdge == "" || visited[b.Name] {
		return false
	}
	visited[b.Name] = true
	d, ok := e.binding(b.DownstreamEdge)
	if !ok {
		return false
	}
	if d.fronts(service) {
		return true
	}
	return e.downstreamParticipates(d, service, visited)
}

// forwardDial returns the address the front dials to reach its downstream edge for a
// chain WRITE — DownstreamAddress verbatim (configure it host:port). A pure-front
// config (DownstreamAddress empty, "forward everything") is READ-only: there is no
// concrete dial to synthesize, so a chain WRITE through it is refused loudly rather
// than guessing a port.
func (b EdgeBinding) forwardDial() (string, error) {
	if b.DownstreamAddress == "" {
		return "", fmt.Errorf("chain front %q has no downstream_address — cannot synthesize a forward route "+
			"(set downstream_address to host:port to enable cross-chain writes)", b.Name)
	}
	return b.DownstreamAddress, nil
}

// forwardRoute builds the FRONT edge's forward route for host: a direct dial to the
// downstream edge, carrying NO auth (auth attaches at the terminal/downstream edge per
// the P4 observed-auth model). ServerName is the host so the front terminates the
// CLIENT's TLS for it before relaying onward. When the downstream edge listens on TLS
// (an HTTPS `:443` edge — the real home shape), the forward must ALSO re-originate TLS
// to the downstream and preserve the Host, else the downstream answers 400 "Client sent
// an HTTP request to an HTTPS server" (TRIAL-FIX-4): UpstreamTLS carries that intent to
// the driver, which renders the upstream TLS transport + Host. The driver renders this
// route faithfully (host + address, no auth handler); on read-back chain.go recognizes
// it as a chain forward again.
func (b EdgeBinding) forwardRoute(host string) (model.Route, error) {
	dial, err := b.forwardDial()
	if err != nil {
		return model.Route{}, err
	}
	return model.Route{Host: host, Upstream: model.Upstream{
		Kind:        model.DirectBackend,
		Mode:        model.ModeHTTPProxy,
		Address:     dial,
		ServerName:  host,
		UpstreamTLS: b.downstreamUsesTLS(dial),
	}}, nil
}

// downstreamUsesTLS reports whether the front must dial the downstream over HTTPS for a
// chain forward. An explicit DownstreamScheme wins ("https" => true, "http" => false);
// otherwise it INFERS from the dial — a `:443` port is treated as TLS, anything else as
// plain. This keeps the common case (a real `:443` home edge) zero-config while letting
// an operator override a non-standard port or a `:443` listener that is not actually TLS.
func (b EdgeBinding) downstreamUsesTLS(dial string) bool {
	switch strings.ToLower(strings.TrimSpace(b.DownstreamScheme)) {
	case "https":
		return true
	case "http":
		return false
	}
	return dialIsTLSPort(dial)
}

// dialIsTLSPort reports whether a host:port dial targets the standard HTTPS port (443).
// A bare host (no port) or any other port is treated as non-TLS — the inference is
// deliberately conservative so a plain-HTTP downstream is never wrapped in TLS by guess.
// The port is whatever follows the LAST colon, so an IPv6 literal (e.g. "[::1]:443")
// reads its port, not an address colon.
func dialIsTLSPort(dial string) bool {
	i := strings.LastIndex(dial, ":")
	if i < 0 {
		return false
	}
	return dial[i+1:] == "443"
}

// planForward builds the FRONT edge's change for a chain op against its live: add the
// synthesized forward route on expose (a converge no-op when the host is already
// forwarded — idempotency), remove it on unexpose. The front never carries auth.
func (b EdgeBinding) planForward(op model.Op, live model.LiveEdgeState) (model.EdgeChange, error) {
	ec := model.EdgeChange{DenyCatchAllWillBePresent: true}
	switch op.Verb {
	case model.Expose:
		if live.HasHost(op.Host) {
			return ec, nil // already forwarded => converge no-op (idempotent re-expose)
		}
		r, err := b.forwardRoute(op.Host)
		if err != nil {
			return ec, err
		}
		ec.AddRoutes = []model.Route{r}
	case model.Unexpose:
		if live.HasHost(op.Host) {
			ec.RemoveHosts = []string{op.Host}
		}
	}
	return ec, nil
}

// chainDepth returns each edge's depth in the chain topology: a standalone or front
// edge is depth 0, and an edge named as some front's downstream is one deeper than
// that front. The DEEPER (more internal) an edge, the LOWER its effective exposure
// rank — so buildSteps applies the downstream BEFORE the front on expose (and the
// reverse on unexpose), with public DNS last on expose. Depth is 0 for every edge in
// a non-chain topology, so the ordering collapses to the existing edge < internal-DNS
// < public-DNS scheme. Bounded relaxation (≤ len(Edges) passes) guards a cycle.
func (e *Engine) chainDepth() map[string]int {
	depth := make(map[string]int, len(e.Edges))
	for _, b := range e.Edges {
		depth[b.Name] = 0
	}
	for i := 0; i < len(e.Edges); i++ {
		changed := false
		for _, b := range e.Edges {
			if b.DownstreamEdge == "" {
				continue
			}
			if _, ok := depth[b.DownstreamEdge]; !ok {
				continue // downstream not in the topology — no depth relation
			}
			if d := depth[b.Name] + 1; d > depth[b.DownstreamEdge] {
				depth[b.DownstreamEdge] = d
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return depth
}
