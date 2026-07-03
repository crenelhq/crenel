package core

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// chain.go models a front-edge → downstream-edge CHAIN as a first-class, OBSERVED
// relationship (P4). A host enters at the public FRONT edge and is FORWARDED to a
// DOWNSTREAM edge that resolves it further (the front's backend for that host IS
// another edge). This is DISTINCT from the parallel multi-edge "double-write" (peer
// edges fanning the SAME host to several edges at once): a chain is sequential
// (front → downstream → origin).
//
// Resolution is a CORE concern, driver-free (a driver only ever sees its own leaf
// dial). Core recognizes a front leaf that dials the downstream edge as a chain
// FORWARD, then FOLLOWS THROUGH — reading the downstream edge to recover the host's
// real backend + the auth actually enforced there. When the downstream is readable
// the destination/auth are OBSERVED; when it is not, they are DECLARED "downstream,
// not observed" — never assumed safe. See DESIGN.md "Chain-aware model (P4)".

// edgeRead is one edge's live read result. err is non-nil only for a CHAIN-TARGET
// edge whose read failed: that failure is TOLERATED (the front degrades to "downstream
// unresolved" and the target surfaces as UNKNOWN) instead of aborting the whole
// status/audit. An ordinary edge's read error is returned by readAll and still aborts.
type edgeRead struct {
	live model.LiveEdgeState
	err  error
}

// chainTargets returns the set of edge names referenced as some front's downstream
// edge — the edges whose read failures readAll tolerates.
func (e *Engine) chainTargets() map[string]bool {
	t := map[string]bool{}
	for _, b := range e.Edges {
		if b.DownstreamEdge != "" {
			t[b.DownstreamEdge] = true
		}
	}
	return t
}

// readAll reads every edge's live state once into a name-keyed map shared by
// status/audit AND chain resolution (so a downstream edge is read exactly once, not
// twice). A read error on an ordinary edge aborts (unchanged behavior); a read error
// on a CHAIN-TARGET edge is CAPTURED, not fatal — the front declares its forwards
// "downstream, not observed" and the target surfaces as UNKNOWN, never a misread.
func (e *Engine) readAll(ctx context.Context) (map[string]edgeRead, error) {
	targets := e.chainTargets()
	m := make(map[string]edgeRead, len(e.Edges))
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil && !targets[b.Name] {
			return nil, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		m[b.Name] = edgeRead{live: live, err: err}
	}
	return m, nil
}

// chainContext indexes every edge's live routes by host so a front's forwarded host
// can be resolved against its downstream edge. Built once from readAll's map; an
// edge that could not be read carries its err so resolution declares it unresolved.
type chainContext struct {
	byEdge map[string]edgeIndex
}

type edgeIndex struct {
	hosts map[string]model.Route // lower(host) -> route on that edge
	err   error                  // set when this edge (a chain target) could not be read
}

// buildChainContext indexes the read map by edge name + host. It is total over the
// map (it indexes every edge, not just chain targets) so resolution is a cheap map
// lookup; resolveChain consults only the edges actually referenced as downstream.
func buildChainContext(reads map[string]edgeRead) chainContext {
	cc := chainContext{byEdge: make(map[string]edgeIndex, len(reads))}
	for name, rd := range reads {
		idx := edgeIndex{hosts: make(map[string]model.Route, len(rd.live.Routes)), err: rd.err}
		for _, r := range rd.live.Routes {
			idx.hosts[strings.ToLower(r.Host)] = r
		}
		cc.byEdge[name] = idx
	}
	return cc
}

// isChainFront reports whether this binding is the front of a chain (names a
// downstream edge it forwards to).
func (b EdgeBinding) isChainFront() bool { return b.DownstreamEdge != "" }

// chainForward reports whether route r on this (front) binding FORWARDS into the
// chain rather than to a terminal origin: a non-mesh data-plane route whose backend
// HOST matches the configured downstream address. With no DownstreamAddress every
// non-mesh route is treated as a forward (the "pure front" case — the front does
// nothing but relay downstream). Mesh grants are identity-scoped, never forwarded.
func (b EdgeBinding) chainForward(r model.Route) bool {
	if !b.isChainFront() || r.Upstream.Mode == model.ModeMeshGrant {
		return false
	}
	if b.DownstreamAddress == "" {
		return true
	}
	return dialHost(r.Upstream.Address) == dialHost(b.DownstreamAddress)
}

// resolveChain returns the ChainLink for a front route that forwards into the chain,
// or nil when this binding is not a chain front or the route is not a forward. It
// FOLLOWS THROUGH to the downstream edge: a readable downstream that routes the host
// yields a RESOLVED link (real backend + OBSERVED auth); an unreadable downstream, a
// downstream edge missing from the topology, or a host the downstream does not route
// yields an honest UNRESOLVED link (declared "downstream, not observed" — NEVER
// assumed safe).
func (cc chainContext) resolveChain(b EdgeBinding, r model.Route) *model.ChainLink {
	if !b.chainForward(r) {
		return nil
	}
	link := &model.ChainLink{DownstreamEdge: b.DownstreamEdge}
	idx, ok := cc.byEdge[b.DownstreamEdge]
	switch {
	case !ok:
		link.Reason = fmt.Sprintf("downstream edge %q is not configured in the topology", b.DownstreamEdge)
	case idx.err != nil:
		link.Reason = fmt.Sprintf("downstream edge %q could not be read: %v", b.DownstreamEdge, idx.err)
	default:
		if dr, found := idx.hosts[strings.ToLower(r.Host)]; found {
			link.Resolved = true
			link.DownstreamAddress = dr.Upstream.Address
			link.DownstreamAuth = dr.Upstream.Auth
		} else {
			link.Reason = fmt.Sprintf("host not routed at downstream edge %q (dangling forward)", b.DownstreamEdge)
		}
	}
	return link
}

// effectiveAuth resolves the auth value to DISPLAY/AUDIT for route r on edge b,
// honoring the chain (P4). Priority (highest first):
//  1. a REAL auth reference read at the FRONT edge wins (a host genuinely gated here
//     keeps its policy);
//  2. an OBSERVED downstream auth — a RESOLVED chain forward returns whatever the
//     downstream enforces, which is "" when it enforces NONE (so the host is correctly
//     flagged public_without_auth despite the chain — the P4 correctness win);
//  3. the auth_downstream ASSERTION (model.AuthDownstream) for an UNRESOLVED forward
//     (downstream unreadable / not routed) or the legacy flag with no downstream_edge.
//
// Mesh grants are identity-enforced and never annotated. Shared by status and audit
// so they always agree on a host's protection.
func (cc chainContext) effectiveAuth(b EdgeBinding, r model.Route) string {
	if r.Upstream.Auth != "" {
		return r.Upstream.Auth
	}
	if r.Upstream.Mode == model.ModeMeshGrant {
		return ""
	}
	if link := cc.resolveChain(b, r); link != nil {
		if link.Resolved {
			return link.DownstreamAuth // observed ("" => no auth downstream => flagged)
		}
		return model.AuthDownstream // asserted, not observed
	}
	if b.AuthDownstream {
		return model.AuthDownstream
	}
	return ""
}

// dialHost extracts the HOST part of a backend dial for matching a front leaf against
// the configured downstream address (port-insensitive: the front may dial :443 while
// the address is written bare). It tolerates a leading scheme and a bare host.
func dialHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	addr = strings.TrimSuffix(addr, "/")
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(addr)
}
