package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// Rename moves a service from oldHost to newHost as ONE atomic, read-back-verified
// transaction: on every edge that serves oldHost it ADDS newHost (copying the source
// route's exact backend, route mode, upstream-TLS and auth — only the hostname changes)
// and REMOVES oldHost, in a single ChangeSet. It runs through the same transactional
// engine as expose/unexpose (`applyPlanned`), so it inherits:
//
//   - the refuse-to-manage gate (a foreign/unknown source route is refused),
//   - make-before-break ordering at the driver (the new host is inserted + settled BEFORE
//     the old is deleted — zero-downtime; and if the add fails the old is never removed),
//   - read-back-verify of BOTH transitions (new reachable, old absent) with all-or-nothing
//     rollback,
//   - a SINGLE coordinated durable persist that writes the final region (… + new, − old)
//     in one pass — which also sidesteps the multi-host persist gap by construction.
//
// It refuses if oldHost is not exposed anywhere, if newHost already exists (no silent
// overwrite), or if the source carries auth crenel cannot reproduce by name (AuthDetected:
// a recognized-but-unnamed gate, e.g. a brownfield/post-reload route — configure the policy
// and re-expose, or rename keeps the old name). Chain-forwarded hosts (front+downstream) are
// out of scope for this verb today — rename targets the edges that directly serve the host.
func (e *Engine) Rename(ctx context.Context, oldHost, newHost string, confirm ConfirmFunc) (ApplyReport, error) {
	cs, err := e.PlanRename(ctx, oldHost, newHost)
	if err != nil {
		return ApplyReport{Op: model.Op{Verb: model.Rename, Host: strings.TrimSpace(newHost)}}, err
	}
	return e.applyPlanned(ctx, cs.Op, cs, confirm)
}

// PlanRename computes (without applying) the atomic rename ChangeSet: per edge serving
// oldHost, an AddRoutes:[copy of the source route under newHost] + RemoveHosts:[oldHost].
// `preview rename` and Rename share it. It performs the refuse-up-front checks (old must
// exist, new must not, source auth must be reproducible by name).
func (e *Engine) PlanRename(ctx context.Context, oldHost, newHost string) (model.ChangeSet, error) {
	oldHost = strings.TrimSpace(oldHost)
	newHost = strings.TrimSpace(newHost)
	op := model.Op{Verb: model.Rename, Host: newHost}

	if oldHost == "" || newHost == "" {
		return model.ChangeSet{Op: op}, fmt.Errorf("rename: both <old-host> and <new-host> are required")
	}
	if strings.EqualFold(oldHost, newHost) {
		return model.ChangeSet{Op: op}, fmt.Errorf("rename: <old-host> and <new-host> are the same (%s) — nothing to do", oldHost)
	}

	var edges []model.EdgePlan
	foundOld := false
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return model.ChangeSet{Op: op}, fmt.Errorf("rename: read live edge %q: %w", b.Name, err)
		}
		src := findRoute(live, oldHost)
		if src == nil {
			continue
		}
		foundOld = true
		if live.HasHost(newHost) {
			return model.ChangeSet{Op: op}, fmt.Errorf("rename: %s already exists on edge %q — refusing to overwrite it; unexpose it first if you mean to replace it",
				newHost, b.Name)
		}
		if src.Upstream.Auth == model.AuthDetected {
			return model.ChangeSet{Op: op}, fmt.Errorf("rename: %s on edge %q carries auth crenel recognizes but cannot reproduce BY NAME (a brownfield/"+
				"post-reload forward-auth gate) — renaming it would risk dropping that protection; configure the policy (--auth) and "+
				"re-expose under the new name instead", oldHost, b.Name)
		}
		// The new route is the source route with ONLY the hostname changed — backend,
		// mode, upstream-TLS and auth-by-name are preserved. Ownership/marker is cleared
		// (the driver @id-tags the freshly inserted route); chain metadata is a core read
		// overlay, never a write input.
		nr := *src
		nr.Host = newHost
		nr.Upstream.ServerName = newHost
		nr.Managed = false
		nr.Ownership = ""
		nr.Chain = nil
		edges = append(edges, model.EdgePlan{
			Edge:   b.Name,
			Driver: b.Provider.Name(),
			Change: model.EdgeChange{
				AddRoutes:                 []model.Route{nr},
				RemoveHosts:               []string{src.Host},
				DenyCatchAllWillBePresent: true,
			},
		})
	}
	if !foundOld {
		return model.ChangeSet{Op: op}, fmt.Errorf("rename: %s is not exposed on any edge — nothing to rename", oldHost)
	}

	return model.ChangeSet{Op: op, Edges: edges, NewPublic: []string{newHost}}, nil
}

// findRoute returns a COPY of the first route serving host (case-insensitive), or nil.
func findRoute(live model.LiveEdgeState, host string) *model.Route {
	for i := range live.Routes {
		if strings.EqualFold(live.Routes[i].Host, host) {
			r := live.Routes[i]
			return &r
		}
	}
	return nil
}
