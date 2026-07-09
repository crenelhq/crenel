// Package netbird is a THIRD EdgeProvider — for an integrated identity-MESH edge
// (NetBird; the same shape applies to Tailscale `serve` / ACLs). Its purpose is to
// validate the EdgeProvider port's LIMITS, not just its reach: M2 (Traefik) proved
// the port HOLDS for a dumb data-plane edge; this driver proves a genuinely
// different edge is handled by ERRORING LOUDLY on intents it cannot express,
// rather than faking a leaky mapping. docs/internal/DESIGN.md and docs/internal/STRAIN.md predict exactly this.
//
// Why a mesh edge strains the port (the "collapse"): NetBird/Tailscale collapse
// transport + identity + authz + SNI into ONE model. Exposure is an ACL GRANT to a
// peer/group over WireGuard — not a host→backend HTTP route with edge TLS
// termination. With the typed route Mode (model.RouteMode, docs/internal/STRAIN.md §2) the port
// now lets this edge express its NATIVE intent and refuse the rest:
//   - READ works and is honest: a mesh is default-deny by construction (no grant =
//     no access), and current grants are surfaced read-only (with a clearly
//     non-HTTP pseudo-address so the collapse is visible in `status`).
//   - PLAN/APPLY in ModeMeshGrant express the native grant (host→identity/group)
//     against the grant store. Any OTHER mode (the default HTTP-proxy intent, or
//     SNI passthrough) ERRORS LOUDLY wrapping model.ErrModeUnsupported — refusing
//     beats approximating.
package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// IsUnsupported reports whether err is a driver's refusal to express the
// requested route mode (wraps model.ErrModeUnsupported).
func IsUnsupported(err error) bool { return errors.Is(err, model.ErrModeUnsupported) }

// meshGrantPrefix tags a grant's pseudo-address so the transport/identity collapse
// is visible in status and so Apply can recover the group from an EdgeChange.
const meshGrantPrefix = "mesh-grant:"

// Driver implements ports.EdgeProvider against a NetBird-style ACL grant store
// (modelled as a JSON file for the fake: {"grants":[{"host":...,"group":...}]}).
type Driver struct {
	path string
}

// New builds a NetBird driver bound to the grant store at path.
func New(path string) *Driver { return &Driver{path: path} }

func (d *Driver) Name() string { return "netbird" }

// Validate confirms the grant store exists and parses.
func (d *Driver) Validate(ctx context.Context) error {
	_, err := d.read()
	return err
}

// grantStore is the fake's on-disk shape.
type grantStore struct {
	Grants []grant `json:"grants"`
}

type grant struct {
	Host  string `json:"host"`  // the resource a grant exposes
	Group string `json:"group"` // the identity/group the grant is to
}

// ReadLiveState reports the mesh's live access state. A mesh is default-deny by
// construction (DenyCatchAllPresent is ALWAYS true: no grant ⇒ no access), so the
// structural invariant holds trivially and honestly. Current grants are surfaced
// as routes with a deliberately non-HTTP pseudo-address ("mesh-grant:<group>") so
// the transport/identity collapse is VISIBLE rather than hidden behind a fake
// backend address.
func (d *Driver) ReadLiveState(ctx context.Context) (model.LiveEdgeState, error) {
	store, err := d.read()
	if err != nil {
		return model.LiveEdgeState{}, err
	}
	state := model.LiveEdgeState{DenyCatchAllPresent: true}
	grants := append([]grant(nil), store.Grants...)
	sort.Slice(grants, func(i, j int) bool { return grants[i].Host < grants[j].Host })
	for _, g := range grants {
		state.Routes = append(state.Routes, model.Route{
			Host: g.Host,
			Upstream: model.Upstream{
				Kind:    model.DirectBackend,
				Mode:    model.ModeMeshGrant,
				Address: meshGrantPrefix + g.Group,
			},
		})
	}
	return state, nil
}

// Plan expresses the mesh's NATIVE mode (ModeMeshGrant, a WireGuard ACL grant) and
// ERRORS LOUDLY on any other mode. crenel's default HTTP-proxy intent (host →
// dialed backend with edge TLS termination) is something an identity-mesh cannot
// express, so it is refused rather than approximated.
func (d *Driver) Plan(op model.Op, live model.LiveEdgeState) (model.ChangeSet, error) {
	cs := model.ChangeSet{Op: op}
	cs.Edge.DenyCatchAllWillBePresent = true // a mesh is default-deny by construction

	if op.Mode != model.ModeMeshGrant {
		return cs, fmt.Errorf(
			"%w: netbird is an identity-mesh edge — exposure here is a WireGuard ACL grant "+
				"to a peer/group (mode=%s), not a host→backend HTTP reverse-proxy route with "+
				"edge TLS termination (got mode=%s). Refusing to approximate; re-run with "+
				"--mode %s --param group=<identity/group>",
			model.ErrModeUnsupported, model.ModeMeshGrant, op.Mode.String(), model.ModeMeshGrant)
	}

	switch op.Verb {
	case model.Expose:
		if op.Host == "" {
			return cs, fmt.Errorf("netbird plan: expose requires a host")
		}
		group := op.Params["group"]
		if group == "" {
			return cs, fmt.Errorf("netbird plan: mode=%s requires --param group=<identity/group>", model.ModeMeshGrant)
		}
		if live.HasHost(op.Host) {
			return cs, nil // grant already present => no-op
		}
		cs.Edge.AddRoutes = []model.Route{{
			Host: op.Host,
			Upstream: model.Upstream{
				Kind:    model.DirectBackend,
				Mode:    model.ModeMeshGrant,
				Address: meshGrantPrefix + group,
			},
		}}
	case model.Unexpose:
		if op.Host == "" {
			return cs, fmt.Errorf("netbird plan: unexpose requires a host")
		}
		if !live.HasHost(op.Host) {
			return cs, nil // no grant => no-op
		}
		cs.Edge.RemoveHosts = []string{op.Host}
	default:
		return cs, fmt.Errorf("netbird plan: unknown verb %q", op.Verb)
	}
	return cs, nil
}

// Apply realizes a mesh-grant change against the grant store: it adds grants for
// AddRoutes (recovering the group from the route's mesh-grant pseudo-address) and
// removes grants for RemoveHosts. As with every EdgeProvider, core read-back-
// verifies afterwards.
func (d *Driver) Apply(ctx context.Context, cs model.ChangeSet) error {
	store, err := d.read()
	if err != nil {
		return fmt.Errorf("netbird apply: read: %w", err)
	}
	remove := map[string]bool{}
	for _, h := range cs.Edge.RemoveHosts {
		remove[strings.ToLower(h)] = true
	}
	var kept []grant
	for _, g := range store.Grants {
		if !remove[strings.ToLower(g.Host)] {
			kept = append(kept, g)
		}
	}
	for _, r := range cs.Edge.AddRoutes {
		group := strings.TrimPrefix(r.Upstream.Address, meshGrantPrefix)
		kept = append(kept, grant{Host: r.Host, Group: group})
	}
	store.Grants = kept
	return d.write(store)
}

func (d *Driver) write(store grantStore) error {
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("netbird encode grants: %w", err)
	}
	if err := os.WriteFile(d.path, b, 0o644); err != nil {
		return fmt.Errorf("netbird write grants %s: %w", d.path, err)
	}
	return nil
}

func (d *Driver) read() (grantStore, error) {
	b, err := os.ReadFile(d.path)
	if err != nil {
		return grantStore{}, fmt.Errorf("read netbird grants %s: %w", d.path, err)
	}
	var store grantStore
	if t := strings.TrimSpace(string(b)); t != "" && t != "null" {
		if err := json.Unmarshal(b, &store); err != nil {
			return grantStore{}, fmt.Errorf("parse netbird grants %s: %w", d.path, err)
		}
	}
	return store, nil
}
