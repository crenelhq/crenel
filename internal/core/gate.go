package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// ErrRefuseToManage classifies the refuse-to-manage gate's refusal: crenel will not
// mutate a route/edge whose ownership is FOREIGN (a generator owns it — an edit would
// be reverted) or UNKNOWN (crenel cannot determine who owns it). It is the
// MISMANAGE safety net (TOPOLOGY-RISK-REGISTER §4.5): better to refuse loudly than to
// edit-and-hope. Callers/tests classify it with errors.Is.
//
// CRITICAL posture: --yes does NOT bypass this. --yes skips the are-you-sure prompt;
// the gate is about this-will-silently-break, a different thing. Only Engine.Force
// (the documented, human-load-bearing escape) bypasses it — and ONLY for UNKNOWN,
// never FOREIGN (a foreign edit has no safe force: it will be reverted regardless).
var ErrRefuseToManage = errors.New("refuse to manage: ambiguous route/edge ownership")

// gateOwnership is the pre-mutation ownership gate, enforced in core BEFORE any
// driver Apply (so it covers every mutating verb identically). For each
// participating edge it re-reads live and refuses when:
//   - the EDGE is generator-owned (Generator set) — edge-wide refusal: even an
//     additive route would be reverted on the generator's next regeneration;
//   - a TOUCHED host's existing route is FOREIGN — refuse, naming the generator;
//   - a TOUCHED host's existing route is UNKNOWN — refuse unless Engine.Force.
//
// A host the change ADDS that does not yet exist in live has no owner to consult, so
// it is permitted on a non-generator edge (the ordinary expose-a-new-route path).
// In the absence of generator detection (P0) drivers only ever produce crenel/
// unmanaged routes, so this gate is dormant for them — it activates exactly when a
// route/edge is classified foreign/unknown (P2 detection, or a test double).
func (e *Engine) gateOwnership(ctx context.Context, cs model.ChangeSet) error {
	// Chain write (P4-write): the gate must span BOTH edges of a chain. A pre-existing
	// foreign/unknown route on a chain participant can converge to an EMPTY change (the
	// host is already present), so it would NOT appear in cs.Edges below — yet fronting
	// a foreign downstream with a new forward is exactly the MISMANAGE the gate exists
	// to stop. gateChainOwnership re-checks every chain participant's ownership of the
	// op host directly. Inert for a non-chain op or a host-less changeset (reconcile/
	// declarative build explicit per-edge changes that the loop below already gates).
	if err := e.gateChainOwnership(ctx, cs.Op); err != nil {
		return err
	}
	for _, ep := range cs.Edges {
		if ep.Change.Empty() {
			continue
		}
		b, ok := e.binding(ep.Edge)
		if !ok {
			continue
		}
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return fmt.Errorf("ownership gate: read live edge state (%s): %w", ep.Edge, err)
		}

		// Edge-wide foreign ownership: the whole config is generated, so NOTHING crenel
		// writes here sticks. Refuse any change, additive or not.
		if live.Generator != "" {
			return fmt.Errorf("%w: edge %q is generated/owned by %s — a crenel edit would be reverted on its next "+
				"regeneration (a Docker event / UI save / API sync); add or remove this route at the %s source instead "+
				"(--yes does not bypass this; there is no safe --force for a generator-owned edge)",
				ErrRefuseToManage, ep.Edge, live.Generator, live.Generator)
		}

		owners := ownershipByHost(live)
		for _, host := range touchedHosts(ep.Change) {
			own, present := owners[strings.ToLower(host)]
			if !present {
				continue // a new host with no existing owner — safe to add on a non-generator edge
			}
			switch own {
			case model.OwnForeign:
				src := live.Generator
				if src == "" {
					src = "another tool"
				}
				return fmt.Errorf("%w: %s on edge %q is owned by %s — a crenel edit would be reverted; manage it at the source "+
					"(--yes does not bypass this; there is no safe --force for a foreign-managed route)",
					ErrRefuseToManage, host, ep.Edge, src)
			case model.OwnUnknown:
				if !e.Force {
					return fmt.Errorf("%w: crenel cannot determine who owns %s on edge %q — refusing to mutate it. Re-run with "+
						"--force ONLY if you have verified out-of-band that crenel may manage it (--yes does not bypass this)",
						ErrRefuseToManage, host, ep.Edge)
				}
			}
		}
	}
	return nil
}

// gateChainOwnership refuses a CHAIN write whose op host is owned by a generator
// (FOREIGN) or undetermined (UNKNOWN) on ANY participating edge — the front OR the
// downstream — even where that edge's planned change is a converge no-op. It fires
// only for a real chain op (some participant FORWARDS) with a concrete host; a
// non-chain or host-less op returns nil so the per-edge loop in gateOwnership remains
// the sole gate. Same posture as the per-edge gate: --yes never bypasses; --force
// covers UNKNOWN only, never FOREIGN.
func (e *Engine) gateChainOwnership(ctx context.Context, op model.Op) error {
	if op.Host == "" {
		return nil
	}
	var parts []EdgeBinding
	isChain := false
	for _, b := range e.Edges {
		switch e.roleFor(b, op.Service) {
		case roleForward:
			parts = append(parts, b)
			isChain = true
		case roleTerminal:
			parts = append(parts, b)
		}
	}
	if !isChain {
		return nil
	}
	for _, b := range parts {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return fmt.Errorf("ownership gate (chain): read live edge state (%s): %w", b.Name, err)
		}
		if live.Generator != "" {
			return fmt.Errorf("%w: chain edge %q is generated/owned by %s — a crenel edit would be reverted on its next "+
				"regeneration; manage the chain at the %s source instead (--yes does not bypass this; there is no safe "+
				"--force for a generator-owned edge)", ErrRefuseToManage, b.Name, live.Generator, live.Generator)
		}
		switch ownershipOf(live, op.Host) {
		case model.OwnForeign:
			src := live.Generator
			if src == "" {
				src = "another tool"
			}
			return fmt.Errorf("%w: %s on chain edge %q is owned by %s — a crenel edit would be reverted; manage it at the "+
				"source (--yes does not bypass this; there is no safe --force for a foreign-managed route)",
				ErrRefuseToManage, op.Host, b.Name, src)
		case model.OwnUnknown:
			if !e.Force {
				return fmt.Errorf("%w: crenel cannot determine who owns %s on chain edge %q — refusing to mutate the chain. "+
					"Re-run with --force ONLY if you have verified out-of-band that crenel may manage it (--yes does not bypass this)",
					ErrRefuseToManage, op.Host, b.Name)
			}
		}
	}
	return nil
}

// touchedHosts returns the hosts an EdgeChange would mutate: every host it adds and
// every host it removes (deduped, sorted for deterministic messages).
func touchedHosts(ec model.EdgeChange) []string {
	seen := map[string]bool{}
	for _, r := range ec.AddRoutes {
		seen[r.Host] = true
	}
	for _, h := range ec.RemoveHosts {
		seen[h] = true
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ownershipOf returns the ownership of host's route in live (case-insensitive), or
// the empty value when host is absent.
func ownershipOf(live model.LiveEdgeState, host string) model.Ownership {
	for _, r := range live.Routes {
		if strings.EqualFold(r.Host, host) {
			return r.Ownership
		}
	}
	return ""
}

// ownershipByHost indexes a live edge's routes by lower(host) -> Ownership.
func ownershipByHost(live model.LiveEdgeState) map[string]model.Ownership {
	m := make(map[string]model.Ownership, len(live.Routes))
	for _, r := range live.Routes {
		m[strings.ToLower(r.Host)] = r.Ownership
	}
	return m
}
