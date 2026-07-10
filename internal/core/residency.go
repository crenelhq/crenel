package core

import (
	"fmt"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// residency.go — the residency selector's core-side gate.
//
// A host's RESIDENCY class (model.Op.Residency / Exposure.Residency) is the
// operator's declaration of WHERE the service lives, so each internal resolver
// can answer with its own vantage-correct target for that host — the
// `target(class, vantage)` rule of docs/REFERENCE-ARCH-split-horizon.md §2. The
// resolution itself is a DRIVER concern (ports.ResidencyTargeter: each provider
// resolves the class against its own `targets` map, refusing an unknown class);
// core's job is only to guarantee the refuse-loudly contract holds even for a
// provider that predates the capability:
//
//   - class "" (home-resident, the default and the bulk) gates nothing — every
//     provider answers its configured edge_addr, byte-identical to pre-residency
//     behavior;
//   - a non-default class on an INTERNAL provider WITHOUT the capability is a
//     plan-time refusal: that provider would otherwise silently write its default
//     edge_addr and misdirect its entire vantage (the exact wrong-target failure
//     the selector exists to prevent);
//   - PUBLIC providers are exempt by design: the §2 table's public column is
//     class-invariant (every class's public answer is the public edge), so a
//     public provider legitimately ignores the class.

// residencySupported reports (as a loud error) whether dp can honor a residency
// class at all. It does NOT check the class has a target — that is the driver's
// own ResidencyTarget refusal, raised from DesiredRecords with the instance name
// attached. Shared by the imperative plan (engine.Plan) and the declarative plan
// (planDeclarative) so both paths refuse identically.
func residencySupported(dp ports.DNSProvider, class string) error {
	if class == "" || dp.Scope() != model.ScopeInternal {
		return nil
	}
	if _, ok := dp.(ports.ResidencyTargeter); ok {
		return nil
	}
	return fmt.Errorf("dns %s: provider does not support residency classes — residency %q would silently get the default edge_addr on this vantage; use a provider type with per-residency targets (adguard/pihole) or drop the residency",
		dp.Name(), class)
}
