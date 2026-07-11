package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// dnsCoverageRecords returns the provider's PRESENCE/coverage view of its zone: the
// full owned+foreign record list when the provider offers one (ports.CoverageReporter
// — the surgical Cloudflare driver, whose LiveRecords is marker-filtered to crenel's
// own records), else the already-read LiveRecords `owned` slice unchanged.
//
// The fallback is not a degradation: AdGuard/Pi-hole LiveRecords are zone-filtered but
// NOT ownership-filtered (they have no ownership marker), so for them LiveRecords
// ALREADY IS the full coverage view — the asymmetry the CoverageReporter capability
// exists to close on marker-filtered providers only. Callers must consume the result
// for presence checks ONLY (see the CoverageReporter contract): never for mutation,
// ownership, or owned-record value-drift decisions.
func dnsCoverageRecords(ctx context.Context, dp ports.DNSProvider, owned []model.Record) ([]model.Record, error) {
	cr, ok := dp.(ports.CoverageReporter)
	if !ok {
		return owned, nil
	}
	recs, err := cr.CoverageRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("read dns coverage (%s): %w", dp.Name(), err)
	}
	return recs, nil
}

// exactCoverageMatch reports whether any live zone answer at a record's key already
// matches the desired value — presence satisfied by an exact record (owned or
// foreign). All answers at the key are checked so a foreign+matching answer is not
// masked by another record at the same name.
func exactCoverageMatch(liveValues []string, desired string) bool {
	for _, v := range liveValues {
		if sameDNSValue(v, desired) {
			return true
		}
	}
	return false
}

// sameDNSValue reports whether two DNS answer values are the same, under the one
// normalization the codebase already uses everywhere values are compared
// (case-insensitive, surrounding-whitespace-insensitive).
func sameDNSValue(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
