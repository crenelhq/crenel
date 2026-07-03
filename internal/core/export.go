package core

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/crenelhq/crenel/internal/model"
)

// ExportSnapshot is a point-in-time dump of live state. It is throwaway: Crenel
// never reads it back (there is no stored desired state). It exists for humans,
// backups, and debugging only. With M4 it carries one entry per edge.
//
// SECURITY: a snapshot can carry secret bytes — a declared-unknown excerpt
// (ExportEdge.Unparsed[].RawExcerpt) may capture an unmodeled secret-bearing block
// (an nginx auth header, a basic-auth hash). The default export holds REAL values
// (so it is a faithful record); the CLI writes it 0600 and offers a --redacted
// scrub for sharing. Redaction is a presentation concern applied at the CLI, so the
// snapshot struct itself always holds the real read-back values. See SECURITY.md §6.
type ExportSnapshot struct {
	Edges []ExportEdge   `json:"edges"`
	DNS   []ScopeRecords `json:"dns,omitempty"`
}

type ExportEdge struct {
	Name                string        `json:"name"`
	Provider            string        `json:"provider"`
	DenyCatchAllPresent bool          `json:"deny_catchall_present"`
	Routes              []ExportRoute `json:"routes"`
	// Unparsed records what the edge reported that crenel could not fully model — the
	// P0 declared-unknowns — so an export is a faithful picture of coverage, not just
	// the understood subset. Its RawExcerpt is the secret-bearing field (see above).
	Unparsed []model.Unparsed `json:"unparsed,omitempty"`
}

type ExportRoute struct {
	Host    string `json:"host"`
	Backend string `json:"backend"`
}

// ExportSnapshotData reads live state and returns the structured snapshot (real
// values). The CLI marshals it (and optionally redacts the shareable copy).
func (e *Engine) ExportSnapshotData(ctx context.Context) (ExportSnapshot, error) {
	var snap ExportSnapshot
	for _, b := range e.Edges {
		live, err := b.Provider.ReadLiveState(ctx)
		if err != nil {
			return snap, fmt.Errorf("read live edge state (%s): %w", b.Name, err)
		}
		ee := ExportEdge{
			Name:                b.Name,
			Provider:            b.Provider.Name(),
			DenyCatchAllPresent: live.DenyCatchAllPresent,
			Unparsed:            live.Unparsed,
		}
		for _, r := range live.Routes {
			ee.Routes = append(ee.Routes, ExportRoute{Host: r.Host, Backend: r.Upstream.Address})
		}
		snap.Edges = append(snap.Edges, ee)
	}
	for _, dp := range e.DNS {
		recs, err := dp.LiveRecords(ctx)
		if err != nil {
			return snap, fmt.Errorf("read live dns (%s): %w", dp.Name(), err)
		}
		snap.DNS = append(snap.DNS, ScopeRecords{
			Provider: dp.Name(),
			Scope:    dp.Scope(),
			Records:  recs,
		})
	}
	return snap, nil
}

// Export reads live state and returns it serialized as pretty JSON (real values).
func (e *Engine) Export(ctx context.Context) ([]byte, error) {
	snap, err := e.ExportSnapshotData(ctx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(snap, "", "  ")
}
