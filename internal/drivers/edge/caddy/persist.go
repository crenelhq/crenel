package caddy

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/crenelhq/crenel/internal/model"
)

// persist.go implements OPTIONAL on-disk persistence for the Caddy driver, closing
// the admin-API durability gap: the admin API mutates Caddy's IN-MEMORY config, so
// a `docker restart` reloads the on-disk Caddyfile and DROPS crenel-managed routes
// (proven on the live edge). When a persist path is configured, Crenel ADDITIVELY
// writes its managed routes into the mounted Caddyfile (between sentinels, never
// touching unmanaged config), validates it, and reloads with the CORRECT
// invocation. See USABILITY-DESIGN.md §B. Default OFF.

const (
	// persistBegin/persistEnd delimit the crenel-managed region of the on-disk
	// Caddyfile. Everything OUTSIDE these sentinels is the operator's own config and
	// is preserved byte-for-byte across a Persist.
	persistBegin = "# crenel-managed-begin — managed by crenel; do not edit between these markers"
	persistEnd   = "# crenel-managed-end"
)

// CaddyCLI is the injected seam for the two on-disk operations Persist needs:
// validating a candidate Caddyfile and reloading the running Caddy from it. The
// default OSCaddyCLI shells out; tests inject a fake so the suite never execs caddy.
type CaddyCLI interface {
	// Validate checks that configPath is a valid Caddyfile. A non-nil error means
	// DO NOT reload (the candidate is rejected).
	Validate(ctx context.Context, configPath string) error
	// Reload reloads the running Caddy from configPath. It MUST use the correct
	// invocation (`caddy reload --config <path>`), never a bare `caddy reload`.
	Reload(ctx context.Context, configPath string) error
}

// OSCaddyCLI shells out to the real `caddy` binary. It is the default when a
// persist path is configured and no CLI is injected.
type OSCaddyCLI struct {
	// Adapter is the config adapter passed to `caddy validate` (default "caddyfile").
	Adapter string
}

func (c OSCaddyCLI) adapter() string {
	if c.Adapter == "" {
		return "caddyfile"
	}
	return c.Adapter
}

// Validate runs `caddy validate --config <path> --adapter caddyfile`.
func (c OSCaddyCLI) Validate(ctx context.Context, configPath string) error {
	out, err := exec.CommandContext(ctx, "caddy", "validate", "--config", configPath, "--adapter", c.adapter()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy validate failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Reload runs `caddy reload --config <path>` — the correct, non-wedging
// invocation diagnosed on the live edge (NEVER a bare `caddy reload`).
func (c OSCaddyCLI) Reload(ctx context.Context, configPath string) error {
	out, err := exec.CommandContext(ctx, "caddy", "reload", "--config", configPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy reload failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LogCaddyCLI is a no-exec CaddyCLI for the safe, no-infra demo path (used with a
// fake-seeded edge): it SKIPS validation (no real caddy binary) and records the
// reload it WOULD run, so the on-disk injection is demoable without infrastructure.
type LogCaddyCLI struct{ W io.Writer }

func (c LogCaddyCLI) Validate(ctx context.Context, configPath string) error { return nil }
func (c LogCaddyCLI) Reload(ctx context.Context, configPath string) error {
	if c.W != nil {
		fmt.Fprintf(c.W, "[persist] would run: caddy reload --config %s\n", configPath)
	}
	return nil
}

// WithPersistPath enables on-disk persistence: after a verified apply, Crenel
// writes its managed routes into the Caddyfile at path (additively), validates,
// and reloads. It makes the driver implement ports.Persister.
func WithPersistPath(path string) Option { return func(d *Driver) { d.persistPath = path } }

// WithCaddyCLI injects the validate/reload seam (default OSCaddyCLI).
func WithCaddyCLI(cli CaddyCLI) Option { return func(d *Driver) { d.caddyCLI = cli } }

// WithPersistenceModel OVERRIDES the edge's declared durability posture
// (model.PersistenceModel). Use it to declare a posture the admin API cannot reveal:
// "resume" (the control plane boots with `--resume`, so admin writes autosave durably
// with no crenel action) or "durable-file"/"durable-config" to assert an out-of-band
// persist. Absent an override the driver defaults to durable-file when a persist path is
// configured, else ephemeral-admin (the safe default). See persistenceModel.
func WithPersistenceModel(m model.PersistenceModel) Option {
	return func(d *Driver) { d.persistenceDeclared = m }
}

// Persist writes the current crenel-managed routes into the on-disk Caddyfile
// ADDITIVELY (only the sentinel-delimited region), validates the result, and — on
// success — reloads Caddy ONCE (debounced: one validate + one reload per call,
// never per route). It is best-effort durability called by core AFTER a verified
// apply; a failure is surfaced as a warning, not a rollback. Implements
// ports.Persister.
func (d *Driver) Persist(ctx context.Context) error {
	if d.persistPath == "" {
		return nil // persistence not configured — no-op
	}
	live, err := d.ReadLiveState(ctx)
	if err != nil {
		return fmt.Errorf("persist: read live: %w", err)
	}

	existingBytes, err := d.configStoreOrDefault().Read(ctx)
	if err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	existing := string(existingBytes)

	// Mirror the crenel-managed http-proxy routes (passthrough lives in the layer4 JSON
	// tree, not the Caddyfile; out of scope for the on-disk mirror). A route counts as
	// crenel's if it carries crenel's @id (a freshly-inserted route) OR its host is
	// ALREADY in the crenel Caddyfile region (TRIAL-FIX-DURABLE-2): after a durable
	// persist's reload, a previously-persisted route is re-derived from the Caddyfile and
	// carries NO @id, so a NAIVE @id-only filter would OMIT it from a subsequent persist —
	// dropping it from the region (which the no-drift-loss gate then rightly refuses,
	// blocking a second durable host). Including the existing-region hosts keeps every
	// already-managed host in the mirror so multiple durable hosts coexist. A host that
	// has since left live (unexposed) is absent from live.Routes, so it correctly drops.
	region := existingRegionHostSet(existing)
	var managed []model.Route
	for _, r := range live.Routes {
		if r.Upstream.Mode != model.ModeHTTPProxy {
			continue
		}
		if r.Managed || region[strings.ToLower(r.Host)] {
			managed = append(managed, r)
		}
	}

	// Wildcard-site reconcile: when the operator routes through wildcard site blocks
	// (the real home-edge shape), a managed host's DURABLE form is a per-host handle
	// INSIDE the covering `*.zone` site — inheriting its TLS — not a top-level `host {}`
	// site, which would shadow the wildcard and lose its cert config. Dispatch to the
	// wildcard-faithful reconciler when any managed host is covered by a wildcard site;
	// the flat top-level form below is the greenfield/simple-edge path. See
	// persist_caddyfile.go.
	if d.inSiteReconcile(existing, managed) {
		return d.persistInSite(ctx, existing, managed, live.Hosts())
	}

	merged := mergeManagedRegion(existing, renderManagedBlocks(managed, d.authSnippet))

	// Write a candidate next to the target, validate it, and only on success replace
	// the target atomically + reload. A bad candidate never touches the live file.
	cli := d.caddyCLI
	if cli == nil {
		cli = OSCaddyCLI{}
	}
	tmp := filepath.Join(filepath.Dir(d.persistPath), ".crenel-caddyfile.tmp")
	if err := os.WriteFile(tmp, []byte(merged), 0o644); err != nil {
		return fmt.Errorf("persist: write candidate: %w", err)
	}
	defer os.Remove(tmp)

	// Bound each subprocess: a hung `caddy validate`/`reload` must never wedge the
	// CLI (the postmortem's lesson is "never hang"). Reuse the driver's write bound.
	to := d.writeTimeout
	if to <= 0 {
		to = defaultWriteTimeout
	}
	vctx, vcancel := context.WithTimeout(ctx, to)
	defer vcancel()
	if err := cli.Validate(vctx, tmp); err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	if err := os.Rename(tmp, d.persistPath); err != nil {
		return fmt.Errorf("persist: replace %s: %w", d.persistPath, err)
	}
	rctx, rcancel := context.WithTimeout(ctx, to)
	defer rcancel()
	if err := cli.Reload(rctx, d.persistPath); err != nil {
		return fmt.Errorf("persist: reload: %w", err)
	}
	return nil
}

// renderManagedBlocks renders crenel's managed host site-blocks (no deny — the
// operator's base Caddyfile owns global/default config). Sorted for stable output.
// A route carrying a forward-auth policy emits an `import <snippet>` reference
// before reverse_proxy — the canonical Caddyfile auth-by-reference form, resolving
// the snippet via snippetFor (the operator owns the snippet definition).
func renderManagedBlocks(routes []model.Route, snippetFor func(string) string) string {
	sorted := append([]model.Route(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })
	var b strings.Builder
	for _, r := range sorted {
		if policy := r.Upstream.Auth; policy != "" && policy != model.AuthNone {
			fmt.Fprintf(&b, "%s {\n\timport %s\n\treverse_proxy %s\n}\n", r.Host, snippetFor(policy), r.Upstream.Address)
			continue
		}
		fmt.Fprintf(&b, "%s {\n\treverse_proxy %s\n}\n", r.Host, r.Upstream.Address)
	}
	return b.String()
}

// mergeManagedRegion replaces the sentinel-delimited crenel region of existing
// with block (rendered managed routes), preserving everything outside the
// sentinels byte-for-byte. If no sentinel region exists yet, it appends a fresh
// one at the end. An empty block still writes empty sentinels (so an unexpose that
// empties the managed set leaves a clean, well-formed region).
func mergeManagedRegion(existing, block string) string {
	region := persistBegin + "\n" + strings.TrimRight(block, "\n") + "\n" + persistEnd + "\n"
	if block == "" {
		region = persistBegin + "\n" + persistEnd + "\n"
	}

	begin := strings.Index(existing, persistBegin)
	if begin < 0 {
		// No region yet — append one, ensuring a separating newline.
		sep := ""
		if existing != "" && !strings.HasSuffix(existing, "\n") {
			sep = "\n"
		}
		if existing != "" {
			sep += "\n"
		}
		return existing + sep + region
	}
	// Replace from the begin sentinel through the end sentinel (inclusive).
	endIdx := strings.Index(existing[begin:], persistEnd)
	if endIdx < 0 {
		// Malformed (begin without end): replace from begin to EOF.
		return existing[:begin] + region
	}
	endIdx = begin + endIdx + len(persistEnd)
	// Consume a trailing newline after the end sentinel so we don't accrete blanks.
	rest := existing[endIdx:]
	rest = strings.TrimPrefix(rest, "\n")
	return existing[:begin] + region + rest
}
