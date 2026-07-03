package caddy

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/crenelhq/crenel/internal/drivers/transport"
)

// persist_exec.go provides the TRANSPORT-BACKED durable-persist seams the home edge
// needs: its boot Caddyfile lives on the LXC HOST (/etc/homeedge/caddy/Caddyfile,
// bind-mounted READ-ONLY into the container), while `caddy validate`/`reload`/`adapt`
// must run INSIDE the container (where the caddy binary + container DNS live). So a
// durable persist crosses TWO exec channels — a file channel to the host and a caddy
// channel to the container — each an operator-supplied argv PREFIX crenel does not
// shell-parse (the script travels over stdin, exactly like the ssh-exec admin transport).
//
// These seams are the production wiring exercised by the gated LIVE trial. Like the
// transport's OSRunner/OSForwarder, the REAL exec is never run by the unit suite (the
// Runner is faked); the tests assert the exact generated argv + script, and the live
// trial is the only real exercise. See ExecConfigStore/ExecCaddyCLI/ExecAdapter.

// OSAdapter shells out to the local `caddy adapt` binary (the on-box / direct case). It
// is the Adapter the durable reconciler uses to prove a candidate re-adapts to the live
// managed state when caddy runs locally.
type OSAdapter struct {
	// Adapter is the config adapter (default "caddyfile").
	Adapter string
}

func (a OSAdapter) adapter() string {
	if a.Adapter == "" {
		return "caddyfile"
	}
	return a.Adapter
}

// Adapt writes the candidate to a temp file and runs `caddy adapt`, returning the JSON.
func (a OSAdapter) Adapt(ctx context.Context, configBytes []byte) ([]byte, error) {
	// caddy adapt reads --config from a path; feed via a temp file the local fs owns.
	cmd := exec.CommandContext(ctx, "caddy", "adapt", "--config", "/dev/stdin", "--adapter", a.adapter())
	cmd.Stdin = strings.NewReader(string(configBytes))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("caddy adapt failed: %w", err)
	}
	return out, nil
}

// execScript renders a POSIX-sh script that base64-decodes embedded bytes to a path, or
// runs a command, etc. — the same single-quote-safe, stdin-fed pattern the ssh-exec
// transport uses so quoting survives an arbitrarily nested ssh→pct→docker chain.

// ExecConfigStore reads/writes the boot Caddyfile over an exec chain landing a shell on
// the host that HOLDS the file (for the home edge: `ssh root@pve1 pct exec 150 -- sh`).
// The bytes travel base64-embedded over stdin; nothing crosses a shell-parse boundary.
type ExecConfigStore struct {
	// Command is the exec PREFIX (argv, not shell-parsed) landing a stdin-reading POSIX
	// shell where the file lives. The innermost element MUST be a bare `sh`.
	Command []string
	// Path is the boot Caddyfile path ON THAT HOST (e.g. /etc/homeedge/caddy/Caddyfile).
	Path string
	// Runner is the exec seam (default transport.OSRunner shells out).
	Runner transport.Runner
}

func (s ExecConfigStore) runner() transport.Runner {
	if s.Runner == nil {
		return transport.OSRunner{}
	}
	return s.Runner
}

// Read returns the boot file bytes via `cat 'path'`.
func (s ExecConfigStore) Read(ctx context.Context) ([]byte, error) {
	if len(s.Command) == 0 || s.Path == "" {
		return nil, fmt.Errorf("exec config store: command and path required")
	}
	script := fmt.Sprintf("cat '%s'", s.Path)
	out, errb, code, err := s.runner().Run(ctx, s.Command, []byte(script))
	if err != nil || code != 0 {
		return nil, fmt.Errorf("exec config store read %s: exit %d: %v: %s", s.Path, code, err, snippetBytes(errb))
	}
	return out, nil
}

// WriteCandidate stages the candidate at the boot path's sibling (Path+".crenel-candidate")
// on the far end — where the caddy binary can validate it (the host dir ro-mounts into the
// container, so the sibling appears beside the boot file there too). The live boot file is
// untouched.
func (s ExecConfigStore) WriteCandidate(ctx context.Context, b []byte) error {
	if len(s.Command) == 0 || s.Path == "" {
		return fmt.Errorf("exec config store: command and path required")
	}
	enc := base64.StdEncoding.EncodeToString(b)
	script := fmt.Sprintf("printf %%s '%s' | base64 -d > '%s.crenel-candidate'", enc, s.Path)
	_, errb, code, err := s.runner().Run(ctx, s.Command, []byte(script))
	if err != nil || code != 0 {
		return fmt.Errorf("exec config store stage %s: exit %d: %v: %s", s.Path, code, err, snippetBytes(errb))
	}
	return nil
}

// RemoveCandidate deletes the staged candidate (best-effort).
func (s ExecConfigStore) RemoveCandidate(ctx context.Context) error {
	if len(s.Command) == 0 || s.Path == "" {
		return nil
	}
	script := fmt.Sprintf("rm -f '%s.crenel-candidate'", s.Path)
	s.runner().Run(ctx, s.Command, []byte(script))
	return nil
}

// Write atomically commits b as the new boot config: decode to a sibling temp then mv —
// an atomic replace; a failed decode never truncates the live boot file.
func (s ExecConfigStore) Write(ctx context.Context, b []byte) error {
	if len(s.Command) == 0 || s.Path == "" {
		return fmt.Errorf("exec config store: command and path required")
	}
	enc := base64.StdEncoding.EncodeToString(b)
	script := fmt.Sprintf("printf %%s '%s' | base64 -d > '%s.crenel-commit' && mv '%s.crenel-commit' '%s'",
		enc, s.Path, s.Path, s.Path)
	_, errb, code, err := s.runner().Run(ctx, s.Command, []byte(script))
	if err != nil || code != 0 {
		return fmt.Errorf("exec config store write %s: exit %d: %v: %s", s.Path, code, err, snippetBytes(errb))
	}
	return nil
}

// ExecCaddyCLI runs `caddy validate`/`caddy reload` over an exec chain landing a shell
// INSIDE the caddy container (for the home edge: `ssh root@pve1 pct exec 150 -- docker
// exec -i caddy sh`). It implements CaddyCLI for the transport-backed durable path.
type ExecCaddyCLI struct {
	Command []string // exec prefix landing a stdin-reading shell in the container
	Adapter string   // --adapter (default caddyfile)
	Runner  transport.Runner
}

func (c ExecCaddyCLI) runner() transport.Runner {
	if c.Runner == nil {
		return transport.OSRunner{}
	}
	return c.Runner
}
func (c ExecCaddyCLI) adapter() string {
	if c.Adapter == "" {
		return "caddyfile"
	}
	return c.Adapter
}

// Validate runs `caddy validate --config 'path' --adapter <adapter>` in the container.
func (c ExecCaddyCLI) Validate(ctx context.Context, path string) error {
	script := fmt.Sprintf("caddy validate --config '%s' --adapter '%s'", path, c.adapter())
	out, errb, code, err := c.runner().Run(ctx, c.Command, []byte(script))
	if err != nil || code != 0 {
		return fmt.Errorf("caddy validate failed (exit %d): %v: %s", code, err, diagBytes(out, errb))
	}
	return nil
}

// Reload runs `caddy reload --config 'path'` in the container (the correct, non-wedging
// invocation diagnosed on the live edge — NEVER a bare `caddy reload`).
func (c ExecCaddyCLI) Reload(ctx context.Context, path string) error {
	script := fmt.Sprintf("caddy reload --config '%s'", path)
	out, errb, code, err := c.runner().Run(ctx, c.Command, []byte(script))
	if err != nil || code != 0 {
		return fmt.Errorf("caddy reload failed (exit %d): %v: %s", code, err, diagBytes(out, errb))
	}
	return nil
}

// ExecAdapter runs `caddy adapt` over an exec chain in the container, returning the JSON
// — the transport-backed re-adaptation read-back. It writes the candidate to a container
// temp via base64 (over stdin), adapts it, and prints the JSON to stdout.
type ExecAdapter struct {
	Command []string // exec prefix landing a stdin-reading shell in the container
	Adapter string
	Runner  transport.Runner
}

func (a ExecAdapter) runner() transport.Runner {
	if a.Runner == nil {
		return transport.OSRunner{}
	}
	return a.Runner
}
func (a ExecAdapter) adapter() string {
	if a.Adapter == "" {
		return "caddyfile"
	}
	return a.Adapter
}

// Adapt decodes the candidate to a container temp, runs `caddy adapt`, and returns the
// JSON on stdout. A non-zero exit (an unadaptable candidate) is an error.
func (a ExecAdapter) Adapt(ctx context.Context, configBytes []byte) ([]byte, error) {
	if len(a.Command) == 0 {
		return nil, fmt.Errorf("exec adapter: command required")
	}
	enc := base64.StdEncoding.EncodeToString(configBytes)
	const tmp = "/tmp/crenel-adapt.caddyfile"
	script := fmt.Sprintf("printf %%s '%s' | base64 -d > '%s' && caddy adapt --config '%s' --adapter '%s'; rc=$?; rm -f '%s'; exit $rc",
		enc, tmp, tmp, a.adapter(), tmp)
	out, errb, code, err := a.runner().Run(ctx, a.Command, []byte(script))
	if err != nil || code != 0 {
		return nil, fmt.Errorf("exec adapt failed (exit %d): %v: %s", code, err, snippetBytes(errb))
	}
	return out, nil
}

func snippetBytes(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func diagBytes(out, errb []byte) string {
	if s := snippetBytes(errb); s != "" {
		return "stderr: " + s
	}
	return "stdout: " + snippetBytes(out)
}
