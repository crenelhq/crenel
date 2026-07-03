package dnscontrol

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests exercise the REAL OSShell exec seam — the one path the rest of the
// suite never touches (everything else injects a fake). They run a THROWAWAY fake
// `dnscontrol` script on a temp path, so the real exec.CommandContext machinery is
// proven (arg passing, working dir, stdout+stderr capture, exit-code propagation,
// ctx honoring) WITHOUT contacting any real DNS provider.

// writeFakeBin writes a tiny POSIX shell script that stands in for `dnscontrol`,
// returns its path, and skips on platforms without /bin/sh.
func writeFakeBin(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("OSShell exec test needs a POSIX shell")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "dnscontrol")
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestOSShellRunsBinaryAndCapturesOutput(t *testing.T) {
	bin := writeFakeBin(t, `#!/bin/sh
echo "ARGS=$*"
echo "PWD=$(pwd)"
echo "to stderr" 1>&2
if [ "$1" = "boom" ]; then exit 3; fi
`)
	workdir := t.TempDir()
	sh := OSShell{Bin: bin}

	out, err := sh.Run(context.Background(), workdir, "get-zones", "--format=tsv", "cloudflare", "CLOUDFLAREAPI", "example.com")
	if err != nil {
		t.Fatalf("expected success, got err=%v out=%q", err, out)
	}
	if !strings.Contains(out, "ARGS=get-zones --format=tsv cloudflare CLOUDFLAREAPI example.com") {
		t.Errorf("args not passed through: %q", out)
	}
	// Working dir must be where dnsconfig.js/creds.json live.
	if !strings.Contains(out, "PWD="+workdir) {
		t.Errorf("cmd.Dir not set to workdir %q: %q", workdir, out)
	}
	// stderr is merged into stdout (so a real dnscontrol error is visible).
	if !strings.Contains(out, "to stderr") {
		t.Errorf("stderr not captured: %q", out)
	}
}

func TestOSShellPropagatesNonZeroExit(t *testing.T) {
	bin := writeFakeBin(t, `#!/bin/sh
echo "ARGS=$*"
if [ "$1" = "boom" ]; then exit 3; fi
`)
	sh := OSShell{Bin: bin}
	out, err := sh.Run(context.Background(), t.TempDir(), "boom")
	if err == nil {
		t.Fatalf("expected non-zero exit to propagate as error, out=%q", out)
	}
	if !strings.Contains(out, "ARGS=boom") {
		t.Errorf("output should still be captured on failure: %q", out)
	}
}

func TestOSShellHonorsCanceledContext(t *testing.T) {
	bin := writeFakeBin(t, `#!/bin/sh
echo hi
`)
	sh := OSShell{Bin: bin}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled — exec must not run to completion as success.
	if _, err := sh.Run(ctx, t.TempDir(), "get-zones"); err == nil {
		t.Error("expected canceled context to surface an error")
	}
}

func TestOSShellMissingBinaryErrors(t *testing.T) {
	sh := OSShell{Bin: filepath.Join(t.TempDir(), "does-not-exist")}
	if _, err := sh.Run(context.Background(), t.TempDir(), "get-zones"); err == nil {
		t.Error("expected error for a missing dnscontrol binary")
	}
}
