package caddy

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// recRunner is a hermetic fake transport.Runner: it records the argv + stdin script and
// returns canned output, so the exec seams' generated commands are asserted EXACTLY
// without spawning ssh/docker/caddy (mirrors the transport package's fakeRunner).
type recRunner struct {
	gotArgv  []string
	gotStdin string
	stdout   string
	stderr   string
	code     int
}

func (r *recRunner) Run(_ context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	r.gotArgv = append([]string(nil), argv...)
	r.gotStdin = string(stdin)
	return []byte(r.stdout), []byte(r.stderr), r.code, nil
}

var homeFileCmd = []string{"ssh", "root@ml350", "pct", "exec", "113", "--", "sh"}
var homeCaddyCmd = []string{"ssh", "root@ml350", "pct", "exec", "113", "--", "docker", "exec", "-i", "caddy", "sh"}

func TestExecConfigStore_ReadWrite(t *testing.T) {
	// READ: cat the host-side path over the file channel.
	rd := &recRunner{stdout: "*.homelab.example {\n}\n"}
	store := ExecConfigStore{Command: homeFileCmd, Path: "/opt/stacks/caddy/conf/Caddyfile", Runner: rd}
	got, err := store.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "*.homelab.example {\n}\n" {
		t.Fatalf("read body: %q", got)
	}
	if strings.Join(rd.gotArgv, " ") != strings.Join(homeFileCmd, " ") {
		t.Fatalf("read argv: %v", rd.gotArgv)
	}
	if rd.gotStdin != "cat '/opt/stacks/caddy/conf/Caddyfile'" {
		t.Fatalf("read script: %q", rd.gotStdin)
	}

	body := []byte("new caddyfile bytes\n")
	enc := base64.StdEncoding.EncodeToString(body)

	// STAGE: candidate written to the boot-path sibling (never the live file).
	st := &recRunner{}
	store.Runner = st
	if err := store.WriteCandidate(context.Background(), body); err != nil {
		t.Fatalf("stage: %v", err)
	}
	wantStage := "printf %s '" + enc + "' | base64 -d > '/opt/stacks/caddy/conf/Caddyfile.crenel-candidate'"
	if st.gotStdin != wantStage {
		t.Fatalf("stage script:\n got %q\nwant %q", st.gotStdin, wantStage)
	}

	// COMMIT: base64-decode to a sibling temp then atomically mv into place.
	wr := &recRunner{}
	store.Runner = wr
	if err := store.Write(context.Background(), body); err != nil {
		t.Fatalf("write: %v", err)
	}
	wantScript := "printf %s '" + enc + "' | base64 -d > '/opt/stacks/caddy/conf/Caddyfile.crenel-commit' && " +
		"mv '/opt/stacks/caddy/conf/Caddyfile.crenel-commit' '/opt/stacks/caddy/conf/Caddyfile'"
	if wr.gotStdin != wantScript {
		t.Fatalf("write script:\n got %q\nwant %q", wr.gotStdin, wantScript)
	}

	// CLEANUP: remove the staged candidate (best-effort).
	rm := &recRunner{}
	store.Runner = rm
	_ = store.RemoveCandidate(context.Background())
	if rm.gotStdin != "rm -f '/opt/stacks/caddy/conf/Caddyfile.crenel-candidate'" {
		t.Fatalf("cleanup script: %q", rm.gotStdin)
	}
}

func TestExecCaddyCLI_ValidateReload(t *testing.T) {
	r := &recRunner{}
	cli := ExecCaddyCLI{Command: homeCaddyCmd, Runner: r}
	if err := cli.Validate(context.Background(), "/etc/caddy/Caddyfile.crenel-candidate"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if r.gotStdin != "caddy validate --config '/etc/caddy/Caddyfile.crenel-candidate' --adapter 'caddyfile'" {
		t.Fatalf("validate script: %q", r.gotStdin)
	}
	if strings.Join(r.gotArgv, " ") != strings.Join(homeCaddyCmd, " ") {
		t.Fatalf("validate argv: %v", r.gotArgv)
	}
	if err := cli.Reload(context.Background(), "/etc/caddy/Caddyfile"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if r.gotStdin != "caddy reload --config '/etc/caddy/Caddyfile'" {
		t.Fatalf("reload script: %q", r.gotStdin)
	}
}

func TestExecCaddyCLI_NonZeroExitIsError(t *testing.T) {
	r := &recRunner{code: 1, stderr: "adapt: unknown directive"}
	cli := ExecCaddyCLI{Command: homeCaddyCmd, Runner: r}
	if err := cli.Validate(context.Background(), "/x"); err == nil {
		t.Fatal("a non-zero validate exit must be an error")
	}
}

func TestExecAdapter_AdaptReturnsJSON(t *testing.T) {
	r := &recRunner{stdout: `{"apps":{"http":{}}}`}
	ad := ExecAdapter{Command: homeCaddyCmd, Runner: r}
	out, err := ad.Adapt(context.Background(), []byte("*.x.com {\n}\n"))
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if string(out) != `{"apps":{"http":{}}}` {
		t.Fatalf("adapt json: %q", out)
	}
	// The candidate is base64-fed to a container temp, adapted, then cleaned up.
	if !strings.Contains(r.gotStdin, "base64 -d > '/tmp/crenel-adapt.caddyfile'") ||
		!strings.Contains(r.gotStdin, "caddy adapt --config '/tmp/crenel-adapt.caddyfile' --adapter 'caddyfile'") ||
		!strings.Contains(r.gotStdin, "rm -f '/tmp/crenel-adapt.caddyfile'") {
		t.Fatalf("adapt script shape: %q", r.gotStdin)
	}
}
