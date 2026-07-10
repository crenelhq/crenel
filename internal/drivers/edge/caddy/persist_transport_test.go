package caddy

import (
	"context"
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/drivers/transport"
	"github.com/crenelhq/crenel/internal/ports"
)

// persist_transport_test.go pins the durability fix: when the admin transport is an exec
// chain (ssh-exec → `docker exec -i caddy sh`), the persist's `caddy reload` MUST run
// THROUGH that chain — inside the container where the boot file, the caddy binary, and the
// admin API all live — NEVER a LOCAL `caddy` on crenel's host. The host-exec path was the
// live bug: the host `caddy reload` adapted the on-disk file but the container-only admin
// API answered `connection refused` on every persist.

// execCall records one exec of the chain (argv prefix + the stdin script).
type execCall struct {
	argv   []string
	script string
}

// recExecRunner records every exec, returning a canned exit. failOn, when non-empty, makes
// any script CONTAINING it exit non-zero (to prove a reload failure still surfaces).
type recExecRunner struct {
	calls  []execCall
	failOn string
}

func (r *recExecRunner) Run(_ context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	r.calls = append(r.calls, execCall{argv: append([]string(nil), argv...), script: string(stdin)})
	if r.failOn != "" && strings.Contains(string(stdin), r.failOn) {
		return nil, []byte("simulated caddy failure"), 1, nil
	}
	return nil, nil, 0, nil
}

func (r *recExecRunner) call(substr string) (execCall, bool) {
	for _, c := range r.calls {
		if strings.Contains(c.script, substr) {
			return c, true
		}
	}
	return execCall{}, false
}

// fakeExecXport is a fake admin transport that is ALSO an exec transport: admin calls (Do)
// tunnel to an in-process caddyfake, while the exec seams (ExecCommand/ExecAdminAddress/
// ExecRunner) hand the durable persist the SAME channel — so the reconciler runs caddy
// validate/reload/adapt over a fake Runner, fully hermetically.
type fakeExecXport struct {
	inner  ports.Transport
	cmd    []string
	addr   string
	runner transport.Runner
}

func (f *fakeExecXport) Do(ctx context.Context, method, path, ct string, body []byte) (int, []byte, error) {
	return f.inner.Do(ctx, method, path, ct, body)
}
func (f *fakeExecXport) ExecCommand() []string        { return f.cmd }
func (f *fakeExecXport) ExecAdminAddress() string     { return f.addr }
func (f *fakeExecXport) ExecRunner() transport.Runner { return f.runner }

// dockerExecCmd is the home edge's caddy channel: ssh → pct exec → docker exec -i caddy sh.
var dockerExecCmd = []string{"ssh", "root@ml350", "pct", "exec", "113", "--", "docker", "exec", "-i", "caddy", "sh"}

// newExecDriver builds a durable driver whose admin+caddy channel is the fake exec transport
// and whose boot file lives locally at bootPath (the file channel is out of scope here). A
// faithful fake adapter is injected so the adapt read-back passes; the CaddyCLI is LEFT
// UNSET so the driver defaults it onto the transport (the code under test).
func newExecDriver(t *testing.T, boot string, runner transport.Runner) *Driver {
	t.Helper()
	fake := caddyfake.New()
	t.Cleanup(fake.Close)
	if err := fake.SeedJSON(liveWithManaged); err != nil {
		t.Fatal(err)
	}
	xt := &fakeExecXport{inner: transport.NewDirect(fake.URL()), cmd: dockerExecCmd, addr: "127.0.0.1:2019", runner: runner}
	// persistPath is the IN-CONTAINER path caddy sees; the config store commits the real
	// bytes to the local temp file, decoupling the container path from the file location.
	return New("http://placeholder-admin:2019", static.New(map[string]string{}),
		WithGranularApply(),
		WithPersistPath("/etc/caddy/Caddyfile"),
		WithTransport(xt),
		WithConfigStore(localConfigStore{path: boot}),
		WithAdapter(caddyfileAdapter{server: "srv0"}))
}

func TestPersist_ReloadRunsThroughTransport(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile)
	rr := &recExecRunner{}
	d := newExecDriver(t, boot, rr)

	if err := d.Persist(context.Background()); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// The reload ran THROUGH the transport's exec chain (docker exec … caddy sh), targeting
	// the IN-CONTAINER path with an explicit --address — not a host exec of a local caddy.
	wantReload := "caddy reload --config '/etc/caddy/Caddyfile' --address '127.0.0.1:2019'"
	rc, ok := rr.call("caddy reload")
	if !ok {
		t.Fatalf("no reload ran through the transport; calls: %+v", rr.calls)
	}
	if rc.script != wantReload {
		t.Fatalf("reload script:\n got %q\nwant %q", rc.script, wantReload)
	}
	if strings.Join(rc.argv, " ") != strings.Join(dockerExecCmd, " ") {
		t.Fatalf("reload did not ride the container exec chain: argv=%v", rc.argv)
	}
	// Concretely: the reload landed in the container, not on the host.
	if rc.argv[0] != "ssh" || !strings.Contains(strings.Join(rc.argv, " "), "docker exec -i caddy sh") {
		t.Fatalf("reload must run inside the caddy container, got argv=%v", rc.argv)
	}
	// Validate also rode the same chain, against the staged in-container candidate path.
	if vc, ok := rr.call("caddy validate"); !ok {
		t.Fatalf("validate did not run through the transport; calls: %+v", rr.calls)
	} else if !strings.Contains(vc.script, "/etc/caddy/Caddyfile.crenel-candidate") {
		t.Fatalf("validate must target the in-container candidate path, got %q", vc.script)
	}
}

func TestPersist_ReloadFailureSurfaces(t *testing.T) {
	boot := writeBoot(t, operatorWildcardCaddyfile)
	rr := &recExecRunner{failOn: "caddy reload"}
	d := newExecDriver(t, boot, rr)

	err := d.Persist(context.Background())
	if err == nil {
		t.Fatal("a failed in-container reload MUST surface as an error, never be swallowed")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Fatalf("error must name the reload failure, got: %v", err)
	}
}

// TestPersistCaddyCLI_Selection is the seam unit test: an exec transport yields a
// transport-backed ExecCaddyCLI (command + address from the transport); a Direct transport
// keeps the local OSCaddyCLI (with the driver-derived admin address). An explicitly injected
// CaddyCLI always wins over both.
func TestPersistCaddyCLI_Selection(t *testing.T) {
	// Exec transport → ExecCaddyCLI over that chain.
	xt := &fakeExecXport{cmd: dockerExecCmd, addr: "127.0.0.1:2019", runner: &recExecRunner{}}
	d := &Driver{adminURL: "http://placeholder:2019", xport: xt}
	cli := d.persistCaddyCLI()
	ec, ok := cli.(ExecCaddyCLI)
	if !ok {
		t.Fatalf("exec transport must default to ExecCaddyCLI, got %T", cli)
	}
	if strings.Join(ec.Command, " ") != strings.Join(dockerExecCmd, " ") {
		t.Fatalf("ExecCaddyCLI.Command = %v", ec.Command)
	}
	if ec.Address != "127.0.0.1:2019" {
		t.Fatalf("ExecCaddyCLI.Address = %q", ec.Address)
	}
	// Adapter default also rides the transport.
	if _, ok := d.persistAdapter().(ExecAdapter); !ok {
		t.Fatalf("exec transport must default to ExecAdapter, got %T", d.persistAdapter())
	}

	// Direct (on-box) transport → local OSCaddyCLI, address from admin_url.
	dd := &Driver{adminURL: "http://127.0.0.1:2019", xport: transport.NewDirect("http://127.0.0.1:2019")}
	oc, ok := dd.persistCaddyCLI().(OSCaddyCLI)
	if !ok {
		t.Fatalf("direct transport must keep OSCaddyCLI, got %T", dd.persistCaddyCLI())
	}
	if oc.Address != "127.0.0.1:2019" {
		t.Fatalf("OSCaddyCLI.Address = %q", oc.Address)
	}
	if dd.persistAdapter() != nil {
		t.Fatalf("direct transport with no adapter wired must skip adapt, got %T", dd.persistAdapter())
	}

	// Explicit injection wins over the transport default.
	inj := &fakeReloadCLI{}
	di := &Driver{xport: xt, caddyCLI: inj}
	if di.persistCaddyCLI() != inj {
		t.Fatal("an injected CaddyCLI must win over the transport default")
	}
}
