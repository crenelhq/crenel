package transport_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/crenelhq/crenel/internal/drivers/transport"
)

// fakeRunner records the argv + stdin it was handed and returns canned output, so
// the suite can assert the EXACT command crenel builds and how it parses results —
// fully hermetic, never spawning ssh.
type fakeRunner struct {
	gotArgv  []string
	gotStdin string
	stdout   string
	stderr   string
	code     int
	err      error
	block    bool // simulate a hung chain: wait for ctx cancellation
}

func (f *fakeRunner) Run(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	f.gotArgv = append([]string(nil), argv...)
	f.gotStdin = string(stdin)
	if f.block {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	return []byte(f.stdout), []byte(f.stderr), f.code, f.err
}

func nestedCommand() []string {
	return []string{"ssh", "root@proxmox", "pct", "exec", "100", "--", "docker", "exec", "-i", "caddy", "sh"}
}

// TestSSHExec_GetScriptAndParse: a GET builds the expected curl script, ships it over
// stdin to the unmodified exec prefix, and parses the (status, body) from the marker.
func TestSSHExec_GetScriptAndParse(t *testing.T) {
	r := &fakeRunner{stdout: `{"apps":{}}` + "CRENEL_HTTP_STATUS:200"}
	s := &transport.SSHExec{Command: nestedCommand(), AdminURL: "http://127.0.0.1:2019", Runner: r}

	status, body, err := s.Do(context.Background(), "GET", "/config/", "", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if status != 200 || string(body) != `{"apps":{}}` {
		t.Fatalf("got status=%d body=%q", status, body)
	}
	// The exec prefix is passed verbatim — nothing crosses a shell-parse boundary.
	if strings.Join(r.gotArgv, " ") != strings.Join(nestedCommand(), " ") {
		t.Errorf("argv = %v, want the verbatim prefix", r.gotArgv)
	}
	want := `curl -s -X 'GET' 'http://127.0.0.1:2019/config/' -w 'CRENEL_HTTP_STATUS:%{http_code}'`
	if r.gotStdin != want {
		t.Errorf("script over stdin:\n got: %s\nwant: %s", r.gotStdin, want)
	}
}

// TestSSHExec_BodyScriptIsBase64: a write (POST /load) base64-embeds the body so it
// survives quoting, passes the content type, and streams via --data-binary @-.
func TestSSHExec_BodyScriptIsBase64(t *testing.T) {
	r := &fakeRunner{stdout: "CRENEL_HTTP_STATUS:200"}
	s := &transport.SSHExec{Command: []string{"sh"}, Runner: r}
	body := []byte("example.com {\n\treverse_proxy 10.0.0.5:3000\n}\n") // spaces, tabs, newlines

	if _, _, err := s.Do(context.Background(), "POST", "/load", "text/caddyfile", body); err != nil {
		t.Fatalf("Do: %v", err)
	}
	script := r.gotStdin
	if !strings.Contains(script, "base64 -d | curl -s -X 'POST'") {
		t.Errorf("expected base64-decode piped to curl, got: %s", script)
	}
	if !strings.Contains(script, "-H 'Content-Type: text/caddyfile'") {
		t.Errorf("missing content-type header, got: %s", script)
	}
	if !strings.Contains(script, "--data-binary @- 'http://127.0.0.1:2019/load'") {
		t.Errorf("missing data-binary/url, got: %s", script)
	}
	// The embedded base64 must decode back to the exact body (round-trip proof).
	enc := base64.StdEncoding.EncodeToString(body)
	if !strings.Contains(script, "printf %s '"+enc+"'") {
		t.Errorf("base64 payload not embedded verbatim, got: %s", script)
	}
}

// TestSSHExec_AdminNon2xx: curl reached the admin and it answered non-2xx — that is a
// STATUS with a nil error (the driver decides), NOT a transport error.
func TestSSHExec_AdminNon2xx(t *testing.T) {
	r := &fakeRunner{stdout: "bad caddyfile" + "CRENEL_HTTP_STATUS:400"}
	s := &transport.SSHExec{Command: []string{"sh"}, Runner: r}

	status, body, err := s.Do(context.Background(), "POST", "/load", "text/caddyfile", []byte("x"))
	if err != nil {
		t.Fatalf("non-2xx must not be a transport error, got: %v", err)
	}
	if status != 400 || string(body) != "bad caddyfile" {
		t.Fatalf("got status=%d body=%q", status, body)
	}
}

// TestSSHExec_Unreachable_NoMarker: no status marker => the chain never reached the
// admin (ssh/connect failure) => ErrTransportUnreachable, enriched with stderr.
func TestSSHExec_Unreachable_NoMarker(t *testing.T) {
	r := &fakeRunner{stderr: "ssh: connect to host proxmox port 22: Connection refused", code: 255}
	s := &transport.SSHExec{Command: nestedCommand(), Runner: r}

	_, _, err := s.Do(context.Background(), "GET", "/config/", "", nil)
	if !transport.IsUnreachable(err) {
		t.Fatalf("expected ErrTransportUnreachable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("error should carry the stderr diagnostic, got: %v", err)
	}
}

// TestSSHExec_RunError_Unreachable: a failure to even start the chain (binary missing)
// is transport-unreachable too.
func TestSSHExec_RunError_Unreachable(t *testing.T) {
	r := &fakeRunner{err: errors.New("exec: \"ssh\": executable file not found in $PATH"), code: -1}
	s := &transport.SSHExec{Command: nestedCommand(), Runner: r}

	_, _, err := s.Do(context.Background(), "GET", "/config/", "", nil)
	if !transport.IsUnreachable(err) {
		t.Fatalf("expected ErrTransportUnreachable, got: %v", err)
	}
}

// TestSSHExec_Wedge_DeadlineClassified: a hung chain must surface a deadline error
// (which the driver maps to ErrAdminUnresponsive), NOT transport-unreachable.
func TestSSHExec_Wedge_DeadlineClassified(t *testing.T) {
	r := &fakeRunner{block: true}
	s := &transport.SSHExec{Command: nestedCommand(), Runner: r}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { _, _, e := s.Do(ctx, "GET", "/config/", "", nil); done <- e }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wedge must wrap context.DeadlineExceeded, got: %v", err)
		}
		if transport.IsUnreachable(err) {
			t.Errorf("a wedge must NOT be classified as transport-unreachable: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do hung past the deadline")
	}
}

// TestSSHExec_NoCommand: a misconfigured transport (no command) is unreachable, not a
// panic.
func TestSSHExec_NoCommand(t *testing.T) {
	s := &transport.SSHExec{}
	if _, _, err := s.Do(context.Background(), "GET", "/config/", "", nil); !transport.IsUnreachable(err) {
		t.Fatalf("expected ErrTransportUnreachable, got: %v", err)
	}
}

// TestSSHExec_Wget: wget builds a GET-only script (synthesized 200) and refuses writes.
func TestSSHExec_Wget(t *testing.T) {
	r := &fakeRunner{stdout: `{"apps":{}}` + "CRENEL_HTTP_STATUS:200"}
	s := &transport.SSHExec{Command: []string{"sh"}, Curl: "wget", Runner: r}

	status, body, err := s.Do(context.Background(), "GET", "/config/", "", nil)
	if err != nil || status != 200 || string(body) != `{"apps":{}}` {
		t.Fatalf("wget GET: status=%d body=%q err=%v", status, body, err)
	}
	if !strings.Contains(r.gotStdin, "wget -q -O - 'http://127.0.0.1:2019/config/'") {
		t.Errorf("unexpected wget script: %s", r.gotStdin)
	}
	if _, _, err := s.Do(context.Background(), "POST", "/load", "text/caddyfile", []byte("x")); !transport.IsUnreachable(err) {
		t.Errorf("wget must refuse writes as unreachable, got: %v", err)
	}
}

// shCapable reports whether real sh + curl + `base64 -d` are usable, so the
// integration test below can self-skip on a minimal CI without them.
func shCapable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		return false
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return false
	}
	out, err := exec.Command("sh", "-c", "printf aGk= | base64 -d").Output()
	return err == nil && string(out) == "hi"
}

// TestSSHExec_RealShAgainstFakeAdmin proves the GENERATED script actually works end to
// end: a real `sh` (the innermost shell of the exec chain) running real curl against an
// in-process HTTP admin — no live infra, no ssh. Covers a GET read and a PUT write
// (body delivered base64 over stdin). Skips if sh/curl/base64 are unavailable.
func TestSSHExec_RealShAgainstFakeAdmin(t *testing.T) {
	if !shCapable(t) {
		t.Skip("sh/curl/base64 not available — skipping the real-exec integration test")
	}
	var gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte("hello-from-admin"))
	}))
	defer srv.Close()

	// Command = a bare local `sh` reading the script from stdin — the same contract as
	// the innermost `sh` in a real ssh→pct→docker chain.
	s := &transport.SSHExec{Command: []string{"sh"}, AdminURL: srv.URL}

	status, body, err := s.Do(context.Background(), "GET", "/config/", "", nil)
	if err != nil {
		t.Fatalf("real GET: %v", err)
	}
	if status != 200 || string(body) != "hello-from-admin" || gotMethod != "GET" {
		t.Fatalf("real GET got status=%d body=%q method=%s", status, body, gotMethod)
	}

	payload := []byte(`{"@id":"crenel-route-x","match":[{"host":["x.example.com"]}]}`)
	status, _, err = s.Do(context.Background(), "PUT", "/config/apps/http/servers/srv0/routes/0", "application/json", payload)
	if err != nil {
		t.Fatalf("real PUT: %v", err)
	}
	if status != 201 || gotMethod != "PUT" || gotBody != string(payload) {
		t.Fatalf("real PUT got status=%d method=%s body=%q", status, gotMethod, gotBody)
	}
}
