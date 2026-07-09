package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ErrTransportUnreachable signals the exec chain could not obtain an HTTP response
// from the admin at all — ssh failed, the host/container is down, the far-end HTTP
// client could not connect, or a binary is missing. It is DISTINCT from an admin
// non-2xx (the admin answered; returned as a status with a nil error) and from a
// wedge-timeout (the ctx deadline fired; returned wrapping context.DeadlineExceeded
// so the driver maps it to ErrAdminUnresponsive). Three error classes, kept apart.
var ErrTransportUnreachable = errors.New("admin unreachable over exec transport")

// IsUnreachable reports whether err is (or wraps) ErrTransportUnreachable.
func IsUnreachable(err error) bool { return errors.Is(err, ErrTransportUnreachable) }

// statusMarker is appended by the far-end HTTP client (curl -w) AFTER the response
// body, so SSHExec can split captured stdout into (body, status). The prefix is
// chosen not to collide with Caddy config bytes.
const statusMarker = "CRENEL_HTTP_STATUS:"

// Runner is the exec seam: it runs argv (which crenel does NOT shell-parse) with the
// given stdin, bounded by ctx, and returns stdout, stderr, the process exit code,
// and an error ONLY for a failure to start/await the process. A non-zero process
// EXIT is reported via exitCode, never as err (the far-end client signals a
// connection failure that way, and that is a transport condition SSHExec classifies,
// not a Go-level error). Tests inject a fake so the suite never spawns ssh.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
}

// SSHExec reaches an admin API by running the admin call as a COMMAND on the far end
// — typically `ssh` into a host, then `pct exec` / `docker exec` into a container,
// landing a shell next to the admin's own loopback. It publishes NO port and opens
// NO tunnel, so a loopback-bound, unpublished admin (the maintainer's home Caddy) stays exactly
// as locked-down as it is. `docker-exec` / `pct-exec` are just shorter Command
// prefixes of this same transport.
type SSHExec struct {
	// Command is the exec PREFIX argv crenel does not shell-parse: the chain that
	// lands a POSIX shell where the admin loopback lives. The innermost element MUST
	// be a shell that reads its script from STDIN (a bare `sh`). crenel writes the
	// generated HTTP-client script to the process stdin, so nothing crosses a
	// shell-parse boundary as an argument — quoting survives arbitrarily nested
	// ssh→pct→docker chains. Example:
	//   []string{"ssh", "root@ml350", "pct", "exec", "113", "--",
	//            "docker", "exec", "-i", "caddy", "sh"}
	Command []string
	// AdminURL is the admin API base URL AS SEEN FROM the far end (default
	// "http://127.0.0.1:2019" — the loopback inside the container).
	AdminURL string
	// Curl names the far-end HTTP client: "curl" (default; full status fidelity, all
	// methods) or "wget" (GET reads only — BusyBox wget cannot report the HTTP status,
	// so a successful fetch reports 200 and any failure reports transport-unreachable).
	Curl string
	// Runner is the exec seam (default OSRunner shells out).
	Runner Runner
}

func (s *SSHExec) adminURL() string {
	if s.AdminURL == "" {
		return "http://127.0.0.1:2019"
	}
	return strings.TrimRight(s.AdminURL, "/")
}

func (s *SSHExec) client() string {
	if s.Curl == "" {
		return "curl"
	}
	return s.Curl
}

func (s *SSHExec) runner() Runner {
	if s.Runner == nil {
		return OSRunner{}
	}
	return s.Runner
}

// Do builds the far-end HTTP-client script, feeds it to the exec chain over stdin,
// and classifies the result into the three transport classes (see
// ErrTransportUnreachable). It honors ctx: on a deadline it returns an error
// wrapping context.DeadlineExceeded so the driver reports a wedged admin uniformly.
func (s *SSHExec) Do(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	if len(s.Command) == 0 {
		return 0, nil, fmt.Errorf("%w: ssh-exec transport has no command configured", ErrTransportUnreachable)
	}
	script, err := s.script(method, path, contentType, body)
	if err != nil {
		return 0, nil, err
	}
	stdout, stderr, code, runErr := s.runner().Run(ctx, s.Command, []byte(script))

	// Wedge FIRST: a fired ctx deadline surfaces as a wrapped DeadlineExceeded so the
	// driver classifies it as a wedged admin (ErrAdminUnresponsive), exactly as a
	// direct transport would — the never-hang guarantee holds through ssh-exec.
	if ctx.Err() != nil {
		return 0, nil, fmt.Errorf("ssh-exec %s %s: %w", method, path, ctx.Err())
	}
	if runErr != nil {
		return 0, nil, fmt.Errorf("%w: %s %s: exec chain failed to run: %v: %s",
			ErrTransportUnreachable, method, path, runErr, diag(stdout, stderr))
	}
	status, respBody, ok := parseResponse(stdout)
	if !ok {
		// No status marker => the far-end client never produced an HTTP response
		// (couldn't connect, missing binary, an intermediate hop errored).
		return 0, nil, fmt.Errorf("%w: %s %s: exit %d: %s",
			ErrTransportUnreachable, method, path, code, diag(stdout, stderr))
	}
	return status, respBody, nil
}

// script renders the POSIX-sh program the far-end shell executes. The request body
// is base64-embedded so a Caddyfile/JSON body with spaces, quotes, or newlines
// travels safely inside single quotes; the status code is captured after the body
// via curl's -w marker. All interpolated values (method/url/content-type) are
// controlled, single-token, and single-quote-safe.
func (s *SSHExec) script(method, path, contentType string, body []byte) (string, error) {
	url := s.adminURL() + path
	switch s.client() {
	case "curl":
		return s.curlScript(method, url, contentType, body), nil
	case "wget":
		return s.wgetScript(method, url)
	default:
		return "", fmt.Errorf("%w: unsupported far-end client %q (want curl|wget)", ErrTransportUnreachable, s.client())
	}
}

// curlScript builds the curl invocation. `-s` silences progress; `-w` appends the
// status marker after the body. For a request WITH a body, the base64 payload is
// decoded on the far end and streamed to curl via --data-binary @-.
func (s *SSHExec) curlScript(method, url, contentType string, body []byte) string {
	var b strings.Builder
	if len(body) > 0 {
		enc := base64.StdEncoding.EncodeToString(body)
		fmt.Fprintf(&b, "printf %%s '%s' | base64 -d | curl -s -X '%s' ", enc, method)
		if contentType != "" {
			fmt.Fprintf(&b, "-H 'Content-Type: %s' ", contentType)
		}
		fmt.Fprintf(&b, "--data-binary @- '%s' -w '%s%%{http_code}'", url, statusMarker)
	} else {
		fmt.Fprintf(&b, "curl -s -X '%s' '%s' -w '%s%%{http_code}'", method, url, statusMarker)
	}
	return b.String()
}

// wgetScript builds a BusyBox-compatible wget GET. wget cannot report the HTTP
// status, so a successful fetch emits the body + a synthesized 200 marker and any
// failure emits no marker (→ transport-unreachable). Non-GET is refused: configure
// curl for writes (the far end that performs writes — the VPS — has curl).
func (s *SSHExec) wgetScript(method, url string) (string, error) {
	if method != "GET" {
		return "", fmt.Errorf("%w: wget ssh-exec supports only GET reads; configure curl for %s", ErrTransportUnreachable, method)
	}
	// On success (exit 0) append the 200 marker; on failure emit nothing → unreachable.
	return fmt.Sprintf("wget -q -O - '%s' && printf '%s200'", url, statusMarker), nil
}

// parseResponse splits captured stdout into (status, body) at the LAST status marker.
// ok=false when no parseable marker is present (no HTTP response was obtained).
func parseResponse(stdout []byte) (int, []byte, bool) {
	idx := bytes.LastIndex(stdout, []byte(statusMarker))
	if idx < 0 {
		return 0, nil, false
	}
	body := stdout[:idx]
	code, err := strconv.Atoi(strings.TrimSpace(string(stdout[idx+len(statusMarker):])))
	if err != nil {
		return 0, nil, false
	}
	return code, body, true
}

// diag renders a bounded stderr-then-stdout snippet for a transport-error message.
func diag(stdout, stderr []byte) string {
	if se := snippet(stderr); se != "" {
		return "stderr: " + se
	}
	if so := snippet(stdout); so != "" {
		return "stdout: " + so
	}
	return "no output from the exec chain"
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// OSRunner runs the exec chain via os/exec, bounded by ctx (which kills the whole
// process tree on cancellation). It is the default Runner; the test suite injects a
// fake so it NEVER spawns ssh against real infrastructure.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	if len(argv) == 0 {
		return nil, nil, -1, errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
			err = nil // a non-zero exit is a transport condition, reported via code
		} else {
			code = -1 // failed to start (binary missing, etc.)
		}
	}
	return out.Bytes(), errb.Bytes(), code, err
}
