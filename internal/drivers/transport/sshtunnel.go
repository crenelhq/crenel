package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Forwarder establishes a local TCP forward to a remote admin and returns the local
// address to talk to plus a close func. The default OSForwarder shells out to
// `ssh -N -L`; tests inject a fake (pointing the inner Direct at an in-process admin)
// so the open/use/close lifecycle is proven without real ssh.
type Forwarder interface {
	// Open establishes the forward, bounded by ctx for the readiness handshake, and
	// returns the local "host:port" to dial plus a close func that tears it down.
	Open(ctx context.Context) (localAddr string, closeFn func() error, err error)
}

// SSHTunnel opens an ephemeral, crenel-MANAGED local-forward SSH tunnel to the remote
// admin's loopback, then speaks Direct HTTP over the local forwarded port. It
// automates the manual `ssh -fN -L` tunnel (Option A in the chain-write trial): the
// tunnel opens lazily on first use and is closed on Close (wired into the cmd cleanup
// chain) — ephemeral to the crenel invocation, with no manual tunnel left running.
// The admin is never published; only an authenticated, crenel-lifecycle ssh forward
// carries the traffic.
type SSHTunnel struct {
	// Forwarder establishes (and tears down) the local forward.
	Forwarder Forwarder

	mu      sync.Mutex
	direct  *Direct
	closeFn func() error
	opened  bool
}

// ensureOpen lazily establishes the forward once and builds the inner Direct against
// the local forwarded port. Bounded by ctx (the op's read/write deadline), so a
// tunnel that never comes up cannot hang crenel.
func (s *SSHTunnel) ensureOpen(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened {
		return nil
	}
	if s.Forwarder == nil {
		return fmt.Errorf("%w: ssh-tunnel has no forwarder configured", ErrTransportUnreachable)
	}
	local, closeFn, err := s.Forwarder.Open(ctx)
	if err != nil {
		return fmt.Errorf("%w: open ssh tunnel: %v", ErrTransportUnreachable, err)
	}
	s.direct = NewDirect("http://" + local)
	s.closeFn = closeFn
	s.opened = true
	return nil
}

// Do ensures the tunnel is up, then issues the request as a Direct call over the
// forward. The deadline/wedge semantics are the inner Direct's (and the driver's),
// so the never-hang guarantee holds across the tunnel exactly as for a direct admin.
func (s *SSHTunnel) Do(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	if err := s.ensureOpen(ctx); err != nil {
		return 0, nil, err
	}
	s.mu.Lock()
	d := s.direct
	s.mu.Unlock()
	return d.Do(ctx, method, path, contentType, body)
}

// Close tears down the tunnel (idempotent). Wired into the cmd cleanup chain so the
// ephemeral forward never outlives the crenel process. After Close a subsequent Do
// re-opens — the tunnel is reusable, not one-shot.
func (s *SSHTunnel) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened || s.closeFn == nil {
		return nil
	}
	err := s.closeFn()
	s.opened, s.closeFn, s.direct = false, nil, nil
	return err
}

// OSForwarder shells out to `ssh -N -L <local>:<remoteHost>:<remotePort> <target>` as
// a MANAGED child process (not `-f`, so crenel owns its lifecycle) and waits for the
// forward to accept connections before returning. It is the default Forwarder and is
// NEVER exercised by the test suite (tests inject a fake), preserving the guarantee
// that crenel touches no real infrastructure in this repo.
type OSForwarder struct {
	Target     string        // user@host (required)
	Identity   string        // ssh -i identity path (optional)
	LocalPort  int           // local forward port (required)
	RemoteHost string        // remote side of the forward (default 127.0.0.1)
	RemotePort int           // remote admin port (default 2019)
	ReadyWait  time.Duration // how long to wait for the forward to accept (default 10s)
}

func (f OSForwarder) Open(ctx context.Context) (string, func() error, error) {
	if f.Target == "" {
		return "", nil, errors.New("ssh-tunnel: ssh_target is required")
	}
	if f.LocalPort == 0 {
		return "", nil, errors.New("ssh-tunnel: local_port is required")
	}
	remoteHost := f.RemoteHost
	if remoteHost == "" {
		remoteHost = "127.0.0.1"
	}
	remotePort := f.RemotePort
	if remotePort == 0 {
		remotePort = 2019
	}
	local := fmt.Sprintf("127.0.0.1:%d", f.LocalPort)

	args := []string{"-N", "-o", "ExitOnForwardFailure=yes", "-o", "BatchMode=yes"}
	if f.Identity != "" {
		args = append(args, "-i", f.Identity)
	}
	args = append(args, "-L", fmt.Sprintf("%s:%s:%d", local, remoteHost, remotePort), f.Target)

	// Run ssh detached from the op's ctx — the tunnel must outlive a single Do; Close
	// kills it explicitly.
	cmd := exec.Command("ssh", args...)
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("start ssh: %w", err)
	}
	closeFn := func() error {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil
	}

	// Poll the local forward until it accepts a connection, bounded by ReadyWait and
	// the caller's ctx, so a tunnel that never comes up fails fast instead of hanging.
	wait := f.ReadyWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if c, err := net.DialTimeout("tcp", local, 500*time.Millisecond); err == nil {
			_ = c.Close()
			return local, closeFn, nil
		}
		select {
		case <-ctx.Done():
			_ = closeFn()
			return "", nil, fmt.Errorf("ssh tunnel %s: %w", local, ctx.Err())
		default:
		}
		if time.Now().After(deadline) {
			_ = closeFn()
			return "", nil, fmt.Errorf("ssh tunnel %s did not become ready within %s", local, wait)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// LocalAddr extracts a "host:port" from a baseURL like "http://127.0.0.1:12019" for
// callers that need the bare address (kept small + dependency-free).
func LocalAddr(baseURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
}
