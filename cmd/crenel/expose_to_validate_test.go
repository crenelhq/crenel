package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// withDialTo swaps the package-level dialTo for the duration of a test. Tests
// use it to make the pre-flight probe DETERMINISTIC (no real sockets, no
// timing dependence, no OS/CI-firewall interference).
func withDialTo(t *testing.T, fn func(addr string, timeout time.Duration) (net.Conn, error)) {
	t.Helper()
	prev := dialTo
	dialTo = fn
	t.Cleanup(func() { dialTo = prev })
}

// unreachable is a dial stub that always returns a real net.OpError, matching
// what net.Dial returns for a closed port. Deterministic; no real sockets.
func unreachable(addr string, _ time.Duration) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: mustResolveTCP(addr), Err: errors.New("connect: connection refused")}
}

func mustResolveTCP(addr string) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", addr); err == nil {
		return a
	}
	return nil
}

// TestCLI_ExposeWithTo_AbortsOnUnreachableBackend: the verify-principle-
// pre-flight contract. An unreachable --to must ABORT before any route or
// origin write, and the error must be GUIDING (naming the three common
// address shapes operators get wrong), not a bare dial error.
func TestCLI_ExposeWithTo_AbortsOnUnreachableBackend(t *testing.T) {
	withDialTo(t, unreachable)

	fake := seedEmptyDenyFake(t)
	c, _, p := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.auth = "none"
	c.gf.to = "immich:2283"

	err := c.dispatch(context.Background(), "expose", []string{"immich"})
	if err == nil {
		t.Fatal("unreachable --to must abort with an error")
	}
	msg := err.Error()
	// GUIDING: the message must name the address, the three common shapes, and
	// point at --no-validate as the intentional bypass. A cryptic bare dial
	// error would leave a first-run operator stuck.
	for _, want := range []string{
		`"immich:2283"`,
		"docker network",
		"LAN-IP",
		"127.0.0.1",
		"--no-validate",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should include %q; got: %v", want, err)
		}
	}
	// Nothing must have been written — same discipline as the public-auth guard.
	if len(fake.Loads) != 0 {
		t.Error("unreachable --to must abort BEFORE any /load POST")
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "immich") {
		t.Errorf("unreachable --to must NOT persist origins; file: %s", raw)
	}
}

// TestCLI_ExposeWithTo_ReachableBackendAllowsApply: when the operator's
// address DOES accept a connection, the probe passes and the existing
// preview→confirm→apply→verify pipeline runs unchanged. This proves the
// probe is a pre-flight guard, not a semantic change to the apply path.
func TestCLI_ExposeWithTo_ReachableBackendAllowsApply(t *testing.T) {
	// A real listener stands in for the operator's backend. Immediate-close on
	// each accept — the probe only cares about the SYN, not the payload.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	fake := seedEmptyDenyFake(t)
	c, out, _ := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.auth = "none"
	c.gf.to = ln.Addr().String()

	if err := c.dispatch(context.Background(), "expose", []string{"immich"}); err != nil {
		t.Fatalf("reachable --to should apply cleanly, got %v: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("expose should verify:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "persisted origin: immich -> "+ln.Addr().String()) {
		t.Errorf("expected persistence trace:\n%s", out.String())
	}
}

// TestCLI_ExposeWithTo_NoValidateBypassesProbe: the escape hatch. Even with
// a stub that ALWAYS returns unreachable, --no-validate lets the apply
// proceed — the operator has taken explicit responsibility for the address.
func TestCLI_ExposeWithTo_NoValidateBypassesProbe(t *testing.T) {
	withDialTo(t, unreachable)

	fake := seedEmptyDenyFake(t)
	c, out, _ := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{}}`)
	c.gf.auth = "none"
	c.gf.to = "immich:2283"
	c.gf.noValidate = true

	if err := c.dispatch(context.Background(), "expose", []string{"immich"}); err != nil {
		t.Fatalf("--no-validate should bypass the probe, got %v: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("expose --no-validate should apply and verify:\n%s", out.String())
	}
}

// TestCLI_ExposeWithoutTo_SkipsProbe: pure regression guard — a pre-declared
// origin (no --to) must NOT trigger the probe, so an origin whose backend
// happens to be down still applies (the pre-flag path is unchanged).
func TestCLI_ExposeWithoutTo_SkipsProbe(t *testing.T) {
	dialCalls := 0
	withDialTo(t, func(addr string, _ time.Duration) (net.Conn, error) {
		dialCalls++
		return nil, errors.New("should not be called")
	})

	fake := seedEmptyDenyFake(t)
	c, _, _ := newExposeToCLI(t, fake, `{"admin_url":"http://x","zone":"example.com","origins":{"photos":"10.0.0.6:2342"}}`)
	c.gf.auth = "none"
	// no c.gf.to

	if err := c.dispatch(context.Background(), "expose", []string{"photos"}); err != nil {
		t.Fatalf("no-to path must not run the probe: %v", err)
	}
	if dialCalls != 0 {
		t.Errorf("probe ran on the no-to path (called %d times)", dialCalls)
	}
}

// TestAbsorbPostVerbFlags_NoValidate: the user-natural post-verb ordering
// must absorb --no-validate too (matching --yes, --to, --auth).
func TestAbsorbPostVerbFlags_NoValidate(t *testing.T) {
	gf := &globalFlags{}
	rest, err := absorbPostVerbFlags(gf, []string{"immich", "--to", "immich:2283", "--auth", "none", "--no-validate"})
	if err != nil {
		t.Fatal(err)
	}
	if !gf.noValidate {
		t.Error("--no-validate not absorbed")
	}
	if gf.to != "immich:2283" || gf.auth != "none" {
		t.Errorf("companion flags lost: to=%q auth=%q", gf.to, gf.auth)
	}
	if len(rest) != 1 || rest[0] != "immich" {
		t.Errorf("positional lost: %v", rest)
	}
}
