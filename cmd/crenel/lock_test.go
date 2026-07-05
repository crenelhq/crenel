package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcquireLock_SecondCallerRefused proves the flock is genuinely exclusive:
// a second attempt on the same path fails fast (never blocks) while the first
// holder is still open, and releasing the first lets a third attempt succeed.
func TestAcquireLock_SecondCallerRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crenel.lock")

	unlock1, err := acquireLock(path)
	if err != nil {
		t.Fatalf("first acquireLock: %v", err)
	}

	if _, err := acquireLock(path); err == nil {
		t.Fatal("second overlapping acquireLock should have been refused")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Errorf("refusal error should explain why, got: %v", err)
	}

	unlock1()

	unlock3, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock after release should succeed: %v", err)
	}
	unlock3()
}

// TestDispatch_MutatingVerbLockCollision proves dispatch() itself gates on the
// same lock: a mutating verb refuses while another mutating command holds the
// lock for the same settings path, but a read-only verb (not in mutatingVerbs)
// is unaffected.
func TestDispatch_MutatingVerbLockCollision(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	unlock, err := acquireLock(lockPath(settingsPath))
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer unlock()

	c, _ := newTestCLI(t, seedFake(t), true, "")
	c.settingsPath = settingsPath

	if err := c.dispatch(context.Background(), "expose", []string{"photos"}); err == nil {
		t.Error("expose should refuse while another mutating command holds the lock")
	}
	if err := c.dispatch(context.Background(), "status", nil); err != nil {
		t.Errorf("status (read-only) should not be gated by the lock: %v", err)
	}
}
