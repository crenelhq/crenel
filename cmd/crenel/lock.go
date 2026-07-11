package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// mutatingVerbs names every verb whose flow reads live, plans, applies, and
// read-back-verifies (or reconciles/resumes one) — the transactional apply path
// audit F3 is about. Two overlapping runs of any of these can interleave their
// snapshot/rollback compensators and stomp each other. status/audit/export/
// preview/drift/init/serve are read-only or single-file-local and are not
// gated.
var mutatingVerbs = map[string]bool{
	"expose": true, "unexpose": true, "set": true,
	"rename": true, "move": true,
	"reconcile": true, "resume": true,
	"import": true, "apply": true,
	"ack": true, "unack": true,
	// triage is the interactive ack loop — every [a] is the same live-config
	// write as `ack`, so it holds the same lock for its whole session.
	"triage": true,
}

// lockPath is the flock target for a mutating command: beside the settings file
// when one is configured (so distinct configs on the same machine don't block
// each other), else a fixed path in the OS temp dir.
func lockPath(settingsPath string) string {
	if settingsPath != "" {
		return settingsPath + ".lock"
	}
	return filepath.Join(os.TempDir(), "crenel.lock")
}

// acquireLock takes an exclusive, non-blocking flock for the duration of one
// mutating verb, so two overlapping apply/expose/... runs can't collide
// (audit F3: "no concurrent-writer isolation"). Marginal value for a solo
// operator, so this is intentionally minimal — one lock file, no retry or
// queueing: a second concurrent run fails fast with a clear message instead of
// silently racing the first.
func acquireLock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another crenel mutating command is already running (lock held on %s) — wait for it to finish", path)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
