package dnscontrol

import (
	"context"
	"os/exec"
	"strings"
)

// Shell is the seam for invoking the dnscontrol binary. It is mocked in tests so
// no real DNS provider is ever contacted. `dir` contains the generated
// dnsconfig.js (and a creds file) that dnscontrol reads.
type Shell interface {
	Run(ctx context.Context, dir string, args ...string) (stdout string, err error)
}

// OSShell runs the real `dnscontrol` binary. It is NEVER exercised by the test
// suite (tests inject a fake), keeping the safety guarantee that Crenel touches
// no real infrastructure in this repo.
type OSShell struct {
	// Bin is the dnscontrol binary name/path (default "dnscontrol").
	Bin string
}

func (s OSShell) Run(ctx context.Context, dir string, args ...string) (string, error) {
	bin := s.Bin
	if bin == "" {
		bin = "dnscontrol"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
