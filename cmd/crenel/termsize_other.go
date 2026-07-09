//go:build !linux && !darwin

package main

import "os"

// ttySize is unavailable on this platform; width/height resolution falls back
// to the -width/-height flags, the COLUMNS/LINES env, and the ui defaults.
func ttySize(_ *os.File) (cols, rows int, ok bool) { return 0, 0, false }
