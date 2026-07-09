//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// ttySize asks the kernel for the real window size of f (TIOCGWINSZ). It is the
// only reliable source on an interactive terminal — most shells do NOT export
// COLUMNS/LINES to subprocesses, so the env-based path alone left the banner
// assuming its optimistic default and wrapping on narrower real terminals.
// Raw stdlib ioctl (syscall + unsafe), keeping the zero-dependency rule.
// ok is false when f is not a terminal (piped/redirected output).
func ttySize(f *os.File) (cols, rows int, ok bool) {
	var ws struct{ rows, cols, xpix, ypix uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.cols == 0 {
		return 0, 0, false
	}
	return int(ws.cols), int(ws.rows), true
}
