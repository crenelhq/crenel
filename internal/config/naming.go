// Package config holds centralized, parameterized constants for the tool.
//
// Every user-visible string that names the tool is sourced from this file
// (plus the Go module path, which is the only other place the name is
// hard-coded), so it stays consistent everywhere.
package config

const (
	// ToolName is the canonical binary / command name.
	ToolName = "crenel"

	// ToolTitle is the human-facing display name.
	ToolTitle = "Crenel"

	// ToolTagline is the one-line description used in CLI help.
	ToolTagline = "vendor-agnostic, live-state-authoritative control of what your edge exposes"

	// ModulePath is the Go module path. Kept here for reference; the real
	// source of truth is go.mod. A rename touches: this file + go.mod + imports.
	ModulePath = "github.com/crenelhq/crenel"
)
