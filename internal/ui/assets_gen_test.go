package ui

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateAssets (re)writes the committed SVG assets from the live renderers,
// so the brand files in docs/brand/ can never drift from the glyph grid +
// semantic palette the terminal uses. It is SKIPPED in the normal test run;
// regenerate explicitly with:
//
//	CRENEL_GEN_ASSETS=1 go test ./internal/ui/ -run TestGenerateAssets
//
// It writes the canonical wordmark pair and the status-HUD mock.
func TestGenerateAssets(t *testing.T) {
	if os.Getenv("CRENEL_GEN_ASSETS") == "" {
		t.Skip("set CRENEL_GEN_ASSETS=1 to (re)generate docs/brand/*.svg")
	}
	dir := filepath.Join("..", "..", "docs", "brand")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The status-HUD asset is the early read-only-dashboard mock: a realistic,
	// healthy multi-edge topology drawn with real field names.
	hud := HUDModel{
		Exposed: 3, Public: 2, DenyEnforced: true, Drift: 0,
		Edges: []EdgeRef{
			{Name: "home", Driver: "caddy"},
			{Name: "vps", Driver: "traefik"},
		},
		DNSScopes: []string{"internal", "public"},
		LastApply: "unknown",
	}
	writes := []struct {
		name, data string
	}{
		// Canonical pair — what the README points at.
		{"crenel-wordmark.svg", WordmarkSVG()},
		{"crenel-wordmark-light.svg", WordmarkSVGLight()},
		{"crenel-status-hud.svg", StatusHUDSVG(hud)},
	}
	for _, wsp := range writes {
		p := filepath.Join(dir, wsp.name)
		if err := os.WriteFile(p, []byte(wsp.data), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		t.Logf("wrote %s (%d bytes)", p, len(wsp.data))
	}
}
