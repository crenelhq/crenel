package static_test

import (
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/origin/static"
)

func TestResolve_CaseInsensitive(t *testing.T) {
	r := static.New(map[string]string{"Grafana": "10.0.0.5:3000"})
	addr, err := r.Resolve("grafana")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.0.0.5:3000" {
		t.Errorf("unexpected addr %q", addr)
	}
}

func TestResolve_UnknownListsKnown(t *testing.T) {
	r := static.New(map[string]string{"grafana": "x", "photos": "y"})
	_, err := r.Resolve("nope")
	if err == nil {
		t.Fatal("expected error for unknown service")
	}
	// Error should help the user by listing known services.
	if !strings.Contains(err.Error(), "grafana") || !strings.Contains(err.Error(), "photos") {
		t.Errorf("error should list known services: %v", err)
	}
}
