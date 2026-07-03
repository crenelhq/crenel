package core_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDependencyRule enforces the hexagonal boundary: core and model must NEVER
// import a driver package. Drivers are wired in only at cmd. If this test fails,
// the open-core seam has been breached.
func TestDependencyRule(t *testing.T) {
	roots := map[string]string{
		"core":  "..", // internal/core
		"model": "../../internal/model",
	}
	const driverPrefix = "github.com/crenelhq/crenel/internal/drivers"

	for name, dir := range roots {
		imports := collectImports(t, dir)
		for _, imp := range imports {
			if strings.HasPrefix(imp, driverPrefix) {
				t.Errorf("dependency rule violated: package %q imports driver %q", name, imp)
			}
		}
	}
}

func collectImports(t *testing.T, dir string) []string {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		t.Fatalf("read dir %s: %v", abs, err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(abs, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			out = append(out, strings.Trim(imp.Path.Value, `"`))
		}
	}
	return out
}
