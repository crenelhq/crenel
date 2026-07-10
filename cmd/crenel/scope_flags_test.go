package main

import (
	"strings"
	"testing"

	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/model"
)

// scopeCLI builds a cli over a two-edge topology (home + vps) so --edges validation
// has real names to check against. No apply happens; these tests exercise buildOp's
// flag→op resolution only.
func scopeCLI(t *testing.T, gf *globalFlags) *cli {
	t.Helper()
	f := caddyfake.New()
	t.Cleanup(f.Close)
	res := static.New(map[string]string{"ha": "10.0.0.19:8123"})
	home := core.EdgeBinding{Name: "home", Provider: caddy.New(f.URL(), res)}
	vps := core.EdgeBinding{Name: "vps", Provider: caddy.New(f.URL(), res)}
	engine := core.NewMulti([]core.EdgeBinding{home, vps}, "example.com")
	return &cli{engine: engine, gf: gf, out: &strings.Builder{}}
}

func TestBuildOp_ScopeInternalSetsInternalScope(t *testing.T) {
	c := scopeCLI(t, &globalFlags{scope: "internal"})
	op, err := c.buildOp(model.Expose, "ha")
	if err != nil {
		t.Fatal(err)
	}
	if len(op.Scopes) != 1 || op.Scopes[0] != model.ScopeInternal {
		t.Fatalf("--scope internal => op.Scopes [internal], got %v", op.Scopes)
	}
}

func TestBuildOp_ScopePublicAndDNSGranular(t *testing.T) {
	for _, tc := range []struct {
		name string
		gf   *globalFlags
		want []model.Scope
	}{
		{"scope public", &globalFlags{scope: "public"}, []model.Scope{model.ScopePublic}},
		{"scope both -> all", &globalFlags{scope: "both"}, nil},
		{"dns internal", &globalFlags{dns: "internal"}, []model.Scope{model.ScopeInternal}},
		{"unset -> all", &globalFlags{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scopeCLI(t, tc.gf)
			op, err := c.buildOp(model.Expose, "ha")
			if err != nil {
				t.Fatal(err)
			}
			if len(op.Scopes) != len(tc.want) {
				t.Fatalf("scopes = %v, want %v", op.Scopes, tc.want)
			}
			for i := range tc.want {
				if op.Scopes[i] != tc.want[i] {
					t.Fatalf("scopes = %v, want %v", op.Scopes, tc.want)
				}
			}
		})
	}
}

func TestBuildOp_ScopeAndDNSMutuallyExclusive(t *testing.T) {
	c := scopeCLI(t, &globalFlags{scope: "internal", dns: "public"})
	if _, err := c.buildOp(model.Expose, "ha"); err == nil ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestBuildOp_UnknownScopeRejected(t *testing.T) {
	c := scopeCLI(t, &globalFlags{scope: "dmz"})
	if _, err := c.buildOp(model.Expose, "ha"); err == nil ||
		!strings.Contains(err.Error(), "internal|public|both") {
		t.Fatalf("expected scope-value error, got %v", err)
	}
}

func TestBuildOp_EdgesAppointsNamedEdges(t *testing.T) {
	c := scopeCLI(t, &globalFlags{edges: "home, vps"})
	op, err := c.buildOp(model.Expose, "ha")
	if err != nil {
		t.Fatal(err)
	}
	if len(op.Edges) != 2 || op.Edges[0] != "home" || op.Edges[1] != "vps" {
		t.Fatalf("--edges parse = %v, want [home vps]", op.Edges)
	}
}

func TestBuildOp_UnknownEdgeRejected(t *testing.T) {
	c := scopeCLI(t, &globalFlags{edges: "home,typo"})
	if _, err := c.buildOp(model.Expose, "ha"); err == nil ||
		!strings.Contains(err.Error(), "unknown edge") {
		t.Fatalf("expected unknown-edge error, got %v", err)
	}
}

// TestAbsorbPostVerbFlags_ScopeEdges proves the new flags are absorbed wherever they
// appear after the verb (both --flag value and --flag=value forms), matching the
// documented `expose ha --scope internal --edges home` shape.
func TestAbsorbPostVerbFlags_ScopeEdges(t *testing.T) {
	gf := &globalFlags{}
	rest, err := absorbPostVerbFlags(gf, []string{"ha", "--scope", "internal", "--edges=home,vps", "--dns", "public"})
	if err != nil {
		t.Fatal(err)
	}
	if gf.scope != "internal" || gf.edges != "home,vps" || gf.dns != "public" {
		t.Fatalf("absorb: scope=%q edges=%q dns=%q", gf.scope, gf.edges, gf.dns)
	}
	if len(rest) != 1 || rest[0] != "ha" {
		t.Fatalf("positional should survive, got %v", rest)
	}
}
