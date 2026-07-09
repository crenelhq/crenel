package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/ui"
)

// cmdServe runs the read-only status dashboard: a small HTTP surface that renders
// live `status` as the branded HUD (SVG) on an auto-refreshing page. It is
// READ-ONLY BY CONSTRUCTION — it only ever calls the engine's read paths
// (Status / DetectDrift); there is no route that exposes/unexposes/mutates. All
// writes stay on the CLI, deliberately (see docs/internal/BUNDLE-DESIGN.md §1 + §4: the bundle's
// dashboard never lets the web mutate the edge).
//
// Flags (after the verb): --addr (listen address, default :8080, env
// CRENEL_SERVE_ADDR) and --refresh (auto-refresh seconds, default 5).
func (c *cli) cmdServe(ctx context.Context, args []string) error {
	addr := envOr("CRENEL_SERVE_ADDR", ":8080")
	refresh := 5
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--addr" || a == "-addr":
			if i+1 >= len(args) {
				return fmt.Errorf("--addr needs a value")
			}
			addr = args[i+1]
			i++
		case strings.HasPrefix(a, "--addr="):
			addr = strings.TrimPrefix(a, "--addr=")
		case a == "--refresh" || a == "-refresh":
			if i+1 >= len(args) {
				return fmt.Errorf("--refresh needs a value")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("--refresh: %w", err)
			}
			refresh = n
			i++
		case strings.HasPrefix(a, "--refresh="):
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--refresh="))
			if err != nil {
				return fmt.Errorf("--refresh: %w", err)
			}
			refresh = n
		default:
			return fmt.Errorf("serve: unknown argument %q", a)
		}
	}

	d := &dashboard{engine: c.engine, refresh: refresh}
	srv := &http.Server{
		Addr:              addr,
		Handler:           d.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Shut down cleanly when the context is cancelled (lets a caller/test stop us).
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(c.out, "%s dashboard (read-only) listening on %s — refresh %ds\n", config.ToolName, addr, refresh)
	fmt.Fprintf(c.out, "open http://localhost%s  ·  writes stay on the CLI (`crenel expose …`)\n", normalizeAddr(addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// dashboard is the read-only HTTP surface. It holds only a read path into the
// engine; it has no method that mutates.
type dashboard struct {
	engine  statusSource
	refresh int
}

// statusSource is the read-only slice of the engine the dashboard depends on.
// Narrowing the dependency to these two read methods makes "the web cannot
// mutate" a compile-time property, not just a convention.
type statusSource interface {
	Status(ctx context.Context) (core.StatusReport, error)
	DetectDrift(ctx context.Context) (core.ReconcilePlan, error)
}

// handler builds the read-only mux. Every route is GET-only (405 otherwise), so
// the dashboard physically cannot accept a mutating request.
func (d *dashboard) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.getOnly(d.handleIndex))
	mux.HandleFunc("/hud.svg", d.getOnly(d.handleHUD))
	mux.HandleFunc("/healthz", d.getOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	}))
	return mux
}

// getOnly rejects any non-GET/HEAD method with 405 — the structural guarantee
// that no web request can mutate the edge.
func (d *dashboard) getOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only dashboard: method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// handleIndex serves the HTML shell: it embeds the HUD SVG and re-fetches it on
// an interval (zero-dependency vanilla JS; degrades to a static view if JS is
// off). The page is intentionally tiny and self-contained.
func (d *dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, indexHTML, d.refresh*1000)
}

// handleHUD renders the live status HUD as SVG. On a read error (e.g. the edge's
// admin API is not up yet) it serves a degraded "edge unreachable" SVG with 200,
// so a polling dashboard keeps retrying rather than going blank — and crucially
// never shows a misleading green/ENFORCED state for an edge it could not read.
func (d *dashboard) handleHUD(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	svg, err := d.renderHUD(r.Context())
	if err != nil {
		w.Write([]byte(unreachableSVG(err)))
		return
	}
	w.Write([]byte(svg))
}

// renderHUD reads live status (+ best-effort drift) and renders the HUD SVG using
// the SAME model builder as `crenel status --hud`, so the web view and the CLI
// can never disagree about what is exposed.
func (d *dashboard) renderHUD(ctx context.Context) (string, error) {
	rep, err := d.engine.Status(ctx)
	if err != nil {
		return "", err
	}
	drift := -1
	if plan, derr := d.engine.DetectDrift(ctx); derr == nil {
		drift = len(plan.Drift)
	}
	return ui.StatusHUDSVG(hudModelFromStatus(rep, drift)), nil
}

// envOr returns the environment value for key, or def when unset/empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// normalizeAddr turns a listen address into the host:port suffix for a localhost
// URL hint (":8080" -> ":8080", "0.0.0.0:8080" -> ":8080").
func normalizeAddr(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ":" + addr
}
