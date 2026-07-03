package main

import (
	"fmt"
	"os"
	"time"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/edge/netbird"
	"github.com/crenelhq/crenel/internal/drivers/edge/nginx"
	"github.com/crenelhq/crenel/internal/drivers/edge/traefik"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/drivers/transport"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// wiring is the composition root: it is the ONLY place concrete drivers are
// constructed and injected into core. core/model never import drivers.
type wiring struct {
	engine  *core.Engine
	cleanup func()
}

// addCleanup chains a teardown (e.g. closing a fake admin API) onto the wiring.
func (w *wiring) addCleanup(fn func()) {
	prev := w.cleanup
	w.cleanup = func() { fn(); prev() }
}

// build assembles the engine from settings. When settings.Edges is non-empty it
// builds a multi-edge topology (M4); otherwise it builds the single top-level
// edge (degenerate N=1). FakeSeed paths start in-process fake Caddy admin APIs
// (the safe, no-infra demo path).
func build(s config.Settings) (*wiring, error) {
	w := &wiring{cleanup: func() {}}

	bindings, err := buildBindings(s, w)
	if err != nil {
		w.cleanup()
		return nil, err
	}

	dnsProviders, err := buildDNS(s)
	if err != nil {
		w.cleanup()
		return nil, err
	}

	w.engine = core.NewMulti(bindings, s.Zone, dnsProviders...)
	return w, nil
}

// edgeSpec is the driver-agnostic description of one edge to construct.
type edgeSpec struct {
	name             string
	driver           string // "caddy" | "traefik"
	adminURL         string
	fakeSeed         string
	traefikPath      string
	nginxPath        string
	netbirdPath      string
	traefikAPIURL    string                       // traefik runtime-verify API base
	nginxRuntime     *config.NginxRuntimeSettings // nginx validate/reload/probe surface
	nginxTLS         *config.NginxTLSSettings     // nginx TLS termination (cert/key/port)
	nginxListenPort  int                          // nginx plain-HTTP listen port (default 80)
	granular         bool
	layer4           bool
	persistPath      string
	caddyPersist     *config.PersistSettings // durable wildcard-site reconciler wiring (caddy)
	generator        string                  // operator-declared config generator (caddy)
	generatorPath    string                  // on-disk artifact to scan for a generator signature (caddy)
	ingressKind      string                  // declared off-edge ingress mechanism (tunnel/overlay/...)
	ingressPath      string                  // tunnel/overlay config to scan for an ingress signature
	authDownstream   bool
	downstreamEdge   string                    // chain front: the downstream edge this one forwards to (P4)
	downstreamAddr   string                    // address the front dials to reach the downstream edge (P4)
	downstreamScheme string                    // "https"/"http" for the front→downstream dial; empty infers from :443
	transport        *config.TransportSettings // HOW to reach the admin API (caddy only)
	readTimeout      time.Duration
	writeTimeout     time.Duration
	origins          map[string]string
	// authPolicies is the global policy-name -> per-driver reference map (from
	// config.AuthPolicies), translated per driver at construction. Shared by every
	// edge: the operator defines a policy once.
	authPolicies map[string]config.AuthPolicy
}

// buildBindings produces the edge topology: one binding per configured edge.
func buildBindings(s config.Settings, w *wiring) ([]core.EdgeBinding, error) {
	specs := edgeSpecs(s)
	var out []core.EdgeBinding
	for _, spec := range specs {
		prov, err := buildEdgeProvider(spec, w)
		if err != nil {
			return nil, err
		}
		b := core.EdgeBinding{
			Name:              spec.name,
			Provider:          prov,
			AuthDownstream:    spec.authDownstream,
			IngressKind:       model.IngressKind(spec.ingressKind),
			IngressConfigPath: spec.ingressPath,
			DownstreamEdge:    spec.downstreamEdge,
			DownstreamAddress: spec.downstreamAddr,
			DownstreamScheme:  spec.downstreamScheme,
		}
		// Multi-edge: project by the edge's own origins. Single top-level edge
		// keeps Fronts=nil (fronts everything) so behaviour is unchanged.
		if len(s.Edges) > 0 {
			b.Fronts = frontsFor(spec.origins)
		}
		out = append(out, b)
	}
	return out, nil
}

// edgeSpecs derives the list of edges to build from settings — either the
// explicit multi-edge list or the single top-level edge.
func edgeSpecs(s config.Settings) []edgeSpec {
	if len(s.Edges) > 0 {
		var specs []edgeSpec
		for _, es := range s.Edges {
			specs = append(specs, edgeSpec{
				name:             es.Name,
				driver:           es.Driver,
				adminURL:         es.AdminURL,
				fakeSeed:         es.FakeSeed,
				traefikPath:      es.TraefikConfigPath,
				nginxPath:        es.NginxConfigPath,
				netbirdPath:      es.NetbirdGrantsPath,
				traefikAPIURL:    es.TraefikAPIURL,
				nginxRuntime:     es.NginxRuntime,
				nginxTLS:         es.NginxTLS,
				nginxListenPort:  es.NginxListenPort,
				granular:         es.GranularApply,
				layer4:           es.CaddyLayer4,
				persistPath:      es.CaddyPersistPath,
				caddyPersist:     es.CaddyPersist,
				generator:        es.CaddyGenerator,
				generatorPath:    es.CaddyGeneratorConfigPath,
				ingressKind:      es.IngressKind,
				ingressPath:      es.IngressConfigPath,
				authDownstream:   es.AuthDownstream,
				downstreamEdge:   es.DownstreamEdge,
				downstreamAddr:   es.DownstreamAddress,
				downstreamScheme: es.DownstreamScheme,
				transport:        es.Transport,
				readTimeout:      time.Duration(es.AdminReadTimeoutSeconds) * time.Second,
				writeTimeout:     time.Duration(es.AdminWriteTimeoutSeconds) * time.Second,
				origins:          es.Origins,
				authPolicies:     s.AuthPolicies,
			})
		}
		return specs
	}
	return []edgeSpec{{
		name:             s.EdgeDriver,
		driver:           s.EdgeDriver,
		adminURL:         s.AdminURL,
		fakeSeed:         s.FakeSeed,
		traefikPath:      s.TraefikConfigPath,
		nginxPath:        s.NginxConfigPath,
		netbirdPath:      s.NetbirdGrantsPath,
		traefikAPIURL:    s.TraefikAPIURL,
		nginxRuntime:     s.NginxRuntime,
		nginxTLS:         s.NginxTLS,
		nginxListenPort:  s.NginxListenPort,
		granular:         s.GranularApply,
		layer4:           s.CaddyLayer4,
		persistPath:      s.CaddyPersistPath,
		caddyPersist:     s.CaddyPersist,
		generator:        s.CaddyGenerator,
		generatorPath:    s.CaddyGeneratorConfigPath,
		ingressKind:      s.IngressKind,
		ingressPath:      s.IngressConfigPath,
		authDownstream:   s.AuthDownstream,
		downstreamEdge:   s.DownstreamEdge,
		downstreamAddr:   s.DownstreamAddress,
		downstreamScheme: s.DownstreamScheme,
		transport:        s.Transport,
		readTimeout:      s.AdminReadTimeout(),
		writeTimeout:     s.AdminWriteTimeout(),
		origins:          s.Origins,
		authPolicies:     s.AuthPolicies,
	}}
}

// caddyAuthRefs translates the global auth-policy config into Caddy references
// (snippet to import / forward_auth endpoint). Only policies with an explicit Caddy
// field are included; the driver applies the default convention for the rest.
func caddyAuthRefs(m map[string]config.AuthPolicy) map[string]caddy.AuthRef {
	if len(m) == 0 {
		return nil
	}
	out := map[string]caddy.AuthRef{}
	for name, p := range m {
		if p.CaddyImport != "" || p.CaddyForwardAuth != "" || len(p.CaddyHandlerJSON) > 0 {
			out[name] = caddy.AuthRef{
				Import:      p.CaddyImport,
				ForwardAuth: p.CaddyForwardAuth,
				VerifyURI:   p.CaddyForwardAuthVerifyURI,
				CopyHeaders: p.CaddyForwardAuthCopyHeaders,
				Handler:     p.CaddyHandlerJSON,
			}
		}
	}
	return out
}

// traefikAuthMiddlewares translates the global auth-policy config into Traefik
// middleware names (only explicit overrides; default convention "<name>@file").
func traefikAuthMiddlewares(m map[string]config.AuthPolicy) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for name, p := range m {
		if p.TraefikMiddleware != "" {
			out[name] = p.TraefikMiddleware
		}
	}
	return out
}

// nginxAuthRequests translates the global auth-policy config into nginx
// auth_request URIs (only explicit overrides; default convention "/<name>").
func nginxAuthRequests(m map[string]config.AuthPolicy) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for name, p := range m {
		if p.NginxAuthRequest != "" {
			out[name] = p.NginxAuthRequest
		}
	}
	return out
}

// buildTransport constructs the connection channel for an admin-API edge from its
// transport config. nil config (or type "direct"/"") returns (nil, nil) — the driver
// then builds its default Direct-to-admin_url transport, so an edge with just an
// admin_url is unchanged. ssh-tunnel registers its Close into the wiring cleanup so
// the ephemeral forward is torn down on exit. This is the ONLY place a concrete
// transport is chosen.
func buildTransport(ts *config.TransportSettings, w *wiring) (ports.Transport, error) {
	if ts == nil || ts.Type == "" || ts.Type == "direct" {
		return nil, nil
	}
	switch ts.Type {
	case "ssh-exec":
		if len(ts.Command) == 0 {
			return nil, fmt.Errorf("transport ssh-exec requires a non-empty `command` (the exec prefix ending in a stdin shell)")
		}
		return &transport.SSHExec{Command: ts.Command, AdminURL: ts.AdminURL, Curl: ts.Curl}, nil
	case "ssh-tunnel":
		tun := &transport.SSHTunnel{Forwarder: transport.OSForwarder{
			Target:     ts.SSHTarget,
			Identity:   ts.SSHIdentity,
			LocalPort:  ts.LocalPort,
			RemoteHost: ts.RemoteHost,
			RemotePort: ts.RemotePort,
		}}
		w.addCleanup(func() { _ = tun.Close() })
		return tun, nil
	default:
		return nil, fmt.Errorf("unknown transport type %q (want direct|ssh-exec|ssh-tunnel)", ts.Type)
	}
}

// frontsFor builds a projection predicate from an edge's origins: it fronts a
// service iff that service is in its origin map.
func frontsFor(origins map[string]string) func(string) bool {
	return func(service string) bool {
		_, ok := origins[service]
		return ok
	}
}

// buildEdgeProvider constructs one edge's EdgeProvider from its spec. This is the
// ONLY place an edge driver is chosen — core never knows which it got.
func buildEdgeProvider(spec edgeSpec, w *wiring) (ports.EdgeProvider, error) {
	resolver := static.New(spec.origins)
	switch spec.driver {
	case "traefik":
		if spec.traefikPath == "" {
			return nil, fmt.Errorf("edge %q: driver=traefik requires traefik_config_path", spec.name)
		}
		tOpts := []traefik.Option{traefik.WithAuthMiddlewares(traefikAuthMiddlewares(spec.authPolicies))}
		if spec.traefikAPIURL != "" {
			tOpts = append(tOpts, traefik.WithAPIURL(spec.traefikAPIURL))
		}
		return traefik.New(spec.traefikPath, resolver, tOpts...), nil
	case "nginx":
		if spec.nginxPath == "" {
			return nil, fmt.Errorf("edge %q: driver=nginx requires nginx_config_path", spec.name)
		}
		nOpts := []nginx.Option{nginx.WithAuthRequests(nginxAuthRequests(spec.authPolicies))}
		if spec.nginxTLS != nil {
			nOpts = append(nOpts, nginx.WithTLS(spec.nginxTLS.Port, spec.nginxTLS.CertPath, spec.nginxTLS.KeyPath))
		} else if spec.nginxListenPort != 0 {
			nOpts = append(nOpts, nginx.WithListenPort(spec.nginxListenPort))
		}
		if rt := spec.nginxRuntime; rt != nil {
			nOpts = append(nOpts, nginx.WithRuntime(rt.TestCmd, rt.ReloadCmd, rt.ProbeURL))
		}
		return nginx.New(spec.nginxPath, resolver, nOpts...), nil
	case "netbird":
		if spec.netbirdPath == "" {
			return nil, fmt.Errorf("edge %q: driver=netbird requires netbird_grants_path", spec.name)
		}
		// Identity-mesh edge: read-only here; mutations error loudly (see netbird pkg).
		return netbird.New(spec.netbirdPath), nil
	case "", "caddy":
		return buildCaddyEdge(spec, resolver, w)
	default:
		return nil, fmt.Errorf("edge %q: unknown driver %q (want caddy|traefik|nginx|netbird)", spec.name, spec.driver)
	}
}

// buildCaddyEdge builds the Caddy driver, optionally fronted by an in-process
// fake admin API seeded from a fixture (the safe, no-infra demo path).
func buildCaddyEdge(spec edgeSpec, resolver ports.OriginResolver, w *wiring) (ports.EdgeProvider, error) {
	adminURL := spec.adminURL
	if spec.fakeSeed != "" {
		fake := caddyfake.New()
		seed, err := os.ReadFile(spec.fakeSeed)
		if err != nil {
			fake.Close()
			return nil, fmt.Errorf("read fake seed %s: %w", spec.fakeSeed, err)
		}
		// JSON fixtures start with '{'; everything else is treated as Caddyfile.
		if len(seed) > 0 && seed[0] == '{' {
			if err := fake.SeedJSON(string(seed)); err != nil {
				fake.Close()
				return nil, fmt.Errorf("seed fake (json): %w", err)
			}
		} else {
			fake.SeedCaddyfile(string(seed))
		}
		adminURL = fake.URL()
		w.addCleanup(fake.Close)
	}

	var edgeOpts []caddy.Option
	// Connection transport: how the admin calls physically travel. Only when NOT in
	// the fake-seed demo path (the fake is an in-process HTTP admin reached directly).
	if spec.fakeSeed == "" {
		xport, err := buildTransport(spec.transport, w)
		if err != nil {
			return nil, fmt.Errorf("edge %q: %w", spec.name, err)
		}
		if xport != nil {
			edgeOpts = append(edgeOpts, caddy.WithTransport(xport))
		}
	}
	if refs := caddyAuthRefs(spec.authPolicies); refs != nil {
		edgeOpts = append(edgeOpts, caddy.WithAuthPolicies(refs))
	}
	if spec.granular {
		edgeOpts = append(edgeOpts, caddy.WithGranularApply())
	}
	if spec.layer4 {
		edgeOpts = append(edgeOpts, caddy.WithLayer4())
	}
	if spec.generator != "" {
		edgeOpts = append(edgeOpts, caddy.WithGenerator(spec.generator))
	}
	if spec.generatorPath != "" {
		edgeOpts = append(edgeOpts, caddy.WithGeneratorConfigPath(spec.generatorPath))
	}
	if spec.readTimeout > 0 || spec.writeTimeout > 0 {
		edgeOpts = append(edgeOpts, caddy.WithTimeouts(spec.readTimeout, spec.writeTimeout))
	}
	if spec.caddyPersist != nil {
		// Durable wildcard-site reconciler (the home-edge two-channel path).
		edgeOpts = append(edgeOpts, durablePersistOpts(spec)...)
	} else if spec.persistPath != "" {
		edgeOpts = append(edgeOpts, caddy.WithPersistPath(spec.persistPath))
		// A fake-seeded edge is the no-infra demo path: there is no real `caddy`
		// binary to validate/reload, so inject a no-exec CLI that records the reload
		// it WOULD run. A real edge uses the default OSCaddyCLI.
		if spec.fakeSeed != "" {
			edgeOpts = append(edgeOpts, caddy.WithCaddyCLI(caddy.LogCaddyCLI{W: os.Stderr}))
		}
	}
	return caddy.New(adminURL, resolver, edgeOpts...), nil
}

// durablePersistOpts builds the driver options for the DURABLE wildcard-site reconciler
// from a PersistSettings block. It wires the two exec channels the home edge needs — the
// FILE channel to the host that holds the boot Caddyfile, and the CADDY channel to where
// the binary runs for validate/reload/adapt — falling back to the local filesystem /
// local `caddy` when a channel's command is unset. The boot path declares the edge
// durable-file and is what reload targets.
func durablePersistOpts(spec edgeSpec) []caddy.Option {
	p := spec.caddyPersist
	bootPath := p.BootPath
	if bootPath == "" {
		bootPath = spec.persistPath
	}
	opts := []caddy.Option{caddy.WithPersistPath(bootPath)}

	// FILE channel: read/write the boot Caddyfile where it lives.
	if len(p.FileCommand) > 0 {
		opts = append(opts, caddy.WithConfigStore(caddy.ExecConfigStore{Command: p.FileCommand, Path: p.FilePath}))
	}

	// CADDY channel: validate/reload (+ adapt) where the binary runs.
	if len(p.CaddyCommand) > 0 {
		opts = append(opts, caddy.WithCaddyCLI(caddy.ExecCaddyCLI{Command: p.CaddyCommand, Adapter: p.Adapter}))
		if verifyAdapt(p) {
			opts = append(opts, caddy.WithAdapter(caddy.ExecAdapter{Command: p.CaddyCommand, Adapter: p.Adapter}))
		}
	} else if spec.fakeSeed != "" {
		// No-infra demo: no real caddy binary — record the reload, skip the adapt check.
		opts = append(opts, caddy.WithCaddyCLI(caddy.LogCaddyCLI{W: os.Stderr}))
	} else if verifyAdapt(p) {
		opts = append(opts, caddy.WithAdapter(caddy.OSAdapter{Adapter: p.Adapter}))
	}
	return opts
}

// verifyAdapt reports whether the re-adaptation read-back is enabled (default true).
func verifyAdapt(p *config.PersistSettings) bool {
	return p.VerifyAdapt == nil || *p.VerifyAdapt
}
