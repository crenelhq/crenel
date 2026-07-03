package traefik

// This file models the subset of Traefik's *dynamic configuration* (the document
// the file provider watches) that Crenel needs to read and normalize: HTTP
// routers and their backing services. It is intentionally minimal.
//
// FORMAT NOTE: real Traefik reads YAML or TOML dynamic-config files. To keep
// Crenel a zero-dependency, fully-offline build (no yaml/toml module), this
// driver marshals the same structure as JSON (see codec.go). The dynamic-config
// SHAPE is faithful; only the serialization is simplified, and it is isolated to
// codec.go so a real deployment can swap in a YAML codec in one place.

// dynamicConfig is the top-level Traefik dynamic configuration.
type dynamicConfig struct {
	HTTP httpConfig `json:"http"`
	TCP  *tcpConfig `json:"tcp,omitempty"`
}

// tcpConfig holds TCP routers/services — how Traefik does TLS/SNI PASSTHROUGH: a
// TCP router matched by HostSNI with tls.passthrough=true forwards the raw TLS
// connection to the backend without terminating it. This is a different config
// tree than http.routers (the ModeTCPPassthrough renderer, M9).
type tcpConfig struct {
	Routers  map[string]*tcpRouter  `json:"routers,omitempty"`
	Services map[string]*tcpService `json:"services,omitempty"`
}

type tcpRouter struct {
	Rule        string   `json:"rule"` // HostSNI(`host`)
	Service     string   `json:"service"`
	EntryPoints []string `json:"entryPoints,omitempty"`
	TLS         *tcpTLS  `json:"tls,omitempty"`
}

type tcpTLS struct {
	Passthrough bool `json:"passthrough"`
}

type tcpService struct {
	LoadBalancer tcpLoadBalancer `json:"loadBalancer"`
}

type tcpLoadBalancer struct {
	Servers []tcpServer `json:"servers,omitempty"`
}

// tcpServer addresses are host:port (no scheme) — unlike http servers' url.
type tcpServer struct {
	Address string `json:"address"`
}

func (s *tcpService) firstAddress() string {
	if s == nil {
		return ""
	}
	for _, srv := range s.LoadBalancer.Servers {
		if srv.Address != "" {
			return srv.Address
		}
	}
	return ""
}

type httpConfig struct {
	Routers  map[string]*router  `json:"routers,omitempty"`
	Services map[string]*service `json:"services,omitempty"`
}

// router is a Traefik HTTP router: a rule (e.g. Host(`x`)) -> a service.
type router struct {
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
	Priority    int      `json:"priority,omitempty"`
	EntryPoints []string `json:"entryPoints,omitempty"`
	Middlewares []string `json:"middlewares,omitempty"`
	TLS         *tlsConf `json:"tls,omitempty"`
}

// tlsConf is carried opaquely so unmanaged routers' TLS settings survive a
// read-modify-write untouched (see additivity test).
type tlsConf struct {
	CertResolver string `json:"certResolver,omitempty"`
	Passthrough  bool   `json:"passthrough,omitempty"`
}

type service struct {
	LoadBalancer loadBalancer `json:"loadBalancer"`
}

type loadBalancer struct {
	Servers []serverURL `json:"servers,omitempty"`
}

type serverURL struct {
	URL string `json:"url"`
}

const (
	// managedPrefix tags every router/service Crenel owns, so a read-modify-write
	// of the dynamic-config file only ever touches Crenel's own keys — every other
	// router/service (Authelia, dashboards, other vendors' routes) is preserved.
	managedPrefix = "crenel-"
	// tcpPrefix tags crenel-managed TCP (passthrough) routers/services.
	tcpPrefix = "crenel-tcp-"
	// denyKey is the key of the LEGACY explicit catch-all deny router+service. crenel
	// no longer EMITS it (its empty-loadBalancer service was rejected by real Traefik —
	// bench gap T3); the structural default-deny is Traefik's native 404 for unmatched
	// hosts. The key is kept so Apply can DELETE a stale one written by an older crenel
	// (removeStaleDeny) and so the driver still RECOGNIZES it on read.
	denyKey       = "crenel-deny"
	routePriority = 10
)

func managedRouterID(host string) string  { return managedPrefix + host }
func managedServiceID(host string) string { return managedPrefix + host }
func tcpRouterID(host string) string      { return tcpPrefix + host }
func tcpServiceID(host string) string     { return tcpPrefix + host }

// hasUpstream reports whether the service has at least one non-empty server URL.
func (s *service) hasUpstream() bool {
	if s == nil {
		return false
	}
	for _, srv := range s.LoadBalancer.Servers {
		if srv.URL != "" {
			return true
		}
	}
	return false
}

// firstUpstream returns the first server URL, if any.
func (s *service) firstUpstream() string {
	if s == nil {
		return ""
	}
	for _, srv := range s.LoadBalancer.Servers {
		if srv.URL != "" {
			return srv.URL
		}
	}
	return ""
}
