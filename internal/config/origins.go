package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// OriginScope values accepted on a structured origins entry. The zero value ("")
// and the explicit "all" spelling are the pre-scope default: the service
// participates in every DNS scope and every chain leg, exactly as a plain-string
// entry always has. "internal" is the split-horizon declaration: the service is
// INTERNAL-ONLY — internal DNS records and the downstream edge route stay fully
// managed and verified, but crenel must never demand (or create) a public DNS
// record for it, and a chain FRONT edge must never be asked to forward it. See
// docs/internal/DESIGN.md "Internal-scope services".
const (
	OriginScopeDefault  = ""         // plain-string semantics: all scopes
	OriginScopeAll      = "all"      // explicit spelling of the default
	OriginScopeInternal = "internal" // internal-only: no public DNS, no front forward
)

// Origin is ONE origins entry: the backend address plus an optional declared
// scope. The JSON/YAML wire form is polymorphic — a plain string is the address
// with default scope (byte-identical to the historical map[string]string shape),
// and an object {"addr": ..., "scope": ...} carries the structured declaration:
//
//	"origins": {
//	  "grafana": "10.0.0.7:3000",
//	  "ha":      {"addr": "10.0.0.19:8123", "scope": "internal"}
//	}
//
// The YAML path decodes through the same UnmarshalJSON (the yaml subset decoder
// JSON-roundtrips into the target); the structured entry there is the nested
// BLOCK-map form (flow maps `{...}` are outside the yaml subset):
//
//	origins:
//	  grafana: 10.0.0.7:3000
//	  ha:
//	    addr: 10.0.0.19:8123
//	    scope: internal
type Origin struct {
	// Addr is the service's backend dial address (host:port).
	Addr string `json:"addr"`
	// Scope is the declared reachability scope: "" / "all" (default — every
	// managed scope) or "internal" (internal-only; see OriginScopeInternal).
	Scope string `json:"scope,omitempty"`
}

// Internal reports whether this entry declares the service internal-only.
func (o Origin) Internal() bool { return o.Scope == OriginScopeInternal }

// UnmarshalJSON accepts the polymorphic wire form: a JSON string (the plain
// historical entry — address only, default scope) or an object with an "addr"
// and optional "scope". Errors are LOUD by design: an unknown key, a missing
// addr, or an unrecognized scope value refuses the whole config load rather
// than silently defaulting a security-relevant declaration.
func (o *Origin) UnmarshalJSON(b []byte) error {
	// Plain-string form: today's semantics exactly.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*o = Origin{Addr: s}
		return nil
	}
	// Structured form: strict decode — unknown fields are refused so a typo like
	// {"adr": ...} or {"scop": ...} can never silently drop a scope declaration.
	type wire struct {
		Addr  string `json:"addr"`
		Scope string `json:"scope"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return fmt.Errorf("origins entry must be an address string or {addr, scope} object: %w", err)
	}
	if w.Addr == "" {
		return fmt.Errorf("structured origins entry is missing required \"addr\"")
	}
	switch w.Scope {
	case OriginScopeDefault, OriginScopeInternal:
		// valid as-is
	case OriginScopeAll:
		w.Scope = OriginScopeDefault // normalize the explicit spelling
	default:
		return fmt.Errorf("origins entry has unknown scope %q (want %q or %q)", w.Scope, OriginScopeAll, OriginScopeInternal)
	}
	*o = Origin{Addr: w.Addr, Scope: w.Scope}
	return nil
}

// MarshalJSON round-trips the wire form: a default-scope entry re-emits as the
// plain string (so a config that only ever used plain entries re-encodes
// byte-compatibly), and a scoped entry emits the structured object.
func (o Origin) MarshalJSON() ([]byte, error) {
	if o.Scope == OriginScopeDefault {
		return json.Marshal(o.Addr)
	}
	type wire struct {
		Addr  string `json:"addr"`
		Scope string `json:"scope"`
	}
	return json.Marshal(wire{Addr: o.Addr, Scope: o.Scope})
}

// Origins is the service -> origin map. It replaces the historical
// map[string]string field type; every plain-string entry decodes to the same
// (address, default-scope) meaning it always had.
type Origins map[string]Origin

// Addrs flattens the map to the historical service -> address shape — what the
// per-edge OriginResolver and any address-only consumer expect.
func (o Origins) Addrs() map[string]string {
	if o == nil {
		return nil
	}
	out := make(map[string]string, len(o))
	for svc, org := range o {
		out[svc] = org.Addr
	}
	return out
}

// InternalServices returns (sorted) the services this map declares internal-only.
func (o Origins) InternalServices() []string {
	var out []string
	for svc, org := range o {
		if org.Internal() {
			out = append(out, svc)
		}
	}
	sort.Strings(out)
	return out
}

// PlainOrigins builds an Origins map from the historical address-only shape —
// the convenience constructor for tests and callers that carry no scopes.
func PlainOrigins(m map[string]string) Origins {
	if m == nil {
		return nil
	}
	out := make(Origins, len(m))
	for svc, addr := range m {
		out[svc] = Origin{Addr: addr}
	}
	return out
}
