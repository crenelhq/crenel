// Package static is an OriginResolver backed by a fixed service->address map.
// This is the M0 resolver; later milestones may add dynamic discovery.
package static

import (
	"fmt"
	"sort"
	"strings"
)

// Resolver resolves service names to backend addresses from a static map.
type Resolver struct {
	m map[string]string
}

// New builds a Resolver. Keys are lower-cased for case-insensitive lookup.
func New(m map[string]string) *Resolver {
	norm := make(map[string]string, len(m))
	for k, v := range m {
		norm[strings.ToLower(k)] = v
	}
	return &Resolver{m: norm}
}

// Resolve returns the backend address for serviceName.
func (r *Resolver) Resolve(serviceName string) (string, error) {
	if addr, ok := r.m[strings.ToLower(serviceName)]; ok {
		return addr, nil
	}
	return "", fmt.Errorf("static resolver: no backend mapped for service %q (known: %s)",
		serviceName, strings.Join(r.known(), ", "))
}

func (r *Resolver) known() []string {
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
