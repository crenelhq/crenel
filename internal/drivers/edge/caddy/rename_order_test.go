package caddy_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/crenelhq/crenel/internal/drivers/edge/caddy"
	"github.com/crenelhq/crenel/internal/drivers/edge/caddy/caddyfake"
	"github.com/crenelhq/crenel/internal/drivers/origin/static"
	"github.com/crenelhq/crenel/internal/drivers/transport"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/ports"
)

// recordXport records the method of each mutating admin call (PUT/DELETE) in order, then
// delegates to a real Direct transport against the fake — so a test can assert the
// driver's make-before-break ordering on the wire.
type recordXport struct {
	inner ports.Transport
	ops   *[]string
}

func (r recordXport) Do(ctx context.Context, method, path, ct string, body []byte) (int, []byte, error) {
	if method == http.MethodPut || method == http.MethodDelete {
		*r.ops = append(*r.ops, method)
	}
	return r.inner.Do(ctx, method, path, ct, body)
}

// TestApplyGranular_MakeBeforeBreakOrdering proves a rename-shaped change (add new host +
// remove old host) inserts the NEW route BEFORE deleting the OLD one — so the new host is
// up before the old comes down (zero-downtime) and a failed insert never strands the old.
func TestApplyGranular_MakeBeforeBreakOrdering(t *testing.T) {
	fake := caddyfake.New()
	defer fake.Close()
	if err := fake.SeedJSON(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
	 {"@id":"crenel-route-old.example.com","match":[{"host":["old.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.5:3000"}]}]},
	 {"handle":[{"handler":"static_response","status_code":403}]}
	]}}}}}`); err != nil {
		t.Fatal(err)
	}
	var ops []string
	d := caddy.New(fake.URL(), static.New(map[string]string{}), caddy.WithGranularApply(),
		caddy.WithTransport(recordXport{inner: transport.NewDirect(fake.URL()), ops: &ops}))

	cs := model.ChangeSet{Edge: model.EdgeChange{
		AddRoutes:                 []model.Route{{Host: "new.example.com", Upstream: model.Upstream{Mode: model.ModeHTTPProxy, Address: "10.0.0.5:3000", ServerName: "new.example.com"}}},
		RemoveHosts:               []string{"old.example.com"},
		DenyCatchAllWillBePresent: true,
	}}
	if err := d.Apply(context.Background(), cs); err != nil {
		t.Fatalf("apply rename-shaped change: %v", err)
	}

	firstPut, firstDel := -1, -1
	for i, op := range ops {
		if op == http.MethodPut && firstPut < 0 {
			firstPut = i
		}
		if op == http.MethodDelete && firstDel < 0 {
			firstDel = i
		}
	}
	if firstPut < 0 || firstDel < 0 {
		t.Fatalf("expected both an insert (PUT) and a delete (DELETE), got ops=%v", ops)
	}
	if firstPut > firstDel {
		t.Fatalf("make-before-break violated: insert(new) must precede delete(old); ops=%v", ops)
	}
}
