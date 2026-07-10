package caddy

import (
	"encoding/json"
	"strings"
	"testing"
)

// auth_forwardauth_golden_test.go PINS the exact JSON crenel's canonicalForwardAuth
// renderer emits and DIFFS it against Caddy's documented `forward_auth` directive
// expansion. It exists because the live production trial reported a 502 (instead of the
// expected 302-redirect-to-authelia) on a crenel-auth'd host, and auth is a SECURITY path
// where a wrong "fix" can fail OPEN. Rather than mutate the renderer speculatively, this
// test locks the CURRENT output so any future change is a deliberate, reviewed diff — and
// documents (below) where the real divergence lies.
//
// FINDING (flagged for human review — NOT auto-fixed):
//
//   crenel's canonicalForwardAuth is a FAITHFUL reproduction of Caddy's forward_auth
//   expansion. Per the Caddy docs (caddyserver.com/docs/caddyfile/directives/forward_auth),
//   forward_auth compiles to a reverse_proxy(authorizer) with `@good status 2xx` +
//   `handle_response @good { copy_headers }` and NOTHING for the non-2xx case. The 302
//   challenge reaches the client via reverse_proxy's DEFAULT behavior: any upstream
//   response NOT matched by a handle_response block is copied back to the client verbatim.
//   So the "unauthenticated → return authelia's 302" path is handled by Caddy's default
//   fall-through, by design — it is NOT (and should not be) a second handle_response entry.
//   The task's hypothesis (a) — "handle_response missing the copy-authelia-response-back
//   path" — does NOT hold: adding such a block would be a divergence FROM canonical.
//
//   The real divergence is in the AuthRef CONFIG the trial ran, not the renderer shape.
//   The trial's dumped route was `reverse_proxy{..., rewrite{method:GET}, ...,
//   handle_response{match{status_code:[2]} -> vars}}` — i.e. rewrite has NO `uri` and there
//   are NO copy_headers. That is EXACTLY what canonicalForwardAuth emits when the policy's
//   AuthRef has ForwardAuth set but VerifyURI and CopyHeaders EMPTY (see the "bare" golden
//   below). With no verify URI the auth subrequest keeps the app's ORIGINAL path instead of
//   authelia's `/api/verify?rd=…`, so authelia never receives a well-formed forward-auth
//   probe — producing the 502 (and, worse, risking fail-OPEN if authelia answers 2xx for
//   the app path). The known-good home-edge config (auth_test.go homeAuthRef) sets both
//   VerifyURI and CopyHeaders and renders the working gate.
//
//   RECOMMENDATION (for review, deliberately NOT committed as a behavioral change here):
//   have the granular auth path REFUSE loudly — the same fail-CLOSED pattern authGate
//   already uses for a snippet-only policy — when ForwardAuth is set but VerifyURI is
//   empty, so an incomplete forward-auth policy can never be applied as a silently-broken
//   (or fail-open) gate. This is a config-completeness guard, not a change to the gate's
//   runtime semantics, so it cannot fail open; it is left for a human to confirm the
//   verify-URI is truly mandatory for every authorizer (Authelia needs it) before landing.

// TestForwardAuth_GoldenFullyConfigured pins the exact rendered JSON for a fully
// configured authelia policy (endpoint + verify URI + one copy header). This is the
// canonical, working shape; any drift is a reviewed change.
func TestForwardAuth_GoldenFullyConfigured(t *testing.T) {
	ref := AuthRef{
		ForwardAuth: "authelia:9091",
		VerifyURI:   "/api/verify?rd=https://auth.example.com",
		CopyHeaders: []string{"Remote-User"},
	}
	const want = `{"handle_response":[{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"vars"}]},{"handle":[{"handler":"headers","request":{"delete":["Remote-User"]}}]},{"handle":[{"handler":"headers","request":{"set":{"Remote-User":["{http.reverse_proxy.header.Remote-User}"]}}}],"match":[{"not":[{"vars":{"{http.reverse_proxy.header.Remote-User}":[""]}}]}]}]}],"handler":"reverse_proxy","headers":{"request":{"set":{"X-Forwarded-Method":["{http.request.method}"],"X-Forwarded-Uri":["{http.request.uri}"]}}},"rewrite":{"method":"GET","uri":"/api/verify?rd=https://auth.example.com"},"upstreams":[{"dial":"authelia:9091"}]}`
	got := mustJSON(t, canonicalForwardAuth(ref))
	if got != want {
		t.Fatalf("canonical forward_auth render drifted.\n got: %s\nwant: %s", got, want)
	}
	// The 2xx-only matcher is load-bearing: on non-2xx, reverse_proxy's default copies
	// the authorizer's 302 back to the client. There must be exactly ONE handle_response
	// entry, matching status_code class 2 only (no separate non-2xx block).
	if strings.Count(got, `"match":{"status_code"`) != 1 {
		t.Fatalf("expected exactly one status_code-matched handle_response (2xx-only): %s", got)
	}
}

// TestForwardAuth_GoldenBareReproducesTrial pins the UNDER-configured render — the exact
// shape the live trial dumped (rewrite{method:GET} with no uri, no copy_headers) — proving
// the 502 stemmed from a policy AuthRef missing VerifyURI/CopyHeaders, not a renderer bug.
// See the FINDING at the top of this file.
func TestForwardAuth_GoldenBareReproducesTrial(t *testing.T) {
	const want = `{"handle_response":[{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"vars"}]}]}],"handler":"reverse_proxy","headers":{"request":{"set":{"X-Forwarded-Method":["{http.request.method}"],"X-Forwarded-Uri":["{http.request.uri}"]}}},"rewrite":{"method":"GET"},"upstreams":[{"dial":"authelia:9091"}]}`
	got := mustJSON(t, canonicalForwardAuth(AuthRef{ForwardAuth: "authelia:9091"}))
	if got != want {
		t.Fatalf("bare forward_auth render drifted.\n got: %s\nwant: %s", got, want)
	}
	// The bug signature: no `uri` in the rewrite (auth subrequest hits the app path, not
	// authelia's verify endpoint) and no copy_headers.
	if strings.Contains(got, `"uri"`) {
		t.Fatalf("bare render unexpectedly carries a rewrite uri: %s", got)
	}
}

// TestAuthGate_ForwardAuthWithoutVerifyURI exercises the guard at the renderer seam
// directly (in-package): authGate must return not-renderable for a ForwardAuth policy with
// no VerifyURI, and authGateError must produce the SPECIFIC verify-URI message (not the
// generic snippet-only one). This is the second enforcement site the coordinator required —
// so a footgun policy can never render anywhere, at Plan or at insertRoute.
func TestAuthGate_ForwardAuthWithoutVerifyURI(t *testing.T) {
	d := &Driver{authPolicies: map[string]AuthRef{"authelia": {ForwardAuth: "authelia:9091"}}}

	if _, ok := d.authGate("authelia"); ok {
		t.Fatal("authGate must refuse a forward-auth policy with no verify URI")
	}
	msg := d.authGateError("authelia").Error()
	for _, must := range []string{"caddy_forward_auth_verify_uri", "verify endpoint", "caddy_handler_json"} {
		if !strings.Contains(msg, must) {
			t.Errorf("authGateError must be specific (missing %q): %s", must, msg)
		}
	}
	if strings.Contains(msg, "no renderable Caddy reference") {
		t.Errorf("must not emit the generic snippet-only error: %s", msg)
	}

	// Fully-configured ForwardAuth renders (guard fires ONLY on the empty-VerifyURI case).
	full := &Driver{authPolicies: map[string]AuthRef{"authelia": {
		ForwardAuth: "authelia:9091", VerifyURI: "/api/verify?rd=https://auth.example.com",
	}}}
	if _, ok := full.authGate("authelia"); !ok {
		t.Fatal("authGate must render a forward-auth policy WITH a verify URI")
	}
}

// TestAuthGate_RawHandlerEscapeHatch proves the "I know what I'm doing" seam survives the
// guard: a raw caddy_handler_json blob renders even with NO verify URI (the operator owns
// the authorizer handler wholesale). Only the ForwardAuth-without-VerifyURI combination is
// refused, never a verbatim Handler.
func TestAuthGate_RawHandlerEscapeHatch(t *testing.T) {
	blob := []byte(`{"handler":"reverse_proxy","upstreams":[{"dial":"authelia:9091"}]}`)
	d := &Driver{authPolicies: map[string]AuthRef{"authelia": {Handler: blob}}}
	if _, ok := d.authGate("authelia"); !ok {
		t.Fatal("a raw handler blob must render regardless of verify URI (escape hatch intact)")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
