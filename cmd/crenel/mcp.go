package main

// crenel mcp — a Model Context Protocol server over stdio, for an LLM agent.
//
// Default mode is READ-ONLY (default-deny, crenel's core posture): the agent can
// query what the edge exposes (crenel_status), audit its posture (crenel_audit),
// and detect drift (crenel_drift), but cannot mutate anything. Writes are OFF
// unless the operator starts the server with `--write`.
//
// Read-only BY CONSTRUCTION (the load-bearing guarantee for the default mode): the
// read-only server depends only on a narrow `core.ReadOnlyEngine` interface (Status /
// Audit / DetectDrift) and holds NO write capability (writer == nil), so no
// mutating method is reachable through the server's fields — the Go type system,
// not a runtime check, forbids it. This mirrors the `serve` dashboard's posture.
//
// The `--write` server ADDS a two-phase gated write surface (crenel_plan +
// crenel_apply) on top of the same reads. The gate: crenel_plan returns the exact
// diff plus a content-hash plan_id; crenel_apply refuses unless its confirm_plan_id
// re-derives to the SAME id against current live state — so an agent can never
// blind-write, and a change that drifted since preview is refused (TOCTOU-safe).
// crenel's own guarantees are never bypassed: default-deny, the public-without-auth
// gate, read-back verify, the ownership gate, and the runtime-verify honesty gate
// all still apply exactly as on the CLI. See docs/MCP.md + docs/mcp/SKILL.md.
//
// Zero-dependency: MCP is just JSON-RPC 2.0 framed as newline-delimited JSON on
// stdio. We handle initialize / notifications/initialized / tools/list / tools/call
// (+ ping) with encoding/json, crypto/sha256, and bufio from the standard library —
// go.mod gains nothing.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/crenelhq/crenel/internal/config"
	"github.com/crenelhq/crenel/internal/core"
	"github.com/crenelhq/crenel/internal/model"
	"github.com/crenelhq/crenel/internal/redact"
)

// cmdMCP runs the MCP server over stdio (JSON-RPC 2.0). Default is READ-ONLY (the
// agent-facing analog of `crenel serve`): READ-ONLY BY CONSTRUCTION — the engine is
// handed to the server only through the narrow core.ReadOnlyEngine interface with no
// write capability, so no mutating verb is reachable. Passing `--write` starts the
// read/write server, which ADDS the two-phase gated write tools (crenel_plan +
// crenel_apply) — writes are opt-in, never the default (default-deny).
//
// Diagnostics (the startup line, errors) go to STDERR so they never corrupt the
// JSON-RPC frame stream on stdout.
func (c *cli) cmdMCP(ctx context.Context, args []string) error {
	write := false
	for _, a := range args {
		switch a {
		case "--write", "-write", "--read-write":
			write = true
		default:
			return fmt.Errorf("mcp takes no arguments except --write (transport is stdio); got %q", a)
		}
	}
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	var srv *mcpServer
	mode := "read-only"
	if write {
		srv = newReadWriteMCPServer(c.engine, version)
		mode = "read/write (two-phase gated writes)"
	} else {
		srv = newMCPServer(c.engine, version)
	}
	fmt.Fprintf(c.errOut, "%s mcp (%s) speaking MCP over stdio — initialize to begin\n", config.ToolName, mode)
	return srv.serve(ctx, in, c.out)
}

// The read-only capability the MCP server is given is core.ReadOnlyEngine: the
// three live read paths (Status / Audit / DetectDrift) and nothing else. Every
// mutating Engine method (Apply, Reconcile, Import, Rename, …) is OUT OF SCOPE
// because it is not in that interface, so the server literally cannot call one.
// The interface lives in internal/core (exported by M-A1) so the serve dashboard,
// the audit-target mode, and this server share ONE definition of "read-only by
// construction" — no private duplicate here.

// mcpProtocolVersion is the MCP revision the server implements. When a client
// requests a version we recognize we echo it back; otherwise we answer with this.
const mcpProtocolVersion = "2024-11-05"

// mcpServer speaks MCP over an in/out stream. It always holds a core.ReadOnlyEngine
// (reads). It holds a `writer` (the concrete *core.Engine) ONLY in read/write mode;
// in the default read-only mode writer is nil AND no write tool is advertised, so
// the write path is unreachable by construction.
type mcpServer struct {
	engine  core.ReadOnlyEngine
	writer  *core.Engine // non-nil only in --write mode; gated write tools use it
	version string
}

// newMCPServer builds the READ-ONLY server (writer nil): the narrow read interface
// only. Its signature stays `core.ReadOnlyEngine` so the by-construction guarantee holds
// — a caller literally cannot give it a write capability.
func newMCPServer(engine core.ReadOnlyEngine, version string) *mcpServer {
	return &mcpServer{engine: engine, version: version}
}

// newReadWriteMCPServer builds the READ/WRITE server: the same reads PLUS the
// two-phase gated write tools, driven by the concrete engine the CLI uses.
func newReadWriteMCPServer(engine *core.Engine, version string) *mcpServer {
	return &mcpServer{engine: engine, writer: engine, version: version}
}

// readWrite reports whether the write surface is enabled.
func (s *mcpServer) readWrite() bool { return s.writer != nil }

// --- JSON-RPC 2.0 wire types ---------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification (no reply)
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC standard error codes (subset we use).
const (
	errParse          = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
)

// --- MCP tool catalog ----------------------------------------------------------

// mcpTool is one advertised tool: name + human/LLM description + JSON Schema for
// its arguments. handle decodes the raw arguments it needs and returns the
// structured result value.
type mcpTool struct {
	Name        string
	Description string
	InputSchema map[string]any
	handle      func(ctx context.Context, s *mcpServer, raw json.RawMessage) (any, error)
}

// readArgs is the decoded `arguments` object of a READ tools/call. Every field is
// an optional read-only filter — there is no field that could drive a mutation.
type readArgs struct {
	Edge string `json:"edge"`
}

// decodeArgs unmarshals a tools/call arguments object into v (a no-op for absent
// arguments), returning a descriptive error on malformed JSON.
func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// edgeFilterSchema is the shared optional-edge-filter input schema.
func edgeFilterSchema(desc string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"edge": map[string]any{
				"type":        "string",
				"description": desc,
			},
		},
		"additionalProperties": false,
	}
}

// emptySchema is an input schema that accepts no arguments.
func emptySchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"properties":           map[string]any{},
		"additionalProperties": false,
	}
}

// tools is the full catalog. In the default (read-only) mode it contains the three
// READ tools ONLY — no expose/unexpose/rename/set/apply/reconcile/import entry — and
// because tools/call dispatches off this same list, an un-advertised tool is also
// un-callable. In --write mode it appends the two-phase write pair (crenel_plan +
// crenel_apply); those are the ONLY way to mutate, and both go through the plan_id
// gate.
func (s *mcpServer) tools() []mcpTool {
	cat := s.readTools()
	if s.readWrite() {
		cat = append(cat, s.writeTools()...)
	}
	return cat
}

// readTools is the read-only catalog (always available).
func (s *mcpServer) readTools() []mcpTool {
	return []mcpTool{
		{
			Name: "crenel_status",
			Description: "Read the edge's LIVE exposure state: per-edge routes (host -> backend, " +
				"mode, attached forward-auth, chain follow-through), the ternary default-deny " +
				"posture (enforced / unknown / missing), config coverage (understood vs not-" +
				"understood routes), durability, off-edge ingress, and managed DNS records. " +
				"Strictly read-only; consults live state only (there is no stored desired state). " +
				"Secret bytes in unparsed-config excerpts are redacted. Optional `edge` filters " +
				"to a single edge by topology name.",
			InputSchema: edgeFilterSchema("Topology name of a single edge to report (e.g. \"home\", \"vps\"). Omit for all edges."),
			handle:      handleStatus,
		},
		{
			Name: "crenel_audit",
			Description: "Run the live-only invariant + cross-provider consistency audit and return " +
				"its findings: public-without-auth hosts, fail-open (missing default-deny) edges, " +
				"not-understood/unknown constructs, and chain-resolution notes. Each finding has a " +
				"severity (critical / warning / ok), a machine code, and a message. Strictly read-" +
				"only — it inspects live state and changes nothing.",
			InputSchema: emptySchema(),
			handle:      handleAudit,
		},
		{
			Name: "crenel_drift",
			Description: "Detect divergence between live edge/DNS state and the canonical currently-" +
				"exposed set: routes missing from an edge that should carry them, mode mismatches, " +
				"and stale managed DNS records. Returns the drift items (kind, host, target edge/DNS, " +
				"detail) and the corrective change that WOULD converge — but applies nothing. " +
				"Strictly read-only. Optional `edge` filters drift to a single edge/target.",
			InputSchema: edgeFilterSchema("Topology name of an edge (or DNS target) to filter drift to. Omit for all targets."),
			handle:      handleDrift,
		},
	}
}

// toolByName returns the catalog tool with the given name, or false. tools/call
// uses ONLY this lookup, so a name not in the read-only catalog cannot be invoked.
func (s *mcpServer) toolByName(name string) (mcpTool, bool) {
	for _, t := range s.tools() {
		if t.Name == name {
			return t, true
		}
	}
	return mcpTool{}, false
}

// --- tool handlers (read paths) ------------------------------------------------

func handleStatus(ctx context.Context, s *mcpServer, raw json.RawMessage) (any, error) {
	var args readArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	rep, err := s.engine.Status(ctx)
	if err != nil {
		return nil, err
	}
	// Always redact secret bytes carried in declared-unknown excerpts: this output
	// goes to an autonomous agent, so a stray auth hash / token must never leak.
	// RawExcerpt is display-only (never read back for apply), so scrubbing is safe.
	for i := range rep.Edges {
		for j := range rep.Edges[i].Unparsed {
			rep.Edges[i].Unparsed[j].RawExcerpt = redact.Snippet(rep.Edges[i].Unparsed[j].RawExcerpt)
		}
	}
	if args.Edge != "" {
		filtered := rep.Edges[:0:0]
		for _, es := range rep.Edges {
			if es.Name == args.Edge {
				filtered = append(filtered, es)
			}
		}
		rep.Edges = filtered
	}
	return rep, nil
}

func handleAudit(ctx context.Context, s *mcpServer, _ json.RawMessage) (any, error) {
	rep, err := s.engine.Audit(ctx)
	if err != nil {
		return nil, err
	}
	return rep, nil
}

func handleDrift(ctx context.Context, s *mcpServer, raw json.RawMessage) (any, error) {
	var args readArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	plan, err := s.engine.DetectDrift(ctx)
	if err != nil {
		return nil, err
	}
	if args.Edge != "" {
		filtered := plan.Drift[:0:0]
		for _, d := range plan.Drift {
			if d.Target == args.Edge {
				filtered = append(filtered, d)
			}
		}
		plan.Drift = filtered
	}
	return plan, nil
}

// --- write path (two-phase gated) ----------------------------------------------

// writeArgs is the decoded arguments of crenel_plan / crenel_apply. The same shape
// serves every write verb; which fields matter depends on `verb` (documented in the
// schema). ConfirmPlanID is required by crenel_apply and ignored by crenel_plan.
type writeArgs struct {
	Verb          string   `json:"verb"`
	Service       string   `json:"service"`
	State         string   `json:"state"`
	To            string   `json:"to"`
	Auth          string   `json:"auth"`
	Mode          string   `json:"mode"`
	Scope         string   `json:"scope"`
	DNS           string   `json:"dns"`
	Edges         []string `json:"edges"`
	OldHost       string   `json:"old_host"`
	NewHost       string   `json:"new_host"`
	ConfirmPlanID string   `json:"confirm_plan_id"`
}

// writeSchemaProps is the shared property set for the write tools.
func writeSchemaProps() map[string]any {
	return map[string]any{
		"verb":     map[string]any{"type": "string", "enum": []string{"expose", "unexpose", "set", "rename"}, "description": "The write verb. expose/unexpose/set take `service` (+ optional to/auth/mode/scope/dns/edges); set also takes `state` on|off; rename takes `old_host`+`new_host`."},
		"service":  map[string]any{"type": "string", "description": "Service/host to expose|unexpose|set (e.g. \"grafana\" -> grafana.<zone>, or a full host)."},
		"state":    map[string]any{"type": "string", "enum": []string{"on", "off"}, "description": "set only: on = expose, off = unexpose."},
		"to":       map[string]any{"type": "string", "description": "expose only: explicit backend host:port (e.g. \"10.0.0.19:8123\"). Omit to use the pre-declared origin."},
		"auth":     map[string]any{"type": "string", "description": "expose only: forward-auth policy name (e.g. \"authelia\"), or \"none\" to publish unprotected on purpose. REQUIRED to expose a host publicly."},
		"mode":     map[string]any{"type": "string", "enum": []string{"http", "passthrough", "mesh"}, "description": "expose only: route mode. Default http."},
		"scope":    map[string]any{"type": "string", "enum": []string{"internal", "public", "both"}, "description": "DNS reachability posture. internal = internal DNS only (no public record, no forced auth); public = public chain + auth required; both = default. Sugar over `dns`."},
		"dns":      map[string]any{"type": "string", "enum": []string{"internal", "public", "both"}, "description": "Granular DNS-scope restriction (mutually exclusive with `scope`)."},
		"edges":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Edge topology names to appoint the route to (e.g. [\"home\"]). Omit for every edge that fronts the service."},
		"old_host": map[string]any{"type": "string", "description": "rename only: the current hostname."},
		"new_host": map[string]any{"type": "string", "description": "rename only: the new hostname."},
	}
}

// writeTools is the two-phase write catalog (only appended in --write mode).
func (s *mcpServer) writeTools() []mcpTool {
	planProps := writeSchemaProps()
	applyProps := writeSchemaProps()
	applyProps["confirm_plan_id"] = map[string]any{"type": "string", "description": "The plan_id returned by crenel_plan for the SAME change. crenel_apply refuses if it does not re-derive against current live state."}
	return []mcpTool{
		{
			Name: "crenel_plan",
			Description: "PHASE 1 of a gated write: compute (but do NOT apply) the exact change for a " +
				"write verb (expose/unexpose/set/rename) against live state, and return the diff " +
				"(edge routes + DNS records added/removed), whether it makes a host public, whether " +
				"auth is required, and a content-hash `plan_id`. Nothing is mutated. To actually " +
				"apply, pass this plan_id to crenel_apply. Read this diff before applying.",
			InputSchema: map[string]any{"type": "object", "properties": planProps, "required": []string{"verb"}, "additionalProperties": false},
			handle:      handlePlan,
		},
		{
			Name: "crenel_apply",
			Description: "PHASE 2 of a gated write: apply a change previously previewed with crenel_plan. " +
				"REQUIRES `confirm_plan_id` equal to that plan's id; crenel re-computes the change " +
				"against CURRENT live state and refuses (no mutation) if the id does not match — so " +
				"you cannot blind-write, and a change that drifted since preview is rejected. On " +
				"match it runs crenel's full apply: preview→apply→read-back-verify, rolled back on " +
				"any failure. Exposing PUBLIC with no auth is refused unless `auth` is set.",
			InputSchema: map[string]any{"type": "object", "properties": applyProps, "required": []string{"verb", "confirm_plan_id"}, "additionalProperties": false},
			handle:      handleApply,
		},
	}
}

// writeVerbOf maps the tool's `verb` (+ `state` for set) to a model.Verb and whether
// it is a rename. It rejects an unknown verb / a bad set state loudly.
func writeVerbOf(a writeArgs) (verb model.Verb, isRename bool, err error) {
	switch a.Verb {
	case "expose":
		return model.Expose, false, nil
	case "unexpose":
		return model.Unexpose, false, nil
	case "set":
		switch strings.ToLower(strings.TrimSpace(a.State)) {
		case "on", "true", "expose", "1":
			return model.Expose, false, nil
		case "off", "false", "unexpose", "0":
			return model.Unexpose, false, nil
		default:
			return "", false, fmt.Errorf("set requires state on|off, got %q", a.State)
		}
	case "rename", "move":
		return model.Rename, true, nil
	default:
		return "", false, fmt.Errorf("unknown verb %q (want expose|unexpose|set|rename)", a.Verb)
	}
}

// planWrite computes the ChangeSet for a write request — the shared core of BOTH
// phases, so crenel_apply hashes the exact same change crenel_plan previewed. It
// mutates nothing (Plan/PlanRename are read-only). It returns the op (empty for
// rename) so the caller can apply the auth gate + drive the matching apply verb.
func (s *mcpServer) planWrite(ctx context.Context, a writeArgs) (op model.Op, isRename bool, cs model.ChangeSet, err error) {
	verb, isRename, err := writeVerbOf(a)
	if err != nil {
		return op, false, cs, err
	}
	if isRename {
		if a.OldHost == "" || a.NewHost == "" {
			return op, true, cs, fmt.Errorf("rename requires old_host and new_host")
		}
		cs, err = s.writer.PlanRename(ctx, a.OldHost, a.NewHost)
		return op, true, cs, err
	}
	if a.Service == "" {
		return op, false, cs, fmt.Errorf("%s requires service", a.Verb)
	}
	op, err = buildOpFrom(s.writer, verb, a.Service, opIntent{
		mode: a.Mode, auth: a.Auth, to: a.To, scope: a.Scope, dns: a.DNS, edges: strings.Join(a.Edges, ","),
	})
	if err != nil {
		return op, false, cs, err
	}
	cs, err = s.writer.Plan(ctx, op)
	return op, false, cs, err
}

// planID is the two-phase confirmation token: a content hash of the exact computed
// change. Same change against same live state => same id; ANY difference (different
// intent, or live state drifted so the diff differs) => different id. This is what
// makes crenel_apply's confirm_plan_id both a "you previewed this" proof and a
// TOCTOU guard, with no server-side state to keep.
func planID(cs model.ChangeSet) string {
	b, err := json.Marshal(cs)
	if err != nil {
		// A change that will not marshal cannot be safely confirmed; a random-looking
		// but STABLE fallback over the error keeps apply from ever matching.
		sum := sha256.Sum256([]byte("crenel-planid-error:" + err.Error()))
		return hex.EncodeToString(sum[:])[:16]
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// previewResult is crenel_plan's structured output.
type previewResult struct {
	PlanID       string          `json:"plan_id"`
	Verb         string          `json:"verb"`
	Empty        bool            `json:"empty"`         // true => applying would change nothing
	GoesPublic   bool            `json:"goes_public"`   // true => makes >=1 host publicly reachable
	NewPublic    []string        `json:"new_public"`    // the host(s) about to go public
	AuthRequired bool            `json:"auth_required"` // true => apply will refuse without auth
	Summary      string          `json:"summary"`
	Change       model.ChangeSet `json:"change"` // the exact diff (edge + DNS adds/removes)
}

// applyResult is crenel_apply's structured output.
type applyResult struct {
	PlanID        string              `json:"plan_id"`
	Applied       bool                `json:"applied"`
	NoOp          bool                `json:"no_op"`
	Verified      bool                `json:"verified"`
	FullyVerified bool                `json:"fully_verified"`
	NewPublic     []string            `json:"new_public,omitempty"`
	Verify        []core.VerifyResult `json:"verify,omitempty"`
	Summary       string              `json:"summary"`
}

// authWouldBlock reports whether applying this op/cs would hit the public-without-
// auth guardrail: an expose that makes a host public with no auth policy set. It is
// the same notion as the CLI's guardPublicAuth (unexpose/rename never trip it).
func authWouldBlock(op model.Op, isRename bool, cs model.ChangeSet) bool {
	if isRename || op.Verb != model.Expose || op.Auth != "" {
		return false
	}
	return len(cs.NewPublic) > 0
}

func handlePlan(ctx context.Context, s *mcpServer, raw json.RawMessage) (any, error) {
	var a writeArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	op, isRename, cs, err := s.planWrite(ctx, a)
	if err != nil {
		return nil, err
	}
	id := planID(cs)
	res := previewResult{
		PlanID:       id,
		Verb:         a.Verb,
		Empty:        cs.Empty(),
		GoesPublic:   len(cs.NewPublic) > 0,
		NewPublic:    cs.NewPublic,
		AuthRequired: authWouldBlock(op, isRename, cs),
		Change:       cs,
	}
	switch {
	case res.Empty:
		res.Summary = "no change — live already matches this intent; nothing to apply"
	case res.AuthRequired:
		res.Summary = fmt.Sprintf("would make %v PUBLIC with NO auth — crenel_apply will REFUSE unless you set auth (a policy, or \"none\"). plan_id %s", cs.NewPublic, id)
	case res.GoesPublic:
		res.Summary = fmt.Sprintf("would make %v public (auth set). Apply with confirm_plan_id=%s", cs.NewPublic, id)
	default:
		res.Summary = fmt.Sprintf("internal/no-new-public change. Apply with confirm_plan_id=%s", id)
	}
	return res, nil
}

func handleApply(ctx context.Context, s *mcpServer, raw json.RawMessage) (any, error) {
	var a writeArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.ConfirmPlanID == "" {
		return nil, fmt.Errorf("crenel_apply requires confirm_plan_id — call crenel_plan first and pass its plan_id")
	}
	// Re-plan against CURRENT live and re-derive the id: this is the whole gate.
	op, isRename, cs, err := s.planWrite(ctx, a)
	if err != nil {
		return nil, err
	}
	id := planID(cs)
	if id != a.ConfirmPlanID {
		return nil, fmt.Errorf("plan_id mismatch: confirm_plan_id %q does not match the change computed now (%q). Live state changed since preview, or you did not preview THIS exact change. Call crenel_plan again and apply with its fresh plan_id", a.ConfirmPlanID, id)
	}
	if cs.Empty() {
		return applyResult{PlanID: id, Applied: false, NoOp: true, Verified: true, FullyVerified: true,
			Summary: "no change — live already matches; nothing applied"}, nil
	}
	// crenel's own public-without-auth guardrail — never bypassed by the MCP path.
	if authWouldBlock(op, isRename, cs) {
		return nil, fmt.Errorf("refusing to expose %v PUBLIC with no auth — set auth to a policy, or \"none\" to publish unprotected on purpose", cs.NewPublic)
	}

	// Apply through the same engine the CLI uses. The plan_id echo is the operator's
	// confirmation, so the engine confirm callback is AlwaysYes; read-back verify still
	// runs and rolls back on failure. We do NOT set AllowUnverified: an unconfirmable
	// file-driver write is surfaced as an error, not silently accepted.
	var rep core.ApplyReport
	if isRename {
		rep, err = s.writer.Rename(ctx, a.OldHost, a.NewHost, core.AlwaysYes)
	} else {
		rep, err = s.writer.Apply(ctx, op, core.AlwaysYes)
	}
	if err != nil {
		var uerr *core.UnverifiedWriteError
		if errors.As(err, &uerr) {
			return nil, fmt.Errorf("write rolled back — runtime verify unavailable for %v; apply from the CLI with --allow-unverified, or configure a runtime probe on that driver", uerr.Providers)
		}
		return nil, err
	}
	return applyResult{
		PlanID:        id,
		Applied:       rep.Applied,
		Verified:      rep.Verified(),
		FullyVerified: rep.FullyVerified(),
		NewPublic:     rep.NewPublic,
		Verify:        rep.Verify,
		Summary:       fmt.Sprintf("applied + read-back-verified (%s)", a.Verb),
	}, nil
}

// --- serve loop ----------------------------------------------------------------

// serve reads newline-delimited JSON-RPC messages from in, dispatches each, and
// writes responses to out. It returns nil on clean EOF. Notifications (requests
// with no id) get no reply. The loop is single-threaded: MCP stdio is one ordered
// stream, and the underlying reads are themselves serialized.
func (s *mcpServer) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(bufio.NewReader(in))
	enc := json.NewEncoder(out)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			// A malformed frame: report a parse error with null id and keep serving
			// is impossible (the decoder stream is now unaligned), so stop cleanly.
			_ = enc.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: errParse, Message: "parse error: " + err.Error()},
			})
			return nil
		}
		resp, reply := s.handle(ctx, req)
		if !reply {
			continue // notification — no response per JSON-RPC
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
}

// handle dispatches one request and returns the response plus whether to send it
// (false for notifications). It never mutates anything: the only side effects are
// the read methods on core.ReadOnlyEngine.
func (s *mcpServer) handle(ctx context.Context, req rpcRequest) (rpcResponse, bool) {
	isNotification := len(req.ID) == 0
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = s.initializeResult(req.Params)
	case "notifications/initialized", "initialized", "notifications/cancelled":
		return resp, false // notifications: acknowledge by doing nothing
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = s.toolsListResult()
	case "tools/call":
		resp.Result, resp.Error = s.toolsCall(ctx, req.Params)
	default:
		if isNotification {
			return resp, false // unknown notification — ignore, never error
		}
		resp.Error = &rpcError{Code: errMethodNotFound, Message: "method not found: " + req.Method}
	}

	if isNotification {
		return resp, false
	}
	return resp, true
}

// initializeResult returns the MCP initialize response: protocol version, the
// server's capabilities (tools only — no resources/prompts), and identity. We echo
// the client's requested protocolVersion when we recognize it, else answer with
// our own.
func (s *mcpServer) initializeResult(params json.RawMessage) map[string]any {
	version := mcpProtocolVersion
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			version = p.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			// Advertise tools only. We do NOT advertise tools.listChanged (the catalog
			// is static) and expose no resources/prompts — the read-only surface is the
			// three tools and nothing else.
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    config.ToolName + "-mcp",
			"title":   config.ToolTitle + s.modeSuffix(),
			"version": s.version,
		},
		"instructions": s.instructions(),
	}
}

// modeSuffix labels the server's identity by mode.
func (s *mcpServer) modeSuffix() string {
	if s.readWrite() {
		return " (read/write)"
	}
	return " (read-only)"
}

// instructions is the MCP initialize `instructions` string the client shows the
// agent — it states the capability boundary + the two-phase write contract.
func (s *mcpServer) instructions() string {
	if s.readWrite() {
		return "Read + GATED-WRITE control of " + config.ToolTitle + ". Reads: crenel_status " +
			"(live exposure), crenel_audit (posture), crenel_drift. Writes are TWO-PHASE and " +
			"cannot be done blind: call crenel_plan first to get the exact diff + a plan_id, " +
			"then crenel_apply with confirm_plan_id set to that id. crenel_apply refuses if the " +
			"id no longer matches the live-computed change (someone/something changed state, or " +
			"you didn't preview THIS change). crenel never bypasses its own gates: exposing a " +
			"host PUBLIC with no auth is refused unless you set auth (a policy, or \"none\" to " +
			"publish unprotected on purpose), and every write is read-back-verified or rolled back."
	}
	return "Read-only edge introspection for " + config.ToolTitle + ". Tools report live exposure " +
		"(crenel_status), audit posture (crenel_audit), and drift (crenel_drift). This server " +
		"CANNOT change the edge — there is no expose, apply, or reconcile capability. Safe to " +
		"hand to autonomous agents."
}

// toolListEntry is one advertised tool in tools/list (wire shape).
type toolListEntry struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *mcpServer) toolsListResult() map[string]any {
	cat := s.tools()
	entries := make([]toolListEntry, 0, len(cat))
	for _, t := range cat {
		entries = append(entries, toolListEntry{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return map[string]any{"tools": entries}
}

// toolsCall runs a tools/call. A tool whose READ fails is reported as an MCP tool
// error (CallToolResult.isError) so the agent sees the failure as data; a missing
// tool name or bad params is a JSON-RPC protocol error. Either way, no mutator is
// reachable: dispatch is off the read-only catalog.
func (s *mcpServer) toolsCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &call); err != nil {
			return nil, &rpcError{Code: errInvalidParams, Message: "invalid tools/call params: " + err.Error()}
		}
	}
	if call.Name == "" {
		return nil, &rpcError{Code: errInvalidParams, Message: "tools/call requires a tool name"}
	}
	tool, ok := s.toolByName(call.Name)
	if !ok {
		// Not in the catalog for this mode (in read-only mode this includes every write
		// tool) => not a callable tool. Reported as invalid params so the agent gets an
		// unambiguous "no such tool", and crucially no mutation code path is consulted.
		return nil, &rpcError{Code: errInvalidParams, Message: "unknown tool: " + call.Name}
	}

	// Each handler decodes the argument shape it needs from the raw object (read
	// filters vs write intent), so a malformed-JSON error is per-tool and precise.
	result, err := tool.handle(ctx, s, call.Arguments)
	if err != nil {
		return callToolError(fmt.Sprintf("%s failed: %v", call.Name, err)), nil
	}
	return callToolResult(result)
}

// callToolResult marshals a read result into an MCP CallToolResult: a text content
// block carrying the pretty-printed JSON, plus structuredContent for clients that
// consume typed output. isError is false.
func callToolResult(v any) (any, *rpcError) {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return callToolError("failed to serialize result: " + err.Error()), nil
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(pretty)},
		},
		"structuredContent": v,
		"isError":           false,
	}, nil
}

// callToolError builds an MCP CallToolResult with isError=true — the convention for
// a tool that ran but failed (vs a JSON-RPC protocol error).
func callToolError(msg string) any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": msg},
		},
		"isError": true,
	}
}
