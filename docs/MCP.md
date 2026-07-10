# Crenel MCP server

`crenel mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio for an LLM agent. **Default mode is read-only** (default-deny —
crenel's core posture): the agent can **query** what your edge exposes but cannot
mutate anything. Starting the server with **`crenel mcp --write`** adds a **two-phase
gated write** surface (see [Write mode](#write-mode---write--two-phase-gated)).

The read-only mode is the agent-facing analog of `crenel serve` (the read-only web
dashboard): where `serve` renders live status as a web HUD, `mcp` answers read-only
tool calls for an LLM agent. It is **read-only by construction** — the server is
given the engine only through a narrow interface that exposes the read paths and no
write capability, so a mutating call is not merely refused at runtime, it is
*unrepresentable*.

> **Teaching an agent to drive it:** [`docs/mcp/SKILL.md`](mcp/SKILL.md) is a drop-in
> skill that teaches an agent the verbs + the safety contract; [`docs/mcp/mcp.json`](mcp/mcp.json)
> is a ready `mcpServers` snippet.

## Why it's safe to hand to an autonomous agent

- **No mutating tool exists.** The catalog advertises exactly three tools
  (`crenel_status`, `crenel_audit`, `crenel_drift`). `tools/call` dispatches off
  that same catalog, so a mutating name (`crenel_expose`, `expose`, `apply`, …)
  does not resolve — it returns a JSON-RPC `-32602 unknown tool` error. No mutation
  code path is ever consulted.
- **Read-only by construction (compiler-enforced).** The server holds the engine
  only as the narrow `core.ReadOnlyEngine` interface (`Status` / `Audit` /
  `DetectDrift`, `internal/core/readonly.go`). Every
  mutating `Engine` method is out of scope — calling one would not compile.
- **Secrets are redacted.** Any secret bytes carried in not-understood config
  excerpts (`status`) are masked in the output, so a stray auth hash or token is
  never handed to the agent. (There is no `--show-secrets` on this server.)
- **Live-only, no stored desired state.** Every tool reads live edge/DNS state at
  call time; nothing is cached or written.

## Tools

| Tool            | What it returns                                                                                                  | Arguments                          |
| --------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `crenel_status` | Per-edge live routes (host → backend, mode, forward-auth, chain follow-through), ternary default-deny posture, coverage, durability, ingress, managed DNS | `edge` *(optional)* — one edge by name |
| `crenel_audit`  | Live invariant + consistency findings: public-without-auth, fail-open (missing default-deny), unknown constructs, chain notes. Each has severity / code / message | *(none)*                           |
| `crenel_drift`  | Divergence from the canonical exposed set (missing routes, mode mismatches, stale DNS) + the corrective change that *would* converge (applies nothing) | `edge` *(optional)* — filter to one target |

Each tool returns a `CallToolResult` with both a human-readable `content` text
block (pretty-printed JSON) and a typed `structuredContent` object.

## Write mode (`--write`) — two-phase gated

`crenel mcp --write` keeps all three read tools and **adds two write tools**. Writes
are **off by default** and enabled only by this explicit flag. There is still no
blind write: every mutation is a **two-phase commit** an agent cannot short-circuit.

| Tool           | Phase | What it does                                                                                 |
| -------------- | ----- | -------------------------------------------------------------------------------------------- |
| `crenel_plan`  | 1     | Compute (do **not** apply) the exact change for a write verb against live state; return the diff + a content-hash **`plan_id`**, plus `goes_public` / `auth_required`. Mutates nothing. |
| `crenel_apply` | 2     | Apply a change **only** if `confirm_plan_id` re-derives to the same id against *current* live state. Then runs crenel's full preview→apply→read-back-verify (rolled back on any failure). |

Both take the same argument shape, keyed on `verb`:

- `verb: "expose"` — `service` (required), optional `to` (backend `host:port`),
  `auth` (policy name or `"none"`), `mode` (`http`/`passthrough`/`mesh`), `scope`
  (`internal`/`public`/`both`), `dns` (granular scope), `edges` (array of edge names).
- `verb: "unexpose"` — `service` (+ optional `scope`/`dns`/`edges`).
- `verb: "set"` — `service` + `state` (`on`/`off`) (+ optional `scope`/`dns`/`edges`).
- `verb: "rename"` — `old_host` + `new_host`.
- `crenel_apply` additionally requires **`confirm_plan_id`**.

### The gate, and why it holds

- **No blind write.** `crenel_apply` refuses unless `confirm_plan_id` equals the id
  `crenel_plan` returned — so the agent must have previewed the exact change.
- **TOCTOU-safe, stateless.** The `plan_id` is a hash of the *computed diff*, not a
  server-side token. If live state changed since the preview, the recomputed id
  differs and apply is refused — "someone changed the world, re-preview." No state
  is kept between calls (a fresh server re-derives the same id).
- **crenel's own gates are never bypassed.** Exposing a host **public with no auth**
  is refused unless `auth` is set (a policy, or `"none"` to publish unprotected on
  purpose) — `crenel_plan` flags this up front as `auth_required: true`. Every apply
  is **read-back-verified** and rolled back on failure; an unconfirmable file-driver
  write (no runtime probe) is surfaced as an error, never a silent green. Default-deny
  and the ownership gate apply exactly as on the CLI.
- **Composes with the engine-level read-only posture.** An engine constructed
  read-only (`read_only: true` in settings, or an audit-target invocation)
  refuses `crenel_apply` at the *engine* layer (`core.ErrReadOnlyEngine`),
  before any driver plan/apply — even if the server was started with `--write`.
  `crenel_plan` stays available there: planning is a pure read, exactly like
  CLI preview.

Because writes are gated, an agent should be granted the write tools behind your
client's normal tool-approval flow. `crenel_plan` is always safe to auto-approve
(it only reads); reserve approval for `crenel_apply`.

## Transport

Standard MCP **stdio** transport: the agent launches `crenel mcp` as a subprocess
and exchanges newline-delimited JSON-RPC 2.0 frames over its stdin/stdout. The
server writes only diagnostics to **stderr** (a one-line startup notice), so the
stdout frame stream is never corrupted.

The server reads the **same crenel config as the CLI** — point it at whichever edge
you want it to read (via `--config`, `-admin-url`/`-zone`, or `CRENEL_*` env vars).
It runs wherever crenel can reach that edge. **No credentials are baked in.**

## Wiring it into an agent

The exact command to register is `crenel mcp` plus whatever flags select the edge
to read. For example, against a settings file:

```
crenel --config /etc/crenel/crenel.settings.yaml mcp
```

### Claude Code / generic `mcpServers` JSON

```json
{
  "mcpServers": {
    "crenel": {
      "command": "crenel",
      "args": ["--config", "/etc/crenel/crenel.settings.yaml", "mcp"]
    }
  }
}
```

Or drive the edge entirely from env / flags (no settings file):

```json
{
  "mcpServers": {
    "crenel": {
      "command": "crenel",
      "args": ["-admin-url", "http://127.0.0.1:2019", "-zone", "example.com", "mcp"],
      "env": { "CRENEL_ADMIN_URL": "http://127.0.0.1:2019" }
    }
  }
}
```

Once registered, the agent will see the three `crenel_*` tools after the
`initialize` → `tools/list` handshake. Because the read-only server is read-only by
construction, you can grant the agent the tools without an approval gate — there is
no action it can take that changes the edge.

### Enabling gated writes

Add `--write` to the args to turn on `crenel_plan` + `crenel_apply` (five tools
total). Keep the two-phase gate meaningful by approving `crenel_apply` through your
client's tool-approval flow:

```json
{
  "mcpServers": {
    "crenel-rw": {
      "command": "crenel",
      "args": ["--config", "/etc/crenel/crenel.settings.yaml", "mcp", "--write"]
    }
  }
}
```

## Protocol surface

JSON-RPC 2.0 methods handled: `initialize`, `notifications/initialized`,
`tools/list`, `tools/call`, `ping`. Unknown methods get `-32601 method not found`;
unknown notifications are silently ignored (no reply). Implemented zero-dependency
in stdlib Go (`encoding/json` + `bufio` + `crypto/sha256` for the plan id) — `go mod
tidy` adds nothing.

## Verifying it yourself

Pipe a handshake straight into the binary (safe demo edge via `--fake-seed`):

```
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"crenel_status","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"crenel_expose","arguments":{"service":"grafana"}}}' \
  | crenel --fake-seed examples/seed-chain-home.json --zone homelab.example mcp
```

`id:3` returns the live status; `id:4` (a mutation attempt) returns
`{"error":{"code":-32602,"message":"unknown tool: crenel_expose"}}` — proof the
server cannot mutate.
