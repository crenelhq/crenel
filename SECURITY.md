# Crenel: security model & threat model

> The doc to read to understand what secrets Crenel touches, where they can leak,
> what Crenel trusts, and how to run it safely. It formalizes the security analysis
> behind the **Transport** axis (DESIGN.md "Transport / Connection") and the
> **secret-redaction** hardening (this pass). Companions: **DESIGN.md** (architecture
> + the two load-bearing invariants), **TOPOLOGY-RISK-REGISTER.md** (the long-tail
> *correctness* safety net, a different axis from *secrecy*), **DEPLOY-VPS.md** (the
> safe loopback-admin deployment runbook), **AUTH-DESIGN.md** (the auth-by-reference
> posture).
>
> Scope: Crenel is an **on-demand operator CLI**, not a daemon. It has no network
> listener, no stored desired state, and no background process. Its security surface
> is therefore "what an operator's invocation can read, write, print, and persist,"
> not "what an exposed service can be attacked through."

---

## 0. TL;DR for the operator

1. **Keep every edge admin API loopback-bound.** Caddy's admin API (`:2019`) is
   **plaintext and unauthenticated** by design. Never publish it, never rebind it to a
   routable interface, never tunnel it as a listener. For a remote edge use the
   `ssh-exec` or `ssh-tunnel` **transport** so the config travels inside SSH.
2. **The live config contains real secrets:** Cloudflare DNS-01 tokens, ACME account
   keys, basic-auth hashes, forward-auth shared secrets. Treat any dump of it (backup,
   export, `--show-secrets` output) as a credential file.
3. **Crenel redacts secrets in everything it prints by default** (status/audit JSON,
   error messages, declared-unknown excerpts). `--show-secrets` turns that off; only
   use it when you deliberately want raw values on a trusted terminal.
4. **`export`/backup files are written `0600` and contain REAL secrets** (they have to,
   to be restorable). Keep them off shared storage and out of git. Use
   `export --redacted` for a copy that is safe to paste into an issue.
5. **Use SSH key auth and verify `known_hosts`.** Crenel's remote-edge security reduces
   to your SSH setup; a MITM on a TOFU-accepted host key sees the config in clear.

---

## 1. Sensitive-data inventory: what secrets exist and where

Crenel itself stores no secrets. But it *reads and writes the full edge config*, and a
real reverse-proxy edge config is full of them. Two buckets: secrets **inside a managed
edge config** (Crenel reads/writes them, so they pass through its process and can reach
its output), and Crenel's **own operational files**.

### 1a. Secrets inside a managed edge config

When Crenel reads an edge (`GET /config/` on Caddy, the file on Traefik/nginx) it pulls
the **entire** config into memory, including fields Crenel does not model. Any of these
can appear:

| Secret | Where it lives | Why Crenel sees it |
|---|---|---|
| **Cloudflare / DNS-01 provider API token** | Caddy `tls.automation` → `dns` provider (`api_token`, `api_key`, `auth_token`, `zone_token`) | Read whole-config; preserved verbatim on granular apply |
| **ACME account key / email** | Caddy `tls.automation.acme` issuer (`email`, account `private_key`) | Same |
| **basic-auth password hashes** | Caddy `basic_auth`/`basicauth` handler accounts (`password` = bcrypt hash, `salt`) | Read whole-config; an unmodeled handler is captured in an `Unparsed` excerpt |
| **forward-auth shared secrets / cookies** | a `forward_auth`/`authentication` handler's headers, an Authelia/Authentik secret embedded in a handler | Same |
| **Any embedded credential** | env interpolation results, upstream auth headers, a `transport` TLS client cert/key path or inline PEM | Same |
| **TLS private key material** | Caddy `tls` PEM blobs / key references; nginx `ssl_certificate_key` paths | Read whole-config (key *bytes* if inlined; usually a path) |

Crenel's parsed model (`internal/drivers/edge/*/types.go`) is deliberately **minimal**:
it models reverse-proxy routes, the catch-all deny, subroutes, and an auth *reference*.
It does **not** model `tls`/`dns`/`basic_auth` blocks. That is good for blast radius (it
never *interprets* a token) but it means those secrets ride along in two raw carriers:

- **`LiveEdgeState.Raw`**: the untouched provider payload (the full `GET /config/`
  bytes), kept for export/debug. **Crenel never surfaces `Raw` in any command today**
  (it is set but not read), so it is an internal-only carrier. It is also the reason a
  future "dump raw config" path would leak everything, and is redacted-on-print if ever
  surfaced.
- **`Unparsed.RawExcerpt`**: a bounded snippet of a construct Crenel could not fully
  model (the P0 detect-and-declare-unknown net). An unmodeled `basic_auth` handler, a
  custom handler carrying an `api_token`, or a sibling server block is captured here so
  the operator can inspect it, which means **the excerpt can contain secret bytes** and
  is shown in `status --json` / `audit`.

### 1b. Crenel's own operational files

| File | Contains | Protection |
|---|---|---|
| **Git-remote push credential** | the maintainer's credential for `origin` | Read fresh from an out-of-repo file via a `GIT_ASKPASS` helper at push time; **never** embedded in the remote URL, `.git/config`, process args, or scrollback |
| **Operator backup files** (`live-backup/`, DEPLOY-VPS.md snapshots) | the **real** full edge config = every secret in 1a | `.gitignore`d; written `0600` by `export`; manual `curl` backups inherit the operator's umask, so **set `0600` yourself** |
| **`export <file>` output** | live state snapshot (REAL values by default) | Written `0600`; `--redacted` writes a secret-free copy |
| **Settings file** (`-config`) | provider/topology config: `admin_url`, SSH targets, `ssh_identity` path, origins, **auth-policy *references*** | Not secret by itself (references + addresses), but names your infra; the `ssh_identity` is a path, not a key. Keep it private as config hygiene |
| **Caddy persist file** (`caddy_persist_path`) | managed routes mirrored as a Caddyfile; auth as `import <snippet>` **references**, not snippet bodies | Crenel emits references only; it never writes the operator's auth secret into the persisted Caddyfile |

---

## 2. Trust boundaries & the transport security model

The single most important security property is **where the plaintext, unauthenticated
admin API is reachable from.**

### 2a. The admin API is plaintext + unauthenticated → it MUST stay loopback

Caddy's admin API (`127.0.0.1:2019`) has **no TLS and no auth**. Anyone who can open a
TCP connection to it can read the entire config (every secret in §1a) and rewrite the
edge (open any host, strip any auth, install a permissive catch-all). Therefore:

- **The admin API must never be network-exposed.** Binding it to `0.0.0.0`, publishing
  the container port, or running a long-lived `ssh -L` that leaves it listening on a
  routable interface are all **anti-patterns**: they convert a loopback-only,
  credential-bearing control plane into an unauthenticated network service. Crenel is
  built to make this unnecessary.

### 2b. The transport seam keeps the sensitive config inside SSH

Crenel reaches an admin API through a pluggable **Transport** (DESIGN.md). The three
implementations map directly onto a trust model:

| Transport | Where the admin call travels | When it is safe |
|---|---|---|
| **`direct`** | plaintext HTTP to `admin_url` | **Loopback only**: run Crenel *on* the edge host, hitting `127.0.0.1:2019`. Safe because the plaintext never leaves the box. (DEPLOY-VPS.md is exactly this.) |
| **`ssh-exec`** | the admin call runs as a command on the far end (`ssh → … → curl 127.0.0.1:2019`); request/response travel inside the **SSH-encrypted channel** | Remote edge, **admin stays loopback-only and unpublished**. The home edge's container-localhost admin is reached with **zero port exposure and no tunnel**. The preferred remote transport. |
| **`ssh-tunnel`** | Crenel opens an **ephemeral, crenel-managed** `ssh -N -L` and talks `direct` over it; closed on teardown | Remote edge; the forward binds `127.0.0.1:<local>` on the *operator's* box for the life of one invocation only; no `ssh -fN` left running |

The guarantee: **for a remote edge, the sensitive config never crosses the network in
clear.** It is either local-loopback (`direct` on-box) or inside SSH (`ssh-exec`/
`ssh-tunnel`). The admin API itself is never the thing exposed to the network.

### 2c. Boundary diagram (who can observe/modify what)

```
  operator's terminal ──┐
   (Crenel process)     │  [B1] local host: anyone with the operator's UID can read
   - prints redacted    │       Crenel's memory/args, the settings file, backups,
     output by default  │       and ~/.config/forgejo-mcp/token. SECRETS at rest here.
                        │
        ssh-exec /      ▼
        ssh-tunnel  [B2] SSH channel: encrypted. Observer needs the SSH key OR a
        ──────────▶      MITM on an unverified host key. known_hosts is the guard.
                        │
                        ▼
   edge host ────────[B3] loopback admin API: PLAINTEXT + UNAUTHENTICATED. Anyone who
   - 127.0.0.1:2019      can reach 127.0.0.1:2019 on THIS box (any local process, any
   - full config +       container with host-net, any accidental port publish) owns
     all secrets         the edge. Keep it loopback. This is the boundary to defend.
                        │
        git push (GIT_ASKPASS, token never in URL)
                        ▼
   git remote ─────[B4] private git host: code + docs only. NO live config,
                        NO backups (gitignored), NO token. A repo compromise leaks
                        source, not secrets, provided the gitignore discipline holds.
```

---

## 3. What Crenel persists vs. does not

- **Does NOT persist:** desired state / source-of-truth (the live edge is the only
  truth; DESIGN.md invariant 1), secrets of any kind, the push token (read fresh per
  push), credentials in process args or `.git/config`.
- **Persists only on explicit operator action:** `export <file>` (a throwaway snapshot,
  `0600`), `caddy_persist_path` (managed routes + auth *references*, no secret bodies),
  `init` scaffold files (templates, no secrets).
- **Holds transiently in memory for one invocation:** the full edge config (incl.
  secrets) while planning/applying; the Op (the only "desired state," discarded at exit).

Because there is no daemon and no stored SOT, there is **no long-lived secret store to
compromise**. The residual at-rest exposure is exactly the operator-written backup/
export files (§1b) and whatever the OS keeps of a transient process.

---

## 4. Threat model: adversary by boundary

| # | Boundary | Adversary | Can observe | Can modify | Mitigation |
|---|---|---|---|---|---|
| **B1** | Local host (operator's box / edge box) | Another local user, a co-tenant container with host networking, malware at operator UID | Crenel's memory + args, settings file, **backups/exports (real secrets)**, the push token, anything on `127.0.0.1:2019` of *that* box | Rewrite the edge via the loopback admin | OS user isolation; `0600` on backups/exports/token; don't run the edge admin on a shared/multi-tenant host without loopback discipline |
| **B2** | SSH channel (remote edge) | Network MITM, a compromised intermediate hop | Nothing if the host key is verified; **everything** if a forged host key is TOFU-accepted | Inject admin calls if it fully controls the channel | **SSH key auth + verified `known_hosts`** (pin the host key out-of-band); avoid blind first-connect over hostile networks |
| **B3** | Loopback admin API | Any process/container able to reach `127.0.0.1:2019` on the edge box | The entire config + all secrets | The entire edge (open hosts, strip auth, fail-open the deny) | **Keep it loopback + unpublished.** This is the crown-jewel boundary; the whole transport design exists to avoid widening it |
| **B4** | Git remote | Whoever can read the repo | Source + docs | Code (a supply-chain risk to *Crenel*, not to live secrets) | Token via `GIT_ASKPASS` only; `live-backup/`, `*.snap.json`, `live-snapshot.json` gitignored; **never commit a backup/export** |
| **B5** | Crenel's own output (terminal / logs / pasted issue) | Anyone reading the operator's screen, terminal logs, CI output, or a pasted snippet | Secrets **only if** redaction is off | Nothing | **Default redaction** of status/audit JSON, error messages, and declared-unknown excerpts; `export --redacted` for shareable copies; `--show-secrets` is opt-in and documented as sensitive |

---

## 5. Residual risks (honest)

Redaction and the transport model close the *output* and *network* leaks. What remains:

1. **Operator SSH setup is out of Crenel's control.** `ssh-exec`/`ssh-tunnel` security
   reduces to your key management and `known_hosts`. A TOFU-accepted forged host key, an
   agent-forwarded key to a hostile bastion, or a compromised SSH client defeats B2.
   Crenel does not (and cannot) verify your host keys for you.
2. **Backups/exports contain real secrets by necessity.** A redacted backup cannot be
   restored, so the restore-grade backup (DEPLOY-VPS.md) holds real Cloudflare tokens,
   ACME keys, and auth hashes. `0600` + gitignore + "keep off shared storage" is the only
   protection; a stolen backup file is a full edge-secret compromise.
3. **No daemon, but full operator trust at run time.** Crenel acts with the operator's
   privileges and whatever SSH/admin access the settings grant. There is no
   least-privilege sandbox: if the invoking user is compromised, so is the edge. The
   on-demand model *limits the window* (no always-on attack surface) but not the blast
   radius of a compromised operator session.
4. **Redaction is best-effort on bytes Crenel did not model.** The redactor is
   value-aware (key patterns + value heuristics) over arbitrary config bytes, so a
   secret in a field that matches *no* known key pattern *and* no value heuristic (e.g. a
   bare high-entropy string under an innocuous key) could slip into an excerpt. It
   prefers over-masking by design, but it's not a guarantee for unmodeled
   shapes; see §6. The **apply/verify paths never redact**, so this never affects
   correctness, only the secrecy of printed output.
5. **The loopback admin trusts every local process.** On a shared or container-dense
   edge host, "loopback-only" still means "every local UID / host-net container can hit
   it." Crenel cannot add auth to Caddy's admin API; defending B3 fully is the operator's
   host-isolation job.
6. **`--show-secrets` and driver-level error bodies.** With `--show-secrets`, output is
   intentionally raw; anything on the screen is then a credential. Error messages are
   redacted at the print boundary, so a secret already formatted into an error string is
   masked; but a third-party library that logs independently of Crenel's boundary is out
   of scope.

---

## 6. Secret redaction: what is masked, where, and the apply/verify guarantee

Crenel redacts secret-bearing fields in **operator-facing output only**. The internal
apply / read-back-verify / preserve-unmanaged paths **always use the real values**.
Crenel must write the operator's actual auth snippet and verify the edge against the real
config, so redaction is a *presentation* transform applied at the output boundary, never
to the data Crenel acts on.

**What is detected** (`internal/redact`, value-aware: key pattern AND value heuristic):

- **Key patterns** (case-insensitive substring on the JSON key / config directive):
  `token`, `secret`, `password`/`passwd`, `api_key`/`apikey`/`api_token`,
  `client_secret`, `private_key`, `access_key`, `auth_key`, `signing_key`,
  `credential`, `passphrase`, `email` (ACME). Covers the Caddy DNS-provider
  `api_token`/`api_key`, ACME `email`, and `basic_auth` `password` hashes.
- **Value heuristics** (redact regardless of key, to catch secrets in unexpected
  fields): PEM private-key blocks (`-----BEGIN … PRIVATE KEY-----`), bcrypt/argon/apr1
  hashes (`$2a$`/`$2b$`/`$2y$`/`$argon2`/`$apr1$`), and JWT-shaped triples.

**How it masks:** a long value becomes `••••<last4>` (a short, non-sensitive suffix to
keep the field recognizable); a short value becomes `REDACTED`. Structure, keys, and
non-secret values are preserved so the output stays diagnostic.

**Where it is applied** (all default-on; `--show-secrets` reveals):

- `status --json` / `audit`: the `Unparsed.RawExcerpt` declared-unknown excerpts (the
  P0 net can capture secret bytes from an unmodeled handler/server block).
- Any verbose/raw-config dump path and `LiveEdgeState.Raw` if surfaced.
- **Error messages** that echo admin-API response bytes (a Caddy `/load` rejection
  echoes the offending config), redacted at the CLI print boundary.
- `export --redacted <file>`: a secret-free snapshot for sharing.

**The explicit guarantee:** a managed `expose`/`unexpose`/`reconcile` round-trips with
**secrets intact in the real write path**: the driver renders real config, applies it,
and read-back-verifies against the real live config. Redaction touches only what is
printed/exported, gated by `--show-secrets`, and the default-redacted-print path and the
real-apply path are exercised independently by tests.

**Backups:** `export` and operator backups are written `0600` and hold **real** values
(redacting a restore-grade backup would make it useless for recovery; DEPLOY-VPS.md
restore depends on byte-exact real config). Use `export --redacted` only for the
shareable form. Manual `curl` backups (DEPLOY-VPS.md) inherit your umask, so
`chmod 0600` them.

---

## 7. Operator guidance (the checklist)

1. **Admin API stays loopback + unpublished.** Never bind it to a routable interface or
   publish the container port. If you see `admin 0.0.0.0:2019`, fix it.
2. **Remote edge → `ssh-exec` (preferred) or `ssh-tunnel`.** Run `direct` only on-box
   against `127.0.0.1`. The config then never crosses the network in clear.
3. **SSH key auth + verified `known_hosts`.** Pin the host key out-of-band; do not
   blind-accept on first connect over an untrusted network. Prefer a dedicated key; avoid
   agent-forwarding to untrusted hops.
4. **Lock down secret files.** `chmod 0600` every backup/export and the push token;
   keep `live-backup/` gitignored; never paste a non-`--redacted` export into an issue,
   chat, or CI log.
5. **Leave redaction on.** Default output is safe to share-ish (but treat it as
   sensitive anyway). Use `--show-secrets` only on a trusted terminal when you genuinely
   need raw values; `export --redacted` for anything you'll hand to someone else.
6. **Push via `GIT_ASKPASS` only.** The push credential is read fresh from disk per push
   and never lands in the URL/args/`.git/config`.
7. **Backups are credentials.** A restore-grade backup is a full set of edge secrets.
   Store it like one.

---

## 8. Reporting a vulnerability (responsible disclosure)

Crenel's core promise is that it is **never silently wrong** about exposure. A way to
make it silently wrong (e.g. reporting default-deny **ENFORCED** while a host is
actually reachable, bypassing the `managed-by:crenel` ownership boundary, leaking a
secret past the redaction layer, or escaping the read-only guarantee of
`status`/`audit`/`drift`/`mcp`) is a security vulnerability here, even though Crenel
itself has no network listener.

- **Do not open a public issue for a vulnerability.**
- Email **`security@crenel.sh`** with: the affected claim (ideally one from
  [`docs/security/CLAIMS-TO-VERIFY.md`](docs/security/CLAIMS-TO-VERIFY.md)), a minimal
  repro (a failing `go test` is ideal), and the impact in the project's own severity
  vocabulary (**MISREAD**: Crenel reports something false / **MISMANAGE**: a change
  applies or reverts silently).
- You'll get an acknowledgment within **72 hours** and a fix-or-status answer within
  **14 days**. Coordinated disclosure preferred; credit given unless you'd rather not.
- Already-documented limits (see [`docs/security/KNOWN-LIMITS.md`](docs/security/KNOWN-LIMITS.md))
  are not new vulnerabilities. Unless, that is, you found a way around a stated
  mitigation, which absolutely is.
