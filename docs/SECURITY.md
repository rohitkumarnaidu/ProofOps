# ProofOps Security Foundation (M00.6 foundation; full coverage owned by later modules)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §37 (threat model), §38 (invariants),
§18 (policy engine), §27 (HITL), §32 (audit).

Status: foundation plus the M21 identity guard. This doc records what is
implemented and tested today, states plainly what is **not** enforced, and
marks the rest PLANNED with its owning module. Nothing here claims production
readiness or certification.

## Implemented today (M00.1–M00.5, tested)

- Image/runtime hardening (M00.1): non-root `appuser`, `cap_drop: ALL`,
  `no-new-privileges`, no `privileged`, pinned base images, no `:latest` on any
  compose service. Tests: `tests/test_repo_structure.py`, `tests/test_compose.py`.
- **Container networking and host binds are not the clean story this doc used to
  claim.** An earlier revision said "no host networking, no host binds". Both are
  now false, and the correction matters more than the original claim:
  - There is exactly **one** host bind, `./var/live:/live:ro`
    (`docker-compose.yml:76`), and it is asserted read-only by
    `tests/test_compose.py`.
  - The `api` container joins the external `kind` Docker network
    (`docker-compose.yml:84`) so it can reach a live API server at an
    in-network address. That network is `internal: false`, so the container has
    outbound egress on it.
  - `cap_drop: ALL` and `no-new-privileges: true` are on the **`api` service
    only** (`docker-compose.yml:94-97`). `db` and `ui` have neither.
- Secret handling (M00.2): `.env` never committed (gitignored plus a
  tracked-file test); the template ships empty secrets with placeholder
  template values; required keys fail closed; `POSTGRES_PASSWORD` uses the
  compose `:?` hard-require form; `snapshot()`/`repr`/error text are redacted;
  `DATABASE_URL` is never snapshotted. Tests: `tests/test_config.py`.
- Health bodies (M00.4): `/healthz` and `/readyz` carry no DSN, no passwords,
  no approval secrets; driver errors are replaced with static text
  (`database unreachable` / `database query failed`). Tests:
  `tests/test_health.py` (plus live `tests/test_health_runtime.py`).
- Log redaction (M00.5): format-then-scrub of message, args, and tracebacks
  covering registered secret values plus generic URI-credential,
  password-assignment, bearer-token, API-key, and private-key-block patterns.
  Boundary: uvicorn boot lines keep the stock formatter (secret-free by nature,
  asserted hygienic live). Tests: `tests/test_logging.py` (plus live runtime).
- Safe vs unsafe commands: SAFE is `docker compose config --quiet`,
  `config --services`, `ps`, `logs`. UNSAFE is plain `docker compose config`
  (renders secret values) and `down -v` (destroys `pgdata`).
- Dependency posture (M00.7, live): `backend/requirements.lock` (34 exact
  cp312/manylinux pins) + `scripts/freeze.py --check` gate + `pip-audit`
  gate with per-ID written exceptions (`scripts/pip_audit_allowlist.txt`:
  7 starlette IDs with no in-bounds fix and no file-upload / static-serving /
  form-parsing surface in this API, 1 local-only pytest ID). Anything unlisted
  FAILS. Repro: `python scripts/freeze.py --audit` (needs `pip-audit`; fails
  closed without it).

## Identity and authorization (M21b, implemented — demo-grade, not production identity)

All of this lives in `backend/app/routers/auth.py`. The gate is a shared
secret comparison; there is no user account concept behind it.

**Key store.** `var/api_keys.json` — a JSON list of
`{key_id, key_sha256, owner, roles[]}`. Only SHA256 hex digests are persisted;
raw keys never touch disk. The presented key is hashed and compared against
each stored digest with `hmac.compare_digest` (`resolve_identity`,
`backend/app/routers/auth.py:194-226`); a miss is 403. The store is
gitignored (only `var/api_keys.json.example` is tracked) and lives on the
`api_state` volume, so a lost volume loses every key.

**Fail-closed on tamper, fallback on absence.** A *present but corrupt* store
(bad JSON, bad entry shape, duplicate `key_id` or digest) raises and becomes
HTTP 500 — a tampered store can never silently downgrade the deployment to the
shared key (`load_key_store`, `backend/app/routers/auth.py:145`, mapping at
`:300-302`). An *absent or unreadable* store falls back to the pre-Lane-1
single-key behavior against the configured `PROOFOPS_API_KEY`.

**Two identity modes, and the honest label for each.**

| `mode` | What it means | What it does not mean |
|---|---|---|
| `per_key` | A key store resolved the caller; `roles` are server-owned; `require_role` enforces them. `GET /identity` returns `server_enforced: true`. | — |
| `bootstrap` | Shared single-key demo fallback. Identity is the literal `{key_id: "bootstrap", owner: "bootstrap", roles: []}`, and `require_role` **permits it by default** (`bootstrap_permits` is unset in the shipped path, `backend/app/routers/auth.py:238-241`). | There is **no per-user identity**: no per-user password, no distinct principal, and no server-side roles. One shared credential passes every role gate. |

`check_key_role()` compares a **client-asserted** role string and is
explicitly *not* an authorization boundary — a caller who controls the string
can pick any role it holds (`backend/app/routers/auth.py:275-296`). The
production gate is `require_role()`, whose allowed set is server code
(`backend/app/routers/auth.py:243-272`); in `per_key` mode an empty role list
is DENIED, never a wildcard.

Because of that, **every product surface that shows identity must also show
`mode`**: reporting `bootstrap` as an authenticated user would be a false
claim. `GET /identity` returns `mode` and `server_enforced` for exactly this
reason (`identity_view`, `backend/app/routers/auth.py:373-385`), and
`GET /approvals/{id}` returns `identity_mode` + `sod`.

### Second credential carrier, only partly wired

`guard_http` also accepts `Authorization: Bearer <jwt>`, an HS256 token signed
with `APPROVAL_SECRET` (`backend/app/routers/auth.py:299-313`). An invalid
bearer yields **403, not 401**.

Only two call sites forward the header, so Bearer works on `POST /token`,
`POST /auth/token`, `POST /runs`, `POST /runs/{id}/advance`, and
`POST /runs/{id}/sweep`, and **not** on `/identity`, `/approvals*`, `/audit*`,
`/alerts/ingest`, `/orchestrator/stop`, or `/eval/smoke`. `GET /identity` in
particular does not accept a Bearer token even though `POST /token` issues one.
Treat this as a partial implementation. Either extend it to the whole surface or
remove it; leaving it half-wired means a reader cannot infer the auth model from
any single route. Owning module: unassigned, PLANNED.

### Routes that accept a key and never check it

`POST /alerts/webhook/{alertmanager,cloudwatch,datadog,pagerduty}` declare an
`X-API-Key` parameter and perform no verification at all. **An unauthenticated
caller can inject alert payloads**, which is a real input-trust gap and not a
theoretical one: the injected bundle reaches the same ingest path that drives
triage. No signature, no allowlist, no network-level filter is present in this
tree. Owning module: unassigned, PLANNED. Until it is closed, do not describe
these routes as authenticated and do not expose them beyond a trusted network.

`POST /agents/investigate` is a different case and is acceptable: it declares
the header and ignores it, but the surface is read-only, can execute nothing,
and returns proposals rather than actions. Its integrity rests on it holding no
mutating path, not on the gate.

**Not implemented — stated plainly.**

- No SSO/OIDC. There is no federated identity in front of the key gate.
  Owning module: unassigned, PLANNED.
- No per-user passwords, no per-user sessions, no logout.
- No key expiry, no rotation, no remote revocation list. The store is a
  local JSON file; rotation means replacing the file by hand, and a leaked key
  stays valid until it is removed. Owning module: unassigned, PLANNED.
- No rate limiting, lockout, or per-key throttling on any route. A wrong
  key is answered 403 with no backoff and no counter that blocks anything.
  Owning module: unassigned, PLANNED.
- No signature, allowlist, or network filter on the four webhook ingest routes.
  Owning module: unassigned, PLANNED.
- The Bearer/JWT carrier is wired to two routers, not the surface. See above.
  Owning module: unassigned, PLANNED.
- `cap_drop: ALL` and `no-new-privileges: true` apply to `api` only. `db` and
  `ui` run with Docker's defaults. Owning module: unassigned, PLANNED.
- No CSRF protection, no TLS termination, and no IP allowlist exist in this
  tree; an operator must supply those network-level controls outside the API
  (PLANNED, unassigned).

**Audit principal.** The immutable `key_id` is the audit principal, never the
mutable `owner` name, so renaming a user cannot retroactively change who the
chain claims acted (`principal`, `backend/app/routers/auth.py:229`). For the
external append route the recorded actor is likewise server-derived and a
client-claimed name is kept only as a label
(`_emit_actor`, `backend/app/routers/audit.py:149-166`).

## Live-tier credential handling (read-only mount is load-bearing)

The optional live tier writes a Kubernetes ServiceAccount token to
`var/live/` and mounts that directory at `/live:ro`. Three independent reasons
make the read-only flag load-bearing rather than cosmetic:

1. **Self-escalation.** `var/live/token` is a bearer token whose Role grants
   `patch` on deployments in one namespace. If the API container could write to
   its own credentials, any code-execution or arbitrary-write bug in the API
   process could mint itself a stronger identity, and the RBAC boundary in
   `scripts/live_tier.sh` would become advisory. `tests/test_compose.py` asserts
   the `:ro` flag specifically.
2. **Blast-radius containment.** This is the only host bind in the compose file.
   It hands the container a channel to the host filesystem that nothing else in
   the stack has, so the exception is scoped to exactly one path.
3. **A second, independent boundary.** The namespaced Role plus a `/metrics`-only
   ClusterRole mean Kubernetes itself refuses namespace deletion, secret reads,
   and Role mutation. This is deliberately *not* the same boundary as the policy
   engine, which is our own code reasoning about our own inputs and is therefore
   necessary but not sufficient.

Two honest limits on that protection:

- Read-only is enforced by the **mount flag only**. On a Windows host bind the
  files present as world-writable, because POSIX modes are not meaningful on
  Docker Desktop. The protection is `RW=false` in the bind, nothing else.
- `scripts/live_tier.sh down` removes the cluster but leaves `var/live/token` on
  the host. It is gitignored, so nothing is committed, but the credential stays
  readable until the cluster dies or the token's lifetime elapses. Clear
  `var/live/` by hand if that matters to you.

**Scoping is verified, not assumed.** `scripts/live_tier.sh status` reports what
the agent identity can actually do using `kubectl auth can-i`, and prints
`UNMEASURED` rather than a passing number when there are not yet enough metric
series to evaluate. The Role grants `get,list,watch,patch,update` on
deployments, read on pods, services and configmaps, and `create,patch` on
events. It grants **no delete verb and no access to secrets**, so a destructive
action is refused by Kubernetes itself even if our own policy were bypassed.

## Separation of duties (approvals)

- **Per-key approve path.** The HMAC token subject is the *request* actor, so
  the real four-eyes comparison is the two server-resolved key ids:
  `approver_key_id` vs the stored `requester_key_id`. Self-approval is denied
  outright with **no override**, because a second human identity is the whole
  point (`backend/app/routers/approvals.py:517-561`). If either key id is
  missing, the decision is denied rather than defaulted.
- **Label honesty.** `approval_view.sod` is `"enforced"` only in `per_key` mode
  with a differing approver, `"not_enforced_bootstrap"` in bootstrap mode, and
  `"not_recorded"` otherwise (`backend/app/routers/approvals.py:471-475`).
- **Reject deliberately does NOT apply separation of duties.** Four-eyes
  control protects against *granting* execution authority; a denial can only
  withhold it, and forcing a second identity would also stop the requester from
  withdrawing their own request. Authorization still applies to reject — an
  authenticated key holding `approver`/`admin` is required
  (`http_reject`, `backend/app/routers/approvals.py:1028`).
- **Where SoD is not exercised.** The in-process pipeline requests and then
  approves with the same scripted actor
  (`APPROVER = {"role": "approver", "id": "sre-1"}` in
  `backend/app/services/pipeline.py:59`, used by `_hitl_permit` at `:883`).
  The HMAC mechanics — signature, scope, actor and exact-params binding, nonce
  burn, TTL, permit freshness — are real and exercised on that path, but the
  human decision is scripted and the two-principal SoD branch is not covered by
  that run. SoD evidence comes from the router tests, not from a baseline run.

## PLANNED + LANDED (registry governs — per-row truth in docs/MODULE_REGISTRY.md; PLANNED marks only what is still unbuilt)

- Policy engine ALLOW/ESCALATE/DENY plus default deny (M06 HUMAN_APPROVED);
  action validator rejecting shell/DROP shapes pre-policy (M06.1 HUMAN_APPROVED).
- HMAC HITL: single-use nonce, TTL, scope/actor binding, replay deny (M07
  IMPLEMENTED_TESTED, hardening pending). Today's approval settings are the
  trust-boundary inputs only.
- Sandbox isolation: unprivileged, no secret mounts, network-isolated, with a
  zero-diff block guarantee (M08 IMPLEMENTED_TESTED, hardening pending).
- Independent verifier plus one-auto-attempt rollback (M09/M10
  IMPLEMENTED_TESTED, hardening pending); runbook version pin plus hash
  validation (M11 IMPLEMENTED_TESTED, hardening pending).
- Adversarial-14 suite: log injection, prompt-injection-direct, poisoned
  runbook, fake/stale/contradictory telemetry, unsafe command, policy-bypass,
  parameter injection, secret exfiltration, approval replay,
  duplicate-execution, verification-spoofing, runaway loop (M18
  IMPLEMENTED_TESTED, hardening pending; per-row truth in
  docs/MODULE_REGISTRY.md).
- FUTURE, post-hackathon, never claimed: SSO/OIDC and RBAC approvals, SIEM
  export, managed secrets, confidential-compute executors, rate limiting.

## Invariants (spec §38 — direction quoted; per-row enforcement in the registry)

The contract direction, quoted from the spec: unvalidated Action never reaches
the executor; RED never executes; YELLOW needs a valid unused unexpired scoped
token; telemetry is DATA, never instructions; every block emits audit. Code
enforcement has landed (M06 HUMAN_APPROVED, M07–M10 IMPLEMENTED_TESTED per the
docs/MODULE_REGISTRY.md per-row table, hardening pending), each with its own
gate tests. The identity gate does **not** strengthen these invariants: a
`bootstrap` key satisfies every role gate, so role-based authorization is not
currently an authentication boundary in that mode.

## Repro (host-safe)

```bash
python -m pytest tests/test_config.py tests/test_logging.py tests/test_health.py -q
```
