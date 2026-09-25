# ProofOps Security Foundation (M00.6 foundation; full coverage owned by later modules)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §37 (threat model), §38 (invariants),
§18 (policy engine), §27 (HITL), §32 (audit).

Status: foundation plus the M21 identity guard. This doc records what is
implemented and tested today, states plainly what is **not** enforced, and
marks the rest PLANNED with its owning module. Nothing here claims production
readiness or certification.

## Implemented today (M00.1–M00.5, tested)

- Image/runtime hardening (M00.1): non-root `appuser`, `cap_drop: ALL`,
  `no-new-privileges`, no `privileged`, no host networking, no host binds;
  pinned bases, no `:latest`. Tests: `tests/test_repo_structure.py`,
  `tests/test_compose.py`.
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
each stored digest with `hmac.compare_digest`
(`backend/app/routers/auth.py:198-203`); a miss is 403. The store is
gitignored (only `var/api_keys.json.example` is tracked) and lives on the
`api_state` volume, so a lost volume loses every key.

**Fail-closed on tamper, fallback on absence.** A *present but corrupt* store
(bad JSON, bad entry shape, duplicate `key_id` or digest) raises and becomes
HTTP 500 — a tampered store can never silently downgrade the deployment to the
shared key (`load_key_store` at `backend/app/routers/auth.py:136-171`, mapping
at `:300-302`). An *absent or unreadable* store falls back to the
pre-Lane-1 single-key behavior against the configured `PROOFOPS_API_KEY`.

**Two identity modes, and the honest label for each.**

| `mode` | What it means | What it does not mean |
|---|---|---|
| `per_key` | A key store resolved the caller; `roles` are server-owned; `require_role` enforces them. `GET /identity` returns `server_enforced: true`. | — |
| `bootstrap` | Shared single-key demo fallback. Identity is the literal `{key_id: "bootstrap", owner: "bootstrap", roles: []}`, and `require_role` **permits it by default** (`bootstrap_permits` is unset in the shipped path, `backend/app/routers/auth.py:238-241`). | There is **no per-user identity**: no per-user password, no distinct principal, and no server-side roles. One shared credential passes every role gate. |

`check_key_role()` compares a **client-asserted** role string and is
explicitly *not* an authorization boundary — a caller who controls the string
can pick any role it holds (`backend/app/routers/auth.py:252-265`). The
production gate is `require_role()`, whose allowed set is server code
(`backend/app/routers/auth.py:220-249`); in `per_key` mode an empty role list
is DENIED, never a wildcard.

Because of that, **every product surface that shows identity must also show
`mode`**: reporting `bootstrap` as an authenticated user would be a false
claim. `GET /identity` returns `mode` and `server_enforced` for exactly this
reason (`identity_view`, `backend/app/routers/auth.py:308-320`), and
`GET /approvals/{id}` returns `identity_mode` + `sod`.

**Not implemented — stated plainly.**

- **No SSO/OIDC.** There is no federated identity in front of the key gate.
  Owning module: unassigned, PLANNED.
- **No per-user passwords**, no per-user sessions, no logout.
- **No key expiry, no rotation, no remote revocation list.** The store is a
  local JSON file; rotation means replacing the file by hand, and a leaked key
  stays valid until it is removed. Owning module: unassigned, PLANNED.
- **No rate limiting, lockout, or per-key throttling** on any route. A wrong
  key is answered 403 with no backoff and no counter that blocks anything.
  Owning module: unassigned, PLANNED.
- No CSRF protection, no TLS termination, and no IP allowlist exist in this
  tree; an operator must supply those network-level controls outside the API
  (PLANNED, unassigned).

**Audit principal.** The immutable `key_id` is the audit principal, never the
mutable `owner` name, so renaming a user cannot retroactively change who the
chain claims acted (`principal`, `backend/app/routers/auth.py:206-217`). For
the external append route the recorded actor is likewise server-derived and a
client-claimed name is kept only as a label
(`backend/app/routers/audit.py:126-143`).

## Separation of duties (approvals)

- **Per-key approve path.** The HMAC token subject is the *request* actor, so
  the real four-eyes comparison is the two server-resolved key ids:
  `approver_key_id` vs the stored `requester_key_id`. Self-approval is denied
  outright with **no override**, because a second human identity is the whole
  point (`backend/app/routers/approvals.py:406-419`). If either key id is
  missing, the decision is denied rather than defaulted
  (`:407-411`).
- **Label honesty.** `approval_view.sod` is `"enforced"` only in `per_key` mode
  with a differing approver, `"not_enforced_bootstrap"` in bootstrap mode, and
  `"not_recorded"` otherwise (`backend/app/routers/approvals.py:330-333`).
- **Reject deliberately does NOT apply separation of duties.** Four-eyes
  control protects against *granting* execution authority; a denial can only
  withhold it, and forcing a second identity would also stop the requester from
  withdrawing their own request. Authorization still applies to reject — an
  authenticated key holding `approver`/`admin` is required
  (`backend/app/routers/approvals.py:474-486,743-751`).
- **Where SoD is not exercised.** The in-process pipeline requests and then
  approves with the same scripted actor
  (`APPROVER = {"role": "approver", "id": "sre-1"}` in
  `backend/app/services/pipeline.py:53`, used by `_hitl_permit` at `:466-486`).
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
