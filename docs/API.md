# ProofOps API (M00.6 foundation; built through M19, owned per module)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §40 (required surface), §38 (invariants),
§27 (HITL), §32 (audit).

Status: implemented through M19, plus the M20 observability routes and the
M21 identity guard. Per-route truth lives in `backend/app/main.py` +
`backend/app/routers/` + tests. Nothing here claims production readiness or
certification.

## Live today (tested)

The route inventory is the union of `backend/app/main.py` and the six routers
in `backend/app/routers/` (`runs`, `audit`, `approvals`, `auth`, `eval`,
`stream`). "Gate" states whether `X-API-Key` is required; the identity model
behind every gate is documented in `docs/SECURITY.md`.

| Method + path | Gate | Owner | Behavior |
|---|---|---|---|
| `GET /healthz` | open | M00.1 (frozen body) | Liveness: `{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}`. Always 200 while the process lives, even with db down. Drives the image + compose HEALTHCHECK. |
| `GET /meta` | open | M19 | Executor disclosure for the UI mode badge: `service`, `spec`, `executor_tier` (`mock`\|`docker`), `mode` (`APP_ENV`), `nonce_store_durable`, `nonce_store_degraded`. Public values only. |
| `GET /readyz` | open | M00.4 | Readiness: 200 `ready` only when every dependency serves, else 503 `not-ready`. Body is secret-free (`database unreachable` / `database query failed`, never a DSN). Bounded 2s probe. |
| `GET /metrics` | open | M20 (Lane 2) | **Prometheus text exposition, not JSON** (`text/plain; version=0.0.4`, hand-rendered, stdlib only). Only the HTTP route/code/latency counters are wired, by the ASGI middleware in `main.py`. The approval / policy / LLM / tool / budget increment functions exist but **no router calls them**, so they render as `0` and their SLO objectives evaluate `ok` with note `no data (counter not yet wired)` — documented, never faked (`backend/app/services/metrics.py:11-17,466-470`). |
| `GET /alerts` | open | M20 (Lane 2) | JSON `{"alerts":[...]}` where each item is a `SloAlert` (`name`, `state`, `metric`, `observed`, `target`, `op`, `window`, `owner`, `severity`, `note`). Read-only evaluation of `policies/slo.yaml` against the registry snapshot. A missing/malformed SLO fails closed with 500 `{"error":"SLO configuration unavailable"}` (no stack trace). **No paging**: a firing alert needs an external webhook — PLANNED, not built. |
| `GET /identity` | `X-API-Key` | M21b | Server-resolved identity, so a client never asserts its own. See "Identity" below. |
| `POST /runs` (201) | key + `RUN_WRITE_ROLES` | M14/M21 | Open a run; 409 on duplicate id. |
| `GET /runs` | open | M14 | Queue summaries: `incident_id`, `state`, `history_len`. |
| `GET /runs/{id}` | open | M14 | `run_view`: `state`, `replans`, `rolled_back`, `permit_pending`, `history`, `handoffs`, `audit_records`, `verification_verdicts`, `rollback`. |
| `POST /runs/{id}/advance` | key + `RUN_WRITE_ROLES` | M14 | Guarded transition: no-skip permit gate, re-plan ≤2, rollback-once. `APPROVED` additionally requires an HMAC-bound approval (`approval_id` + `token` + `actor`) verified against the **stored** M07 request — a raw client permit is refused. Accepts `idempotency_key`; a duplicate returns the cached view with `duplicate: true` (in-process cache only, not persisted). |
| `POST /runs/{id}/sweep` | key + `RUN_WRITE_ROLES` | M14 | TTL sweep; staged approvals escalate on expiry. |
| `POST /approvals` | key + `operator`/`approver`/`admin` | M19 (M07 crypto) | Queue an approval request and mint its HMAC token. Actions are re-validated as contracts + the M06.1 validator. Write-role gated: this route writes the queue, mints a live token, and appends to the exported chain, so a read-only `viewer` key is refused 403. |
| `GET /approvals/{id}` | open | M19 | Status + TTL countdown + identity provenance. See "Approvals" below. |
| `POST /approvals/{id}/approve` | key + `approver`/`admin` | M19 (M07 crypto) | HMAC verify, nonce burn, single-use, per-key separation of duties. |
| `POST /approvals/{id}/reject` | key + `approver`/`admin` | M19 | Deny + reason; separation of duties deliberately not applied (reason below). |
| `GET /incidents/{id}/audit` | open | M15 | Chain view: `origin: "custom-hash-chain"`, `valid`, `checked`, `events`. **CUSTOM hash audit, not AIMS.** |
| `POST /incidents/{id}/audit/verify` | open | M15 | Chain validity verdict. |
| `GET /incidents/{id}/audit/export` | open | M15 | Chain export. |
| `POST /incidents/{id}/audit/events` | key + `operator`/`approver`/`admin` | M15 | External append, write-role gated. The audit actor is the server-derived immutable key id; a supplied `actor` string is kept only as a `key (claimed name)` label so forensics still sees the claim without letting it become the record (`backend/app/routers/audit.py:126-143`). A read-only `viewer` key is refused 403: this route writes the chain that is exported as proof. |
| `POST /eval/smoke` | key + `operator`/`approver`/`admin` + `{"confirm": true}` | M19 (M16 engine) | Mock-harness numbers on demand. `system` is the literal `"mock-deterministic"` and `note` says the run proves the eval machinery, not product quality. Not open compute: a missing key is 401 and `confirm != true` is 400. |
| `GET /stream/incidents/{id}?since=` | open | Lane 3 | **REPLAY-ONLY SSE.** See "Incident stream" below. |

`RUN_WRITE_ROLES` is server code — `("operator", "approver", "admin")`
(`backend/app/routers/runs.py:641`). A client-supplied role string never
appears in that decision.

Repro:

```bash
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
python -m pytest tests/test_health.py tests/test_repo_structure.py -q
```

## Identity (`GET /identity`)

`GET /identity` requires `X-API-Key` (missing → 401, wrong → 403, corrupt key
store → 500) and returns `identity_view`
(`backend/app/routers/auth.py:308-361`):

| Field | Meaning |
|---|---|
| `key_id` | Stable, non-secret principal. This is what the audit chain records; an owner rename never rewrites history. |
| `owner` | Mutable display name registered for the key. |
| `roles` | Server-side roles read from the key store. Never client-asserted. |
| `mode` | `per_key` (a key store resolved this caller) or `bootstrap` (shared single-key demo fallback). |
| `server_enforced` | `true` only in `per_key` mode. |

`bootstrap` is a **shared demo credential with no per-user identity and no
server-side roles**. Every surface that shows identity must show `mode` too;
presenting `bootstrap` as an authenticated user would be a false claim. See
`docs/SECURITY.md` for the full model and for what does not exist yet (no
SSO/OIDC, no key expiry or revocation, no rate limiting).

## Approvals (request / approve / reject)

Both request bodies are `extra: forbid`. Request:
`action` (required object), `actor` (optional, default `""`, ≤128),
`ttl_seconds` (optional, default 600, 1–900). Decide: `actor`, `token`,
`role`, `reason`, `idempotency_key` — all optional.

**`actor` and `role` are NOT authorization inputs.**

- `actor`: a blank body actor is filled from the authenticated key's
  registered `owner` (`_actor_for`). A non-blank claim must equal that owner
  in `per_key` mode, otherwise 403 (`_actor_for` / `_assert_owner`,
  `backend/app/routers/approvals.py:663-699`). In `bootstrap` mode a non-blank
  actor is accepted as a display label only, and the response reports
  `identity_mode: "bootstrap"` precisely because that label is not an
  authenticated identity.
- `role`: the gate is `require_role(identity, "approver", "admin")` over the
  **key's server-side roles** (`http_approve` / `http_reject`,
  `backend/app/routers/approvals.py:730-751`). The body `role` is a legacy
  secondary check that only fires when non-blank
  (`backend/app/routers/approvals.py:402-404,492-493`), so a body claiming
  `role: "admin"` grants nothing.

`GET /approvals/{id}` returns `approval_view`
(`backend/app/routers/approvals.py:312-344`): `approval_id`, `incident_id`,
`action_id`, `actor`, `scope`, `params_hash`, `status`, `expires_at`,
`seconds_remaining`, plus the identity provenance `identity_mode`,
`requester_key_id`, `decided_by`, and `sod`. `sod` is `"enforced"` only in
`per_key` mode when the deciding key differs from the requesting key;
`"not_enforced_bootstrap"` in bootstrap mode; `"not_recorded"` when the mode
is recorded but the approver or requester key id is absent. The frontend
`ApprovalView` type declares only the first two values.

Status codes (fail-closed mapping, `http_status` at
`backend/app/routers/approvals.py:234-245` plus the auth gate):

| Code | Cause |
|---|---|
| 401 | `X-API-Key` missing or blank |
| 403 | wrong key · key store holds none of the required roles · `actor` ≠ the key's owner · approval not `pending` · token signature / scope / actor verify failure |
| 404 | unknown `approval_id` |
| 409 | token replay (nonce already burned) |
| 410 | approval past TTL |
| 422 | action rejected by the contract or by the validator (`ValueError`) |
| 400 | anything else (`extra` field, malformed `idempotency_key`) |

`Idempotency-Key` is honored through the in-process `IDEM_RESPONSES` map only;
a duplicate returns the cached view with `duplicate: true` and is not
persisted across restarts.

## Incident stream (REPLAY-ONLY, not push)

`GET /stream/incidents/{id}?since=<event_id>` returns
`text/event-stream` frames of the form `id: <audit_event_id>\ndata: {json}\n\n`
(`backend/app/routers/stream.py:111-122,175-191`). What it is:

- **REPLAY-ONLY.** It streams a finite, already-known snapshot of the
  incident's audit chain and then the response body ends. There is no push,
  no publish/subscribe, no long-poll, no heartbeat/keep-alive, and no
  websocket. A newly emitted event is not delivered to an already-open
  connection.
- **Cursor semantics.** `?since=` must match an `event_id` /
  `audit_event_id` present in the chain; the matched event is excluded and
  only newer events replay. An unknown cursor is **400**, never a silent
  restart to the beginning. Absent/blank `since` replays the whole chain.
- **Unauthenticated read.** No `X-API-Key` is required, matching the other
  audit read endpoints. The route cannot mutate anything — it holds no emit,
  approve, or execute path (`backend/app/routers/stream.py:11-17`).
- **Error mapping.** Unknown incident → 404. An incident known only through an
  open run with an empty chain replays as an empty body (honest empty, not a
  404).
- **What the UI does with it.** `frontend/src/sse.ts` re-arms the connection
  with the advanced cursor and, when `EventSource` is unavailable or the
  stream errors, falls back to polling `GET /incidents/{id}/audit` every 3s
  with exponential backoff (`frontend/src/components/useIncidentEvents.ts`).
  So the live-looking behavior in the UI is repeated finite replays plus
  polling — not a push channel. Any REPLAY-sourced view must be labeled
  REPLAY, never LIVE.

## Contract rules (binding on future routes, quoted from spec, not implemented)

- Every endpoint declares: responsibility · request/response schema · validation ·
  authorization · failure behavior · idempotency where mutating · audit event where
  relevant · test coverage.
- Mutations require: authenticated role + action context + policy decision +
  idempotency + approval when necessary. No endpoint bypasses validation, policy,
  HITL, verification, or audit.
- Guards: role verified server-side; execute re-checks policy-permit freshness
  (≤5m); typed errors (400/401/403/404/409/410/422/429), each audited where relevant.
- Config is loaded at import (`get_settings()` fail-closed); secrets never appear
  in bodies, errors, or logs (M00.2/M00.4/M00.5 gates).
- No route applies rate limiting or request throttling. `X-API-Key` is compared
  by digest and answered 401/403; there is no per-key or per-IP throttle, lockout,
  or backoff — PLANNED, not built.

## PLANNED (owning modules, not implemented)

- Alerts ingest, triage/evidence/diagnose/remediation endpoints, executions +
  verify + rollback, RCA publish, `POST /demo/seed` (spec §40) — owners:
  M21 integration, demo (M22).
- Identity hardening: SSO/OIDC in front of the key gate, key expiry/rotation,
  remote revocation. The shipped per-key store is a local JSON file and the
  `bootstrap` fallback remains reachable. Owner: unassigned (PLANNED).
- Rate limiting / lockout on any route. Owner: unassigned (PLANNED).
- A push or long-poll stream. The current endpoint is finite replay only.
  Owner: unassigned (PLANNED).
- No route is claimed to exist until its module lands with tests.
