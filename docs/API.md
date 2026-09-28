# ProofOps API (M00.6 foundation; built through M21, owned per module)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §40 (required surface), §38
(invariants), §27 (HITL), §32 (audit).

Status: implemented through M21, plus the M20 observability routes and the
M21b identity guard. Per-route truth lives in `backend/app/main.py` +
`backend/app/routers/` + the tests. Nothing here claims production readiness or
certification.

Operator walkthrough: [`QUICKSTART.md`](QUICKSTART.md). Full auth model:
[`SECURITY.md`](SECURITY.md).

## Live today (tested)

The route inventory is the union of six routes registered in
`backend/app/main.py` and the nine routers in `backend/app/routers/` (`runs`,
`audit`, `approvals`, `auth`, `eval`, `stream`, `agents`, `ingest`,
`webhooks`). "Gate" states the credential requirement. The identity model behind
every gate is documented in `SECURITY.md`.

### Open routes (no credential)

| Method + path | Owner | Behavior |
|---|---|---|
| `GET /healthz` | M00.1 (frozen body) | Liveness: `{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}`. Always 200 while the process lives, even with db down. Drives the image + compose HEALTHCHECK. |
| `GET /readyz` | M00.4 | Readiness: 200 `ready` only when every dependency serves, else 503 `not-ready`. Body is secret-free (`database unreachable` / `database query failed`, never a DSN). Bounded 2s probe. |
| `GET /meta` | M19 | Executor disclosure for the UI mode badge: `service`, `spec`, `executor_tier` (`mock`\|`docker`), `mode` (`APP_ENV`), `nonce_store_durable`, `nonce_store_degraded`. Public values only. |
| `GET /meta/engines` | live-tier lane | Live status of all four control-plane engines. See "Engine status" below. |
| `GET /metrics` | M20 (Lane 2) | **Prometheus text exposition, not JSON** (`text/plain; version=0.0.4`, hand-rendered, stdlib only). Only the HTTP route/code/latency counters are wired, by the ASGI middleware in `main.py`. The approval / policy / LLM / tool / budget increment functions exist but **no router calls them**, so they render as `0` and their SLO objectives evaluate `ok` with note `no data (counter not yet wired)`. Never faked (`backend/app/services/metrics.py:11-17,466-470`). |
| `GET /alerts` | M20 (Lane 2) | JSON `{"alerts":[...]}`, each a `SloAlert` (`name`, `state`, `metric`, `observed`, `target`, `op`, `window`, `owner`, `severity`, `note`). Read-only evaluation of `policies/slo.yaml`. **This is the SLO alert surface, not an incident list.** A missing or malformed SLO fails closed with 500 `{"error":"SLO configuration unavailable"}`. **No paging**: a firing alert needs an external webhook, PLANNED, not built. |
| `GET /orchestrator` | M21 | Worker counters plus a note describing whether the agent brain is a scripted oracle. Deliberately open so an operator can see the pipeline is alive without a credential. |
| `GET /runs` | M14 | Queue summaries: `incident_id`, `state`, `history_len`. |
| `GET /runs/{id}` | M14 | `run_view`. See "Run view" below. |
| `GET /approvals/{id}` | M19 | Status + TTL countdown + identity provenance. See "Approvals" below. |
| `GET /approval-proposals` | M07 | `{"proposals":[{action_id, incident_id, action_type, risk_level, runbook_id, parked_at, token_available, action}]}`. The queue of actions parked at `AWAITING_APPROVAL`, which is how a human discovers there is something to approve. |
| `GET /identity`, `GET /auth/identity` | M21b | Server-resolved identity, so a client never asserts its own. `GET /auth/identity` is an alias of `GET /identity`. See "Identity" below. |
| `GET /incidents/{id}/audit` | M15 | Chain view: `origin: "custom-hash-chain"`, `valid`, `checked`, `events`. **CUSTOM hash audit, not AIMS.** |
| `POST /incidents/{id}/audit/verify` | M15 | Chain validity verdict: `incident_id`, `valid`, `checked`, `first_bad_seq`, `reason`. |
| `GET /incidents/{id}/audit/export` | M15 | Chain export with `exported_at`. |
| `GET /incidents/{id}/rca` | M21.7 | The published blameless postmortem, or an explicit statement that none exists. See "Postmortem" below. |
| `GET /stream/incidents/{id}?since=` | M21 | **Live SSE with replay backlog.** See "Incident stream" below. |
| `GET /agents/{id}/thread` | M13 | `incident_id`, `session_id`, `turns[]`. Read-only transcript of the investigation surface. |
| `GET /alerts/webhook/{alertmanager,cloudwatch,datadog,pagerduty}` | M21 | Vendor alert ingestion. See the honest note in "Credential handling" below. |

### Credentialed routes

| Method + path | Gate | Owner | Behavior |
|---|---|---|---|
| `POST /runs` (201) | key + `RUN_WRITE_ROLES` | M14/M21 | Open a run; 409 on duplicate id. |
| `POST /runs/{id}/advance` | key + `RUN_WRITE_ROLES` | M14 | Guarded transition: no-skip permit gate, re-plan ≤2, rollback-once. `APPROVED` additionally requires an HMAC-bound approval (`approval_id` + `token` + `actor`) verified against the **stored** M07 request, so a raw client permit is refused. Accepts `idempotency_key`; a duplicate returns the cached view with `duplicate: true` (in-process cache only, not persisted). |
| `POST /runs/{id}/sweep` | key + `RUN_WRITE_ROLES` | M14 | TTL sweep; staged approvals escalate on expiry. |
| `POST /alerts/ingest` | key + `operator`/`approver`/`admin` | M21 | Queue a telemetry bundle and, with `process: true`, hand it to the worker that runs the real pipeline. 422 on a bad bundle or unknown scenario, 503 when the worker is disabled by the kill switch. **This route is implemented**, contrary to earlier revisions of this doc. |
| `POST /orchestrator/stop` | key + `operator`/`approver`/`admin` | M21 | Kill switch. Disables the worker; ingest then answers 503 rather than silently dropping work. |
| `POST /incidents/{id}/rca/publish` | key + `operator`/`approver`/`admin` | M21.7 | Drive or retry the post-incident stage. Write-gated because publication appends to the chain that is exported as proof. Idempotent. See "Postmortem" below. |
| `POST /approvals` | key + `operator`/`approver`/`admin` | M19 (M07 crypto) | Queue an approval request and mint its HMAC token. Actions are re-validated as contracts + the M06.1 validator. Write-role gated: this route writes the queue, mints a live token, and appends to the exported chain, so a read-only `viewer` key is refused 403. |
| `POST /approvals/{id}/approve` | key + `approver`/`admin` | M19 (M07 crypto) | HMAC verify, nonce burn, single-use, per-key separation of duties. |
| `POST /approvals/{id}/reject` | key + `approver`/`admin` | M19 | Deny + reason; separation of duties deliberately not applied (reason below). |
| `POST /approvals/{id}/token` | key + `approver`/`admin` | M07 | Single-read pickup of a `scoped_view` token, returning a `scoped_view` body only. 404 when the token is not collectable. This route exists only because the weakest carrier puts a live credential on a read path. |
| `POST /incidents/{id}/audit/events` | key + `operator`/`approver`/`admin` | M15 | External append, write-role gated. The audit actor is the server-derived immutable key id; a supplied `actor` string is kept only as a `key (claimed name)` label so forensics sees the claim without letting it become the record (`backend/app/routers/audit.py:149-166`). |
| `POST /token`, `POST /auth/token` | key or bearer | M21b | Mint an HS256 JWT (`expires_in: 86400`) signed with `APPROVAL_SECRET`. `POST /auth/token` is an alias. |
| `POST /agents/investigate` | none enforced | M13 | Read-only investigation. Returns `answer`, `citations`, `trace`, `proposed_action`, `authority`, `reasoning_mode`, `verdict`, `evidence_ids`. It can propose; it cannot execute, approve, or mutate. See "Credential handling". |
| `POST /eval/smoke` | key + `operator`/`approver`/`admin` + `{"confirm": true}` | M19 (M16 engine) | Mock-harness numbers on demand. `system` is the literal `"mock-deterministic"` and `note` says the run proves the eval machinery, not product quality. Not open compute: a missing key is 401 and `confirm != true` is 400. |

`RUN_WRITE_ROLES` is server code, `("operator", "approver", "admin")`
(`backend/app/routers/runs.py:682`). A client-supplied role string never appears
in that decision.

Repro:

```bash
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
curl http://localhost:8000/openapi.json
python -m pytest tests/test_http_guards.py tests/test_health.py -q
```

## Credential handling (two modes, and where each is honored)

There are two credential carriers, and which one a route honors is not uniform.
This is documented explicitly because a reader who assumes "everything takes the
API key" will be wrong in both directions.

**`X-API-Key` header (primary).** Compared by SHA-256 digest with
`hmac.compare_digest`, never by plaintext equality. Resolution has two modes
(`backend/app/routers/auth.py:111-112`):

- `per_key`: a key store resolved the caller, and server-side roles are known.
- `bootstrap`: the store is absent or unreadable, so the raw key is compared
  against `PROOFOPS_API_KEY` and the identity carries **no** roles. Fail-closed
  at the store level: a present but corrupt store is a 500, never a silent
  downgrade to bootstrap.

**`Authorization: Bearer <jwt>` (secondary).** HS256 over `APPROVAL_SECRET`.
`guard_http` accepts it. Bearer is honoured on `POST /token`,
`POST /auth/token`, `GET /identity`, every `POST /approvals*`,
`POST /alerts/ingest`, `POST /orchestrator/stop`,
`POST /incidents/{id}/rca/publish`, `POST /runs`, `POST /runs/{id}/advance`,
and `POST /runs/{id}/sweep`. An invalid bearer yields 403, not 401.

This used to be genuinely partial: `runs.py` forwarded the header and the
approvals and ingest routers did not, so a token minted by `POST /auth/token`
was useless for the routes an operator actually needs — sign-in succeeded and
every write still answered 401. The routers now forward it consistently, and
`tests/test_frontend_e2e_integration.py` fails if one of them stops, because
the failure is a missing parameter and no response-shape test can see it.

A token is only as good as the key it was minted from, and it is signed with
`APPROVAL_SECRET`: it cannot be forged without that secret, and the identity it
carries is the one the server resolved when it was issued. Note the operational
property: revoking a key does not invalidate tokens already issued to it, which
is bounded by the 24h `expires_in`.

**Accepted and ignored.** `POST /agents/investigate` and all four webhook routes
declare an `X-API-Key` parameter and never verify it. `/agents/investigate` is
deliberately read-only and asserts no authority, so an open surface is
intentional there. The webhooks have no guard at all, which is a real gap: an
unauthenticated caller can inject alert payloads. Recorded as PLANNED, owner
unassigned. Do not describe these routes as authenticated.

## Engine status (`GET /meta/engines`)

The honest, per-engine report. `backend/app/main.py:136-154`.

| Object | Fields |
|---|---|
| `database` | `healthy`, `dialect` (`postgresql`\|`sqlite`), `database`, `error`, `degraded`, `fallback_reason` |
| `kubernetes` | `connected`, `host`, `tier` (`k8s`\|`offline`), `version`, `namespace`, `error` |
| `prometheus` | `connected`, `url`, `tier` (`live-promql`\|`standby-sandbox`) |
| `llm_hub` | `provider`, `status` (`UNVERIFIED`\|`OFFLINE`), `tier` |

Read the tier strings literally:

- `kubernetes.tier` is `k8s` only when a real API server answered `/version`
  **and** authorized a pod list in the configured namespace. `error` carries the
  exception type name, because "not connected" is not actionable: a missing
  driver, an absent kubeconfig, and a cluster refusing our identity are three
  different problems with three different fixes.
- `prometheus.tier` describes the **verifier**, not the executor.
  `standby-sandbox` does not mean the sandbox is executing.
- `llm_hub.status` is `UNVERIFIED` whenever a credential is present and `OFFLINE`
  when none is. **The backend never returns `CONNECTED`.** Holding a config
  string is not a connection, and `tests/test_llm_honesty.py` asserts the literal
  is absent from the source.

`database.degraded` is reported rather than hidden: a local sqlite file is a
working fallback, but an operator reading `healthy` must be able to tell that the
audit trail is not in Postgres right now. Note that the frontend `EngineStatus`
type in `frontend/src/api.ts` does not yet carry `degraded`, `fallback_reason`,
`kubernetes.version`, `kubernetes.namespace`, or `kubernetes.error`, so the UI
cannot render them.

## Identity (`GET /identity`)

Requires `X-API-Key` (missing → 401, wrong → 403, corrupt key store → 500) and
returns `identity_view` (`backend/app/routers/auth.py:373-385`):

| Field | Meaning |
|---|---|
| `key_id` | Stable, non-secret principal. This is what the audit chain records; an owner rename never rewrites history. |
| `owner` | Mutable display name registered for the key. |
| `roles` | Server-side roles read from the key store. Never client-asserted. |
| `mode` | `per_key` (a key store resolved this caller) or `bootstrap` (shared single-key demo fallback). |
| `server_enforced` | `true` only in `per_key` mode. |

`bootstrap` is a **shared demo credential with no per-user identity and no
server-side roles**. Every surface that shows identity must show `mode` too;
presenting `bootstrap` as an authenticated user would be a false claim.

## Run view (`GET /runs/{id}`)

`run_view` (`backend/app/routers/runs.py`) returns `incident_id`, `state`,
`replans`, `rolled_back`, `permit_pending`, `state_diff`, `execution_logs`,
`execution_tier`, `history`, `handoffs`, `audit_records`,
`verification_verdicts`, `verification_results`, `rca_report`, and `rollback`.

`state_diff`, `execution_logs` and `execution_tier` are empty/`""` until an
action actually executes, which is why the Execution view renders an explicit
empty state instead of a blank panel. `rca_report` is `null` when no postmortem
has been published — `null` means "never published", which is deliberately
distinct from "published and empty". `POST /runs/{id}/sweep` additionally
returns `escalated`.

All four of `state_diff`, `execution_logs`, `execution_tier` and `rca_report`
are attached to the run with `setattr` rather than declared on `IncidentRun`, so
they are durable only because the run store serialises them as declared
**optional** keys. Two consequences worth knowing:

- They are validated when present and ignored when absent, so a store written
  before a key existed still loads. Requiring them would turn a schema addition
  into a load failure for every previously persisted run.
- `resume_from_approval` (the human-approved path) attaches them explicitly.
  It previously emitted the state diff and verdict to the audit chain and
  returned, so the single most important path in the product left no evidence on
  `run_view` at all.

`verification_results` carries the real verifier output — `execution_id`,
`verdict`, per-check `checks`, `detail`, `at` — and is distinct from
`verification_verdicts`, which is an FSM *transition* projection. One name over
two shapes is what made the real evidence unreachable: the panel titled
"Verification verdicts" was rendering state moves while the checks the verifier
actually ran were never shown.

## Postmortem (`GET /incidents/{id}/rca`, `POST /incidents/{id}/rca/publish`)

The blameless postmortem is A4's output, published only after the MUST-CITE
coverage gate accepts it.

`GET` returns one of three states, which are deliberately distinct:

| State | Meaning |
|---|---|
| `published: true` + `report` | A document exists and passed the gate. |
| `published: false`, run at `RCA_PENDING` | The stage ran and the gate **refused**. `detail` says so. |
| `published: false`, run elsewhere | The post-incident stage has not run. `detail` names the state. |

Collapsing these is how a UI ends up rendering an empty postmortem as though one
had been written.

`report` is `RCAReport`: `summary`, `timeline` (audit-chain rows carrying
ts + actor + hash), `root_cause`, `claim_ids`, `remediation_log`,
`prevention`, `gated`, `gate_reason`, `agent: "reporter"`,
`model_tier: "economical"`.

Fail-closed properties, all covered by `tests/test_rca_stage.py`:

- Publication goes through the hardened path only. A cited evidence id grounds a
  claim only when it resolves to evidence that is fresh, not `LOW` trust, and
  sealed; the valid-evidence set is measured from the evidence pack, never from
  the claims, so a claim cannot ground itself by citing its own citation.
- A below-coverage draft is **denied**, audited as `rca.publish … DENIED`, and
  the run stays at `RCA_PENDING`. It is never advanced to `RCA_PUBLISHED`, so
  the run cannot claim a postmortem that does not exist.
- Every input is derived from banked artifacts (run handoffs, FSM history,
  verification results, audit chain), never from live telemetry and never
  invented. A postmortem that fabricates its own timeline is worse than none.
- Personal-blame prose is rejected by the blameless lint, not softened.

Retry and idempotency: a failure after the `RCA_PENDING` advance is retryable
from `RCA_PENDING` (an earlier version only accepted `RESOLVED`/`ESCALATED`, so
any mid-stage failure stranded the incident permanently), and re-publishing
returns the stored document rather than appending a second one.

The stage is driven automatically by the orchestrator after a run reaches
`RESOLVED`/`ESCALATED`, which is what makes `AUDITED` — the FSM's terminal state
— reachable at all.

## Approvals (request / approve / reject)

Both request bodies are `extra: forbid`. Request: `action` (required object),
`actor` (optional, default `""`, ≤128), `ttl_seconds` (optional, default 600,
1–900). Decide: `actor`, `token`, `role`, `reason`, `idempotency_key`, all
optional.

**`actor` and `role` are NOT authorization inputs.**

- `actor`: a blank body actor is filled from the authenticated key's registered
  `owner` (`_actor_for`). A non-blank claim must equal that owner in `per_key`
  mode, otherwise 403 (`_actor_for` / `_assert_owner`,
  `backend/app/routers/approvals.py:921-957`). In `bootstrap` mode a non-blank
  actor is accepted as a display label only, and the response reports
  `identity_mode: "bootstrap"` precisely because that label is not an
  authenticated identity.
- `role`: the gate is `require_role(identity, "approver", "admin")` over the
  **key's server-side roles** (`http_approve` / `http_reject`,
  `backend/app/routers/approvals.py:1013-1039`). The body `role` is a legacy
  secondary check that only fires when non-blank
  (`backend/app/routers/approvals.py:545-547`), so a body claiming
  `role: "admin"` grants nothing.

`GET /approvals/{id}` returns `approval_view`
(`backend/app/routers/approvals.py:454-486`): `approval_id`, `incident_id`,
`action_id`, `actor`, `scope`, `params_hash`, `status`, `expires_at`,
`seconds_remaining`, plus the identity provenance `identity_mode`,
`requester_key_id`, `decided_by`, and `sod`. `sod` is `"enforced"` only in
`per_key` mode when the deciding key differs from the requesting key;
`"not_enforced_bootstrap"` in bootstrap mode; `"not_recorded"` when the mode is
recorded but a key id is absent. The frontend `ApprovalView` type declares only
the first two values.

Status codes (fail-closed mapping, `http_status` at
`backend/app/routers/approvals.py:250-261` plus the auth gate):

| Code | Cause |
|---|---|
| 401 | `X-API-Key` missing or blank |
| 403 | wrong key · key store holds none of the required roles · `actor` ≠ the key's owner · approval not `pending` · token signature / scope / actor verify failure |
| 404 | unknown `approval_id` |
| 409 | token replay (nonce already burned) |
| 410 | approval past TTL |
| 422 | action rejected by the contract or by the validator (`ValueError`) |
| 400 | anything else (`extra` field, malformed `idempotency_key`) |

The token is **never stored**. The persisted record holds the request, the
action, status, and provenance; the caller re-presents the token and
cryptographic continuity comes from recomputing the MAC over the reloaded
request. That is why scope binding survives a restart without a token table.

`Idempotency-Key` is honored through the in-process `IDEM_RESPONSES` map only; a
duplicate returns the cached view with `duplicate: true` and is not persisted
across restarts.

## Incident stream (live, with a replay backlog)

`GET /stream/incidents/{id}?since=<event_id>` returns `text/event-stream` frames
of the form `id: <audit_event_id>\ndata: {json}\n\n`
(`backend/app/routers/stream.py:222-305`). It is **not** a finite replay. Earlier
revisions of this doc described it as replay-only with no push, no keepalive, and
no held connection; that was wrong, and `tests/test_stream_live.py` exists
specifically to pin the difference.

What it does, in order:

1. **Replay the backlog.** Every event newer than the cursor is emitted.
2. **Signal completion.** A replay-complete marker carrying the backlog length.
3. **Stay open.** The connection is held and subscribes to the event bus. A
   keepalive comment frame is emitted every 15 seconds
   (`KEEPALIVE_SECONDS`), up to a 3600 second cap
   (`MAX_CONNECTION_SECONDS`). A newly emitted event **is** delivered to an
   already-open connection.

Other behavior:

- **Cursor semantics.** `?since=` must match an event id present in the chain;
  the matched event is excluded and only newer events are sent. An unknown
  cursor is **400**, never a silent restart to the beginning. Absent or blank
  `since` replays the whole chain.
- **Unauthenticated read.** No credential is required, matching the other audit
  read endpoints. The route cannot mutate anything: it holds no emit, approve,
  or execute path (`backend/app/routers/stream.py:11-17`).
- **Error mapping.** Unknown incident → 404. An incident known only through an
  open run with an empty chain replays as an empty body, which is an honest empty
  rather than a 404. A completed replay is not a stream failure, and
  `tests/test_stream_replay_completion.py` pins that.
- **What the UI does with it.** `frontend/src/sse.ts` re-arms with the advanced
  cursor and, when `EventSource` is unavailable or the stream errors, falls back
  to polling `GET /incidents/{id}/audit` with debounce and exponential backoff
  (`frontend/src/components/useIncidentEvents.ts`). The fallback is a
  degradation, not the normal path.

## Contract rules (binding on future routes, quoted from spec, not implemented)

- Every endpoint declares: responsibility · request/response schema · validation ·
  authorization · failure behavior · idempotency where mutating · audit event where
  relevant · test coverage.
- Mutations require: authenticated role + action context + policy decision +
  idempotency + approval when necessary. No endpoint bypasses validation, policy,
  HITL, verification, or audit.
- Guards: role verified server-side; execute re-checks policy-permit freshness
  (≤5m); typed errors (400/401/403/404/409/410/422/429), each audited where
  relevant.
- Config is loaded at import (`get_settings()` fail-closed); secrets never appear
  in bodies, errors, or logs (M00.2/M00.4/M00.5 gates).
- No route applies rate limiting or request throttling. `X-API-Key` is compared
  by digest and answered 401/403; there is no per-key or per-IP throttle, lockout,
  or backoff. PLANNED, not built.
- Webhook ingestion is unauthenticated (above). PLANNED, not built.

## PLANNED (owning modules, not implemented)

- `POST /demo/seed` (spec §40) and `scripts/demo.sh --check`. Owner: M22.1, M22.5.
- Discrete triage, evidence, diagnosis, remediation, execution, verify, rollback,
  and RCA-publish endpoints. The **behavior** exists and is reachable through
  `POST /alerts/ingest` plus the orchestrator; what is missing is a per-stage HTTP
  surface. Owner: M21 integration, M22.
- An RCA document renderer. The RCA view renders the audit chain and the
  six-gate scorecard today. Owner: M22.
- A credential on the webhook ingest routes. Owner: unassigned.
- Extending the Bearer path from its current two-file scope to the whole surface,
  or removing it. Pick one and write it down. Owner: unassigned.
- Identity hardening: SSO/OIDC in front of the key gate, key expiry/rotation,
  remote revocation. The shipped per-key store is a local JSON file and the
  `bootstrap` fallback remains reachable. Owner: unassigned.
- Rate limiting / lockout on any route. Owner: unassigned.
- No route is claimed to exist until its module lands with tests.
