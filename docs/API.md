# ProofOps API (M00.6 foundation; built through M19, owned per module)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §40 (required surface), §38 (invariants),
§27 (HITL), §32 (audit).

Status: implemented through M19 (runs, approvals, audit, eval smoke).
Per-route truth lives in `backend/app/routers/` + tests. Nothing here
claims production readiness or certification.

## Live today (tested)

| Method + path | Owner | Behavior |
|---|---|---|
| `GET /healthz` | M00.1 (frozen body) | Liveness: `{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}`. Always 200 while the process lives, even with db down. Drives image HEALTHCHECK. |
| `GET /readyz` | M00.4 | Readiness: 200 `ready` only when every dependency serves, else 503 `not-ready`. Body is secret-free (`database unreachable` / `database query failed`, never DSN). Bounded 2s probe. |
| `POST /runs`, `GET /runs`, `GET /runs/{id}` | M14/M19 | FSM runs: open (409 on dup), queue list, state + history + handoffs + audit records. |
| `POST /runs/{id}/advance` (+ Idempotency-Key) | M14 | Guarded transition: no-skip permit gate, re-plan ≤2, rollback-once; duplicate keys return cached. |
| `POST /runs/{id}/sweep` | M14 | TTL sweep: staged approvals escalate on expiry. |
| `POST /approvals`, `GET /approvals/{id}` | M19 (M07 crypto) | HITL request queue + status/TTL-countdown view. Actions re-validated as contracts. |
| `POST /approvals/{id}/approve|reject` (+ Idempotency-Key) | M19 (M07 crypto) | Demo-role gate (approver/admin; M21 hardens), HMAC verify, nonce burn; typed 403/409/410. |
| `GET /incidents/{id}/audit` (+ `/verify`, `/export`, `POST /events`) | M15 | Hash chain view + validity bool + export + event append. Origin `custom-hash-chain`. |
| `POST /eval/smoke` | M19 (M16 engine) | Measured harness numbers on demand (mock systems, labeled): gates, deltas, rubric. |

Repro:

```bash
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
python -m pytest tests/test_health.py tests/test_repo_structure.py -q
```

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

## PLANNED (owning modules, not implemented)

- Alerts ingest, triage/evidence/diagnose/remediation endpoints, executions +
  verify + rollback, RCA publish, `POST /demo/seed` (spec §40) — owners:
  M21 integration, demo (M22).
- Auth: full API-key guard matrix, server-side (M21; demo-role gate today).
- Streaming: `GET /stream/incidents/{id}` SSE endpoint (client + contract
  exist in M19 UI; server endpoint is M21).
- No route is claimed to exist until its module lands with tests.
