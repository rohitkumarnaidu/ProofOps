# ProofOps API Foundation (M00.6 foundation; full surface owned by later phases)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §40 (required surface), §38 (invariants),
§27 (HITL), §32 (audit).

Status: foundation only. Two routes exist today (`GET /healthz`, `GET /readyz`).
Everything else below is marked PLANNED with its owning module. Nothing here
claims production readiness or certification.

## Live today (M00.1/M00.4, tested)

| Method + path | Owner | Behavior |
|---|---|---|
| `GET /healthz` | M00.1 (frozen body) | Liveness: `{"status":"ok","service":"proofops-api","spec":"PS03_FINAL_SPEC_V2"}`. Always 200 while the process lives, even with db down. Drives image HEALTHCHECK. |
| `GET /readyz` | M00.4 | Readiness: 200 `ready` only when every dependency serves, else 503 `not-ready`. Body is secret-free (`database unreachable` / `database query failed`, never DSN). Bounded 2s probe. |

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

- Alerts/incidents/triage/evidence/diagnose/remediation/approvals
  (approve/reject)/executions + verify + rollback/audit/RCA/evaluations/
  `POST /demo/seed` (spec §40) — owners: API + FSM (M14), HITL (M07/M15),
  eval (M16), demo (M22).
- Auth: API-key role checks (server-side); HMAC approval tokens single-use,
  scope-bound (`action_id` + param hash), TTL-bound, nonce-burned (M07).
- Streaming: `GET /stream/incidents/{id}` SSE for control-plane events with
  reconnect + polling fallback + LIVE/REPLAY/MOCK badge (M19).
- No route is claimed to exist until its module lands with tests; this doc
  asserts the absence honestly instead of simulating it.
