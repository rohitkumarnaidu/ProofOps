# ProofOps Security Foundation (M00.6 foundation; full coverage owned by later modules)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §37 (threat model), §38 (invariants),
§18 (policy engine), §27 (HITL), §32 (audit).

Status: foundation only. This doc records what M00.1–M00.5 implemented and tested
today. Everything else is marked PLANNED with its owning module.
Nothing here claims production readiness or certification.

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
  gate with per-ID written exceptions
  (`scripts/pip_audit_allowlist.txt`: 7 starlette IDs with no in-bounds fix
  and no exploitable surface in this 2-route API, 1 local-only pytest ID).
  Anything unlisted FAILS. Repro: `python scripts/freeze.py --audit`
  (needs `pip-audit`; fails closed without it).

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
- FUTURE, post-hackathon, never claimed: SSO/RBAC approvals, SIEM export,
  managed secrets, confidential-compute executors.

## Invariants (spec §38; enforced when owning modules land)

The contract direction, quoted from the spec, not claimed as code today:
unvalidated Action never reaches the executor; RED never executes; YELLOW
needs a valid unused unexpired scoped token; telemetry is DATA, never
instructions; every block emits audit. Code enforcement landed (M06
HUMAN_APPROVED, M07–M10 IMPLEMENTED_TESTED per docs/MODULE_REGISTRY.md
per-row table, hardening pending), each with its own gate tests.

## Repro (host-safe)

```bash
python -m pytest tests/test_config.py tests/test_logging.py tests/test_health.py -q
```
