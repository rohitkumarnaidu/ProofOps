# ProofOps Contracts (M01.1 freeze surface)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` §16 (contracts).

## Freeze surface

`backend/app/contracts/` is the canonical package. M01.2+ and M02 import
from `app.contracts` ONLY. `backend/app/schemas.py` is a compatibility
re-export layer and defines no domain vocabulary.

Freeze version: `1.0` (`CONTRACT_VERSION`). Breaking changes need a change
request + impact analysis + human review + version bump + migration plan.

## What lives here

- `enums.py` — one definition per domain vocabulary (`str`-Enums, so every
  member compares equal to its wire string and serializes as it).
  `ActionType` is generated from the `ACTION_TYPES` allowlist tuple;
  `IncidentStatus` from `FSM_STATES`; neither pair can drift.
- `values.py` — identifiers (`new_id`), time (`utcnow`, tz-aware ISO-8601),
  `SEMVER_RE` / `NAMESPACE_RE`, canonical hashing (`canonical_json`,
  `sha256_hex`, `params_hash`), confidence buckets, bounded `PageParams`.

## Locked M01.1 decisions

1. M00 operational enums stay in frozen `app.config` (how the process runs
   vs what the domain talks about — different concerns, never merged).
2. Domain `Environment` (`dev/staging/prod/mock`, where the workload lives)
   is a different axis from config `AppEnv` (`development/test/demo/
   production`, how this process runs). Documented, not merged.
3. `ExecutorTier` is `mock|docker`; `kind` is reserved-absent until its tier
   lands (mirrors the M00.2 production rule). `Execution.tier="kind"` now
   fails validation — the one intentional behavior change from legacy.
4. `EvidenceType` aliases `SourceType`; the kind-vs-source split is M05's.
5. Confidence buckets: <0.4 low, <0.7 medium, else high.
6. Page ceiling 500 reuses the spec's `get_logs` limit so pagination can
   never widen a bounded read.

## Compatibility

All 15 legacy models keep their names, fields, and defaults; string inputs
coerce to Enums, so pre-M01.1 callers and `tests/test_schemas.py` (28 tests,
unmodified) keep passing byte-for-byte, except decision 3 above.
