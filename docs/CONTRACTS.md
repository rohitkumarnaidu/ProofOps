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

## M01.2 Incident hardening (zero-trust pass)

`Incident` (`backend/app/contracts/incident.py`, re-exported via
`app.schemas`) additionally guarantees:

1. **Bypass containment.** `Incident.model_construct` raises `TypeError`
   (upstream validation-skipping API is blocked on this class);
   `model_copy(update=...)` re-validates the merged data (the sibling
   bypass is closed too). AST scan tests forbid `model_construct` in
   application code and pin the only `object.__setattr__` sites
   (`FrozenDict` construction, M00-frozen `Settings` init, legacy Alert
   normalizer — none touches `Incident`). Anything built outside
   `Incident(...)` / `model_validate*` must be re-validated before
   crossing a trust boundary. In-process `object.__setattr__` memory
   tampering is documented as framework-level / out of scope.
2. **Deep immutability.** ID lists are stored as `tuple[str, ...]`
   (list input accepted, dumped as fresh `list`); `impact`/`metadata` are
   stored as `FrozenDict` (dict input copied + recursively frozen, dumped
   as fresh plain `dict`). Item mutation raises; dumps are detached by
   construction. JSON wire output is byte-identical to pre-hardening
   (golden fixtures in `tests/test_contracts_m01_2_hardening.py`).
3. **Explicit bounds.** Identifier strings ≤128 chars; ID lists ≤100
   entries of ≤128 chars; `impact` ≤32 entries / 4 KiB canonical JSON;
   `metadata` ≤64 entries / 128-char keys / depth 5 / 16 KiB canonical
   JSON. Rationale per constant in `incident.py` (`MAX_*`).
4. **Whitespace: reject, never strip.** Padded identifiers (scalars, list
   items, mapping keys) fail validation; interior whitespace is allowed;
   free-form `impact`/`metadata` values are preserved as-is.
