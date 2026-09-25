# ProofOps Docs — Index

> Authoritative spec: [`PS03_FINAL_SPEC_V2.md`](PS03_FINAL_SPEC_V2.md) · Registry: [`MODULE_REGISTRY.md`](MODULE_REGISTRY.md)

## Root — Entry-point docs (indexed below; 19 total on disk)

These stay at `docs/` root because they are frozen M00–M01 contracts or live-reviewed. `tests/test_docs.py` pins 11 of them in `CANONICAL_DOCS` (4 frozen M00.2–M00.5 + 7 M00.6 foundation) and governs 8 more as `known_extra` (SPEC, registry, plan, checklist, index, audit, safety-plan, contracts).

| File | Owner | Purpose |
|------|-------|---------|
| `PS03_FINAL_SPEC_V2.md` | Spec | Final authoritative PRD (supersedes `archive/PS03_FINAL_SPEC.md` on conflict) |
| `MODULE_REGISTRY.md` | Control plane | 183-unit tracker, gate ≥90 |
| `CONTRACTS.md` | M01 | Contract freeze surface |
| `CONFIGURATION.md` | M00.2 | Env/config trust boundary |
| `COMPOSE.md` | M00.3 | Docker Compose + runtime matrix |
| `HEALTH.md` | M00.4 | `/healthz` vs `/readyz` |
| `LOGGING.md` | M00.5 | Logging/redaction |
| `EVALUATION.md` | M16 | Eval runner + scorecard |
| `SECURITY.md` | M00.6 | Security posture |
| `DECISIONS.md` | M00.6 | ADR log (bridges frozen docs to spec) |
| `DEMO.md` | M22 | Demo script |
| `ARCHITECTURE.md` | later phases | System snapshot (implemented-today truth) |
| `API.md` | later phases | API snapshot (routers + tests are truth) |
| `TESTING.md` | test lanes | Suite map (suite output is truth) |

> Note: this index table lists the entry-point docs (14 rows). The test-pinned canonical 11 are `CONFIGURATION, COMPOSE, HEALTH, LOGGING, EVALUATION, SECURITY, DECISIONS, DEMO, ARCHITECTURE, API, TESTING` (see `tests/test_docs.py`). The 8 `known_extra` are `PS03_FINAL_SPEC_V2, MODULE_REGISTRY, CONTRACTS, BUILD_FIRST_MASTER_PLAN, ProofOps_…_Checklist, README, ZERO_TRUST_AUDIT_M00-M11, SAFETY_CROSSING_PLAN`. 11 + 8 = 19 `docs/*.md` on disk.

## Subfolders

- [`research/`](research/) — 7 feasibility / hackathon-strategy papers + master research. Not part of runtime contract; moved out of root to reduce clutter. PLANNED work only.
- [`archive/`](archive/) — `PS03_FINAL_SPEC.md` (V1) kept for history, superseded by V2. See V2 header.

## Rules
- Root docs are **implemented-today truth**; future work marked `PLANNED` with owning module (see `MODULE_REGISTRY.md`).
- `PS03_FINAL_SPEC_V2.md` is the only source of truth for behavior; all other docs must trace to it (directly or via `DECISIONS.md` bridge for frozen M00.2-M00.5).
- Do not add new root docs without updating `tests/test_docs.py` canonical set.

Maintained by: M00.6 docs foundation. Per-doc content is updated by whichever
module changes the code it describes; the index row is the only thing this
file owns.
