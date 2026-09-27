# ProofOps Docs — Index

> Authoritative spec: [`PS03_FINAL_SPEC_V2.md`](PS03_FINAL_SPEC_V2.md) · Registry: [`MODULE_REGISTRY.md`](MODULE_REGISTRY.md)

## Start here

New to the project, or trying to run it? Read
[`QUICKSTART.md`](QUICKSTART.md) first. It goes from a clean clone to a running
stack and a first incident, and every command in it was executed against this
tree.

## Root — Entry-point docs (21 total on disk)

These stay at `docs/` root because they are frozen M00–M01 contracts or
live-reviewed. `tests/test_docs.py` pins 12 of them in `CANONICAL_DOCS` and
governs 9 more as `known_extra`. 12 + 9 = 21 `docs/*.md` on disk.

| File | Owner | Purpose |
|------|-------|---------|
| `QUICKSTART.md` | M00 | Operator entry point: clone, configure, start, first incident |
| `PS03_FINAL_SPEC_V2.md` | Spec | Final authoritative PRD (supersedes `archive/PS03_FINAL_SPEC.md` on conflict) |
| `MODULE_REGISTRY.md` | Control plane | Module tracker, the naming and status authority |
| `CONTRACTS.md` | M01 | Contract freeze surface |
| `CONFIGURATION.md` | M00.2 | Env/config trust boundary |
| `COMPOSE.md` | M00.3 | Docker Compose + runtime matrix |
| `HEALTH.md` | M00.4 | `/healthz` vs `/readyz` |
| `LOGGING.md` | M00.5 | Logging/redaction |
| `EVALUATION.md` | M16 | Eval runner + scorecard |
| `SECURITY.md` | M00.6 | Security posture |
| `DECISIONS.md` | M00.6 | ADR log (bridges frozen docs to spec) |
| `DEMO.md` | M22 | Demo status + the 5:00 spec target |
| `ARCHITECTURE.md` | later phases | System snapshot (implemented-today truth) |
| `API.md` | later phases | API snapshot (routers + tests are truth) |
| `TESTING.md` | test lanes | Suite map (suite output is truth) |
| `BUILD_FIRST_MASTER_PLAN.md` | M21 | Wave plan and entry/exit criteria |
| `SAFETY_CROSSING_PLAN.md` | crossing campaign | M00–M06 safety campaign plan. SUPERSEDED, never deleted |
| `PROOF_OPS_REAL_CLOUD_AND_SECURITY_ARCHITECTURE.md` | live-tier lane | Enterprise cloud-integration + zero-trust control-plane architecture |
| `ZERO_TRUST_AUDIT_M00-M11.md` | audit | Dated historical report (do not rewrite) |
| `ProofOps_PS03_Master_Winning_Implementation_Trust_Submission_Checklist.md` | unverified | Companion checklist; the registry and spec govern on conflict |

**The test-pinned canonical 12** are `CONFIGURATION, COMPOSE, HEALTH, LOGGING,
EVALUATION, SECURITY, DECISIONS, DEMO, ARCHITECTURE, API, TESTING, QUICKSTART`
(see `tests/test_docs.py`).

**The 9 `known_extra`** are `PS03_FINAL_SPEC_V2, MODULE_REGISTRY, CONTRACTS,
BUILD_FIRST_MASTER_PLAN, ProofOps_…_Checklist, README, ZERO_TRUST_AUDIT_M00-M11,
SAFETY_CROSSING_PLAN, PROOF_OPS_REAL_CLOUD_AND_SECURITY_ARCHITECTURE`.

Governing a doc is not the same as promoting it. `CANONICAL_DOCS` entries are
gated for content (owning module, spec traceability, PLANNED marking, no
fabricated claims, no leaked credential markers). `known_extra` entries are
required to exist and are maintained by their owning lane, but are not
content-gated, because some of them are dated reports or a lane description
rather than baseline truth.

## Subfolders

- [`research/`](research/) — feasibility and hackathon-strategy papers plus
  master research. Not part of the runtime contract. PLANNED work only.
- [`archive/`](archive/) — `PS03_FINAL_SPEC.md` (V1) kept for history,
  superseded by V2. See the V2 header.

## Rules

- Root docs are **implemented-today truth**; future work is marked `PLANNED` with
  an owning module (see `MODULE_REGISTRY.md`).
- `PS03_FINAL_SPEC_V2.md` is the only source of truth for behavior; all other
  docs must trace to it (directly, or via the `DECISIONS.md` bridge for the
  frozen M00.2–M00.5 docs).
- Do not add new root docs without updating `CANONICAL_DOCS` or `known_extra` in
  `tests/test_docs.py`, and without recording the reason in `DECISIONS.md`.
- Four docs are frozen and must not be edited: `CONFIGURATION.md` (M00.2),
  `COMPOSE.md` (M00.3), `HEALTH.md` (M00.4), `LOGGING.md` (M00.5). Changing one
  needs an ADR that unfreezes it.
- Never write a "green" or "verified" claim that no current command output
  supports. A stale pass count is a defect, not a footnote.

Maintained by: M00.6 docs foundation, extended by ADR-016. Per-doc content is
updated by whichever module changes the code it describes; this index and the
governance split are the only things this file owns.
