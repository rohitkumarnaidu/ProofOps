# ProofOps Architecture Decisions (M00.6 foundation log)

Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` (per-ADR section refs below).

Status: this log records decisions taken in M00.1–M00.5 plus the M00.6
documentation-scope decision. Future ADRs are listed as PLANNED slots with
owners, not taken here.
Nothing here claims production readiness or certification.

## ADR-001 — Container is the source of truth (M00.1)

Context: host Python (3.13/3.14) drifts from the pinned image
(`python:3.12-slim`, Starlette v1 ABI break).
Decision: `Dockerfile`/`backend/Dockerfile` pin `python:3.12-slim`; host may
run offline structure tests only. Spec: §43, §47.
Consequences: live FastAPI checks run in the container; host skips report
SKIP, never PASS (`tests/test_repo_structure.py`).

## ADR-002 — Unknown-env typo policy: ignore, documented (M00.2)

Context: `extra='forbid'` provably ignores both system env and planted typo
vars under pydantic-settings 2.13, buying zero protection while suggesting it.
Decision: `extra=ignore` plus template completeness, AST code/template parity
tests, and the machine-readable `Settings.inventory()` contract — a
misspelled key fails visibly as "required key missing".
Spec: §43. Detail: `docs/CONFIGURATION.md`.

## ADR-003 — DB password fails closed at two layers (M00.2/M00.3)

Context: a soft dev default for the DB password could silently cross into
demo/prod use.
Decision: `Settings` requires the secret AND compose uses the `:?`
hard-require form so `docker compose config` aborts with an actionable
message when unset. Note postgres semantics: the password applies at volume
initialization only (see stickiness note in `docs/COMPOSE.md`).
Spec: §39, §43.

## ADR-004 — Liveness vs readiness split; readiness is NOT the healthcheck (M00.4)

Context: the M00.3 skeleton answered `/healthz` even with the database down;
a flapping database must never restart the api container.
Decision: `/healthz` stays liveness-only (always 200 while the process
lives); new `/readyz` reports dependency depth (200 ready / 503 not-ready,
2s bounded probe, secret-free static errors). Only liveness drives the image
`HEALTHCHECK` and compose `service_healthy`.
Spec: §29 (verification independence reads the same split). Detail:
`docs/HEALTH.md`. Reconciliation: the M00.3-era "M00.4 scope/gap" wording for
the db-down behavior was closed by M00.4; the `docs/COMPOSE.md` db-down line
was updated in M00.6 (single authorized line edit, human-assigned).

## ADR-005 — Format-then-scrub logging with a stated boundary (M00.5)

Context: secrets can arrive via message, args, or tracebacks; taking over
uvicorn's boot formatter would need deprecated hooks.
Decision: `RedactingFormatter` scrubs the fully rendered line (message, args,
tracebacks) for registered values plus generic credential patterns; uvicorn
boot lines keep the stock formatter (secret-free by nature, asserted hygienic
live). Detail: `docs/LOGGING.md`. Spec: §37 (secret-leak control).

## ADR-006 — M00.6 documentation scope and README reconciliation (this module,
hardened to 11-docs in 90+ pass)

Context: `README.md` lists `docs/EVALUATION.md`, `docs/SECURITY.md`,
`docs/DECISIONS.md`, `docs/DEMO.md` as PLANNED "in M00.6/M22", while spec §44
additionally names `ARCHITECTURE.md`, `API.md`, `TESTING.md`.
Decision: the canonical M00.6 set is the 4 frozen foundation docs
(`CONFIGURATION`, `COMPOSE`, `HEALTH`, `LOGGING`) plus foundation versions of
the 4 README-planned docs created here (honest status, spec links, owning
modules for the unbuilt remainder) plus foundation versions of the 3 spec-§44
docs (`ARCHITECTURE.md`, `API.md`, `TESTING.md`) added in the 90+ hardening
pass so spec §44 has no gap. "M00.6/M22" means: M00.6 creates the
foundation skeleton; M22 owns full demo hardening (`demo.sh --check`,
rehearsals, evidence package) and M16 owns the eval runner. No full
implementation is claimed in foundation docs — every unbuilt remainder is
marked PLANNED with its owning module.

## ADR-007 — M00 90+ hardening (this pass, owns M00.1–M00.7 lift to ≥90)

Decision: additive hardening only — no frozen-body changes (`/healthz` body
byte-frozen, `Settings` trust boundary preserved, liveness vs readiness split
preserved). New tests in new files where the original file is frozen; edits to
frozen docs/compose/logging are minimal, reviewed, and re-tested. Registry
status flips only on human APPROVE.
Spec: §43–§46. Detail: `docs/TESTING.md`, `docs/ARCHITECTURE.md`, `docs/API.md`.

## PLANNED ADR slots (not taken in M00.6)

- FSM-primary over SuperFlow mirror (owning module: orchestration phase).
- 4-agent split plus session_id=incident_id (M13).
- No-pgvector retrieval freeze: Classic KB plus local pre-digestion (M12/M13).
- RAI per-agent placement, policy engine as authz boundary (M06/M13).
- HMAC token crypto shape: scope hash, nonce burn, TTL (M07).
- mock-default executor with docker/kind tiers (M08).
