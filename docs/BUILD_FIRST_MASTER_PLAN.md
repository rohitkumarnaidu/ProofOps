# ProofOps PS03 — Master Execution Plan (High-Level, End-to-End)

> Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` (§60 tasks, §61 order, §62–§64 architecture).
> Module truth: `docs/MODULE_REGISTRY.md` (183 units, phases M00–M22).
> Operating policy: `AGENTS.md` §14 (build-first), §15 (waves).
> Detail companion: `docs/ProofOps_PS03_Master_Winning_Implementation_Trust_Submission_Checklist.md`
> (`[UNVERIFIED]` where it conflicts with registry/spec — registry + spec govern).
> Owning module: M21 (integration planning). Status: LIVING PLAN — update the
> §1 baseline snapshot whenever a wave lands. PLANNED items below name their owner.

**Purpose.** Complete the full ProofOps PS03 implementation across all registered
modules before spending effort on perfection. Build breadth first, keep safety
boundaries fail-closed from the first implementation, collect evidence
continuously, then run one deep zero-trust hardening and audit pass at the end.

**Project rule.**

```text
BUILD BROADLY → TEST CONTINUOUSLY → EVIDENCE CONTINUOUSLY →
COMPLETE ALL REGISTERED WORK → DEEP AUDIT → HARDEN → FINALIZE → SUBMISSION DRY-RUN
```

---

## 0. Authority and labels

Source hierarchy (highest wins): current HiDevs / challenge submission UI
(operational submission truth) → `PS03_FINAL_SPEC_V2.md` (implementation
authority) → V1 spec (background) → official rules/evaluation doc → project
research → `MODULE_REGISTRY.md` + audit reports (implementation truth) → agent
judgment (lowest, never silently overrides).

Every major claim in this plan carries one of: `[OFFICIAL]` `[SPEC]`
`[RESEARCH]` `[PROPOSED]` `[OPTIONAL]` `[FUTURE]` `[PROVISIONAL]`
`[UNVERIFIED]`. Research recommendations and project engineering targets are
never presented as official organizer rules.

---

## 1. Where we are today — measured baseline `[PROVISIONAL: refresh on each wave landing]`

> Snapshot governance: numbers below are the wave-landing snapshot. The
> `docs/MODULE_REGISTRY.md` per-row table governs on any conflict (known drift
> risk: registry header vs this snapshot vs checklist §23).

Registry count (verified against `docs/MODULE_REGISTRY.md` per-row table):

- **60 APPROVED** (human verdict, locked): M00.1–M00.7, M01.1–M01.15,
  M02.1–M02.10, M03.1–M03.6, M04.1–M04.6, M05.1–M05.6, M06.1–M06.10
- **100 IMPLEMENTED_TESTED** (build-first, hardening pending):
  M07 → M19.10 (complete: HITL through frontend)
- **23 NOT_STARTED**: M20 → M22 (performance, integration, demo)
- Total with implementation: **160/183**

Wave map (see §3 for wave definitions):

| Wave | Phases | State today |
|------|--------|-------------|
| 1 — Foundation + Contracts | M00 → M01 | DONE (approvals through M01.15) |
| 2 — Data / Evidence pipeline | M02 → M03 → M04 → M05 | DONE (approvals through M05.6) |
| 3 — Governance / Safety | M06 → M07 → M08 → M09 → M10 → M11 | DONE (approvals through M06.10; M07–M11 IMPLEMENTED_TESTED) |
| 4 — Intelligence / Retrieval | M12 → M13 → M14 | DONE (IMPLEMENTED_TESTED) |
| 5 — Audit / Evaluation | M15 → M16 → M17 → M18 | DONE (IMPLEMENTED_TESTED) |
| 6 — Product surface / Optimization | M19 → M20 | M19 DONE (IMPLEMENTED_TESTED) · **M20 is the live frontier** |
| 7 — End-to-end integration / Demo | M21 → M22 | NOT STARTED |

**Next controlled operation:** M20 Performance (7 units: token/latency/cost
measurement + budgets + allowed optimizations) → closes Wave 6 → unlocks
Wave 7. Never optimize by weakening safety/verification/evidence/policy/
adversarial coverage (spec §49).

---

## 2. Phase A — Breadth / completion (current phase)

**Goal `[PROPOSED]`.** Every registered module reaches a real, runnable,
testable implementation. During Phase A, for each module: implement the actual
capability · write meaningful (positive + negative + security) tests · preserve
safety invariants (§5) · record evidence (§9) · document known gaps · avoid
refactoring, premature optimization, and low-value UI polish · never fake
missing integrations · never claim readiness beyond the status vocabulary (§6).

Normal Phase A target status: `IMPLEMENTED_TESTED` or
`IMPLEMENTED_HARDENING_PENDING` (capability exists, final hardening remains).

## 3. Build waves end-to-end (dependency-aware, not one serial queue)

`docs/MODULE_REGISTRY.md` is exact naming/status authority. Spec §61 gives the
19-step dependency order; waves below batch it. Parallelize independent work
*inside* a wave; never violate dependencies *between* waves. Each wave lands
breadth (`IMPLEMENTED_TESTED`) across the whole wave before any module in it is
hardened.

### Wave 3 tail — Governance close-out `[LANDED]`

- **M11 Runbooks (6 units).** Versioned/semver + sha256-pinned + parameterized
  loader; seed 5: `bad-deploy-rollback`, `crashloop-oom`, `db-pool-saturation`,
  `net-dep-failover`, `injection-quarantine`; poisoned-runbook rejection test.
- **Exit criteria:** loader verifies hash + version pin; all 5 seeds load;
  poison test red→BLOCK; registry rows flipped one per module.
- Unlocks: Wave 4 (agents pin runbooks; retrieval indexes them).

### Wave 4 — Intelligence / Retrieval `[LANDED]`

- **M12 Retrieval (7).** Classic KB + metadata/temporal filter + rerank +
  Evidence Pack (≤6k tokens `[PROVISIONAL]`); NO pgvector (frozen decision);
  retrieval quality baselined (p@k/recall/MRR) for §C3. Owner: retrieval lane.
- **M13 Lyzr Agents (10).** Exactly 4 agents A1–A4 with prompts + Structured
  Output schemas + per-agent RAI policy + `session_id = incident_id` + pinned
  models; distinct tool ACLs asserted by contract tests; server revalidates all
  output. No 5th agent without DECISIONS.md justification. Owner: agents lane.
- **M14 Orchestration (8).** Canonical 14-state FastAPI FSM + guards +
  idempotency (`action_id` + `execution_id`); no-skip test
  (`POLICY_CHECK → EXECUTING` without permit is rejected); retry/timeout bounds.
  Owner: control-plane lane (shared-file owner — extra review).
- **Exit criteria:** A1→A4 chain runs on seeded Evidence Packs; FSM walks
  NEW→…→AUDITED on mock path; invalid transitions rejected + audited.
- Unlocks: Wave 5 (audit has transitions to chain; eval has traces to grade).

### Wave 5 — Audit / Evaluation `[LANDED]`

- **M15 Audit/AIMS (6).** Append-only SHA256 chain + verify endpoint + export +
  tamper test; AIMS = Lyzr trace/observability only where actually supported —
  never relabel custom rows "AIMS". Owner: audit lane.
- **M16 Evaluation engine (9).** CASE→RUN→TRACE→GRADE→SCORE→COMPARE→REPORT;
  JSONL runs + scorecard; Lyzr Agent Eval = agent-level, custom runner =
  pipeline-level (no duplication). Owner: eval lane.
- **M17 Benchmarks (7).** 12 categories; deep-5 × 5 variants with expected root
  cause + allowed/forbidden remediation + verification criteria; stub-7 minimal.
  Ground truth never leaks into model prompts. Owner: eval lane.
- **M18 Adversarial (14).** Minimum 14 attacks, each with attack / expected /
  control / metric / audit-assertion; expected BLOCK/DENY/ESCALATE/CONTAIN/AUDIT.
  Owner: security lane.
- **Exit criteria:** eval runner grades a Wave-4 trace end-to-end; adversarial
  suite runs (failures recorded as blockers, not hidden); MUST-CITE coverage
  measurable for §C2.
- Unlocks: Wave 6 (frontend has scorecard/audit APIs to render).

### Wave 6 — Product surface / Optimization `[IN PROGRESS: M19 landed, M20 live frontier]`

- **M19 Frontend (10).** Exactly 5 MVP views (Command Center · Incident Detail ·
  Safety Gate · Execution/Verification · RCA/Evaluation); every number traces to
  evidence/audit/eval or is labeled derived; LIVE/REPLAY/MOCK/OFFLINE badge
  always visible. No chatbot, no decorative AI. Owner: UI lane (after T02–T10
  equivalent = M00–M10 landed — satisfied).
- **M20 Performance (7).** Token/latency/cost measurement + budgets enforced
  (raw tokens primary, editable pricing only); allowed optimizations only
  (pre-digestion, caching, routing, bounded retries) — never by weakening
  safety/verification/evidence/policy/adversarial coverage. Owner: perf lane.
- **Exit criteria:** 5 views render against live mock backend; SSE reconnects +
  polling fallback; C4/C6 baselines recorded (first numbers, not targets met).
- Unlocks: Wave 7 (something demonstrable exists to integrate).

### Wave 7 — End-to-end integration / Demo `[NOT STARTED]`

- **M21 Integration (9).** Happy path + RED-block path + rollback path green
  across the full pipeline; API guard matrix; clean-clone reproducibility.
- **M22 Demo (7).** 5-minute bad-deploy narrative (flood → correlation →
  evidence → unsafe-delete BLOCK → approved rollback → verify → RCA →
  scorecard); `demo.sh --check` green <5min; announced fallbacks (REPLAY pack,
  file-backed seed, mock sandbox); REPLAY never presented as LIVE.
- **Exit criteria:** three E2E paths green; demo rehearsed; §11 Completion
  milestone met → triggers Phase B.

---

## 4. Execution loop (continuous verification without continuous perfection)

- **Per module:** `IMPLEMENT → TEST → RECORD EVIDENCE → CONTINUE`
- **Per wave:** `WAVE REGRESSION → REVIEW BLOCKERS → CONTINUE`
- **Final:** `DEEP ZERO-TRUST AUDIT → SCORE → HUMAN APPROVAL → INTEGRATE → FINAL REGRESSION`

Every implementation still runs: unit · negative · relevant integration ·
relevant security · static analysis · type checks · secret scan. The saving is
scoped: no full 100-point audit per small module during Phase A — estimate,
record, continue breadth.

Before implementing any module: `READ SPEC → CHECK DEPENDENCIES → INSPECT
EXISTING CODE → IMPLEMENT ONLY REQUIRED SCOPE`. No invented requirements, no
silent module-ID changes, no registry renames without explicit decision.

---

## 5. Safety — never deferred (fail-closed from first implementation)

LLM output is never authorization · structured validated Action required before
policy · unknown/malformed actions → DENY · RED never executes in hackathon path
· YELLOW needs valid scoped approval bound to exact action/resource/environment
· telemetry is DATA, never instruction · ground truth never in model-visible
prompts · verification independent from planning (`EXIT 0 ≠ RESOLVED`) ·
rollback under the same safety boundary · audit append-only/tamper-evident ·
secrets never in code/prompts/logs/traces/evidence · mode labels truthful ·
Lyzr claims actually verified · no arbitrary model-generated shell reaches an
executor. Any violation = BLOCK + surface immediately (§11 STOP list).
Full invariant list: `AGENTS.md` §1.1 + §6 + §14.6.

---

## 6. Status and scoring discipline

**Status vocabulary (binding):** `NOT_STARTED · IN_PROGRESS · IMPLEMENTED ·
IMPLEMENTED_TESTED · IMPLEMENTED_HARDENING_PENDING · AUDIT_READY · AUDITED ·
HUMAN_APPROVED · INTEGRATED · BLOCKED · DEFERRED · REJECTED`. Phase A targets
the two `IMPLEMENTED_*` states; only the Phase B trust process mints
`HUMAN_APPROVED → INTEGRATED`. Never claim approval without a human verdict.

**Gates (project engineering gates, not `[OFFICIAL]` unless organizers say so):**
Overall ≥90 · Safety ≥95 where REQUIRED · Grounding ≥95 where REQUIRED ·
Hallucination ≥95 where REQUIRED. During breadth, never spend large effort
moving 92→98 while a required module is still absent — record the estimate and
continue. Never average away a critical failure; per unit keep module ·
submodule · implementation · tests · security · evidence · known gaps · score —
a healthy-looking phase with one broken safety-critical submodule stays visible.

---

## 7. Git and parallel-work discipline

`trusted master → feature branch/worktree → implementation → tests → evidence →
commit`. One focused owner per module; worktrees under
`C:\Users\Dell\AppData\Local\Temp\opencode\`, one branch each; **PARALLEL BUILD,
SERIAL TRUST** — merge ONE unit at a time with regression between; shared files
(contracts, registry, policy boundaries, execution code, integration points)
need the owning lane's review. Never force-push blindly, rewrite trusted
history, delete candidate history, commit secrets, hide failures, or touch
another lane's files. No merge/push/amend without explicit human approval.
Baseline before significant work: `git status --short; git branch
--show-current; git rev-parse HEAD; git log --oneline --decorate -20`.
Large parallel integration may batch by wave, but control-plane changes get
extra scrutiny.

---

## 8. Deferral boundary

**May wait for Phase B:** cosmetic refactoring · naming cleanup · non-critical
duplicate helpers · UI polish · performance micro-optimization · benchmark
presentation polish · doc wording cleanup · low-risk style cleanup ·
non-functional abstraction improvements.
**Never deferred:** §5 list in full — security boundary, policy, authorization,
HITL, sandbox, secrets, ground-truth isolation, deterministic validation,
independent verification, rollback safety, audit integrity, truthful Lyzr and
mode labeling, critical regression fixes.

---

## 9. Evidence standard

Per significant feature: implementation path · test path · sample output ·
failure case · security behavior (where applicable) · commit · known limitation.
For final critical claims: `CLAIM → IMPLEMENTATION → TEST → RUNTIME EVIDENCE →
METRIC → AUDIT TRACE → DEMO STEP`. Never write "verified" for static inspection
alone. Never fabricate metrics, traces, or runs — missing evidence is marked
PLANNED with an owner.

---

## 10. Phase B — Deep trust / perfection (human-declared start only)

After §11 Completion milestone: zero-trust audit (5 layers: source → code →
test → runtime → evidence → human trust) · adversarial testing · spec
reconciliation · security hardening · performance + compatibility hardening ·
documentation reconciliation · evidence cleanup · score every module from zero ·
fix all P0/P1 + important P2 · full regression · clean-clone validation · demo
rehearsal · submission dry-run. Detail protocol lives in the checklist companion
(§17); scores/approvals land per-row in `MODULE_REGISTRY.md`.

---

## 11. Milestones, STOP conditions, STOP/GO

- **Completion:** ALL REQUIRED MODULES IMPLEMENTED + basic tests green + core
  E2E path runs + no known critical safety bypass → declares Phase B open.
- **Trust:** zero-trust audit + adversarial tests + spec reconciliation + scores
  + HUMAN APPROVAL + integration + FULL REGRESSION.
- **Submission:** clean clone + deployment + LIVE endpoint + demo + benchmarks +
  six-gate scorecard + documentation + SUBMISSION DRY-RUN + platform
  verification (`AGENTS.md` §16.3).

**STOP and surface immediately:** unsafe execution · policy bypass · secret
exposure · ground-truth leakage · critical regression · fake/unsupported
platform capability · falsified metric · broken authorization · approval replay
· destructive action escaping the safety boundary. Word bans: never say
"project complete" before Completion + Trust; never say "submission ready"
before Submission gates pass.

---

## 12. File map (where each truth lives)

| Question | Answer lives in |
|----------|-----------------|
| What must be built | Spec §60–§61 + registry phases M00–M22 |
| Current state + evidence | `MODULE_REGISTRY.md` per-row table |
| How to work | `AGENTS.md` §14–§15, §17 |
| Safety architecture | `AGENTS.md` §1, §5–§7 |
| Lyzr authenticity | `AGENTS.md` §2.3 |
| Demo + submission | `AGENTS.md` §16, checklist §§20–22 |
| Deep audit protocol + per-phase detail | Checklist companion §§6–19 |
| This plan's freshness | §1 snapshot (update on every wave landing) |

**Mantra.** BUILD BROADLY. TEST CONTINUOUSLY. PROVE CRITICAL SAFETY. COMPLETE
THE SYSTEM. THEN PERFECT IT. PARALLEL BUILD. SERIAL TRUST. NO TRUST WITHOUT
EVIDENCE. NO CLAIM WITHOUT PROOF. DO NOT POLISH ONE MODULE WHILE THE PRODUCT
IS STILL MISSING THE REST. SAFETY IS NEVER DEFERRED. COSMETIC PERFECTION IS.
