# ProofOps — PS03 Master Winning Implementation, Zero-Trust & Submission Checklist

> **Project:** ProofOps — Evidence-Grounded Autonomous Incident Commander  
> **Challenge:** AI Quest: Beyond the Wrapper — 2026 · HiDevs × Lyzr  
> **Problem Statement:** PS03 — Enterprise Cloud Incident Triage & Runbook Remediation Agent  
> **Operating thesis:** **THE AGENT MAY REASON. THE CONTROL PLANE DECIDES. THE SANDBOX CONTAINS. VERIFICATION PROVES. AIMS RECORDS.**  
> **Security invariant:** **THE LLM IS NOT THE SECURITY BOUNDARY.**

---

## 0. Document Status & Authority

**Purpose:** This is the master control checklist for building, auditing, validating, integrating, documenting, demonstrating, deploying, benchmarking, and submitting ProofOps.

**Important truth rule:** This checklist cannot guarantee a judging outcome. It can guarantee only a disciplined engineering process: every claimed capability must have implementation evidence, tests, adversarial evidence where applicable, measured results, traceability, and human approval before trust is granted.

### 0.1 Source hierarchy — never silently override a higher source

1. **Current official HiDevs / challenge submission UI and current organizer instructions** — operational source of truth for submission state, current limits, required fields, and any late changes.
2. **`PS03_FINAL_SPEC_V2.md` / `PS03_FINAL_SPEC_V2(1).md`** — authoritative implementation specification for this project; it supersedes V1 Part B where conflicts exist.
3. **`PS03_FINAL_SPEC.md` / `PS03_FINAL_SPEC(1).md`** — background, research, and prior implementation specification where V2 does not conflict.
4. **Official PS03 rules/evaluation document** — official problem requirements, rubric, repository expectations, and stated MVP/stretch scope.
5. **Project research reports** — engineering strategy, winning patterns, competitive analysis, threat models, and recommended controls.
6. **Project module registry and audit reports** — current implementation state, trusted commits, scores, residual findings, and human approval state.

### 0.2 Truth labels

Every major requirement, design statement, README claim, UI claim, demo statement, and architecture diagram must be classifiable as one of:

- `[OFFICIAL]` — explicitly required by organizer materials.
- `[RESEARCH]` — evidence-backed engineering recommendation.
- `[PROPOSED]` — our design choice.
- `[OPTIONAL]` — stretch/future extension that is not baseline.
- `[FUTURE]` — post-hackathon capability.
- `[PROVISIONAL]` — numerical engineering target pending baseline measurement/revision.
- `[UNVERIFIED]` — capability not confirmed; never present as completed.

**Rule:** Never present `[RESEARCH]`, `[PROPOSED]`, `[OPTIONAL]`, `[FUTURE]`, or `[PROVISIONAL]` as an official organizer requirement.

---

# 1. Non-Negotiable Engineering Laws

## 1.1 Core laws

- [ ] **Agent reasoning is untrusted.** Treat every model output as a proposal.
- [ ] **Control-plane code owns authorization.** The LLM never decides whether a mutation is allowed.
- [ ] **No arbitrary shell execution.** No LLM-generated shell string may directly reach an executor.
- [ ] **All mutations are structured actions.** Schema-validate before policy evaluation.
- [ ] **Policy is fail-closed.** Any policy error, unknown action, malformed action, missing context, or inconsistent state must block/escalate.
- [ ] **RED actions do not execute in the hackathon path.** No demo break-glass execution.
- [ ] **YELLOW actions require a valid scoped human approval token.**
- [ ] **Verification is independent from planning.** Planner output cannot prove its own success.
- [ ] **Execution success is not incident resolution.** Only deterministic verification can declare outcome.
- [ ] **RCA publication is evidence-gated.** Unsupported must-cite claims block publication.
- [ ] **Audit is append-only and tamper-evident.** Every critical transition produces an event.
- [ ] **Ground truth is never leaked into model prompts.**
- [ ] **Telemetry is DATA, never instructions.**
- [ ] **All loops are bounded.** No runaway replanning or tool fan-out.
- [ ] **Cost optimization must never remove safety, evidence, or verification.**
- [ ] **Demo mode must always be truthful.** LIVE, REPLAY, MOCK, and OFFLINE are visibly distinct.

## 1.2 Engineering process law

> **BUILD → SELF-AUDIT → ATTACK → VERIFY → MEASURE → SCORE → HUMAN REVIEW → APPROVE → INTEGRATE → REGRESSION → MERGE → PUSH → VERIFY**

Never replace this with:

> BUILD → PERFECT → MERGE

---

# 2. Parallel Build / Serial Trust Governance

## 2.1 Parallel implementation rule

When a wave is marked **PARALLEL**, use multiple OpenCode agents/sessions/worktrees simultaneously.

- [ ] One agent/worktree owns one scoped module or module cluster.
- [ ] Every branch starts from the **current trusted `origin/master`**, never from a stale branch.
- [ ] Agents do not assume another branch has already fixed a defect.
- [ ] Agents do not silently edit shared integration files.
- [ ] Integration ownership is explicit.
- [ ] Old failed candidates are preserved for forensic history; do not rewrite their history.

## 2.2 Serial trust rule

Even when build is parallel, trust is serial.

- [ ] Each candidate receives an independent zero-trust audit.
- [ ] Score from zero against the current trusted baseline.
- [ ] Run positive tests.
- [ ] Run negative/security tests.
- [ ] Run integration tests.
- [ ] Run performance tests where applicable.
- [ ] Inspect actual diff and dependency surface.
- [ ] Produce evidence package.
- [ ] Human reviews.
- [ ] Human chooses `APPROVE`, `REJECT`, or `FIX REQUIRED`.
- [ ] Only approved modules can enter integration.
- [ ] Only one integration merge at a time.
- [ ] Run full regression between merges when shared contracts/control plane are affected.

## 2.3 Git laws

- [ ] `git fetch origin --prune` before branch creation.
- [ ] Resolve `origin/master` explicitly.
- [ ] Confirm branch merge-base with trusted master.
- [ ] Preserve old candidate branches.
- [ ] No blind `git push --force`.
- [ ] Any required force update uses `--force-with-lease` only after explicit reconciliation.
- [ ] No history rewrite.
- [ ] No silent fixes after scoring.
- [ ] No score inflation.
- [ ] No merge before human approval.
- [ ] No push before merge verification.
- [ ] No next-module work while the previous module is still blocked.

---

# 3. Competition Requirements Master Gate

## 3.1 Official PS03 outcome

ProofOps must visibly and reproducibly demonstrate:

- [ ] Alert ingestion.
- [ ] Alert triage and deduplication.
- [ ] Severity P1–P4.
- [ ] Root-cause diagnosis using mock logs/traces/metrics.
- [ ] Governed remediation.
- [ ] Human approval for risky/destructive actions.
- [ ] Safe controlled execution.
- [ ] Automated blameless postmortem.
- [ ] Chronological execution/audit history.
- [ ] Lyzr-powered agent workflow.
- [ ] Lyzr Safe AI used authentically.
- [ ] AIMS used where supported, without falsely labeling custom logging as AIMS.
- [ ] Mock Prometheus/Kubernetes environment.

## 3.2 Rubric coverage

### 30% — Lyzr Agent Orchestration

- [ ] Distinct agent responsibilities are visible.
- [ ] Real Lyzr agent definitions exist.
- [ ] Actual agent calls are observable.
- [ ] Tool authorization is explicit.
- [ ] Session/incident state persists correctly.
- [ ] State transitions are explicit and tested.
- [ ] Failure handling is demonstrated.
- [ ] Agent outputs use structured schemas.
- [ ] Lyzr integration is not decorative.

### 30% — DevOps Safety & Reliability

- [ ] Diagnosis is evidence grounded.
- [ ] Dangerous shell hallucination is prevented.
- [ ] Structured action is validated.
- [ ] Policy is deterministic and fail-closed.
- [ ] RED is blocked.
- [ ] YELLOW is HITL gated.
- [ ] Approval is single-use, scoped, time-bound, and identity-bound.
- [ ] Execution occurs in a controlled sandbox.
- [ ] Verification is independent.
- [ ] Rollback is demonstrated.
- [ ] All safety events are audited.

### 20% — Code Quality & Architecture

- [ ] Clean modular repository.
- [ ] Mock telemetry generator.
- [ ] Docker/Compose path works.
- [ ] Typed contracts are used.
- [ ] Tests cover critical controls.
- [ ] Documentation is reproducible.
- [ ] Secrets are absent from repository.

### 20% — SRE Experience & UI

- [ ] Real-time command center.
- [ ] Log/event streaming.
- [ ] Action logs.
- [ ] Evidence-linked investigation.
- [ ] Safety gate is visible.
- [ ] Before/after state diff is visible.
- [ ] Verification outcome is visible.
- [ ] RCA and evaluation scorecard are visible.

---

# 4. Final Architecture Freeze

## 4.1 Canonical execution architecture

```text
Telemetry Generator / Simulation
        ↓
Normalizer / Pre-digestor [CUSTOM]
        ↓
Correlator [CUSTOM]
        ↓
A1 Triage [LYZR]
        ↓
Evidence Pack + Classic KB [CUSTOM + LYZR]
        ↓
A2 Diagnostic [LYZR]
        ↓
Hypothesis Test [CUSTOM + A2]
        ↓
Pinned Runbook
        ↓
A3 Remediation Planner [LYZR]
        ↓
Structured Action
        ↓
Validator [CUSTOM]
        ↓
Policy Engine [CUSTOM]
        ↓
RAI / Safe AI [LYZR, semantic guard]
        ↓
HITL Gate [CUSTOM]
        ↓
Sandbox Executor [CUSTOM]
        ↓
Independent Verifier [CUSTOM]
        ↓
Rollback / Escalate
        ↓
A4 RCA Reporter [LYZR]
        ↓
Hash Audit + AIMS Trace
        ↓
Evaluation Engine
        ↓
UI Scorecard
```

## 4.2 Lyzr truth model

### LYZR-NATIVE

- [ ] Agent API / ADK.
- [ ] Four specialized agents.
- [ ] Structured Output.
- [ ] RAI / `PS03-Governed` on agent interactions.
- [ ] Classic KB for runbooks/history.
- [ ] Cognis/session memory where configured.
- [ ] Global Context for organization rules if used.
- [ ] `chat` / `stream-chat` where used.
- [ ] Lyzr trace/evaluation assistance where available.

### CUSTOM-DETERMINISTIC

- [ ] FastAPI control plane.
- [ ] FSM.
- [ ] Normalizer.
- [ ] Correlator.
- [ ] Pre-digestor/retriever.
- [ ] Action validator.
- [ ] Policy engine.
- [ ] HMAC HITL service.
- [ ] Sandbox/executor.
- [ ] Independent verifier.
- [ ] Rollback controller.
- [ ] SHA256 audit chain.
- [ ] Pipeline-level evaluation engine.
- [ ] Control-plane SSE hub.

### SIMULATED

- [ ] Synthetic telemetry.
- [ ] Mock Kubernetes/state.
- [ ] Mock executor.

### FUTURE / OPTIONAL

- [ ] Kind live sandbox.
- [ ] Voice briefing.
- [ ] Custom decision graph visualization.
- [ ] Live vendor integrations.
- [ ] Multi-cluster.
- [ ] SSO/SIEM.
- [ ] gVisor/Kata/Firecracker-class stronger isolation.

## 4.3 Orchestration conflict resolution — mandatory verification

The supplied materials contain an important conflict: older research/brief wording describes **Automata** as the core orchestrator, while the authoritative V2 implementation specification explicitly freezes **custom FastAPI FSM as primary**, permits **SuperFlow as an optional mirror**, and bans the experimental `lyzr-automata` package as the control plane. This checklist therefore does not assume either path.

- [ ] Verify the current organizer evaluator expectation for Automata/orchestration before final submission.
- [ ] Verify the current Lyzr workspace capabilities.
- [ ] Primary repo implementation remains the V2 canonical FastAPI FSM unless current official instructions require an honestly supported alternative.
- [ ] **SuperFlow** may be implemented only as an optional mirror when practical and verifiable.
- [ ] **Automata** must never be faked, renamed, or represented by the custom FSM.
- [ ] Record the final decision and evidence in `docs/DECISIONS.md`.
- [ ] Update README/demo truth labels after the capability check.

## 4.4 Lyzr capability verification gate

Because older source materials describe Automata as core while the final V2 specification explicitly bans `lyzr-automata` as the control plane and freezes a custom FastAPI FSM as canonical, **do not resolve this by assumption**.

- [ ] Check current Lyzr/HiDevs capability documentation.
- [ ] Check current challenge evaluator expectations.
- [ ] Check the actual project account/workspace capability.
- [ ] If supported and required, integrate it honestly and test it.
- [ ] If unsupported or not required by the current evaluator, use the V2 FSM decision and document the limitation.
- [ ] Never fake an Automata graph, screenshot, trace, or execution.
- [ ] Never label the custom FSM “Automata”.
- [ ] Record the decision in `DECISIONS.md`.

---

# 5. Repository Freeze

**Canonical local deployment command:** `docker compose up --build`

Required top-level layout:

```text
/agents
/frontend
/backend
/policies
/runbooks
/telemetry
/tools
/evaluation
/benchmarks
/tests
/docs
/scripts
Dockerfile
README.md
docker-compose.yml
.env.example
```

## 5.1 Required documentation

- [ ] `README.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/API.md`
- [ ] `docs/SECURITY.md`
- [ ] `docs/EVALUATION.md`
- [ ] `docs/DEMO.md`
- [ ] `docs/TESTING.md`
- [ ] `docs/DECISIONS.md`

## 5.2 README completeness

- [ ] Problem statement.
- [ ] Product thesis.
- [ ] Architecture diagram.
- [ ] Agent graph.
- [ ] Lyzr-native vs custom vs simulated vs future table.
- [ ] Setup instructions.
- [ ] Environment variables.
- [ ] One-command run.
- [ ] Tests.
- [ ] Demo script.
- [ ] Benchmark results.
- [ ] Six-gate scorecard.
- [ ] Cost table.
- [ ] Latency table.
- [ ] Known limitations.
- [ ] Hackathon-vs-enterprise distinction.
- [ ] Attribution/inspirations.
- [ ] Live endpoint.
- [ ] Repository link.

## 5.3 Secret and environment hygiene

- [ ] No Lyzr/API keys committed.
- [ ] `.env.example` includes required variables.
- [ ] Environment variables match code usage.
- [ ] Demo secrets are synthetic only.
- [ ] Secrets do not enter prompts.
- [ ] Secrets do not enter logs.
- [ ] Secret scanning passes.

---

# 6. Master Module Roadmap — 23 Phases / 183 Module Slots

> **Important:** The current repository `docs/MODULE_REGISTRY.md` is the canonical naming authority for the exact module titles. Do not invent, rename, or silently renumber repository modules. The phase counts below are the project plan counts.

| Phase | Area | Module count | Trust focus | Dependency gate |
|---|---|---:|---|---|
| M00 | Foundation | 7 | reproducibility/base | none |
| M01 | Contracts | 15 | schemas/invariants | M00 |
| M02 | Telemetry | 10 | deterministic evidence generation | M00+M01 |
| M03 | Normalization | 6 | canonicalization | M01+M02 |
| M04 | Correlation | 6 | dedup/severity/topology linkage | M03 |
| M05 | Evidence | 6 | groundedness/evidence provenance | M04 |
| M06 | Policy/Safety | 10 | fail-closed authorization | M05 |
| M07 | HITL | 8 | approval security | M06 |
| M08 | Sandbox | 6 | containment/zero-diff | M06+M07 |
| M09 | Verification | 8 | independent outcome proof | M08 |
| M10 | Rollback | 5 | failure recovery | M09 |
| M11 | Runbooks | 6 | pinned governed procedures | M05+M06 |
| M12 | Retrieval | 7 | p@k/grounding | M05+M11 |
| M13 | Lyzr Agents | 10 | real agent value/hallucination | M12 |
| M14 | Orchestration | 8 | FSM/state/idempotency | M06–M13 |
| M15 | Audit/AIMS | 6 | chronological proof | M14 |
| M16 | Evaluation | 9 | repeatable grading | M12–M15 |
| M17 | Benchmarks | 7 | golden scenarios | M16 |
| M18 | Adversarial | 10 | attack resistance | M06–M17 |
| M19 | Frontend | 10 | SRE UX/realtime | M14–M18 |
| M20 | Performance | 7 | latency/cost/throughput | M16–M19 |
| M21 | Integration | 9 | end-to-end system proof | M14–M20 |
| M22 | Demo | 7 | submission/demo reliability | M21 |
| **TOTAL** | | **183** | | |

## 6.1 Dependency law

- [ ] Never start a dependent phase before its dependency gate is approved.
- [ ] Build waves may run in parallel only when their inputs are frozen.
- [ ] Cross-module integration happens after human approvals.
- [ ] M03 remains locked until M01+M02 are fully trusted/integrated.

---

# 7. Universal Module Trust Card

Apply this to **every single module**, including submodules and sub-submodules.

### A. Scope
- [ ] Module purpose explicitly documented.
- [ ] Inputs documented.
- [ ] Outputs documented.
- [ ] Dependencies documented.
- [ ] Files owned by module explicitly listed.
- [ ] Shared files protected.

### B. Implementation
- [ ] Happy path implemented.
- [ ] Edge cases implemented.
- [ ] Failure path implemented.
- [ ] Timeout behavior implemented.
- [ ] Retry behavior bounded.
- [ ] Idempotency implemented where mutation exists.
- [ ] Observability emitted.

### C. Positive tests
- [ ] Valid minimum input.
- [ ] Valid nominal input.
- [ ] Valid boundary input.
- [ ] Valid maximum input.
- [ ] Expected output verified.

### D. Negative tests
- [ ] Empty input.
- [ ] Wrong type.
- [ ] Missing required field.
- [ ] Extra field.
- [ ] Oversized input.
- [ ] Malformed identifier.
- [ ] Invalid enum.
- [ ] Invalid state transition.
- [ ] Duplicate request.
- [ ] Stale request.
- [ ] Unauthorized request.
- [ ] Adversarial payload where relevant.

### E. Security
- [ ] Threat model entry exists.
- [ ] Attack path tested.
- [ ] Fail-closed behavior tested.
- [ ] Sensitive data handling reviewed.
- [ ] Injection resistance reviewed.
- [ ] Authorization checked server-side.
- [ ] Audit event emitted on block/failure.

### F. Integration
- [ ] Backward compatibility checked.
- [ ] Serialization checked.
- [ ] IDs compatible.
- [ ] No circular imports.
- [ ] No duplicate contract definitions.
- [ ] No cross-module state leakage.
- [ ] Full dependent suite passes.

### G. Performance
- [ ] Relevant latency measured.
- [ ] Relevant memory/cost measured.
- [ ] Baseline recorded.
- [ ] Optimized result recorded if optimization is claimed.
- [ ] Sample size recorded.

### H. Evidence package
- [ ] Diff captured.
- [ ] Test command/output captured.
- [ ] Negative/security output captured.
- [ ] Performance result captured.
- [ ] Audit trace captured.
- [ ] Metric/result linked to evidence.
- [ ] Limitations explicitly recorded.

### I. Score
Use the project’s 10 dimensions:

| Dimension | Max |
|---|---:|
| Functional correctness | 20 |
| Test / verification | 15 |
| Security | 15 |
| Reliability | 10 |
| Specification | 10 |
| Integration | 10 |
| Performance | 5 |
| Observability | 5 |
| Maintainability | 5 |
| Hackathon value | 5 |
| **Total** | **100** |

Gate:

- [ ] Overall ≥90.
- [ ] Safety ≥95 for safety-critical modules.
- [ ] Grounding ≥95 where evidence/retrieval/agents own trust.
- [ ] Hallucination ≥95 for agent modules.
- [ ] No P0.
- [ ] All required tests green.
- [ ] Required metrics reported.
- [ ] Human APPROVE.

---

# 8. Master Implementation Task Map — T01 to T21

These are the authoritative high-level implementation tasks from the supplied final specification. Each task is expanded by the phase/module sections below and must be independently tested and trusted.

- [ ] **T01 — Repository + Compose:** repository tree, Compose, Docker, healthz, clean start.
- [ ] **T02 — Contracts:** Action/Evidence/Approval/Audit and invalid fixtures.
- [ ] **T03 — Telemetry:** deterministic generator, deep-5 seeds, seed/hash log.
- [ ] **T04 — Policy:** policy engine, risk matrix, bundle, 40+ policy tests.
- [ ] **T05 — Validator:** schema/parameter allowlist; shell/DROP/meta-command rejection before policy.
- [ ] **T06 — Approval:** HMAC token issuance/verification, replay/tamper/expiry/identity/scope tests.
- [ ] **T07 — Mock Sandbox:** stateful transitions, zero-diff blocked actions.
- [ ] **T08 — Docker Executor:** allowlisted mutations, non-privileged/network/secret restrictions, RED refusal.
- [ ] **T09 — Verifier:** all deterministic verdicts, bad-SLO despite exit-0 failure test.
- [ ] **T10 — Rollback:** one automatic rollback, re-verification, escalation.
- [ ] **T11 — Runbooks:** five deep runbooks, loader, version pinning, hashes, poisoning tests.
- [ ] **T12 — Retrieval:** Lyzr Classic KB, pre-digestion, Evidence Pack, p@k evaluation.
- [ ] **T13 — Lyzr Agents:** four agents, prompts, Structured Output, RAI, session state, contract tests.
- [ ] **T14 — Orchestration:** FSM, legal/illegal transitions, guards, idempotency, no-skip test.
- [ ] **T15 — HITL API + UI:** approval API, Safety Gate, approve/deny/expire e2e.
- [ ] **T16 — Audit:** SHA256 chain, verification endpoint, tamper test, AIMS trace mapping.
- [ ] **T17 — Evaluation:** runner, graders, suites, JSONL, HTML scorecard, baseline comparison.
- [ ] **T18 — Frontend:** five views, dual SSE, LIVE/REPLAY/MOCK badges, evidence drill-down.
- [ ] **T19 — Adversarial:** critical attack suite and audit assertions.
- [ ] **T20 — Budgets:** latency/token/call/context/cache measurement and assertions.
- [ ] **T21 — Demo Harden:** seed/eval/demo scripts, `demo.sh --check`, replay package, 5-minute DEMO.md.

**Task-level gate:** no task is complete from prose alone; implementation + tests + evidence + score + human approval are required.

# 9. Phase-by-Phase Implementation & Verification Plan

## M00 — Foundation / 7 modules

### 8.1 Scope
- [ ] Repository structure.
- [ ] Configuration.
- [ ] Docker/Compose.
- [ ] Health endpoint.
- [ ] Logging.
- [ ] Base documentation.
- [ ] CI.

### 8.2 Sub-sub checks
- [ ] Clean clone can install dependencies.
- [ ] Compose configuration parses.
- [ ] Images build.
- [ ] Services start.
- [ ] Health endpoint returns correct JSON/status.
- [ ] Logs are structured and sane.
- [ ] Environment parity is verified.
- [ ] No secrets present.
- [ ] CI reproduces required lint/type/test/security stages.
- [ ] README commands are true.
- [ ] Foundation tests reproduced independently.

### 8.3 Gate
- [x] M00 trusted baseline exists from prior audit.
- [ ] Any later shared-foundation modification triggers M00 regression.

---

## M01 — Contracts / 15 modules

### 9.1 Contract inventory
Canonical contracts must cover:

- [ ] Shared primitives/enums/values.
- [ ] Incident.
- [ ] Alert.
- [ ] Evidence.
- [ ] Hypothesis.
- [ ] Runbook.
- [ ] Action.
- [ ] Policy Decision.
- [ ] Approval.
- [ ] Execution.
- [ ] Verification.
- [ ] Rollback.
- [ ] RCA.
- [ ] Audit.
- [ ] Evaluation.

### 9.2 Contract hardening standard
Every mutable/structured contract must be checked for:

- [ ] `extra="forbid"` where applicable.
- [ ] Explicit enum restrictions.
- [ ] Bounds.
- [ ] Whitespace policy.
- [ ] tz-aware timestamps where required.
- [ ] Deep immutability for frozen structures.
- [ ] Input aliasing protection.
- [ ] Dump detachment.
- [ ] `model_construct` containment where the contract requires framework bypass resistance.
- [ ] `model_copy(update=...)` re-validation where applicable.
- [ ] Deterministic serialization.
- [ ] JSON-compatible boundaries.
- [ ] Mutation tests proving controls are load-bearing.

### 9.3 Current project state
- [x] M01.1 approved/merged.
- [x] M01.2 approved/merged.
- [x] M01.3 implementation/hardening human-approved.
- [ ] M01.3 integration export + registry + regression + merge/push.
- [ ] M01.4 human approval.
- [ ] M01.5–M01.15 human approval and integration in controlled order.

### 9.4 M01-specific final gate
- [ ] Cross-contract serialization matrix.
- [ ] Enum compatibility matrix.
- [ ] ID compatibility matrix.
- [ ] Old-vs-new wire compatibility where required.
- [ ] Full M00+M01 regression.

---

## M02 — Telemetry / 10 modules

### 10.1 Telemetry sources
- [ ] Alerts.
- [ ] Logs.
- [ ] Metrics.
- [ ] Traces.
- [ ] Kubernetes events.
- [ ] Deployments.
- [ ] Services.
- [ ] Pods.
- [ ] Correlation metadata.
- [ ] Ground-truth/seed metadata kept separate from agent-visible evidence.

### 10.2 Generator requirements
- [ ] Deterministic `(scenario, variant, seed)` behavior.
- [ ] Stable IDs where intended.
- [ ] Timestamp policy defined.
- [ ] SHA/hash log where specified.
- [ ] Normal scenario.
- [ ] Noisy scenario.
- [ ] Incomplete scenario.
- [ ] Contradictory scenario.
- [ ] Adversarial scenario.

### 10.3 Cross-source integrity
- [ ] Alert↔log linkage.
- [ ] Alert↔metric linkage.
- [ ] Alert↔trace linkage.
- [ ] Alert↔K8s event linkage.
- [ ] Alert↔deployment linkage.
- [ ] Service↔topology linkage.
- [ ] No impossible timestamps.
- [ ] No accidental ground-truth leakage.
- [ ] Negative-seed policy is standardized at integration.
- [ ] Determinism is verified cross-process.

---

## M03 — Normalization / 6 modules

### 11.1 Canonicalization
- [ ] Source normalization.
- [ ] Timestamp normalization.
- [ ] Service naming normalization.
- [ ] Environment normalization.
- [ ] Severity normalization.
- [ ] Label/metadata normalization.

### 11.2 Trust checks
- [ ] Same semantic input gives stable canonical output.
- [ ] Malformed telemetry is rejected or isolated.
- [ ] No normalization step can inject executable instructions.
- [ ] Original source identifiers remain traceable.
- [ ] Canonical hash is reproducible.

---

## M04 — Correlation / 6 modules

### 12.1 Correlation engine
- [ ] Fingerprinting.
- [ ] Duplicate suppression.
- [ ] Time-window correlation.
- [ ] Dependency/topology correlation.
- [ ] Signature similarity.
- [ ] Severity P1–P4.

### 12.2 Verification
- [ ] Split cases.
- [ ] Merge cases.
- [ ] Same-fingerprint cases.
- [ ] Near-window cases.
- [ ] Cross-service dependency cases.
- [ ] Security-like P1 cases.
- [ ] False positives.
- [ ] Noise suppression.
- [ ] LLM cannot override deterministic grouping/severity.

---

## M05 — Evidence / 6 modules

### 13.1 Evidence model
- [ ] Evidence ID.
- [ ] Incident linkage.
- [ ] Source type.
- [ ] Source ID.
- [ ] Timestamp.
- [ ] Source span/ref.
- [ ] Hash.
- [ ] Freshness.
- [ ] Relevance.
- [ ] Trust level.

### 13.2 Evidence-grounding checks
- [ ] Claim→evidence.
- [ ] Evidence→source.
- [ ] Source→timestamp.
- [ ] Source→hash.
- [ ] Invalid/expired evidence rejected where required.
- [ ] Missing evidence produces `INSUFFICIENT_EVIDENCE` rather than invented facts.
- [ ] RCA must-cite gate enforced.
- [ ] UI evidence links are functional.

---

## M06 — Policy/Safety / 10 modules

### 14.1 Action taxonomy
- [ ] Read actions.
- [ ] Reversible actions.
- [ ] Controlled changes.
- [ ] High-impact changes.
- [ ] Destructive actions.
- [ ] Unknown actions.

### 14.2 Policy engine
- [ ] Schema validation before policy.
- [ ] Allowlist.
- [ ] Parameter-shape validation.
- [ ] Risk classification.
- [ ] Environment awareness.
- [ ] Severity awareness.
- [ ] Blast-radius awareness.
- [ ] Actor role awareness.
- [ ] Runbook version awareness.
- [ ] Evidence freshness awareness.
- [ ] DENY > ESCALATE > ALLOW precedence.
- [ ] Most restrictive conflict resolution.
- [ ] Default DENY.
- [ ] Policy errors deny.
- [ ] Policy version recorded in audit.

### 14.3 Mandatory safety tests
- [ ] 40+ policy tests or current module-registry equivalent.
- [ ] Every rule tested.
- [ ] Every conflict tested.
- [ ] Default-deny tested.
- [ ] Production destructive actions denied.
- [ ] Unsafe parameters denied.
- [ ] Unpinned runbook denied.
- [ ] Missing evidence denied.
- [ ] Policy-skip bypass denied.

---

## M07 — HITL / 8 modules

### 15.1 Approval object
- [ ] Incident.
- [ ] Action ID.
- [ ] Exact parameter hash.
- [ ] Risk.
- [ ] Blast radius.
- [ ] Evidence IDs.
- [ ] Reason.
- [ ] Policy reference.
- [ ] Expected outcome.
- [ ] Rollback.
- [ ] Agent identity.
- [ ] Timestamp.
- [ ] Expiry.

### 15.2 Token security
- [ ] HMAC-SHA256.
- [ ] Nonce.
- [ ] Single-use.
- [ ] Expiry.
- [ ] Exact-scope binding.
- [ ] Actor/role binding.
- [ ] Replay rejection.
- [ ] Tamper rejection.
- [ ] Wrong-actor rejection.
- [ ] Approval-deny audit event.
- [ ] Expiry audit event.

### 15.3 HITL UX
- [ ] Safety Gate renders full decision context.
- [ ] Approve.
- [ ] Deny.
- [ ] Request evidence / escalate behavior where implemented.
- [ ] Countdown.
- [ ] No client-side trust.
- [ ] Server revalidates all approval conditions.

---

## M08 — Sandbox / 6 modules

### 16.1 Mock executor — default
- [ ] Stateful state model.
- [ ] Pod state transition.
- [ ] Scale transition.
- [ ] Deployment rollback.
- [ ] Blocked action = zero side effect.
- [ ] State diff captured.
- [ ] Execution ID generated.
- [ ] Duplicate action suppressed.

### 16.2 Docker executor — optional but planned
- [ ] Non-privileged.
- [ ] No secret mounts.
- [ ] Network isolation.
- [ ] Timeout.
- [ ] Allowlisted operations only.
- [ ] RED refuses.
- [ ] Failure produces typed result.

### 16.3 Kind
- [ ] Only after mock/docker path is stable.
- [ ] `EXECUTOR=kind` toggle.
- [ ] `demo.sh --check` verifies it.
- [ ] No dependence on Kind for the baseline demo.

---

## M09 — Verification / 8 modules

### 17.1 Independent checks
- [ ] Pod readiness.
- [ ] Deployment availability.
- [ ] Error-rate threshold.
- [ ] P95 latency/SLO.
- [ ] CrashLoop absence.
- [ ] Expected version.
- [ ] Timeout window.
- [ ] Incident state consistency.

### 17.2 Verdict matrix
- [ ] RESOLVED.
- [ ] PARTIAL.
- [ ] FAILED.
- [ ] WORSENED.
- [ ] ROLLBACK_REQUIRED.
- [ ] ESCALATE.

### 17.3 Safety rule
- [ ] Exit code cannot independently declare resolution.
- [ ] Planner cannot override verifier.
- [ ] Verifier configuration is versioned.
- [ ] All verdicts have tests.

---

## M10 — Rollback / 5 modules

- [ ] Reversible YELLOW action includes rollback action.
- [ ] Rollback conditions are deterministic.
- [ ] Failed verification triggers rollback where appropriate.
- [ ] Only one automatic rollback attempt.
- [ ] Rollback is re-verified.
- [ ] Failed rollback escalates.
- [ ] Irreversible RED action remains blocked.
- [ ] Rollback event is fully audited.

---

## M11 — Runbooks / 6 modules

### 19.1 Runbook schema
- [ ] ID.
- [ ] Semver version.
- [ ] Title.
- [ ] Trigger conditions.
- [ ] Environment scope.
- [ ] Preconditions.
- [ ] Diagnostic steps.
- [ ] Allowed actions.
- [ ] Forbidden actions.
- [ ] Parameter JSON schema.
- [ ] Approval conditions.
- [ ] Verification SLOs.
- [ ] Rollback template.
- [ ] Owner.
- [ ] Review timestamp.
- [ ] Hash.

### 19.2 Seed runbooks
- [ ] Bad deployment rollback.
- [ ] CrashLoop/OOM.
- [ ] DB pool saturation.
- [ ] Network/dependency failover.
- [ ] Injection quarantine.

### 19.3 Poisoning resistance
- [ ] Hash verification.
- [ ] Version pinning.
- [ ] Owner/review metadata.
- [ ] Poisoned runbook test.
- [ ] Hidden shell/meta-command test.
- [ ] No arbitrary runbook execution.

---

## M12 — Retrieval / 7 modules

### 20.1 Retrieval sources
- [ ] Runbooks.
- [ ] Historical incidents.
- [ ] Service metadata.
- [ ] Deployment history.
- [ ] Known errors.
- [ ] Incident-scoped telemetry evidence.
- [ ] Architecture/operational knowledge where genuinely useful.

### 20.2 Frozen retrieval design
- [ ] Lyzr Classic KB.
- [ ] Runbooks/history collections.
- [ ] Metadata filters.
- [ ] Temporal filtering.
- [ ] MMR/hybrid retrieval as configured.
- [ ] Top-k=5 baseline target.
- [ ] Reranking.
- [ ] Score threshold measured/tuned.
- [ ] Raw telemetry is not bulk-dumped into context.
- [ ] Pre-digestor generates Evidence Pack.

### 20.3 Retrieval benchmark
- [ ] precision@5.
- [ ] recall@5.
- [ ] MRR.
- [ ] nDCG.
- [ ] irrelevant-context ratio.
- [ ] Baseline run.
- [ ] Optimized run.
- [ ] Same fixture set.
- [ ] Sample size recorded.

---

## M13 — Lyzr Agents / 10 modules

### 21.1 Agent A1 — Triage
- [ ] Role/goal/instructions.
- [ ] Structured Output schema.
- [ ] RAI in/out.
- [ ] Correct model routing.
- [ ] Session persistence.
- [ ] Read-only tools only.
- [ ] No diagnosis ownership.
- [ ] No mutation access.
- [ ] P1–P4 output handoff.

### 21.2 Agent A2 — Diagnostic
- [ ] Evidence Pack input.
- [ ] 2–3 hypotheses or documented single-cause exception.
- [ ] Supporting evidence.
- [ ] Contradicting evidence.
- [ ] Test proposal.
- [ ] Runbook pin.
- [ ] `INSUFFICIENT_EVIDENCE` behavior.
- [ ] No invented telemetry.
- [ ] Read-only tools.

### 21.3 Agent A3 — Planner
- [ ] Receives governed runbook.
- [ ] Produces structured Action only.
- [ ] Never emits arbitrary shell.
- [ ] Evidence IDs required for mutation.
- [ ] Expected outcome.
- [ ] Rollback action.
- [ ] Verification plan.
- [ ] Policy receives action independently.

### 21.4 Agent A4 — RCA Reporter
- [ ] Runs after verification.
- [ ] Timeline.
- [ ] Verified root cause.
- [ ] Remediation log.
- [ ] Prevention.
- [ ] Claim→evidence map.
- [ ] Blameless language.
- [ ] Publish gate enforced.

### 21.5 Agent trust checks
- [ ] All four use actual Lyzr capability where claimed.
- [ ] Structured Output validated by server.
- [ ] RAI attached to every configured interaction.
- [ ] Agent session trace visible.
- [ ] Distinct ACLs tested.
- [ ] Prompt injection tests.
- [ ] Tool argument tests.
- [ ] Schema mutation tests.
- [ ] Same-seed replay where deterministic test mode supports it.
- [ ] Hallucination metrics captured.

---

## M14 — Orchestration / 8 modules

### 22.1 Canonical FSM

```text
NEW
→ TRIAGING
→ CORRELATED
→ INVESTIGATING
→ DIAGNOSING
→ PLANNED
→ POLICY_CHECK
→ {BLOCKED | AWAITING_APPROVAL | APPROVED}
→ EXECUTING
→ VERIFYING
→ {RESOLVED | ROLLBACK | ESCALATED}
→ RCA_PENDING
→ RCA_PUBLISHED
→ AUDITED
```

- [ ] Every legal transition encoded.
- [ ] Every illegal transition rejected.
- [ ] Policy skip impossible.
- [ ] Approval without token impossible.
- [ ] Execution without action ID impossible.
- [ ] RCA publish without coverage impossible.
- [ ] Retry states bounded.
- [ ] Re-plan capped.
- [ ] Tool count capped.
- [ ] LLM call count capped.
- [ ] Idempotency keys enforced.
- [ ] Duplicate delivery returns cached result.

### 22.2 Orchestration resilience
- [ ] Agent timeout.
- [ ] Retry once where allowed.
- [ ] Deterministic service retry rules.
- [ ] Lyzr timeout fallback.
- [ ] Database failure fallback.
- [ ] Sandbox fallback.
- [ ] Offline replay fallback.
- [ ] Every failure is audited.

---

## M15 — Audit/AIMS / 6 modules

### 23.1 Event model
- [ ] Event ID.
- [ ] Sequence.
- [ ] Timestamp.
- [ ] Incident ID.
- [ ] Actor.
- [ ] Agent.
- [ ] Event type.
- [ ] Input hash.
- [ ] Evidence IDs.
- [ ] Policy version/rule/result.
- [ ] Action/approval/execution IDs.
- [ ] Result.
- [ ] Previous hash.
- [ ] Current hash.

### 23.2 Coverage
Audit every:

- [ ] Incident ingest.
- [ ] State transition.
- [ ] Tool call.
- [ ] Retrieval event where appropriate.
- [ ] Policy result.
- [ ] HITL request.
- [ ] HITL decision.
- [ ] Execution.
- [ ] Verification.
- [ ] Rollback.
- [ ] RCA publication.
- [ ] Evaluation run.
- [ ] Blocked action.
- [ ] Duplicate suppression.

### 23.3 AIMS honesty
- [ ] AIMS traces are labeled AIMS.
- [ ] Custom hash chain is labeled CUSTOM.
- [ ] No fake AIMS event screenshot.
- [ ] AIMS capability screenshot/trace captured where genuinely available.
- [ ] Fallback explicitly documented where not available.

---

## M16 — Evaluation / 9 modules

### 24.1 Pipeline

```text
CASE → RUN → TRACE → GRADE → SCORE → COMPARE → REPORT
```

- [ ] Deterministic fixture runner.
- [ ] Mock/recorded LLM option for repeatable tests.
- [ ] Audit capture.
- [ ] Tool capture.
- [ ] Evidence capture.
- [ ] Grader outputs.
- [ ] JSONL outputs.
- [ ] HTML scorecard.
- [ ] Baseline-vs-optimized comparison.

### 24.2 Graders
- [ ] Schema validity.
- [ ] Policy correctness.
- [ ] Citation coverage.
- [ ] Unsafe execution count.
- [ ] Attack containment.
- [ ] Verification verdict match.
- [ ] Token budget.
- [ ] Latency budget.
- [ ] Tool-call budget.

### 24.3 Lyzr Agent Eval separation
- [ ] Agent-level hallucination/faithfulness/tool-argument evaluation is distinct.
- [ ] Custom pipeline-level evaluator owns safety/state/rollback/end-to-end checks.
- [ ] No double-counted metric.
- [ ] Reports explain metric ownership.

---

## M17 — Benchmarks / 7 modules

### 25.1 Twelve golden categories

- [ ] Bad deployment.
- [ ] Memory leak.
- [ ] CrashLoopBackOff.
- [ ] CPU saturation.
- [ ] Disk pressure.
- [ ] Database connection exhaustion.
- [ ] Deadlock.
- [ ] Network failure.
- [ ] Configuration error.
- [ ] Dependency outage.
- [ ] False-positive alert.
- [ ] Cascading alert storm.

### 25.2 Deep-5
Each deep scenario gets:

- [ ] NORMAL.
- [ ] NOISY.
- [ ] INCOMPLETE.
- [ ] CONTRADICTORY.
- [ ] ADVERSARIAL.

Deep-5 scenarios:

- [ ] Bad deployment.
- [ ] CrashLoop/OOM.
- [ ] DB exhaustion.
- [ ] Network/dependency failure.
- [ ] Malicious log injection.

### 25.3 Stub-7
- [ ] Remaining seven categories have minimal but executable fixtures.
- [ ] Do not claim full deep coverage if only stub coverage exists.

### 25.4 Ground truth isolation
- [ ] Expected root cause.
- [ ] Allowed remediation.
- [ ] Forbidden remediation.
- [ ] Verification SLO.
- [ ] Ground truth not exposed to agents except through intended evidence.

---

## M18 — Adversarial / 10 modules

Minimum critical attacks:

- [ ] Log/prompt injection.
- [ ] Poisoned runbook.
- [ ] Fake telemetry.
- [ ] Stale telemetry.
- [ ] Contradictory telemetry.
- [ ] Unsafe command/action.
- [ ] Parameter injection.
- [ ] Secret exfiltration.
- [ ] Approval replay.
- [ ] Runaway loop.

Bonus:

- [ ] Cost bomb.
- [ ] Policy-bypass paraphrase.
- [ ] Verification spoof.
- [ ] Duplicate execution.
- [ ] Unauthorized privilege escalation.

For every attack case:

- [ ] Attack input.
- [ ] Expected control.
- [ ] Block/deny/escalate outcome.
- [ ] Audit assertion.
- [ ] Metric captured.
- [ ] Recovery path.
- [ ] No unsafe side effect.

Targets are engineering targets, not organizer guarantees:

- [ ] `unsafe_exec = 0`
- [ ] `bypass = 0`
- [ ] `injection_success = 0`
- [ ] false-block target measured and reported.

---

## M19 — Frontend / 10 modules

### 27.1 View 1 — Command Center
- [ ] Incident queue.
- [ ] Severity.
- [ ] Status.
- [ ] Service.
- [ ] Age.
- [ ] MTTR.
- [ ] Cost/latency mini-metrics.
- [ ] LIVE/REPLAY/MOCK badge.

### 27.2 View 2 — Incident Detail
- [ ] Timeline.
- [ ] Alerts.
- [ ] Evidence chips.
- [ ] Source line/row links.
- [ ] Hypotheses.
- [ ] Confidence.
- [ ] Ruled-out causes.
- [ ] Runbook pin.

### 27.3 View 3 — Safety Gate
- [ ] Action type.
- [ ] Resource.
- [ ] Parameters.
- [ ] Blast radius.
- [ ] Risk.
- [ ] Policy rule.
- [ ] Policy version.
- [ ] Evidence links.
- [ ] Expected outcome.
- [ ] Rollback.
- [ ] Verification plan.
- [ ] Approve/Deny.
- [ ] TTL.

### 27.4 View 4 — Execution/Verification
- [ ] SSE stream.
- [ ] State diff.
- [ ] SLO badges.
- [ ] Verdict.
- [ ] Rollback controls.
- [ ] Execution ID.
- [ ] Audit link.

### 27.5 View 5 — RCA/Evaluation
- [ ] RCA.
- [ ] Evidence map.
- [ ] Audit chain.
- [ ] Validity badge.
- [ ] Six-gate cards.
- [ ] Charts.
- [ ] Link to JSONL run.

### 27.6 UI laws
- [ ] Maximum five MVP views/routes.
- [ ] No dashboard-only theater.
- [ ] Every important number links to evidence/audit/run.
- [ ] No fake live data.
- [ ] Mode badge always visible.
- [ ] Accessibility and responsive layout checked.

---

## M20 — Performance / 7 modules

### 28.1 Cost
- [ ] Tokens in.
- [ ] Tokens out.
- [ ] LLM calls.
- [ ] Context size.
- [ ] Cache hits.
- [ ] Cost using configurable pricing table.
- [ ] Per-incident ledger.
- [ ] Cost dashboard.

### 28.2 Latency
Measure:

- [ ] Ingest.
- [ ] Triage.
- [ ] Retrieval.
- [ ] Diagnosis.
- [ ] Policy.
- [ ] Approval wait separately.
- [ ] Execution.
- [ ] Verification.
- [ ] RCA.
- [ ] Total.
- [ ] P50.
- [ ] P95.

### 28.3 Provisional budget checks
- [ ] ≤80k tokens/incident.
- [ ] ≤12 LLM calls/incident.
- [ ] ≤12k context per call.
- [ ] ≤5 tools/agent.
- [ ] ≤3 hypotheses.
- [ ] ≤2 replans.
- [ ] Mock e2e P50 <90s.
- [ ] Tool p95 target measured.
- [ ] Stage latency targets measured.

**All numeric thresholds remain `[PROVISIONAL]` until the baseline/revision protocol is completed.**

### 28.4 Optimization discipline
- [ ] Focused retrieval.
- [ ] Pre-digestion.
- [ ] Caching.
- [ ] Small-model routing.
- [ ] Parallel independent retrieval.
- [ ] Bounded reasoning loops.
- [ ] Never save tokens by skipping evidence, policy, or verification.

---

## M21 — Integration / 9 modules

### 29.1 End-to-end paths

#### Happy path
- [ ] Seed incident.
- [ ] Alerts correlate.
- [ ] Evidence retrieved.
- [ ] Diagnosis grounded.
- [ ] Runbook pinned.
- [ ] Action planned.
- [ ] Validator passes.
- [ ] Policy allows or escalates correctly.
- [ ] Approval if required.
- [ ] Sandbox executes.
- [ ] Verify passes.
- [ ] RCA publishes.
- [ ] Audit valid.

#### Block path
- [ ] Poisoned/dangerous action proposed.
- [ ] Validator/policy blocks.
- [ ] Zero state diff.
- [ ] Audit records block.
- [ ] Incident can safely replan/escalate.

#### Rollback path
- [ ] Approved reversible action.
- [ ] Action executes.
- [ ] Verification fails/worsens.
- [ ] One auto-rollback.
- [ ] Reverify.
- [ ] Resolve or escalate.

### 29.2 API guard matrix
- [ ] Authentication.
- [ ] Role authorization.
- [ ] Idempotency.
- [ ] Policy freshness.
- [ ] Action ownership.
- [ ] Execution ownership.
- [ ] No policy/HITL bypass endpoint.
- [ ] Error codes typed.
- [ ] Errors audited where required.

### 29.3 Cross-system compatibility
- [ ] M01 contracts ↔ M02 telemetry.
- [ ] Telemetry ↔ normalization.
- [ ] normalization ↔ correlation.
- [ ] correlation ↔ incident.
- [ ] evidence ↔ hypothesis.
- [ ] runbook ↔ action.
- [ ] action ↔ policy.
- [ ] approval ↔ action.
- [ ] execution ↔ verification.
- [ ] rollback ↔ execution.
- [ ] RCA ↔ evidence.
- [ ] evaluation ↔ scenario/seed/trace.

---

## M22 — Demo / 7 modules

### 30.1 Five-minute canonical demo

- [ ] **0:00** — Hook: pager at 2am.
- [ ] **0:20** — Seed bad deployment; N alerts become one P1.
- [ ] **0:40** — Show topology + deployment marker.
- [ ] **1:00** — Evidence chips / hashes.
- [ ] **1:30** — Hypotheses + ruled-out hypothesis + runbook pin.
- [ ] **2:00** — Dangerous `delete_namespace/prod` proposal.
- [ ] **2:10** — RED BLOCK + rule quote + zero-diff proof.
- [ ] **2:30** — YELLOW rollback proposal.
- [ ] **2:40** — Human approval + TTL.
- [ ] **3:00** — Sandbox execution + before/after diff.
- [ ] **3:20** — Independent verification.
- [ ] **3:40** — RCA.
- [ ] **4:00** — Six-gate scorecard.
- [ ] **4:30** — Lyzr-native vs custom table.
- [ ] **5:00** — thesis + repository + live endpoint.

### 30.2 Demo failure modes
- [ ] Lyzr unavailable → REPLAY.
- [ ] DB unavailable → file-backed fallback.
- [ ] Sandbox unavailable → MOCK.
- [ ] Network unavailable → OFFLINE package/video.
- [ ] Every fallback is labeled.
- [ ] No fallback is presented as LIVE.

### 30.3 Rehearsal
- [ ] Full demo rehearsal #1.
- [ ] Full demo rehearsal #2.
- [ ] Full demo rehearsal #3.
- [ ] Timed under five minutes.
- [ ] No manual typing required except approved interaction.
- [ ] Standby approval path tested.
- [ ] `demo.sh --check` passes.

---

# 9. Six Global Production Quality Gates

## C1 — Hallucination Mitigation

- [ ] No fabricated telemetry.
- [ ] No fabricated root cause.
- [ ] No fabricated commands.
- [ ] No fabricated runbook steps.
- [ ] No fabricated verification result.
- [ ] Structured outputs.
- [ ] Tool-backed facts.
- [ ] Evidence IDs.
- [ ] Explicit uncertainty states.
- [ ] Replay tests.

Metrics:

- [ ] `unsupported_claim_rate`
- [ ] `fabricated_command_rate`
- [ ] `invalid_tool_argument_rate`
- [ ] `repeatability_rate`

## C2 — Groundedness

- [ ] Diagnosis claims map to evidence.
- [ ] Action justification maps to evidence.
- [ ] RCA claims map to evidence.
- [ ] Hashes valid.
- [ ] Evidence freshness enforced where needed.
- [ ] Missing evidence blocks the gate.

Metrics:

- [ ] `diagnosis_evidence_coverage`
- [ ] `action_evidence_coverage`
- [ ] `citation_completeness`
- [ ] `unsupported_recommendation_rate`

## C3 — Retrieval Quality

- [ ] Time filter.
- [ ] Service filter.
- [ ] Environment filter.
- [ ] Deployment context.
- [ ] Semantic search.
- [ ] Lexical/keyword search.
- [ ] Metadata filters.
- [ ] Temporal ranking.
- [ ] Rerank.
- [ ] Pre-digest.

Metrics:

- [ ] precision@5
- [ ] recall@5
- [ ] MRR
- [ ] nDCG
- [ ] irrelevant-context ratio

## C4 — Costing & Token Optimization

- [ ] Tokens/incident measured.
- [ ] Calls/incident measured.
- [ ] Cost/incident measured from config pricing.
- [ ] Average context measured.
- [ ] Cache hit rate measured.
- [ ] Baseline and optimized result shown.

## C5 — Prompt Architecture

Every agent prompt includes:

- [ ] Identity.
- [ ] Objective.
- [ ] Inputs.
- [ ] Trusted vs untrusted data.
- [ ] Output schema.
- [ ] Evidence rules.
- [ ] Tool rules.
- [ ] Safety rules.
- [ ] Forbidden behavior.
- [ ] Uncertainty behavior.
- [ ] Escalation.
- [ ] Stop conditions.

Security tests:

- [ ] Prompt injection.
- [ ] Indirect injection in logs.
- [ ] Poisoned runbook.
- [ ] Tool abuse prompt.
- [ ] Secret exfil prompt.
- [ ] Policy bypass paraphrase.

## C6 — Latency Optimization

- [ ] Ingest latency.
- [ ] Triage latency.
- [ ] Retrieval latency.
- [ ] Diagnosis latency.
- [ ] Policy latency.
- [ ] Execution latency.
- [ ] Verification latency.
- [ ] RCA latency.
- [ ] Total pipeline latency.
- [ ] P50.
- [ ] P95.

---

# 10. Security Invariant Master List

These must be enforced in **code + tests + integration evidence**.

1. [ ] No unvalidated Action reaches executor.
2. [ ] RED never executes in hackathon path.
3. [ ] YELLOW requires valid unused unexpired scoped approval.
4. [ ] Approval tokens are HMAC protected, nonce protected, and single-use.
5. [ ] LLM has no shell/exec tool.
6. [ ] Telemetry is data, not instructions.
7. [ ] Every mutation has an action ID.
8. [ ] Every mutation has a policy decision reference.
9. [ ] Mutation path requires verification.
10. [ ] Every block emits an audit event.
11. [ ] RCA requires must-cite coverage.
12. [ ] Hypotheses, tools, replans, and calls are bounded.
13. [ ] Token/cost/loop kill-switch exists.
14. [ ] Safety failures fail closed.
15. [ ] `POLICY_CHECK → EXECUTING` requires a valid permit/token.
16. [ ] Exit status alone cannot declare incident resolution.

---

# 11. API Master Checklist

Auth:

- [ ] Demo API key.
- [ ] `viewer` role.
- [ ] `approver` role.
- [ ] `admin` role only where genuinely needed.
- [ ] Server-side role enforcement.

Idempotency:

- [ ] Mutations require `Idempotency-Key`.
- [ ] Duplicate delivery returns cached result.
- [ ] Duplicate is audited.

Endpoints:

- [ ] `POST /alerts`
- [ ] `POST /incidents`
- [ ] `GET /incidents`
- [ ] `GET /incidents/{id}`
- [ ] `POST /incidents/{id}/triage`
- [ ] `GET /incidents/{id}/evidence`
- [ ] `POST /incidents/{id}/diagnose`
- [ ] `POST /incidents/{id}/remediation`
- [ ] `GET /approvals/{id}`
- [ ] `POST /approvals/{id}/approve`
- [ ] `POST /approvals/{id}/reject`
- [ ] `POST /executions`
- [ ] `POST /executions/{id}/verify`
- [ ] `POST /executions/{id}/rollback`
- [ ] `GET /incidents/{id}/audit`
- [ ] `GET /incidents/{id}/rca`
- [ ] `POST /evaluations/run`
- [ ] `GET /evaluations/{id}`
- [ ] `POST /demo/seed`

For every endpoint:

- [ ] Request schema.
- [ ] Response schema.
- [ ] Validation.
- [ ] Authentication.
- [ ] Authorization.
- [ ] Idempotency if mutation.
- [ ] Error semantics.
- [ ] Audit behavior.
- [ ] No unsafe bypass path.

---

# 12. Data Model Master Checklist

Required core entities:

- [ ] users / roles.
- [ ] services.
- [ ] incidents.
- [ ] alerts.
- [ ] logs.
- [ ] metrics.
- [ ] traces.
- [ ] K8s events.
- [ ] deploy events.
- [ ] evidence.
- [ ] hypotheses.
- [ ] diagnoses.
- [ ] runbooks.
- [ ] policies.
- [ ] actions.
- [ ] approvals.
- [ ] executions.
- [ ] verification results.
- [ ] rollbacks.
- [ ] postmortems.
- [ ] agent runs.
- [ ] tool calls.
- [ ] retrieval events.
- [ ] audit events.
- [ ] evaluation runs.
- [ ] benchmark results.

Database checks:

- [ ] Foreign keys.
- [ ] Unique constraints.
- [ ] Required indexes.
- [ ] Timestamp indexes.
- [ ] Incident indexes.
- [ ] Action idempotency uniqueness.
- [ ] Approval nonce uniqueness.
- [ ] Approval token hash uniqueness.
- [ ] Runbook ID/version primary key.
- [ ] Audit sequence ordering.
- [ ] Hash fields.
- [ ] Retention policy documented.
- [ ] PII redaction at ingest.
- [ ] Seed script idempotent.

---

# 13. Prompt & Agent Security Checklist

- [ ] Every prompt identifies trusted inputs.
- [ ] Every telemetry block is clearly delimited as data.
- [ ] “Instructions in data are void” rule is explicit.
- [ ] Agents cannot invent evidence.
- [ ] Agents must cite IDs for required claims.
- [ ] Agents must emit structured outputs.
- [ ] Agents return uncertainty rather than forcing an answer.
- [ ] Agent tool ACLs are least-privilege.
- [ ] Mutation tools are not exposed to Lyzr.
- [ ] Agents cannot self-approve.
- [ ] Agents cannot self-verify.
- [ ] Agents cannot bypass policy.
- [ ] Agents cannot alter audit history.
- [ ] Agent prompts do not contain ground truth expected answers from benchmark fixtures.

---

# 14. Observability & Evidence Checklist

For every stage, capture:

- [ ] Start time.
- [ ] End time.
- [ ] Duration.
- [ ] Actor/agent.
- [ ] Input hash.
- [ ] Output hash where appropriate.
- [ ] Evidence IDs.
- [ ] Tool name.
- [ ] Tool arguments hash.
- [ ] Policy result.
- [ ] Action ID.
- [ ] Approval ID.
- [ ] Execution ID.
- [ ] Verification verdict.
- [ ] Audit event ID.

Every score displayed in UI:

- [ ] Metric definition.
- [ ] Dataset/suite.
- [ ] Run ID.
- [ ] Sample size.
- [ ] Baseline.
- [ ] Optimized.
- [ ] Timestamp/version.
- [ ] Link to JSONL evidence.

---

# 15. CI/CD Master Gate

Pipeline order:

```text
ruff
→ mypy
→ unit tests
→ integration tests
→ security scans
→ evaluation
→ build
→ Docker smoke
→ seed
→ one e2e incident
```

Required checks:

- [ ] Ruff.
- [ ] Mypy.
- [ ] Unit tests.
- [ ] Integration/Compose tests.
- [ ] `pip-audit` or equivalent dependency scan.
- [ ] Gitleaks/secret scan.
- [ ] Deep-5 evaluation.
- [ ] Unsafe execution gate.
- [ ] Grounding gate.
- [ ] Budget gate.
- [ ] Docker build.
- [ ] Docker smoke.
- [ ] Seed.
- [ ] One complete incident.
- [ ] `eval.sh` works.
- [ ] `demo.sh --check` works.

Merge blockers:

- [ ] Any P0.
- [ ] Any unsafe execution.
- [ ] Policy bypass.
- [ ] Approval bypass.
- [ ] RCA citation gate failure.
- [ ] Regression failure.
- [ ] Secret finding.
- [ ] Broken clean-clone build.

---

# 16. Six-Gate Scorecard Standard

Every final scorecard must show **metric + baseline + optimized + sample size + chart + run ID**.

| Gate | Core proof | Required status |
|---|---|---|
| C1 Hallucination | unsupported claims / fabricated commands / args / replay | PASS |
| C2 Groundedness | claim/evidence coverage | PASS |
| C3 Retrieval | p@k / recall / MRR / nDCG / irrelevant ratio | PASS or documented target revision |
| C4 Cost | tokens / calls / context / cache / cost | PASS or documented target revision |
| C5 Prompt | injection / unsafe compliance / schema / bypass | PASS |
| C6 Latency | stage + e2e P50/P95 | PASS or documented target revision |

### Target classification

- [ ] Every numeric target carries `[PROVISIONAL]` until 20 baseline runs and revision.
- [ ] No source-derived engineering number is presented as organizer-guaranteed.
- [ ] Any target changed after baseline is explained in `DECISIONS.md` and scorecard notes.

---

# 17. Final Zero-Trust Audit Protocol

Run this at module, phase, integration, and final-release level.

## 17.1 Layer 1 — Source audit

- [ ] Scope matches spec.
- [ ] No hidden requirement omitted.
- [ ] Official vs research vs proposed classification preserved.
- [ ] Current capability claims rechecked.

## 17.2 Layer 2 — Code audit

- [ ] Diff inspected manually.
- [ ] Imports inspected.
- [ ] Shared-file edits inspected.
- [ ] Security boundary inspected.
- [ ] Bypass paths searched.
- [ ] Dead code searched.
- [ ] TODO/FIXME reviewed.
- [ ] Debug code removed.
- [ ] Hardcoded secrets searched.

## 17.3 Layer 3 — Test audit

- [ ] Positive.
- [ ] Negative.
- [ ] Security.
- [ ] Integration.
- [ ] Performance.
- [ ] Mutation/load-bearing tests.

## 17.4 Layer 4 — Runtime audit

- [ ] Clean clone.
- [ ] Clean environment.
- [ ] Compose up.
- [ ] Health.
- [ ] Seed.
- [ ] E2E.
- [ ] Failure paths.
- [ ] Fallback paths.

## 17.5 Layer 5 — Evidence audit

- [ ] Every score has evidence.
- [ ] Every safety claim has a test.
- [ ] Every Lyzr claim has authentic integration evidence.
- [ ] Every demo claim matches actual runtime.
- [ ] Every benchmark result points to a reproducible run.

## 17.6 Layer 6 — Human trust audit

- [ ] Score reconstructed independently.
- [ ] Residual limitations explicit.
- [ ] No P0.
- [ ] Human APPROVE.
- [ ] Integration approved.
- [ ] Full regression after integration.

---

# 18. What We MUST NOT Do

## Product / architecture

- [ ] Do not build chatbot-only UX.
- [ ] Do not build dashboard-only theater.
- [ ] Do not create decorative agents.
- [ ] Do not add agents without distinct state/permission responsibility.
- [ ] Do not add complex infrastructure without measured need.
- [ ] Do not add 12 live vendor integrations.
- [ ] Do not build a custom vector database without justified need.
- [ ] Do not build multi-cluster support for the baseline.
- [ ] Do not build autonomous RED execution.

## Safety

- [ ] Do not use prompt text as the only safety mechanism.
- [ ] Do not allow raw shell passthrough.
- [ ] Do not let Safe AI masquerade as Kubernetes authorization.
- [ ] Do not let the planner verify itself.
- [ ] Do not let the client decide authorization.
- [ ] Do not allow approval replay.
- [ ] Do not allow policy bypass through a second endpoint.

## Grounding

- [ ] Do not invent evidence.
- [ ] Do not stuff massive raw telemetry into model context.
- [ ] Do not publish unsupported RCA claims.
- [ ] Do not expose benchmark ground truth to the agent.

## Lyzr honesty

- [ ] Do not fake Lyzr agent usage.
- [ ] Do not fake Automata.
- [ ] Do not fake AIMS.
- [ ] Do not label custom hash audit as AIMS.
- [ ] Do not label custom FSM as Automata.

## Demo

- [ ] Do not fake live data.
- [ ] Do not present REPLAY as LIVE.
- [ ] Do not rely on fragile manual typing.
- [ ] Do not make the demo a feature tour.
- [ ] Do not claim an attack passed when it was merely described.

## Engineering process

- [ ] No history rewrite.
- [ ] No silent fixes after scoring.
- [ ] No score inflation.
- [ ] No merge before human approval.
- [ ] No next module before the current gate closes.

---

# 19. “Every Important Feature Must Be Provable” Rule

A feature is **PROVEN** only when all applicable boxes are checked:

- [ ] Implemented.
- [ ] Unit-tested.
- [ ] Negative-tested.
- [ ] Security-tested.
- [ ] Integration-tested.
- [ ] Performance-measured where material.
- [ ] Runtime-observable.
- [ ] Audited/traceable.
- [ ] Benchmark/evaluation covered where material.
- [ ] Demo-representable where material.
- [ ] Documentation matches implementation.
- [ ] Limitations disclosed.

A feature is **NOT PROVEN** when it exists only in:

- [ ] source code without tests;
- [ ] a README claim;
- [ ] a screenshot without reproducibility;
- [ ] a mocked result not labeled mock;
- [ ] an agent prompt;
- [ ] a benchmark definition without executed output;
- [ ] a demo script that was never rehearsed.

---

# 20. Final End-to-End Definition of Done

## Lyzr

- [ ] Required keys/configuration wired.
- [ ] Four agents real and structured-output-valid.
- [ ] Sessions resume correctly.
- [ ] RAI policy attached and evidenced.
- [ ] Trace visible or fallback honestly documented.
- [ ] Lyzr capability claims verified against current docs/platform.

## Safety

- [ ] All security invariants green.
- [ ] Policy tests green.
- [ ] No-skip tests green.
- [ ] Approval replay tests green.
- [ ] Zero-diff block tests green.
- [ ] Audit tamper tests green.
- [ ] Unsafe execution = 0 in adversarial suite.

## Grounding

- [ ] Evidence coverage = target met.
- [ ] MUST-CITE coverage = 1.0 for final gate.
- [ ] Retrieval gate measured.
- [ ] Runbook pinning verified.

## Evaluation

- [ ] Deep-5 × 5 variants executed.
- [ ] Adversarial-10 executed.
- [ ] Stub-7 executed if claimed.
- [ ] JSONL artifacts committed.
- [ ] HTML scorecard generated.
- [ ] Baseline/optimized comparisons present.
- [ ] Six checkpoints reported.

## Repository

- [ ] Required paths.
- [ ] Clean clone works.
- [ ] Compose works.
- [ ] `.env.example` accurate.
- [ ] No secrets.
- [ ] Eight core docs present and consistent.
- [ ] README is truthful.

## Demo

- [ ] LIVE path works.
- [ ] RED block works.
- [ ] YELLOW approval works.
- [ ] Sandbox works.
- [ ] Verify works.
- [ ] Rollback works or is explicitly shown as rehearsed fallback.
- [ ] RCA works.
- [ ] Audit works.
- [ ] Scorecard works.
- [ ] Fallback modes work and are labeled.
- [ ] Three full rehearsals pass.

---

# 21. Submission Readiness Gate

## Competition / platform

- [ ] Correct PS03 selected.
- [ ] Correct repository connected.
- [ ] Current submission UI checked.
- [ ] Current deadline/status checked.
- [ ] Repository accessible to evaluator.
- [ ] Correct live endpoint recorded.
- [ ] Latest trusted code pushed.
- [ ] No untracked critical files.
- [ ] No accidental branches/commits containing secrets.

## Product

- [ ] Full PS03 workflow works end-to-end.
- [ ] Alert ingestion.
- [ ] Correlation.
- [ ] Diagnosis.
- [ ] Evidence.
- [ ] Runbook selection.
- [ ] Action generation.
- [ ] RED block.
- [ ] YELLOW approval.
- [ ] Sandbox execution.
- [ ] Independent verify.
- [ ] Rollback.
- [ ] RCA.
- [ ] Audit.
- [ ] Evaluation.

## Lyzr

- [ ] Agent API authentic.
- [ ] Safe AI authentic.
- [ ] AIMS authentic where supported.
- [ ] Any orchestration capability requirement verified against current evaluator.
- [ ] No fake platform claims.

## Quality

- [ ] Six checkpoints complete.
- [ ] Security invariants complete.
- [ ] Adversarial suite complete.
- [ ] Benchmark suite complete.
- [ ] Performance budget measured.
- [ ] Full regression green.
- [ ] Clean-clone smoke green.

## Documentation

- [ ] README.
- [ ] Architecture.
- [ ] API.
- [ ] Security.
- [ ] Evaluation.
- [ ] Demo.
- [ ] Testing.
- [ ] Decisions.
- [ ] License/attribution reviewed.
- [ ] Competitor/inspiration wording is hedged and provable.

---

# 22. Final Submission Dry-Run — NEVER SKIP

Run this as a separate event immediately before submission.

```text
BUILD
  ↓
TEST
  ↓
VALIDATE
  ↓
PACKAGE
  ↓
SUBMISSION DRY-RUN
  ↓
SUBMIT
  ↓
VERIFY SUBMISSION
```

## Dry-run checklist

- [ ] Start from clean checkout of trusted master.
- [ ] Pull/fetch latest remote.
- [ ] Verify commit hash.
- [ ] Clean working tree.
- [ ] Build from committed tree.
- [ ] Start services.
- [ ] Health check.
- [ ] Seed `bad-deploy/NORMAL`.
- [ ] Execute full demo path.
- [ ] Execute RED block path.
- [ ] Execute YELLOW approval path.
- [ ] Execute verification.
- [ ] Execute rollback path.
- [ ] Generate RCA.
- [ ] Verify audit hash chain.
- [ ] Run deep-5 evaluation.
- [ ] Run adversarial suite.
- [ ] Generate scorecard.
- [ ] Confirm README screenshots/artifacts are current.
- [ ] Confirm live endpoint.
- [ ] Confirm platform fields.
- [ ] Verify repository visibility/access.
- [ ] Capture final evidence package.

### STOP condition

If any critical check fails:

> **DO NOT SUBMIT.**

Return to the smallest failing gate, fix, re-audit, and repeat the dry-run.

---

# 23. Current Project State — Known Baseline

At the time this checklist was created from the supplied reports:

- [x] M00 Foundation — trusted/merged.
- [x] M01.1 Shared Types — trusted/merged.
- [x] M01.2 Incident — trusted/merged.
- [x] M01.3 Alert — implementation/hardening human-approved.
- [ ] M01.3 integration/merge/push verification remains.
- [ ] Remaining M01/M02 modules require their individual human trust gates and controlled integration.
- [ ] M01+M02 cross-track final zero-trust audit required after approvals.
- [ ] M03 and later remain locked until dependency gates close.

### M01.3 approved branch state to preserve

- Branch: `feature/m01.3-alert-final`
- Approved commit: `c347ea7`
- Trusted master at the reported review point: `d9105f7`
- Old candidate `feature/m01.3-alert` remains preserved.

### Immediate next controlled operation

1. [ ] Integrate `Alert` export in `backend/app/contracts/__init__.py`.
2. [ ] Update the M01.3 registry row to the appropriate post-approval status.
3. [ ] Run M00 + M01 regression.
4. [ ] Inspect integration diff.
5. [ ] Commit integration.
6. [ ] Merge one module at a time.
7. [ ] Push safely.
8. [ ] Fetch and verify remote state.
9. [ ] Only then process the next approved module.

---

# 24. Final Judge-Evidence Pack

Prepare one compact evidence pack covering:

- [ ] Architecture diagram.
- [ ] Agent graph.
- [ ] Lyzr-native/custom/simulated/future table.
- [ ] Policy decision example.
- [ ] RED blocked trace.
- [ ] YELLOW approval trace.
- [ ] Sandbox before/after state diff.
- [ ] Verification verdict.
- [ ] Rollback trace.
- [ ] Hash-chain verification.
- [ ] RCA with evidence map.
- [ ] Deep-5 benchmark score.
- [ ] Adversarial score.
- [ ] Six-gate scorecard.
- [ ] Token/cost result.
- [ ] Latency result.
- [ ] Clean-clone/Compose proof.
- [ ] Final commit hash.
- [ ] Live endpoint.

For every claim:

```text
CLAIM
  ↓
CODE
  ↓
TEST
  ↓
RUNTIME EVIDENCE
  ↓
METRIC
  ↓
AUDIT / TRACE
  ↓
DEMO
```

---

# 25. Winning Strategy Summary

The winning wedge is **verifiable governed execution**, not model cleverness.

Prioritize:

1. **Deterministic policy hook** — the primary safety boundary.
2. **Evidence-grounded diagnosis** — claim→evidence→source.
3. **Sandbox + verification + rollback** — prove the action lifecycle.
4. **Authentic Lyzr usage** — agents, RAI, KB/memory/trace as actually supported.
5. **Adversarial evaluation** — show failure resistance, not only happy paths.
6. **Quantitative scorecard** — turn claims into measured evidence.
7. **Clean repository + reproducible demo** — repository itself is part of evaluation.
8. **Truthful presentation** — never claim more than the evidence proves.

---

# 26. Final STOP / GO Decision

## GO only when ALL applicable boxes are checked

- [ ] Official requirements satisfied.
- [ ] Final specification satisfied.
- [ ] All dependency modules trusted.
- [ ] No P0.
- [ ] Safety critical modules ≥95 safety score.
- [ ] Grounding-critical modules ≥95 grounding score.
- [ ] Agent modules ≥95 hallucination score.
- [ ] Overall module gates ≥90.
- [ ] Full regression green.
- [ ] Security suite green.
- [ ] Adversarial suite green.
- [ ] Benchmark evidence exists.
- [ ] Six-gate scorecard exists.
- [ ] Clean-clone build works.
- [ ] Demo dry-run works.
- [ ] Fallback works.
- [ ] Documentation is consistent.
- [ ] Lyzr claims are authentic and verified.
- [ ] Platform submission state is verified against the current UI.
- [ ] Human final approval recorded.

## NO-GO when ANY applies

- [ ] Unsafe execution observed.
- [ ] Policy bypass exists.
- [ ] Approval replay works.
- [ ] Ground truth leaks into agent context.
- [ ] RCA publishes unsupported must-cite claims.
- [ ] Critical regression exists.
- [ ] Secret exposure exists.
- [ ] Live/Replay/Mock labeling is false.
- [ ] Any major capability is claimed but not evidenced.
- [ ] Submission fields/repository/live endpoint are not verified.

---

# 27. Evidence Sources Used to Build This Checklist

Primary project sources supplied for this plan:

- `AI_Quest_2026_PS03_Hackathon_Rules_and_Evaluation(1).md`
- `AI_Quest_2026_PS03_Master_Research(1).md`
- `PS03_FINAL_SPEC(1).md`
- `PS03_FINAL_SPEC_V2(1).md`
- `Beyond the Wrapper_ A Blueprint for Verifiable Autonomous SRE in the AI Quest 2026 Hackathon(1).md`
- `From Code to Confidence_ An Engineering Framework for Verifying Trust in Autonomous SRE Systems(1).md`
- `From Hallucination to Verifiable Action_ A Comparative Analysis of Lyzr's Regulated Agent Challenges(2).md`
- `The Minimalist Safeguard_ A Hybrid Architecture for Production AI Agents Combining Lyzr's Capabilities with a Critical Deterministic Control Layer(1).md`
- `Why Action Safety is the Winning Hackathon Strategy_ A Feasibility Study for Building Credible, Governed Autonomous Agents(2).md`
- Prior ProofOps module audit/forensic/hardening reports supplied in the conversation.

**Conflict rule:** Where the final V2 specification explicitly supersedes V1 implementation details, V2 wins. Where a capability or submission condition can change, re-check the current official platform before acting.

---

# 28. Master Operating Mantra

> **BUILD LESS. PROVE MORE. GOVERN THE AGENT. MEASURE EVERYTHING. MAKE THE DEMO UNFORGETTABLE.**

> **PARALLEL BUILD. SERIAL TRUST.**

> **NO TRUST WITHOUT EVIDENCE. NO MERGE WITHOUT APPROVAL. NO CLAIM WITHOUT PROOF.**

---

**END OF MASTER CHECKLIST**
