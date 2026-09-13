# ProofOps — Complete Module Registry (183 controlled units)

> Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md`. One module at a time. No auto-continue.
> Progress: **3/183 implemented** (M00.1 APPROVED 84, M00.2 awaiting verdict, M00.3 APPROVED 90/100, locked) · **2/183 approved** · Overall project score: NOT COMPUTED.

## Global Verification Gate (applies to every unit)

A unit proceeds only if ALL hold: OVERALL ≥ 90 · SAFETY ≥ 95 where REQUIRED · GROUNDING ≥ 95 where REQUIRED ·
HALLUCINATION ≥ 95 where REQUIRED · no critical security failures · no unresolved P0 · all tests pass · human APPROVE.
Otherwise: STOP. Critical defects (shell exec, policy bypass, RED executed, YELLOW w/o approval, replayable approval,
fake audit, MUST-CITE without evidence, verifier trusting planner, telemetry-as-instructions, committed secret,
hidden safety failure, false Lyzr claim) BLOCK downstream immediately.

## Score codes

`R` = REQUIRED (≥95 gate, blocks next module) · `S` = SCORED (reported, non-blocking) · `N` = N/A with justification.
Every unit also gets: Overall /100 (10 dimensions) · Performance measured (P50/P95/tokens/cost, never invented) ·
Auditability /100. Submodules + sub-submodules are expanded at implementation time (no-average-hiding rule);
registry tracks unit-level status only.

## Standard human verification checklist (every unit)

`[ ] Code inspected [ ] Tests reproduced [ ] Negative tests reproduced [ ] Security test reproduced [ ] Output verified
[ ] Audit verified [ ] Metrics verified [ ] Spec matched [ ] No unexpected files/features [ ] No secrets [ ] No unsafe bypass`
→ Verdict: APPROVE / REJECT / FIX REQUIRED.

---

## PHASE 00 — Repository Foundation (7)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M00.1 | repository structure | APPROVED (84/100, human verdict, locked) | S | N | N | N | hardened structure tests (22) + clean --no-cache build + 3x healthy + secret scan + scorecard |
| M00.2 | environment/configuration | IMPLEMENTED, awaiting verdict | S | N | N | N | env-load + missing-key + secret-scan tests |
| M00.3 | Docker Compose | APPROVED (90/100, human verdict, locked) | S | N | N | N | runtime matrix + failure injection + persistence + COMPOSE.md |
| M00.4 | health checks | APPROVED (95/100, human verdict, locked) | S | N | N | N | endpoint + dependency-down tests |
| M00.5 | logging foundation | APPROVED (94/100, human verdict, locked) | S | N | N | N | format/redaction + no-secret-in-log tests |
| M00.6 | documentation foundation | APPROVED (96/100, human verdict, locked) | N | N | N | N | 8-docs presence + spec-link tests |
| M00.7 | CI foundation | APPROVED (93/100, human verdict, locked) | S | N | N | N | ruff→mypy→unit→security pipeline green |

## PHASE 01 — Contracts (15)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M01.1 | shared types | APPROVED (94/100, human verdict, locked) | S | N | N | N | schema unit + 20-invalid-fixture tests |
| M01.2 | Incident schema | NOT STARTED | S | N | N | N | valid + invalid + 14-state CHECK tests |
| M01.3 | Alert schema | NOT STARTED | S | N | N | N | valid + invalid tests |
| M01.4 | Evidence schema | NOT STARTED | S | N | N | N | valid + invalid + hash-field tests |
| M01.5 | Hypothesis schema | NOT STARTED | S | N | N | N | status-enum + citation-field tests |
| M01.6 | Runbook schema | NOT STARTED | S | N | N | N | pin + hash-field tests |
| M01.7 | Action schema | NOT STARTED | S | N | N | N | allowlist + param-shape + shell-reject tests |
| M01.8 | PolicyDecision schema | NOT STARTED | S | N | N | N | ALLOW/ESCALATE/DENY + rule-ref tests |
| M01.9 | Approval schema | NOT STARTED | S | N | N | N | token/nonce/expiry-field tests |
| M01.10 | Execution schema | NOT STARTED | S | N | N | N | idempotency-field + diff-field tests |
| M01.11 | Verification schema | NOT STARTED | S | N | N | N | verdict-enum tests |
| M01.12 | Rollback schema | NOT STARTED | S | N | N | N | reversibility-field tests |
| M01.13 | RCA schema | NOT STARTED | S | N | N | N | gate-field + claim-map tests |
| M01.14 | Audit schema | NOT STARTED | S | N | N | N | hash-chain-field + ordering tests |
| M01.15 | Evaluation schema | NOT STARTED | S | N | N | N | metric-JSONB + run-ref tests |

## PHASE 02 — Telemetry (10)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M02.1 | telemetry generator | NOT STARTED | S | N | N | N | determinism: same-seed→same-sha tests |
| M02.2 | deterministic seeding | NOT STARTED | S | N | N | N | seed-log + replay-identical tests |
| M02.3 | alert generation | NOT STARTED | S | N | N | N | count/shape per (scenario,variant,seed) tests |
| M02.4 | log generation | NOT STARTED | S | N | N | N | injection-neutral content tests |
| M02.5 | metrics generation | NOT STARTED | S | N | N | N | pre/post-delta shape tests |
| M02.6 | traces | NOT STARTED | S | N | N | N | exemplar + span-ref tests |
| M02.7 | Kubernetes events | NOT STARTED | S | N | N | N | event-shape + ts-index tests |
| M02.8 | deployment events | NOT STARTED | S | N | N | N | from→to+author ±15m tests |
| M02.9 | service topology | NOT STARTED | S | N | N | N | neighbor-edge tests |
| M02.10 | telemetry hashing | NOT STARTED | S | N | N | N | sha-log completeness tests |

## PHASE 03 — Normalization (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M03.1 | alert normalization | NOT STARTED | S | N | N | N | malformed-input + missing-field tests |
| M03.2 | log normalization | NOT STARTED | S | N | N | N | DATA-not-instructions + delimit tests |
| M03.3 | metrics normalization | NOT STARTED | S | N | N | N | window/delta tests |
| M03.4 | trace normalization | NOT STARTED | S | N | N | N | ref-integrity tests |
| M03.5 | deployment normalization | NOT STARTED | S | N | N | N | diff-shape tests |
| M03.6 | canonical telemetry model | NOT STARTED | S | N | N | N | cross-source join + index tests |

## PHASE 04 — Correlation (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M04.1 | fingerprinting | NOT STARTED | S | N | N | N | sha256(service\|sig\|env\|window) tests |
| M04.2 | grouping | NOT STARTED | S | N | N | N | 30-fixture group tests |
| M04.3 | deduplication | NOT STARTED | S | N | N | N | ≤5s + duplicate-suppress tests |
| M04.4 | severity | NOT STARTED | S | N | N | N | P1–P4 rule tests |
| M04.5 | dependency correlation | NOT STARTED | S | N | N | N | edge+10m+sim>0.7 tests |
| M04.6 | edge cases | NOT STARTED | S | N | N | N | split/merge adversarial-fixture tests |

## PHASE 05 — Evidence (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M05.1 | evidence object | NOT STARTED | S | R | N | N | field + ref tests |
| M05.2 | evidence hashing | NOT STARTED | S | R | N | N | hash-validity tests |
| M05.3 | evidence freshness | NOT STARTED | S | R | N | N | staleness>15m-escalate tests |
| M05.4 | trust level | NOT STARTED | S | R | N | N | high/med/low + agreement tests |
| M05.5 | evidence pack | NOT STARTED | S | R | N | N | ≤6k-token + predigest tests |
| M05.6 | claim-to-evidence mapping | NOT STARTED | S | R | N | N | MUST-CITE coverage=1.0 gate tests |

## PHASE 06 — Policy / Safety (10)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M06.1 | action validator | NOT STARTED | R | N | N | N | shell/DROP/param-shape reject tests (pre-policy) |
| M06.2 | action taxonomy | NOT STARTED | R | N | N | N | allowlist completeness tests |
| M06.3 | risk matrix | NOT STARTED | R | N | N | N | matrix-vs-bundle consistency tests |
| M06.4 | policy schema | NOT STARTED | R | N | N | N | bundle version/rule-ref tests |
| M06.5 | policy engine | NOT STARTED | R | N | N | N | 40+ regression tests (ALLOW/ESCALATE/DENY) |
| M06.6 | default deny | NOT STARTED | R | N | N | N | unknown/exception→DENY tests |
| M06.7 | conflict resolution | NOT STARTED | R | N | N | N | most-restrictive-wins tests |
| M06.8 | blast-radius evaluation | NOT STARTED | R | N | N | N | scope/replicas/traffic% threshold tests |
| M06.9 | environment-aware rules | NOT STARTED | R | N | N | N | mock/staging/prod matrix tests |
| M06.10 | policy audit | NOT STARTED | R | N | N | N | version+rule_id linkage tests |

## PHASE 07 — HITL (8)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M07.1 | approval request | NOT STARTED | R | N | N | N | field + params-hash binding tests |
| M07.2 | HMAC token | NOT STARTED | R | N | N | N | sign/verify + wrong-secret DENY tests |
| M07.3 | nonce | NOT STARTED | R | N | N | N | single-use burn tests |
| M07.4 | TTL | NOT STARTED | R | N | N | N | expiry→410 + escalate tests |
| M07.5 | scope binding | NOT STARTED | R | N | N | N | tampered-params DENY tests |
| M07.6 | actor binding | NOT STARTED | R | N | N | N | wrong-role DENY tests |
| M07.7 | replay protection | NOT STARTED | R | N | N | N | replay→DENY + audit tests |
| M07.8 | approval audit | NOT STARTED | R | N | N | N | approve/deny/expire event tests |

## PHASE 08 — Sandbox (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M08.1 | stateful mock executor | NOT STARTED | R | N | N | N | state-flap/ready transition tests |
| M08.2 | action state transitions | NOT STARTED | R | N | N | N | restart/scale/rollback transition tests |
| M08.3 | zero-diff block guarantee | NOT STARTED | R | N | N | N | blocked-action→zero-diff assert tests |
| M08.4 | execution logging | NOT STARTED | R | N | N | N | tier + diff + log-record tests |
| M08.5 | Docker executor | NOT STARTED | R | N | N | N | allowlist-mutate + RED-refuse tests |
| M08.6 | isolation checks | NOT STARTED | R | N | N | N | unpriv + no-secret-mount + net-isolated tests |

## PHASE 09 — Verification (8)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M09.1 | health checks | NOT STARTED | R | N | N | N | pod-ready tests |
| M09.2 | deployment checks | NOT STARTED | R | N | N | N | available-replicas + version tests |
| M09.3 | SLO checks | NOT STARTED | R | N | N | N | threshold-config tests |
| M09.4 | error-rate checks | NOT STARTED | R | N | N | N | err<thr tests |
| M09.5 | latency checks | NOT STARTED | R | N | N | N | p95<SLO tests |
| M09.6 | CrashLoop checks | NOT STARTED | R | N | N | N | zero-new-CrashLoop-60s tests |
| M09.7 | verification verdict | NOT STARTED | R | N | N | N | RESOLVED/PARTIAL/FAILED/WORSENED matrix tests |
| M09.8 | rollback trigger | NOT STARTED | R | N | N | N | exit-0-bad-SLO→FAILED + trigger tests |

## PHASE 10 — Rollback (5)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M10.1 | rollback action schema | NOT STARTED | R | N | N | N | template-field tests |
| M10.2 | rollback conditions | NOT STARTED | R | N | N | N | FAILED/WORSENED/REQUIRED-condition tests |
| M10.3 | rollback executor | NOT STARTED | R | N | N | N | one-auto-attempt tests |
| M10.4 | re-verification | NOT STARTED | R | N | N | N | re-verify→RESOLVED\|ESCALATED tests |
| M10.5 | escalation | NOT STARTED | R | N | N | N | irreversible-no-path + escalate tests |

## PHASE 11 — Runbooks (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M11.1 | runbook schema | NOT STARTED | R | N | N | N | field + forbidden-action tests |
| M11.2 | runbook loader | NOT STARTED | R | N | N | N | load + parse-error tests |
| M11.3 | hash validation | NOT STARTED | R | N | N | N | tampered-hash reject tests |
| M11.4 | version pinning | NOT STARTED | R | N | N | N | floating-version reject tests |
| M11.5 | parameter validation | NOT STARTED | R | N | N | N | JSON-schema + regex/range tests |
| M11.6 | five deep runbooks | NOT STARTED | R | N | N | N | poisoned-runbook rejection + content tests |

## PHASE 12 — Retrieval (7)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M12.1 | Lyzr KB | NOT STARTED | S | R | N | R | Classic-KB wiring + threshold tests |
| M12.2 | metadata filtering | NOT STARTED | S | R | N | R | service/env filter tests |
| M12.3 | temporal filtering | NOT STARTED | S | R | N | R | ±window + decay tests |
| M12.4 | pre-digestion | NOT STARTED | S | R | N | R | raw-vs-predigest comparison tests |
| M12.5 | Evidence Pack generation | NOT STARTED | S | R | N | R | ≤6k-token pack tests |
| M12.6 | ranking | NOT STARTED | S | R | N | R | rerank + top-k=5 tests |
| M12.7 | retrieval metrics | NOT STARTED | S | R | N | R | p@5/r@5/MRR/nDCG + baseline-vs-optimized delta |

## PHASE 13 — Lyzr Agents (10)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M13.1 | Lyzr client | NOT STARTED | R | R | R | S | chat/session/stream + fallback-classification tests |
| M13.2 | Triage Agent | NOT STARTED | R | R | R | S | mocked-LLM severity/fingerprint contract tests |
| M13.3 | Diagnostic Agent | NOT STARTED | R | R | R | S | hypotheses + INSUFFICIENT_EVIDENCE tests |
| M13.4 | Remediation Planner | NOT STARTED | R | R | R | S | Action-struct + no-shell-vocab tests |
| M13.5 | RCA Reporter | NOT STARTED | R | R | R | S | gated-publish + blameless-lint tests |
| M13.6 | structured output | NOT STARTED | R | R | R | S | schema-conformance + Pydantic re-validation tests |
| M13.7 | sessions | NOT STARTED | R | R | R | S | session_id=incident_id + resume tests |
| M13.8 | RAI | NOT STARTED | R | R | R | S | per-agent guard attachment + verdict tests |
| M13.9 | KB | NOT STARTED | R | R | R | S | runbook/history link + threshold tests |
| M13.10 | memory | NOT STARTED | R | R | R | S | Cognis + Global-Context + 10-msg-window tests |

## PHASE 14 — Orchestration (8)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M14.1 | FSM | NOT STARTED | R | N | N | N | 14-state definition tests |
| M14.2 | transitions | NOT STARTED | R | N | N | N | valid/invalid/terminal transition tests |
| M14.3 | retries | NOT STARTED | R | N | N | N | bounded-retry (re-plan≤2) tests |
| M14.4 | timeouts | NOT STARTED | R | N | N | N | stage-TTL→ESCALATED tests |
| M14.5 | idempotency | NOT STARTED | R | N | N | N | duplicate→cached + audit tests |
| M14.6 | agent handoffs | NOT STARTED | R | N | N | N | handoff-schema + ACL tests |
| M14.7 | approval branch | NOT STARTED | R | N | N | N | no-skip POLICY_CHECK→EXECUTING tests |
| M14.8 | failure branches | NOT STARTED | R | N | N | N | BLOCKED/ESCALATED path + audit tests |

## PHASE 15 — Audit / AIMS (6)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M15.1 | audit events | NOT STARTED | S | N | N | N | completeness + ordering tests |
| M15.2 | hash chain | NOT STARTED | S | N | N | N | prev/curr SHA256-link tests |
| M15.3 | audit verification | NOT STARTED | S | N | N | N | verify-endpoint + tamper-detect tests |
| M15.4 | AIMS trace | NOT STARTED | S | N | N | N | trace-link (labelled non-custom) tests |
| M15.5 | audit export | NOT STARTED | S | N | N | N | export-format + valid-bool tests |
| M15.6 | evidence linkage | NOT STARTED | S | N | N | N | action/approval/execution linkage tests |

## PHASE 16 — Evaluation Engine (9)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M16.1 | runner | NOT STARTED | S | N | N | S | CASE→RUN→TRACE→GRADE→SCORE pipeline tests |
| M16.2 | dataset loader | NOT STARTED | S | N | N | S | deep-5×5 + stub-7 load tests |
| M16.3 | graders | NOT STARTED | S | N | N | S | grader-determinism tests |
| M16.4 | baseline | NOT STARTED | S | N | N | S | baseline-capture tests |
| M16.5 | optimized | NOT STARTED | S | N | N | S | optimized-capture + delta tests |
| M16.6 | six checkpoint scoring | NOT STARTED | S | N | N | S | C1–C6 metric tests |
| M16.7 | rubric scoring | NOT STARTED | S | N | N | S | 30/30/20/20 estimator tests |
| M16.8 | JSONL | NOT STARTED | S | N | N | S | runs/*.jsonl schema tests |
| M16.9 | HTML scorecard | NOT STARTED | S | N | N | S | scorecard-link→run tests |

## PHASE 17 — Benchmarks (7)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M17.1 | bad deployment | NOT STARTED | S | N | N | N | expected-RCA + allowed/forbidden tests |
| M17.2 | CrashLoop/OOM | NOT STARTED | S | N | N | N | expected-RCA + SLO tests |
| M17.3 | DB exhaustion | NOT STARTED | S | N | N | N | expected-RCA + SLO tests |
| M17.4 | network/dependency | NOT STARTED | S | N | N | N | expected-RCA + failover tests |
| M17.5 | malicious log injection | NOT STARTED | S | N | N | N | containment-expectation tests |
| M17.6 | variants | NOT STARTED | S | N | N | N | NORMAL/NOISY/INCOMPLETE/CONTRADICTORY/ADVERSARIAL ×5 tests |
| M17.7 | stub seven scenarios | NOT STARTED | S | N | N | N | minimal-fixture tests |

## PHASE 18 — Adversarial (10)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M18.1 | prompt injection | NOT STARTED | R | N | N | N | injection_success=0 tests |
| M18.2 | poisoned runbook | NOT STARTED | R | N | N | N | loader-rejection tests |
| M18.3 | fake telemetry | NOT STARTED | R | N | N | N | multi-source-agreement tests |
| M18.4 | stale telemetry | NOT STARTED | R | N | N | N | freshness-gate tests |
| M18.5 | contradictory telemetry | NOT STARTED | R | N | N | N | contradiction-surface (never-average) tests |
| M18.6 | unsafe action | NOT STARTED | R | N | N | N | unsafe_exec=0 tests |
| M18.7 | parameter injection | NOT STARTED | R | N | N | N | regex/range-reject tests |
| M18.8 | secret extraction | NOT STARTED | R | N | N | N | redact + no-secret-mount tests |
| M18.9 | approval replay | NOT STARTED | R | N | N | N | replay-DENY tests |
| M18.10 | runaway loop | NOT STARTED | R | N | N | N | bounds (hyp≤3/tools≤5/calls≤12) + kill-switch tests |

## PHASE 19 — Frontend (10)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M19.1 | shell/app foundation | NOT STARTED | S | N | N | N | 5-route scaffold + build tests |
| M19.2 | command center | NOT STARTED | S | N | N | N | queue + severity-chip tests |
| M19.3 | incident detail | NOT STARTED | S | N | N | N | timeline + evidence-chip-link tests |
| M19.4 | safety gate | NOT STARTED | S | N | N | N | approve/deny + TTL-countdown tests |
| M19.5 | execution/verification | NOT STARTED | S | N | N | N | stream + BEFORE/AFTER-diff tests |
| M19.6 | RCA/evaluation | NOT STARTED | S | N | N | N | RCA-doc + six-gate-chart tests |
| M19.7 | SSE | NOT STARTED | S | N | N | N | stream + reconnect + polling-fallback tests |
| M19.8 | live/replay/mock indicators | NOT STARTED | S | N | N | N | badge-visibility + honesty tests |
| M19.9 | state-diff visualization | NOT STARTED | S | N | N | N | diff-render tests |
| M19.10 | audit visualization | NOT STARTED | S | N | N | N | chain + valid-badge tests |

## PHASE 20 — Performance (7)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M20.1 | token measurement | NOT STARTED | N | N | N | N | tokens_in/out ledger + budget-assert tests |
| M20.2 | latency measurement | NOT STARTED | N | N | N | N | per-stage P50/P95 tests |
| M20.3 | cost measurement | NOT STARTED | N | N | N | N | pricing-table (no-hardcoded-$) tests |
| M20.4 | retrieval optimization | NOT STARTED | N | N | N | S | cache_hit>50% tests |
| M20.5 | model routing | NOT STARTED | N | N | N | S | small-triage/large-diagnosis routing tests |
| M20.6 | caching | NOT STARTED | N | N | N | S | static-ctx-cache tests |
| M20.7 | parallelization | NOT STARTED | N | N | N | S | parallel-fetch timing tests |

## PHASE 21 — Integration (9)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M21.1 | end-to-end happy path | NOT STARTED | R | S | N | N | seed→RESOLVED full-path test |
| M21.2 | RED block | NOT STARTED | R | S | N | N | block + zero-diff + audit test |
| M21.3 | YELLOW approval | NOT STARTED | R | S | N | N | token→approve→execute test |
| M21.4 | sandbox execution | NOT STARTED | R | S | N | N | tier-labelled exec test |
| M21.5 | verification | NOT STARTED | R | S | N | N | verdict-badge test |
| M21.6 | rollback | NOT STARTED | R | S | N | N | auto-once + re-verify test |
| M21.7 | RCA | NOT STARTED | R | S | N | N | gated-publish test |
| M21.8 | audit | NOT STARTED | R | S | N | N | chain-valid export test |
| M21.9 | evaluation | NOT STARTED | R | S | N | N | scorecard-link test |

## PHASE 22 — Demo (7)

| ID | Unit | Status | Safety | Ground | Hall | Retr | Verify method |
|---|---|---|---|---|---|---|---|
| M22.1 | seeded scenario | NOT STARTED | S | N | N | N | bad-deploy/NORMAL reseed tests |
| M22.2 | demo script | NOT STARTED | S | N | N | N | 5:00-moment→code mapping tests |
| M22.3 | replay mode | NOT STARTED | S | N | N | N | cached-Action live-gate tests |
| M22.4 | fallback | NOT STARTED | S | N | N | N | LIVE/REPLAY/MOCK/OFFLINE trigger tests |
| M22.5 | demo checker | NOT STARTED | S | N | N | N | `demo.sh --check` <5min tests |
| M22.6 | rehearsal | NOT STARTED | S | N | N | N | 3× rehearsal-log tests |
| M22.7 | final evidence package | NOT STARTED | S | N | N | N | package-completeness tests |

---

## Totals

7+15+10+6+6+6+10+8+6+8+5+6+7+10+8+6+9+7+10+10+7+9+7 = **183 units** across 23 phases (00–22).
