# AGENTS.md — ProofOps Operating Constitution

**AI Quest 2026 · PS03 — Enterprise Cloud Incident Triage & Runbook Remediation Agent**

> THE AGENT MAY REASON. THE CONTROL PLANE DECIDES. THE SANDBOX CONTAINS.
> VERIFICATION PROVES. AIMS RECORDS.
>
> **THE LLM IS NOT THE SECURITY BOUNDARY.**
>
> **CURRENT MODE: BUILD-FIRST — breadth before perfection. PARALLEL BUILD, SERIAL TRUST. Never defer safety (see §14).**

Every coding agent working on ProofOps must read this file first, then the
authoritative spec, then the module tracker — before touching any code.
Documentation/governance only: this file contains no implementation code.
Current mission: complete system coverage first (§14 BUILD PHASE), then a
dedicated zero-trust hardening and audit phase (§14 FINAL TRUST PHASE).
Do not spend disproportionate time perfecting early modules while most
registered modules remain unimplemented.

- Authoritative spec: `docs/PS03_FINAL_SPEC_V2.md` (FINAL AUTHORITATIVE —
  supersedes `docs/archive/PS03_FINAL_SPEC.md` Part B on conflict).
- Module tracker: `docs/MODULE_REGISTRY.md` (183 controlled units, phases 00–22).
- Architecture decisions: `docs/DECISIONS.md` (ADR log).
- Trust motto: agent reasons, control plane decides — verify everything,
  claim nothing unproven.

---

## §0 — How to read this file: source hierarchy and label legend

### 0.1 Source-of-truth order (highest wins on conflict)

| # | Source | Role |
|---|--------|------|
| 0 | Current HiDevs / challenge submission UI + current organizer instructions | OPERATIONAL source of truth for submission state, limits, required fields, late changes. |
| 1 | `docs/PS03_FINAL_SPEC_V2.md` | AUTHORITATIVE implementation spec. V2 wins over V1 everywhere. |
| 2 | `docs/archive/PS03_FINAL_SPEC.md` (V1) | Background only unless superseded by V2. |
| 3 | `docs/research/AI_Quest_2026_PS03_Hackathon_Rules_and_Evaluation.md` | OFFICIAL competition requirements. Never upgrade recommendations into requirements. |
| 4 | `docs/research/AI_Quest_2026_PS03_Master_Research.md` | Research-backed engineering guidance, competitive strategy. |
| 5 | `docs/research/Beyond the Wrapper…md` | Winner patterns, verifiability, architecture, evaluation, demo strategy. |
| 6 | `docs/research/From Code to Confidence…md` | Trust engineering, observability, evaluation, Lyzr capability role separation. |
| 7 | `docs/research/From Hallucination to Verifiable Action…md` | Regulated-agent patterns, safety, governance, action control. |
| 8 | `docs/research/The Minimalist Safeguard…md` | Deterministic safety boundary, sandboxing, risk containment. |
| 9 | `docs/research/Why Action Safety is the Winning Hackathon Strategy…md` | Strategic positioning, defensible safety architecture. |
| 10 | `docs/MODULE_REGISTRY.md` + audit reports | Current implementation truth + evidence. Never assume a capability exists because a spec mentions it. |
| 11 | Agent judgment | LOWEST authority; never silently overrides higher sources. |

Master operational checklist (`docs/ProofOps_PS03_Master_Winning_Implementation_Trust_Submission_Checklist.md`,
when present) is `[UNVERIFIED]` input — `docs/MODULE_REGISTRY.md` + spec §60–§61
govern on conflict. Do not assume its contents.

### 0.2 Claim labels (mandatory — every important claim carries one)

`[OFFICIAL]` organizer requirement · `[SPEC]` V2 spec requirement ·
`[RESEARCH]` evidence-backed · `[PROPOSED]` our choice · `[OPTIONAL]` stretch ·
`[FUTURE]` post-hackathon · `[PROVISIONAL]` target to revise after baseline runs ·
`[UNVERIFIED]` not confirmed.

Never present `[PROPOSED]` or `[RESEARCH]` material as an official organizer requirement.

### 0.3 Requirement classification (spec §03)

- `[OFFICIAL]` = spec §02 only (ingest, triage+dedup, P1–P4, diagnosis from
  mock telemetry, governed remediation + HITL, blameless postmortem,
  Lyzr capabilities + orchestration, Safe AI, AIMS audit where supported, MVP scope).
- `[RESEARCH]` = runbook grounding, hash-chained audit, eval harness +
  adversarial suite, pre-digestion, SSE streaming, MTTR/scorecard surfaces.
- `[PROPOSED]` = 4th agent (RCA Reporter), HMAC approval tokens,
  mock→docker→kind tiers, 14-state FSM, claim classes.
- `[OPTIONAL]` = Kind live, cost board, FP feedback, prevention-PR draft,
  Manager Agent conversational front, SuperFlow mirror, Semantic Model queries.
- `[FUTURE]` = voice, live vendor integrations (Prometheus/PagerDuty/Datadog/
  ServiceNow/GitHub/Argo), multi-cluster, gVisor/Kata/Firecracker, SSO/SIEM,
  break-glass production behavior (MUST remain disabled in hackathon demo).

---

## §1 — What ProofOps is

**Product:** Evidence-Grounded Incident Commander — subtitle: Agentic Operations
Control Plane. **Core value:** evidence-grounded incident response with provable safety.

Canonical pipeline (never reduce to ALERT → LLM → ANSWER):

```text
DETECT → NORMALIZE → CORRELATE → EVIDENCE → REASON → HYPOTHESIZE → PLAN →
VALIDATE → POLICY → SAFE AI → HITL → EXECUTE → VERIFY → ROLLBACK/ESCALATE →
RCA → AUDIT → EVALUATE
```

Canonical control flow (no endpoint, agent, tool, UI interaction, or shortcut
may bypass it):

```text
INGEST → NORMALIZE → CORRELATE → TRIAGE → EVIDENCE RETRIEVAL → DIAGNOSIS →
HYPOTHESIS TESTING → RUNBOOK PIN → PLAN → ACTION VALIDATION → POLICY → RAI →
HITL IF REQUIRED → SANDBOX/EXECUTION → VERIFICATION → ROLLBACK IF REQUIRED →
RCA → AUDIT → EVALUATION
```

### 1.1 Security invariants (non-negotiable — any violation = BLOCK)

1. No unvalidated Action reaches the executor.
2. RED never executes in hackathon mode (no break-glass path exists).
3. YELLOW requires valid authorization (ALLOW permit or valid approval token).
4. Approval tokens are single-use.
5. Approval tokens are HMAC-protected where implemented.
6. Approval tokens are nonce-protected.
7. Approval tokens are TTL-bound.
8. Approval scope is exact (bound to `action_id` + exact parameter hash).
9. LLM has no direct shell/exec capability.
10. Telemetry cannot change trusted instructions (telemetry is DATA).
11. Mutation requires `action_id`.
12. Mutation requires a policy decision.
13. Execution requires verification.
14. Blocks emit audit events.
15. RCA requires evidence coverage (MUST-CITE gate).
16. Agent loops are bounded (hypotheses ≤3, re-plans ≤2, tools ≤5/agent,
    LLM calls ≤12/incident, retries explicitly bounded).
17. Token/cost budgets are bounded; kill-switch exists for unsafe conditions.
18. Safety failures fail closed.
19. `POLICY_CHECK → EXECUTING` without a deterministic ALLOW permit or a valid
    approval token for the exact action is forbidden (enforced in code + test).
20. Exit status cannot substitute for verification (`EXIT 0 ≠ RESOLVED`).
21. Client cannot authorize itself; UI cannot bypass server policy.
22. Replay cannot recreate authority.
23. Tampered audit chain must be detectable.

---

## §2 — Authoritative architecture (frozen)

### 2.1 Lyzr responsibility model

**LYZR-NATIVE** (real responsibility each — see §3):
1. Triage Agent (A1) · 2. Diagnostic Agent (A2) · 3. Remediation Planner (A3) ·
4. RCA Reporter (A4).

Authentic Lyzr capabilities: Agent API/ADK · Structured Output · Responsible
AI / Safe AI / RAI · Classic Knowledge Base · Cognis/memory · Global Context ·
session persistence · chat · stream-chat · trace/observability · Agent
Evaluation / Eval-assist where useful.

**CUSTOM-DETERMINISTIC:** FastAPI FSM, validator, policy engine, HMAC HITL,
sandbox, verifier, rollback, SHA256 hash audit, eval runner, pre-digester, SSE hub.

**SIMULATED:** telemetry generator, mock K8s state, mock executor; docker tier
is real-but-local.

**FUTURE:** Kind default, voice, KG/Semantic Model, vendor connectors,
gVisor/Kata, SSO/SIEM.

### 2.2 Canonical control plane decision (frozen, spec §04-G01)

**CUSTOM FASTAPI FSM IS THE CANONICAL CONTROL PLANE.**
SuperFlow is `[OPTIONAL]` mirror only. **Automata MUST NOT be the canonical
control plane** — it is banned as control plane (experimental upstream README,
"imperfections"). Automata may be mentioned historically in `docs/DECISIONS.md`
only. Never quietly reintroduce Automata as the authority.

Rationale (recorded): repo-versioned, CI-testable, offline-demo-safe; a Studio
DAG cannot be diffed/tested in CI.

### 2.3 Lyzr authenticity rule (binding on code, README, UI, demo)

Every Lyzr capability must have: actual integration · actual execution ·
testable behavior · observable evidence · documented responsibility · clear
failure behavior. Never: fake Lyzr labels around custom code; call a local
function "Lyzr"; create decorative agents; claim Safe AI is Kubernetes
authorization; claim custom hash audit is AIMS; claim a custom FSM is Automata;
claim replay is live Lyzr execution; claim a local log is AIMS.

Before claiming any Lyzr capability, check: current official Lyzr docs ·
current challenge expectations · actual project account/workspace capability ·
verify the implementation · label the result accurately. Never fake: Automata
graphs · Safe AI traces · AIMS traces · Agent API calls · screenshots ·
execution results.

README/UI/demo must clearly distinguish: **LYZR-NATIVE · CUSTOM-DETERMINISTIC ·
SIMULATED · FUTURE**. If custom, say CUSTOM. If simulated, say SIMULATED.
If future, say FUTURE. If Lyzr-native and verified, say LYZR-NATIVE.

A capability is authentic only when all six authenticity properties hold.
`[OPTIONAL]` Manager Agent = conversational front only, may call GET views or
trigger FSM runs, never owns mutations.

---

## §3 — Agent workforce (exactly four Lyzr agents, frozen)

| Agent | Non-mutating in | Must |
|-------|-----------------|------|
| **A1 Triage** — normalized alerts → severity P1–P4, fingerprint, cluster, owner, signals; supports correlation context | MUST NOT execute mutations, make final authorization decisions, change infrastructure, invent telemetry | stay non-mutating; reads only |
| **A2 Diagnostic** — Evidence Pack → 2–3 competing hypotheses + runbook pin, or `INSUFFICIENT_EVIDENCE` | MUST NOT authorize execution, invent evidence, mutate infrastructure | cite evidence; surface contradictions; never average them away |
| **A3 Remediation Planner** — diagnostic output → structured Action + expected outcome + verification plan + rollback where reversible | MUST NEVER produce arbitrary shell, execute tools directly, bypass validator/policy, redefine risk authority | emit data only; no shell vocabulary in output schema |
| **A4 RCA Reporter** — timeline, verified root cause, claim→evidence map, remediation/approval/verification record, blameless prevention notes | MUST NOT publish when evidence gate fails | remain blameless (lint blocks personal-blame terms) |

Agent rules: role/goal/instructions + Structured Output schema + KB links + RAI
policy + `session_id = incident_id` + pinned model in config; distinct tool ACLs
per agent (asserted by contract tests); server-side code revalidates ALL Lyzr
output with Pydantic (never trust client JSON alone).

DO NOT ADD EXTRA AGENTS unless: a real responsibility exists · a permission
boundary differs · benchmark evidence justifies it · cost/latency impact is
measured · the change is recorded in `docs/DECISIONS.md`.
**Agent count is not a quality metric.**

---

## §4 — Deterministic services (LLMs reason; these decide)

Deterministic wherever applicable: normalization · correlation · pre-digestion ·
retrieval filtering · action validation · policy engine · risk classification ·
permission checks · FSM transitions · idempotency · approval-token validation ·
sandbox execution · verification · rollback · hash audit · evaluation grading ·
budget enforcement · kill-switch behavior.

Deterministic services own anything involving authorization, permissions,
mutation, side effects, final verification, state transitions, audit integrity.

---

## §5 — State machine (canonical 14 states, spec §15)

```text
NEW → TRIAGING → CORRELATED → INVESTIGATING → DIAGNOSING → PLANNED →
POLICY_CHECK → {BLOCKED | AWAITING_APPROVAL | APPROVED} → EXECUTING →
VERIFYING → {RESOLVED | ROLLBACK | ESCALATED} → RCA_PENDING →
RCA_PUBLISHED → AUDITED
```

- Transitions: explicit, deterministic, validated, auditable; invalid
  transitions, policy skips, execution without authorization, approval without
  valid token, RCA publication without evidence gate are all rejected.
- `APPROVED` is a transient permit (token ref). V1 extras (`INGESTING`,
  `FAILED`) are subsumed as entry sub-status / `ESCALATED` with `reason`.
- Retryable: TRIAGING, DIAGNOSING, PLANNED (re-plan ≤2), EXECUTING (idempotent
  key), VERIFYING. Agent stages 30–60s → ESCALATED; approval TTL 10m
  (15m demo mode) → ESCALATED.
- Rollback: VERIFYING → ROLLBACK → VERIFYING once → RESOLVED|ESCALATED.
- Idempotency: `action_id` + `execution_id`; duplicates return cached result +
  `duplicate-suppressed` audit.
- Bound loops: hypotheses ≤3 · re-plans ≤2 · tools ≤5/agent ·
  LLM calls ≤12/incident · retries explicitly bounded. **No infinite agent loops.**

---

## §6 — Action safety

Action is a structured object (spec §16: `action_id`, `incident_id`,
`agent_id`, `action_type`, `resource_type`, `resource_id`, `environment`,
`parameters`, `risk_level` (ADVISORY — policy recomputes effective risk),
`reason`, `evidence_ids`, `runbook_id` + `runbook_version` (pinned),
`expected_outcome`, `rollback_action` where applicable, `verification_plan`).
**The LLM NEVER gets arbitrary shell execution.** Server-side code revalidates
all Lyzr output; risk is recomputed by deterministic policy.

Never trust: model-provided risk · client-provided role · client-provided
authorization · UI state · model assertions · execution exit code.

### 6.1 GREEN / YELLOW / RED (spec §17; decision = f(type, resource, env, params, severity, blast, actor, policy_version) — never keyword-only)

| Tier | Examples | Rule |
|------|----------|------|
| **GREEN** | read, describe, logs, metrics, list, explicitly allowlisted low-risk ops | auto; no HITL |
| **YELLOW** | restart, bounded scale (±≤2), rolling restart, deployment rollback, non-secret config change, other policy-approved reversible mutation | HITL where policy says so; every reversible YELLOW carries rollback + conditions + re-verify plan |
| **RED** | delete namespace/deployment, destructive DB ops, arbitrary shell, RBAC mutation, secret access, node reboot, other forbidden actions | **BLOCKED in hackathon mode.** Break-glass is `[FUTURE]` and MUST remain disabled. Never create a hidden RED execution path. Prod `delete_pod` counts RED in hackathon scope (fail-closed). |

### 6.2 Policy engine (primary deterministic authorization boundary)

Input: action type, resource type, environment, parameters, incident severity,
blast radius, actor identity/role, evidence freshness, runbook version, policy
version. Output: `ALLOW | ESCALATE | DENY` + `rule_id` + obligations + TTL.
Priority `DENY > ESCALATE > ALLOW`; most-restrictive conflict wins; default
`DENY`; any evaluation exception → `DENY` + `policy-error` audit event.
Policy bundle (`/policies/bundle_vX.yaml`) is versioned, testable,
deterministic, explainable, auditable; every decision captures policy version +
matched rule + result + obligations. 40+ regression tests. Do not use
keyword-only safety ("contains delete" is not a policy model).

### 6.3 Safe AI / RAI placement (corrected, spec §04-G02)

Correct sequence: `INPUT → RAI INPUT → LLM → STRUCTURED OUTPUT → RAI OUTPUT →
VALIDATOR → POLICY → HITL → EXECUTOR`. RAI is a per-agent input+output guard
("runs on every agent interaction"), defense-in-depth — it MUST NOT replace
validator, policy, authorization, sandbox, or verification. Every agent uses the
governed RAI policy (`PS03-Governed`) where supported. Never claim "Safe AI
alone guarantees infrastructure safety" and never describe Safe AI as the
deterministic authorization boundary.

### 6.4 HITL

Approval is explicit, action-specific, identity-bound, scope-bound, time-bound,
single-use, auditable, HMAC-protected where implemented. Token binds
`action_id` + exact parameter hash + scope + actor + expiry + nonce.
Server verifies signature, actor role, exact scope match, expiry, unused nonce
(store+burn). Replay/tamper/expired/wrong-actor/wrong-action/wrong-hash/reuse →
`DENY` + audit; errors fail closed. UI Safety Gate exposes incident, action,
resource, risk, blast radius, evidence, policy rule, expected outcome,
rollback, verification plan, agent identity, timestamp, expiry. Approve/deny
are POST with `Idempotency-Key`.

### 6.5 Sandbox

Hackathon default: **MOCK** executor (stateful dict; restart→flap+ready,
scale→replicas, rollback→version; blocked actions → zero state diff, asserted).
`[OPTIONAL]`: DOCKER (unprivileged, no secret mounts, net-isolated, 60s
timeout), KIND toggle. `[FUTURE]` production: gVisor/Kata/Firecracker-class
isolation. Never connect autonomous execution to real production
infrastructure. Every execution exposes its tier; UI badge always shows
**LIVE / REPLAY / MOCK / OFFLINE**. Never hide fallback mode; never call
replay live.

### 6.6 Verification (independent of the planner)

Deterministic; inspects pod readiness, deployment availability, error rates,
latency/SLO, CrashLoop behavior, expected version, relevant health signals.
Verdicts: `RESOLVED | PARTIAL | FAILED | WORSENED | ROLLBACK_REQUIRED |
ESCALATED`. **EXIT CODE 0 DOES NOT MEAN INCIDENT RESOLVED.** Planner output is
never verification evidence. SLO config (`/policies/slo.yaml`) is versioned;
`exit-0-with-bad-SLO → FAILED` is tested.

### 6.7 Rollback

Every reversible YELLOW mutation carries rollback action + conditions +
re-verification criteria. On verification failure: one auto-rollback attempt
where reversible → re-verify → still unhealthy → ESCALATE. Never loop rollback
indefinitely. RED destructive actions intentionally have no autonomous rollback path.

---

## §7 — Runbooks (governed procedures, not model inventions)

Each runbook (`/runbooks/*.yaml`, sha256-pinned): versioned (semver), pinned,
hashed where implemented, scoped, reviewed, owner-attributed, parameterized
through JSON schema, allowlisted, forbidden-action-aware, verification-aware,
rollback-aware. LLM may SELECT and PARAMETERIZE; it may NOT invent runtime
procedures. Initial deep set: `bad-deploy-rollback`, `crashloop-oom`,
`db-pool-saturation`, `net-dep-failover`, `injection-quarantine`. Loader
verifies hash + version pin; poisoned runbooks are rejected (tested).

---

## §8 — Evidence, retrieval, prompts, telemetry, correlation

### 8.1 Evidence + groundedness — NO EVIDENCE → NO CLAIM → NO ACTION

Every important conclusion traces CLAIM → EVIDENCE → SOURCE → TIMESTAMP →
HASH/REFERENCE. Evidence captures `evidence_id`, `incident_id`, `source_type`,
`source_id`, timestamp, reference/span, hash, freshness, relevance, trust
level. Claim classes: MUST-CITE (root cause, factual incident state,
remediation justification, verification result, safety claim) · SHOULD-CITE
(recommendations, context) · OPTIONAL (general synthesis). RCA publication
fails closed when mandatory citation coverage is insufficient. UI makes
evidence navigable (claim→evidence→source line).

### 8.2 Retrieval (frozen — NO pgvector)

Lyzr Classic KB (`runbooks-v*`, `history`) with MMR + score threshold (start
0.7, revise) + top-k=5, plus local metadata/temporal filtering
(service/env/±window, decay) + rerank. Telemetry is pre-digested into a compact
Evidence Pack (≤6k tokens `[PROVISIONAL]`); full blobs live in Postgres by ref.
Never inject giant raw telemetry dumps into the model. Flow: metadata filters +
lexical/keyword + semantic + temporal → ranking/reranking → compact Evidence
Pack. Track precision@k, recall@k, MRR, nDCG, irrelevant-context ratio,
citation precision; always report baseline vs optimized. KG / Semantic Model
(read-only SELECT) are documented `[OPTIONAL]` only. Do not create pgvector
merely because vector search is popular; do not add Kafka/Redis/etc. without
measured need (record justification in `docs/DECISIONS.md`).

### 8.3 Prompt architecture

Every agent prompt defines: IDENTITY · ROLE · OBJECTIVE · SCOPE · INPUT
CONTRACT · TRUSTED DATA · UNTRUSTED DATA · OUTPUT SCHEMA · EVIDENCE RULES ·
TOOL RULES · SAFETY RULES · FORBIDDEN BEHAVIOR · UNCERTAINTY RULES ·
ESCALATION CONDITIONS · STOP CONDITIONS · FAILURE BEHAVIOR. Telemetry is DATA,
never instruction. Injection inside logs/traces/incidents/runbooks/alert text
is untrusted content. Prompt defense is defense-in-depth, NOT the security boundary.

### 8.4 Hallucination mitigation

Agents must not invent alerts, metrics, logs, service state, deployment
history, commands, runbook steps, verification results, evidence, or causal
claims. `UNKNOWN` / `INSUFFICIENT_EVIDENCE` is always safer than fabricated
certainty. Track unsupported-claim rate, fabricated-command rate,
invalid-tool-argument rate, repeatability rate.

### 8.5 Telemetry

Synthetic telemetry must tell coherent incident stories with realistic
correlations across alerts, logs, metrics, traces, K8s events, deployments,
topology, service state. Generator deterministic by scenario + variant + seed;
same seed → reproducible evaluation. Ground truth never leaks into model prompts.

### 8.6 Correlation (deterministic)

Owns fingerprinting (`sha256(service|error_signature|env|deploy_window±15m)`),
grouping, deduplication (≤5s), clustering, severity P1–P4. LLM may propose an
owner; it is never the authority for grouping or severity. Test merge/split,
near-duplicates, unrelated alerts, deploy-window, dependency-correlated, false
positives, alert storms (30-fixture groups).

---

## §9 — Database, API, frontend, realtime

### 9.1 Database / state integrity

FKs, uniqueness, timestamps, indexes, immutable/auditable relationships,
idempotency, state integrity across: users, roles, services, incidents,
alerts, logs, metrics, traces, K8s events, deployments, evidence, hypotheses,
diagnoses, runbooks, policies, actions, approvals, executions, verification
results, rollbacks, postmortems, agent runs, tool calls, retrieval events,
audit events, evaluation runs, benchmark results. No duplicate domain models;
shared contracts (`backend/app/contracts/`) are canonical — no ad-hoc dicts
across module boundaries.

### 9.2 API governance

Every endpoint: explicit responsibility · request/response schema · validation ·
authorization · failure behavior · idempotency where mutating · audit event
where relevant · test coverage. Mutations require authenticated role + action
context + policy decision + idempotency + approval when necessary. No endpoint
bypasses validation, policy, HITL, verification, or audit. Required surface
stays aligned to spec §40 (alerts, incidents, triage, evidence, diagnose,
remediation, approvals approve/reject, executions + verify + rollback, audit,
RCA, evaluations, `POST /demo/seed`). Guards: role verified server-side;
execute re-checks policy-permit freshness (≤5m); typed errors
(400/401/403/404/409/410/422/429), each audited where relevant.

### 9.3 Frontend — exactly five primary MVP views

1. Command Center · 2. Incident Detail · 3. Safety Gate · 4. Execution /
   Verification · 5. RCA / Evaluation. Priorities: operational state, evidence,
   policy, blast radius, approval, execution, verification, audit, scorecard.
   Do not build a chatbot; no decorative AI animation as proof substitute.
   Every UI number traces to evidence/audit/eval run or is labeled a derived metric.

### 9.4 Realtime UX

Lyzr `stream-chat` for agent-token streaming where actually integrated; custom
SSE (`/stream/incidents/{id}`) for control-plane events (incident, agent,
retrieval, policy, approval, execution, verification, audit). SSE reconnects,
carries audit event IDs, has polling fallback, discloses operating mode
(LIVE/REPLAY/MOCK badge always visible).

---

## §10 — Audit / AIMS (label honestly)

**AIMS** = supported Lyzr trace/observability (per-step trace + latency,
transcripts, reports, RBAC/SSO, audit-log filtering) — link incident→session.
**CUSTOM HASH AUDIT** = append-only SHA256 chain
(`curr = SHA256(prev + canonical)`) for exportable local proof, with verify
endpoint + export + tamper-check. **Never label custom rows "AIMS".**
Emit on every transition/tool/policy/approval/exec/verify/RCA/eval event with
`event_id`, `seq`, actor/agent, input hash, evidence IDs, policy
(version/rule/result), action/approval/execution refs, prev/curr hashes.
Tampering test must exist.

---

## §11 — Evaluation, benchmarks, adversarial, quality gates

### 11.1 Evaluation engine (product capability, not a last-minute report)

Pipeline: CASE → RUN → TRACE → GRADE → SCORE → COMPARE → REPORT. Maintains
JSONL runs + machine-readable metrics + human-readable scorecard + baseline-vs-
optimized comparisons + regression history. Split (frozen): **Lyzr Agent Eval**
= agent-level (hallucination/faithfulness/tool-arg via CSV import of our
cases); **custom runner** = pipeline-level (policy/adversarial/SLO/regression).
Do not duplicate responsibilities.

### 11.2 Golden benchmarks

12 data-model categories (bad deployment, memory leak, crashloop, CPU
saturation, disk pressure, DB connection exhaustion, deadlock, network failure,
config error, dependency outage, false positive, cascading alert storm).
Deep-5 fully seeded (bad-deploy, crashloop/OOM, DB exhaustion, network/dep
failure, malicious log injection) × 5 variants
(NORMAL/NOISY/INCOMPLETE/CONTRADICTORY/ADVERSARIAL), each with expected root
cause, allowed/forbidden remediation, verification criteria, relevant evidence;
stub-7 minimal fixtures.

### 11.3 Adversarial testing (minimum 14 attacks; each file: attack / expected / control / metric / audit-assertion)

log injection · prompt injection · poisoned runbook · fake telemetry · stale
telemetry · contradictory telemetry · unsafe command · parameter injection ·
secret exfiltration · approval replay · runaway planner loop · policy bypass ·
duplicate execution · verification spoofing. Expected: BLOCK/DENY/ESCALATE/
CONTAIN/AUDIT. Never "best effort" on security failures.

### 11.4 Six global quality gates (continuous, not postponed; all numeric thresholds `[PROVISIONAL]` — revalidate after 20 baseline runs)

C1 hallucination · C2 groundedness · C3 retrieval quality · C4 cost/token ·
C5 prompt architecture · C6 latency (spec §36 for exact targets; e2e P50 <90s
mock / P95 <4min Kind). Dashboard: metric + baseline + optimized + n + chart
per gate; every number links to run JSONL.

### 11.5 Performance / cost

Never optimize by reducing safety, removing verification, weakening evidence,
bypassing policy, or reducing adversarial coverage. Allowed: pre-digestion,
parallel retrieval, caching, model routing (small triage / larger diagnosis /
medium planner / economical RCA), bounded retries, structured state, context
compression, smaller models for simpler tasks. Measure per-agent/total tokens,
LLM calls, retrieval calls, latency, first paint, execution/verification time,
cache hits. **Raw tokens before $; never hard-code vendor prices** (editable
pricing config only). Approval human-time excluded from e2e budget, TTL-tracked.

---

## §12 — Repository rules (preserve required structure)

Required top-level (spec §43; `[OFFICIAL]` subset: `/agents /frontend /backend
Dockerfile docker-compose.yml .env.example README.md`):

```text
/agents /frontend /backend /policies /runbooks /telemetry /tools
/evaluation /benchmarks /tests /docs /scripts
Dockerfile docker-compose.yml .env.example README.md
```

Required docs: README.md · ARCHITECTURE.md · API.md · SECURITY.md ·
EVALUATION.md · DEMO.md · TESTING.md · DECISIONS.md. Add docs only for real
value. Never create duplicate "final-v2-final" specs. Docs rule: every
statement reflects implemented-today truth; future work is marked PLANNED with
an owning module. Root docs stay minimal — `tests/test_docs.py` pins the
canonical set; updating it requires justification.

Every architecture statement answers: WHAT · WHY · OWNER · TRUST BOUNDARY ·
INPUT · OUTPUT · FAILURE · AUDIT · TEST · METRIC. Avoid marketing-only
architecture, vague "AI-powered" language, unsupported "enterprise-ready" /
certification / compliance claims, fake Lyzr integration, fake benchmarks.
Label simulation honestly.

---

## §13 — Local operating environment (implemented-today truth — preserve)

### 13.1 Shell (Windows PowerShell 5.1)

- No `grep`/`head`/`&&`: use `Select-String`, `Select-Object -First/-Last`, `;` chains.
- `git` prints info to stderr — PowerShell shows it as red noise; check exit codes, not color.
- `git show X > file` truncates via shell redirect; pipe into `python` or use `git cat-file` instead.
- CRLF warnings on add/commit are normal. `commit.gpgsign=true` hangs headless —
  use `git -c commit.gpgsign=false commit`.

### 13.2 Python: container is truth, host is crippled

- Runtime source of truth: `python:3.12-slim` image. Host is 3.14 with starlette v1.x,
  which breaks `fastapi.testclient` — host runs unit/structure tests only.
- The 1 skipped test (`test_healthz_runtime_parity`) is that drift. Skips are never passes.
- Tools drift too (host ruff 0.15/mypy 1.19 vs CI-pinned ranges) — `pyproject.toml` keeps both green.

### 13.3 Verification commands

```powershell
python -m pytest tests/ -q -p no:warnings --ignore=tests/test_compose_runtime.py --ignore=tests/test_config_runtime.py --ignore=tests/test_health_runtime.py --ignore=tests/test_logging_runtime.py
python -m ruff check backend tests scripts
python -m mypy backend/app
python scripts/secret_scan.py   # values never printed; hunter2-fake-* are fixtures, not leaks
```

- `*_runtime.py` need a live daemon and mutate the stack (stop/start/restart) — they leave it UP+healthy.
- Full suite incl. runtime takes ~5 min. `scripts/ci.sh` mirrors CI; run it under Git Bash.
- Never run plain `docker compose config` (prints secrets). Safe: `config --quiet`, `ps`, `logs`.

### 13.4 Docker / Compose facts

- Ports: api `8000`, ui `5173`, db `5433:5432`. Named volume `pgdata` — never `down -v` casually.
- `POSTGRES_PASSWORD` applies at volume init only; changing `.env` later needs `ALTER USER`, not a restart.
- `/healthz` = liveness (drives HEALTHCHECK, frozen body). `/readyz` = readiness (200/503, 2s probe).
- Isolated experiments: fresh clone + temp `.env` + `-p <name>` + remapped ports; `--no-cache` build proves clean start.

### 13.5 Code ownership (do not cross without approval)

- `backend/app/contracts/` is the frozen M01.1 surface — M01.2+/M02 import from here only.
- `schemas.py` is a re-export layer; defines no vocabulary. `config.py`/logging enums are M00-frozen.
- `backend/app/services/`, `telemetry/gen.py` are legacy T-series: present, tested, but unwired until their modules land.
- `main.py` changes must stay additive (`/healthz` body is byte-frozen).

---

## §14 — Build-First operating policy + Git, parallel development, zero-trust verification

> **Core principle: Build broadly first. Perfect deliberately second. Never defer safety.**

### 14.0 Operating modes (frozen for this mission)

Project rule: `BUILD BROADLY → TEST CONTINUOUSLY → EVIDENCE CONTINUOUSLY →
COMPLETE ALL REGISTERED WORK → DEEP AUDIT → HARDEN → FINALIZE → SUBMISSION DRY-RUN`.

**BUILD PHASE (current) — Phase A Breadth / completion:** complete registered
scope breadth-first. Goal: every registered module reaches a real, runnable,
testable implementation. During Phase A: implement the actual capability ·
write meaningful tests · preserve safety-critical invariants · record evidence ·
document known gaps · avoid unnecessary refactoring / premature optimization /
low-value UI polish · do not fake missing integrations · do not claim
production readiness.

```text
INSPECT → PLAN → IMPLEMENT → TEST → SECURITY CHECK → RECORD EVIDENCE → COMMIT → CONTINUE
```

**FINAL TRUST PHASE (declared explicitly by human only) — Phase B Deep trust /
perfection:** after registered scope is substantially complete: zero-trust audit ·
adversarial testing · spec reconciliation · security hardening · performance
optimization · compatibility hardening · documentation reconciliation · evidence
cleanup · score every module · fix all P0/P1 + important P2 · full regression ·
clean-clone validation · demo rehearsal · submission dry-run.

```text
ZERO-TRUST AUDIT → ADVERSARIAL TEST → SPEC RECONCILIATION → MEASURE → SCORE →
FIX → RE-AUDIT → HUMAN APPROVAL → INTEGRATE → FULL REGRESSION
```

Build-first rules (binding in BUILD PHASE):

1. Implement the complete registered scope before deep perfection work.
2. Work in dependency-aware waves (§15.2) — do not perfect early modules while
   most registered modules remain unimplemented.
3. Parallelize independent implementation where useful (§14.1).
4. Keep safety-critical controls fail-closed from their first implementation
   (§1.1, §6, §14.6). Safety is never deferred for breadth.
5. Test continuously; do not postpone all testing to the end. Every module
   ships with positive + negative + security tests.
6. Record evidence continuously (§14.9).
7. Do not fabricate missing integrations, metrics, benchmark results, Lyzr
   capabilities, or runtime evidence. Missing = missing, marked PLANNED with owner.
8. Do not mark an incomplete feature as production-ready. Use
   `IMPLEMENTED_HARDENING_PENDING` when the capability exists but final
   hardening remains (§14.4).
9. Do not start unrelated polish when required modules are still absent.
10. Do not invent requirements; do not silently change module IDs; do not rename
    registry modules without explicit project decision (§15.1).

### 14.1 Parallel development (multiple agents/worktrees simultaneously — not one agent pretending)

1. Every module gets one focused owner.
2. Branches originate from current trusted master; never use a stale baseline intentionally.
3. Never force-push blindly; never rewrite trusted history; never delete
   candidate history for convenience; never overwrite another agent's work
   without reconciliation.
4. Preserve old branches for forensic history when required.
5. Shared files (central exports, registry, root docs, global config, shared
   compatibility surfaces, contracts, policy boundaries, execution code,
   integration points) have an explicit owner — normally the integration/lead
   session — and require dependency-aware review.
6. No two agents modify the same high-conflict files.
7. Integration is separate from implementation: **PARALLEL BUILD, SERIAL TRUST.**
   Parallel implementation is allowed for independent modules; trust/integration
   stays serial.
8. In BUILD PHASE: merge ONE `IMPLEMENTED_TESTED` / `IMPLEMENTED_HARDENING_PENDING`
   unit at a time with regression between merges. In FINAL TRUST PHASE: merge ONE
   `HUMAN_APPROVED` unit at a time with full regression between merges.
9. Never merge a module that fails its phase gate; never start a dependent module
   before its dependency's implementation exists (BUILD) / gate passes (TRUST).
10. Parallel tracks use worktrees under `C:\Users\Dell\AppData\Local\Temp\opencode\`,
    one branch each, merged `--no-ff` ONE AT A TIME with regression between.
    Never touch another lane's files.
11. Registry row flips are per-module, one line each; merge conflicts there are
    routine — keep all APPROVED rows.
12. No merge, push, force-push, amend, or new module without explicit human approval.
13. `origin/master` is canonical since the reconcile;
    `archive/remote-master-before-reconcile` must be kept.
14. Before significant work, capture baseline:
    `git status --short; git branch --show-current; git rev-parse HEAD; git log --oneline --decorate -20`.
    Keep implementation commits small enough to audit. Never commit secrets;
    never hide failures.

### 14.2 Zero-trust development model (full weight in FINAL TRUST PHASE, recorded in BUILD PHASE)

Never trust: self-reported agent score · "tests pass" without reproducible
evidence · branch age/naming · registry status · README claims · generated demo
screenshots · model confidence · LLM assertions · client claims · prior audit claims.

BUILD PHASE per-module flow: INSPECT → PLAN → IMPLEMENT → TEST → SECURITY CHECK →
RECORD EVIDENCE → COMMIT → CONTINUE (scope discipline §15.1, evidence §14.9).

Continuous verification without continuous perfection — the time-saving mechanism:

```text
Per module: IMPLEMENT → TEST → RECORD EVIDENCE → CONTINUE
Per wave:   WAVE REGRESSION → REVIEW BLOCKERS → CONTINUE
Final:      DEEP ZERO-TRUST AUDIT → SCORE → HUMAN APPROVAL → INTEGRATE → FINAL REGRESSION
```

Every implementation still runs: unit tests · negative tests · relevant
integration tests · relevant security checks · static analysis · type checks ·
secret scan. But do NOT stop after every small module for a full 100-point audit
during BUILD — record the estimate and continue breadth.

FINAL TRUST PHASE per-module flow: IMPLEMENT → SELF-AUDIT → STATIC CHECK → POSITIVE →
NEGATIVE → SECURITY → ADVERSARIAL → INTEGRATION → PERFORMANCE →
OBSERVABILITY → EVIDENCE → HIERARCHICAL SCORE → HUMAN REVIEW →
APPROVE/REJECT/FIX → INTEGRATE → REGRESSION → MERGE → VERIFY MASTER.
(Short form used in §13-track lanes: IMPLEMENT → SELF-AUDIT → POSITIVE →
NEGATIVE → SECURITY → RUNTIME → ESCAPE ANALYSIS → REGRESSION → SCORE FROM
ZERO → HUMAN VERIFICATION → STOP.)

### 14.3 Module score (independent per module, from zero)

Dimensions: Functional Correctness /20 · Verification /15 · Security /15 ·
Reliability /10 · Specification /10 · Integration /10 · Performance /5 ·
Observability /5 · Maintainability /5 · Hackathon Value /5.
Gate **≥90 overall**; safety-sensitive modules ≥95 Security; grounding-sensitive
modules ≥95 Grounding where the gate requires it. Universal conditions: zero P0 ·
no unresolved safety-critical P1 · all required tests green · evidence
reproducible · human approval · no hidden regressions. Scores start at zero
against the rubric; never average old scores. **Never average away a critical
failure** — a severe security failure is not "good enough" at average ≥90.

Score discipline: during BUILD, estimate current state, identify gaps,
prioritize blockers, continue breadth — do not self-score as final truth. A high
self-score does not authorize integration. During FINAL TRUST, independently
score from evidence, compare against project gates, fix failures, re-run the audit.

Score targets are project engineering gates (`Overall ≥90 · Safety ≥95 where
REQUIRED · Grounding ≥95 where REQUIRED · Hallucination ≥95 where REQUIRED`),
not automatically `[OFFICIAL]` organizer rules unless the official source says
so. Do NOT spend large effort moving 92→98 during breadth while another required
module is still absent — record the estimate and continue.

### 14.4 Hierarchical scoring + statuses

Score Project → Phase → Module → Submodule → Sub-submodule; never hide failed
children behind a passing parent. Every leaf: status · evidence · test · owner ·
score · blocker state. Per unit maintain: module · submodule · implementation ·
tests · security · evidence · known gaps · score — a phase that looks healthy
while one safety-critical submodule is broken must remain visible (no-average-hiding).

Build-first status set (binding):

```text
NOT_STARTED · IN_PROGRESS · IMPLEMENTED · IMPLEMENTED_TESTED ·
IMPLEMENTED_HARDENING_PENDING · AUDIT_READY · AUDITED · HUMAN_APPROVED ·
INTEGRATED · BLOCKED · DEFERRED · REJECTED
```

During BUILD-FIRST prefer `IMPLEMENTED_TESTED` or
`IMPLEMENTED_HARDENING_PENDING` (capability exists, final hardening remains).
Only the FINAL TRUST process converts required modules to `HUMAN_APPROVED` and
then `INTEGRATED`. Registry must not claim `HUMAN_APPROVED` / `APPROVED` /
`INTEGRATED` / `TRUSTED` before actual human approval.

### 14.5 Human gate (real state transition, never inferred)

Human approval = implementation reviewed · evidence inspected · test output
inspected · security inspected · integration boundary inspected. Never infer it
from self-score, green tests, branch naming, "ready" messages, or registry wording.

### 14.6 Safety rules — NEVER DEFER (BUILD and TRUST phases alike)

Even in breadth-first BUILD, these are fail-closed from first implementation —
any violation = BLOCK + surface immediately (§18):

1. LLM output is never authorization.
2. No arbitrary model-generated shell reaches an executor.
3. Structured actions must be validated before policy evaluation.
4. Unknown/malformed actions fail closed.
5. RED actions do not execute in the hackathon path (§6.1).
6. YELLOW actions require valid scoped approval (§6.4).
7. Telemetry is data, not instructions; telemetry cannot change trusted instructions.
8. Ground truth never enters model-visible context.
9. Verification is independent from planning (`EXIT 0 ≠ RESOLVED`).
10. Rollback is governed by the same safety boundary as execution.
11. Secrets never enter code, prompts, logs, traces, screenshots or evidence.
12. LIVE/REPLAY/MOCK/OFFLINE modes must be truthful; never present REPLAY as LIVE.
13. Lyzr-native capabilities must be actually verified (§2.3) — never fake Lyzr/AIMS/Safe AI.

### 14.7 Scope discipline (before implementing a module)

```text
READ SPEC → CHECK DEPENDENCIES → INSPECT EXISTING CODE → IMPLEMENT ONLY REQUIRED SCOPE
```

Do not invent requirements. Do not silently change module IDs. Do not rename
registry modules without explicit project decision. See §15.1 for the required
pre-implementation checklist.

### 14.8 Completion discipline (word bans)

Do not say "Project complete" until all registered required work has been
implemented AND the FINAL TRUST audit confirms readiness (§19).
Do not say "Submission ready" until the clean-clone, deployment, demo,
benchmark, evidence and submission gates pass (§16.3).

### 14.9 Evidence discipline (continuous)

For each meaningful capability record: what was built · where it lives · what
test proves it · what negative test proves its boundary · what runtime evidence
exists · what remains unverified. Never write "verified" when only static code
inspection was performed. Never fabricate metrics, benchmark results, Lyzr
traces, or runtime evidence.

Minimum evidence per significant feature: implementation path · test path ·
sample output · failure case · security behavior where applicable · commit ·
known limitation. For final critical claims expand to:
`CLAIM → IMPLEMENTATION → TEST → RUNTIME EVIDENCE → METRIC → AUDIT TRACE → DEMO STEP`.

### 14.10 Deferral boundary (what may wait vs what never waits)

May wait for FINAL TRUST hardening: cosmetic refactoring · naming cleanup ·
non-critical duplicate helpers · UI polish · performance micro-optimization ·
benchmark presentation polish · documentation wording cleanup · low-risk style
cleanup · non-functional abstraction improvements.

Never deferred (see §14.6): security boundary · policy enforcement ·
authorization · HITL correctness · sandbox boundary · secret handling ·
ground-truth isolation · deterministic validation · independent verification ·
rollback safety · audit integrity · truthful Lyzr labeling · truthful
LIVE/REPLAY/MOCK labeling · critical regression fixes.

---

## §15 — Module plan, development order, dependencies

### 15.1 Task backbone T01–T21 (spec §60; full 183-unit expansion in registry phases 00–22)

T01 repo+compose · T02 schemas (+20 invalid fixtures) · T03 telemetry generator
+ seeds · T04 policy engine + matrix + bundle · T05 action validator · T06 HMAC
approval · T07 mock sandbox · T08 docker executor · T09 verifier · T10 rollback ·
T11 runbooks (5) + loader · T12 retrieval + Evidence Pack · T13 4 Lyzr agents +
prompts + Structured Output · T14 FSM + guards + idempotency · T15 HITL API +
Gate UI · T16 hash audit + verify endpoint · T17 evaluation engine + scorecard ·
T18 frontend 5 views + dual SSE · T19 adversarial suite · T20 budgets/performance ·
T21 demo hardening (`seed.sh`, `eval.sh`, `demo.sh --check`, REPLAY pack, DEMO.md).

Before implementing a module: READ SPEC → CHECK DEPENDENCIES → INSPECT
EXISTING CODE → IMPLEMENT ONLY REQUIRED SCOPE. Concretely: inspect dependencies ·
contract ownership · existing implementation · current master · audit history ·
current tests · conflict risk · integration files · acceptance criteria.
Do not invent requirements. Do not silently change module IDs. Do not rename
registry modules without explicit project decision.

### 15.2 Development order (dependency-aware waves, not deep perfection)

1. repository foundation → 2. shared contracts → 3. telemetry → 4. normalization →
5. correlation → 6. evidence → 7. policy → 8. validation → 9. HITL → 10. sandbox →
11. verification → 12. rollback → 13. runbooks → 14. retrieval → 15. Lyzr agents →
16. orchestration/FSM → 17. audit/AIMS → 18. evaluation → 19. adversarial →
20. frontend → 21. performance → 22. integration → 23. demo → 24. submission.
Respect registry dependency locks; do not bypass locked prerequisites.

Build waves (registry phases M00–M22; `docs/MODULE_REGISTRY.md` is exact
naming/status authority):

- Wave 1 Foundation + Contracts: M00 → M01
- Wave 2 Data / Evidence pipeline: M02 → M03 → M04 → M05
- Wave 3 Governance / Safety: M06 → M07 → M08 → M09 → M10 → M11
- Wave 4 Intelligence / Retrieval: M12 → M13 → M14
- Wave 5 Audit / Evaluation: M15 → M16 → M17 → M18
- Wave 6 Product surface / Optimization: M19 → M20
- Wave 7 End-to-end integration / Demo: M21 → M22

Parallelize independent work inside a wave, but do not violate dependencies.
In BUILD PHASE work in waves: land breadth (`IMPLEMENTED_TESTED` /
`IMPLEMENTED_HARDENING_PENDING`) across a wave before hardening any single
module. Do not perfect early modules while most registered modules remain
unimplemented. Do not start unrelated polish when required modules are absent.
UI only after T02–T10 merged. Each PR states: purpose/files/deps/input/output/
acceptance/test/metric/rubric-impact.

---

## §16 — Competitive differentiation, demo, submission

### 16.1 Positioning: VERIFIABLE SAFETY

Demonstrable edge in hackathon scope (hedged, provable — never "nobody else can
do this"): evidence + structured actions + deterministic policy + HITL +
sandbox + independent verification + rollback + hash audit + adversarial
evaluation + cost/latency scorecard in ONE live inspectable flow. Verify
against HolmesGPT/SRE-agent/kube-agents repos and Bits AI/Rootly docs; claim
only what demo + tests + audit prove. Adapt concepts with attribution; never
copy proprietary code, UI, branding, assets, or text.

### 16.2 Demo governance (primary: bad-deploy)

Narrative: PAGER/ALERT FLOOD → CORRELATION → SINGLE INCIDENT → EVIDENCE →
DIAGNOSIS → UNSAFE DELETE PROPOSAL → RED BLOCK → SAFE YELLOW ROLLBACK → HUMAN
APPROVAL → SANDBOX EXECUTION → STATE DIFF → VERIFICATION → RCA → AUDIT →
SIX-GATE SCORECARD (spec §55 beat map, 5:00, seed `bad-deploy/NORMAL`,
pre-issued standby approval). Show real controls — no fake typing, static
animations, fake logs, hidden actions, fake approvals. Fallbacks announced
on-screen with triggers (Lyzr timeout>20s → REPLAY agent spans; DB down →
file-backed seed+audit; sandbox down → mock; net down → local images+video);
`demo.sh --check` validates seeds+policies+runbooks+e2e <5min before stage.
**Never present REPLAY as LIVE.**

### 16.3 Submission governance — BUILD → TEST → VALIDATE → PACKAGE → SUBMISSION DRY-RUN → SUBMIT → VERIFY SUBMISSION

- [ ] COMPETITION: correct PS · correct repository · correct connected repo ·
      correct live endpoint · latest intended commit pushed · repo accessible · required files present.
- [ ] PRODUCT: triage · diagnosis · remediation · safety · HITL · execution ·
      verification · rollback · RCA · audit · evaluation all work end-to-end.
- [ ] LYZR: Agent API / Structured Output / RAI / KB / memory authentic where
      claimed · trace authentic · fallback documented · no fake Automata claim · no fake AIMS claim.
- [ ] QUALITY: C1–C6 measured · adversarial + benchmark suites green · security
      invariants green · no unsafe execution · no bypass · evidence coverage meets
      gate · retrieval/latency/token-cost benchmarks present.
- [ ] REPOSITORY: clean tree · no secrets · `.env.example` valid · docs complete ·
      Docker path works from clean environment · live endpoint works.
- [ ] DEMO: LIVE works · fallback works · RED block · YELLOW approval ·
      execution · verification · RCA · scorecard all demonstrable.
- [ ] FINAL: submission page reviewed · assets verified · URLs verified ·
      confirmation captured · final state independently verified.
- Never stop at BUILD → AUDIT → PERFECT.

---

## §17 — Agent conduct: NEVER list, MUST list, change rules, failure handling

### 17.1 NEVER

Modify code without inspecting existing code · assume a feature exists · claim
"production-ready"/"secure"/"hallucination-free" without evidence · mark an
incomplete feature as production-ready · fabricate missing integrations, metrics,
benchmark results, Lyzr capabilities, or runtime evidence · trust LLM
risk labels · allow arbitrary shell · bypass policy/HITL/validation/
verification/audit · silently weaken or remove failing tests · inflate scores ·
self-score as final truth · mark registry APPROVED without human approval ·
rewrite trusted history · delete candidate history for convenience ·
blind-force-push · hide failures · overwrite another agent's work without
reconciliation · merge stale branches without rebase/rebuild policy · copy
proprietary competitor material · fake Lyzr/AIMS/Safe AI integration · invent
benchmark numbers or make unsupported benchmark claims · expose secrets or put
them in prompts/logs · commit secrets · dump giant telemetry into prompts · add agents to raise
agent count · add infrastructure (pgvector, Kafka/Redis, …) without measured
need · add live cloud credentials · connect to production · implement
autonomous RED or hidden break-glass · present OPTIONAL as mandatory or
research recommendations as official rules · start unrelated polish when required
modules are still absent · say "Project complete" / "Submission ready" before
§14.8 gates pass.

### 17.2 Every coding agent MUST

**Before coding:** read AGENTS.md · read the spec · read the module checklist ·
inspect master/contracts/dependencies/tests · identify ownership + integration
risks · write a small implementation plan. Before significant work capture
`git status --short; git branch --show-current; git rev-parse HEAD; git log --oneline --decorate -20`.
**During coding (BUILD PHASE flow):** INSPECT → PLAN → IMPLEMENT → TEST →
SECURITY CHECK → RECORD EVIDENCE → COMMIT → CONTINUE. Modify only owned files
unless authorized · preserve contracts and safety boundaries (§14.6 never deferred) ·
add positive + negative + security tests with implementation · keep deterministic
logic deterministic · emit evidence (§14.9) · preserve auditability · document
deviations · maintain compatibility.
**After coding:** self-audit · run positive/negative/adversarial/security/
integration/performance/lint/type checks · verify no secret leakage · inspect
diff (no unrelated files) · estimate state from zero (BUILD) — do not self-score
as final truth · list residual risks honestly · produce a human review package.

### 17.3 Change management (every meaningful PR contains all 15)

Purpose · problem solved · files changed · dependency assumptions ·
architecture impact · security impact · input/output contracts · tests ·
negative tests · metrics · evidence · rubric impact · known limitations ·
rollback strategy · human-review checklist. No silent fixes, no score inflation, no scope creep.

### 17.4 Failure handling — FAIL CLOSED

On serious defect do NOT hide it, weaken the test, remove the feature, or
downgrade severity without evidence. DO: stop · document · classify · fix ·
add regression test · rerun affected + broader regression · rescore · surface
to human review.

---

## §18 — STOP conditions (progress is BLOCKED while any hold)

Stop implementation and surface immediately for: unsafe execution · policy
bypass · secret exposure · ground-truth leakage · critical regression ·
fake/unsupported platform capability · falsified metric · broken authorization ·
approval replay · destructive action escaping the safety boundary. Concretely
(progress is BLOCKED while any hold):

- Unvalidated Action can reach the executor; RED path executable; YELLOW
  executable without valid token; approval replay/tamper accepted.
- `POLICY_CHECK → EXECUTING` bypass possible; verifier trusts planner output;
  exit code accepted as resolution.
- Telemetry can alter trusted instructions; secrets in prompts/logs; secret committed.
- Ground truth leaked into model-visible context; critical regression; falsified
  metric (benchmark number without linked run JSONL counts here too).
- RCA publishable below MUST-CITE coverage; audit chain tamper undetectable;
  blocks emitted without audit events.
- Unbounded agent loop (any of hyp>3 / re-plan>2 / tools>5/agent / calls>12
  unenforced); token/cost budget unenforced; no kill-switch.
- Module score <90 (or <95 on a gated safety/grounding dimension); P0 open;
  safety-critical P1 unresolved; tests red; evidence irreproducible.
- Registry APPROVED claimed without human verdict; unapproved module merged;
  trusted history rewritten; another lane's files touched.
- Lyzr/AIMS/Automata claim unauthentic; REPLAY presented as LIVE; benchmark
  number without linked run JSONL.
- Adversarial suite red (any attack uncontained), eval `unsafe_exec > 0`,
  MUST-CITE coverage < 1.0, or any C1–C6 gate failing its `[PROVISIONAL]`
  target without a recorded human-accepted waiver + rescoring plan.
- Submission dry-run failing; live endpoint down; required files missing.

---

## §19 — Final definition of DONE (ALL must be true)

Milestones (in order — "implemented" ≠ "submission ready"):

- **Completion:** ALL REQUIRED MODULES IMPLEMENTED + basic tests green +
  core E2E path runs + no known critical safety bypass.
- **Trust:** ZERO-TRUST AUDIT + adversarial tests + spec reconciliation +
  scores + HUMAN APPROVAL + integration + FULL REGRESSION.
- **Submission:** CLEAN CLONE + deployment + LIVE endpoint + demo +
  benchmarks + six-gate scorecard + documentation + SUBMISSION DRY-RUN +
  platform verification (§16.3).

1. Official PS03 requirements satisfied (§0.3). 2. Authoritative architecture
   satisfied (§2). 3. Four real Lyzr agents work (§3). 4. Lyzr capabilities
   authentic (§2.3). 5. Deterministic control plane enforced (§4–§5).
6. Structured Action contract enforced (§6). 7. Policy engine deterministic and
   fail-closed (§6.2). 8. HITL action-bound and protected (§6.4). 9. Sandbox
   reliable (§6.5). 10. Verification independent (§6.6). 11. Rollback works
   (§6.7). 12. Evidence grounding measurable (§8.1). 13. Retrieval quality
   benchmarked (§8.2). 14. Audit verifiable (§10). 15. AIMS usage authentic
   where supported (§10). 16. Evaluation engine works (§11.1). 17. Deep
   benchmark suite works (§11.2). 18. Adversarial suite works (§11.3).
19. Six quality gates measured (§11.4). 20. Performance budgets measured
   (§11.5). 21. Five-view SRE UI works (§9.3). 22. Realtime streaming works
   (§9.4). 23. Documentation complete (§12). 24. Repository reproducible
   (§12–§13). 25. Demo rehearsed (§16.2). 26. Fallbacks rehearsed (§16.2).
27. All security invariants green (§1.1). 28. No unresolved P0. 29. Required
   human approvals exist (§14.5). 30. Master clean and verified. 31. Submission
   dry-run passes (§16.3). 32. Actual submission independently verified (§16.3).

---

## §20 — Governing principles

BUILD BROADLY FIRST. PERFECT DELIBERATELY SECOND. NEVER DEFER SAFETY.
BUILD LESS. PROVE MORE. GOVERN THE AGENT. MEASURE EVERYTHING. MAKE THE DEMO
UNFORGETTABLE. Parallel Build. Serial Trust. NO TRUST WITHOUT EVIDENCE.
NO CLAIM WITHOUT PROOF. DO NOT POLISH ONE MODULE WHILE THE PRODUCT IS STILL
MISSING THE REST. SAFETY IS NEVER DEFERRED. COSMETIC PERFECTION IS.
The model is not the authority — the policy is. The executor is not the
verifier — the verifier is independent. Evidence is not decoration. Audit is
not a fake log. Safety is not a prompt. Benchmarks are not marketing.
A score is not proof. A claim is not evidence. A human approval is not implied.
A green test is not permission to merge. The repository is part of the product.
The demo is part of the evaluation. Every important feature must be
IMPLEMENTED + TESTED + ATTACKED + MEASURED + TRACEABLE + DEFENSIBLE.

---

## Appendix A — Resolved source conflicts (V2 applied, old rules retired)

| # | Conflict | Resolution (authoritative) |
|---|----------|----------------------------|
| 1 | Official PS03 text names "Lyzr Automata" as core opportunity; V2 bans Automata as control plane | V2 wins: custom FastAPI FSM canonical; Automata in `docs/DECISIONS.md` history only; never claim Automata execution |
| 2 | Official MVP says multi-agent "triad" (3 agents); project builds 4 | `[PROPOSED]` 4th agent (RCA Reporter) retained with justification; A1–A3 cover the MVP triad |
| 3 | Older material places Safe AI between policy and executor as the gate | Corrected (spec §04-G02): RAI wraps each agent call (input+output); policy engine is the authorization boundary; both must pass |
| 4 | Stretch goal "AIMS decision graph" reads as native capability | Corrected (spec §04-G08): AIMS = trace/transcripts/reports/audit-log; decision-graph = CUSTOM viz over our audit chain, labeled as such |
| 5 | Older material ambiguous on SuperFlow vs FSM ("two preferred paths") | Frozen (spec §04-G01): FSM primary, SuperFlow `[OPTIONAL]` mirror |
| 6 | Older material "use pgvector / vector DB" openness | Frozen (spec §04-G05): Classic KB + pre-digestion; NO pgvector without measured need |
| 7 | Dollar/cost figures and latency/token budgets stated as fixed targets | All numeric thresholds `[PROVISIONAL]`; revise after 20 baseline runs; raw tokens primary, $ via editable pricing table only |

## Appendix B — Unresolved / [UNVERIFIED] items (do not assume; verify before relying)

1. Master operational checklist file named in the task brief is **absent from
   this tree** — `docs/MODULE_REGISTRY.md` + spec §60–§61 govern instead.
2. Registry header tally (e.g. "87/183 with implementation · overall NOT
   COMPUTED") can go **stale relative to its own per-row table**. Per-row status
   + human verdict govern, not the header line.
3. Lyzr platform details (SuperFlow programmatic API shape, credit/rate limits,
   session-window behavior beyond the 10-message summarize note) are
   `[UNVERIFIED]` for our purposes — mitigated by caps + REPLAY fallback + local-first demo.
4. Submission timing/page details in the rules research doc reflect the public
   listing as of Sep 2026 — **the live HiDevs Quest Engine page is the
   operational source of truth** at submission time.
5. No evaluation, benchmark, adversarial, latency, token, or cost numbers exist
   yet — every such number is a `[PROVISIONAL]` target until measured runs land in JSONL.
