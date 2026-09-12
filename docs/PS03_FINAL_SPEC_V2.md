# PS03_FINAL_SPEC_V2 — Authoritative Implementation Specification
## Evidence-Grounded Incident Commander · Agentic Operations Control Plane · AI Quest 2026 PS03
> **THE AGENT MAY REASON. THE CONTROL PLANE DECIDES. THE SANDBOX CONTAINS. VERIFICATION PROVES. AIMS RECORDS.**
> **THE LLM IS NOT THE SECURITY BOUNDARY.**
> Status: FINAL AUTHORITATIVE. Supersedes `PS03_FINAL_SPEC.md` Part B where they conflict. Part A research dossier in V1 remains valid background.

Legend: `[OFFICIAL]` organizer requirement · `[RESEARCH]` evidence-backed · `[PROPOSED]` our choice · `[OPTIONAL]` stretch · `[FUTURE]` post-hackathon · `[PROVISIONAL]` target to revise after baseline runs · `[UNVERIFIED]` not confirmed in docs.

---

## 01 Executive Summary
Build a governed SRE mesh: 4 Lyzr agents propose (Triage, Diagnostic, Remediation Planner, RCA Reporter); deterministic FastAPI control plane disposes (validate → policy → HITL → sandboxed exec → independent verify → rollback → hash audit → eval). Lyzr-native: Agent API/ADK + Structured Output + RAI guardrails + Classic KB + Cognis + session persistence + streaming + trace/eval-assist. Custom: policy engine, validator, HMAC HITL, sandbox, verifier, rollback, hash audit, eval runner, pre-digestion. Demo: seeded bad-deploy → correlation → evidence → diagnosis → live RED block of destructive action → approved YELLOW rollback → state diff → verify → RCA → scorecard. **Canonical orchestration: custom FastAPI FSM (primary); SuperFlow = optional mirror, never Automata.**

## 02 Official Requirements `[OFFICIAL]`
1. Alert ingestion (PagerDuty/Prometheus-style). 2. Triage + dedup. 3. Severity P1–P4. 4. Root-cause diagnosis from mock logs/traces/metrics. 5. Governed remediation + HITL for risky actions. 6. Blameless postmortem (timeline, cause, prevention). 7. Lyzr agent capabilities + Automata/orchestration as required. 8. Lyzr Safe AI protection. 9. AIMS audit where supported. 10. MVP: mock Prom/K8s + correlation + multi-agent triad + Safe AI + destructive-action protection + auto-postmortem. Rubric: 30% orchestration / 30% safety / 20% code+arch / 20% SRE UX.

## 03 Requirement Classification
`[OFFICIAL]` = §02 only. `[RESEARCH]` = runbook grounding, hash-chained audit, eval harness + adversarial suite, blast badge, MTTR board, pre-digestion, SSE streaming. `[PROPOSED]` = 4th agent (RCA Reporter), HMAC approval tokens, mock→docker→kind tiers, 14-state FSM, claim classes. `[OPTIONAL]` = Kind live, cost board, FP feedback, prevention-PR draft. `[FUTURE]` = voice, decision-graph viz, live Prometheus/PagerDuty/Datadog/ServiceNow/GitHub/Argo, multi-cluster, gVisor/Kata. Never present PROPOSED as OFFICIAL in README/demo/UI.

## 04 Current Blueprint Audit (V1 → V2 dispositions)
| ID | Area | Problem | Sev | Fix → Final Decision |
|---|---|---|---|---|
| G01 | Orchestration | SuperFlow-vs-FSM ambiguous, two "preferred" paths | HIGH | **Freeze: custom FastAPI FSM primary; SuperFlow optional mirror** (§10–11). Rationale: repo-versioned, CI-testable, offline-demo-safe; Studio DAG can't be diffed/tested in CI. |
| G02 | Safe AI ordering | V1 implied RAI sits between policy and executor as an API call | HIGH | **Correct: RAI is per-agent input+output guard** (docs: "runs on every agent interaction"). Policy engine stays the authz boundary; RAI wraps each agent call (§10, §18). |
| G03 | Structured Output | V1 hand-rolled JSON discipline, ignored native feature | MED | **Use Lyzr Structured Output (JSON schema) on all 4 agents + Pydantic double-validation** (§12, §16). |
| G04 | Streaming | V1 proposed SSE custom only | MED | **Use Lyzr `stream-chat` (SSE) for agent tokens + custom SSE for control-plane events** (§42). |
| G05 | Retrieval | V1 left KB-vs-pgvector open | MED | **Freeze: Lyzr Classic KB + score threshold + local pre-digestion; NO pgvector** (§22). KG/Semantic Model documented as options. |
| G06 | Memory | V1 "Cognis" vague | LOW | **Freeze: session_id=incident_id + Cognis cross-session + Global Context for org rules** (§10). Note 10-msg summarize window. |
| G07 | Tools | V1 "function/MCP wrappers" vague | MED | **Freeze: custom tools via OpenAPI/JSON schema (reads only); mutations never exposed as Lyzr tools** (§19). Shared-auth demo account. |
| G08 | AIMS | "AIMS decision graph" implied native | MED | **Correct: AIMS = trace/transcripts/reports/audit-log; decision-graph = CUSTOM viz over our audit** (§32). Label honestly. |
| G09 | Automata | Lingering references | LOW | **Banned as control plane** (experimental README). Mention once in DECISIONS.md only. |
| G10 | FSM size | 20 states risks over-engineering | MED | **Freeze 14 canonical states** (§15); V1 extras become sub-statuses/flags. |
| G11 | Cost claims | Dollar figures without pricing table | MED | **Raw tokens metered; $ via config pricing table only** (§49). |
| G12 | Targets | Budgets read as standards | LOW | **All numeric targets tagged `[PROVISIONAL]`**, revision rule after 20 baseline runs (§36). |
| G13 | Agent endpoints | No exact API cited | MED | **Pin `POST /v3/agent/{id}/chat|stream-chat`, stable session_id** (§10, §40). |
| G14 | Eval overlap | Custom runner vs Lyzr Agent Eval duplicated | LOW | **Split: Lyzr Eval = agent-level (hallucination/faithfulness/tool-arg); custom runner = pipeline-level (policy/adversarial/SLO/regression)** (§33). |

## 05 Product Specification
Evidence-Grounded Incident Commander: queue → 1 incident from N alerts → evidence-linked hypotheses → scoped approve/deny → sandboxed exec + SLO verify (+ auto-rollback) → gated RCA + audit export + scorecard. Non-goals: real paging, prod credentials, autonomous prod-DB writes, live vendor integrations.

## 06 Personas
On-call SRE (approver; needs blast+evidence ≤60s); Incident Commander (queue, MTTR, audit export); Platform engineer (repro seed, eval, diagrams). Default role viewer; `approver` required for YELLOW approve/execute.

## 07 User Journeys (≤3 clicks from queue)
J1 Triage (flood→1 P1→owner). J2 Diagnose (evidence→hypotheses→runbook pin). J3 Govern (RED blocked visibly→YELLOW approved). J4 Heal (exec→verify→rollback-if-fail + state diff). J5 Learn (RCA+prevention+audit export+scorecard).

## 08 Functional Requirements
FR1 ingest normalized alerts (REST + `POST /demo/seed`). FR2 deterministic dedup ≤5s + P1–P4. FR3 parallel scoped evidence fetch. FR4 hypotheses with citations+confidence+ruled-out. FR5 runbook select+parameterize (pinned version). FR6 structured Action only. FR7 policy ALLOW/ESCALATE/DENY, fail-closed, default DENY. FR8 HITL single-use/TTL/scope/identity-bound. FR9 sandbox exec; blocks = zero diff. FR10 independent SLO verify (exit-code ≠ resolved). FR11 one auto-rollback then escalate. FR12 RCA publish gated on MUST-CITE coverage=1.0. FR13 append-only SHA256 audit + verify endpoint + export. FR14 eval runner + JSONL + HTML scorecard + rubric estimate. FR15 5 views + streaming (LIVE/REPLAY/MOCK badge) + `docker compose up` one-command.

## 09 Non-Functional Requirements
e2e P50 <90s mock / P95 <4min Kind `[PROVISIONAL]`; tool p95 <3s; caps: ≤80k tokens, ≤12 LLM calls, ≤12k ctx/call, 5 tools/agent, 3 hypotheses, 2 re-plans `[PROVISIONAL]`; same-seed replay deterministic; fail-closed safety; no secrets in prompts/logs; policy/sandbox/verifier/audit coverage 100%.

## 10 Lyzr Verification (fetched Sep 2026, docs.lyzr.ai/enterprise)
| # | Capability | Official? | Actual functionality (docs) | Integration decision | Limits/auth |
|---|---|---|---|---|---|
| 1 | Agent API/ADK (role/goal/instructions) | ✅ concepts/agents | LLM + role/goal/instructions + features; model-agnostic (OpenAI/Anthropic/Gemini/Bedrock/Groq/Perplexity/BYOM) | LYZR-NATIVE: 4 agents | API key; per-agent model swap free |
| 2 | Agent endpoints + sessions | ✅ concepts/agents | `POST /v3/agent/{id}/chat`, `/stream-chat` (SSE), `/multimodal-chat`; stable `session_id` = multi-turn, fresh UUID = stateless; default 10-msg window then summarize | LYZR-NATIVE: chat+stream-chat; session_id=incident_id | session persistence = rubric state proof |
| 3 | Structured Output | ✅ concepts/agents (Optional features) | Forces JSON conforming to defined schema | LYZR-NATIVE: schema on all 4 agents; Pydantic re-validates server-side | never trust client JSON alone |
| 4 | Tools | ✅ concepts/tool-calling | OpenAI function-calling standard; pre-built (Slack/GitHub/Jira…), custom via OpenAPI/JSON schema (API key/OAuth2/none), MCP via URL; shared vs per-user auth; ACI.dev OSS self-host | LYZR-NATIVE reads only (custom tools → our GET endpoints); shared-auth demo svc account | mutations NOT exposed as tools |
| 5 | Manager Agent | ✅ multi-agent-orchestration | Dynamic router via `usage_description`, seq/parallel delegation + synthesis | LYZR-NATIVE optional conversational front only | never owns mutations |
| 6 | SuperFlow | ✅ multi-agent-orchestration | Visual DAG, fixed order, mid-flow approvals, cron/webhook, exactly-once, retries, HTTP/code/conditional nodes | OPTIONAL mirror; canonical = FSM (§11) | not repo-testable → not primary |
| 7 | Safe AI / Responsible AI + Guardrails | ✅ connections/guardrails, responsible-safe-ai | Per-agent policy (Security, Privacy/PII, Brand, Content, Format); checks incl. injection/PII/toxicity/groundedness; BYO Bedrock/Google; custom HTTP guardrail; "runs on every agent interaction" | LYZR-NATIVE: policy `PS03-Governed` on all 4 agents | semantic layer, NOT K8s authz |
| 8 | AIMS/trace/audit | ✅ intro, tracing, transcripts, reports, governance | Per-step trace + latency, transcripts, reports, RBAC/SSO, audit-log filtering | LYZR-NATIVE trace; CUSTOM hash chain supplements (§32) | label custom vs AIMS |
| 9 | Evaluation (Agent Eval) | ✅ concepts/evaluating-agents | Environments→scenarios/personas→auto test cases→metrics (Task Completion, Hallucination, Bias, Toxicity, Faithfulness, Reflection, LLM-judge; tool/KB arg+relevance)→scores→Hardening | LYZR-NATIVE agent-level; CUSTOM runner pipeline-level (§33) | CSV import for our cases |
| 10 | Knowledge/RAG | ✅ concepts/rag-knowledge | Classic KB (PDF/DOCX/TXT/sites/SharePoint/S3; Basic/MMR/HyDE; chunk size/count/overlap; score threshold; live re-sync ≥1h) + KG (Neo4j) + Semantic Model (NL→read-only SELECT; PG/MySQL/BQ/Snowflake + glossary) | LYZR-NATIVE Classic KB for runbooks/history; Semantic Model OPTIONAL | start small corpus; threshold filters junk |
| 11 | Memory/Cognis + Global Context | ✅ concepts/memory-context | Session memory (recent-N verbatim + summarize rest) + Cognis (zero-config, cross-session toggle, temporal) + Global Context (org-wide, auto-applied) | LYZR-NATIVE: Cognis on; Global Context = compliance rules | KB≠memory: KB org knowledge, memory conversation |
| 12 | Automata (pip) | ⚠️ experimental README ("imperfections") | Low-code Agents/Tasks/Pipelines | BANNED as control plane | docs only |
| 13 | Voice | ✅ Telephony/voice | Twilio/Telnyx/Plivo | FUTURE stretch | — |
UNVERIFIED for our purposes: none blocking; SuperFlow programmatic API shape (use Studio UI if mirroring; FSM needs no API).

## 11 Lyzr Architecture (final integration decision)
- **LYZR-NATIVE:** 4 agents (ADK/API, Structured Output schemas, RAI `PS03-Governed`, Classic KB `runbooks-v*` + `history`, Cognis cross-session, Global Context compliance text, chat+stream-chat, session_id=incident_id, trace). Manager agent optional front that may only call `GET` views or trigger FSM runs — never tools that mutate.
- **CUSTOM-DETERMINISTIC:** FastAPI FSM, validator, policy, HMAC HITL, sandbox, verifier, rollback, SHA256 audit, eval runner, pre-digestion, SSE hub.
- **OPEN-SOURCE:** Postgres, React/Vite/Tailwind/shadcn, ACI.dev pattern for tool specs (no extra deps).
- **SIMULATED:** telemetry gen, mock K8s state, mock executor; docker tier real-but-local.
- **FUTURE:** Kind default, voice, KG/Semantic Model, vendor connectors, gVisor/Kata, SSO/SIEM.
- Safe-AI placement (corrected): `User/alert → Agent(RAI-in) → LLM → Structured Output → Agent(RAI-out) → Validator → Policy → HITL → Executor`. RAI never authorizes K8s; policy never judges semantics. Both must pass.

## 12 Agent Architecture
- **A1 Triage** (small/fast, e.g. GPT-4o-mini/Haiku/Gemini-Flash class): alerts[] → Incident{severity P1–P4, fingerprint, cluster, owner, signals}. Tools: none-mutating reads only. No diagnosis.
- **A2 Diagnostic** (larger): Evidence Pack → hypotheses[2–3] + runbook pin. Must cite or return INSUFFICIENT_EVIDENCE. Tools: fetch_runbook, read APIs.
- **A3 Planner** (medium): runbook+params → Action struct + expected + rollback + verify plan. Emits data only; no shell vocabulary allowed in output schema.
- **A4 RCA Reporter** (economical): timeline+cause+prevention+claim map; blocked if gate fails.
- Each: role/goal/instructions + Structured Output schema + KB links + RAI policy + session persistence + model pinned in config. Distinct tool ACLs per agent (tests assert).

## 13 Deterministic Services
Normalizer, Correlator, Pre-digester/Retriever, Validator, Policy, Approval-HMAC, Sandbox, Verifier, Rollback, Audit-hasher, Eval-runner. Deterministic because: reproducible, versioned, unit-testable to 100%, dependency-free of model randomness; they own every state transition, auth decision, side effect, verdict, and audit link.

## 14 End-to-End Workflow
INGEST(api,→TRIAGING,5s)→CORRELATE(det)→TRIAGE(A1)→EVIDENCE(det parallel)→DIAGNOSIS(A2)→HYP-TEST→RUNBOOK-pin→PLAN(A3)→VALIDATE(det)→POLICY(det)→RAI(agent-bound)→HITL?→EXECUTE(sandbox)→VERIFY(det)→ROLLBACK?/ESCALATE→RCA(A4,gated)→AUDITED→EVAL(async). Each stage: owner, input/output schema, timeout, retry (LLM once / det zero-or-idempotent), failure→BLOCKED/ESCALATED, audit event. Approval human-time excluded from e2e budget, TTL-tracked.

## 15 State Machine (canonical 14)
`NEW → TRIAGING → CORRELATED → INVESTIGATING → DIAGNOSING → PLANNED → POLICY_CHECK → {BLOCKED | AWAITING_APPROVAL | APPROVED} → EXECUTING → VERIFYING → {RESOLVED | ROLLBACK | ESCALATED} → RCA_PENDING → RCA_PUBLISHED → AUDITED`. Subsumed V1 states: INGESTING⊂NEW→TRIAGING entry; FAILED⊂ESCALATED with `reason`; APPROVED is transient permit (token ref). Valid/invalid/terminal per V1 §15 + **hard prohibition: POLICY_CHECK→EXECUTING without ALLOW-permit or valid approval token** (enforced in code + test `test_no_policy_skip`). Retryable: TRIAGING, DIAGNOSING, PLANNED (re-plan ≤2), EXECUTING (idempotent key), VERIFYING. Timeouts: agent stages 30–60s → ESCALATED; approval TTL 10m (15m demo mode) → ESCALATED. Rollback: VERIFYING→ROLLBACK→VERIFYING once → RESOLVED|ESCALATED. Idempotency: action_id+execution_id; duplicates return cached + `duplicate-suppressed` audit.

## 16 Action Contract
```python
class Action(BaseModel):
    action_id: str  # uuid4, idempotency key
    incident_id: str; agent_id: str
    action_type: Literal["read","describe","logs","metrics","list","restart_pod","scale_deployment",
      "rolling_restart","rollback_deployment","patch_config","delete_pod","delete_deployment",
      "delete_namespace","rbac_change","secret_access","db_write","reboot_node","shell"]
    resource_type: str; resource_id: str
    environment: Literal["dev","staging","prod","mock"]; namespace: str = "default"
    parameters: dict = {}   # per-type validator (replicas int 1..10; image tag ^[a-z0-9._-]+$; no `;|&$()` )
    risk_level: Literal["GREEN","YELLOW","RED"]  # ADVISORY; policy recomputes effective risk
    reason: str; evidence_ids: list[str]; runbook_id: str; runbook_version: str  # pinned, e.g. "1.2.0"
    expected_outcome: str; rollback_action: Optional[dict]; verification_plan: list[str]
```
Reject: any `shell` from LLM; `delete_namespace`+prod; secret/destructive-db without break-glass flag (disabled in hackathon); empty evidence on mutation; unpinned/floating runbook; reversible YELLOW without rollback. Lyzr Structured Output schema mirrors this exactly; server re-validates.

## 17 Risk Matrix (implementation table; also `/policies/risk_matrix.yaml`)
| action_type | mock/dev | staging | prod | role | HITL | sandbox | verify | rollback |
|---|---|---|---|---|---|---|---|---|
| read/describe/logs/metrics/list | GREEN auto | GREEN | GREEN | viewer+ | no | n/a | n/a | n/a |
| restart_pod | GREEN auto | YELLOW | YELLOW | approver | yes | mock/docker | pod-ready+err | n/a (disruptive, recreate) |
| scale_deployment (±≤2) | GREEN auto | YELLOW | YELLOW | approver | yes | mock/docker | avail-replicas+SLO | scale-back |
| rolling_restart | YELLOW | YELLOW | YELLOW | approver | yes | mock/docker(+kind opt) | avail+SLO 60s | rollback_deployment |
| rollback_deployment | YELLOW | YELLOW | YELLOW | approver | yes | mock/docker | version+SLO | re-rollback (forward fix) |
| patch_config (non-secret) | YELLOW | YELLOW | YELLOW | approver | yes | mock/docker | SLO + config-hash | prior-config |
| delete_pod (surgical) | YELLOW | YELLOW | RED* | approver | yes | mock/docker | pod-ready+SLO | n/a |
| delete_deployment/delete_namespace/rbac_change/secret_access/db destructive/reboot_node/shell | RED | RED | RED | admin bg | BLOCKED | none | n/a | n/a |
`*` prod delete_pod RED in hackathon (fail-closed; revisit with break-glass post-hackathon). No keyword matching: decision = f(type,resource,env,params,severity,blast,actor,policy_version).

## 18 Policy Engine
`evaluate(Action, Actor{role,id}, Env, Severity, Blast{scope,replicas,traffic%}, PolicyBundle vX) → {ALLOW|ESCALATE|DENY, rule_id, obligations[], ttl}`. Stages: 1) schema/allowlist/param-shape 2) DENY rules (RED table, prod-destructive, secret, unpinned runbook, tampered approval) 3) ESCALATE (YELLOW table, blast>threshold, first-seen action, stale evidence>15m) 4) ALLOW (GREEN + SLO-ok + fresh evidence) 5) default DENY. Priority DENY>ESCALATE>ALLOW; most-restrictive conflict wins; any exception → DENY + `policy-error` audit. Bundle `/policies/bundle_vX.yaml` {version, effective_from, rules[{id,when,decision,message,obligations}]}; 40+ regression tests; audit stores policy_version+rule_id.

## 19 Tool Authorization
READ (Lyzr custom tools → FastAPI GET, shared demo auth, timeout 5–15s, retry 1 idempotent): fetch_alerts, get_logs{service,window,limit≤500}, query_metrics{service,window,delta}, get_traces{trace_id}, get_deployments{service}, fetch_runbook{id,version}, get_topology{service}. MUTATION (server-side only, never Lyzr tools): propose_action, execute_action{action_id+token}, verify_slo, rollback, publish_rca (gated). Each: JSON schema, permission, scope, risk, timeout (exec 60s), retry (reads 1, writes 0), audit event, typed errors (never hallucinated values). A1 gets reads-minus-topology? A2 full reads; A3 propose only; A4 reads + publish_rca. Assert per-agent ACL in contract tests.

## 20 Runbooks (`/runbooks/*.yaml`, sha256 pinned)
{id, version semver, title, trigger{alert regex, service}, scope{env}, preconditions[], diagnostic_steps[], allowed_actions[typed+ranges], forbidden_actions[], parameters JSON-schema, approval{for}, verification{slos[]}, rollback{template}, owner, reviewed_at, hash}. SELECT+PARAMETERIZE only. Ship 5: bad-deploy-rollback 1.2.0, crashloop-oom 1.0.0, db-pool-saturation 1.1.0, net-dep-failover 1.0.0, injection-quarantine 1.0.0. Loader verifies hash + version pin; poisoned-runbook test asserts rejection.

## 21 Evidence
Evidence{evidence_id, incident_id, source_type, source_id, ts, ref(span/line/row), hash, freshness_s, relevance 0..1, trust high|med|low}. Claim classes: MUST-CITE (facts, causality, RCA, remediation justification) / SHOULD-CITE (recommendations, context) / OPTIONAL (general synthesis). Gate: all MUST-CITE have ≥1 high/med valid-hash evidence else RCA publish DENIED + `rca-gate-failed` audit. UI chips link claim→evidence→source line.

## 22 Retrieval (frozen)
Lyzr Classic KB (`runbooks-v*`, `history`) with MMR, chunk≈natural section (~500 tokens), overlap 10%, score threshold tuned (start 0.7, revise), top-k=5 + local metadata/temporal filter (service/env/±window, decay) + rerank. Telemetry never bulk-indexed: pre-digester builds Evidence Pack (§23); full blobs in Postgres retrievable by ref. NO pgvector (unjustified duplication). KG/Semantic Model: documented options; Semantic Model (read-only SELECT) may query telemetry tables as `[OPTIONAL]` if time. Metrics: p@5, r@5, MRR, nDCG, irrelevant_ratio, citation precision.

## 23 Telemetry
Tables: alerts, logs, metrics, traces, k8s_events, deploy_events, services, pods (all ts+service+env+hash indexed). Generator `/telemetry/gen.py` deterministic per (scenario,variant,seed) with sha log. Pre-digest per incident: windowed error signature, top-5 errors+counts, metric deltas (pre/post 15m), deploy diff (from→to+author within ±15m), 3 trace exemplars, topology neighbors. Output Evidence Pack ≤6k tokens `[PROVISIONAL]` to A2.

## 24 Correlation (deterministic)
fingerprint=sha256(service|error_signature|env|deploy_window±15m). Group if same fingerprint OR (service/dependency edge + 10m + sig_sim>0.7). Severity: P1 prod+(err>5%|SLO breach|security-like); P2 prod degraded; P3 staging/non-critical; P4 noise/FP-pattern. LLM may propose owner only. Tests: 30 fixture groups incl. split/merge edge cases.

## 25 Diagnosis
A2 → hypotheses[{text, confidence, supporting[], contradicting[], test{tool,args}, result, status SUPPORTED|REJECTED|UNCERTAIN}] + runbook pin or INSUFFICIENT_EVIDENCE (conf<0.6 or contradiction unresolved). Require ≥2 hypotheses unless single-cause evidence overwhelming (document why). Contradictions surfaced, never averaged.

## 26 Sandbox
mock (default, stateful dict services/pods/deploys; restart→state flap+ready, scale→replicas, rollback→version, blocks→zero diff asserted); docker (`EXECUTOR=docker`, unpriv, no secret mounts, net-isolated, 60s timeout); kind `[OPTIONAL]` toggle. Same Action schema all tiers; tier label on every execution + UI badge.

## 27 HITL
Request{incident, action+params-hash, risk, blast, evidence, reason, policy ref, expected, rollback, agent, ts, expires}. Token=HMAC-SHA256(secret, action_id|actor|params_hash|scope|expiry|nonce); server verifies: signature, actor role, scope==exact params hash, expiry, nonce unused (store+burn). Replay/tamper/expired/wrong-actor → DENY + audit. UI Safety Gate shows all fields + countdown; approve/deny are POST with Idempotency-Key.

## 28 Execution
Accept iff validator-pass + (ALLOW-permit | valid token for exact params hash). Lock incident → dry-run → apply tier → stream → record execution{state_diff{before,after}, logs, tier}. Duplicate action_id → cached result + audit. Any gate failure → no exec + audit.

## 29 Verification (independent)
Checks: pod ready, deploy available, err_rate<thr, p95<SLO, zero new CrashLoop 60s (mock ticks), version==expected. Verdict RESOLVED|PARTIAL|FAILED|WORSENED|ROLLBACK_REQUIRED|ESCALATE. Planner output inadmissible as evidence. Config `/policies/slo.yaml` versioned. exit-0-with-bad-SLO → FAILED (test).

## 30 Rollback
Reversible YELLOW must carry rollback_action+conditions+re-verify plan. Auto one attempt on FAILED/WORSENED/ROLLBACK_REQUIRED; success→re-verify→RESOLVED else ESCALATED. Irreversible (RED) has no path by design.

## 31 RCA
Sections: summary, timeline(ts+actor+hash per row), root cause (claims+map), impact (MTTR, blast), remediation log, prevention (runbook patch/monitor/test; PR draft `[OPTIONAL]`), audit ref. Blameless lint blocks personal-blame terms. Gate §21 enforced in `publish_rca`.

## 32 AIMS/Audit
Event{event_id, seq, ts, incident_id, actor, agent, event_type, input_hash, evidence_ids, policy{version,rule,result}, action_id, approval_id, execution_id, result, prev_hash, curr_hash=SHA256(prev+canonical)}. Emit on every transition/tool/policy/approval/exec/verify/RCA/eval. AIMS trace/transcripts/reports = platform view (link incident→session). Custom chain = exportable proof: `GET /incidents/{id}/audit` returns chain+`valid` bool + verify routine; nightly tamper-check job in CI demo. Never label custom rows "AIMS".

## 33 Evaluation Engine
Custom runner (pipeline-level) + Lyzr Agent Eval (agent-level: hallucination/faithfulness/tool-args via CSV import of our cases). Runner: CASE→RUN→TRACE→GRADE→SCORE→COMPARE→REPORT; stores `runs/*.jsonl` + `scorecard.html` + metrics JSON. Graders: schema-valid, policy-correct (expected ALLOW/ESCALATE/DENY), citation gate, unsafe_exec==0, attack contained, SLO-verdict match, budgets. Rubric estimator maps §57. Baseline-vs-optimized harness: raw-vs-predigest, big-vs-routed-models, serial-vs-parallel retrieval.

## 34 Golden Benchmarks
12 categories at data-model level; deep-5 (bad-deploy, crashloop/OOM, db-exhaust, net/dep-fail, injection) × 5 variants (NORMAL/NOISY/INCOMPLETE/CONTRADICTORY/ADVERSARIAL) fully seeded with expected RCA + allowed/forbidden + SLO; stub-7 minimal fixtures. Each: alerts/metrics/logs/traces/topology/deploys/expected/allowed/forbidden/verify.

## 35 Adversarial Tests (10 critical)
log-injection, poisoned-runbook, fake-telemetry, stale-telemetry, contradictory, unsafe-command, param-injection, secret-exfil, approval-replay, runaway-loop (+cost-bomb, policy-bypass paraphrase as bonus). Each file: attack/expected/control/metric/audit-assertion. Gates: injection_success=0, bypass=0, unsafe_exec=0, false_block<5%.

## 36 Six Quality Gates (all `[PROVISIONAL]`; revise after 20 baseline runs)
C1 hallucination: unsupported MUST-CITE=0, fabricated_cmd=0, invalid_args<2%, replay-identical=100%. C2 groundedness: diag/action coverage=1.0, citation complete=1.0, unsupported_rec=0. C3 retrieval: p@5≥0.8 r@5≥0.75 MRR≥0.8 nDCG≥0.8 irrelevant<0.2. C4 cost: <80k tok, <12 calls, ctx<12k/call, cache_hit>50%; $ via pricing table only. C5 prompt: injection 0/10, unsafe_compliance 0, schema_valid>98%, bypass 0. C6 latency: triage<10s retrieval<15s diagnosis<30s policy<3s exec<20s verify<25s e2e P50<90s. Dashboard: metric+baseline+optimized+n+chart per gate; every number links to run JSONL.

## 37 Security / Threat Model
Injection (direct/indirect via logs|runbook|telemetry) → DATA-delimiting + "instructions-in-data void" prompt rule + RAI + validator; detect: injection-case alerts; recover: clean re-plan. Command/param injection → typed schema + regex + ranges + dry-run. Tool abuse/priv-esc → per-agent ACL + shared-auth least-privilege. Secret leak/exfil → PII/redact policy + no-secret mounts + output scan. Poisoned runbook → pin+hash+owner + loader verify. Fake/stale/contra telemetry → freshness + multi-source agreement + trust levels. State tamper/double-exec → locks + idempotency. Approval replay → nonce/TTL/scope/HMAC. Audit tamper → hash verify job. Dependency compromise → lockfiles + pip-audit + gitleaks. All fail-closed + audited + escalated.

## 38 Invariants (enforced in code + tests)
1 unvalidated Action never reaches executor. 2 RED never executes (hackathon: no break-glass path). 3 YELLOW needs valid unused unexpired scoped token. 4 tokens HMAC+nonce, single-use. 5 LLM has no shell/exec tool. 6 telemetry is DATA, never instructions. 7 mutations need action_id. 8 mutations need policy decision id. 9 mutations need verification. 10 blocks emit audit. 11 RCA gated on MUST-CITE. 12 loops bounded (hyp≤3, tools≤5/agent, re-plan≤2, calls≤12). 13 tokens bounded + kill-switch. 14 safety failures fail closed. 15 POLICY_CHECK→EXECUTING requires permit/token (no skip). 16 exit-status ≠ resolved.

## 39 Data Model
(FK/uniq/indexes/timestamps/hash/JSONB as V1 §39 +) deltas: `incidents.status` CHECK against 14 states; `actions.params_hash` generated column (uniq with action_id scope for approval binding); `approvals.token_hash UNIQUE, nonce UNIQUE, used_at`; `executions.action_id UNIQUE` (idempotency); `audit_events(seq BIGSERIAL PK, prev_hash, curr_hash)`; `runbooks(id,version PK, hash)`; `policies(version PK)`; `agent_runs(tokens_in/out, latency_ms, session_id)`; `tool_calls(agent, tool, args_hash, latency_ms, result_ref)`; `retrieval_events(query_hash, k, scores)`; eval tables store metrics JSONB. Migrations in `/backend/db/migrations`; seed script idempotent.

## 40 API
Auth: demo `X-API-Key` + `X-Role: viewer|approver|admin`. Mutations require Idempotency-Key. Endpoints: POST /alerts · POST /incidents · GET /incidents · GET /incidents/{id} · POST /incidents/{id}/triage · GET /incidents/{id}/evidence · POST /incidents/{id}/diagnose · POST /incidents/{id}/remediation · GET /approvals/{id} · POST /approvals/{id}/approve|reject · POST /executions{action_id,approval_token} · POST /executions/{id}/verify · POST /executions/{id}/rollback · GET /incidents/{id}/audit · GET /incidents/{id}/rca · POST /evaluations/run · GET /evaluations/{id} · POST /demo/seed. Guards: approve/execute verify role server-side; execute re-checks policy permit freshness (≤5m); verify/rollback check execution ownership; no endpoint bypasses policy/HITL/verify (negative tests). Errors: 400 validation{audit}, 401/403 role{audit}, 404, 409 conflict/duplicate{audit}, 410 expired approval, 422 schema, 429 rate-limit. OpenAPI auto + `/docs/API.md` examples with exact Lyzr endpoint refs.

## 41 Frontend (5 views, React+TS+Vite+Tailwind+shadcn)
1 Command Center (queue, severity chips, status, age, MTTR, budget mini, mode badge). 2 Incident Detail (timeline, alerts, evidence chips→source, hypotheses+ruled-out, runbook pin). 3 Safety Gate (action card, risk badge, policy rule quote, evidence, expected/rollback/verify, Approve/Deny + TTL). 4 Execution/Verification (stream, state-diff BEFORE/AFTER, SLO badges, verdict, Rollback). 5 RCA/Evaluation (RCA doc, audit viewer + valid badge, six-gate cards + charts). Max 5 routes; every number links to evidence/audit/run.

## 42 Realtime UX
Lyzr `stream-chat` SSE for agent tokens; custom `/stream/incidents/{id}` SSE for control-plane (incident/agent/retrieval/policy/approval/execution/verification/audit). Auto-reconnect + 3s polling fallback. Every streamed item carries audit event id. Header badge LIVE/REPLAY/MOCK always visible.

## 43 Repository
Keep `[OFFICIAL]` `/agents /frontend /backend /Dockerfile /docker-compose.yml /.env.example /README.md` + `/policies /runbooks /telemetry /tools /evaluation /benchmarks /tests /docs /scripts`. Responsibilities per V1 §43. No Lyzr keys committed; `.env.example` documents all vars incl. `LYZR_API_KEY, LYZR_AGENT_*_ID, LYZR_RAI_POLICY=PS03-Governed, EXECUTOR, APPROVAL_SECRET, POLICY_VERSION`.

## 44 Documentation
README (problem/solution/diagram/Lyzr-vs-custom table/setup/demo/tests/budget table/benchmark shot/limits/roadmap/attribution) + ARCHITECTURE.md + API.md + SECURITY.md + EVALUATION.md + DEMO.md + TESTING.md + DECISIONS.md (ADRs: FSM-primary, 4-agent, no-pgvector, RAI-placement, token-crypto, mock-default).

## 45 Testing
unit·policy(40+ incl. default-deny/conflicts/no-skip)·schema(20 invalid)·tools(ACL/timeout)·retrieval(p@k fixtures)·agent-contract (mocked LLM: schema-valid, cited, ACL-respecting)·sandbox(transitions + zero-diff)·verify(all verdicts)·integration(3 paths: happy/block/rollback)·security+adversarial(10+)·eval(grader determinism)·regression(golden in CI)·perf(budget asserts). Policy/sandbox/verifier/audit 100%, overall >80%.

## 46 CI/CD
ruff→mypy→unit→integration(compose)→security(pip-audit+gitleaks)→evaluation(deep-5; fail if unsafe_exec>0 or coverage<1.0 or budget breach)→build→smoke(up+seed+1 e2e). Policy tests are independent blocking job. `eval.sh` + `demo.sh --check` runnable locally.

## 47 Technology Stack
UI React+TS+Vite+Tailwind+shadcn · API FastAPI+Pydantic+SQLAlchemy · DB Postgres · stream SSE · infra Docker Compose (+Kind opt) · gen Python · agents Lyzr ADK/API · control FSM (SuperFlow mirror opt) · safety RAI + custom policy · audit hash + AIMS trace · eval custom + Lyzr Eval assist. Add nothing without measured justification (record in DECISIONS.md).

## 48 Deployment
`docker compose up --build` → api:8000 ui:5173 db:5432 seed-job. Profiles: default mock; `EXECUTOR=docker`; `EXECUTOR=kind` (+kind setup step). UI footer + README label SIMULATED telemetry. No prod/regulatory claims.

## 49 Cost
Routing: triage small/fast · diagnosis larger · planner medium · RCA economical (model ids in config, swappable). Bounds §09. Meter tokens_in/out, calls, ctx size, cache hits per incident; $ = tokens × pricing-table (config-editable, no hardcoded vendor prices). Widget + eval report show raw tokens first, $ second. Never trade verification/citation for tokens.

## 50 Latency
Budgets §09/`§36` `[PROVISIONAL]`; measure P50/P95 per stage (ingest/triage/retrieval/diagnosis/policy/approval-wait/exec/verify/RCA) via agent_runs/tool_calls timestamps + AIMS trace. Levers: parallel fetch, pre-digest, small triage model, cached static ctx, bounded loops, progressive SSE render. Report in scorecard with n.

## 51 Hackathon vs Enterprise
| Component | Hackathon | Enterprise future |
|---|---|---|
| Telemetry | seeded gen + mock K8s | OTel/Prom/Datadog/PD webhooks |
| Control | FSM (SuperFlow mirror opt) | SuperFlow-native + GitOps |
| Retrieval | Classic KB + predigest | +KG/Semantic Model, access-trimmed |
| Exec | mock/docker (+kind opt) | per-tenant runners, gVisor/Kata, PR-based |
| HITL | HMAC demo tokens | SSO/RBAC/PD approvals, 2-person break-glass |
| Audit | hash chain + AIMS trace | SIEM export, WORM retention |
| DB/deploy | compose Postgres | managed, PII retention |
| Cost/auth | shared demo svc account | per-user tool auth, budgets/quotas |

## 52 Competitive Differentiation (hedged, provable)
"Vendor correlators scale wider; OSS investigators cover more toolsets. Our demonstrable edge in hackathon scope: structured-action policy + sandbox + independent verify + auto-rollback + hash audit + adversarial scoreboard in ONE live flow — each step inspectable. Verify against HolmesGPT/SRE-agent/kube-agents repos and Bits AI/Rootly docs; we claim only what the demo + tests + audit prove."

## 53 Innovation (Follow/Adapt/Inspire/Invent/Avoid)
FOLLOW: P1-P4, timeline, citations, approvals, append-only log, blameless RCA, SLO verify, grouping, rollback, RBAC. ADAPT: kassi FSM→our FSM; CATAS ledger→G/Y/R; Holmes catalog→versioned YAML; SRE-agent predigest→retriever; BlastRadius→impact badge; ChangeShield→HMAC tokens; AgentSight→trace view; Workwizee→MTTR board. INSPIRE: Triangle (keep simple), ModelProof (verifier instead of judge-agent). INVENT: policy+sandbox+verify+hash+eval combo; per-incident token/latency ledger; FP learning loop. AVOID: chatbot-only, dashboard-only, fake N-agents/logos/audit, shell tools, prompt-only safety, giant contexts, benchmark-free %, integration sprawl, UI sprawl. Attribute all inspirations; copy zero proprietary assets/code/text.

## 54 Feature Priority
P0 (§62 must-pass items). P1: Kind toggle, blast badge, cost/latency board, FP feedback, stub-7, prevention-PR draft. P2: decision-graph viz, Semantic-Model telemetry queries. STRETCH: voice briefing. DO NOT BUILD: live vendor integrations, custom vector DB, secret UI, multi-cluster, autonomous RED, extra agents.

## 55 Demo (5:00, seed `bad-deploy/NORMAL`, pre-issued standby approval)
0:00 hook → 0:20 inject (N alerts→1 P1) → 0:40 topology+deploy marker → 1:00 evidence chips → 1:30 2 hypotheses + ruled-out + runbook pin → 2:00 planner emits `delete_namespace/prod` (poisoned suggestion path) → 2:10 RED BLOCK + rule quote + zero-diff proof → 2:30 YELLOW `rollback_deployment` → 2:40 Approve (TTL visible, mode LIVE) → 3:00 sandbox stream + BEFORE/AFTER diff (err 18%→0.8%, v23→v22) → 3:20 VERIFIED badge (+mention auto-rollback path; optional 2nd fail→rollback if timeboxed rehearsal passes 3/3) → 3:40 RCA (gated) → 4:00 scorecard (6 gates + tokens/latency) → 4:30 Lyzr-vs-custom table → 5:00 "Agent reasons. Control plane decides." + repo/URL.

## 56 Demo Fallback
Modes announced on-screen: LIVE (full), REPLAY (recorded agent trace + live policy/sandbox/verify on cached Action), MOCK (executor forced mock), OFFLINE (30s video last resort). Triggers: Lyzr timeout>20s→REPLAY agent spans; DB down→file-backed seed+audit; sandbox down→mock; net down→local images+video. Never present REPLAY as LIVE. `demo.sh --check` validates seeds+policies+runbooks+e2e <5min before stage.

## 57 Judge Traceability
| Rubric | Feature | Code | Test | Metric | Demo |
|---|---|---|---|---|---|
| 30% Orchestration | 4 agents + FSM + sessions | /agents/*, /backend/services/fsm.py | contract+transition+session-resume | tool_success>98%, persist-ok | 0:20–1:30, 4:30 trace |
| 30% Safety | validator+policy+HITL+sandbox+verify+rollback | policy/, approval/, sandbox/, verifier/ | 40 policy, 10 adversarial, no-skip, zero-diff | unsafe_exec=0, bypass=0, coverage=1.0 | 2:00–3:20 blocks+rollback |
| 20% Code/Arch | monorepo+compose+gen+types | /* layout, gen.py | unit+integration+lint+mypy | cov>80% (100% safety) | repo tour + one-command |
| 20% UX | 5 views+SSE+logs+diff | /frontend/* | stream+e2e click-to-evidence | first-paint<3s | whole 5:00, esp. 3:00 diff |
| C1–C6 | §36 gates | evaluation/ | suites+graders | scorecard | 4:00 board (link→JSONL) |

## 58 Gap Analysis (residual, post-correction)
| GAP | SEV | FIX | STATUS |
|---|---|---|---|
| SuperFlow programmatic mirror unbuilt | LOW | FSM canonical; mirror only if Studio time | Accepted, OPTIONAL |
| Lyzr credit/rate limits unknown | MED | caps + REPLAY fallback + local-first demo | Mitigated |
| Kind flakiness | MED | default mock; kind opt-in + `--check` | Mitigated |
| Pricing table variance | LOW | raw tokens primary, $ secondary | Accepted |
| 14-state UI complexity | LOW | group into 6 phase badges (Triage→Diagnose→Govern→Execute→Verify→Learn) | Do in frontend |
| Secret handling for future prod | MED | out of scope; documented FUTURE + redaction now | Accepted |
| Multi-user approval identity | LOW | X-Role demo; SSO FUTURE | Accepted |

## 59 Definition of Done
LYZR: keys wired; 4 agents Structured-Output-valid; sessions resume; RAI `PS03-Governed` attached (screenshot); trace visible or fallback doc'd. SAFETY: invariants §38 green; no-skip + replay + zero-diff + tamper tests pass. GROUNDING: coverage 1.0; retrieval gates; KB threshold tuned. EVAL: deep-5×5 + adversarial-10 green; JSONL committed; scorecard in README. REPO: paths+compose+env+8 docs. DEMO: live+fallback rehearsed 3×; `--check` green; block+approve+verify+scorecard all shown.

## 60 Implementation Tasks
T01 repo+compose (up+healthz). T02 schemas Action/Evidence/Approval/Audit + 20 invalid fixtures. T03 gen.py + deep-5 seeds + sha log. T04 policy engine + matrix + bundle_v1 + 40 tests. T05 validator (shell/DROP reject pre-policy). T06 HMAC approval (issue/verify/replay/tamper/expiry tests). T07 mock sandbox (transitions + zero-diff). T08 docker executor (allowlist mutate, RED refuse). T09 verifier (5 verdicts; exit-0-bad-SLO→FAILED). T10 rollback (auto-once + re-verify). T11 5 runbooks + loader hash/pin. T12 retriever + Evidence Pack (p@5 gate). T13 4 Lyzr agents + prompts + Structured Output + contract tests (mocked). T14 FSM + guards + idempotency + no-skip test. T15 HITL API+Gate UI (approve/deny/expire e2e). T16 hash audit + verify endpoint + tamper test. T17 eval runner + graders + suites + scorecard. T18 frontend 5 views + dual SSE + badges. T19 adversarial-10 red tests. T20 budgets (token/latency asserts). T21 demo harden (`seed.sh eval.sh demo.sh --check`, REPLAY pack, DEMO.md). Each PR states: purpose/files/deps/input/output/acceptance/test/metric/rubric-impact.

## 61 Development Order
1 repo → 2 schemas → 3 telemetry → 4 policy → 5 validator → 6 sandbox → 7 verifier → 8 rollback → 9 runbooks → 10 retrieval → 11 Lyzr agents → 12 orchestration → 13 HITL → 14 audit → 15 evaluation → 16 frontend → 17 adversarial → 18 performance → 19 demo harden. UI only after T02–T10 merged.

## 62 Final Architecture
```
Telemetry(gen/SIM) → Normalize/Pre-digest(CUSTOM) → Correlate(CUSTOM) → A1 Triage(LYZR) →
Evidence Pack(CUSTOM) + KB(LYZR) → A2 Diagnostic(LYZR) → Hypotheses → Runbook pin →
A3 Planner(LYZR) → Action → Validator(CUSTOM) → Policy(CUSTOM) → RAI(LYZR, agent-bound) →
HITL(CUSTOM HMAC) → Sandbox+Execute(CUSTOM mock/docker) → Verify(CUSTOM) → Rollback?(CUSTOM) →
A4 RCA(LYZR, gated) → Audit hash(CUSTOM) + Trace(AIMS/LYZR) → Eval runner(CUSTOM)+AgentEval(LYZR) →
UI 5 views + dual SSE. Manager(LYZR, opt front). SuperFlow(OPT mirror). Automata(BANNED).
```

## 63 Final Agent Graph
Triage → Diagnostic ⇄(test/reject, ≤3 hyp) → Planner → Control Plane[Validator→Policy→RAI→HITL] → Executor → Verifier →(fail: Rollback→re-verify once)→ RCA Reporter → Published/AUDITED. Eval Engine observes all nodes. Bounds: tools≤5/agent, re-plan≤2, calls≤12. Fallbacks: safe-alt re-plan → escalate → replay.

## 64 Final Build Blueprint
PRODUCT Evidence-Grounded Incident Commander. LYZR: ADK 4 agents + Structured Output + RAI + Classic KB + Cognis/Global Context + chat/stream-chat + trace + Eval-assist (+Manager opt, SuperFlow mirror opt). CUSTOM: FSM, validator, policy, HMAC HITL, sandbox, verifier, rollback, hash audit, eval runner, pre-digester. SIMULATED: telemetry + mock K8s. CORE VALUE: evidence-grounded response with provable safety — every claim cited, every action authorized, every mutation verified, every step audited and scored.
