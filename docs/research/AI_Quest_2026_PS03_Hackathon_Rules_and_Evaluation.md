# AI Quest 2026 — PS03 Hackathon Rules & Evaluation Specification

## Purpose

This document consolidates the currently available official challenge information for **AI Quest: Beyond the Wrapper — 2026**, with a PS03-specific implementation focus.

It deliberately separates:

- **Official / organizer-provided requirements**
- **PS03 problem-specific requirements**
- **Six global production evaluation checkpoints**
- **Recommended engineering controls** that we should implement even where they are not explicitly stated as organizer rules

Do not present recommendations in this document as official rules.

---

# 1. Competition Identity

## Competition

**AI Quest: Beyond the Wrapper — 2026**

## Platform / ecosystem

HiDevs + Lyzr

## Selected problem statement

**PS03 — Enterprise Cloud Incident Triage & Runbook Remediation Agent**

## Track

DevOps / SRE / Cloud Infrastructure

## Participation

Individual / solo participation.

The current public Unstop listing explicitly states **Team Size: Individual Participation** and shows registration for the challenge as closed on 9 September 2026 at 10:00 PM IST. citeturn685655search1

The challenge is presented as an online HiDevs experience. citeturn685655search1turn685655search0

---

# 2. Competition Philosophy

The central theme is **“Beyond the Wrapper.”**

The public challenge description frames the quest as moving away from thin LLM wrappers toward production-grade autonomous agents that are stress-tested using strict engineering rubrics. It explicitly emphasizes resilient multi-step workflows, governance, quantitative evaluation, and native Lyzr usage. citeturn685655search0turn685655search1

The public event description also states that projects are evaluated through quantitative execution metrics rather than merely subjective pitch decks or basic UI wrappers. citeturn685655search0turn685655search1

## Practical interpretation for PS03

We should therefore think in terms of:

```text
LLM / Agent Reasoning
        ↓
Evidence
        ↓
Structured State
        ↓
Policy / Governance
        ↓
Controlled Tool Use
        ↓
Execution
        ↓
Verification
        ↓
Audit
        ↓
Measurement
```

Not:

```text
Alert → LLM → Answer
```

---

# 3. Quest Lifecycle / Stages

The current public challenge flow describes the following stages:

1. **Registration & Platform Access**
2. **Challenge Release & Kickoff**
3. **Build, Deploy & Benchmark**
4. **Evaluation & Results**

The public listing says the build stage requires participants to build and deploy a production-grade autonomous AI agent using Lyzr and submit the repository and live endpoint through the HiDevs Quest Engine. Submitted agents are then benchmarked against the defined engineering rubrics. citeturn685655search1

The HiDevs quest page supplied in this project further presents the operational path as:

```text
Register
→ Select PS
→ Build
→ Pre-submit
→ Feedback
→ Team / Build Evaluation
→ Rewards
```

For our actual PS03 page, the UI also provides:

- GitHub repository connection
- Dr Agent feedback
- pre-submit evaluation
- repository-based review
- live endpoint submission

The selected repository is described as the same repository used for review.

---

# 4. Current Official Timing Information

## Registration

Public Unstop listing:

**9 September 2026 — 10:00 PM IST** registration deadline. citeturn685655search1

## Submission

The current public listing states:

**Submission deadline — 13 September 2026 — 10:00 PM IST.** citeturn685655search1

## Results

The public listing says:

**Results announced — 15 September 2026.** citeturn685655search1

## Important date note

Different public event/listing surfaces contain slightly different earlier milestone wording. The current Unstop listing explicitly states the submission deadline as **13 September 2026 at 10:00 PM IST** and says submission starts by 9 September at 10:00 PM. citeturn685655search1

Therefore:

> Treat the current challenge/platform page and current submission UI as the operational source of truth for final submission timing.

---

# 5. Prize / Recognition Information

The challenge advertises a combined prize pool of:

**₹50,000**

consisting of:

- **₹20,000 cash**
- **₹30,000 AI / infrastructure credits**

The public challenge/event materials describe recognition for the top **3–5 breakout builds** / winning builds. citeturn685655search0turn685655search1

---

# 6. PS03 Official Problem Statement

## Name

**Enterprise Cloud Incident Triage & Runbook Remediation Agent**

## Domain

DevOps / SRE / Cloud Infrastructure

## Core objective

Build a **governed multi-agent SRE mesh** that:

- triages alerts
- diagnoses root cause
- proposes safe runbooks
- uses human-in-the-loop gates for risky actions
- performs safe remediation
- produces a blameless RCA / postmortem
- maintains an auditable execution history

---

# 7. PS03 Context

The challenge describes the problem as noisy and cascading production alerts across systems such as:

- Datadog
- CloudWatch
- PagerDuty
- Kubernetes logs
- Prometheus-style telemetry

The stated operational concern is that incidents can overwhelm SREs and that unsafe automation can introduce additional damage, such as dropping databases or causing destructive infrastructure changes.

The problem also emphasizes the time cost of postmortems.

---

# 8. PS03 Required Opportunity

The challenge calls for a governed multi-agent SRE team using:

- **Lyzr Automata**
- **Lyzr Agent API**

The system should be able to:

- correlate alerts
- test hypotheses
- propose safe remediations
- obtain human approval for destructive / risky actions
- publish an end-to-end RCA

---

# 9. PS03 Architecture Given by the Challenge

## 01 — Alert Ingest

Ingest PagerDuty / Prometheus-style alerts into a Lyzr telemetry environment.

## 02 — Triage & Dedup

Cluster related anomalies and classify severity P1–P4.

## 03 — Root Cause Diagnostician

Query mock logs / traces and identify likely causes such as:

- memory leak
- deadlock
- bad deployment

## 04 — Safe Remediation Gate

Use Lyzr Safe AI so destructive actions such as:

- DELETE
- DROP
- REBOOT

are protected by human approval.

## 05 — Post-Mortem

Produce a blameless RCA containing:

- timeline
- root cause
- prevention notes

and log the execution history to AIMS.

---

# 10. PS03 Official MVP Requirements

The PS03 MVP explicitly calls for:

### MVP-01 — Alert ingestion

Support mock Prometheus / Kubernetes-style alert inputs.

### MVP-02 — Multi-agent triad

Use:

- Triage agent
- Diagnostic agent
- Remediation agent

### MVP-03 — Safe AI safety boundary

Use Lyzr Safe AI to protect destructive actions and require human confirmation where required.

### MVP-04 — Automated postmortem

Produce a timeline, root cause, and prevention recommendations.

---

# 11. PS03 Stretch Goals

The stated stretch goals are:

### Stretch 01 — Live sandbox

Use Kind / Minikube for non-destructive `kubectl` workflows.

### Stretch 02 — Voice briefing

Provide a real-time incident briefing agent.

### Stretch 03 — AIMS decision graph

Expose diagnostic reasoning / decision-path information through AIMS.

These are stretch goals, not baseline requirements.

---

# 12. PS03 Problem-Specific Judging Rubric

## 30% — Lyzr Agent Orchestration

The challenge evaluates:

- clear task distribution
- robust tool calling
- state persistence

### What this means for us

We must make it obvious that the agents are real specialized workers rather than multiple decorative prompts.

Evidence should include:

- agent definitions
- actual agent calls
- explicit state transitions
- tool use
- failure handling
- persisted incident state

---

## 30% — DevOps Safety & Reliability

The challenge evaluates:

- sound diagnosis
- avoidance of dangerous shell hallucinations
- clear HITL gating

### What this means for us

Safety must be visible and testable.

We should demonstrate:

```text
LLM proposal
    ↓
Structured action
    ↓
Safety / policy check
    ↓
ALLOW / APPROVAL / BLOCK
    ↓
Controlled execution
```

A prompt saying “do not delete production” is not enough.

---

## 20% — Code Quality & Architecture

The challenge explicitly calls for:

- clean codebase
- mock telemetry generator
- Dockerized setup

### Repository implications

Our code should be:

- modular
- typed where practical
- testable
- clearly documented
- reproducible
- easy to run

---

## 20% — SRE Experience & UI

The challenge calls for:

- real-time incident dashboard
- log streaming
- action logs

### UI implication

The dashboard should expose operational state, not merely provide a chat window.

---

# 13. Six Global Production Evaluation Checkpoints

These six checkpoints must be treated as explicit engineering targets.

---

## Checkpoint 01 — Hallucination Mitigation

### Official objective

**Eliminate fabricated facts and maintain deterministic output consistency.**

### PS03 interpretation

The system must avoid inventing:

- alerts
- metrics
- log evidence
- service state
- deployment state
- root causes
- commands
- runbook steps
- verification results

### Recommended controls

- structured outputs
- schema validation
- tool-backed facts
- evidence IDs
- controlled command generation
- deterministic policy layer
- explicit UNKNOWN / INSUFFICIENT_EVIDENCE states
- replay tests

### Recommended metrics

```text
unsupported_claim_rate
fabricated_command_rate
invalid_tool_argument_rate
repeatability_rate
```

These metrics are **our engineering proposal**, not organizer-published numerical thresholds unless the current testbed specifies otherwise.

---

## Checkpoint 02 — Groundedness

### Official objective

**Ensure tight adherence and verified attribution to source data.**

### PS03 interpretation

Every important conclusion should be traceable to actual incident evidence:

```text
Diagnosis
   ↓
Evidence IDs
   ↓
Alert / Log / Metric / Trace / Event / Deployment
```

### Recommended evidence object

```text
evidence_id
incident_id
source_type
source_id
timestamp
content_span
freshness
trust_level
```

### Recommended metrics

```text
diagnosis_evidence_coverage
action_evidence_coverage
citation_completeness
unsupported_recommendation_rate
```

---

## Checkpoint 03 — Retrieval Quality

### Official objective

**Maximize semantic precision, chunk relevance, and context injection efficiency.**

### PS03 interpretation

The system should not dump thousands of log lines into the context window.

It should retrieve incident-relevant context using combinations of:

- service filters
- time windows
- environment
- deployment
- alert type
- semantic search
- keyword search
- metadata filters

### Recommended metrics

```text
precision@k
recall@k
MRR
nDCG
irrelevant_context_ratio
```

### Recommended retrieval sources

- runbooks
- logs
- historical incidents
- deployment history
- service metadata
- known-error records

---

## Checkpoint 04 — Costing & Token Optimization

### Official objective

**Minimize token consumption overhead and streamline reasoning loops.**

### PS03 interpretation

Do not create expensive agent loops merely to look agentic.

Optimize through:

- focused retrieval
- compressed evidence
- bounded retries
- cached data
- structured state
- small-model routing where appropriate
- deterministic processing for simple tasks
- parallel retrieval where safe

### Recommended metrics

```text
tokens_per_incident
LLM_calls_per_incident
cost_per_incident
average_context_size
cache_hit_rate
```

---

## Checkpoint 05 — Prompt Architecture

### Official objective

**Engineer robust defensive guardrails and structured system instructions.**

### PS03 interpretation

Prompts should define:

- role
- objective
- inputs
- outputs
- evidence rules
- uncertainty behavior
- tool rules
- safety rules
- forbidden behavior
- escalation
- stop conditions

### Important security principle

Prompt architecture is defense-in-depth.

It must NOT be the sole runtime security boundary.

---

## Checkpoint 06 — Latency Optimization

### Official objective

**Achieve fast end-to-end execution traces and rapid tool calling performance.**

### PS03 interpretation

Incident response is time-sensitive.

We should measure:

```text
ingestion latency
triage latency
retrieval latency
diagnosis latency
policy latency
execution latency
verification latency
total pipeline latency
```

### Recommended metrics

```text
P50
P95
incident_triage_time
triage_diagnosis_time
diagnosis_policy_time
policy_action_time
action_verification_time
total_pipeline_time
```

---

# 14. Required GitHub Repository Structure

The current PS03 HiDevs page provides this required structure:

```text
your-repo/
│
├── agents/
│   └── Lyzr agents, configs, orchestration
│
├── frontend/
│   └── UI / app clients that call agents
│
├── backend/
│   └── APIs, services, integrations
│
├── Dockerfile                 [optional]
├── docker-compose.yml         [optional]
├── .env.example               [optional]
└── README.md
```

## README requirement

The page specifically describes the README as containing:

- setup
- run instructions
- architecture notes

## Practical recommendation

We should extend this required structure with additional clearly organized directories only when they improve the project, for example:

```text
/agents
/backend
/frontend
/policies
/runbooks
/tools
/retrieval
/telemetry
/evaluation
/tests
/docs
```

Do not destroy the required top-level structure.

---

# 15. GitHub Connection / Review Rules

The current HiDevs page states that GitHub connection is used for feedback and that the selected repository is used for review.

The workflow includes a Dr Agent feedback mechanism.

Practical consequence:

> The repository itself is part of the evaluation surface.

Therefore the repository should be treated as a production artifact, not simply a code dump.

---

# 16. What “Production-Grade” Should Mean for Our Submission

We should distinguish:

### Production-oriented architecture

The design principles used in a real enterprise environment.

### Hackathon deployment

The actual sandbox / simulated environment we can reliably run.

### Production deployment

A future system connected to real observability and infrastructure platforms.

We should NOT claim the hackathon sandbox is equivalent to a production environment.

Instead:

```text
REAL ENTERPRISE ARCHITECTURE
        ↓
HACKATHON-SAFE SIMULATION
        ↓
SAME INTERFACES / POLICIES / STATE MODEL
        ↓
FUTURE REAL CONNECTORS
```

---

# 17. Recommended PS03 Architecture

```text
                    ALERT / TELEMETRY
                           ↓
                     INGESTION LAYER
                           ↓
                    NORMALIZATION
                           ↓
                   TRIAGE / CORRELATION
                           ↓
                    EVIDENCE RETRIEVAL
                           ↓
                    DIAGNOSTIC AGENT
                           ↓
                  HYPOTHESIS TESTING
                           ↓
                 REMEDIATION PLANNER
                           ↓
               STRUCTURED ACTION REQUEST
                           ↓
              DETERMINISTIC POLICY ENGINE
                           ↓
                     LYZR SAFE AI
                           ↓
             ┌─────────────┴─────────────┐
             ↓                           ↓
          SAFE AUTO                  HITL REQUIRED
             ↓                           ↓
             │                       HUMAN REVIEW
             │                           ↓
             └─────────────┬─────────────┘
                           ↓
                  SANDBOX EXECUTOR
                           ↓
                 DETERMINISTIC VERIFY
                           ↓
             ┌─────────────┼─────────────┐
             ↓             ↓             ↓
          RESOLVED     ROLLBACK       ESCALATE
             └─────────────┼─────────────┘
                           ↓
                         AIMS
                           ↓
                    RCA / POSTMORTEM
                           ↓
                  EVALUATION ENGINE
```

---

# 18. Lyzr Usage Policy for Our Project

## Agent API — CORE

Use for real specialized agents.

Expected responsibility:

- Triage
- Diagnostic
- Remediation

The exact final agent count should be justified; more agents do not automatically mean better architecture.

## Automata — CORE

Use as deeply as officially supported for the multi-step incident workflow and orchestration.

Do not fake Automata usage.

## Safe AI — CORE

Use as a real part of the safety architecture.

For example:

```text
agent proposes action
        ↓
Safe AI / governance checks
        ↓
policy path
```

Do not claim that Safe AI alone is the entire security boundary.

## AIMS — CORE

Use for actual audit / execution observability where the current platform capability supports it.

Do not create a fake local log and label it AIMS.

---

# 19. Minimal Custom Deterministic Layer

The strongest architecture should include a small custom layer around the Lyzr workflow for controls that must be deterministic.

Primary responsibilities:

- structured action validation
- policy evaluation
- risk classification
- parameter validation
- permission checks
- state transition validation
- idempotency
- execution gating
- post-action verification

Conceptual decision:

```text
LLM SUGGESTS
      ↓
CUSTOM DETERMINISTIC CONTROL
      ↓
ALLOW / APPROVE / DENY / ESCALATE
      ↓
EXECUTOR
```

This is an architecture recommendation, not an organizer requirement.

---

# 20. Action Risk Model

Use a practical risk model for the sandbox.

## Tier 1 — Read-only

Examples:

- get resource
- describe resource
- retrieve logs
- retrieve metrics
- inspect status

Recommended:

**AUTOMATIC**

## Tier 2 — Low-risk / reversible mutation

Examples:

- restart a controlled sandbox workload
- scale a sandbox deployment
- change a temporary test configuration

Recommended:

**AUTOMATIC OR CONDITIONAL APPROVAL** depending on policy.

## Tier 3 — High-impact external / state-changing action

Examples:

- rollback a deployment
- modify sensitive configuration
- change network routing

Recommended:

**HITL OR STRICT POLICY-BASED APPROVAL**

## Tier 4 — Destructive / irreversible

Examples:

- DROP
- DELETE production resources
- delete namespace
- destructive data modification
- unsafe cluster-wide operations

Recommended:

**BLOCK OR MANDATORY HUMAN APPROVAL**

For the hackathon, the safest demonstration is to show these actions being detected and prevented from executing in the restricted environment.

---

# 21. Sandbox Rules

The hackathon version should NOT connect autonomous execution to real production infrastructure.

Use a controlled environment such as:

- simulated executor
- Docker-based sandbox
- Kind
- Minikube
- K3d

The final choice should be based on reliability, setup risk, resource usage, and demo stability.

The sandbox should demonstrate realistic state changes where possible.

For high-risk actions, the important behavior is:

```text
PROPOSE
→ CLASSIFY
→ BLOCK / APPROVAL
→ NO UNSAFE SIDE EFFECT
```

---

# 22. Human-in-the-Loop Rules

A strong approval workflow should expose:

- incident
- proposed action
- risk tier
- affected resources
- reason
- evidence
- expected impact
- policy result
- rollback plan
- agent identity
- timestamp

Human options should include:

- Approve
- Reject
- Request Evidence
- Escalate
- Cancel

The approval should be tied to the specific action, not merely the general incident.

---

# 23. Verification Rules

Never consider an incident fixed simply because a command returned successfully.

Use:

```text
ACTION
 ↓
HEALTH CHECK
 ↓
METRICS
 ↓
LOG CHECK
 ↓
SERVICE STATE
 ↓
SLO CHECK
 ↓
FINAL STATUS
```

Possible outputs:

- RESOLVED
- PARTIALLY_RESOLVED
- FAILED
- WORSENED
- ROLLBACK_REQUIRED
- ESCALATED

---

# 24. Grounded Diagnosis Requirements

A diagnosis should be represented as:

```json
{
  "hypothesis": "bad_deployment",
  "confidence": 0.91,
  "supporting_evidence": ["E-102", "E-107"],
  "contradicting_evidence": ["E-113"],
  "affected_services": ["payments-api"],
  "proposed_test": "compare_error_rate_before_after_deployment"
}
```

The final RCA should be generated from accepted evidence, not merely model prose.

---

# 25. Prompt Architecture Requirements

Each agent prompt should include:

## Identity

What role does this agent perform?

## Objective

What is it trying to accomplish?

## Input contract

What data may it trust?

## Output schema

What structure must it return?

## Evidence rules

Which claims require evidence?

## Tool rules

What tools may it call?

## Safety rules

What must it refuse or escalate?

## Uncertainty rules

When must it say UNKNOWN?

## Stop conditions

When should the workflow terminate?

---

# 26. Retrieval Requirements

Do not create RAG just to satisfy a buzzword.

Use retrieval where incident response actually needs it.

Candidate knowledge sources:

- runbooks
- historical incidents
- service metadata
- deployment history
- known errors
- architecture documentation

Recommended hybrid strategy:

```text
metadata filters
+
keyword / lexical search
+
semantic retrieval
+
temporal filtering
```

Then rank only the evidence relevant to the current incident.

---

# 27. Evaluation Engine

We should build an internal Evaluation Engine even though this is our implementation choice rather than a separately stated PS03 requirement.

Purpose:

> Prove that the system actually satisfies the six production checkpoints.

Flow:

```text
Golden Incident
      ↓
Inject Telemetry
      ↓
Run PS03
      ↓
Capture Execution Trace
      ↓
Grade
      ↓
Score Six Gates
      ↓
Compare Against Baseline
```

---

# 28. Golden Incident Dataset

Recommended incident classes:

1. Bad deployment
2. Memory leak
3. CrashLoopBackOff
4. CPU saturation
5. Disk pressure
6. Database connection exhaustion
7. Deadlock
8. Network failure
9. Configuration error
10. Dependency outage
11. False-positive alert
12. Cascading alert storm

Each test case should contain:

- alerts
- logs
- metrics
- traces if used
- deployments
- service topology
- expected root cause
- allowed remediation
- forbidden remediation
- verification criteria

---

# 29. Adversarial Dataset

At minimum include tests for:

- malicious log injection
- prompt injection inside logs
- fabricated telemetry
- contradictory telemetry
- stale telemetry
- malicious runbook instructions
- dangerous commands
- parameter manipulation
- policy bypass
- unauthorized privilege escalation
- duplicate execution
- replay of approval
- verification spoofing

Expected principle:

> Untrusted telemetry is DATA, not INSTRUCTIONS.

---

# 30. Minimum Benchmark Scorecard

## Reliability

- triage accuracy
- RCA accuracy
- remediation success
- verification success

## Safety

- unsafe action block rate
- false block rate
- policy violation rate
- tool authorization failure rate

## Hallucination

- unsupported claim rate
- fabricated command rate

## Grounding

- evidence coverage
- citation completeness

## Retrieval

- precision@k
- recall@k
- MRR
- nDCG

## Cost

- tokens / incident
- calls / incident
- cost / incident

## Latency

- P50
- P95
- total pipeline time

---

# 31. Demo Requirements

The demo should not be a feature tour.

Use a single compelling incident.

Recommended narrative:

```text
NOISY INCIDENT
     ↓
ALERT CORRELATION
     ↓
EVIDENCE RETRIEVAL
     ↓
ROOT CAUSE
     ↓
REMEDIATION PROPOSAL
     ↓
UNSAFE ACTION ATTEMPT
     ↓
BLOCKED
     ↓
SAFE ACTION
     ↓
HUMAN APPROVAL
     ↓
SANDBOX EXECUTION
     ↓
VERIFICATION
     ↓
RCA
     ↓
AUDIT
     ↓
EVALUATION SCORECARD
```

The most important demo moments should demonstrate real controls, not animations.

---

# 32. Repository Quality Gate

Before submission:

```text
[ ] Required folders exist
[ ] README works from a clean environment
[ ] No secrets committed
[ ] .env.example is accurate
[ ] Docker build works if Docker is provided
[ ] App starts reliably
[ ] Live endpoint works
[ ] Agents can be invoked
[ ] Safety gate can be demonstrated
[ ] HITL can be demonstrated
[ ] Audit path works
[ ] Evaluation can run
[ ] Sample incident is reproducible
[ ] Adversarial case is reproducible
[ ] Architecture is documented
```

---

# 33. Submission Readiness Gate

Before clicking final submit, verify:

## Competition

[ ] correct problem statement selected
[ ] correct repository connected
[ ] correct live endpoint
[ ] latest code pushed
[ ] repository accessible
[ ] required files present

## Product

[ ] PS03 core workflow works end-to-end
[ ] incident triage works
[ ] diagnosis works
[ ] remediation proposal works
[ ] unsafe action is blocked / gated
[ ] human approval works
[ ] execution is safe
[ ] verification works
[ ] RCA works

## Lyzr

[ ] Agent API used authentically
[ ] Automata used where intended
[ ] Safe AI used authentically
[ ] AIMS used authentically where supported

## Six checkpoints

[ ] hallucination tests
[ ] grounding tests
[ ] retrieval tests
[ ] cost/token measurements
[ ] prompt-resilience tests
[ ] latency measurements

## Documentation

[ ] architecture diagram
[ ] agent graph
[ ] setup instructions
[ ] test instructions
[ ] benchmark results
[ ] known limitations

---

# 34. Things That Are NOT Official Rules Unless Explicitly Confirmed

The following are recommended engineering decisions, not organizer requirements unless the current HiDevs testbed or submission instructions explicitly state otherwise:

- a specific database
- a specific vector database
- a specific Kubernetes sandbox
- exact benchmark thresholds
- exact P50/P95 latency targets
- exact token budget
- exact number of agents
- Firecracker / gVisor / Kata
- cryptographic proof-of-execution
- graph database
- formal verification
- specific cloud provider
- any claim of regulatory certification

Do not present these as mandatory competition rules.

---

# 35. What We Should NOT Do

## Do not build a chatbot-only system

The competition is explicitly positioned beyond basic wrappers. citeturn685655search0turn685655search1

## Do not create fake multi-agent architecture

Three prompts are not necessarily three meaningful agents.

## Do not allow arbitrary model-generated shell execution

Use structured actions and deterministic authorization.

## Do not rely only on prompt safety

Runtime controls must remain outside the LLM reasoning layer.

## Do not fake AIMS / Safe AI usage

If a control is implemented by our custom code, label it as custom.

## Do not dump massive telemetry into context

Retrieve only relevant evidence.

## Do not optimize cost by destroying reliability

Safety and correctness come first.

## Do not build a huge UI before the workflow works

Backend/agent/safety correctness first; UI should expose it.

---

# 36. Our Target End-to-End System

```text
                    HI DEVS QUEST
                         │
                         ▼
              PS03 INCIDENT PLATFORM
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
    Lyzr Agents      Automata         Safe AI
        │                │                │
    Reasoning       Orchestration     Guardrails
        └────────────────┼────────────────┘
                         ▼
                CUSTOM CONTROL PLANE
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           Policy     Tool Auth   State
              └──────────┼──────────┘
                         ▼
                     SANDBOX
                         ▼
                   VERIFICATION
                         ▼
                       AIMS
                         ▼
                  EVALUATION ENGINE
                         ▼
                 SIX-GATE SCORECARD
```

---

# 37. Final Strategy

## Our core product

**Governed Autonomous Incident Commander**

## Core value proposition

> Investigate production-like incidents, ground diagnoses in evidence, propose policy-bounded remediation, require human approval for risky actions, execute safely in a controlled environment, verify the outcome, and produce a complete auditable record.

## Core design principle

> **The agent may reason. The control plane decides. The sandbox contains. Verification proves. AIMS records.**

---

# 38. Final PS03 Priority Order

For the hackathon, prioritize in this order:

### Priority 1 — Safety + Reliability

Because this directly represents 30% of the PS03 rubric.

### Priority 2 — Authentic Lyzr orchestration

Because this directly represents another 30% of the PS03 rubric.

### Priority 3 — End-to-end correctness

Triage → diagnosis → remediation → verification.

### Priority 4 — Evaluation evidence

Show measured performance rather than qualitative claims.

### Priority 5 — UX

Expose the incident state, evidence, decision, action and audit trail.

### Priority 6 — Stretch features

Only after the core workflow is stable.

---

# 39. Final Principle: Build Less, Prove More

The strongest submission is not necessarily the one with the most features.

It is the one that can prove:

```text
I can detect the incident.
I can ground my reasoning.
I can retrieve the right evidence.
I can avoid hallucinated actions.
I can enforce policy.
I can safely handle risky actions.
I can involve a human where needed.
I can execute in a controlled environment.
I can verify the result.
I can audit the entire flow.
I can measure my own reliability.
I can show the judge the evidence.
```

That is the standard we should use for every remaining PS03 design and implementation decision.

---

# 40. Source Notes

Current public challenge sources consulted:

- HiDevs / AI Quest public event information: AI Quest: Beyond the Wrapper. citeturn685655search0
- Unstop public competition listing: AI Quest: Beyond the Wrapper — 2026. citeturn685655search1

Source note:

The PS03-specific problem statement, MVP, stretch goals, repository structure, six checkpoints, and PS03 rubric in this document are also preserved from the challenge information supplied in this project by the participant. Where current public source access was incomplete, the document does not invent missing details.
