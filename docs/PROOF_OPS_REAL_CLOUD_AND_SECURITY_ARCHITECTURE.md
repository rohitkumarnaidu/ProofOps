# ProofOps: Enterprise Cloud Integration, Zero-Trust Security & Control Plane Architecture

**AI Quest 2026 · PS03 — Enterprise Cloud Incident Triage & Runbook Remediation Agent**  
*Motto: "The Agent May Reason. The Control Plane Decides. The Sandbox Contains. Verification Proves. AIMS Records."*

---

## 1. Executive Summary & Core Principle

ProofOps is not a decorative chatbot or a prompt wrapper over raw shell scripts. It is a **deterministic agentic control plane** designed for mission-critical cloud infrastructure.

```
       UNTRUSTED DATA                                         DETERMINISTIC TRUST BOUNDARY
+----------------------------+        +-----------------------------------------------------------+
| Alertmanager / Datadog     |        | 1. Webhook Adapter & Ingestion Validator                  |
| CloudWatch / PagerDuty     | ------>| 2. Deterministic Pre-Digestion (Evidence Pack <= 6k tok)  |
+----------------------------+        +-----------------------------------------------------------+
                                                                    |
                                                                    v
+----------------------------+                     +---------------------------------+
|   4 Lyzr AI Workforce      |<------------------->| LLM Hub (Lyzr / OpenAI / Anth)  |
| A1 Triage -> A2 Diagnostic |                     +---------------------------------+
| A3 Planner -> A4 Postmortem|                                      |
+----------------------------+                                      v
                                                   +---------------------------------+
                                                   | Deterministic Policy Engine     |
                                                   | (/policies/bundle_v1.yaml)      |
                                                   +---------------------------------+
                                                                    |
                                                                    v
                                                   +---------------------------------+
                                                   | Cryptographic HITL Safety Gate  |
                                                   | (HMAC-SHA256 Token + Nonce Burn)|
                                                   +---------------------------------+
                                                                    |
                                                                    v
+----------------------------+                     +---------------------------------+
| Live Cloud Infrastructure  |<--------------------| Kubernetes Executor (M08)       |
| EKS / GKE / AKS via IRSA   |                     | Prometheus PromQL Verifier (M09)|
+----------------------------+                     +---------------------------------+
```

> **THE NON-NEGOTIABLE CORE INVARIANT:**  
> **The LLM is NEVER the security boundary.** The agent may reason over evidence, hypothesize root causes, and propose parameter values. Only the deterministic control plane decides whether an action is authorized, valid, and safe to execute.

---

## 2. Connecting ProofOps to Real Cloud Applications

ProofOps natively interfaces with cloud-native infrastructure across AWS, GCP, Azure, and on-premises Kubernetes.

### 2.1 Kubernetes Cluster Connectivity (`backend/app/services/k8s_executor.py`)

ProofOps uses the official Kubernetes Python API client and automatically discovers authentication context through standard enterprise patterns:

```
+-----------------------------------------------------------------------------------+
|                            KUBERNETES EXECUTOR (M08)                              |
+-----------------------------------------------------------------------------------+
|  AWS EKS:              IRSA (IAM Roles for Service Accounts) / EKS Pod Identity   |
|  GCP GKE:              GCP Workload Identity Federation                           |
|  Azure AKS:            Azure Workload Identity (Federated Identity Credentials)   |
|  Off-Cluster / Bastion: ~/.kube/config or $KUBECONFIG with mTLS Certificates      |
+-----------------------------------------------------------------------------------+
```

#### How Authentication Works Under the Hood
1. **In-Cluster Auto-Discovery (`config.load_incluster_config()`):**
   - ProofOps reads the projected service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token` and the cluster CA certificate from `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
   - On AWS EKS, this token is exchanged with AWS STS for IAM permissions specified in the ServiceAccount annotation:
     ```yaml
     eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/ProofOpsIncidentCommanderRole"
     ```
   - On GCP GKE, the token is exchanged with Google Cloud IAM via Workload Identity:
     ```yaml
     iam.gke.io/gcp-service-account: "proofops-sa@project-id.iam.gserviceaccount.com"
     ```
2. **External Cluster Access (`config.load_kube_config(config_file=...)`):**
   - Supports local development, Kind/Minikube clusters, and cross-account multi-cluster control planes using custom kubeconfig files.

#### Safe, Governed Mutations
When an authorized action is dispatched, ProofOps performs controlled Kubernetes API calls:
- **Rollout Restart:** Patches the deployment pod template annotation `kubectl.kubernetes.io/restartedAt` with an ISO-8601 UTC timestamp, triggering a graceful Kubernetes zero-downtime rolling restart.
- **Rollback Deployment:** Patches the deployment with the target image tag and records the rollback annotation `proofops.io/rolled-back-to: <revision>`.
- **Bounded Horizontal Scaling:** Modifies `deployment.spec.replicas` within policy-enforced blast radius bounds ($\Delta \le 2$).
- **StateDiff Extraction:** Queries deployment observables before and after execution, generating an exact JSON diff (`before_state` vs `after_state`) for the operator and audit log.

---

## 3. Real Cloud Telemetry & Alert Webhooks (`backend/app/routers/webhooks.py`)

ProofOps features native inbound webhook adapters for all major cloud observability backends:

| Observability Backend | Endpoint | Native Payload Parsed | Auto-Detected Scenarios |
| :--- | :--- | :--- | :--- |
| **Prometheus Alertmanager** | `POST /alerts/webhook/alertmanager` | Alert labels, annotations, firing count, startsAt | CrashLoopBackOff, OOMKilled, High Error Rate |
| **Datadog** | `POST /alerts/webhook/datadog` | `event_title`, `body`, tags (`env:prod`, `service:api`) | Database pool exhaustion, Slow query spike |
| **AWS CloudWatch / SNS** | `POST /alerts/webhook/cloudwatch` | SNS JSON envelope, AlarmName, Reason, Dimensions | Upstream network timeout, 5xx threshold breach |
| **PagerDuty v2** | `POST /alerts/webhook/pagerduty` | `incident.triggered`, urgency, service summary | Production outage, bad deployment rollback |

### Ingestion Flow & Deduplication
1. **Normalization:** The raw webhook payload is converted into a standardized `NormalizedAlert` containing service name, environment, error signature, and metric values.
2. **Deterministic Fingerprinting:** Computes `sha256(service + error_signature + env + deploy_window)` to correlate incoming alerts within a 15-minute sliding window.
3. **Deduplication:** Repeated alerts within a 5-second burst are deduplicated, preventing alert storms and keeping the Merkle audit chain clean.
4. **Orchestrator Submission:** The normalized incident is queued in `ORCHESTRATOR.submit(incident_id, scenario, telemetry)`.

---

## 4. Independent Prometheus PromQL Verification (`backend/app/services/prom_verifier.py`)

ProofOps strictly rejects the naive assumption that an exit status of 0 means the problem is solved.

$$ \text{EXIT CODE } 0 \ne \text{RESOLVED} $$

### The Verification Engine
ProofOps executes independent PromQL queries against the live Prometheus HTTP API (`/api/v1/query`):

1. **5xx Error Rate:**
   ```promql
   sum(rate(http_requests_total{status=~"5..", service="payment-service"}[2m])) 
   / 
   sum(rate(http_requests_total{service="payment-service"}[2m]))
   ```
   Must drop strictly below the Service Level Objective (SLO): $E_{\text{obs}} < 0.01$.

2. **Pod Availability:**
   ```promql
   kube_deployment_status_replicas_available{deployment=~".*payment-service.*"} > 0
   ```

3. **CrashLoop / OOMKilled Termination:**
   ```promql
   sum(kube_pod_container_status_last_terminated_reason{reason="OOMKilled", pod=~".*payment-service.*"}) == 0
   ```

### Deterministic Verdicts & Auto-Rollback
- **`RESOLVED`**: All SLO checks pass $\implies$ proceed to RCA and audit.
- **`PARTIAL`**: Pods are running but error rate is still above target $\implies$ flag for human escalation.
- **`FAILED` or `WORSENED`**: Error rate increased $\implies$ trigger immediate automated rollback to `to_version` and re-verify.

---

## 5. End-to-End Enterprise Security Architecture

```
                                  ZERO-TRUST SECURITY MODEL
+---------------------------------------------------------------------------------------------------+
| 1. IDENTITY & RBAC:   JWT Bearer Authentication (/auth/token) with roles:                         |
|                       ['admin', 'incident_commander', 'sre_lead', 'operator', 'viewer']          |
+---------------------------------------------------------------------------------------------------+
| 2. ACTION TIERS:      GREEN  -> Low-risk read/describe actions (auto-executed)                   |
|                       YELLOW -> Reversible mutations (requires single-use HMAC token)             |
|                       RED    -> Destructive actions (strictly BLOCKED in hackathon/demo mode)     |
+---------------------------------------------------------------------------------------------------+
| 3. HITL CRYPTO TOKEN: HMAC-SHA256 signature binding:                                              |
|                       sha256(action_id + sha256(parameters) + actor + role + expiry + nonce)      |
+---------------------------------------------------------------------------------------------------+
| 4. ANTI-REPLAY:       Durable Nonce Store & Burn. Replayed tokens fail with 409 Conflict.         |
+---------------------------------------------------------------------------------------------------+
| 5. AUDIT INTEGRITY:   SHA-256 Merkle Hash-Chained Ledger. Tampering mathematically detectable.     |
+---------------------------------------------------------------------------------------------------+
```

### 5.1 Action Risk Classification & Deterministic Policy
All actions proposed by the LLM Planner are evaluated by the deterministic Policy Engine (`backend/app/services/policy.py`) against `/policies/bundle_v1.yaml`:

- **GREEN (Read-Only):** `read`, `describe`, `logs`, `metrics`, `list`. Auto-executed without human approval.
- **YELLOW (Reversible Mutation):** `rolling_restart`, `rollback_deployment`, `scale_deployment` ($\Delta \le 2$). Allowed ONLY when accompanied by a valid, single-use cryptographic approval token.
- **RED (Destructive):** `delete_namespace`, `delete_deployment`, `drop_database`, `exec_shell`, `reboot_node`. **Unconditionally blocked in hackathon/demo mode.** No break-glass bypass exists.

### 5.2 Single-Use HMAC-SHA256 Approval Tokens (`backend/app/services/approval.py`)
Human-in-the-Loop approvals are mathematically secured:
1. **Parameter Hash Binding:**
   $$\text{param\_hash} = \text{SHA256}(\text{canonical\_json}(\text{parameters}))$$
   If an operator approves scaling to 2 replicas, an attacker cannot modify the request to scale to 200 replicas because the signature check will fail.
2. **Anti-Replay Nonce Store & Burn:**
   Every approval request is issued a cryptographic 128-bit UUID nonce. When the action executes, the nonce is stored in the persistent database and burned. Replay attempts immediately return `409 Conflict`.
3. **Time-to-Live (TTL):**
   Tokens expire after 10 minutes (15 minutes in demo mode). Expired tokens fail closed.

### 5.3 SHA-256 Merkle Audit Chain (`backend/app/services/audit.py`)
Every state transition, policy check, operator approval, cluster mutation, and PromQL verification is appended to a cryptographic hash chain:

$$ H_n = \text{SHA256}(H_{n-1} \,\|\, T_n \,\|\, \text{Event}_n \,\|\, \text{Payload}_n) $$

Any modification to a past event invalidates the hash chain downstream and is caught by `GET /audit/verify`.

---

## 6. Real-Time Backend & Frontend Control Loop

The frontend cockpit is a real-time reactive workstation built with React, Vite, and Tailwind CSS.

### 6.1 The 14-State Canonical FSM
```
NEW -> TRIAGING -> CORRELATED -> INVESTIGATING -> DIAGNOSING -> PLANNED ->
POLICY_CHECK -> [BLOCKED | AWAITING_APPROVAL | APPROVED] -> EXECUTING ->
VERIFYING -> [RESOLVED | ROLLBACK | ESCALATED] -> RCA_PENDING ->
RCA_PUBLISHED -> AUDITED
```

### 6.2 Real-Time SSE Streaming (`/runs/{incident_id}/stream`)
- **Resilient Transport:** Frontend establishes a persistent Server-Sent Events (SSE) connection.
- **State Synchronization:** Receives state changes, agent logs, and audit events in real-time.
- **Degraded Network Fallback:** If the SSE socket disconnects, the frontend automatically falls back to 3-second HTTP polling while attempting exponential backoff reconnection.

### 6.3 The 5 Core MVP Views
1. **Command Center:** Real-time incident queue, P1–P4 severity chips, 14-state status badges, MTTR boards, active cluster engines indicator.
2. **Incident Detail:** Interactive causal timeline, evidence chips linking directly to raw telemetry logs, competing diagnostic hypotheses with confidence scores, pinned runbook spec.
3. **Safety Gate:** Interactive authorization modal displaying exact action parameters, advisory vs effective policy risk, blast radius, policy rule citation, parameter hash, and live TTL countdown timer.
4. **Execution / Verification:** Live streaming log terminal, syntax-highlighted Before/After StateDiff, independent Prometheus SLO checks, auto-rollback trigger.
5. **RCA / Postmortem:** Blameless postmortem document, MUST-CITE evidence validation table, cryptographic Merkle audit block explorer with integrity badge.

---

## 7. Cloud-Native Production Deployment (`deploy/k8s/`)

The repository includes production Kubernetes deployment manifests:

```
deploy/k8s/
├── 00-namespace.yaml          # Namespace with Pod Security Standards (Restricted)
├── 01-rbac.yaml               # ServiceAccount with EKS IRSA / GKE / AKS annotations
├── 02-configmap-secrets.yaml  # ConfigMap & Secret templates (HMAC, JWT, DB, Lyzr)
├── 03-network-policy.yaml     # Zero-trust NetworkPolicy (blocks lateral movement)
├── 04-deployment.yaml         # Hardened API & UI Deployments (non-root UID 10001, drop ALL)
└── 05-service-ingress.yaml    # ClusterIP Services and TLS Ingress (SSE timeout tuned)
```

### Pod Hardening Standards Applied
- `runAsNonRoot: true` with non-privileged UID `10001`
- `readOnlyRootFilesystem: true` with ephemeral `/tmp` and `/app/var` volume mounts
- `capabilities: drop: ["ALL"]`
- `allowPrivilegeEscalation: false`
- `seccompProfile: type: RuntimeDefault`
- Liveness and readiness HTTP probes on `/healthz` and `/readyz`
- Bounded CPU and memory requests/limits
