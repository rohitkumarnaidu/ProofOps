// Same-origin by default: nginx (compose) and the Vite dev server both proxy
// /api/ to the backend. The old hardcoded http://localhost:8000 was
// cross-origin from the browser on :5173, and the API ships no CORS middleware
// and answers no OPTIONS preflight (405), so every request failed.
//
// Falsy-check, NOT `??`. A Dockerfile ARG defaults to "", not undefined, so
// `?.trim() ?? "/api"` yields "" and every path silently loses its prefix. The
// SPA fallback then answers /runs with HTTP 200 + HTML, response.json() fails,
// the catch yields {}, and the run list does {}.map -> uncaught TypeError ->
// blank white screen. That shipped once and passed every source-grep test.
const configuredApiUrl = (import.meta.env.VITE_API_URL as string | undefined)?.trim();
const API_URL = configuredApiUrl ? configuredApiUrl : "/api";

// An unset key legitimately means "unauthenticated demo mode", so "" is the
// correct end state here; only trim-vs-raw matters.
const API_KEY =
  (import.meta.env.VITE_PROOFOPS_API_KEY as string | undefined)?.trim() ?? "";

export function apiBase(): string {
  return API_URL.replace(/\/+$/, "");
}

export function hasApiKey(): boolean {
  return API_KEY !== "";
}

export function apiKeyStateLabel(): string {
  return hasApiKey() ? "API key configured" : "unauthenticated demo mode";
}

export type Mode = "LIVE" | "REPLAY" | "MOCK" | "OFFLINE";

export class ApiError extends Error {
  status: number;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = typeof localStorage !== "undefined" ? localStorage.getItem("proofops_jwt_token") : null;
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  if (hasApiKey()) {
    headers["X-API-Key"] = API_KEY;
  }
  try {
    // apiBase(), not the raw API_URL: a configured base with a trailing slash
    // used to produce `https://host//runs` here while the stream URLs built
    // from apiBase() were correct. Two base normalisations cannot both be
    // right, so every path goes through the one that strips them.
    response = await fetch(`${apiBase()}${path}`, {
      ...init,
      headers: { ...headers, ...init?.headers },
    });
  } catch (error) {
    throw new ApiError(0, `backend unreachable: ${String(error)}`);
  }
  if (response.status === 204) return undefined as T;
  // Read the body as text first. `response.json().catch(() => ({}))` turned any
  // non-JSON 200 -- the SPA HTML fallback, a proxy error page, an empty body --
  // into a well-typed `{}`, and a caller doing `.filter`/`.map` on it then threw
  // an uncaught TypeError and blanked the screen. That exact failure shipped
  // once. A body we cannot parse is now a loud error, never a silent `{}`.
  const text = await response.text();
  let body: unknown;
  if (text.trim() !== "") {
    try {
      body = JSON.parse(text);
    } catch {
      if (response.ok) {
        throw new ApiError(
          response.status,
          `expected JSON from ${path} but got ${describeType(response, text)} -- ` +
            "the request probably hit the SPA fallback, not the API",
        );
      }
      body = {};
    }
  } else {
    body = {};
  }
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body
        ? String((body as Record<string, unknown>).detail)
        : `HTTP ${response.status}`;
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

/** Short, safe description of a non-JSON body. Never echoes the whole page. */
function describeType(response: Response, text: string): string {
  const contentType = response.headers.get("content-type") ?? "no content-type";
  const shape = text.trimStart().slice(0, 24).replace(/\s+/g, " ");
  return `${contentType} starting "${shape}"`;
}

export interface Healthz {
  status: string;
  service: string;
  spec: string;
}

/**
 * One real verifier verdict.
 *
 * Distinct from `verification_verdicts` on RunView, which is an FSM *transition*
 * projection. Folding one name over two shapes is what made the real evidence
 * unreachable: the panel titled "Verification verdicts" was rendering state
 * moves, and the checks the verifier actually ran were never shown.
 */
export interface VerificationResult {
  execution_id: string;
  /** RESOLVED | PARTIAL | FAILED | WORSENED | ROLLBACK_REQUIRED | ESCALATED */
  verdict: string;
  /** Per-check pass/fail as the independent verifier computed it. */
  checks: Record<string, boolean>;
  detail: string;
  at: number;
}

/** Sandbox state snapshot before/after an action, and the per-key delta. */
export interface StateDiff {
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  changed?: Record<string, { before: unknown; after: unknown }>;
}

export interface RunView {
  incident_id: string;
  state: string;
  replans: number;
  rolled_back: boolean;
  permit_pending: boolean;
  history: Array<{
    seq: number;
    frm: string;
    to: string;
    reason: string;
    refs: string[];
    forced: boolean;
    at: number;
  }>;
  handoffs: Array<Record<string, unknown>>;
  audit_records: Array<Record<string, unknown>>;
  /** FSM transitions whose target carries verification meaning. Projections. */
  verification_verdicts?: Array<{
    seq: number;
    frm: string;
    to: string;
    reason: string;
    refs: string[];
    at: number;
  }>;
  /** The independent verifier's own output. Always present (possibly empty). */
  verification_results: VerificationResult[];
  rollback?: { eligible: boolean; attempted: boolean };
  state_diff?: StateDiff | null;
  execution_logs?: string[];
  /** Real executor tier ("mock" | "docker" | "k8s"). "" when never executed. */
  execution_tier?: string;
  /** Present only on the sweep response: whether the sweep force-escalated. */
  escalated?: boolean;
}

export interface ApprovalView {
  approval_id: string;
  incident_id: string;
  action_id: string;
  actor: string;
  scope: string;
  params_hash: string;
  status: string;
  expires_at: string;
  seconds_remaining: number;
  identity_mode: string;
  requester_key_id: string;
  decided_by: string;
  sod: "enforced" | "not_enforced_bootstrap" | "not_recorded";
}

export interface ApprovalIssued {
  approval_id: string;
  token: string;
  status: string;
  expires_at: string;
  scope: string;
}

export interface IdentityView {
  key_id: string;
  owner: string;
  roles: string[];
  mode: "per_key" | "bootstrap";
  server_enforced: boolean;
}

export interface Meta {
  service: string;
  spec: string;
  executor_tier: string;
  mode: string;
  /** Whether the single-use nonce store behind the HITL token is durable. */
  nonce_store_durable: boolean;
  nonce_store_degraded: boolean;
}

function auditPath(incidentId: string): string {
  return `/incidents/${encodeURIComponent(incidentId)}/audit`;
}

export function fetchHealth(): Promise<Healthz> {
  return request<Healthz>("/healthz");
}

export async function probeMode(): Promise<Mode> {
  try {
    const meta = await request<Meta>("/meta");
    if (meta.executor_tier === "docker") return "LIVE";
    if (meta.executor_tier === "mock") return "MOCK";
    if (meta.executor_tier === "replay") return "REPLAY";
    return "OFFLINE";
  } catch {
    return "OFFLINE";
  }
}

export interface EngineStatus {
  database: {
    healthy: boolean;
    dialect: string;
    database: string;
    error: string | null;
    /**
     * True when persistence fell back to local sqlite. The backend reports
     * this deliberately: an operator reading "healthy" must be able to tell
     * that the audit trail is not in Postgres right now. Dropping this field
     * renders a degraded audit chain as a healthy green badge.
     */
    degraded: boolean;
    fallback_reason: string | null;
  };
  kubernetes: {
    connected: boolean;
    host: string | null;
    tier: string;
    version?: string | null;
    namespace?: string | null;
    error?: string | null;
  };
  prometheus: { connected: boolean; url: string; tier: string; error?: string | null };
  llm_hub: {
    provider: string;
    /**
     * Only "UNVERIFIED" and "OFFLINE" are ever returned. Typed as a closed
     * union on purpose: comparing against a value outside this set is how a
     * dead "LIVE" branch shipped while every real provider rendered as
     * "DETERMINISTIC".
     */
    status: "UNVERIFIED" | "OFFLINE";
    tier: string;
  };
}

export const metaApi = {
  meta: () => request<Meta>("/meta"),
  engines: () => request<EngineStatus>("/meta/engines"),
};

export const authApi = {
  login: async (apiKey: string) => {
    const res = await request<{ access_token: string; identity: IdentityView }>("/auth/token", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
    });
    if (typeof localStorage !== "undefined" && res.access_token) {
      localStorage.setItem("proofops_jwt_token", res.access_token);
    }
    return res;
  },
  logout: () => {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem("proofops_jwt_token");
    }
  },
};

export const identityApi = {
  view: () => request<IdentityView>("/identity"),
};

export const runsApi = {
  list: () =>
    request<Array<{ incident_id: string; state: string; history_len: number }>>(
      "/runs",
    ),
  create: (incidentId: string) =>
    request<RunView>("/runs", {
      method: "POST",
      body: JSON.stringify({ incident_id: incidentId }),
    }),
  get: (incidentId: string) =>
    request<RunView>(`/runs/${encodeURIComponent(incidentId)}`),
  /**
   * Force a stage/approval TTL sweep. This is what turns a stuck run into a
   * real ESCALATED instead of leaving it parked forever; without it an
   * AWAITING_APPROVAL run never leaves that state once its approval lapses.
   */
  sweep: (incidentId: string) =>
    request<RunView>(`/runs/${encodeURIComponent(incidentId)}/sweep`, {
      method: "POST",
    }),
  advance: (
    incidentId: string,
    to: string,
    opts?: { reason?: string; refs?: string[]; idempotency_key?: string },
  ) =>
    request<RunView>(`/runs/${encodeURIComponent(incidentId)}/advance`, {
      method: "POST",
      body: JSON.stringify({
        to,
        reason: opts?.reason ?? "",
        refs: opts?.refs ?? [],
        idempotency_key: opts?.idempotency_key ?? null,
      }),
    }),
};

/* -------------------------------------------------------------------------- */
/* Ingestion (the front door) + orchestrator control                           */
/* -------------------------------------------------------------------------- */

/**
 * The scenarios the backend has a pinned oracle + runbook for. Must match
 * `orchestrator.ORACLE`; the server rejects anything else with a 422 rather
 * than guessing, and that list is returned in the error detail.
 */
export const INGEST_SCENARIOS = [
  { id: "bad-deploy", label: "Bad deployment" },
  { id: "crashloop-oom", label: "CrashLoop / OOM" },
  { id: "db-exhaust", label: "DB connection exhaustion" },
  { id: "net-dep-fail", label: "Network / dependency failure" },
  { id: "injection", label: "Malicious log injection" },
] as const;

export type IngestScenario = (typeof INGEST_SCENARIOS)[number]["id"];

/** SLO threshold the backend compares the observed error rate against. */
export const DEFAULT_SLO_ERROR_RATE_BELOW = 0.01;

export interface IngestBody {
  incident_id: string;
  scenario: string;
  /** service/env/metrics/error_signature are all required by the server. */
  telemetry: {
    service: string;
    env: string;
    error_signature: string;
    metrics: Array<{ name: string; value: number }>;
    logs?: Array<Record<string, unknown>>;
    deploys?: Array<Record<string, unknown>>;
    slo?: Record<string, unknown>;
  };
  process?: boolean;
}

export interface IngestResult {
  accepted: boolean;
  processed: boolean;
  incident_id: string;
  mode?: string;
  /** Present on every branch; the server states plainly what it did. */
  detail: string;
}

/**
 * Submit a telemetry bundle. This is the ONLY route that drives the pipeline:
 * the orchestrator picks the incident up, runs real triage -> evidence ->
 * diagnosis -> plan -> policy, and (if policy says so) parks a proposal for
 * the Safety Gate. `POST /runs` merely opens an empty run in state NEW and
 * never moves it, so it is not a substitute for this.
 */
export const ingestApi = {
  submit: (body: IngestBody) =>
    request<IngestResult>("/alerts/ingest", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /** The kill-switch. Privileged: the server requires operator/approver/admin. */
  stop: () =>
    request<{ stopped: boolean; running: boolean; enabled: boolean }>(
      "/orchestrator/stop",
      { method: "POST" },
    ),
};

/* -------------------------------------------------------------------------- */
/* SLO alerting (GET /alerts)                                                  */
/* -------------------------------------------------------------------------- */

/**
 * One evaluated SLO alert from `GET /alerts`.
 *
 * Field names taken from `AlertState.to_dict`, not guessed: the wire shape is
 * `state` (not `status`) and `observed`/`target` (not `value`/`threshold`).
 * Guessing here produced a `.toUpperCase()` on undefined that crashed the
 * whole Command Center on render.
 */
export interface SloAlert {
  name: string;
  /** "ok" | "firing" -- the SLO's own evaluation, not an HTTP status. */
  state: string;
  metric: string;
  /** null when the counter is not wired yet, which is a real state. */
  observed: number | null;
  target: number | null;
  op: string;
  window: string;
  owner: string;
  severity: string;
  note: string;
}

export const sloApi = {
  alerts: async () => {
    const res = await request<{ alerts?: SloAlert[] }>("/alerts");
    return res.alerts ?? [];
  },
};

/**
 * An action the pipeline planned and parked for a human to decide on.
 *
 * In the default `approver_minted` delivery mode the backend mints NO token:
 * it parks the whole action server-side and the approver raises the request
 * themselves, so the token they spend is one they created. That makes this
 * endpoint mandatory for the HITL flow -- without it the Safety Gate has an
 * empty hand-written template, the request 422s, and every Approve/Deny button
 * stays permanently disabled.
 *
 * `risk_level` here is the POLICY-RECOMPUTED risk on the action that was
 * actually planned, not a UI guess.
 */
export interface ApprovalProposal {
  action_id: string;
  incident_id: string;
  action_type: string;
  /** GREEN | YELLOW | RED, as classified by the policy engine. */
  risk_level: string;
  runbook_id: string;
  parked_at: number;
  /** Whether an approver could still collect a held token. Never the token. */
  token_available: boolean;
  /** The complete action, which is what gets submitted back to raise approval. */
  action: Record<string, unknown>;
}

export const approvalsApi = {
  /**
   * Parked proposals across all incidents, for the Safety Gate to list.
   *
   * The server wraps the list in `{proposals: [...]}`, so this unwraps rather
   * than casting: treating the envelope as the array would make
   * `proposals.filter(...)` throw on a missing method, and `proposals.length`
   * would read the envelope's key count.
   */
  proposals: async () => {
    const res = await request<{ proposals?: ApprovalProposal[] }>("/approval-proposals");
    return res.proposals ?? [];
  },
  request: (action: Record<string, unknown>) =>
    request<ApprovalIssued>("/approvals", {
      method: "POST",
      body: JSON.stringify({ action }),
    }),
  view: (approvalId: string) =>
    request<ApprovalView>(`/approvals/${encodeURIComponent(approvalId)}`),
  /**
   * Collect a token the server is already holding for this approval, in the
   * delivery modes where the server mints it. Returns a view, never a token --
   * a token reaches the approver out of band, by design.
   */
  claimToken: (approvalId: string) =>
    request<ApprovalView>(`/approvals/${encodeURIComponent(approvalId)}/token`, {
      method: "POST",
    }),
  approve: (approvalId: string, token: string, idempotencyKey?: string) =>
    request<ApprovalView>(
      `/approvals/${encodeURIComponent(approvalId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify({
          token,
          idempotency_key: idempotencyKey ?? null,
        }),
      },
    ),
  reject: (
    approvalId: string,
    reason?: string,
    idempotencyKey?: string,
  ) =>
    request<ApprovalView>(
      `/approvals/${encodeURIComponent(approvalId)}/reject`,
      {
        method: "POST",
        body: JSON.stringify({
          reason: reason ?? "",
          idempotency_key: idempotencyKey ?? null,
        }),
      },
    ),
};

export interface AuditView {
  origin: string;
  incident_id: string;
  valid: boolean;
  checked: number;
  events: Array<Record<string, unknown>>;
}

/** Result of recomputing the whole hash chain. Tampering is detectable here. */
export interface AuditVerify {
  incident_id: string;
  valid: boolean;
  checked: number;
  /** Set when invalid: which sequence number first failed, and why. */
  first_bad_seq: number | null;
  reason: string;
}

export const auditApi = {
  view: (incidentId: string) => request<AuditView>(auditPath(incidentId)),
  pollUrl: (incidentId: string) => auditPath(incidentId),
  /**
   * Recompute every link and the ordering. `GET .../audit` reports a `valid`
   * flag but not WHERE it broke, so an invalid chain was undiagnosable in the
   * UI; this returns first_bad_seq + reason.
   */
  verify: (incidentId: string) =>
    request<AuditVerify>(`${auditPath(incidentId)}/verify`, { method: "POST" }),
  /** The exportable proof artifact, origin-labelled, with its own validity. */
  export: (incidentId: string) =>
    request<AuditView & { exported_at: string }>(`${auditPath(incidentId)}/export`),
};

/** One config's scored set: the run configuration, the sample size, the rates. */
export interface EvalCapture {
  config: {
    name: string;
    retrieval_mode: string;
    model_tier: string;
    predigest: boolean;
  };
  /** Sample size. Required on every gate card -- a rate without an n is noise. */
  n: number;
  pass_rate: number;
  gates_rate?: Record<string, number>;
}

export interface SmokeResult {
  system: string;
  /** The backend's own anti-overclaim statement. Render it; do not hide it. */
  note: string;
  cases: number;
  baseline: EvalCapture;
  optimized: EvalCapture;
  /** baseline/optimized config names, n as [base, opt], d_pass_rate, d_C1..d_C6. */
  delta: Record<string, number | string | [number, number]>;
  rubric: {
    lyzr_30: Record<string, number>;
    safety_30: Record<string, number>;
    code_20: Record<string, number | string[]>;
    ux_20: Record<string, number | string[]>;
    /** Each sub-score carries its own `subtotal`. */
    total_100: number;
    n: number;
  };
}

export const evalApi = {
  smoke: () =>
    request<SmokeResult>("/eval/smoke", {
      method: "POST",
      body: JSON.stringify({ confirm: true }),
    }),
};

/* -------------------------------------------------------------------------- */
/* Orchestrator (M19b real-time control plane)                                 */
/* -------------------------------------------------------------------------- */

export interface OrchestratorState {
  running: boolean;
  enabled: boolean;
  /** "scripted-oracle" unless a live Lyzr key is configured. */
  mode: string;
  auto_generate: boolean;
  submitted: number;
  processed: number;
  blocked: number;
  stalled: number;
  failed: number;
  duplicates_suppressed: number;
  last_incident: string;
  last_outcome: string;
  queue_depth: number;
  note: string;
}

/**
 * The worker's own state.
 *
 * Polled rather than streamed because it is one small object and the
 * interesting signal is a counter moving, not an event arriving. The Command
 * Center uses `submitted` as a cheap change-detector: when it moves, the run
 * list is re-fetched. That keeps the queue view live without continuously
 * polling the expensive endpoint or opening a stream per incident.
 */
export const orchestratorApi = {
  state: () => request<OrchestratorState>("/orchestrator"),
};

/**
 * The read-only agent surface.
 *
 * These are the only two agent routes the product exposes, and neither can
 * mutate anything. `proposed_action` comes back as data for a human to judge on
 * the Safety Gate -- there is no code path from an answer to an execution, and
 * the test suite asserts that the router mentions no mutation endpoint.
 */

/** A proposed action is a proposal. `requires_human_approval` is always true. */
export interface ProposedAction {
  action_type: string;
  parameters: Record<string, unknown>;
  risk_level: string;
  action_id: string;
  runbook_id: string;
  requires_human_approval: boolean;
}

export interface TraceStep {
  step: string;
  ms: number;
  [k: string]: unknown;
}

export interface Citation {
  claim: string;
  evidence_ids: string[];
}

export interface InvestigateReply {
  answer: string;
  citations: Citation[];
  trace: TraceStep[];
  proposed_action: ProposedAction | null;
  /** Always states the agent has no authority to act. */
  authority: string;
  /** `scripted-oracle` or `live-agent`. Never presented as the other. */
  reasoning_mode: string;
  verdict: string;
  evidence_ids: string[];
  severity?: string;
  incident_id?: string;
  session_id?: string;
}

/** One persisted turn. `session_id` is the incident id, by construction. */
export interface ThreadTurn {
  role: string;
  text: string;
  at: number;
  reasoning_mode?: string;
  verdict?: string;
  /** Always present: the backend serialises the full dataclass, and an
   * operator turn simply carries an empty list rather than omitting it. */
  trace: TraceStep[];
  citations?: Citation[];
  evidence_ids: string[];
  proposed_action?: ProposedAction | null;
}

export const agentsApi = {
  investigate: (body: { incident_id: string; question: string }) =>
    request<InvestigateReply>("/agents/investigate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /** Returns the persisted thread for an incident, oldest turn first. */
  thread: async (incidentId: string): Promise<ThreadTurn[]> => {
    const res = await request<{ turns: ThreadTurn[] }>(
      `/agents/${encodeURIComponent(incidentId)}/thread`,
    );
    return res.turns ?? [];
  },
};
