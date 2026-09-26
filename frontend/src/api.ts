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
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { ...headers, ...init?.headers },
    });
  } catch (error) {
    throw new ApiError(0, `backend unreachable: ${String(error)}`);
  }
  const body = (await response.json().catch(() => ({}))) as unknown;
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body
        ? String((body as Record<string, unknown>).detail)
        : `HTTP ${response.status}`;
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

export interface Healthz {
  status: string;
  service: string;
  spec: string;
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
  verification_verdicts?: Array<{
    seq: number;
    frm: string;
    to: string;
    reason: string;
    refs: string[];
    at: number;
  }>;
  rollback?: { eligible: boolean; attempted: boolean };
  state_diff?: {
    before?: Record<string, unknown>;
    after?: Record<string, unknown>;
    changed?: Record<string, { before: unknown; after: unknown }>;
  } | null;
  execution_logs?: string[];
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
  database: { healthy: boolean; dialect: string; database: string; error: string | null };
  kubernetes: { connected: boolean; host: string | null; tier: string };
  prometheus: { connected: boolean; url: string; tier: string };
  llm_hub: { provider: string; status: string; tier: string };
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

export const approvalsApi = {
  request: (action: Record<string, unknown>) =>
    request<ApprovalIssued>("/approvals", {
      method: "POST",
      body: JSON.stringify({ action }),
    }),
  view: (approvalId: string) =>
    request<ApprovalView>(`/approvals/${encodeURIComponent(approvalId)}`),
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

export const auditApi = {
  view: (incidentId: string) => request<AuditView>(auditPath(incidentId)),
  pollUrl: (incidentId: string) => auditPath(incidentId),
};

export interface SmokeResult {
  system: string;
  note: string;
  cases: number;
  baseline: {
    n: number;
    pass_rate: number;
    gates_rate?: Record<string, number>;
  };
  optimized: {
    n: number;
    pass_rate: number;
    gates_rate?: Record<string, number>;
  };
  delta: Record<string, number | string | [number, number]>;
  rubric: {
    lyzr_30: Record<string, number>;
    safety_30: Record<string, number>;
    code_20: Record<string, number | string[]>;
    ux_20: Record<string, number | string[]>;
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
