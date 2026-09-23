/* ProofOps API layer (M19a): typed fetchers over real backend routes.
   No mock data anywhere: unreachable backend surfaces as OFFLINE, never
   as fabricated incidents. */

const API_URL =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  "http://localhost:8000";

/** Backend base URL for non-fetch consumers (the SSE subscriber builds its
    stream URL from the same source the fetchers use). */
export function apiBase(): string {
  return API_URL;
}

/* Auth (M21b demo-key gate): empty = unauthenticated demo mode. Mutating
   calls without a key fail closed server-side (401); nothing here authorizes
   anything — the key is only attached so the server can verify it. */
const API_KEY =
  (import.meta.env.VITE_PROOFOPS_API_KEY as string | undefined)?.trim() ?? "";

/** True when an API key is configured; false = unauthenticated demo mode. */
export function hasApiKey(): boolean {
  return API_KEY !== "";
}

export type Mode = "LIVE" | "REPLAY" | "MOCK" | "OFFLINE";

export class ApiError extends Error {
  status: number;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (hasApiKey()) {
    headers["X-API-Key"] = API_KEY;
  }
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { ...headers, ...init?.headers },
    });
  } catch (err) {
    throw new ApiError(0, `backend unreachable: ${String(err)}`);
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
}

export interface ApprovalIssued {
  approval_id: string;
  token: string;
  status: string;
  expires_at: string;
  scope: string;
}

export interface Meta {
  service: string;
  spec: string;
  executor_tier: string;
  mode: string;
}

/** Liveness probe (kept for diagnostics; mode display uses probeMode). */
export function fetchHealth(): Promise<Healthz> {
  return request<Healthz>("/healthz");
}

/** Backend reachability + tier probe (tier-aware): GET /meta and map the
    server-reported executor_tier — "mock"→MOCK, "docker"→LIVE (docker tier
    is real execution), explicit "replay"→REPLAY if a backend ever reports
    it. Unreachable backend, or any unrecognized tier, → OFFLINE. NEVER
    reports LIVE unless the backend confirms a real execution tier. */
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

export const runsApi = {
  list: () =>
    request<Array<{ incident_id: string; state: string; history_len: number }>>(
      "/runs",
    ),
  create: (incident_id: string) =>
    request<RunView>("/runs", {
      method: "POST",
      body: JSON.stringify({ incident_id }),
    }),
  get: (incident_id: string) => request<RunView>(`/runs/${incident_id}`),
  advance: (
    incident_id: string,
    to: string,
    opts?: { reason?: string; refs?: string[]; idempotency_key?: string },
  ) =>
    request<RunView>(`/runs/${incident_id}/advance`, {
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
  request: (action: Record<string, unknown>, actor: string) =>
    request<ApprovalIssued>("/approvals", {
      method: "POST",
      body: JSON.stringify({ action, actor }),
    }),
  view: (approval_id: string) =>
    request<ApprovalView>(`/approvals/${approval_id}`),
  approve: (
    approval_id: string,
    actor: string,
    token: string,
    role: string,
    idempotency_key?: string,
  ) =>
    request<ApprovalView>(`/approvals/${approval_id}/approve`, {
      method: "POST",
      body: JSON.stringify({
        actor,
        token,
        role,
        idempotency_key: idempotency_key ?? null,
      }),
    }),
  reject: (
    approval_id: string,
    actor: string,
    role: string,
    reason?: string,
  ) =>
    request<ApprovalView>(`/approvals/${approval_id}/reject`, {
      method: "POST",
      body: JSON.stringify({ actor, role, reason: reason ?? "" }),
    }),
};

export const auditApi = {
  view: (incident_id: string) =>
    request<{
      origin: string;
      valid: boolean;
      checked: number;
      events: Array<Record<string, unknown>>;
    }>(`/incidents/${incident_id}/audit`),
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
