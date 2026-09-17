import { useEffect, useState } from "react";
import {
  ApiError,
  approvalsApi,
  probeMode,
  type ApprovalView,
  type Mode,
} from "../api";
import { ModeBadge } from "../components/badges";

const EMPTY_ACTION = JSON.stringify(
  {
    incident_id: "inc-1",
    agent_id: "planner",
    action_type: "rollback_deployment",
    resource_type: "deployment",
    resource_id: "web",
    environment: "mock",
    parameters: { to_version: "v22" },
    reason: "Roll back web to v22.",
    evidence_ids: ["ev-1"],
    runbook_id: "bad-deploy-rollback",
    runbook_version: "1.2.0",
    expected_outcome: "Spike clears.",
    verification_plan: ["deployment_version_expected"],
    rollback_action: { action_type: "rollback_deployment" },
  },
  null,
  2,
);

/** View 3 — Safety Gate (M19.4): request + approve/deny + TTL countdown.
    Every field server-verified; client state never authorizes anything. */
export function SafetyGate() {
  const [mode, setMode] = useState<Mode>("OFFLINE");
  const [actionText, setActionText] = useState(EMPTY_ACTION);
  const [actor, setActor] = useState("sre-1");
  const [role, setRole] = useState("approver");
  const [issued, setIssued] = useState<{
    approval_id: string;
    token: string;
  } | null>(null);
  const [view, setView] = useState<ApprovalView | null>(null);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    void probeMode().then(setMode);
  }, []);

  useEffect(() => {
    if (view === null || view.status !== "pending") return;
    const timer = setInterval(() => {
      approvalsApi
        .view(view.approval_id)
        .then(setView)
        .catch(() => undefined);
    }, 5000);
    return () => clearInterval(timer);
  }, [view?.approval_id, view?.status]);

  async function request() {
    setError("");
    try {
      const action = JSON.parse(actionText) as Record<string, unknown>;
      const out = await approvalsApi.request(action, actor);
      setIssued({ approval_id: out.approval_id, token: out.token });
      setToken(out.token);
      setView(await approvalsApi.view(out.approval_id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function decide(kind: "approve" | "reject") {
    if (view === null) return;
    setError("");
    try {
      const next =
        kind === "approve"
          ? await approvalsApi.approve(
              view.approval_id,
              actor,
              token,
              role,
            )
          : await approvalsApi.reject(view.approval_id, actor, role);
      setView(next);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">Safety Gate</h1>
        <ModeBadge mode={mode} />
      </div>
      {error !== "" && (
        <p data-testid="gate-error" className="mb-3 text-sm text-red-300">
          {error}
        </p>
      )}
      <div className="grid gap-6 md:grid-cols-2">
        <div>
          <h2 className="mb-1 text-sm font-bold text-gray-300">
            1. Request approval (action JSON, server-validated)
          </h2>
          <textarea
            aria-label="Action JSON"
            value={actionText}
            onChange={(e) => setActionText(e.target.value)}
            rows={14}
            spellCheck={false}
            className="w-full rounded border border-gray-700 bg-gray-900 p-2 font-mono text-xs"
          />
          <div className="mt-2 flex gap-2">
            <input
              aria-label="Requesting actor"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
            />
            <button
              onClick={() => void request()}
              className="rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600"
            >
              Request
            </button>
          </div>
          {issued !== null && (
            <p data-testid="issued-token" className="mt-2 text-xs text-gray-400">
              approval_id: {issued.approval_id} · token issued (paste below to
              approve)
            </p>
          )}
        </div>
        <div>
          <h2 className="mb-1 text-sm font-bold text-gray-300">
            2. Decide (approver role + token required)
          </h2>
          {view === null ? (
            <p className="text-sm text-gray-400">
              No approval loaded. Request one on the left first.
            </p>
          ) : (
            <div data-testid="approval-card" className="text-sm">
              <p>
                Status: <strong>{view.status}</strong> · TTL countdown:{" "}
                <span data-testid="ttl-countdown">
                  {Math.max(0, Math.round(view.seconds_remaining))}s remaining
                </span>
              </p>
              <p className="text-gray-400">Scope: {view.scope}</p>
              <p className="text-gray-400">
                Params hash: {view.params_hash}
              </p>
              <p className="text-gray-400">
                Expires: {view.expires_at}
              </p>
              <div className="mt-2 flex flex-col gap-2">
                <input
                  aria-label="Approval token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="paste issued token"
                  className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
                />
                <select
                  aria-label="Role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
                >
                  <option value="approver">approver</option>
                  <option value="admin">admin</option>
                  <option value="viewer">viewer</option>
                </select>
                <div className="flex gap-2">
                  <button
                    onClick={() => void decide("approve")}
                    className="rounded bg-green-700 px-3 py-1 text-sm font-bold hover:bg-green-600"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => void decide("reject")}
                    className="rounded bg-red-700 px-3 py-1 text-sm font-bold hover:bg-red-600"
                  >
                    Deny
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
