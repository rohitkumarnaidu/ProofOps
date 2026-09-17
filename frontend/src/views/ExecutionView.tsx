import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, probeMode, runsApi, type Mode, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import { StateDiff } from "../components/StateDiff";

/** View 4 — Execution/Verification (M19.5): FSM execution-phase timeline,
    audit-sourced execution evidence, rollback eligibility from run flags.
    No execution records yet = honest empty state (execution endpoints land
    with the M21 guard matrix; this view never invents diffs). */
export function ExecutionView() {
  const { id } = useParams<{ id: string }>();
  const [mode, setMode] = useState<Mode>("OFFLINE");
  const [run, setRun] = useState<RunView | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      setMode(await probeMode());
      if (id === undefined) return;
      try {
        setRun(await runsApi.get(id));
        setError("");
      } catch (err) {
        setRun(null);
        setError(err instanceof ApiError ? err.message : String(err));
      }
    }
    void load();
  }, [id]);

  const phaseHistory =
    run?.history.filter((h) =>
      ["EXECUTING", "VERIFYING", "ROLLBACK", "RESOLVED", "ESCALATED"].includes(
        h.to,
      ),
    ) ?? [];
  const rollbackEligible =
    run !== null &&
    (run.state === "VERIFYING" || run.state === "ROLLBACK") &&
    !run.rolled_back;
  const executions = (run?.audit_records ?? []).filter(
    (r) =>
      typeof r === "object" &&
      r !== null &&
      (r as Record<string, unknown>).type === "transition" &&
      ["EXECUTING", "VERIFYING", "ROLLBACK"].includes(
        String((r as Record<string, unknown>).to),
      ),
  );

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">Execution {id}</h1>
        <ModeBadge mode={mode} />
        {run !== null && (
          <span
            data-testid="exec-state"
            className="rounded bg-gray-800 px-2 py-0.5 text-xs font-bold"
          >
            {run.state}
          </span>
        )}
      </div>
      {error !== "" && (
        <p data-testid="exec-error" className="text-sm text-red-300">
          {error}
        </p>
      )}
      {run !== null && (
        <>
          <h2 className="mb-1 text-sm font-bold text-gray-300">
            Execution-phase timeline
          </h2>
          {phaseHistory.length === 0 ? (
            <p
              data-testid="exec-empty"
              className="mb-4 text-sm text-gray-400"
            >
              This run has not reached execution yet — approve its action in
              the Safety Gate first.
            </p>
          ) : (
            <ol data-testid="exec-timeline" className="mb-4 text-sm">
              {phaseHistory.map((h) => (
                <li key={h.seq} className="border-t border-gray-800 py-1">
                  <span className="text-gray-500">#{h.seq}</span> {h.frm} →{" "}
                  {h.to}
                  {h.forced && (
                    <span className="ml-2 rounded bg-red-900 px-1 text-xs">
                      forced
                    </span>
                  )}
                </li>
              ))}
            </ol>
          )}
          <h2 className="mb-1 text-sm font-bold text-gray-300">
            State diff
          </h2>
          <StateDiff diff={null} />
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">
            Rollback
          </h2>
          {rollbackEligible ? (
            <p data-testid="rollback-eligible" className="text-sm">
              Rollback eligible: one auto-rollback attempt available (control
              plane executes it — endpoint lands with M21).
            </p>
          ) : (
            <p data-testid="rollback-ineligible" className="text-sm text-gray-400">
              Rollback not available in state {run.state}
              {run.rolled_back ? " (already attempted once)" : ""}.
            </p>
          )}
          {executions.length > 0 && (
            <p className="mt-2 text-xs text-gray-500">
              {executions.length} execution-phase audit record(s) on file.
            </p>
          )}
        </>
      )}
    </div>
  );
}
