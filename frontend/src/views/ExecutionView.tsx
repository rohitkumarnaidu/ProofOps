import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import { StateDiff } from "../components/StateDiff";
import { useMode } from "../components/useMode";

/** View 4 — Execution/Verification (M19.5): FSM execution-phase timeline,
    audit-sourced execution evidence, rollback eligibility from run flags.
    Mutating endpoints sit behind the M21 key matrix; this view is read-only.
    No execution records yet = honest empty state (never invents diffs). */
export function ExecutionView() {
  const { id } = useParams<{ id: string }>();
  const mode = useMode(id);
  const [run, setRun] = useState<RunView | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
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
        {mode === null && (
          <span
            data-testid="mode-probing"
            aria-busy="true"
            className="text-xs text-gray-500"
          >
            probing backend…
          </span>
        )}
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
          {/* run_view carries no state snapshot: null is the genuine
              no-snapshot case — diff rows are never invented here. */}
          <StateDiff diff={null} />
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">
            Rollback
          </h2>
          {rollbackEligible ? (
            <p data-testid="rollback-eligible" className="text-sm">
              Rollback eligible: the control plane auto-executes one rollback
              attempt on verification failure (this view is read-only — it
              never triggers execution itself).
            </p>
          ) : (
            <p data-testid="rollback-ineligible" className="text-sm text-gray-400">
              Rollback not available in state {run.state}
              {run.rolled_back ? " (already attempted once)" : ""}.
            </p>
          )}
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">
            Execution records ({executions.length}, audit-sourced)
          </h2>
          {executions.length === 0 ? (
            <p data-testid="exec-records-empty" className="mb-4 text-sm text-gray-400">
              No execution-phase audit records on file yet.
            </p>
          ) : (
            <ol data-testid="exec-records" className="mb-4 text-sm">
              {executions.map((record, index) => {
                const seq =
                  typeof record.seq === "number" ? record.seq : null;
                const frm =
                  typeof record.frm === "string" ? record.frm : "?";
                const to = typeof record.to === "string" ? record.to : "?";
                const reason =
                  typeof record.reason === "string" ? record.reason : "";
                const refs = Array.isArray(record.refs)
                  ? record.refs.filter(
                      (r: unknown): r is string => typeof r === "string",
                    )
                  : [];
                return (
                  <li
                    key={seq ?? `row-${String(index)}`}
                    className="border-t border-gray-800 py-1"
                  >
                    <span className="text-gray-500">#{seq ?? "—"}</span>{" "}
                    {frm} → {to}
                    {reason !== "" && (
                      <span className="text-gray-400"> — {reason}</span>
                    )}
                    {refs.length > 0 && (
                      <span className="ml-2">
                        {refs.map((ref) => (
                          <span
                            key={ref}
                            className="mr-1 rounded bg-gray-800 px-1 text-xs text-sky-300"
                          >
                            {ref}
                          </span>
                        ))}
                      </span>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
        </>
      )}
    </div>
  );
}
