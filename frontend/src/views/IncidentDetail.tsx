import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, probeMode, runsApi, type Mode, type RunView } from "../api";
import { ModeBadge } from "../components/badges";

/** View 2 — Incident Detail, part 1 (M19.3): live timeline + run state.
    Evidence-chip drill-down lands in commit B with the audit viewer. */
export function IncidentDetail() {
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

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">Incident {id}</h1>
        <ModeBadge mode={mode} />
        {run !== null && (
          <span
            data-testid="run-state"
            className="rounded bg-gray-800 px-2 py-0.5 text-xs font-bold"
          >
            {run.state}
          </span>
        )}
      </div>
      {error !== "" && (
        <p data-testid="detail-error" className="text-sm text-red-300">
          {error}
        </p>
      )}
      {run !== null && (
        <>
          <p className="mb-2 text-sm text-gray-400">
            Re-plans: {run.replans} · Rolled back:{" "}
            {run.rolled_back ? "yes" : "no"} · Permit pending:{" "}
            {run.permit_pending ? "yes" : "no"}
          </p>
          <h2 className="mb-1 text-sm font-bold text-gray-300">Timeline</h2>
          {run.history.length === 0 ? (
            <p className="text-sm text-gray-400">
              No transitions yet — advance this run from the API.
            </p>
          ) : (
            <ol data-testid="timeline" className="text-sm">
              {run.history.map((h) => (
                <li key={h.seq} className="border-t border-gray-800 py-1">
                  <span className="text-gray-500">#{h.seq}</span> {h.frm} →{" "}
                  {h.to}
                  {h.reason !== "" && (
                    <span className="text-gray-400"> — {h.reason}</span>
                  )}
                  {h.forced && (
                    <span className="ml-2 rounded bg-red-900 px-1 text-xs">
                      forced
                    </span>
                  )}
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </div>
  );
}
