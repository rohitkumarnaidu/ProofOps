import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, probeMode, runsApi, type Mode } from "../api";
import { ModeBadge } from "../components/badges";

/** View 1 — Command Center (M19.2): live run queue, no fabricated rows.
    Empty backend = empty table with guidance. Unreachable = OFFLINE. */
export function CommandCenter() {
  const [mode, setMode] = useState<Mode>("OFFLINE");
  const [runs, setRuns] = useState<
    Array<{ incident_id: string; state: string; history_len: number }>
  >([]);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState("");
  const [newId, setNewId] = useState("");

  async function refresh() {
    setMode(await probeMode());
    try {
      setRuns(await runsApi.list());
      setError("");
    } catch (err) {
      setRuns([]);
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function create() {
    if (!newId.trim()) return;
    setCreating("");
    try {
      await runsApi.create(newId.trim());
      setNewId("");
      await refresh();
    } catch (err) {
      setCreating(err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">Command Center</h1>
        <ModeBadge mode={mode} />
      </div>
      {error !== "" && (
        <p data-testid="queue-error" className="mb-3 text-sm text-red-300">
          Queue unavailable: {error}
        </p>
      )}
      <div className="mb-4 flex gap-2">
        <input
          aria-label="New incident id"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          placeholder="incident id (e.g. inc-1)"
          className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
        />
        <button
          onClick={() => void create()}
          className="rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600"
        >
          Open run
        </button>
        {creating !== "" && (
          <span className="text-sm text-red-300">{creating}</span>
        )}
      </div>
      {runs.length === 0 ? (
        <p data-testid="queue-empty" className="text-sm text-gray-400">
          No open runs. Create one above, or seed the demo backend first.
        </p>
      ) : (
        <table data-testid="queue-table" className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400">
              <th className="py-1">Incident</th>
              <th>State</th>
              <th>Transitions</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.incident_id} className="border-t border-gray-800">
                <td className="py-1">
                  <Link
                    to={`/incidents/${run.incident_id}`}
                    className="text-sky-300 underline"
                  >
                    {run.incident_id}
                  </Link>
                </td>
                <td>{run.state}</td>
                <td>{run.history_len}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
