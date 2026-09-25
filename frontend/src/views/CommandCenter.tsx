import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, runsApi } from "../api";
import { ModeBadge } from "../components/badges";
import { useMode } from "../components/useMode";

export function CommandCenter() {
  const mode = useMode();
  const [runs, setRuns] = useState<
    Array<{ incident_id: string; state: string; history_len: number }>
  >([]);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [creating, setCreating] = useState("");
  const [newId, setNewId] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  async function refresh() {
    setIsLoading(true);
    try {
      setRuns(await runsApi.list());
      setError("");
      setErrorStatus(null);
    } catch (caught) {
      setRuns([]);
      setError(caught instanceof ApiError ? caught.message : String(caught));
      setErrorStatus(caught instanceof ApiError ? caught.status : 0);
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function create() {
    const incidentId = newId.trim();
    if (incidentId === "") return;
    setCreating("");
    try {
      await runsApi.create(incidentId);
      setNewId("");
      await refresh();
    } catch (caught) {
      setCreating(caught instanceof ApiError ? caught.message : String(caught));
    }
  }

  const hasVisibleError = error !== "" || creating !== "";

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold">
          Command Center
        </h1>
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
      </div>
      {error !== "" && (
        <div role="alert" data-testid="queue-error" className="mb-3 text-sm text-red-300">
          <p>
            {errorStatus === 404
              ? "Run queue not found. "
              : "Queue unavailable. "}
            {error}
          </p>
        </div>
      )}
      <div className="mb-4 flex flex-wrap items-end gap-2">
        <div>
          <label htmlFor="new-incident" className="mb-1 block text-xs text-gray-300">
            New incident id
          </label>
          <input
            id="new-incident"
            value={newId}
            onChange={(event) => setNewId(event.target.value)}
            placeholder="incident id"
            className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
          />
        </div>
        <button
          type="button"
          onClick={() => void create()}
          disabled={newId.trim() === ""}
          className="rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Open run
        </button>
      </div>
      {creating !== "" && (
        <p role="alert" className="mb-3 text-sm text-red-300">
          Run creation failed: {creating}
        </p>
      )}
      {isLoading ? (
        <p
          data-testid="queue-loading"
          aria-busy="true"
          className="text-sm text-gray-400"
        >
          Loading runs…
        </p>
      ) : hasVisibleError ? null : runs.length === 0 ? (
        <p data-testid="queue-empty" className="text-sm text-gray-400">
          No open runs. Create one above, or seed the demo backend first.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table data-testid="queue-table" className="w-full text-sm">
            <caption className="sr-only">Open incident runs</caption>
            <thead>
              <tr className="text-left text-gray-400">
                <th scope="col" className="py-1">
                  Incident
                </th>
                <th scope="col">State</th>
                <th scope="col">Transitions</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.incident_id} className="border-t border-gray-800">
                  <td className="py-1">
                    <Link
                      to={`/incidents/${encodeURIComponent(run.incident_id)}`}
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
        </div>
      )}
    </div>
  );
}
