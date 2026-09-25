import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useMode } from "../components/useMode";

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const mode = useMode();
  const [run, setRun] = useState<RunView | null>(null);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const load = useCallback(
    async (showLoading: boolean) => {
      if (id === undefined) return;
      if (showLoading) setIsLoading(true);
      try {
        setRun(await runsApi.get(id));
        setError("");
        setErrorStatus(null);
      } catch (caught) {
        if (showLoading) setRun(null);
        setError(caught instanceof ApiError ? caught.message : String(caught));
        setErrorStatus(caught instanceof ApiError ? caught.status : 0);
      } finally {
        if (showLoading) setIsLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    setRun(null);
    setError("");
    setErrorStatus(null);
    void load(true);
  }, [load]);

  const events = useIncidentEvents({
    incidentId: id,
    enabled: run !== null && !isLoading && !isTerminalIncidentState(run.state),
    onRefresh: () => {
      void load(false);
    },
  });

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold">
          Incident {id}
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
        {run !== null && (
          <span
            data-testid="run-state"
            className="rounded bg-gray-800 px-2 py-0.5 text-xs font-bold"
          >
            {run.state}
          </span>
        )}
      </div>
      <p aria-live="polite" className="mb-2 text-xs text-gray-400">
        Event stream: {events.connectionState}
        {events.lastEventType === null ? "" : ` · ${events.lastEventType}`}
        {events.lastEventId === null ? "" : ` · ${events.lastEventId}`}
      </p>
      {events.error !== "" && (
        <p role="alert" className="mb-3 text-sm text-amber-300">
          Event stream update failed: {events.error}
        </p>
      )}
      {error !== "" && (
        <div role="alert" data-testid="detail-error" className="text-sm text-red-300">
          <p>
            {errorStatus === 404 ? "Run not found. " : "Run unavailable. "}
            {error}
          </p>
        </div>
      )}
      {id !== undefined && (
        <nav aria-label="Incident actions" className="mb-4 flex flex-wrap gap-3">
          <Link
            to={`/safety?incident_id=${encodeURIComponent(id)}`}
            className="rounded bg-amber-900 px-3 py-1 text-sm text-amber-100 underline"
          >
            Open Safety Gate
          </Link>
          <Link
            to={`/execution/${encodeURIComponent(id)}`}
            className="rounded bg-gray-800 px-3 py-1 text-sm underline"
          >
            Open Execution
          </Link>
          <Link
            to={`/rca/${encodeURIComponent(id)}`}
            className="rounded bg-gray-800 px-3 py-1 text-sm underline"
          >
            Open Audit &amp; Evaluation
          </Link>
        </nav>
      )}
      {isLoading ? (
        <p
          data-testid="detail-loading"
          aria-busy="true"
          className="text-sm text-gray-400"
        >
          Loading run…
        </p>
      ) : run !== null ? (
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
              {run.history.map((history) => (
                <li key={history.seq} className="border-t border-gray-800 py-1">
                  <span className="text-gray-500">#{history.seq}</span>{" "}
                  {history.frm} → {history.to}
                  {history.reason !== "" && (
                    <span className="text-gray-400"> — {history.reason}</span>
                  )}
                  {history.forced && (
                    <span className="ml-2 rounded bg-red-900 px-1 text-xs">
                      forced
                    </span>
                  )}
                  {history.refs.length > 0 && (
                    <span className="ml-2 inline-flex flex-wrap gap-1">
                      {history.refs.map((reference) => (
                        <span
                          key={reference}
                          data-testid="evidence-chip"
                          title={reference}
                          className="max-w-full break-all rounded bg-gray-800 px-1 text-xs text-sky-300"
                        >
                          {reference.length > 24
                            ? `${reference.slice(0, 24)}…`
                            : reference}
                        </span>
                      ))}
                    </span>
                  )}
                </li>
              ))}
            </ol>
          )}
        </>
      ) : error === "" ? (
        <p className="text-sm text-gray-400">No run data is available.</p>
      ) : null}
    </div>
  );
}
