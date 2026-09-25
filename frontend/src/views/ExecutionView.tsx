import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import { StateDiff } from "../components/StateDiff";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useMode } from "../components/useMode";

export function ExecutionView() {
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

  const phaseHistory =
    run?.history.filter((history) =>
      ["EXECUTING", "VERIFYING", "ROLLBACK", "RESOLVED", "ESCALATED"].includes(
        history.to,
      ),
    ) ?? [];
  const rollbackEligible =
    run?.rollback !== undefined
      ? run.rollback.eligible
      : run !== null &&
        (run.state === "VERIFYING" || run.state === "ROLLBACK") &&
        !run.rolled_back;
  const rollbackAttempted =
    run?.rollback !== undefined ? run.rollback.attempted : run?.rolled_back === true;
  const verdicts =
    run?.verification_verdicts ??
    phaseHistory.filter(
      (history) => history.to === "VERIFYING" || history.to === "ROLLBACK",
    );
  const executions = (run?.audit_records ?? []).filter(
    (record) =>
      typeof record === "object" &&
      record !== null &&
      record.type === "transition" &&
      ["EXECUTING", "VERIFYING", "ROLLBACK"].includes(String(record.to)),
  );

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold">
          Execution {id}
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
            data-testid="exec-state"
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
        <div role="alert" data-testid="exec-error" className="text-sm text-red-300">
          <p>
            {errorStatus === 404 ? "Run not found. " : "Execution data unavailable. "}
            {error}
          </p>
        </div>
      )}
      {isLoading ? (
        <p
          data-testid="exec-loading"
          aria-busy="true"
          className="text-sm text-gray-400"
        >
          Loading execution…
        </p>
      ) : run !== null ? (
        <>
          <h2 className="mb-1 text-sm font-bold text-gray-300">
            Execution-phase timeline
          </h2>
          {phaseHistory.length === 0 ? (
            <p data-testid="exec-empty" className="mb-4 text-sm text-gray-400">
              This run has not reached execution yet — approve its action in
              the Safety Gate first.
            </p>
          ) : (
            <ol data-testid="exec-timeline" className="mb-4 text-sm">
              {phaseHistory.map((history) => (
                <li key={history.seq} className="border-t border-gray-800 py-1">
                  <span className="text-gray-500">#{history.seq}</span>{" "}
                  {history.frm} → {history.to}
                  {history.forced && (
                    <span className="ml-2 rounded bg-red-900 px-1 text-xs">
                      forced
                    </span>
                  )}
                </li>
              ))}
            </ol>
          )}
          <h2 className="mb-1 text-sm font-bold text-gray-300">State diff</h2>
          <StateDiff diff={null} />
          <p className="mt-1 text-xs text-gray-500">
            No M21 execution or state-diff retrieval endpoint is exposed by the
            current API, so no state transition is fabricated here.
          </p>
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">Rollback</h2>
          {rollbackEligible ? (
            <p data-testid="rollback-eligible" className="text-sm">
              Rollback eligible: the control plane may perform its one governed
              rollback attempt after verification failure. This view is
              read-only.
            </p>
          ) : (
            <p data-testid="rollback-ineligible" className="text-sm text-gray-400">
              Rollback not available in state {run.state}
              {rollbackAttempted ? " (already attempted once)" : ""}.
            </p>
          )}
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">
            Verification verdicts ({verdicts.length}, run_view slice)
          </h2>
          {verdicts.length === 0 ? (
            <p
              data-testid="verdicts-empty"
              className="mb-4 text-sm text-gray-400"
            >
              No verification transitions recorded yet — verdicts appear here
              once the run reaches VERIFYING.
            </p>
          ) : (
            <ol data-testid="verdicts-list" className="mb-4 text-sm">
              {verdicts.map((verdict) => (
                <li key={verdict.seq} className="border-t border-gray-800 py-1">
                  <span className="text-gray-500">#{verdict.seq}</span>{" "}
                  {verdict.frm} → {verdict.to}
                  {verdict.reason !== "" && (
                    <span className="text-gray-400"> — {verdict.reason}</span>
                  )}
                </li>
              ))}
            </ol>
          )}
          <h2 className="mb-1 mt-4 text-sm font-bold text-gray-300">
            Execution records ({executions.length}, audit-sourced)
          </h2>
          {executions.length === 0 ? (
            <p
              data-testid="exec-records-empty"
              className="mb-4 text-sm text-gray-400"
            >
              No execution-phase audit records on file yet.
            </p>
          ) : (
            <ol data-testid="exec-records" className="mb-4 text-sm">
              {executions.map((record, index) => {
                const seq = typeof record.seq === "number" ? record.seq : null;
                const frm = typeof record.frm === "string" ? record.frm : "?";
                const to = typeof record.to === "string" ? record.to : "?";
                const reason =
                  typeof record.reason === "string" ? record.reason : "";
                const refs = Array.isArray(record.refs)
                  ? record.refs.filter(
                      (reference): reference is string =>
                        typeof reference === "string",
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
                      <span className="ml-2 inline-flex flex-wrap gap-1">
                        {refs.map((reference) => (
                          <span
                            key={reference}
                            className="max-w-full break-all rounded bg-gray-800 px-1 text-xs text-sky-300"
                          >
                            {reference}
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
      ) : null}
    </div>
  );
}
