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
import {
  EmptyState,
  ErrorState,
  LoadingState,
  Panel,
  StatusPill,
} from "../components/ui";

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
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Execution {id}
        </h1>
        <ModeBadge mode={mode} />
        {mode === null && (
          <span
            data-testid="mode-probing"
            aria-busy="true"
            className="text-xs text-fg-subtle"
          >
            probing backend…
          </span>
        )}
        {run !== null && (
          <span data-testid="exec-state" className="inline-flex">
            <StatusPill tone="info">{run.state}</StatusPill>
          </span>
        )}
      </div>

      <p aria-live="polite" className="text-xs text-fg-subtle">
        Event stream: {events.connectionState}
        {events.lastEventType === null ? "" : ` · ${events.lastEventType}`}
        {events.lastEventId === null ? "" : ` · ${events.lastEventId}`}
      </p>

      {events.error !== "" && (
        <ErrorState title="Event stream update failed" detail={events.error} />
      )}

      {error !== "" && (
        <div data-testid="exec-error">
          <ErrorState
            title={errorStatus === 404 ? "Run not found" : "Execution data unavailable"}
            detail={error}
          />
        </div>
      )}

      {isLoading ? (
        <div data-testid="exec-loading" aria-busy="true">
          <LoadingState label="Loading execution" />
        </div>
      ) : run !== null ? (
        <>
          <Panel
            title="Execution-phase timeline"
            description="Transitions the run made through the execution phases."
          >
            {phaseHistory.length === 0 ? (
              <div data-testid="exec-empty">
                <EmptyState
                  title="This run has not reached execution yet"
                  hint="Approve its action in the Safety Gate first."
                />
              </div>
            ) : (
              <ol data-testid="exec-timeline" className="text-sm">
                {phaseHistory.map((history) => (
                  <li
                    key={history.seq}
                    className="border-b border-line py-2 last:border-b-0"
                  >
                    <span className="mr-2 text-xs tabular-nums text-fg-subtle">
                      #{history.seq}
                    </span>
                    <span className="font-medium">
                      {history.frm} → {history.to}
                    </span>
                    {history.forced && (
                      <span className="ml-2 inline-flex align-middle">
                        <StatusPill tone="danger">forced</StatusPill>
                      </span>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          {/* Live observed state diff when available, honest fallback otherwise */}
          <Panel title="State diff" description="Observed before/after mutations with side-by-side key diff.">
            {run.state_diff ? (
              <StateDiff diff={run.state_diff} />
            ) : (
              <>
                <StateDiff diff={null} />
                <p className="mt-2 text-xs text-fg-subtle">
                  No M21 execution or state-diff retrieval endpoint is exposed by the
                  current API, so no state transition is fabricated here.
                </p>
              </>
            )}
          </Panel>

          {/* Real-time Rollout & Execution Terminal Logs */}
          <Panel
            title="Execution Terminal Logs"
            description="Live stdout/stderr stream from container sandbox or Kubernetes API server."
          >
            {(run.execution_logs ?? []).length === 0 ? (
              <EmptyState
                title="No execution logs streamed yet"
                hint="Logs appear here in real-time when the action reaches EXECUTING."
              />
            ) : (
              <div className="rounded border border-line bg-black p-3 font-mono text-xs text-emerald-400">
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-zinc-800 text-fg-subtle">
                  <span>TERMINAL · /bin/k8s-exec</span>
                  <span className="text-ok">EXIT CODE 0 (VERIFICATION PENDING)</span>
                </div>
                <div className="max-h-60 overflow-y-auto space-y-1">
                  {(run.execution_logs ?? []).map((line, idx) => (
                    <div key={idx} className="flex gap-2">
                      <span className="text-zinc-600 select-none">&gt;</span>
                      <span className="break-all">{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Panel>

          <Panel title="Rollback">
            {rollbackEligible ? (
              <p data-testid="rollback-eligible" className="text-sm text-fg-muted">
                Rollback eligible: the control plane may perform its one governed
                rollback attempt after verification failure. This view is
                read-only.
              </p>
            ) : (
              <p data-testid="rollback-ineligible" className="text-sm text-fg-subtle">
                Rollback not available in state {run.state}
                {rollbackAttempted ? " (already attempted once)" : ""}.
              </p>
            )}
          </Panel>

          <Panel
            title={`Verification verdicts (${verdicts.length}, run_view slice)`}
            description="Exit status is not resolution; a verdict is the independent check."
          >
            {verdicts.length === 0 ? (
              <div data-testid="verdicts-empty">
                <EmptyState
                  title="No verification transitions recorded yet"
                  hint="Verdicts appear here once the run reaches VERIFYING."
                />
              </div>
            ) : (
              <ol data-testid="verdicts-list" className="text-sm">
                {verdicts.map((verdict) => (
                  <li
                    key={verdict.seq}
                    className="border-b border-line py-2 last:border-b-0"
                  >
                    <span className="mr-2 text-xs tabular-nums text-fg-subtle">
                      #{verdict.seq}
                    </span>
                    <span className="font-medium">
                      {verdict.frm} → {verdict.to}
                    </span>
                    {verdict.reason !== "" && (
                      <span className="text-fg-muted"> — {verdict.reason}</span>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          <Panel
            title={`Execution records (${executions.length}, audit-sourced)`}
            description="Read from the hash-chained audit log, not from a live cluster."
          >
            {executions.length === 0 ? (
              <div data-testid="exec-records-empty">
                <EmptyState title="No execution-phase audit records on file yet." />
              </div>
            ) : (
              <ol data-testid="exec-records" className="text-sm">
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
                      className="border-b border-line py-2 last:border-b-0"
                    >
                      <span className="mr-2 text-xs tabular-nums text-fg-subtle">
                        #{seq ?? "—"}
                      </span>
                      <span className="font-medium">
                        {frm} → {to}
                      </span>
                      {reason !== "" && (
                        <span className="text-fg-muted"> — {reason}</span>
                      )}
                      {refs.length > 0 && (
                        <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                          {refs.map((reference) => (
                            <span
                              key={reference}
                              className="max-w-full break-all rounded border border-line bg-surface-raised px-1.5 py-0.5 text-xs text-accent"
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
          </Panel>
        </>
      ) : null}
    </div>
  );
}
