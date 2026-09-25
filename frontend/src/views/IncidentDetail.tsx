import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useMode } from "../components/useMode";
import {
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Panel,
  StatusPill,
  type StatusTone,
} from "../components/ui";

/** Run state -> tone. Severity of the *operational* situation, not decoration:
    a terminal state is calm, a failure state is loud. */
const STATE_TONE: Record<string, StatusTone> = {
  RESOLVED: "ok",
  ROLLBACK: "warn",
  ESCALATED: "danger",
  BLOCKED: "danger",
  AWAITING_APPROVAL: "warn",
  EXECUTING: "info",
  VERIFYING: "info",
};

function stateTone(state: string): StatusTone {
  return STATE_TONE[state] ?? "neutral";
}

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
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Incident {id}
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
          <span data-testid="run-state" className="inline-flex">
            <StatusPill tone={stateTone(run.state)}>{run.state}</StatusPill>
          </span>
        )}
      </div>

      {/* Connection state changes without the operator re-focusing anything, so
          it is a polite live region rather than static text. */}
      <p aria-live="polite" className="text-xs text-fg-subtle">
        Event stream: {events.connectionState}
        {events.lastEventType === null ? "" : ` · ${events.lastEventType}`}
        {events.lastEventId === null ? "" : ` · ${events.lastEventId}`}
      </p>

      {events.error !== "" && (
        <ErrorState
          title="Event stream update failed"
          detail={events.error}
        />
      )}

      {error !== "" && (
        <div data-testid="detail-error">
          <ErrorState
            title={errorStatus === 404 ? "Run not found" : "Run unavailable"}
            detail={error}
            onRetry={() => void load(true)}
          />
        </div>
      )}

      {id !== undefined && (
        <nav aria-label="Incident actions" className="flex flex-wrap gap-2">
          {[
            { to: `/safety?incident_id=${encodeURIComponent(id)}`, label: "Open Safety Gate", tone: "warn" },
            { to: `/execution/${encodeURIComponent(id)}`, label: "Open Execution", tone: "info" },
            { to: `/rca/${encodeURIComponent(id)}`, label: "Open Audit & Evaluation", tone: "info" },
          ].map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className={`rounded border px-3 py-1.5 text-sm font-medium no-underline transition-colors ${
                link.tone === "warn"
                  ? "border-warn bg-surface text-warn hover:bg-surface-raised"
                  : "border-line bg-surface-raised text-fg hover:bg-line"
              }`}
            >
              {link.label}
            </Link>
          ))}
        </nav>
      )}

      {isLoading ? (
        <div data-testid="detail-loading" aria-busy="true">
          <LoadingState label="Loading run" />
        </div>
      ) : run !== null ? (
        <>
          <Panel title="Run summary">
            <KeyValue
              items={[
                ["Re-plans", run.replans],
                ["Rolled back", run.rolled_back ? "yes" : "no"],
                ["Permit pending", run.permit_pending ? "yes" : "no"],
              ]}
            />
          </Panel>

          <Panel title="Timeline" description="Every state transition, in order.">
            {run.history.length === 0 ? (
              <EmptyState
                title="No transitions yet"
                hint="Advance this run from the API."
              />
            ) : (
              <ol data-testid="timeline" className="text-sm">
                {run.history.map((history) => (
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
                    {history.reason !== "" && (
                      <span className="text-fg-muted"> — {history.reason}</span>
                    )}
                    {history.forced && (
                      <span className="ml-2 inline-flex align-middle">
                        <StatusPill tone="danger" title="Forced transition">
                          forced
                        </StatusPill>
                      </span>
                    )}
                    {history.refs.length > 0 && (
                      <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                        {history.refs.map((reference) => (
                          <span
                            key={reference}
                            data-testid="evidence-chip"
                            title={reference}
                            className="max-w-full break-all rounded border border-line bg-surface-raised px-1.5 py-0.5 text-xs text-accent"
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
          </Panel>
        </>
      ) : error === "" ? (
        <EmptyState title="No run data is available." />
      ) : null}
    </div>
  );
}
