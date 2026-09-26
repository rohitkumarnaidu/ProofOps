import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  ApiError,
  auditApi,
  evalApi,
  hasApiKey,
  runsApi,
  type SmokeResult,
} from "../api";
import { ModeBadge } from "../components/badges";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useMode } from "../components/useMode";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  Notice,
  Panel,
  StatusPill,
} from "../components/ui";

const GATES = ["C1", "C2", "C3", "C4", "C5", "C6"] as const;

function fmtGate(value: unknown): string {
  if (typeof value === "number") return value.toFixed(2);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map((entry: unknown) => fmtGate(entry)).join(",");
  }
  return "—";
}

export function RCAView() {
  const { id } = useParams<{ id: string }>();
  const mode = useMode();
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [incidentState, setIncidentState] = useState<string | null>(null);
  const [smoke, setSmoke] = useState<SmokeResult | null>(null);
  const [auditError, setAuditError] = useState("");
  const [auditErrorStatus, setAuditErrorStatus] = useState<number | null>(null);
  const [chainValidity, setChainValidity] = useState<{
    valid: boolean;
    checked: number;
    origin: string;
  } | null>(null);
  const [evaluationError, setEvaluationError] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  const load = useCallback(
    async (showLoading: boolean) => {
      if (id === undefined) return;
      if (showLoading) setIsLoading(true);
      try {
        const [chain, run] = await Promise.all([auditApi.view(id), runsApi.get(id)]);
        setEvents(Array.isArray(chain.events) ? chain.events : []);
        setChainValidity({ valid: chain.valid, checked: chain.checked, origin: chain.origin });
        setIncidentState(run.state);
        setAuditError("");
        setAuditErrorStatus(null);
      } catch (caught) {
        if (showLoading) setEvents([]);
        setAuditError(caught instanceof ApiError ? caught.message : String(caught));
        setAuditErrorStatus(caught instanceof ApiError ? caught.status : 0);
      } finally {
        if (showLoading) setIsLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    setEvents([]);
    setIncidentState(null);
    setAuditError("");
    setAuditErrorStatus(null);
    void load(true);
  }, [load]);

  const incidentEvents = useIncidentEvents({
    incidentId: id,
    enabled:
      incidentState !== null && !isLoading && !isTerminalIncidentState(incidentState),
    onRefresh: () => {
      void load(false);
    },
  });

  async function runSmoke() {
    setEvaluationError("");
    try {
      setSmoke(await evalApi.smoke());
    } catch (caught) {
      setEvaluationError(
        caught instanceof ApiError ? caught.message : String(caught),
      );
    }
  }

  const baseGates = smoke?.baseline.gates_rate;
  const optimizedGates = smoke?.optimized.gates_rate;
  const showPerGate =
    baseGates !== undefined &&
    optimizedGates !== undefined &&
    GATES.every(
      (gate) =>
        typeof baseGates[gate] === "number" &&
        typeof optimizedGates[gate] === "number",
    );

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Audit &amp; Evaluation {id}
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
        {incidentState !== null && (
          <span className="inline-flex">
            <StatusPill tone="info">{incidentState}</StatusPill>
          </span>
        )}
        {chainValidity && (
          <span data-testid="audit-valid-badge" className="inline-flex">
            <StatusPill
              tone={chainValidity.valid ? "ok" : "danger"}
              title={`${chainValidity.checked} event(s) verified against the hash chain`}
            >
              {chainValidity.valid ? "chain valid" : "chain INVALID"} ·{" "}
              {chainValidity.checked} event{chainValidity.checked === 1 ? "" : "s"} ·{" "}
              {chainValidity.origin}
            </StatusPill>
          </span>
        )}
      </div>

      {/* Scope honesty, stated on the view itself rather than only in the docs:
          this is the audit + measurement surface, not a rendered RCA document. */}
      <Notice tone="info">
        This view renders incident audit events and measured evaluation data. It
        does not render an RCA document.
      </Notice>

      <p aria-live="polite" className="text-xs text-fg-subtle">
        Event stream: {incidentEvents.connectionState}
        {incidentEvents.lastEventType === null
          ? ""
          : ` · ${incidentEvents.lastEventType}`}
        {incidentEvents.lastEventId === null
          ? ""
          : ` · ${incidentEvents.lastEventId}`}
      </p>

      {incidentEvents.error !== "" && (
        <ErrorState title="Event stream update failed" detail={incidentEvents.error} />
      )}

      {auditError !== "" && (
        <div data-testid="rca-error">
          <ErrorState
            title={auditErrorStatus === 404 ? "Incident audit not found" : "Audit data unavailable"}
            detail={auditError}
            onRetry={() => void load(true)}
          />
        </div>
      )}

      {!hasApiKey() && (
        <Notice tone="warn" testId="api-key-notice" live>
          No API key is configured. Audit events may be readable, but the
          evaluation action will return 401.
        </Notice>
      )}

      <Panel
        title="Audit events"
        description="Hash-chained, append-only. Each row links to its predecessor."
        actions={
          <Button size="sm" onClick={() => void load(false)}>
            Refresh audit
          </Button>
        }
      >
        {isLoading ? (
          <div data-testid="rca-loading" aria-busy="true">
            <LoadingState label="Loading audit events" />
          </div>
        ) : auditError !== "" ? null : events.length === 0 ? (
          <div data-testid="audit-empty">
            <EmptyState title="No audit events were returned for this incident." />
          </div>
        ) : (
          <ol data-testid="audit-chain" className="text-xs space-y-2">
            {events.map((event, index) => {
              const eventId =
                typeof event.event_id === "string"
                  ? event.event_id
                  : `row-${String(index)}`;
              const prev = typeof event.prev_hash === "string" ? event.prev_hash : "";
              const curr = typeof event.curr_hash === "string" ? event.curr_hash : "";
              return (
                <li
                  key={eventId}
                  className="max-w-full break-all rounded border border-line bg-surface-raised p-2.5 font-mono"
                >
                  <div className="flex flex-wrap items-center justify-between gap-1 pb-1 border-b border-line text-fg-subtle">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-fg">#{String(event.seq ?? "—")}</span>
                      <span className="font-semibold text-accent">{String(event.event_type ?? "unknown")}</span>
                    </div>
                    <span className="text-xs text-fg-muted">{String(event.actor ?? "control-plane")}</span>
                  </div>
                  {String(event.result ?? "") !== "" ? (
                    <div className="mt-1.5 text-fg">{String(event.result)}</div>
                  ) : null}
                  {(prev !== "" || curr !== "") && (
                    <div className="mt-2 pt-1 border-t border-line/50 flex flex-wrap items-center gap-3 text-[11px] text-fg-subtle">
                      {prev !== "" && <span>prev: <span className="text-fg-muted">{prev.slice(0, 10)}…{prev.slice(-6)}</span></span>}
                      {curr !== "" && <span>curr: <span className="text-ok font-semibold">{curr.slice(0, 10)}…{curr.slice(-6)}</span></span>}
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </Panel>

      <Panel
        title="Six-gate scorecard (harness smoke, mock systems)"
        description="Mock-system figures only; pipeline-system numbers are never mixed into this response."
        actions={
          <Button size="sm" tone="primary" onClick={() => void runSmoke()}>
            Run smoke eval
          </Button>
        }
      >
        {evaluationError !== "" && (
          <ErrorState title="Evaluation failed" detail={evaluationError} />
        )}
        {smoke === null ? (
          <EmptyState
            title="No evaluation run in this page state"
            hint="Run the smoke eval to populate the six-gate scorecard."
          />
        ) : (
          <div data-testid="gate-cards">
            <p className="text-sm text-fg-muted">
              {smoke.system} · {smoke.cases} cases · baseline{" "}
              {smoke.baseline.pass_rate} → degraded {smoke.optimized.pass_rate}
            </p>
            <p className="mt-1 text-sm">
              Rubric total:{" "}
              <span className="font-bold tabular-nums">
                {smoke.rubric.total_100}
              </span>{" "}
              (mock systems; pipeline-system numbers are never mixed into this
              response)
            </p>
            {showPerGate && (
              <div
                data-testid="per-gate-cards"
                className="mt-3 grid gap-2 md:grid-cols-3"
              >
                {GATES.map((gate) => (
                  <div
                    key={gate}
                    data-testid={`gate-card-${gate}`}
                    className="rounded border border-line bg-surface-raised px-2.5 py-1.5"
                  >
                    <p className="text-xs font-bold uppercase tracking-wide text-fg-muted">
                      {gate}
                    </p>
                    <p className="mt-0.5 text-xs text-fg-muted">
                      base {fmtGate(baseGates?.[gate])} → opt{" "}
                      {fmtGate(optimizedGates?.[gate])} (Δ{" "}
                      {fmtGate(smoke.delta[`d_${gate}`])})
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
