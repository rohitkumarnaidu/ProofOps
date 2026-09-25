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
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold">
          Audit &amp; Evaluation {id}
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
        {incidentState !== null && (
          <span className="rounded bg-gray-800 px-2 py-0.5 text-xs font-bold">
            {incidentState}
          </span>
        )}
        {chainValidity && (
          <span
            data-testid="audit-valid-badge"
            className={
              chainValidity.valid
                ? "rounded bg-green-900 px-2 py-0.5 text-xs font-bold text-green-200"
                : "rounded bg-red-900 px-2 py-0.5 text-xs font-bold text-red-200"
            }
          >
            {chainValidity.valid ? "chain valid" : "chain INVALID"} ·{" "}
            {chainValidity.checked} event{chainValidity.checked === 1 ? "" : "s"} ·{" "}
            {chainValidity.origin}
          </span>
        )}
      </div>
      <p className="mb-3 text-sm text-gray-400">
        This view renders incident audit events and measured evaluation data. It
        does not render an RCA document.
      </p>
      <p aria-live="polite" className="mb-2 text-xs text-gray-400">
        Event stream: {incidentEvents.connectionState}
        {incidentEvents.lastEventType === null
          ? ""
          : ` · ${incidentEvents.lastEventType}`}
        {incidentEvents.lastEventId === null
          ? ""
          : ` · ${incidentEvents.lastEventId}`}
      </p>
      {incidentEvents.error !== "" && (
        <p role="alert" className="mb-3 text-sm text-amber-300">
          Event stream update failed: {incidentEvents.error}
        </p>
      )}
      {auditError !== "" && (
        <div role="alert" data-testid="rca-error" className="mb-3 text-sm text-red-300">
          <p>
            {auditErrorStatus === 404
              ? "Incident audit not found. "
              : "Audit data unavailable. "}
            {auditError}
          </p>
        </div>
      )}
      {!hasApiKey() && (
        <p data-testid="api-key-notice" className="mb-3 text-sm text-amber-300">
          No API key is configured. Audit events may be readable, but the
          evaluation action will return 401.
        </p>
      )}
      <div className="mb-1 flex items-center justify-between gap-3">
        <h2 className="text-sm font-bold text-gray-300">Audit events</h2>
        <button
          type="button"
          onClick={() => void load(false)}
          className="rounded border border-gray-700 px-3 py-1 text-sm"
        >
          Refresh audit
        </button>
      </div>
      {isLoading ? (
        <p
          data-testid="rca-loading"
          aria-busy="true"
          className="mb-4 text-sm text-gray-400"
        >
          Loading audit events…
        </p>
      ) : auditError !== "" ? null : events.length === 0 ? (
        <p data-testid="audit-empty" className="mb-4 text-sm text-gray-400">
          No audit events were returned for this incident.
        </p>
      ) : (
        <ol data-testid="audit-chain" className="mb-4 text-sm">
          {events.map((event, index) => {
            const eventId =
              typeof event.event_id === "string" ? event.event_id : `row-${String(index)}`;
            return (
              <li
                key={eventId}
                className="max-w-full break-all border-t border-gray-800 py-1 font-mono text-xs"
              >
                #{String(event.seq ?? "—")} {String(event.event_type ?? "unknown")} —{" "}
                {String(event.result ?? "")}
              </li>
            );
          })}
        </ol>
      )}
      <h2 className="mb-1 text-sm font-bold text-gray-300">
        Six-gate scorecard (harness smoke, mock systems)
      </h2>
      <button
        type="button"
        onClick={() => void runSmoke()}
        className="mb-2 rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600"
      >
        Run smoke eval
      </button>
      {evaluationError !== "" && (
        <p role="alert" className="mb-3 text-sm text-red-300">
          Evaluation failed: {evaluationError}
        </p>
      )}
      {smoke !== null && (
        <div data-testid="gate-cards" className="text-sm">
          <p className="text-gray-400">
            {smoke.system} · {smoke.cases} cases · baseline{" "}
            {smoke.baseline.pass_rate} → degraded {smoke.optimized.pass_rate}
          </p>
          <p>
            Rubric total: <strong>{smoke.rubric.total_100}</strong> (mock
            systems; pipeline-system numbers are never mixed into this response)
          </p>
          {showPerGate && (
            <div
              data-testid="per-gate-cards"
              className="mt-2 grid gap-2 md:grid-cols-3"
            >
              {GATES.map((gate) => (
                <div
                  key={gate}
                  data-testid={`gate-card-${gate}`}
                  className="rounded border border-gray-800 px-2 py-1"
                >
                  <p className="font-bold">{gate}</p>
                  <p className="text-gray-400">
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
    </div>
  );
}
