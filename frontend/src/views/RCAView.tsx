import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  ApiError,
  auditApi,
  evalApi,
  hasApiKey,
  runsApi,
  type AuditVerify,
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
  const [isRunningSmoke, setIsRunningSmoke] = useState(false);
  // Explicit chain re-verification. `GET .../audit` reports a valid flag but not
  // WHERE a break is, so a tampered chain was undiagnosable from the UI.
  const [verifyResult, setVerifyResult] = useState<AuditVerify | null>(null);
  const [verifyError, setVerifyError] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportNote, setExportNote] = useState("");

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

  async function verifyChain() {
    if (id === undefined) return;
    setVerifyError("");
    setVerifyResult(null);
    setIsVerifying(true);
    try {
      setVerifyResult(await auditApi.verify(id));
    } catch (caught) {
      setVerifyError(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setIsVerifying(false);
    }
  }

  async function exportChain() {
    if (id === undefined) return;
    setExportNote("");
    setIsExporting(true);
    try {
      const proof = await auditApi.export(id);
      // The exportable proof artifact is the deliverable, so it is offered as a
      // real download rather than being fetched and discarded.
      const blob = new Blob([JSON.stringify(proof, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `proofops-audit-${id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setExportNote(
        `Exported ${proof.events.length} event(s); chain reported ${proof.valid ? "valid" : "INVALID"} at ${proof.exported_at}.`,
      );
    } catch (caught) {
      setExportNote(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setIsExporting(false);
    }
  }

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
    // In-flight guard: POST /eval/smoke is a compute-heavy campaign, and the
    // button used to stay enabled, so a double click fired it repeatedly.
    setIsRunningSmoke(true);
    try {
      setSmoke(await evalApi.smoke());
    } catch (caught) {
      // Clear the stale scorecard. Leaving the previous run's numbers on screen
      // beside a new error banner reads as "these are the current results".
      setSmoke(null);
      setEvaluationError(
        caught instanceof ApiError ? caught.message : String(caught),
      );
    } finally {
      setIsRunningSmoke(false);
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
        description="Hash-chained, append-only. Each row carries the hash of the row before it."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => void load(false)}>
              Refresh audit
            </Button>
            <Button
              size="sm"
              data-testid="verify-chain"
              onClick={() => void verifyChain()}
              disabled={isVerifying}
            >
              {isVerifying ? "Verifying…" : "Verify chain"}
            </Button>
            <Button
              size="sm"
              data-testid="export-chain"
              onClick={() => void exportChain()}
              disabled={isExporting}
            >
              {isExporting ? "Exporting…" : "Export proof"}
            </Button>
          </div>
        }
      >
        {verifyError !== "" && (
          <div data-testid="verify-error" className="mb-3">
            <ErrorState title="Chain verification failed" detail={verifyError} />
          </div>
        )}
        {verifyResult !== null && (
          <div data-testid="verify-result" className="mb-3">
            <Notice
              tone={verifyResult.valid ? "ok" : "danger"}
              title={
                verifyResult.valid
                  ? `Chain verified: ${verifyResult.checked} event(s) recomputed, no break found.`
                  : `Chain BROKEN at seq ${String(verifyResult.first_bad_seq)} (${verifyResult.reason}). ${verifyResult.checked} event(s) verified before the break.`
              }
            >
              This was recomputed server-side by re-hashing every link and
              re-checking the ordering, not read from the cached valid flag.
            </Notice>
          </div>
        )}
        {exportNote !== "" && (
          <div data-testid="export-note" className="mb-3">
            <Notice tone="info">{exportNote}</Notice>
          </div>
        )}
        {isLoading ? (
          <div data-testid="rca-loading" aria-busy="true">
            <LoadingState label="Loading audit events" />
          </div>
        ) : auditError !== "" ? null : events.length === 0 ? (
          <div data-testid="audit-empty">
            <EmptyState title="No audit events were returned for this incident." />
          </div>
        ) : (
          <ol data-testid="audit-chain" className="space-y-2 text-xs">
            {events.map((event, index) => {
              const eventId =
                typeof event.event_id === "string"
                  ? event.event_id
                  : `row-${String(index)}`;
              const prev = typeof event.prev_hash === "string" ? event.prev_hash : "";
              const curr = typeof event.curr_hash === "string" ? event.curr_hash : "";
              // The event timestamp was never rendered, so the audit list had
              // no time axis at all. Read the contract's own field.
              const ts = typeof event.ts === "string" ? event.ts : "";
              const policy =
                typeof event.policy === "object" && event.policy !== null
                  ? (event.policy as Record<string, unknown>)
                  : null;
              const evidence = Array.isArray(event.evidence_ids)
                ? event.evidence_ids.filter(
                    (e): e is string => typeof e === "string",
                  )
                : [];
              return (
                <li
                  key={eventId}
                  className="max-w-full rounded border border-line bg-surface-raised p-2.5 font-mono break-all"
                >
                  <div className="flex flex-wrap items-center justify-between gap-1 border-b border-line pb-1 text-fg-subtle">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-fg">#{String(event.seq ?? "—")}</span>
                      <span className="font-semibold text-accent">{String(event.event_type ?? "unknown")}</span>
                    </div>
                    <span className="text-xs text-fg-muted">
                      {ts === "" ? "no timestamp reported" : new Date(ts).toLocaleString()}
                      {" · "}
                      {String(event.actor ?? "control-plane")}
                    </span>
                  </div>
                  {String(event.result ?? "") !== "" ? (
                    <div className="mt-1.5 text-fg">{String(event.result)}</div>
                  ) : null}
                  {/* The policy decision was dropped from this view entirely,
                      so the authorization outcome was invisible in the audit
                      surface even though every event carries it. */}
                  {policy !== null && (
                    <div className="mt-1.5 flex flex-wrap gap-2 text-[11px]">
                      <span className="text-fg-subtle">policy:</span>
                      <span className="font-semibold text-fg">
                        {String(policy.result ?? "not reported")}
                      </span>
                      <span className="text-fg-subtle">v{String(policy.version ?? "?")}</span>
                      <span className="font-mono text-fg-muted">
                        {String(policy.rule ?? "rule not reported")}
                      </span>
                    </div>
                  )}
                  {evidence.length > 0 && (
                    <div className="mt-1 text-[11px] text-fg-subtle">
                      evidence:{" "}
                      {evidence.map((e) => (
                        <span key={e} className="mr-1 font-mono text-fg-muted">
                          {e}
                        </span>
                      ))}
                    </div>
                  )}
                  {(prev !== "" || curr !== "") && (
                    <div className="mt-2 flex flex-wrap items-center gap-3 border-t border-line/50 pt-1 text-[11px] text-fg-subtle">
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
          <Button
            size="sm"
            tone="primary"
            data-testid="run-smoke"
            onClick={() => void runSmoke()}
            disabled={isRunningSmoke}
          >
            {isRunningSmoke ? "Running…" : "Run smoke eval"}
          </Button>
        }
      >
        {evaluationError !== "" && (
          <ErrorState
            title="Evaluation failed"
            detail={evaluationError}
            onRetry={() => void runSmoke()}
          />
        )}
        {smoke === null ? (
          <EmptyState
            title="No evaluation run in this page state"
            hint="Run the smoke eval to populate the six-gate scorecard."
          />
        ) : (
          <div data-testid="gate-cards">
            {/* The backend's own anti-overclaim statement, rendered rather than
                dropped. A reader must see the caveat with the number. */}
            <Notice tone="warn" className="mb-2">
              {smoke.note}
            </Notice>
            <p className="text-sm text-fg-muted">
              {smoke.system} · {smoke.cases} cases ·{" "}
              {smoke.baseline.config.name} (n={smoke.baseline.n}) →{" "}
              {smoke.optimized.config.name} (n={smoke.optimized.n}) · pass rate{" "}
              {smoke.baseline.pass_rate} → {smoke.optimized.pass_rate} (Δ
              {String(smoke.delta.d_pass_rate ?? "n/a")})
            </p>
            <p className="mt-1 text-sm">
              Rubric total:{" "}
              <span className="font-bold tabular-nums">
                {smoke.rubric.total_100}
              </span>{" "}
              over n={smoke.rubric.n} (mock systems; pipeline-system numbers are
              never mixed into this response)
            </p>
            {/* The four rubric subtotals were fetched and never rendered, so
                only a bare total appeared with no breakdown behind it. */}
            <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
              {(
                [
                  ["Lyzr 30", smoke.rubric.lyzr_30],
                  ["Safety 30", smoke.rubric.safety_30],
                  ["Code 20", smoke.rubric.code_20],
                  ["UX 20", smoke.rubric.ux_20],
                ] as const
              ).map(([label, group]) => (
                <div
                  key={label}
                  className="rounded border border-line bg-surface-raised px-2.5 py-1.5"
                >
                  <p className="text-xs font-bold uppercase tracking-wide text-fg-muted">
                    {label}
                  </p>
                  <p className="text-sm font-bold tabular-nums text-fg">
                    {typeof group.subtotal === "number" ? group.subtotal : "—"}
                  </p>
                </div>
              ))}
            </div>
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
