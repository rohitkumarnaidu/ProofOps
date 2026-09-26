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
  AUDITED: "ok",
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

interface HypothesisItem {
  hypothesis_id?: string;
  text?: string;
  confidence?: number;
  supporting?: string[];
  contradicting?: string[];
  status?: string;
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

  // Extract AI intelligence and handoffs
  let diagnosticData: Record<string, unknown> | null = null;
  let triageData: Record<string, unknown> | null = null;
  let plannedAction: Record<string, unknown> | null = null;
  let evidencePack: Array<Record<string, unknown>> = [];

  for (const h of run?.handoffs ?? []) {
    if (typeof h === "object" && h !== null) {
      if ("diagnostic_result" in h && typeof h.diagnostic_result === "object" && h.diagnostic_result !== null) {
        diagnosticData = h.diagnostic_result as Record<string, unknown>;
      }
      if ("triage_result" in h && typeof h.triage_result === "object" && h.triage_result !== null) {
        triageData = h.triage_result as Record<string, unknown>;
      }
      if ("planned_action" in h && typeof h.planned_action === "object" && h.planned_action !== null) {
        plannedAction = h.planned_action as Record<string, unknown>;
      }
      if ("evidence_pack" in h && Array.isArray(h.evidence_pack)) {
        evidencePack = h.evidence_pack as Array<Record<string, unknown>>;
      }
    }
  }

  const hypotheses = Array.isArray(diagnosticData?.hypotheses)
    ? (diagnosticData.hypotheses as HypothesisItem[])
    : [];

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

      {/* Polite live region for event stream */}
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

          {/* Diagnostic Hypotheses Panel */}
          {hypotheses.length > 0 && (
            <Panel
              title={`Diagnostic Hypotheses (${hypotheses.length})`}
              description="A2 Diagnostic Agent evaluated competing causal theories grounded in observed evidence."
            >
              <div className="flex flex-col gap-4">
                {hypotheses.map((hyp, index) => {
                  const confPct = Math.round((hyp.confidence ?? 0) * 100);
                  const tone: StatusTone =
                    hyp.status === "SUPPORTED"
                      ? "ok"
                      : hyp.status === "REJECTED"
                        ? "danger"
                        : "warn";
                  return (
                    <div
                      key={hyp.hypothesis_id ?? `hyp-${index}`}
                      className="rounded border border-line bg-surface-raised p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-fg-subtle">
                            HYP-{index + 1}
                          </span>
                          <span className="text-sm font-semibold text-fg">
                            {hyp.text}
                          </span>
                        </div>
                        <StatusPill tone={tone}>{hyp.status ?? "UNCERTAIN"}</StatusPill>
                      </div>

                      {/* Confidence Meter */}
                      <div className="mt-2.5">
                        <div className="flex items-center justify-between text-xs text-fg-subtle">
                          <span>Confidence Score</span>
                          <span className="font-mono font-semibold">{confPct}%</span>
                        </div>
                        <div className="mt-1 h-2 w-full overflow-hidden rounded bg-surface-sunken">
                          <div
                            className={`h-full transition-all ${
                              confPct >= 70
                                ? "bg-accent"
                                : confPct >= 40
                                  ? "bg-warn"
                                  : "bg-danger"
                            }`}
                            style={{ width: `${confPct}%` }}
                          />
                        </div>
                      </div>

                      {/* Citations & Evidence References */}
                      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                        {(hyp.supporting ?? []).length > 0 && (
                          <div className="flex items-center gap-1">
                            <span className="text-fg-subtle">Supporting:</span>
                            {hyp.supporting?.map((ref) => (
                              <span
                                key={ref}
                                data-testid="evidence-chip"
                                className="rounded border border-line bg-surface px-1.5 py-0.5 font-mono text-accent"
                              >
                                {ref}
                              </span>
                            ))}
                          </div>
                        )}
                        {(hyp.contradicting ?? []).length > 0 && (
                          <div className="flex items-center gap-1">
                            <span className="text-fg-subtle">Contradicting:</span>
                            {hyp.contradicting?.map((ref) => (
                              <span
                                key={ref}
                                data-testid="evidence-chip"
                                className="rounded border border-line bg-surface px-1.5 py-0.5 font-mono text-danger"
                              >
                                {ref}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}

                {/* Pinned Runbook Info */}
                {Boolean(diagnosticData?.runbook_id) && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-line bg-surface p-2.5 text-xs">
                    <div>
                      <span className="text-fg-subtle">Pinned Remediation Runbook: </span>
                      <span className="font-mono font-bold text-accent">
                        {String(diagnosticData?.runbook_id)}
                      </span>
                      <span className="ml-2 text-fg-muted font-mono">
                        v{String(diagnosticData?.runbook_version ?? "1.0.0")}
                      </span>
                    </div>
                    <StatusPill tone="ok">INTEGRITY PINNED</StatusPill>
                  </div>
                )}
              </div>
            </Panel>
          )}

          {/* Planned Remediation Action & Blast Radius */}
          {plannedAction !== null && (
            <Panel
              title="Planned Action &amp; Blast Radius"
              description="A3 Remediation Planner structured output governed by deterministic policy."
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded border border-line bg-surface-raised p-3">
                  <div className="text-xs font-semibold text-fg-subtle">PROPOSED ACTION</div>
                  <div className="mt-1 font-mono text-sm font-bold text-fg">
                    {String(plannedAction.action_type ?? "unknown")}
                  </div>
                  <div className="mt-1 text-xs text-fg-muted">
                    Resource: <span className="font-mono text-accent">{String(plannedAction.resource_id ?? "unknown")}</span>
                  </div>
                </div>

                <div className="rounded border border-line bg-surface-raised p-3">
                  <div className="text-xs font-semibold text-fg-subtle">SAFETY LEVEL &amp; REVERSIBILITY</div>
                  <div className="mt-1 flex items-center gap-2">
                    <StatusPill tone={String(plannedAction.risk_level) === "GREEN" ? "ok" : String(plannedAction.risk_level) === "YELLOW" ? "warn" : "danger"}>
                      {String(plannedAction.risk_level ?? "YELLOW")}
                    </StatusPill>
                    <span className="text-xs text-fg-muted">
                      {plannedAction.rollback_action ? "Reversible (Auto-Rollback ready)" : "No rollback"}
                    </span>
                  </div>
                  {Boolean(plannedAction.expected_outcome) && (
                    <div className="mt-1.5 text-xs text-fg-subtle">
                      Expected: {String(plannedAction.expected_outcome)}
                    </div>
                  )}
                </div>
              </div>
            </Panel>
          )}

          {/* Pre-digested Evidence Pack */}
          {evidencePack.length > 0 && (
            <Panel
              title={`Evidence Pack (${evidencePack.length} items)`}
              description="Context-compacted Evidence Pack ingested by diagnostic reasoning."
            >
              <div className="max-h-60 overflow-y-auto space-y-2">
                {evidencePack.map((ev, i) => (
                  <div key={String(ev.evidence_id ?? i)} className="rounded border border-line bg-surface-raised p-2 text-xs font-mono">
                    <div className="flex items-center justify-between text-fg-subtle mb-1">
                      <span className="font-semibold text-accent">{String(ev.evidence_id ?? "")}</span>
                      <span>{String(ev.source_type ?? "telemetry")}</span>
                    </div>
                    <div className="text-fg-muted break-all">
                      {String(ev.snippet ?? JSON.stringify(ev))}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* Triage Intelligence */}
          {triageData !== null && (
            <Panel
              title="Triage Signals &amp; Ownership"
              description="A1 Triage Agent proposal and deterministic correlation grouping."
            >
              <KeyValue
                items={[
                  ["Owner", String(triageData.owner ?? "unassigned")],
                  ["Proposed Severity", <StatusPill tone="warn">{String(triageData.severity ?? "P2")}</StatusPill>],
                  ["Fingerprint", <span className="font-mono text-xs">{String(triageData.fingerprint ?? "")}</span>],
                  ["Signals", Array.isArray(triageData.signals) ? triageData.signals.join(", ") : "none"],
                ]}
              />
            </Panel>
          )}

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
