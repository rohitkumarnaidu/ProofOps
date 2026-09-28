import { useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge, SeverityChip } from "../components/badges";
import { IncidentNav } from "../components/IncidentNav";
import { useAsyncData } from "../components/useAsyncData";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useModeState } from "../components/useMode";
import {
  Button,
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

/** Risk tier as a pill. Unknown values stay neutral rather than borrowing the
    red of RED -- an unrecognised string is not evidence of danger. */
function riskTone(risk: string): StatusTone {
  switch (risk.toUpperCase()) {
    case "GREEN":
      return "ok";
    case "YELLOW":
      return "warn";
    case "RED":
      return "danger";
    default:
      return "neutral";
  }
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
  const modeState = useModeState();
  const mode = modeState.mode;
  // Cancellation + out-of-order protection: an event-stream refresh and an
  // operator refresh can overlap, and the slower must not win.
  const runResource = useAsyncData<RunView>(
    async () => {
      if (id === undefined) throw new ApiError(0, "no incident in the route");
      return runsApi.get(id);
    },
    [id],
    { enabled: id !== undefined },
  );
  const run = runResource.data;
  const error = runResource.error;
  const errorStatus = runResource.status;
  const isLoading = runResource.loading;
  const [isSweeping, setSweeping] = useState(false);
  const [sweepNote, setSweepNote] = useState("");

  /**
   * Force the stage/approval TTL sweep.
   *
   * The FSM exempts terminals and untimed stages, so this is a no-op on a run
   * that has finished -- reported as such rather than as a silent nothing.
   */
  async function sweepTtl() {
    if (id === undefined) return;
    setSweeping(true);
    setSweepNote("");
    try {
      const next = await runsApi.sweep(id);
      runResource.set(next);
      setSweepNote(
        next.escalated
          ? "A stage or approval had exceeded its TTL; the run was force-escalated."
          : `Nothing was past its TTL; the run stays in ${next.state}.`,
      );
    } catch (caught) {
      setSweepNote(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setSweeping(false);
    }
  }

  const events = useIncidentEvents({
    incidentId: id,
    enabled: run !== null && !isLoading && !isTerminalIncidentState(run.state),
    onRefresh: () => {
      void runResource.reload(false);
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

  // Contract defaults are "" / GREEN, never null, so `?? "<something>"`
  // could never fire and an absent value rendered blank. Read the raw value
  // and render an explicit unknown instead of a client-side default -- a
  // fabricated "1.0.0" version or a fabricated "YELLOW" risk is exactly what
  // the deterministic policy engine exists to prevent.
  const runbookVersion =
    diagnosticData !== null && typeof diagnosticData.runbook_version === "string"
      ? diagnosticData.runbook_version
      : "";
  const riskLevel =
    plannedAction !== null && typeof plannedAction.risk_level === "string"
      ? plannedAction.risk_level
      : "";
  const triageOwner =
    triageData !== null && typeof triageData.owner === "string" ? triageData.owner : "";
  const proposedSeverity =
    triageData !== null && typeof triageData.severity === "string" ? triageData.severity : "";
  const triageFingerprint =
    triageData !== null && typeof triageData.fingerprint === "string"
      ? triageData.fingerprint
      : "";

  /**
   * The real policy decision, read off the run's own audit records.
   *
   * This is the authority on effective risk. The planner's `risk_level` is
   * contractually advisory, so showing only that labelled the run "SAFETY
   * LEVEL" from the model's own opinion.
   */
  const policyDecision = (() => {
    for (const record of run?.audit_records ?? []) {
      if (
        typeof record !== "object" ||
        record === null ||
        record.type !== "policy.decision"
      ) {
        continue;
      }
      const policy = record.policy;
      if (typeof policy !== "object" || policy === null) return null;
      const p = policy as Record<string, unknown>;
      const result = typeof p.result === "string" ? p.result : "";
      if (result === "") return null;
      return {
        result,
        version: typeof p.version === "string" ? p.version : "not reported",
        rule: typeof p.rule === "string" ? p.rule : "not reported",
      };
    }
    return null;
  })();

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Incident {id}
        </h1>
        <ModeBadge mode={mode} reason={modeState.reason} />
        {mode === null && (
          <span
            data-testid="mode-probing"
            aria-busy="true"
            className="text-xs text-fg-subtle"
          >
            probing backendÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦
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
        {events.lastEventType === null ? "" : ` ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â· ${events.lastEventType}`}
        {events.lastEventId === null ? "" : ` ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â· ${events.lastEventId}`}
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
            onRetry={() => void runResource.reload(true)}
          />
        </div>
      )}

      {/* One shared set of incident destinations, so the routes an operator can
          reach from here cannot drift from the other views. The hand-rolled
          list this replaced omitted the agent thread, so Incident Detail was
          the one view that could not reach the only surface explaining a
          decision in prose. */}
      {id !== undefined && (
        <div className="min-w-0 overflow-x-auto rounded border border-line bg-surface-raised px-3 py-2">
          <IncidentNav incidentId={id} current="incident" state={run?.state} />
        </div>
      )}

      {/* TTL sweep. A run parked at AWAITING_APPROVAL whose approval lapsed, or
          one stuck in an agent stage, otherwise sits there forever: nothing
          else in the product moves it. This used to be a dead-end hint that
          told the operator to "advance this run from the API". */}
      {id !== undefined && run !== null && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            data-testid="sweep-ttl"
            onClick={() => void sweepTtl()}
            disabled={isSweeping}
            className="max-w-full"
          >
            {isSweeping ? "Sweeping…" : "Sweep stage / approval TTLs"}
          </Button>
          {sweepNote !== "" && (
            <span role="status" data-testid="sweep-note" className="text-xs text-fg-muted">
              {sweepNote}
            </span>
          )}
        </div>
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
                      {/* runbook_version defaults to "" in the contract, so `??`
                          never fired and the row rendered a bare "v". Read the
                          real value and say so when the planner pinned none. */}
                      <span className="ml-2 font-mono text-fg-muted">
                        {runbookVersion === "" ? "version not reported" : `v${runbookVersion}`}
                      </span>
                    </div>
                    {/* No "INTEGRITY PINNED" badge. Nothing on this page fetches
                        or compares a runbook hash, so the badge asserted a sha256
                        verification that was never performed. The version is
                        shown because it is real; the pin is not claimed. */}
                    <StatusPill tone="info">VERSION PINNED BY PLANNER</StatusPill>
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
                  <div className="text-xs font-semibold text-fg-subtle">PLANNER-ADVISED RISK &amp; REVERSIBILITY</div>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    {riskLevel === "" ? (
                      <span className="text-sm text-fg-muted">not stated by the planner</span>
                    ) : (
                      <StatusPill tone={riskTone(riskLevel)}>{riskLevel}</StatusPill>
                    )}
                    {/* Reversibility comes from the run's own rollback
                        projection, not from the mere presence of a rollback
                        template: an action can carry a rollback template while
                        the run is not rollback-eligible. */}
                    <span className="text-xs text-fg-muted">
                      {run.rollback === undefined
                        ? "rollback state not reported"
                        : run.rollback.attempted
                          ? "rollback already attempted once"
                          : run.rollback.eligible
                            ? "rollback eligible now"
                            : "rollback not available in this state"}
                    </span>
                  </div>
                  {/* Action.risk_level is contractually ADVISORY: the policy
                      engine recomputes effective risk and that decision is the
                      authority. Never present the model's label as the
                      classified one. */}
                  <p className="mt-1.5 text-[11px] text-fg-subtle">
                    The planner&apos;s own self-assessment. The policy engine
                    recomputes effective risk; its decision is in the audit
                    chain.
                  </p>
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
              <div className="max-h-60 space-y-2 overflow-y-auto">
                {evidencePack.map((ev, i) => (
                  <div key={String(ev.evidence_id ?? i)} className="rounded border border-line bg-surface-raised p-2 font-mono text-xs">
                    <div className="mb-1 flex items-center justify-between text-fg-subtle">
                      <span className="font-semibold text-accent">
                        {ev.evidence_id === undefined ? "(no id reported)" : String(ev.evidence_id)}
                      </span>
                      {/* Never "telemetry": an evidence item whose source we
                          cannot read must not be attributed to a source. */}
                      <span>
                        {ev.source_type === undefined ? "source not reported" : String(ev.source_type)}
                      </span>
                    </div>
                    <div className="break-all text-fg-muted">
                      {ev.snippet === undefined ? JSON.stringify(ev) : String(ev.snippet)}
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
              description="A1 Triage Agent proposal. Severity here is the agent's proposal; the deterministic correlation severity is the authority."
            >
              <KeyValue
                items={[
                  ["Owner", triageOwner === "" ? "not stated by the agent" : triageOwner],
                  [
                    "Proposed severity",
                    proposedSeverity === "" ? (
                      <span className="text-fg-muted">not stated</span>
                    ) : (
                      <SeverityChip severity={proposedSeverity} />
                    ),
                  ],
                  [
                    "Fingerprint",
                    triageFingerprint === "" ? (
                      <span className="text-fg-muted">not reported</span>
                    ) : (
                      <span className="break-all font-mono text-xs">{triageFingerprint}</span>
                    ),
                  ],
                  [
                    "Signals",
                    // "none" was also shown when signals was merely a non-array,
                    // silently turning a shape mismatch into "no signals".
                    !Array.isArray(triageData.signals)
                      ? "not reported in the expected shape"
                      : triageData.signals.length === 0
                        ? "none listed"
                        : (triageData.signals as unknown[]).join(", "),
                  ],
                ]}
              />
            </Panel>
          )}

          {/* The real policy decision, read from the audit chain. */}
          {policyDecision !== null && (
            <Panel
              title="Policy decision"
              description="The deterministic authorization outcome. This is the authority on effective risk, not the planner's label."
            >
              <KeyValue
                items={[
                  ["Result", <StatusPill key="r" tone={policyDecision.result === "ALLOW" ? "ok" : policyDecision.result === "ESCALATE" ? "warn" : "danger"}>{policyDecision.result}</StatusPill>],
                  ["Policy version", policyDecision.version],
                  ["Matched rule", <span className="font-mono text-xs">{policyDecision.rule}</span>],
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
                    className="flex flex-wrap items-baseline gap-x-2 border-b border-line py-2 last:border-b-0"
                  >
                    <span className="text-xs tabular-nums text-fg-subtle">
                      #{history.seq}
                    </span>
                    {/* break-words, and no fixed width: state names like
                        POLICY_CHECK -> AWAITING_APPROVAL are longer than a
                        360px viewport once the row's other cells are laid out,
                        and an unbreakable run overflowed the page by 2px. */}
                    <span className="min-w-0 break-words font-medium">
                      {history.frm} → {history.to}
                    </span>
                    {history.reason !== "" && (
                      <span className="text-fg-muted"> ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â {history.reason}</span>
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
                              ? `${reference.slice(0, 24)}ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦`
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
