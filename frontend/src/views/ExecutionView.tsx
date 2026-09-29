import { useParams } from "react-router-dom";
import { ApiError, runsApi, type RunView } from "../api";
import { ModeBadge } from "../components/badges";
import { IncidentNav } from "../components/IncidentNav";
import { StateDiff } from "../components/StateDiff";
import { useAsyncData } from "../components/useAsyncData";
import {
  isTerminalIncidentState,
  useIncidentEvents,
} from "../components/useIncidentEvents";
import { useModeState } from "../components/useMode";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  Panel,
  StatusPill,
  type StatusTone,
} from "../components/ui";

/** Verdict -> tone, from the verifier's own closed verdict set. */
function verdictTone(verdict: string): StatusTone {
  switch (verdict.toUpperCase()) {
    case "RESOLVED":
      return "ok";
    case "PARTIAL":
    case "ROLLBACK_REQUIRED":
      return "warn";
    case "FAILED":
    case "WORSENED":
    case "ESCALATED":
      return "danger";
    default:
      return "neutral";
  }
}

/** Run state -> tone. Shared across views so one state is not red on one
    screen and calm blue on another. */
function stateTone(state: string): StatusTone {
  if (state === "RESOLVED" || state === "AUDITED") return "ok";
  if (state === "AWAITING_APPROVAL" || state === "ROLLBACK") return "warn";
  if (state === "ESCALATED" || state === "BLOCKED") return "danger";
  if (state === "EXECUTING" || state === "VERIFYING") return "info";
  return "neutral";
}

export function ExecutionView() {
  const { id } = useParams<{ id: string }>();
  const modeState = useModeState();
  const mode = modeState.mode;
  // Cancellation + out-of-order protection live in the hook: an event-stream
  // refresh and an operator refresh can overlap, and the slower one must not
  // be allowed to overwrite the newer incident state.
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

  const events = useIncidentEvents({
    incidentId: id,
    enabled: run !== null && !isLoading && !isTerminalIncidentState(run.state),
    onRefresh: () => {
      void runResource.reload(false);
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
  // The real verifier output. Distinct from the transition projection below,
  // which is what this panel used to render -- so the panel titled
  // "Verification verdicts" showed state moves and the actual checks the
  // verifier ran were never displayed anywhere.
  const verdicts = run?.verification_results ?? [];
  // The FSM transitions that carry verification meaning, shown separately.
  const transitions =
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
  // Real tier from the executor. "" means the run has not executed; say so
  // rather than defaulting to a mock-looking terminal.
  const tier = run?.execution_tier ?? "";
  const tierLabel =
    tier === ""
      ? "no execution has occurred"
      : tier === "mock"
        ? "MOCK SANDBOX (in-process state dict)"
        : tier === "docker"
          ? "DOCKER (unprivileged container)"
          : tier === "k8s"
            ? "KUBERNETES"
            : tier;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Execution {id}
        </h1>
        <ModeBadge mode={mode} reason={modeState.reason} />
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
            <StatusPill tone={stateTone(run.state)}>{run.state}</StatusPill>
          </span>
        )}
      </div>

      {/* Was a navigation dead end: nothing on this page led to the run's
          evidence, its gate, or its postmortem. */}
      <IncidentNav incidentId={id ?? ""} current="execution" state={run?.state} />

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
                  No state diff recorded. The run_view projection carries one only
                  after an action actually executed in a sandbox tier; a run parked
                  at AWAITING_APPROVAL has produced no diff yet.
                </p>
              </>
            )}
          </Panel>

          {/* Executor output, labelled from the REAL tier the action ran in. */}
          <Panel
            title="Executor output"
            description="Lines returned by the executor that performed the action, with the tier it ran in."
          >
            {(run.execution_logs ?? []).length === 0 ? (
              <EmptyState
                title="No executor output recorded"
                hint="Output appears here once the action reaches EXECUTING in a sandbox tier."
              />
            ) : (
              <div className="rounded border border-line bg-surface-sunken p-3 font-mono text-xs text-fg">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2 text-fg-subtle">
                  <span>EXECUTOR · {tierLabel}</span>
                  {/* No process status is shown. The executor returns logs and
                      a state diff, never a status code, so a green success
                      badge here was a number this page invented -- and on a
                      mock tier it sat under a Kubernetes-exec header for work
                      no cluster performed. */}
                  <span>no exit code is reported by this executor</span>
                </div>
                <div className="max-h-60 space-y-1 overflow-y-auto">
                  {(run.execution_logs ?? []).map((line, idx) => (
                    <div key={idx} className="flex gap-2">
                      <span className="select-none text-fg-subtle">&gt;</span>
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
            title={`Verification verdicts (${verdicts.length})`}
            description="The independent verifier's own output. Exit status is not resolution: a verdict is the check."
          >
            {verdicts.length === 0 ? (
              <div data-testid="verdicts-empty">
                <EmptyState
                  title="No verification verdict recorded yet"
                  hint="A verdict appears here once the verifier has run, which is after EXECUTING."
                />
              </div>
            ) : (
              <ol data-testid="verdicts-list" className="text-sm">
                {verdicts.map((verdict, index) => (
                  <li
                    key={verdict.execution_id || `verdict-${String(index)}`}
                    className="border-b border-line py-2 last:border-b-0"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusPill tone={verdictTone(verdict.verdict)}>
                        {verdict.verdict === "" ? "UNKNOWN" : verdict.verdict}
                      </StatusPill>
                      {verdict.execution_id !== "" && (
                        <span className="break-all font-mono text-xs text-fg-subtle">
                          {verdict.execution_id}
                        </span>
                      )}
                      {verdict.at > 0 && (
                        <span className="text-xs text-fg-subtle">
                          {new Date(verdict.at * 1000).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                    {Object.keys(verdict.checks).length > 0 && (
                      <ul className="mt-1 flex flex-wrap gap-2 text-xs">
                        {Object.entries(verdict.checks).map(([name, passed]) => (
                          <li key={name} className="flex items-center gap-1">
                            <StatusPill tone={passed ? "ok" : "danger"}>
                              {passed ? "PASS" : "FAIL"}
                            </StatusPill>
                            <span className="font-mono text-fg-muted">{name}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {verdict.detail !== "" && (
                      <p className="mt-1 text-fg-muted">{verdict.detail}</p>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          {/* FSM transitions that carry verification meaning, kept separate so
              they are never mistaken for the verifier's output above. */}
          {transitions.length > 0 && (
            <Panel
              title={`Verification-phase transitions (${transitions.length})`}
              description="FSM moves into and out of the verification states. These are state transitions, not verdicts."
            >
              <ol className="text-sm">
                {transitions.map((transition) => (
                  <li
                    key={transition.seq}
                    className="border-b border-line py-2 last:border-b-0"
                  >
                    <span className="mr-2 text-xs tabular-nums text-fg-subtle">
                      #{transition.seq}
                    </span>
                    <span className="font-medium">
                      {transition.frm} → {transition.to}
                    </span>
                    {transition.reason !== "" && (
                      <span className="text-fg-muted"> — {transition.reason}</span>
                    )}
                  </li>
                ))}
              </ol>
            </Panel>
          )}

          <Panel
            title={`FSM execution records (${executions.length})`}
            description="Transitions projected from the run's own FSM record, not from a live cluster and not from the hash-chained audit log."
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
