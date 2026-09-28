import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  DEFAULT_SLO_ERROR_RATE_BELOW,
  fetchHealth,
  INGEST_SCENARIOS,
  ingestApi,
  metaApi,
  orchestratorApi,
  runsApi,
  type EngineStatus,
  type IngestResult,
  type Meta,
  type OrchestratorState,
  type SloAlert,
  sloApi,
} from "../api";
import { ModeBadge } from "../components/badges";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Notice,
  Panel,
  SelectField,
  StatusPill,
  TextField,
  type Column,
} from "../components/ui";
import { useModeState } from "../components/useMode";

interface RunSummary {
  incident_id: string;
  state: string;
  history_len: number;
}

const COLUMNS: Array<Column<RunSummary>> = [
  {
    key: "incident",
    header: "Incident",
    render: (run) => (
      <Link
        to={`/incidents/${encodeURIComponent(run.incident_id)}`}
        className="font-medium text-accent underline"
      >
        {run.incident_id}
      </Link>
    ),
  },
  {
    key: "state",
    header: "State",
    render: (run) => <StatusPill tone={toneFor(run.state)}>{run.state}</StatusPill>,
  },
  {
    key: "transitions",
    header: "Transitions",
    numeric: true,
    render: (run) => run.history_len,
  },
  {
    key: "actions",
    header: "Actions",
    render: (run) => (
      <div className="flex items-center gap-2">
        <Link
          to={`/incidents/${encodeURIComponent(run.incident_id)}`}
          className="text-xs text-accent underline"
        >
          Open run
        </Link>
        {run.state === "AWAITING_APPROVAL" && (
          <Link
            to={`/safety?incident_id=${encodeURIComponent(run.incident_id)}`}
            className="rounded border border-warn bg-warn/10 px-2 py-0.5 text-xs font-semibold text-warn hover:bg-warn/20"
          >
            Gate
          </Link>
        )}
      </div>
    ),
  },
];

function toneFor(state: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  if (state === "RESOLVED" || state === "AUDITED") return "ok";
  if (state === "AWAITING_APPROVAL" || state === "ROLLBACK") return "warn";
  if (state === "ESCALATED" || state === "BLOCKED") return "danger";
  if (state === "EXECUTING" || state === "VERIFYING") return "info";
  return "neutral";
}

const WORKER_POLL_MS = 3000;

/**
 * One engine's honest state.
 *
 * `unknown` is a real, distinct outcome: it means we did not successfully ask.
 * Collapsing it into "offline"/"mock" made a 401 or a 500 render as a measured
 * statement about the deployment, which is worse than showing nothing.
 */
type EngineCell = {
  label: string;
  detail: string;
  tone: "ok" | "warn" | "danger" | "info" | "neutral";
  status: string;
  note?: string | null;
};

function unknownCell(what: string): EngineCell {
  return {
    label: "unknown",
    detail: "not reported by the backend",
    tone: "neutral",
    status: "UNKNOWN",
    note: what,
  };
}

function engineCells(engines: EngineStatus | null, failed: boolean): EngineCell[] {
  if (engines === null) {
    // Distinguish "not loaded yet" from "the ask failed": the operator needs to
    // know whether the blank tile is pending or broken.
    return failed
      ? [
          unknownCell("engine status request failed"),
          unknownCell("engine status request failed"),
          unknownCell("engine status request failed"),
          unknownCell("engine status request failed"),
        ]
      : [
          unknownCell("loading"),
          unknownCell("loading"),
          unknownCell("loading"),
          unknownCell("loading"),
        ];
  }

  const db = engines.database;
  // A degraded audit store is a WORKING fallback, not a healthy Postgres. It
  // must not render as a green ONLINE badge, or "healthy" silently means
  // "healthy on a file instead of on the database you think you have".
  const dbCell: EngineCell = db.healthy
    ? {
        label: db.degraded ? `${db.dialect} (degraded)` : db.dialect,
        detail: db.degraded
          ? `fallback_reason: ${db.fallback_reason ?? "not reported"}`
          : db.database,
        tone: db.degraded ? "warn" : "ok",
        status: db.degraded ? "DEGRADED" : "ONLINE",
        note: db.degraded
          ? "audit trail is NOT in Postgres; local durable store in use"
          : null,
      }
    : {
        label: db.dialect,
        detail: db.error ?? "not reachable",
        tone: "danger",
        status: "OFFLINE",
        note: db.error,
      };

  const k8s = engines.kubernetes;
  const k8sCell: EngineCell = k8s.connected
    ? {
        label: `k8s ${k8s.version ?? ""}`.trim(),
        detail: `${k8s.host ?? "host not reported"} ns=${k8s.namespace ?? "?"}`,
        tone: "ok",
        status: k8s.tier.toUpperCase(),
      }
    : {
        label: k8s.tier || "no cluster",
        detail: k8s.error ?? k8s.host ?? "no reachable cluster",
        tone: "info",
        status: k8s.tier ? k8s.tier.toUpperCase() : "NO CLUSTER",
        note: k8s.error,
      };

  const prom = engines.prometheus;
  const promCell: EngineCell = prom.connected
    ? {
        label: "PromQL",
        detail: prom.url,
        tone: "ok",
        status: prom.tier.toUpperCase(),
      }
    : {
        label: "sandbox",
        detail: prom.error ?? "no Prometheus; verification falls back to sandbox state",
        tone: "info",
        status: "STANDBY",
        note: prom.error,
      };

  // status is a closed union of "UNVERIFIED" | "OFFLINE". There is no
  // "CONNECTED": a provider is never a verified live connection just because a
  // key is present. Say what is actually true.
  const llm = engines.llm_hub;
  const llmCell: EngineCell =
    llm.status === "UNVERIFIED"
      ? {
          label: llm.provider || "unconfigured",
          detail: `${llm.tier}: key present, connection not verified`,
          tone: "info",
          status: "UNVERIFIED",
        }
      : {
          label: llm.provider || "none",
          detail: `${llm.tier}: no usable provider`,
          tone: "warn",
          status: "OFFLINE",
        };

  return [dbCell, k8sCell, promCell, llmCell];
}

const TILE_TITLES = [
  "DATABASE PERSISTENCE",
  "KUBERNETES EXECUTOR",
  "PROMETHEUS TELEMETRY",
  "AI WORKFORCE ENGINE",
];

export function CommandCenter() {
  const modeState = useModeState();
  const mode = modeState.mode;
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [worker, setWorker] = useState<OrchestratorState | null>(null);
  const [workerError, setWorkerError] = useState("");
  const [engines, setEngines] = useState<EngineStatus | null>(null);
  const [enginesFailed, setEnginesFailed] = useState(false);
  /** API process liveness, distinct from dependency health. */
  const [apiAlive, setApiAlive] = useState<boolean | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [sloAlerts, setSloAlerts] = useState<SloAlert[] | null>(null);
  const [filter, setFilter] = useState<string>("ALL");

  // --- incident launch state (the front door) --------------------------------
  const [newId, setNewId] = useState("");
  const [scenario, setScenario] = useState<string>(INGEST_SCENARIOS[0].id);
  const [service, setService] = useState("");
  const [env, setEnv] = useState("prod");
  const [signature, setSignature] = useState("HTTP5xx");
  const [errorRate, setErrorRate] = useState("0.42");
  const [processNow, setProcessNow] = useState(true);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState("");
  const [launchResult, setLaunchResult] = useState<IngestResult | null>(null);
  const [stopping, setStopping] = useState(false);
  const [stopResult, setStopResult] = useState("");

  const lastSubmitted = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      const runList = await runsApi.list();
      setRuns(runList);
      setError("");
      setErrorStatus(null);
    } catch (caught) {
      setRuns([]);
      setError(caught instanceof ApiError ? caught.message : String(caught));
      setErrorStatus(caught instanceof ApiError ? caught.status : 0);
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Engine status is fetched on its own so a failure is recorded rather than
   * swallowed into `null`. `metaApi.engines().catch(() => null)` used to make a
   * 401/500 indistinguishable from "not loaded", and every tile then rendered
   * its negative branch as if it had been measured.
   *
   * Liveness is probed separately and deliberately: /healthz answers while
   * dependencies are down (correct for a liveness probe), so "the API process
   * is alive" and "the control plane's dependencies are healthy" are two
   * different facts and the operator needs to see which one failed.
   */
  const refreshEngines = useCallback(async () => {
    try {
      const [engineStatus, metaStatus, alerts, health] = await Promise.all([
        metaApi.engines(),
        metaApi.meta().catch(() => null),
        sloApi.alerts().catch(() => null),
        fetchHealth()
          .then(() => true)
          .catch(() => false),
      ]);
      setEngines(engineStatus);
      setEnginesFailed(false);
      setApiAlive(health);
      if (metaStatus) setMeta(metaStatus);
      // null means the SLO endpoint failed; leave the prior value and let the
      // panel say "unavailable" rather than pretending there are no alerts.
      if (alerts !== null) setSloAlerts(alerts);
    } catch {
      setEngines(null);
      setEnginesFailed(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    void refreshEngines();
  }, [refreshEngines]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const state = await orchestratorApi.state();
        if (cancelled) return;
        setWorker(state);
        setWorkerError("");
        if (lastSubmitted.current !== null && lastSubmitted.current !== state.submitted) {
          await refresh();
        }
        lastSubmitted.current = state.submitted;
      } catch (caught) {
        // Surface it. Hiding the worker pill made a failure look like
        // "no worker configured", which is a different (and wrong) statement.
        if (cancelled) return;
        setWorker(null);
        setWorkerError(caught instanceof ApiError ? caught.message : String(caught));
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), WORKER_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [refresh]);

  /**
   * Submit a real telemetry bundle.
   *
   * This is the only path that drives the pipeline. The form collects the
   * OBSERVED facts (which service, which environment, what error signature,
   * what error rate) and the server derives everything else -- severity,
   * fingerprint, SLO breach, evidence ids, the plan, the policy verdict --
   * from real deterministic code. Previously this form called POST /runs,
   * which opens an empty run in state NEW and never moves it, so nothing was
   * ever triaged, diagnosed or planned.
   */
  async function launch() {
    const incidentId = newId.trim();
    if (incidentId === "") return;
    const rate = Number.parseFloat(errorRate);
    if (!Number.isFinite(rate) || rate < 0) {
      setLaunchError("Error rate must be a non-negative number (0..1 as a fraction).");
      return;
    }
    setLaunching(true);
    setLaunchError("");
    setLaunchResult(null);
    try {
      const result = await ingestApi.submit({
        incident_id: incidentId,
        scenario,
        telemetry: {
          service: service.trim() === "" ? "checkout-api" : service.trim(),
          env: env.trim() === "" ? "prod" : env.trim(),
          error_signature: signature.trim() === "" ? "HTTP5xx" : signature.trim(),
          metrics: [{ name: "error_rate", value: rate }],
          slo: { error_rate_below: DEFAULT_SLO_ERROR_RATE_BELOW },
        },
        process: processNow,
      });
      setLaunchResult(result);
      setNewId("");
      await refresh();
    } catch (caught) {
      setLaunchError(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setLaunching(false);
    }
  }

  async function stopWorker() {
    setStopping(true);
    setStopResult("");
    try {
      const res = await ingestApi.stop();
      setStopResult(
        res.stopped
          ? "Kill-switch engaged: the orchestrator no longer accepts or drives incidents."
          : "Stop request did not report success.",
      );
    } catch (caught) {
      setStopResult(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setStopping(false);
    }
  }

  const hasVisibleError = error !== "";
  const awaitingHuman = runs.filter((r) => r.state === "AWAITING_APPROVAL");
  const resolvedRuns = runs.filter((r) => r.state === "RESOLVED" || r.state === "AUDITED");
  const blockedRuns = runs.filter((r) => r.state === "BLOCKED" || r.state === "ESCALATED");

  // The KPI number and the table it opens must agree. "Blocked / Escalated"
  // previously counted blocked runs but then filtered to every non-resolved
  // run, so the number and the data disagreed.
  const filteredRuns = runs.filter((r) => {
    if (filter === "AWAITING_APPROVAL") return r.state === "AWAITING_APPROVAL";
    if (filter === "RESOLVED") return r.state === "RESOLVED" || r.state === "AUDITED";
    if (filter === "BLOCKED") return r.state === "BLOCKED" || r.state === "ESCALATED";
    return true;
  });

  const cells = engineCells(engines, enginesFailed);
  const kpi = (active: boolean) =>
    `flex flex-col rounded border p-3 text-left transition-colors ${
      active
        ? "border-accent bg-accent/10"
        : "border-line bg-surface hover:bg-surface-raised"
    }`;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5">
      {/* Top Header & Liveness Badges */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 data-page-heading tabIndex={-1} className="text-2xl font-bold tracking-tight">
            ProofOps Command Center
          </h1>
          <ModeBadge mode={mode} reason={modeState.reason} />
          {mode === null && (
            <span
              data-testid="mode-probing"
              aria-busy="true"
              className="text-xs text-fg-subtle"
            >
              probing backendÃ¢â‚¬Â¦
            </span>
          )}
          {worker !== null && (
            <StatusPill tone={worker.running && worker.enabled ? "ok" : "neutral"} title={worker.note}>
              {worker.running && worker.enabled ? "WORKER ACTIVE" : "WORKER STANDBY"}
            </StatusPill>
          )}
        </div>
        {/* Real deployment mode from GET /meta, not a marketing label. */}
        <div className="text-xs text-fg-subtle">
          {meta === null
            ? "deployment mode: not reported"
            : `deployment mode: ${meta.mode} Ã‚Â· executor: ${meta.executor_tier}`}
        </div>
      </div>

      {enginesFailed && (
        <Notice tone="warn" testId="engines-unavailable">
          Engine status could not be read. The tiles below show UNKNOWN, not a
          guess. Retry to re-read them.
        </Notice>
      )}
      {apiAlive === false && (
        <Notice tone="danger" testId="api-unreachable">
          The API process is not answering its liveness probe. Engine tiles
          below are not evidence about the deployment.
        </Notice>
      )}
      {workerError !== "" && (
        <Notice tone="danger" testId="worker-unavailable">
          Orchestrator status unavailable: {workerError}
        </Notice>
      )}

      {/* Multi-Engine Infrastructure Status Bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {cells.map((cell, i) => (
          <div key={TILE_TITLES[i]} className="rounded border border-line bg-surface-raised p-3">
            <div className="text-xs font-semibold text-fg-subtle">{TILE_TITLES[i]}</div>
            <div className="mt-1 flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
              <span
                className="min-w-0 break-words font-mono text-sm font-bold uppercase text-fg"
                title={cell.detail}
              >
                {cell.label}
              </span>
              <StatusPill tone={cell.tone}>{cell.status}</StatusPill>
            </div>
            <p className="mt-1 break-words text-[11px] text-fg-subtle">{cell.detail}</p>
            {cell.note ? (
              <p className="mt-0.5 text-[11px] font-medium text-warn">{cell.note}</p>
            ) : null}
          </div>
        ))}
      </div>

      {/* Orchestrator worker: real counters, real reasoning mode, kill-switch */}
      <Panel
        title="Incident Orchestrator"
        description="The worker that turns an ingested bundle into a governed run. Counters are the server's own."
        actions={
          <Button
            size="sm"
            tone="danger"
            onClick={() => void stopWorker()}
            disabled={stopping || worker?.enabled === false}
          >
            {stopping ? "StoppingÃ¢â‚¬Â¦" : "Engage kill-switch"}
          </Button>
        }
      >
        {worker === null ? (
          <p className="text-sm text-fg-muted">
            {workerError !== ""
              ? "Worker state unavailable (see the notice above)."
              : "Reading worker stateÃ¢â‚¬Â¦"}
          </p>
        ) : (
          <KeyValue
            items={[
              ["Reasoning mode", <StatusPill tone="info" key="m">{worker.mode}</StatusPill>],
              [
                "Status",
                worker.enabled
                  ? worker.running
                    ? "running and accepting incidents"
                    : "enabled but not running"
                  : "disabled (kill-switch engaged)",
              ],
              ["Auto-generate", worker.auto_generate ? "on" : "off"],
              [
                "Counters",
                `submitted ${worker.submitted} Ã‚Â· processed ${worker.processed} Ã‚Â· blocked ${worker.blocked} Ã‚Â· failed ${worker.failed} Ã‚Â· stalled ${worker.stalled} Ã‚Â· duplicates suppressed ${worker.duplicates_suppressed}`,
              ],
              ["Queue depth", String(worker.queue_depth)],
              [
                "Last incident",
                worker.last_incident === "" ? "none yet" : worker.last_incident,
              ],
              ["Last outcome", worker.last_outcome === "" ? "none yet" : worker.last_outcome],
              ["Note", worker.note],
            ]}
          />
        )}
        {stopResult !== "" && (
          <p role="status" className="mt-3 text-sm font-medium text-fg">
            {stopResult}
          </p>
        )}
      </Panel>

      {/* SLO alerting */}
      {sloAlerts !== null && sloAlerts.length > 0 && (
        <Panel
          title="Control-plane SLO alerts"
          description="From GET /alerts, evaluated against the versioned SLO config."
        >
          <ul className="flex flex-col gap-2 text-sm">
            {sloAlerts.map((alert) => (
              <li key={alert.name} className="flex flex-wrap items-center gap-2">
                <StatusPill tone={alert.state === "firing" ? "danger" : "ok"}>
                  {alert.state.toUpperCase()}
                </StatusPill>
                <span className="font-medium text-fg">{alert.name}</span>
                <span className="font-mono text-xs text-fg-muted">
                  {alert.metric} {alert.op}{" "}
                  {alert.target === null ? "no target" : alert.target} Ã‚Â· observed{" "}
                  {alert.observed === null ? "no data" : alert.observed} Ã‚Â·{" "}
                  {alert.window}
                </span>
                {alert.severity !== "none" && (
                  <StatusPill tone="warn">{alert.severity}</StatusPill>
                )}
                <span className="text-xs text-fg-subtle">{alert.note}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* KPI Overview Metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <button onClick={() => setFilter("ALL")} className={kpi(filter === "ALL")}>
          <span className="text-xs font-medium text-fg-muted">Total Incident Runs</span>
          <span className="text-2xl font-bold text-fg">{runs.length}</span>
        </button>

        <button
          onClick={() => setFilter("AWAITING_APPROVAL")}
          className={
            filter === "AWAITING_APPROVAL"
              ? "flex flex-col rounded border border-warn bg-warn/10 p-3 text-left"
              : "flex flex-col rounded border border-line bg-surface p-3 text-left hover:bg-surface-raised"
          }
        >
          <span className="text-xs font-medium text-warn">Awaiting Approval</span>
          <span className="text-2xl font-bold text-warn">{awaitingHuman.length}</span>
        </button>

        <button
          onClick={() => setFilter("RESOLVED")}
          className={
            filter === "RESOLVED"
              ? "flex flex-col rounded border border-ok bg-ok/10 p-3 text-left"
              : "flex flex-col rounded border border-line bg-surface p-3 text-left hover:bg-surface-raised"
          }
        >
          <span className="text-xs font-medium text-ok">Resolved &amp; Audited</span>
          <span className="text-2xl font-bold text-ok">{resolvedRuns.length}</span>
        </button>

        <button
          onClick={() => setFilter("BLOCKED")}
          className={
            filter === "BLOCKED"
              ? "flex flex-col rounded border border-danger bg-danger/10 p-3 text-left"
              : "flex flex-col rounded border border-line bg-surface p-3 text-left hover:bg-surface-raised"
          }
        >
          <span className="text-xs font-medium text-danger">Blocked / Escalated</span>
          <span className="text-2xl font-bold text-danger">{blockedRuns.length}</span>
        </button>
      </div>

      {/* High-Urgency Safety Gate Action Banner */}
      {awaitingHuman.length > 0 && (
        <div className="rounded border-2 border-warn bg-warn/10 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span aria-hidden="true" className="text-2xl font-bold text-warn">!</span>
              <div>
                <h3 className="font-bold text-warn">
                  Action Required: {awaitingHuman.length} Incident(s) Awaiting Human Authorization
                </h3>
                {/* State-derived only. The action type, risk tier and token state
                    are unknown until the Safety Gate reads the parked proposal,
                    so this says exactly that instead of asserting "reversible
                    YELLOW action with an HMAC token waiting". */}
                <p className="text-xs text-fg-muted">
                  These runs are parked at AWAITING_APPROVAL. Open the Safety Gate
                  to read the exact proposed action, its policy risk tier and its
                  scope before deciding.
                </p>
              </div>
            </div>
            <Link
              to={`/safety?incident_id=${encodeURIComponent(awaitingHuman[0].incident_id)}`}
              className="rounded bg-warn px-4 py-2 text-sm font-bold text-black shadow hover:brightness-110"
            >
              Open Safety Gate ({awaitingHuman[0].incident_id})
            </Link>
          </div>
        </div>
      )}

      {error !== "" && (
        <div data-testid="queue-error">
          <ErrorState
            title={errorStatus === 404 ? "Run queue not found" : "Queue unavailable"}
            detail={error}
            onRetry={() => void refresh()}
          />
        </div>
      )}

      {/* Ingest an incident -- the real front door */}
      <Panel
        title="Ingest an incident"
        description="Submit an observed telemetry bundle. The orchestrator drives real triage, evidence pre-digestion, diagnosis and policy evaluation. Severity, fingerprint, SLO breach and the plan are all derived server-side from the numbers below."
      >
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void launch();
          }}
        >
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <TextField
              label="Incident ID"
              id="new-incident"
              placeholder="prod-payments-bad-deploy-01"
              className="w-full min-w-0"
              value={newId}
              onChange={(event) => setNewId(event.target.value)}
            />
            <SelectField
              label="Scenario (pinned runbook + oracle)"
              id="new-scenario"
              className="w-full min-w-0"
              value={scenario}
              onChange={(event) => setScenario(event.target.value)}
            >
              {INGEST_SCENARIOS.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </SelectField>
            <TextField
              label="Service"
              id="new-service"
              placeholder="checkout-api"
              className="w-full min-w-0"
              value={service}
              onChange={(event) => setService(event.target.value)}
            />
            <TextField
              label="Environment"
              id="new-env"
              placeholder="prod"
              className="w-full min-w-0"
              value={env}
              onChange={(event) => setEnv(event.target.value)}
            />
            <TextField
              label="Error signature"
              id="new-signature"
              placeholder="HTTP5xx"
              className="w-full min-w-0"
              value={signature}
              onChange={(event) => setSignature(event.target.value)}
            />
            <TextField
              label="Observed error rate (fraction 0..1)"
              id="new-error-rate"
              hint={`Compared against the SLO threshold ${DEFAULT_SLO_ERROR_RATE_BELOW}.`}
              className="w-full min-w-0"
              value={errorRate}
              onChange={(event) => setErrorRate(event.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="process-now"
              className="h-4 w-4"
              checked={processNow}
              onChange={(event) => setProcessNow(event.target.checked)}
            />
            <label htmlFor="process-now" className="text-sm text-fg-muted">
              Drive the pipeline now (uncheck to accept the bundle for inspection
              without running the control plane over it)
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" tone="primary" disabled={launching || newId.trim() === ""}>
              {launching ? "IngestingÃ¢â‚¬Â¦" : "Ingest incident"}
            </Button>
            <Button
              type="button"
              tone="ghost"
              onClick={() => void refresh()}
              disabled={isLoading}
            >
              Refresh runs
            </Button>
          </div>
        </form>
        {launchError !== "" && (
          <p role="alert" data-testid="ingest-error" className="mt-3 text-sm font-semibold text-danger">
            Ingest failed: {launchError}
          </p>
        )}
        {launchResult !== null && (
          <div data-testid="ingest-result" className="mt-3">
            <Notice
              tone={launchResult.processed ? "ok" : "info"}
              title={
                launchResult.processed
                  ? `Incident ${launchResult.incident_id} queued`
                  : `Incident ${launchResult.incident_id} accepted, not processed`
              }
            >
              {launchResult.detail}
              {launchResult.mode ? ` (reasoning mode: ${launchResult.mode})` : ""}
            </Notice>
          </div>
        )}
      </Panel>

      {/* Filter Tabs and Incident Runs Table */}
      {isLoading ? (
        <div data-testid="queue-loading" aria-busy="true">
          <LoadingState label="Loading runs" />
        </div>
      ) : hasVisibleError ? null : runs.length === 0 ? (
        <div data-testid="queue-empty">
          <EmptyState
            title="No incident runs yet"
            hint="Ingest a bundle above, or wait for the orchestrator's auto-generate to submit one."
          />
        </div>
      ) : (
        <Panel
          title={`Incident Runs (${filter})`}
          description="Refreshed on the worker's submitted counter and by the operator's Refresh button."
        >
          <DataTable
            testId="queue-table"
            caption="Open incident runs"
            columns={COLUMNS}
            rows={filteredRuns}
            rowKey={(run) => run.incident_id}
            empty="No incident runs match this filter."
          />
        </Panel>
      )}
    </div>
  );
}
