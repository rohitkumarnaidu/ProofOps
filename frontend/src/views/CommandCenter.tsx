import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  metaApi,
  orchestratorApi,
  runsApi,
  type EngineStatus,
  type OrchestratorState,
} from "../api";
import { ModeBadge } from "../components/badges";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  Panel,
  StatusPill,
  TextField,
  type Column,
} from "../components/ui";
import { useMode } from "../components/useMode";

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

export function CommandCenter() {
  const mode = useMode();
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [creating, setCreating] = useState("");
  const [newId, setNewId] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [worker, setWorker] = useState<OrchestratorState | null>(null);
  const [engines, setEngines] = useState<EngineStatus | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const lastSubmitted = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      const [runList, engineStatus] = await Promise.all([
        runsApi.list(),
        metaApi.engines().catch(() => null),
      ]);
      setRuns(runList);
      if (engineStatus) setEngines(engineStatus);
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

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const [state, engineStatus] = await Promise.all([
          orchestratorApi.state(),
          metaApi.engines().catch(() => null),
        ]);
        if (cancelled) return;
        setWorker(state);
        if (engineStatus) setEngines(engineStatus);
        if (lastSubmitted.current !== null && lastSubmitted.current !== state.submitted) {
          await refresh();
        }
        lastSubmitted.current = state.submitted;
      } catch {
        if (!cancelled) setWorker(null);
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), WORKER_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [refresh]);

  async function create() {
    const incidentId = newId.trim();
    if (incidentId === "") return;
    setCreating("");
    try {
      await runsApi.create(incidentId);
      setNewId("");
      await refresh();
    } catch (caught) {
      setCreating(caught instanceof ApiError ? caught.message : String(caught));
    }
  }

  const hasVisibleError = error !== "";
  const awaitingHuman = runs.filter((r) => r.state === "AWAITING_APPROVAL");
  const resolvedRuns = runs.filter((r) => r.state === "RESOLVED" || r.state === "AUDITED");
  const blockedRuns = runs.filter((r) => r.state === "BLOCKED" || r.state === "ESCALATED");

  const filteredRuns = runs.filter((r) => {
    if (filter === "AWAITING_APPROVAL") return r.state === "AWAITING_APPROVAL";
    if (filter === "RESOLVED") return r.state === "RESOLVED" || r.state === "AUDITED";
    if (filter === "ACTIVE") return r.state !== "RESOLVED" && r.state !== "AUDITED";
    return true;
  });

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5">
      {/* Top Header & Liveness Badges */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 data-page-heading tabIndex={-1} className="text-2xl font-bold tracking-tight">
            ProofOps Command Center
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
          {worker !== null && (
            <StatusPill tone={worker.running && worker.enabled ? "ok" : "neutral"} title={worker.note}>
              {worker.running && worker.enabled ? "WORKER ACTIVE" : "WORKER STANDBY"}
            </StatusPill>
          )}
        </div>
        <div className="text-xs text-fg-subtle">
          Realtime Control Plane · Enterprise Edition
        </div>
      </div>

      {/* Multi-Engine Infrastructure Status Bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded border border-line bg-surface-raised p-3">
          <div className="text-xs font-semibold text-fg-subtle">DATABASE PERSISTENCE</div>
          <div className="mt-1 flex items-center justify-between">
            <span className="font-mono text-sm font-bold uppercase text-fg">
              {engines?.database?.dialect === "postgresql" ? "PostgreSQL 16" : "SQLite Durable"}
            </span>
            <StatusPill tone={engines?.database?.healthy ? "ok" : "warn"}>
              {engines?.database?.healthy ? "ONLINE" : "OFFLINE"}
            </StatusPill>
          </div>
        </div>

        <div className="rounded border border-line bg-surface-raised p-3">
          <div className="text-xs font-semibold text-fg-subtle">KUBERNETES EXECUTOR</div>
          <div className="mt-1 flex items-center justify-between">
            <span className="font-mono text-sm font-bold uppercase text-fg">
              {engines?.kubernetes?.connected ? "K8s Cluster" : "Mock Sandbox"}
            </span>
            <StatusPill tone={engines?.kubernetes?.connected ? "ok" : "info"}>
              {engines?.kubernetes?.connected ? "CONNECTED" : "SANDBOX"}
            </StatusPill>
          </div>
        </div>

        <div className="rounded border border-line bg-surface-raised p-3">
          <div className="text-xs font-semibold text-fg-subtle">PROMETHEUS TELEMETRY</div>
          <div className="mt-1 flex items-center justify-between">
            <span className="font-mono text-sm font-bold uppercase text-fg">
              {engines?.prometheus?.connected ? "PromQL Live" : "Standby"}
            </span>
            <StatusPill tone={engines?.prometheus?.connected ? "ok" : "neutral"}>
              {engines?.prometheus?.connected ? "READY" : "STANDBY"}
            </StatusPill>
          </div>
        </div>

        <div className="rounded border border-line bg-surface-raised p-3">
          <div className="text-xs font-semibold text-fg-subtle">AI WORKFORCE ENGINE</div>
          <div className="mt-1 flex items-center justify-between">
            <span className="font-mono text-sm font-bold uppercase text-fg">
              {engines?.llm_hub?.provider ? engines.llm_hub.provider.toUpperCase() : "ORACLE"}
            </span>
            <StatusPill tone={engines?.llm_hub?.status === "CONNECTED" ? "ok" : "info"}>
              {engines?.llm_hub?.status === "CONNECTED" ? "LIVE" : "DETERMINISTIC"}
            </StatusPill>
          </div>
        </div>
      </div>

      {/* KPI Overview Metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <button
          onClick={() => setFilter("ALL")}
          className={`flex flex-col rounded border p-3 text-left transition-colors ${
            filter === "ALL" ? "border-accent bg-accent/10" : "border-line bg-surface hover:bg-surface-raised"
          }`}
        >
          <span className="text-xs font-medium text-fg-muted">Total Incident Runs</span>
          <span className="text-2xl font-bold text-fg">{runs.length}</span>
        </button>

        <button
          onClick={() => setFilter("AWAITING_APPROVAL")}
          className={`flex flex-col rounded border p-3 text-left transition-colors ${
            filter === "AWAITING_APPROVAL"
              ? "border-warn bg-warn/10"
              : "border-line bg-surface hover:bg-surface-raised"
          }`}
        >
          <span className="text-xs font-medium text-warn">Awaiting Approval</span>
          <span className="text-2xl font-bold text-warn">{awaitingHuman.length}</span>
        </button>

        <button
          onClick={() => setFilter("RESOLVED")}
          className={`flex flex-col rounded border p-3 text-left transition-colors ${
            filter === "RESOLVED"
              ? "border-ok bg-ok/10"
              : "border-line bg-surface hover:bg-surface-raised"
          }`}
        >
          <span className="text-xs font-medium text-ok">Resolved & Audited</span>
          <span className="text-2xl font-bold text-ok">{resolvedRuns.length}</span>
        </button>

        <button
          onClick={() => setFilter("ACTIVE")}
          className={`flex flex-col rounded border p-3 text-left transition-colors ${
            filter === "ACTIVE"
              ? "border-danger bg-danger/10"
              : "border-line bg-surface hover:bg-surface-raised"
          }`}
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
              <span className="text-2xl">⚠️</span>
              <div>
                <h3 className="font-bold text-warn">
                  Action Required: {awaitingHuman.length} Incident(s) Awaiting Human Authorization
                </h3>
                <p className="text-xs text-fg-muted">
                  A remediation plan proposed a reversible YELLOW action. Server-side single-use HMAC token is awaiting Incident Commander review.
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

      {/* Open Incident Input */}
      <Panel
        title="Trigger an Incident Run"
        description="Submit a new incident for autonomous triage, evidence pre-digestion, diagnosis, and policy evaluation."
      >
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void create();
          }}
        >
          <TextField
            label="Incident ID"
            id="new-incident"
            placeholder="e.g. prod-payments-oom-23"
            className="w-full min-w-0 sm:w-80"
            value={newId}
            onChange={(event) => setNewId(event.target.value)}
          />
          <Button type="submit" tone="primary" disabled={newId.trim() === ""}>
            Open Incident
          </Button>
        </form>
        {creating !== "" && (
          <p role="alert" className="mt-3 text-sm font-semibold text-danger">
            Run creation failed: {creating}
          </p>
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
            hint="Trigger an incident above or wait for the autonomous orchestrator worker."
          />
        </div>
      ) : (
        <Panel
          title={`Incident Runs (${filter})`}
          description="Updated live via background worker polling and SSE event synchronization."
        >
          <DataTable
            testId="queue-table"
            caption="Open incident runs"
            columns={COLUMNS}
            rows={filteredRuns}
            rowKey={(run) => run.incident_id}
            empty="No incident runs."
          />
        </Panel>
      )}
    </div>
  );
}
