import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, orchestratorApi, runsApi, type OrchestratorState } from "../api";
import { ModeBadge } from "../components/badges";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  Notice,
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
    // The state IS the live signal, so it gets a pill rather than plain text.
    render: (run) => <StatusPill tone={toneFor(run.state)}>{run.state}</StatusPill>,
  },
  {
    key: "transitions",
    header: "Transitions",
    numeric: true,
    render: (run) => run.history_len,
  },
];

/** Run state -> tone. Waiting on a human is amber, not red: nothing is broken. */
function toneFor(state: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  if (state === "RESOLVED" || state === "AUDITED") return "ok";
  if (state === "AWAITING_APPROVAL" || state === "ROLLBACK") return "warn";
  if (state === "ESCALATED" || state === "BLOCKED") return "danger";
  if (state === "EXECUTING" || state === "VERIFYING") return "info";
  return "neutral";
}

/** How often to ask the worker whether it did anything. Cheap, read-only. */
const WORKER_POLL_MS = 4000;

export function CommandCenter() {
  const mode = useMode();
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [creating, setCreating] = useState("");
  const [newId, setNewId] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [worker, setWorker] = useState<OrchestratorState | null>(null);
  // Tracks the worker's submitted counter so the run list is re-fetched only
  // when the control plane actually did something.
  const lastSubmitted = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      setRuns(await runsApi.list());
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

  // The liveness loop. Polls the worker's counters; when `submitted` changes,
  // the queue is re-fetched. This is what makes the page alive without a
  // reload: incidents now arrive and advance on their own.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const state = await orchestratorApi.state();
        if (cancelled) return;
        setWorker(state);
        if (lastSubmitted.current !== null &&
            lastSubmitted.current !== state.submitted) {
          await refresh();
        }
        lastSubmitted.current = state.submitted;
      } catch {
        // A failed poll is not a page-level failure: the run list is still
        // valid, and a loud banner for a transient blip would be noise.
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

  const hasVisibleError = error !== "" || creating !== "";
  const awaitingHuman = runs.filter((r) => r.state === "AWAITING_APPROVAL").length;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Command Center
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
          <span data-testid="worker-status" className="inline-flex items-center gap-2">
            <StatusPill
              tone={worker.running && worker.enabled ? "ok" : "neutral"}
              title={worker.note}
            >
              {worker.running && worker.enabled ? "worker live" : "worker stopped"}
            </StatusPill>
            <span className="text-xs text-fg-subtle">
              {worker.processed + worker.stalled + worker.blocked} processed
              {awaitingHuman > 0 ? ` · ${awaitingHuman} awaiting human` : ""}
            </span>
          </span>
        )}
      </div>

      {/* Honest about what is real and what is scripted. The worker never
          approves, so "awaiting human" is the expected resting state, not a
          stall. */}
      {worker !== null && worker.mode === "scripted-oracle" && (
        <Notice tone="info" testId="oracle-notice">
          Agent reasoning is <strong>scripted-oracle</strong> (no Lyzr key
          configured). The validator, policy engine, FSM, sandbox, verifier and
          hash-chained audit are real, and the worker never approves anything —
          incidents stop at <code>AWAITING_APPROVAL</code> for a human.
        </Notice>
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

      <Panel
        title="Open a run"
        description="Seeds an incident for the orchestrator to drive. Leave it to the worker if you want the full real-time path."
      >
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            void create();
          }}
        >
          <TextField
            label="New incident id"
            id="new-incident"
            placeholder="incident id"
            className="w-full min-w-0 sm:w-64"
            value={newId}
            onChange={(event) => setNewId(event.target.value)}
          />
          <Button type="submit" tone="primary" disabled={newId.trim() === ""}>
            Open run
          </Button>
        </form>
        {creating !== "" && (
          <p role="alert" className="mt-3 text-sm font-semibold text-danger">
            Run creation failed: {creating}
          </p>
        )}
      </Panel>

      {isLoading ? (
        <div data-testid="queue-loading" aria-busy="true">
          <LoadingState label="Loading runs" />
        </div>
      ) : hasVisibleError ? null : runs.length === 0 ? (
        <div data-testid="queue-empty">
          <EmptyState
            title="No open runs"
            hint="The orchestrator seeds incidents on its own. Create one above if you want to drive a specific id."
          />
        </div>
      ) : (
        <Panel
          title="Open incident runs"
          description="Updated live: this list re-fetches whenever the control plane does work."
        >
          <DataTable
            testId="queue-table"
            caption="Open incident runs"
            columns={COLUMNS}
            rows={runs}
            rowKey={(run) => run.incident_id}
            empty="No open runs."
          />
        </Panel>
      )}
    </div>
  );
}
