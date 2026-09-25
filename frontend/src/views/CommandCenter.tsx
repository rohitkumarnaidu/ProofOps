import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, runsApi } from "../api";
import { ModeBadge } from "../components/badges";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  Panel,
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
  { key: "state", header: "State", render: (run) => run.state },
  {
    key: "transitions",
    header: "Transitions",
    numeric: true,
    render: (run) => run.history_len,
  },
];

export function CommandCenter() {
  const mode = useMode();
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState("");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [creating, setCreating] = useState("");
  const [newId, setNewId] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  async function refresh() {
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
  }

  useEffect(() => {
    void refresh();
  }, []);

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
      </div>

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
        description="A run is the control-plane record for one incident. Creating one here is a real server-side mutation."
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
          {/* submit, not a click handler: the field is in a form, so Enter now
              does the obvious thing and a future browser autofill works. */}
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
            hint="Create one above, or seed the demo backend first."
          />
        </div>
      ) : (
        <Panel>
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
