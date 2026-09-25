import { useEffect, useRef, useState } from "react";
import {
  HashRouter,
  Link,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { ApiError, runsApi } from "./api";
import { ErrorState, SelectField } from "./components/ui";
import { CommandCenter } from "./views/CommandCenter";
import { ExecutionView } from "./views/ExecutionView";
import { IncidentDetail } from "./views/IncidentDetail";
import { RCAView } from "./views/RCAView";
import { SafetyGate } from "./views/SafetyGate";

interface RunSummary {
  incident_id: string;
  state: string;
  history_len: number;
}

function incidentFromLocation(pathname: string, search: string): string {
  if (pathname === "/safety") {
    return new URLSearchParams(search).get("incident_id")?.trim() ?? "";
  }
  const match = /^\/(?:incidents|execution|rca)\/([^/]+)/.exec(pathname);
  if (match === null) return "";
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef<HTMLElement>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedIncident, setSelectedIncident] = useState("");
  const [queueError, setQueueError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void runsApi.list().then((items) => {
      if (!cancelled) {
        setRuns(items);
        setQueueError("");
      }
    })
      .catch((error: unknown) => {
        if (!cancelled) {
          setRuns([]);
          setQueueError(error instanceof ApiError ? error.message : String(error));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const routeIncident = incidentFromLocation(
      location.pathname,
      location.search,
    );
    if (routeIncident !== "") setSelectedIncident(routeIncident);
  }, [location.pathname, location.search]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("[data-page-heading]")?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [location.pathname, location.search]);

  const incidentPath = (prefix: string, incidentId: string) =>
    `${prefix}/${encodeURIComponent(incidentId)}`;
  const selectedPath = (prefix: string) =>
    incidentPath(prefix, selectedIncident);
  const safetyPath = `/safety?incident_id=${encodeURIComponent(selectedIncident)}`;
  const chooseIncident = (incidentId: string) => {
    setSelectedIncident(incidentId);
    navigate(incidentId === "" ? "/" : incidentPath("/incidents", incidentId));
  };
  const isCurrent = (prefix: string) =>
    location.pathname === prefix || location.pathname.startsWith(`${prefix}/`);

  const navLink = (
    label: string,
    active: boolean,
    to: string,
    disabledLabel: string,
  ) =>
    selectedIncident === "" ? (
      <span
        key={label}
        role="link"
        aria-disabled="true"
        aria-label={disabledLabel}
        className="cursor-not-allowed px-2 py-2 text-fg-subtle"
      >
        {label}
      </span>
    ) : (
      <Link
        key={label}
        to={to}
        aria-current={active ? "page" : undefined}
        aria-label={active ? `${label}, current page` : undefined}
        className="rounded px-2 py-2 text-fg-muted hover:bg-surface-raised hover:text-fg hover:underline"
      >
        {label}
      </Link>
    );

  return (
    <div className="min-h-screen">
      <a
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
        className="skip-link"
      >
        Skip to main content
      </a>
      <header className="border-b border-line px-4 py-3 sm:px-6">
        <nav aria-label="Primary">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <Link
              to="/"
              className="mr-1 font-bold tracking-tight text-accent"
            >
              ProofOps
            </Link>
            <Link
              to="/"
              aria-current={location.pathname === "/" ? "page" : undefined}
              className={`rounded px-2 py-2 ${
                location.pathname === "/"
                  ? "bg-surface-raised font-semibold text-fg"
                  : "text-fg-muted hover:bg-surface-raised hover:text-fg"
              }`}
            >
              Command Center
            </Link>
            {navLink(
              "Incident",
              isCurrent("/incidents"),
              selectedPath("/incidents"),
              "Select a current incident before opening Incident Detail",
            )}
            {navLink(
              "Safety Gate",
              isCurrent("/safety"),
              safetyPath,
              "Select a current incident before opening Safety Gate",
            )}
            {navLink(
              "Execution",
              isCurrent("/execution"),
              selectedPath("/execution"),
              "Select a current incident before opening Execution",
            )}
            {navLink(
              "Audit & Eval",
              isCurrent("/rca"),
              selectedPath("/rca"),
              "Select a current incident before opening Audit and Evaluation",
            )}
          </div>
        </nav>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <SelectField
            label="Current incident"
            id="current-incident"
            className="w-full min-w-0 sm:w-auto sm:min-w-56"
            value={selectedIncident}
            onChange={(event) => chooseIncident(event.target.value)}
            error={queueError === "" ? null : `Incident list unavailable: ${queueError}`}
          >
            <option value="">Select an incident</option>
            {selectedIncident !== "" &&
              !runs.some((run) => run.incident_id === selectedIncident) && (
                <option value={selectedIncident}>{selectedIncident}</option>
              )}
            {runs.map((run) => (
              <option key={run.incident_id} value={run.incident_id}>
                {run.incident_id} · {run.state}
              </option>
            ))}
          </SelectField>
        </div>
      </header>
      <main id="main-content" ref={mainRef} tabIndex={-1} className="px-4 py-4 sm:px-6 sm:py-6">
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/safety" element={<SafetyGate />} />
          <Route path="/execution/:id" element={<ExecutionView />} />
          <Route path="/rca/:id" element={<RCAView />} />
          <Route path="*" element={<RouteNotFound />} />
        </Routes>
      </main>
    </div>
  );
}

function RouteNotFound() {
  return (
    <section className="mx-auto max-w-3xl">
      <ErrorState
        testId="route-404"
        title="Page not found"
        detail="This route does not exist. Use the primary navigation to open a real operator view."
      />
    </section>
  );
}

export function App() {
  return (
    <HashRouter>
      <AppShell />
    </HashRouter>
  );
}
