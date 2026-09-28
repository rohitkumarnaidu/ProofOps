import { useCallback, useEffect, useRef, useState } from "react";
import {
  HashRouter,
  Link,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  ApiError,
  authApi,
  identityApi,
  runsApi,
  type IdentityView,
} from "./api";
import {
  Button,
  ErrorState,
  SelectField,
  TextField,
} from "./components/ui";
import { AgentsView } from "./views/AgentsView";
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

const HEADER_REFRESH_MS = 5000;

function incidentFromLocation(pathname: string, search: string): string {
  if (pathname === "/safety" || pathname === "/agents") {
    return new URLSearchParams(search).get("incident_id")?.trim() ?? "";
  }
  // `agents` belongs here as well as on the /agents/ branch below. It was
  // missing, so deep-linking or reloading on /agents/<id> parsed to "" and the
  // whole header -- including the Agent link itself -- went aria-disabled while
  // the agent view was displaying that incident.
  const match = /^\/(?:incidents|execution|rca|agents)\/([^/]+)/.exec(pathname);
  if (match === null) return "";
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

/**
 * Operator sign-in.
 *
 * Every write in this product is server-gated: ingest, the kill-switch,
 * approval request and approval decision all answer 401 without a credential.
 * `VITE_PROOFOPS_API_KEY` covers a build-time demo, but it means the shipped
 * bundle carries a shared key and there is no way to sign in as a specific
 * operator at runtime -- so the ingest form and the Safety Gate buttons were
 * present, correctly wired, and unusable in the default deployment.
 *
 * This exchanges a key for a short-lived JWT via POST /auth/token, which the
 * request layer then sends as a bearer token. The key is typed into the page
 * and exchanged; it is never written to storage, and the server remains the
 * only thing that decides who the caller is.
 */
function IdentityBar() {
  const [identity, setIdentity] = useState<IdentityView | null>(null);
  const [issue, setIssue] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setIdentity(await identityApi.view());
      setIssue("");
    } catch (error) {
      setIdentity(null);
      setIssue(error instanceof ApiError ? error.message : String(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function signIn() {
    const value = key.trim();
    if (value === "") return;
    setBusy(true);
    setIssue("");
    try {
      await authApi.login(value);
      // The key is not retained in the page: only the issued token is, and the
      // token is what every later request presents.
      setKey("");
      await refresh();
    } catch (error) {
      setIssue(
        `Sign-in rejected: ${error instanceof ApiError ? error.message : String(error)}`,
      );
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    authApi.logout();
    setIdentity(null);
    setIssue("");
    void refresh();
  }

  const signedIn = identity !== null;

  return (
    <div className="mt-2 flex flex-wrap items-end gap-2 border-t border-line pt-2">
      {signedIn ? (
        <>
          <div className="text-xs text-fg-subtle" data-testid="identity-summary">
            Signed in as <span className="font-mono text-fg">{identity.owner}</span>{" "}
            ({identity.key_id}) · identity mode{" "}
            <span className="font-semibold text-fg">{identity.mode}</span> · roles{" "}
            {identity.roles.length === 0 ? "none reported" : identity.roles.join(", ")}
          </div>
          <Button size="sm" tone="ghost" onClick={signOut} data-testid="sign-out">
            Sign out
          </Button>
        </>
      ) : (
        <div className="flex flex-wrap items-end gap-2" data-testid="sign-in">
          <TextField
            label="Operator API key"
            id="operator-api-key"
            type="password"
            autoComplete="off"
            placeholder="paste the deployment key to enable writes"
            className="w-full min-w-0 sm:w-72"
            value={key}
            onChange={(event) => setKey(event.target.value)}
          />
          <Button
            size="sm"
            tone="primary"
            onClick={() => void signIn()}
            disabled={busy || key.trim() === ""}
          >
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </div>
      )}
      {!signedIn && issue !== "" && (
        <p role="status" data-testid="identity-issue" className="w-full text-xs text-warn">
          {issue} — reads work, but every write (ingest, approval, kill-switch)
          will answer 401 until you sign in.
        </p>
      )}
    </div>
  );
}

function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef<HTMLElement>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedIncident, setSelectedIncident] = useState("");
  const [queueError, setQueueError] = useState("");

  // The header list is polled rather than fetched once. The Command Center can
  // now ingest an incident, and a list loaded only on mount meant a newly
  // created incident was not selectable from the dropdown until a full page
  // reload -- the operator could see a run in the table and not be able to
  // select it. Polled on a slow interval; the list is small.
  useEffect(() => {
    let cancelled = false;
    const load = () => {
      const pending = runsApi.list();
      void pending
        .then((items) => {
          if (cancelled) return;
          setRuns(items);
          setQueueError("");
        })
        .catch((error: unknown) => {
          if (cancelled) return;
          setRuns([]);
          setQueueError(error instanceof ApiError ? error.message : String(error));
        });
    };
    load();
    const timer = window.setInterval(load, HEADER_REFRESH_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
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
            {navLink(
              "Agent",
              isCurrent("/agents"),
              selectedPath("/agents"),
              "Select a current incident before asking the agent",
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
          <IdentityBar />
        </div>
      </header>
      <main id="main-content" ref={mainRef} tabIndex={-1} className="px-4 py-4 sm:px-6 sm:py-6">
        <Routes>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/safety" element={<SafetyGate />} />
          <Route path="/execution/:id" element={<ExecutionView />} />
      <Route path="/agents" element={<AgentsView />} />
      <Route path="/agents/:id" element={<AgentsView />} />
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
