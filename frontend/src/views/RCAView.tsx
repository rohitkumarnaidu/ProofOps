import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  ApiError,
  auditApi,
  evalApi,
  probeMode,
  type Mode,
  type SmokeResult,
} from "../api";
import { ModeBadge } from "../components/badges";

/** View 5 — RCA/Evaluation (M19.6 + M19.10): audit chain viewer with
    validity badge, plus six-gate cards from a live harness-smoke run.
    Gate numbers are measured on demand (labeled mock-system); the audit
    chain is the incident's own export. Nothing estimated. */
export function RCAView() {
  const { id } = useParams<{ id: string }>();
  const [mode, setMode] = useState<Mode>("OFFLINE");
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [valid, setValid] = useState<boolean | null>(null);
  const [origin, setOrigin] = useState("");
  const [smoke, setSmoke] = useState<SmokeResult | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      setMode(await probeMode());
      if (id === undefined) return;
      try {
        const chain = await auditApi.view(id);
        setEvents(chain.events);
        setValid(chain.valid);
        setOrigin(chain.origin);
        setError("");
      } catch (err) {
        setEvents([]);
        setValid(null);
        setError(err instanceof ApiError ? err.message : String(err));
      }
    }
    void load();
  }, [id]);

  async function runSmoke() {
    setError("");
    try {
      setSmoke(await evalApi.smoke());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">RCA {id}</h1>
        <ModeBadge mode={mode} />
        {valid !== null && (
          <span
            data-testid="audit-valid-badge"
            className={`rounded px-2 py-0.5 text-xs font-bold ${
              valid ? "bg-green-800" : "bg-red-800"
            }`}
          >
            audit {valid ? "valid" : "INVALID"}
          </span>
        )}
      </div>
      {error !== "" && (
        <p data-testid="rca-error" className="mb-3 text-sm text-red-300">
          {error}
        </p>
      )}
      <h2 className="mb-1 text-sm font-bold text-gray-300">
        Audit chain {origin !== "" && <span>({origin})</span>}
      </h2>
      {events.length === 0 ? (
        <p data-testid="audit-empty" className="mb-4 text-sm text-gray-400">
          No audit events recorded for this incident yet.
        </p>
      ) : (
        <ol data-testid="audit-chain" className="mb-4 text-sm">
          {events.map((event, index) => (
            <li key={index} className="border-t border-gray-800 py-1 font-mono text-xs">
              #{String(event.seq)} {String(event.event_type)} —{" "}
              {String(event.result ?? "")}
            </li>
          ))}
        </ol>
      )}
      <h2 className="mb-1 text-sm font-bold text-gray-300">
        Six-gate scorecard (harness smoke, mock systems)
      </h2>
      <button
        onClick={() => void runSmoke()}
        className="mb-2 rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600"
      >
        Run smoke eval
      </button>
      {smoke !== null && (
        <div data-testid="gate-cards" className="text-sm">
          <p className="text-gray-400">
            {smoke.system} · {smoke.cases} cases · baseline{" "}
            {smoke.baseline.pass_rate} → degraded {smoke.optimized.pass_rate}
          </p>
          <p>
            Rubric total: <strong>{smoke.rubric.total_100}</strong> (mock
            systems; pipeline numbers arrive with M20/M21)
          </p>
        </div>
      )}
    </div>
  );
}
