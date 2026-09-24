import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  ApiError,
  auditApi,
  evalApi,
  hasApiKey,
  type SmokeResult,
} from "../api";
import { ModeBadge } from "../components/badges";
import { useMode } from "../components/useMode";

const GATES = ["C1", "C2", "C3", "C4", "C5", "C6"] as const;

/** Format a gate number from the smoke response (numbers measured live by
    the harness; anything else renders verbatim or as "—", never estimated). */
function fmtGate(value: unknown): string {
  if (typeof value === "number") return value.toFixed(2);
  if (typeof value === "string") return value;
  if (Array.isArray(value))
    return value.map((v: unknown) => fmtGate(v)).join(",");
  return "—";
}

/** View 5 — RCA/Evaluation (M19.6 + M19.10): audit chain viewer with
    validity badge, plus six-gate cards from a live harness-smoke run.
    Gate numbers are measured on demand (labeled mock-system); the audit
    chain is the incident's own export. Nothing estimated. */
export function RCAView() {
  const { id } = useParams<{ id: string }>();
  const mode = useMode(id);
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [valid, setValid] = useState<boolean | null>(null);
  const [origin, setOrigin] = useState("");
  const [smoke, setSmoke] = useState<SmokeResult | null>(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function load() {
      if (id === undefined) return;
      setIsLoading(true);
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
      } finally {
        setIsLoading(false);
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

  // Per-gate (C1–C6) cards render ONLY from smoke-response data
  // (baseline/optimized gates_rate, measured live by the harness):
  // absent data = no cards, never estimates.
  const baseGates = smoke?.baseline.gates_rate;
  const optGates = smoke?.optimized.gates_rate;
  const showPerGate =
    baseGates !== undefined &&
    optGates !== undefined &&
    GATES.every(
      (gate) =>
        typeof baseGates[gate] === "number" &&
        typeof optGates[gate] === "number",
    );

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-bold">RCA {id}</h1>
        <ModeBadge mode={mode} />
        {mode === null && (
          <span
            data-testid="mode-probing"
            aria-busy="true"
            className="text-xs text-gray-500"
          >
            probing backend…
          </span>
        )}
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
      {!hasApiKey() && (
        <p data-testid="api-key-notice" className="mb-3 text-sm text-amber-300">
          No API key configured — smoke eval will 401. Set
          VITE_PROOFOPS_API_KEY to enable it (server-verified only; the audit
          chain above stays openly readable).
        </p>
      )}
      <h2 className="mb-1 text-sm font-bold text-gray-300">
        Audit chain {origin !== "" && <span>({origin})</span>}
      </h2>
      {isLoading ? (
        <p
          data-testid="rca-loading"
          aria-busy="true"
          className="mb-4 text-sm text-gray-400"
        >
          Loading audit chain…
        </p>
      ) : events.length === 0 ? (
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
            systems; pipeline-system numbers land in runs/*.jsonl and are
            never mixed into this demo response)
          </p>
          {showPerGate && (
            <div
              data-testid="per-gate-cards"
              className="mt-2 grid gap-2 md:grid-cols-3"
            >
              {GATES.map((gate) => (
                <div
                  key={gate}
                  data-testid={`gate-card-${gate}`}
                  className="rounded border border-gray-800 px-2 py-1"
                >
                  <p className="font-bold">{gate}</p>
                  <p className="text-gray-400">
                    base {fmtGate(baseGates?.[gate])} → opt{" "}
                    {fmtGate(optGates?.[gate])} (Δ{" "}
                    {fmtGate(smoke?.delta[`d_${gate}`])})
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
