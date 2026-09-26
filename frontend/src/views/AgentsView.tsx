import { useCallback, useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError, agentsApi, type InvestigateReply, type ThreadTurn } from "../api";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  Notice,
  Panel,
  StatusPill,
  TextAreaField,
  TextField,
} from "../components/ui";

/**
 * The agent surface. Read-only by construction.
 *
 * This screen exists because the four agents (A1 triage, A2 diagnostic, A3
 * planner, A4 RCA) were otherwise reachable only as Python calls inside the
 * pipeline -- the product's own audit logged that as a failure. An operator who
 * cannot ask a question cannot see why the system decided what it decided.
 *
 * Two rules govern everything below:
 *
 *   1. The agent never acts. There is no approve, execute, or mutate control on
 *      this screen, by design and not by omission. A proposal is a proposal.
 *   2. The answer is not the proof. `reasoning_mode` is always shown, every
 *      claim carries its evidence ids, and a `NO_EVIDENCE` verdict renders as
 *      an explicit refusal with no proposal. A confident animation would be the
 *      opposite of what this product is for.
 */
export function AgentsView() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const [incidentId, setIncidentId] = useState(
    id ?? params.get("incident") ?? "",
  );
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reply, setReply] = useState<InvestigateReply | null>(null);
  const [turns, setTurns] = useState<ThreadTurn[]>([]);
  const [loadingThread, setLoadingThread] = useState(false);

  const loadThread = useCallback(async (target: string) => {
    if (!target) {
      setTurns([]);
      return;
    }
    setLoadingThread(true);
    try {
      setTurns(await agentsApi.thread(target));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLoadingThread(false);
    }
  }, []);

  useEffect(() => {
    setIncidentId(id ?? params.get("incident") ?? "");
  }, [id, params]);

  useEffect(() => {
    void loadThread(incidentId);
  }, [incidentId, loadThread]);

  async function ask() {
    if (!incidentId.trim() || !question.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await agentsApi.investigate({
        incident_id: incidentId.trim(),
        question: question.trim(),
      });
      setReply(res);
      setQuestion("");
      setTurns(await agentsApi.thread(incidentId.trim()));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const refused =
    reply !== null &&
    (reply.verdict === "NO_EVIDENCE" || reply.verdict === "ERROR");

  return (
    <div className="space-y-4">
      <Panel
        title="Ask the incident"
        description="Read-only. The agent investigates and proposes; it cannot approve or execute anything."
        actions={
          <StatusPill tone={reply ? "info" : "neutral"}>
            {reply ? reply.reasoning_mode : "idle"}
          </StatusPill>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField
            label="Incident id"
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            placeholder="run_..."
          />
          <div className="flex items-end text-xs text-muted-foreground">
            Answers are persisted per incident, so this thread is auditable
            after the fact.
          </div>
        </div>
        <TextAreaField
          label="Question"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Why is checkout-api erroring, and what would you change?"
          rows={3}
        />
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
            disabled={busy || !incidentId.trim() || !question.trim()}
            onClick={() => void ask()}
          >
            {busy ? "Investigating..." : "Investigate"}
          </button>
          <span className="text-xs text-muted-foreground">
            {reply?.authority ?? "This agent has no authority to act."}
          </span>
        </div>
        {error ? <ErrorState title="Request failed" detail={error} /> : null}
      </Panel>

      {loadingThread ? <LoadingState label="Loading thread" /> : null}

      {turns.length === 0 && !loadingThread ? (
        <EmptyState
          title="No questions yet"
          hint="Ask about an incident to see the agent's reasoning, its citations, and the action it would propose."
        />
      ) : null}

      {turns.map((turn, i) => (
        <Panel
          key={`${turn.at}-${i}`}
          title={turn.role === "operator" ? "You" : "Agent"}
          actions={
            <div className="flex items-center gap-2">
              {turn.verdict ? (
                <StatusPill
                  tone={
                    turn.verdict === "NO_EVIDENCE" ||
                    turn.verdict === "ERROR" ||
                    turn.verdict === "INSUFFICIENT_EVIDENCE"
                      ? "danger"
                      : "ok"
                  }
                >
                  {turn.verdict}
                </StatusPill>
              ) : null}
              {turn.reasoning_mode ? (
                <StatusPill tone="info">{turn.reasoning_mode}</StatusPill>
              ) : null}
            </div>
          }
        >
          <p className="whitespace-pre-wrap text-sm">{turn.text}</p>

          {turn.evidence_ids.length > 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">
              Evidence:{" "}
              {turn.evidence_ids.map((e) => (
                <span key={e} className="mr-1 font-mono">
                  {e}
                </span>
              ))}
            </p>
          ) : (
            <Notice tone="warn" className="mt-2">
              No evidence ids support this turn. Treat it as unverified.
            </Notice>
          )}

          {turn.proposed_action ? (
            <div className="mt-3 rounded-md border border-warn/40 bg-warn/5 p-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-warn">
                Proposed only -- requires human approval
              </p>
              {turn.proposed_action.requires_human_approval ? null : (
                <Notice tone="danger" className="mt-2">
                  The server marked this proposal as not requiring approval. It
                  is still shown as requiring approval: an agent may never
                  downgrade its own human gate.
                </Notice>
              )}
              <dl className="mt-1 grid grid-cols-2 gap-x-3 gap-y-1 text-xs sm:grid-cols-4">
                <div>
                  <dt className="text-muted-foreground">Action</dt>
                  <dd className="font-mono">{turn.proposed_action.action_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Risk</dt>
                  <dd className="font-mono">{turn.proposed_action.risk_level}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Runbook</dt>
                  <dd className="font-mono">{turn.proposed_action.runbook_id}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Action id</dt>
                  <dd className="font-mono break-all">
                    {turn.proposed_action.action_id}
                  </dd>
                </div>
              </dl>
              <p className="mt-2 text-xs text-muted-foreground">
                Nothing has been executed. Approve it deliberately on the{" "}
                <Link className="underline" to="/safety">
                  Safety Gate
                </Link>
                , or do not.
              </p>
            </div>
          ) : null}

          {turn.trace.length > 0 ? (
            <details className="mt-3">
              <summary className="cursor-pointer text-xs text-muted-foreground">
                Reasoning trace ({turn.trace.length} steps)
              </summary>
              <ol className="mt-1 space-y-1 text-xs">
                {turn.trace.map((step, j) => (
                  <li key={j} className="font-mono text-muted-foreground">
                    {step.step} ({step.ms}ms)
                  </li>
                ))}
              </ol>
            </details>
          ) : null}
        </Panel>
      ))}

      {refused ? (
        <Notice tone="danger">
          The agent declined to answer. That is the correct behaviour when
          evidence is missing -- an empty answer is safer than a confident one.
        </Notice>
      ) : null}
    </div>
  );
}
