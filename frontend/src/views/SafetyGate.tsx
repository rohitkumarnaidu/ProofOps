import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ApiError,
  apiKeyStateLabel,
  approvalsApi,
  hasApiKey,
  identityApi,
  type ApprovalView,
  type IdentityView,
} from "../api";
import { ModeBadge } from "../components/badges";
import { useIncidentEvents } from "../components/useIncidentEvents";
import { useMode } from "../components/useMode";

interface GateIssue {
  status: number | null;
  title: string;
  detail: string;
}

function actionTemplate(incidentId: string): string {
  return JSON.stringify(
    {
      incident_id: incidentId,
      agent_id: "",
      action_type: "",
      resource_type: "",
      resource_id: "",
      environment: "",
      parameters: {},
      reason: "",
      evidence_ids: [],
      runbook_id: "",
      runbook_version: "",
      expected_outcome: "",
      verification_plan: [],
      rollback_action: null,
    },
    null,
    2,
  );
}

function issueFromError(error: unknown, subject: string): GateIssue {
  const status = error instanceof ApiError ? error.status : 0;
  const title =
    status === 401
      ? "No API key"
      : status === 403
        ? "Permission denied"
        : status === 404
          ? "Not found"
          : status === 410
            ? "Expired"
            : status === 422
              ? "Validation failed"
              : status === 429
                ? "Throttled"
                : "Backend unavailable";
  return {
    status,
    title: `${title} (HTTP ${status || "network"}): ${subject}`,
    detail: error instanceof ApiError ? error.message : String(error),
  };
}

function IssueMessage({ issue }: { issue: GateIssue }) {
  return (
    <div
      role="alert"
      data-api-status={issue.status ?? "network"}
      data-state={
        issue.status === null
          ? "network-error"
          : `http-${String(issue.status)}`
      }
      className="rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200"
    >
      <p className="font-bold">{issue.title}</p>
      <p className="break-all">{issue.detail}</p>
      {issue.status === 429 && (
        <p className="mt-1">Wait for the server throttle window, then retry.</p>
      )}
    </div>
  );
}

export function SafetyGate() {
  const [searchParams] = useSearchParams();
  const incidentId = searchParams.get("incident_id")?.trim() ?? "";
  const mode = useMode();
  const [actionText, setActionText] = useState(() => actionTemplate(""));
  const [issuedApprovalId, setIssuedApprovalId] = useState<string | null>(null);
  const [view, setView] = useState<ApprovalView | null>(null);
  const [token, setToken] = useState("");
  const [requestIssue, setRequestIssue] = useState<GateIssue | null>(null);
  const [decisionIssue, setDecisionIssue] = useState<GateIssue | null>(null);
  const [pollIssue, setPollIssue] = useState<GateIssue | null>(null);
  const [identity, setIdentity] = useState<IdentityView | null>(null);
  const [identityLoading, setIdentityLoading] = useState(true);
  const [identityIssue, setIdentityIssue] = useState<GateIssue | null>(null);
  const [expiredTerminal, setExpiredTerminal] = useState(false);
  const [isRequesting, setIsRequesting] = useState(false);
  const [isDeciding, setIsDeciding] = useState(false);
  const idempotencyKeysRef = useRef(new Map<string, string>());
  const [loadApprovalId, setLoadApprovalId] = useState("");
  const [loadToken, setLoadToken] = useState("");
  const [isLoadingApproval, setIsLoadingApproval] = useState(false);
  const [loadIssue, setLoadIssue] = useState<GateIssue | null>(null);

  async function loadExistingApproval() {
    const target = loadApprovalId.trim();
    if (!target) return;
    setLoadIssue(null);
    setIsLoadingApproval(true);
    try {
      const loaded = await approvalsApi.view(target);
      applyApproval(loaded);
      setIssuedApprovalId(loaded.approval_id);
      if (loadToken.trim()) setToken(loadToken.trim());
      setExpiredTerminal(loaded.status !== "pending");
    } catch (error) {
      setLoadIssue(issueFromError(error, "approval lookup"));
    } finally {
      setIsLoadingApproval(false);
    }
  }

  useEffect(() => {
    setActionText((current) => {
      try {
        const parsed = JSON.parse(current) as unknown;
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
          return JSON.stringify(
            { ...(parsed as Record<string, unknown>), incident_id: incidentId },
            null,
            2,
          );
        }
      } catch {
        return actionTemplate(incidentId);
      }
      return actionTemplate(incidentId);
    });
  }, [incidentId]);

  useEffect(() => {
    let cancelled = false;
    setIdentityLoading(true);
    void identityApi
      .view()
      .then((next) => {
        if (!cancelled) {
          setIdentity(next);
          setIdentityIssue(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setIdentity(null);
          setIdentityIssue(issueFromError(error, "server identity"));
        }
      })
      .finally(() => {
        if (!cancelled) setIdentityLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const applyApproval = useCallback((next: ApprovalView) => {
    setView(next);
    setPollIssue(null);
    if (next.status !== "pending") {
      idempotencyKeysRef.current.delete(next.approval_id);
      setToken("");
    }
    if (
      next.status === "expired" ||
      (next.status === "pending" && next.seconds_remaining <= 0)
    ) {
      setExpiredTerminal(true);
      setToken("");
    }
  }, []);

  const loadApproval = useCallback(
    async (approvalId: string) => {
      try {
        applyApproval(await approvalsApi.view(approvalId));
      } catch (error) {
        const issue = issueFromError(error, "approval status");
        setPollIssue(issue);
        if (issue.status === 410) {
          setExpiredTerminal(true);
          setToken("");
          idempotencyKeysRef.current.delete(approvalId);
        }
      }
    },
    [applyApproval],
  );

  useEffect(() => {
    if (view === null || view.status !== "pending" || expiredTerminal) return;
    const timer = setInterval(() => {
      void loadApproval(view.approval_id);
    }, 5000);
    return () => clearInterval(timer);
  }, [expiredTerminal, loadApproval, view?.approval_id, view?.status]);

  const incidentEvents = useIncidentEvents({
    incidentId,
    enabled: view !== null && view.status === "pending" && !expiredTerminal,
    onRefresh: () => {
      if (view !== null) void loadApproval(view.approval_id);
    },
  });

  // The gate must mirror what the SERVER will actually do, or the operator is
  // blocked by a control that does not exist server-side. A bootstrap
  // identity carries no server-side roles (the server permits it by
  // configuration, and labels it demo-grade), so blocking on an empty role
  // list would make the product's headline HITL control undemonstrable in the
  // default deployment. A per-key identity is gated strictly on its stored
  // roles.
  const identityIsBootstrap = identity?.mode === "bootstrap";
  const serverHasApproverRole = identityIsBootstrap
    ? true
    : (identity?.roles.some((role) => {
        const normalized = role.toLowerCase();
        return normalized === "approver" || normalized === "admin";
      }) ?? false);
  const decidable =
    view !== null &&
    view.status === "pending" &&
    view.seconds_remaining > 0 &&
    serverHasApproverRole &&
    !expiredTerminal &&
    token.trim() !== "" &&
    !isDeciding;

  async function requestApproval() {
    setRequestIssue(null);
    setDecisionIssue(null);
    setPollIssue(null);
    setExpiredTerminal(false);
    setIsRequesting(true);
    try {
      const parsed = JSON.parse(actionText) as Record<string, unknown>;
      const issued = await approvalsApi.request({
        ...parsed,
        incident_id: incidentId,
      });
      setIssuedApprovalId(issued.approval_id);
      setToken(issued.token);
      const next = await approvalsApi.view(issued.approval_id);
      applyApproval(next);
    } catch (error) {
      const issue = issueFromError(error, "approval request");
      setRequestIssue(issue);
      if (issue.status === 410) {
        setExpiredTerminal(true);
        setToken("");
      }
    } finally {
      setIsRequesting(false);
    }
  }

  async function decide(kind: "approve" | "reject") {
    if (view === null || !decidable) return;
    setDecisionIssue(null);
    setIsDeciding(true);
    let idempotencyKey = idempotencyKeysRef.current.get(view.approval_id);
    if (idempotencyKey === undefined) {
      idempotencyKey = crypto.randomUUID();
      idempotencyKeysRef.current.set(view.approval_id, idempotencyKey);
    }
    try {
      const next =
        kind === "approve"
          ? await approvalsApi.approve(
              view.approval_id,
              token,
              idempotencyKey,
            )
          : await approvalsApi.reject(
              view.approval_id,
              "",
              idempotencyKey,
            );
      applyApproval(next);
    } catch (error) {
      const issue = issueFromError(error, `${kind} decision`);
      setDecisionIssue(issue);
      if (issue.status === 410) {
        setExpiredTerminal(true);
        setToken("");
        idempotencyKeysRef.current.delete(view.approval_id);
      }
    } finally {
      setIsDeciding(false);
    }
  }

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold">
          Safety Gate{incidentId === "" ? "" : ` · ${incidentId}`}
        </h1>
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
      </div>
      <p aria-live="polite" className="mb-3 text-xs text-gray-400">
        Event stream: {incidentEvents.connectionState}
        {incidentEvents.lastEventType === null
          ? ""
          : ` · ${incidentEvents.lastEventType}`}
        {incidentEvents.lastEventId === null
          ? ""
          : ` · ${incidentEvents.lastEventId}`}
      </p>
      {incidentEvents.error !== "" && (
        <p role="alert" className="mb-3 text-sm text-amber-300">
          Event stream update failed: {incidentEvents.error}
        </p>
      )}
      {!hasApiKey() && (
        <p data-testid="api-key-notice" className="mb-3 text-sm text-amber-300">
          {apiKeyStateLabel()}. Identity and approval mutations will return 401
          until VITE_PROOFOPS_API_KEY is set.
        </p>
      )}
      <section aria-labelledby="server-identity" className="mb-5 rounded border border-gray-800 p-3">
        <h2 id="server-identity" className="mb-2 text-sm font-bold text-gray-200">
          Server-derived identity
        </h2>
        {identityLoading ? (
          <p aria-live="polite" className="text-sm text-gray-400">
            Loading server identity…
          </p>
        ) : identityIssue !== null ? (
          <IssueMessage issue={identityIssue} />
        ) : identity !== null ? (
          <>
            <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
              <dt className="text-gray-400">Key id</dt>
              <dd className="break-all">{identity.key_id}</dd>
              <dt className="text-gray-400">Owner</dt>
              <dd className="break-all">{identity.owner}</dd>
              <dt className="text-gray-400">Server roles</dt>
              <dd>{identity.roles.length === 0 ? "none" : identity.roles.join(", ")}</dd>
              <dt className="text-gray-400">Identity mode</dt>
              <dd>{identity.mode}</dd>
            </dl>
            {identity.mode === "bootstrap" && (
              <p data-testid="demo-grade-identity" className="mt-2 text-xs text-amber-300">
                Demo-grade bootstrap identity. This is not an authenticated user
                identity and must not be presented as one.
              </p>
            )}
          </>
        ) : null}
      </section>
      {incidentId === "" && (
        <p role="status" className="mb-4 text-sm text-amber-300">
          Select a current incident before requesting an approval.
        </p>
      )}
      <div className="grid gap-6 lg:grid-cols-2">
        <section aria-labelledby="request-approval">
          <h2 id="request-approval" className="mb-1 text-sm font-bold text-gray-300">
            1. Request approval
          </h2>
          <p className="mb-2 text-xs text-gray-400">
            The server derives requester identity from the API key. Client actor
            and role fields are not authorization controls.
          </p>
          <label htmlFor="action-json" className="mb-1 block text-xs text-gray-300">
            Action JSON
          </label>
          <textarea
            id="action-json"
            value={actionText}
            onChange={(event) => setActionText(event.target.value)}
            rows={20}
            spellCheck={false}
            aria-describedby="action-json-help"
            className="w-full rounded border border-gray-700 bg-gray-900 p-2 font-mono text-xs"
          />
          <p id="action-json-help" className="mt-1 text-xs text-gray-500">
            Empty fields are intentional. The server validates the completed
            action; this view does not supply incident evidence or risk claims.
          </p>
          <button
            type="button"
            onClick={() => void requestApproval()}
            disabled={incidentId === "" || isRequesting}
            className="mt-2 rounded bg-sky-700 px-3 py-1 text-sm font-bold hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isRequesting ? "Requesting…" : "Request approval"}
          </button>
          {requestIssue !== null && (
            <div className="mt-3">
              <IssueMessage issue={requestIssue} />
            </div>
          )}
          {issuedApprovalId !== null && (
            <p data-testid="issued-token" className="mt-2 break-all text-xs text-gray-400">
              approval_id: {issuedApprovalId}. The token is held only in this
              page's memory and is lost on reload.
            </p>
          )}
        </section>
        <section aria-labelledby="load-existing">
          <h2 id="load-existing" className="mb-1 text-sm font-bold text-gray-300">
            2. Load an existing approval (second operator)
          </h2>
          <p className="mb-2 text-xs text-gray-400">
            A request raised by one operator cannot be approved by that same
            operator on the per-key path. Load the approval id issued by the
            requester, then paste the token they were given.
          </p>
          <div className="flex flex-col gap-2">
            <input
              type="text"
              aria-label="Existing approval id"
              placeholder="approval id"
              value={loadApprovalId}
              onChange={(event) => setLoadApprovalId(event.target.value)}
              className="rounded bg-gray-800 px-2 py-1 text-sm"
            />
            <input
              type="text"
              aria-label="Existing approval token"
              placeholder="token from the requester"
              value={loadToken}
              onChange={(event) => setLoadToken(event.target.value)}
              className="rounded bg-gray-800 px-2 py-1 text-sm"
            />
            <button
              type="button"
              data-testid="load-approval"
              onClick={() => void loadExistingApproval()}
              disabled={isLoadingApproval || loadApprovalId.trim() === ""}
              className="self-start rounded bg-gray-700 px-3 py-1 text-sm font-bold hover:bg-gray-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isLoadingApproval ? "Loading…" : "Load approval"}
            </button>
          </div>
          {loadIssue !== null && (
            <div className="mt-3">
              <IssueMessage issue={loadIssue} />
            </div>
          )}
        </section>
        <section aria-labelledby="approval-decision">
          <h2 id="approval-decision" className="mb-1 text-sm font-bold text-gray-300">
            3. Decide
          </h2>
          {pollIssue?.status === 404 && (
            <p data-testid="approval-not-found" role="alert" className="mb-2 text-sm text-red-300">
              Approval not found. The server has no record for this approval id.
            </p>
          )}
          {view === null ? (
            pollIssue === null ? (
              expiredTerminal ? (
                <p
                  data-testid="approval-terminal"
                  className="rounded border border-amber-900 p-2 text-sm text-amber-200"
                >
                  Terminal state: expired. The token was cleared and both
                  actions are disabled.
                </p>
              ) : (
                <p className="text-sm text-gray-400">
                  No approval is loaded in this page state.
                </p>
              )
            ) : null
          ) : (
            <div data-testid="approval-card" className="text-sm">
              <p>
                Status: <strong>{view.status}</strong> · TTL countdown:{" "}
                <span data-testid="ttl-countdown">
                  {Math.max(0, Math.round(view.seconds_remaining))}s remaining
                </span>
              </p>
              <p className="break-all text-gray-400">
                Incident: {view.incident_id} · Action: {view.action_id}
              </p>
              <p className="break-all text-gray-400">Server actor: {view.actor}</p>
              <p className="break-all text-gray-400">Scope: {view.scope}</p>
              <p className="break-all font-mono text-gray-400">
                Params hash: {view.params_hash}
              </p>
              <p className="break-all text-gray-400">Expires: {view.expires_at}</p>
              <p className="break-all text-gray-400">
                Identity mode: {view.identity_mode} · Requester key:{" "}
                {view.requester_key_id}
              </p>
              <p className="break-all text-gray-400">
                Decided by: {view.decided_by ?? "not yet decided"} · SoD: {view.sod}
              </p>
              {(expiredTerminal || view.status === "expired") && (
                <p
                  data-testid="approval-terminal"
                  className="mt-2 rounded border border-amber-900 p-2 text-amber-200"
                >
                  Terminal state: expired. The token was cleared and both actions
                  are disabled.
                </p>
              )}
              {!decidable && view.status === "pending" && view.seconds_remaining <= 0 && (
                <p data-testid="ttl-expired" className="mt-1 text-xs text-amber-300">
                  Approval TTL elapsed — request a fresh approval.
                </p>
              )}
              <div className="mt-2 flex flex-col gap-2">
                <label htmlFor="approval-token" className="text-xs text-gray-300">
                  Approval token (page state only; lost on reload)
                </label>
                <textarea
                  id="approval-token"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  rows={3}
                  spellCheck={false}
                  className="w-full resize-y break-all rounded border border-gray-700 bg-gray-900 p-2 font-mono text-xs"
                />
                {!serverHasApproverRole && (
                  <p
                    data-testid="identity-cannot-decide"
                    className="text-xs text-amber-300"
                  >
                    Server identity lacks the approver or admin role. Both
                    decision actions are disabled; the server remains authoritative.
                  </p>
                )}
                {serverHasApproverRole && token.trim() === "" && (
                  <p className="text-xs text-amber-300">
                    An issued token is required before deciding.
                  </p>
                )}
                {identityIsBootstrap && (
                  <p
                    data-testid="sod-bootstrap-warning"
                    className="text-xs text-amber-300"
                  >
                    Bootstrap identity carries no server-side roles, so the
                    server cannot attribute this decision to a person and
                    separation of duties is not enforced. Deploy a per-key
                    store (var/api_keys.json) for four-eyes control.
                  </p>
                )}
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void decide("approve")}
                    disabled={!decidable}
                    className="rounded bg-green-700 px-3 py-1 text-sm font-bold hover:bg-green-600 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    onClick={() => void decide("reject")}
                    disabled={!decidable}
                    className="rounded bg-red-700 px-3 py-1 text-sm font-bold hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Deny
                  </button>
                </div>
              </div>
            </div>
          )}
          {pollIssue !== null && pollIssue.status !== 404 && (
            <div className="mt-3">
              <IssueMessage issue={pollIssue} />
            </div>
          )}
          {decisionIssue !== null && (
            <div className="mt-3">
              <IssueMessage issue={decisionIssue} />
            </div>
          )}
          {view?.status === "approved" && (
            <p className="mt-3 text-sm text-green-300">Approval resolved: approved.</p>
          )}
          {view?.status === "denied" && (
            <p className="mt-3 text-sm text-red-300">Approval resolved: denied.</p>
          )}
        </section>
      </div>
    </div>
  );
}
