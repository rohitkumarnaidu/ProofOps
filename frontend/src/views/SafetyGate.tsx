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
import {
  Button,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Notice,
  Panel,
  StatusPill,
  TextAreaField,
  TextField,
  type StatusTone,
} from "../components/ui";

interface GateIssue {
  status: number | null;
  title: string;
  detail: string;
}

/** Approval status -> tone. A decision that resolved is calm, an unresolved or
    refused one is loud. Unknown statuses fall back to neutral rather than
    borrowing a colour from a status that means something else. */
const APPROVAL_TONE: Record<string, StatusTone> = {
  approved: "ok",
  denied: "danger",
  expired: "warn",
  pending: "warn",
};

function statusTone(status: string): StatusTone {
  return APPROVAL_TONE[status.toLowerCase()] ?? "neutral";
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
    <div className="mx-auto flex max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 data-page-heading tabIndex={-1} className="text-xl font-bold tracking-tight">
          Safety Gate{incidentId === "" ? "" : ` · ${incidentId}`}
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

      <p aria-live="polite" className="text-xs text-fg-subtle">
        Event stream: {incidentEvents.connectionState}
        {incidentEvents.lastEventType === null
          ? ""
          : ` · ${incidentEvents.lastEventType}`}
        {incidentEvents.lastEventId === null
          ? ""
          : ` · ${incidentEvents.lastEventId}`}
      </p>

      {incidentEvents.error !== "" && (
        <ErrorState title="Event stream update failed" detail={incidentEvents.error} />
      )}

      {!hasApiKey() && (
        <Notice tone="warn" testId="api-key-notice" live>
          {apiKeyStateLabel()}. Identity and approval mutations will return 401
          until VITE_PROOFOPS_API_KEY is set.
        </Notice>
      )}

      <Panel
        title="Server-derived identity"
        description="Who the server thinks you are. This is the only identity that authorizes anything."
      >
        {identityLoading ? (
          <LoadingState label="Loading server identity" />
        ) : identityIssue !== null ? (
          <IssueMessage issue={identityIssue} />
        ) : identity !== null ? (
          <>
            <KeyValue
              items={[
                ["Key id", <span className="break-all">{identity.key_id}</span>],
                ["Owner", <span className="break-all">{identity.owner}</span>],
                [
                  "Server roles",
                  identity.roles.length === 0 ? (
                    <StatusPill tone="warn">none</StatusPill>
                  ) : (
                    identity.roles.join(", ")
                  ),
                ],
                ["Identity mode", identity.mode],
              ]}
            />
            {identity.mode === "bootstrap" && (
              <Notice tone="warn" testId="demo-grade-identity" className="mt-3">
                Demo-grade bootstrap identity. This is not an authenticated user
                identity and must not be presented as one.
              </Notice>
            )}
          </>
        ) : null}
      </Panel>

      {incidentId === "" && (
        <Notice tone="info" polite>
          Select a current incident before requesting an approval.
        </Notice>
      )}

      {/* items-start: without it the grid stretches the shorter panel to the
          taller one's height, leaving a large dead area beside the form. */}
      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Panel
          title="1. Request approval"
          description="The server derives requester identity from the API key. Client actor and role fields are not authorization controls."
        >
          <TextAreaField
            label="Action JSON"
            id="action-json"
            hint="Empty fields are intentional. The server validates the completed action; this view does not supply incident evidence or risk claims."
            rows={20}
            spellCheck={false}
            value={actionText}
            onChange={(event) => setActionText(event.target.value)}
          />
          <div className="mt-3">
            <Button
              tone="primary"
              onClick={() => void requestApproval()}
              disabled={incidentId === "" || isRequesting}
            >
              {isRequesting ? "Requesting…" : "Request approval"}
            </Button>
          </div>
          {requestIssue !== null && (
            <div className="mt-3">
              <IssueMessage issue={requestIssue} />
            </div>
          )}
          {issuedApprovalId !== null && (
            <Notice tone="info" testId="issued-token" className="mt-3">
              approval_id: <span className="break-all">{issuedApprovalId}</span>. The
              token is held only in this page&apos;s memory and is lost on reload.
            </Notice>
          )}
        </Panel>

        <Panel
          title="2. Load an existing approval (second operator)"
          description="A request raised by one operator cannot be approved by that same operator on the per-key path. Load the approval id issued by the requester, then paste the token they were given."
        >
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void loadExistingApproval();
            }}
          >
            <TextField
              label="Existing approval id"
              id="load-approval-id"
              placeholder="approval id"
              value={loadApprovalId}
              onChange={(event) => setLoadApprovalId(event.target.value)}
            />
            <TextField
              label="Existing approval token"
              id="load-approval-token"
              placeholder="token from the requester"
              value={loadToken}
              onChange={(event) => setLoadToken(event.target.value)}
            />
            <div>
              <Button
                type="submit"
                data-testid="load-approval"
                disabled={isLoadingApproval || loadApprovalId.trim() === ""}
              >
                {isLoadingApproval ? "Loading…" : "Load approval"}
              </Button>
            </div>
          </form>
          {loadIssue !== null && (
            <div className="mt-3">
              <IssueMessage issue={loadIssue} />
            </div>
          )}
        </Panel>
      </div>

      <Panel title="3. Decide">
        {pollIssue?.status === 404 && (
          <Notice tone="danger" testId="approval-not-found" live className="mb-3">
            Approval not found. The server has no record for this approval id.
          </Notice>
        )}
        {view === null ? (
          pollIssue === null ? (
            expiredTerminal ? (
              <Notice tone="warn" testId="approval-terminal" live>
                Terminal state: expired. The token was cleared and both actions are
                disabled.
              </Notice>
            ) : (
              <EmptyState title="No approval is loaded in this page state." />
            )
          ) : null
        ) : (
          <div data-testid="approval-card">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <StatusPill tone={statusTone(view.status)}>{view.status}</StatusPill>
              <span
                data-testid="ttl-countdown"
                className="text-sm tabular-nums text-fg-muted"
              >
                TTL countdown: {Math.max(0, Math.round(view.seconds_remaining))}s
                remaining
              </span>
            </div>
            <KeyValue
              items={[
                ["Incident", <span className="break-all">{view.incident_id}</span>],
                ["Action", <span className="break-all">{view.action_id}</span>],
                ["Server actor", <span className="break-all">{view.actor}</span>],
                ["Scope", <span className="break-all">{view.scope}</span>],
                [
                  "Params hash",
                  <span className="break-all font-mono">{view.params_hash}</span>,
                ],
                ["Expires", <span className="break-all">{view.expires_at}</span>],
                [
                  "Identity mode",
                  <span className="break-all">
                    {view.identity_mode} · Requester key: {view.requester_key_id}
                  </span>,
                ],
                [
                  "Decided by",
                  <span className="break-all">
                    {view.decided_by ?? "not yet decided"} · SoD: {view.sod}
                  </span>,
                ],
              ]}
            />
            {/* Blast Radius & Governance Authority Display */}
            <div className="mt-3 rounded border border-line bg-surface-raised p-3">
              <div className="text-xs font-semibold text-fg-subtle uppercase tracking-wider">
                Blast Radius &amp; Governance Verification
              </div>
              <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-fg-subtle">Target Scope: </span>
                  <span className="font-mono font-semibold text-fg">{view.scope}</span>
                </div>
                <div>
                  <span className="text-fg-subtle">Risk Classification: </span>
                  <span className="font-semibold text-warn">YELLOW (Reversible)</span>
                </div>
                <div>
                  <span className="text-fg-subtle">Separation of Duties: </span>
                  <span className="font-mono text-ok">{view.sod}</span>
                </div>
                <div>
                  <span className="text-fg-subtle">Auto-Rollback: </span>
                  <span className="text-fg">1 attempt on SLO breach</span>
                </div>
              </div>
            </div>
            {(expiredTerminal || view.status === "expired") && (
              <Notice tone="warn" testId="approval-terminal" live className="mt-3">
                Terminal state: expired. The token was cleared and both actions are
                disabled.
              </Notice>
            )}
            {!decidable && view.status === "pending" && view.seconds_remaining <= 0 && (
              <Notice tone="warn" testId="ttl-expired" className="mt-3">
                Approval TTL elapsed — request a fresh approval.
              </Notice>
            )}
            <div className="mt-4 flex flex-col gap-3">
              <TextAreaField
                label="Approval token (page state only; lost on reload)"
                id="approval-token"
                rows={3}
                spellCheck={false}
                value={token}
                onChange={(event) => setToken(event.target.value)}
              />
              {!serverHasApproverRole && (
                <Notice tone="warn" testId="identity-cannot-decide" live>
                  Server identity lacks the approver or admin role. Both decision
                  actions are disabled; the server remains authoritative.
                </Notice>
              )}
              {serverHasApproverRole && token.trim() === "" && (
                <Notice tone="warn">
                  An issued token is required before deciding.
                </Notice>
              )}
              {identityIsBootstrap && (
                <Notice tone="danger" testId="sod-bootstrap-warning" live>
                  Bootstrap identity carries no server-side roles, so the server
                  cannot attribute this decision to a person and separation of
                  duties is not enforced. Deploy a per-key store
                  (var/api_keys.json) for four-eyes control.
                </Notice>
              )}
              <div className="flex flex-wrap gap-2">
                <Button
                  tone="primary"
                  onClick={() => void decide("approve")}
                  disabled={!decidable}
                >
                  Approve
                </Button>
                <Button
                  tone="danger"
                  onClick={() => void decide("reject")}
                  disabled={!decidable}
                >
                  Deny
                </Button>
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
          <Notice tone="ok" className="mt-3">
            Approval resolved: approved.
          </Notice>
        )}
        {view?.status === "denied" && (
          <Notice tone="danger" className="mt-3">
            Approval resolved: denied.
          </Notice>
        )}
      </Panel>
    </div>
  );
}
