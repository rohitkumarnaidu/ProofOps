import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ApiError,
  apiKeyStateLabel,
  approvalsApi,
  hasApiKey,
  identityApi,
  type ApprovalProposal,
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

/** Risk tier as the policy engine classified it. Unknown values stay neutral. */
function riskTone(risk: string): StatusTone {
  const normalized = risk.toUpperCase();
  if (normalized === "GREEN") return "ok";
  if (normalized === "YELLOW") return "warn";
  if (normalized === "RED") return "danger";
  return "neutral";
}

/**
 * A blank Action for manual entry.
 *
 * Every contract field is present, including `namespace`, which was missing
 * and so could not be filled in by hand. Prefer loading a parked proposal: a
 * hand-typed action with blank required fields only 422s, and a human inventing
 * one is exactly what the pipeline's own plan exists to prevent.
 */
function actionTemplate(incidentId: string): string {
  return JSON.stringify(
    {
      action_id: "",
      incident_id: incidentId,
      agent_id: "",
      action_type: "",
      resource_type: "",
      resource_id: "",
      environment: "",
      namespace: "",
      parameters: {},
      risk_level: "",
      reason: "",
      evidence_ids: [],
      runbook_id: "",
      runbook_version: "",
      expected_outcome: "",
      rollback_action: null,
      verification_plan: [],
    },
    null,
    2,
  );
}

/**
 * Blast radius, read off the action the system actually planned.
 *
 * Every field is optional because a proposal is only as complete as the
 * planner made it. An absent field renders as "not stated" rather than a
 * default: a guessed resource or an assumed parameter count is exactly the
 * kind of invented blast radius an operator must not authorise against.
 */
function BlastRadius({ action }: { action: Record<string, unknown> }) {
  const text = (key: string): string => {
    const value = action[key];
    if (value === undefined || value === null) return "not stated";
    if (typeof value === "string") return value === "" ? "not stated" : value;
    return JSON.stringify(value);
  };
  const params = action.parameters;
  const paramCount =
    typeof params === "object" && params !== null && !Array.isArray(params)
      ? Object.keys(params as Record<string, unknown>).length
      : 0;
  const evidence = Array.isArray(action.evidence_ids)
    ? (action.evidence_ids as unknown[]).filter((e) => typeof e === "string")
    : [];
  const plan = Array.isArray(action.verification_plan)
    ? (action.verification_plan as unknown[]).filter((p) => typeof p === "string")
    : [];
  const rollback = action.rollback_action;

  return (
    <div className="grid grid-cols-2 gap-2 text-xs">
      <div>
        <span className="text-fg-subtle">Resource type: </span>
        <span className="font-mono text-fg">{text("resource_type")}</span>
      </div>
      <div>
        <span className="text-fg-subtle">Resource id: </span>
        <span className="font-mono text-fg">{text("resource_id")}</span>
      </div>
      <div>
        <span className="text-fg-subtle">Environment: </span>
        <span className="font-mono text-fg">{text("environment")}</span>
      </div>
      <div>
        <span className="text-fg-subtle">Namespace: </span>
        <span className="font-mono text-fg">{text("namespace")}</span>
      </div>
      <div>
        <span className="text-fg-subtle">Parameters: </span>
        <span className="font-mono text-fg">
          {paramCount === 0 ? "none" : `${paramCount} supplied`}
        </span>
      </div>
      <div>
        <span className="text-fg-subtle">Evidence cited: </span>
        <span className="font-mono text-fg">
          {evidence.length === 0 ? "none cited" : evidence.length}
        </span>
      </div>
      <div>
        <span className="text-fg-subtle">Verification plan: </span>
        <span className="font-mono text-fg">
          {plan.length === 0 ? "none stated" : plan.join(", ")}
        </span>
      </div>
      <div>
        <span className="text-fg-subtle">Rollback action: </span>
        <span className="font-mono text-fg">
          {rollback === undefined || rollback === null
            ? "none (not reversible)"
            : "declared"}
        </span>
      </div>
    </div>
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
  // Parked proposals are the gate's discovery mechanism. Without them the
  // operator cannot obtain the action the system proposed, so the request
  // 422s and every decision button stays disabled -- the whole HITL flow was
  // unreachable from the UI.
  const [proposals, setProposals] = useState<ApprovalProposal[] | null>(null);
  const [proposalsIssue, setProposalsIssue] = useState<GateIssue | null>(null);
  const [selectedProposalId, setSelectedProposalId] = useState("");
  const [denyReason, setDenyReason] = useState("");

  /**
   * The proposal currently loaded into the editor, if any.
   *
   * `risk_level` comes from here and nowhere else. It is the risk the policy
   * engine classified on the action that was actually planned. A hardcoded
   * reversibility label in this JSX previously told the operator that every
   * approval was a reversible YELLOW action, whatever tier policy had assigned,
   * on the one screen whose entire purpose is an informed decision.
   */
  const selectedProposal =
    proposals?.find((p) => p.action_id === selectedProposalId) ?? null;

  /** All parked actions when no incident is in scope, else just this one's. */
  const proposalsForIncident =
    proposals === null
      ? []
      : incidentId === ""
        ? proposals
        : proposals.filter((p) => p.incident_id === incidentId);

  const loadProposals = useCallback(async () => {
    try {
      const all = await approvalsApi.proposals();
      setProposals(all);
      setProposalsIssue(null);
    } catch (error) {
      setProposals([]);
      setProposalsIssue(issueFromError(error, "approval proposals"));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const all = await approvalsApi.proposals();
        if (!cancelled) {
          setProposals(all);
          setProposalsIssue(null);
        }
      } catch (error) {
        if (!cancelled) {
          setProposals([]);
          setProposalsIssue(issueFromError(error, "approval proposals"));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

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
      // ONLY an actually-expired approval is a terminal expiry. Any non-pending
      // status used to set this, so a load of an APPROVED or DENIED approval
      // reported "Terminal state: expired" to the operator.
      setExpiredTerminal(loaded.status === "expired");
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
              denyReason.trim(),
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

      {/* Parked proposals: the gate's entry point. */}
      <Panel
        title="Actions awaiting a decision"
        description="Planned actions the pipeline parked server-side. No token exists yet in the default delivery mode; selecting one loads the exact action so it can be submitted for approval."
        actions={
          <Button size="sm" onClick={() => void loadProposals()}>
            Refresh proposals
          </Button>
        }
      >
        {proposalsIssue !== null ? (
          <IssueMessage issue={proposalsIssue} />
        ) : proposals === null ? (
          <LoadingState label="Loading parked proposals" />
        ) : proposalsForIncident.length === 0 ? (
          <EmptyState
            title={
              proposals.length === 0
                ? "No actions are parked for approval."
                : `No parked action for ${incidentId}.`
            }
            hint="An action is parked when the planner produces one and policy escalates it. Ingest an incident and let the pipeline run to produce one."
          />
        ) : (
          <ul data-testid="proposal-list" className="flex flex-col gap-2">
            {proposalsForIncident.map((proposal) => (
              <li
                key={proposal.action_id}
                className="rounded border border-line bg-surface-raised p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill tone={riskTone(proposal.risk_level)}>
                    {proposal.risk_level === "" ? "UNCLASSIFIED" : proposal.risk_level}
                  </StatusPill>
                  <span className="font-mono text-sm font-semibold text-fg">
                    {proposal.action_type === "" ? "(no action type)" : proposal.action_type}
                  </span>
                  {proposal.runbook_id !== "" && (
                    <span className="text-xs text-fg-subtle">
                      runbook {proposal.runbook_id}
                    </span>
                  )}
                  <span className="text-xs text-fg-subtle">
                    parked {new Date(proposal.parked_at * 1000).toLocaleTimeString()}
                  </span>
                </div>
                <p className="mt-1 break-all font-mono text-[11px] text-fg-subtle">
                  {proposal.action_id}
                </p>
                <div className="mt-2">
                  <Button
                    size="sm"
                    tone={selectedProposalId === proposal.action_id ? "primary" : "secondary"}
                    onClick={() => {
                      setSelectedProposalId(proposal.action_id);
                      setActionText(
                        JSON.stringify(
                          { ...proposal.action, incident_id: incidentId },
                          null,
                          2,
                        ),
                      );
                    }}
                  >
                    {selectedProposalId === proposal.action_id
                      ? "Loaded into the request form"
                      : "Load this action"}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

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
            hint="Load a parked action from the panel above to fill this from the pipeline's own plan. Every required field is min_length=1, so a blank template will be rejected by the server."
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
                    {/* decided_by is always a string on the wire ("" when
                        undecided), so `?? "not yet decided"` could never fire
                        and the row rendered blank. Test the empty string. */}
                    {view.decided_by === "" ? "not yet decided" : view.decided_by}{" "}
                    · SoD: {view.sod}
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
                  {/* From the parked proposal the policy engine classified, or
                      explicitly unknown. Never a hardcoded tier: a RED action
                      must not be shown to the approver as YELLOW. */}
                  {selectedProposal === null ? (
                    <span className="font-semibold text-fg-muted">
                      not shown &mdash; no parked action selected
                    </span>
                  ) : (
                    <StatusPill tone={riskTone(selectedProposal.risk_level)}>
                      {selectedProposal.risk_level === ""
                        ? "UNCLASSIFIED"
                        : selectedProposal.risk_level}
                    </StatusPill>
                  )}
                </div>
                <div>
                  <span className="text-fg-subtle">Separation of Duties: </span>
                  <span className="font-mono text-ok">{view.sod}</span>
                </div>
                <div>
                  <span className="text-fg-subtle">Params bound: </span>
                  <span className="break-all font-mono text-fg">
                    {view.params_hash}
                  </span>
                </div>
              </div>
              {/* Real resource-level blast radius, from the planned action. */}
              {selectedProposal !== null && (
                <div className="mt-3 border-t border-line pt-2">
                  <BlastRadius action={selectedProposal.action} />
                </div>
              )}
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
                  duties is not enforced. The buttons are left enabled in this
                  mode only so the flow is demonstrable in the default
                  deployment &mdash; the server still refuses any decision its
                  own policy does not permit. Deploy a per-key store
                  (var/api_keys.json) for four-eyes control.
                </Notice>
              )}
              <TextAreaField
                label="Denial reason (recorded in the audit chain)"
                id="deny-reason"
                rows={2}
                value={denyReason}
                onChange={(event) => setDenyReason(event.target.value)}
                hint="Required by good practice, optional by the server. A denial with an empty reason reaches the audit chain with no operator rationale."
              />
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
