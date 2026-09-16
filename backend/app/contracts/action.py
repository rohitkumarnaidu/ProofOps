"""M01.7 Action schema - canonical Action contract.

Ownership: M01.7 owns THIS FILE ONLY (``backend/app/contracts/action.py``).
Frozen vocabulary (``ActionType``/``Environment``/``RiskLevel``) is owned by
M01.1 and is imported, never redeclared. ``ACTION_TYPES`` is the M01.1
allowlist source: ``action_type`` is a strict ``ActionType`` member, so an
unknown action can never be constructed. Legacy ``app.schemas`` is a compat
layer owned by M01.1 - it is read in tests/bridges but never modified here.

Spec: PS03_FINAL_SPEC_V2 S16::

    Action{action_id, incident_id, agent_id, action_type, resource_type,
    resource_id, environment, namespace, parameters (per-type validator:
    replicas int 1..10, image tag ^[a-z0-9._-]+$, no `;|&$()`),
    risk_level ADVISORY, reason, evidence_ids, runbook_id + runbook_version
    pinned, expected_outcome, rollback_action where applicable,
    verification_plan}.

Trust boundary: this module is STRUCTURE ONLY. It guarantees the shape of one
action (allowlist membership, semver pin, namespace shape, parameters-is-a-
mapping, documented bounds). It performs NO shell/metachar policy, NO
per-type parameter semantics (replicas ranges, image-tag regex), NO risk
adjudication, and NO authorization. Those are validator/policy duties (future
M06.1/M06.5): the LLM-proposed ``risk_level`` is ADVISORY and the policy
engine recomputes effective risk. A constructed ``Action`` is well-formed
DATA awaiting validation - never permission to execute. In particular:

- ``parameters`` MUST be a mapping. A bare string (``"kubectl delete ..."``)
  is rejected at construction: no model-generated shell string may travel
  inside an Action toward an executor (the executor itself, M08, additionally
  only implements typed transitions and has no shell path).
- ``risk_level`` from the model is carried verbatim and MUST be ignored by
  authorizers (M06 test: LLM-risk-ignored). It exists so the planner's
  self-assessment is auditable, not so it can downgrade its own scrutiny.

Legacy wire mapping (field names match legacy ``app.schemas.Action``
EXACTLY)::

    action_id / incident_id / agent_id / action_type / resource_type /
    resource_id / environment / namespace / parameters / risk_level /
    reason / evidence_ids / runbook_id / runbook_version /
    expected_outcome / rollback_action / verification_plan.

    ``parameters``/``rollback_action`` store canonical ``FrozenDict``
    (deep-immutable, detached on dump); legacy carries plain dicts and the
    bridges coerce both directions.

Bounds table (explicit maxima; identifier fields reject empty/padded)::

    action_id/incident_id/agent_id  1..MAX_ID_LEN   (128, auto ``new_id``)
    resource_type                   1..MAX_RES_LEN  (128, e.g. deployment)
    resource_id                     1..MAX_RESID_LEN (256, paths/ARNs fit)
    namespace                       k8s DNS-label   (NAMESPACE_RE, 63 chars)
    parameters                      0..MAX_PARAMS_ENTRIES (32; depth/bytes capped)
    reason / expected_outcome       1..MAX_TEXT_LEN (4096, verbatim, non-blank)
    evidence_ids                    0..MAX_EVID_REFS (100 ID strings)
    runbook_id                      1..MAX_ID_LEN   (128)
    runbook_version                 semver x.y.z    (pinned; floating rejected)
    verification_plan               0..MAX_PLAN_STEPS (32 steps, each <=1024)
    rollback_action                 None or mapping (None = irreversible/none;
                                                 bounded like parameters when
                                                 present: 32 entries, depth
                                                 <= 5, bytes <= 16384)

Bypass containment (Escape 1, M01.2-M01.6 standard):
``model_construct`` is overridden to raise ``TypeError`` and
``model_copy(update=...)`` is routed through full re-validation.

NOT implemented here (owned elsewhere): shell/metachar rejection policy and
per-type parameter semantics (M06.1 validator), risk adjudication and
ALLOW/ESCALATE/DENY (M06.5 policy), approval binding via ``params_hash``
(M07), execution/idempotency (M08/M14), verification of outcomes (M09),
rollback conditions (M10).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Optional, Self

from pydantic import BaseModel, Field, field_validator

from app.contracts.enums import ActionType, Environment, RiskLevel
from app.contracts.incident import FrozenDict
from app.contracts.values import NAMESPACE_RE, SEMVER_RE, canonical_json, new_id

MAX_ID_LEN = 128
MAX_RES_LEN = 128
MAX_RESID_LEN = 256
MAX_PARAMS_ENTRIES = 32
MAX_PARAMS_DEPTH = 5
MAX_PARAMS_JSON_BYTES = 16384
MAX_RB_ENTRIES = 32
MAX_RB_DEPTH = 5
MAX_RB_JSON_BYTES = 16384
MAX_TEXT_LEN = 4096
MAX_EVID_REFS = 100
MAX_PLAN_STEPS = 32
MAX_PLAN_STEP_LEN = 1024


def _check_identifier(name: str, value: str, max_len: int) -> str:
    """Shared identifier rule: non-blank, unpadded, bounded."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    return value


def _nested_depth(value: Any) -> int:
    """Deepest container nesting level (scalars 0). Iterative: no recursion limit."""
    best = 0
    stack: list[Any] = [value]
    levels: list[int] = [0]
    while stack:
        v = stack.pop()
        d = levels.pop()
        if isinstance(v, (Mapping, FrozenDict)):
            best = max(best, d + 1)
            for item in v.values():
                stack.append(item)
                levels.append(d + 1)
        elif isinstance(v, (list, tuple)):
            best = max(best, d + 1)
            for item in v:
                stack.append(item)
                levels.append(d + 1)
    return best


def _check_parameters(value: Any) -> FrozenDict:
    """Parameters rule: must be a mapping (shell strings rejected), bounded."""
    if isinstance(value, FrozenDict):
        params = value
    elif isinstance(value, Mapping):
        try:
            params = FrozenDict(dict(value))
        except Exception as exc:
            raise ValueError("parameters must be a string-keyed object") from exc
    else:
        raise ValueError(
            "parameters must be an object, never a string/command "
            f"(got {type(value).__name__})"
        )
    if len(params) > MAX_PARAMS_ENTRIES:
        raise ValueError(
            f"parameters must hold at most {MAX_PARAMS_ENTRIES} entries")
    for k in params:
        _check_identifier("parameters keys", k, MAX_ID_LEN)
    if _nested_depth(params) > MAX_PARAMS_DEPTH:
        raise ValueError(
            f"parameters must nest at most {MAX_PARAMS_DEPTH} levels deep")
    size = len(canonical_json(params.to_plain()).encode("utf-8"))
    if size > MAX_PARAMS_JSON_BYTES:
        raise ValueError(
            f"parameters must serialize within {MAX_PARAMS_JSON_BYTES} bytes")
    return params


class Action(BaseModel):
    """One structured action proposal: typed mutation request, no authority."""

    model_config = {"frozen": True, "extra": "forbid"}

    action_id: str = Field(
        default_factory=new_id,
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Opaque id, doubles as idempotency key (M08/M14).",
    )
    incident_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Owning incident (plain str link; M01.2 owns Incident).",
    )
    agent_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Proposing agent (e.g. remediation-planner).",
    )
    action_type: ActionType = Field(
        description="Strict M01.1 ActionType (unknown actions rejected).",
    )
    resource_type: str = Field(
        min_length=1,
        max_length=MAX_RES_LEN,
        description="Resource kind (e.g. deployment, pod).",
    )
    resource_id: str = Field(
        min_length=1,
        max_length=MAX_RESID_LEN,
        description="Resource name/ref (paths/ARNs fit).",
    )
    environment: Environment = Field(
        default=Environment.MOCK,
        description="Workload environment (strict; AppEnv is NOT accepted).",
    )
    namespace: str = Field(
        default="default",
        description="K8s DNS-label namespace.",
    )
    parameters: FrozenDict = Field(
        default_factory=FrozenDict,
        description="Typed parameters (mapping only; shell strings rejected).",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.GREEN,
        description="ADVISORY self-assessment; policy recomputes (ignore me).",
    )
    reason: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LEN,
        description="Why this action (verbatim, non-blank).",
    )
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        description="Justifying evidence IDs (mutation needs >=1 per M06).",
    )
    runbook_id: str = Field(
        min_length=1,
        max_length=MAX_ID_LEN,
        description="Pinned runbook id (SELECT+PARAMETERIZE only).",
    )
    runbook_version: str = Field(
        min_length=1,
        description="Pinned runbook semver x.y.z (floating rejected).",
    )
    expected_outcome: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LEN,
        description="Expected post-state (verbatim, non-blank).",
    )
    rollback_action: Optional[FrozenDict] = Field(
        default=None,
        description="Rollback template; None = irreversible/none carried.",
    )
    verification_plan: tuple[str, ...] = Field(
        default=(),
        description="Verification step names (checked by M09).",
    )

    # -- Escape 1: bypass containment --------------------------------------
    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:
        """BLOCKED: Pydantic's validation-bypassing constructor."""
        raise TypeError(
            "Action.model_construct is blocked: it skips validation. "
            "Use Action(...) or Action.model_validate for trusted instances."
        )

    def model_copy(self, *, update: Mapping[str, Any] | None = None,
                   deep: bool = False) -> Self:
        """Copy, with ``update=`` routed through full re-validation."""
        if update:
            merged = self.model_dump()
            merged.update(dict(update))
            return self.model_validate(merged)
        return super().model_copy(update=None, deep=deep)

    @field_validator("action_id", "incident_id", "agent_id")
    @classmethod
    def _ids(cls, v: str, info: Any) -> str:
        return _check_identifier(str(info.field_name), v, MAX_ID_LEN)

    @field_validator("resource_type")
    @classmethod
    def _resource_type(cls, v: str) -> str:
        return _check_identifier("resource_type", v, MAX_RES_LEN)

    @field_validator("resource_id")
    @classmethod
    def _resource_id(cls, v: str) -> str:
        return _check_identifier("resource_id", v, MAX_RESID_LEN)

    @field_validator("namespace")
    @classmethod
    def _namespace(cls, v: str) -> str:
        if not isinstance(v, str) or not NAMESPACE_RE.match(v):
            raise ValueError(f"invalid k8s namespace: {v!r}")
        return v

    @field_validator("parameters", mode="before")
    @classmethod
    def _parameters(cls, v: Any) -> Any:
        return _check_parameters(v)

    @field_validator("reason", "expected_outcome")
    @classmethod
    def _prose(cls, v: str, info: Any) -> str:
        name = str(info.field_name)
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{name} must be a non-empty string")
        if v != v.strip():
            raise ValueError(f"{name} must not have leading/trailing whitespace")
        if len(v) > MAX_TEXT_LEN:
            raise ValueError(f"{name} must be at most {MAX_TEXT_LEN} characters")
        return v

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _evidence_ids(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("evidence_ids must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("evidence_ids must be a list of ID strings")
        items = list(v)
        if len(items) > MAX_EVID_REFS:
            raise ValueError(f"evidence_ids must hold at most {MAX_EVID_REFS} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str):
                raise ValueError("evidence_ids entries must be non-empty strings")
            checked.append(_check_identifier("evidence_ids entries", item, MAX_ID_LEN))
        return checked

    @field_validator("runbook_id")
    @classmethod
    def _runbook_id(cls, v: str) -> str:
        return _check_identifier("runbook_id", v, MAX_ID_LEN)

    @field_validator("runbook_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not isinstance(v, str) or not SEMVER_RE.match(v):
            raise ValueError(
                f"runbook version must be pinned semver x.y.z, got: {v!r}")
        return v

    @field_validator("rollback_action", mode="before")
    @classmethod
    def _rollback_action(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, FrozenDict):
            action = v
        elif isinstance(v, Mapping):
            action = FrozenDict(dict(v))
        else:
            raise ValueError("rollback_action must be an object or null")
        # Same containment as parameters: an unbounded rollback template is
        # an unbounded future mutation. None stays the irreversible marker.
        if len(action) > MAX_RB_ENTRIES:
            raise ValueError(
                f"rollback_action must hold at most {MAX_RB_ENTRIES} entries")
        for k in action:
            _check_identifier("rollback_action keys", k, MAX_ID_LEN)
        if _nested_depth(action) > MAX_RB_DEPTH:
            raise ValueError(
                f"rollback_action must nest at most {MAX_RB_DEPTH} levels deep")
        size = len(canonical_json(action.to_plain()).encode("utf-8"))
        if size > MAX_RB_JSON_BYTES:
            raise ValueError(
                f"rollback_action must serialize within {MAX_RB_JSON_BYTES} bytes")
        return action

    @field_validator("verification_plan", mode="before")
    @classmethod
    def _verification_plan(cls, v: Any) -> Any:
        if v is None:
            raise ValueError("verification_plan must be a list, not null")
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple)):
            raise ValueError("verification_plan must be a list of strings")
        items = list(v)
        if len(items) > MAX_PLAN_STEPS:
            raise ValueError(
                f"verification_plan must hold at most {MAX_PLAN_STEPS} entries")
        checked: list[str] = []
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("verification_plan entries must be non-empty strings")
            if item != item.strip():
                raise ValueError(
                    "verification_plan entries must not have leading/trailing whitespace")
            if len(item) > MAX_PLAN_STEP_LEN:
                raise ValueError(
                    f"verification_plan entries must be at most {MAX_PLAN_STEP_LEN} characters")
            checked.append(item)
        return checked

    @classmethod
    def from_legacy(cls, legacy: Any) -> Action:
        """Build a canonical Action from ``app.schemas.Action`` (1:1 wire)."""
        if type(legacy) is cls:
            return legacy  # already canonical: exact, no coercion
        return cls(
            action_id=str(legacy.action_id),
            incident_id=str(legacy.incident_id),
            agent_id=str(legacy.agent_id),
            action_type=legacy.action_type,
            resource_type=str(legacy.resource_type),
            resource_id=str(legacy.resource_id),
            environment=legacy.environment,
            namespace=str(legacy.namespace),
            parameters=FrozenDict(dict(legacy.parameters)),
            risk_level=legacy.risk_level,
            reason=str(legacy.reason),
            evidence_ids=tuple(legacy.evidence_ids),
            runbook_id=str(legacy.runbook_id),
            runbook_version=str(legacy.runbook_version),
            expected_outcome=str(legacy.expected_outcome),
            rollback_action=(None if legacy.rollback_action is None
                             else FrozenDict(dict(legacy.rollback_action))),
            verification_plan=tuple(legacy.verification_plan),
        )

    def to_legacy(self) -> Any:
        """Convert back to the legacy ``app.schemas.Action`` shape."""
        from app.schemas import Action as LegacyAction  # noqa: E402

        return LegacyAction(
            action_id=self.action_id,
            incident_id=self.incident_id,
            agent_id=self.agent_id,
            action_type=self.action_type,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            environment=self.environment,
            namespace=self.namespace,
            parameters=self.parameters,
            risk_level=self.risk_level,
            reason=self.reason,
            evidence_ids=self.evidence_ids,
            runbook_id=self.runbook_id,
            runbook_version=self.runbook_version,
            expected_outcome=self.expected_outcome,
            rollback_action=self.rollback_action,
            verification_plan=self.verification_plan,
        )
