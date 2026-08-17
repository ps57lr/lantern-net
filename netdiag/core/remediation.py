"""Fail-closed remediation planning and lifecycle contracts.

This module provides orchestration only. It contains no host-changing action.
Concrete actions must be explicitly registered elsewhere after safety review.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Protocol

from netdiag.core.evidence import ErrorDetail, EvidenceStore
from netdiag.core.execution import CancellationToken, CancelledError, PlatformInfo
from netdiag.core.redaction import (
    RedactionAction,
    RedactionPolicy,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.status import RiskTier, Sensitivity
from netdiag.core.values import (
    JsonValue,
    validate_dotted_identifier,
    validate_finding_code,
    validate_nonempty_text,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ActionState(_StringEnum):
    PLANNED = "planned"
    PREVIEWED = "previewed"
    PREVIEW_FAILED = "preview_failed"
    DRY_RUN_COMPLETE = "dry_run_complete"
    AWAITING_APPROVAL = "awaiting_approval"
    MANUAL_ONLY = "manual_only"
    DECLINED = "declined"
    APPROVED = "approved"
    APPLYING = "applying"
    APPLIED = "applied"
    APPLY_FAILED = "apply_failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    VERIFY_FAILED = "verify_failed"
    ROLLBACK_OFFERED = "rollback_offered"
    ROLLBACK_APPROVED = "rollback_approved"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ActionTarget:
    kind: str
    reference: str = field(metadata={"sensitivity": Sensitivity.DEVICE_IDENTIFIER})
    display_name: str = field(metadata={"sensitivity": Sensitivity.DEVICE_IDENTIFIER})

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.kind, label="target kind")
        validate_nonempty_text(self.reference, label="target reference", maximum=1024)
        validate_nonempty_text(self.display_name, label="target display name", maximum=256)
        if any(ord(character) < 32 for character in self.reference):
            raise ValueError("target reference contains control characters")


@dataclass(frozen=True)
class PlannedChange:
    change_id: str
    description: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    reversible: bool

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.change_id, label="change id")
        validate_nonempty_text(self.description, label="change description", maximum=1024)
        if not isinstance(self.reversible, bool):
            raise TypeError("change reversible must be a boolean")


@dataclass(frozen=True)
class PreviewResult:
    summary: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    changes: tuple[PlannedChange, ...]
    precondition_digest: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_nonempty_text(self.summary, label="preview summary", maximum=2048)
        if not isinstance(self.changes, tuple) or any(
            not isinstance(change, PlannedChange) for change in self.changes
        ):
            raise TypeError("changes must be a tuple of PlannedChange instances")
        _validate_digest(self.precondition_digest, label="precondition_digest")
        _validate_refs(self.evidence_refs, label="preview evidence_refs")
        if len({change.change_id for change in self.changes}) != len(self.changes):
            raise ValueError("preview change identifiers must be unique")


@dataclass(frozen=True)
class ApplyResult:
    changed: bool
    summary: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    rollback_handle_id: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.changed, bool):
            raise TypeError("changed must be a boolean")
        validate_nonempty_text(self.summary, label="apply summary", maximum=2048)
        if self.rollback_handle_id is not None:
            validate_dotted_identifier(self.rollback_handle_id, label="rollback handle id")
        _validate_refs(self.evidence_refs, label="apply evidence_refs")


@dataclass(frozen=True)
class VerificationResult:
    successful: bool
    summary: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.successful, bool):
            raise TypeError("successful must be a boolean")
        validate_nonempty_text(self.summary, label="verification summary", maximum=2048)
        _validate_refs(self.evidence_refs, label="verification evidence_refs")


@dataclass(frozen=True)
class RollbackResult:
    successful: bool
    summary: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.successful, bool):
            raise TypeError("successful must be a boolean")
        validate_nonempty_text(self.summary, label="rollback summary", maximum=2048)
        _validate_refs(self.evidence_refs, label="rollback evidence_refs")


@dataclass(frozen=True)
class ActionContext:
    platform: PlatformInfo
    cancellation: CancellationToken
    evidence: EvidenceStore
    granted_permission_ids: tuple[str, ...] = ()
    confirmed_access_prerequisite_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.platform, PlatformInfo):
            raise TypeError("platform must be PlatformInfo")
        if not isinstance(self.cancellation, CancellationToken):
            raise TypeError("cancellation must be CancellationToken")
        if not isinstance(self.evidence, EvidenceStore):
            raise TypeError("evidence must be EvidenceStore")
        for permission_id in self.granted_permission_ids:
            validate_dotted_identifier(permission_id, label="granted permission id")
        _validate_unique(self.granted_permission_ids, label="granted_permission_ids")
        for prerequisite_id in self.confirmed_access_prerequisite_ids:
            validate_dotted_identifier(prerequisite_id, label="confirmed access prerequisite id")
        _validate_unique(
            self.confirmed_access_prerequisite_ids,
            label="confirmed_access_prerequisite_ids",
        )


class Previewer(Protocol):
    def __call__(self, plan: ActionPlan, context: ActionContext) -> PreviewResult: ...


class PreconditionChecker(Protocol):
    def __call__(self, plan: ActionPlan, context: ActionContext) -> str: ...


class Applier(Protocol):
    def __call__(
        self, plan: ActionPlan, preview: PreviewResult, context: ActionContext
    ) -> ApplyResult: ...


class Verifier(Protocol):
    def __call__(
        self, plan: ActionPlan, applied: ApplyResult, context: ActionContext
    ) -> VerificationResult: ...


class Rollbacker(Protocol):
    def __call__(
        self, plan: ActionPlan, applied: ApplyResult, context: ActionContext
    ) -> RollbackResult: ...


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    revision: int
    title: str
    description: str
    risk: RiskTier
    supported_systems: tuple[str, ...]
    addressed_findings: tuple[str, ...]
    permission_ids: tuple[str, ...]
    access_prerequisite_ids: tuple[str, ...]
    expected_interruption: str
    estimated_duration_seconds: float
    reboot_required: bool
    reversible: bool
    previewer: Previewer
    precondition_checker: PreconditionChecker | None = None
    applier: Applier | None = None
    verifier: Verifier | None = None
    rollbacker: Rollbacker | None = None
    manual_steps: tuple[str, ...] = ()
    manual_recovery: str = ""

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.action_id, label="action id")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 1
        ):
            raise ValueError("action revision must be a positive integer")
        validate_nonempty_text(self.title, label="action title", maximum=160)
        validate_nonempty_text(self.description, label="action description", maximum=2048)
        if not isinstance(self.risk, RiskTier):
            raise TypeError("risk must be a RiskTier")
        validate_nonempty_text(
            self.expected_interruption,
            label="expected interruption",
            maximum=512,
        )
        if (
            isinstance(self.estimated_duration_seconds, bool)
            or not isinstance(self.estimated_duration_seconds, (int, float))
            or not math.isfinite(self.estimated_duration_seconds)
            or self.estimated_duration_seconds <= 0
            or self.estimated_duration_seconds > 86_400
        ):
            raise ValueError("estimated duration must be greater than 0 and at most one day")
        if not self.supported_systems or any(
            not isinstance(system, str) or not system.strip() for system in self.supported_systems
        ):
            raise ValueError("supported_systems must contain non-empty names")
        _validate_unique(self.supported_systems, label="supported_systems")
        for code in self.addressed_findings:
            validate_finding_code(code)
        _validate_unique(self.addressed_findings, label="addressed_findings")
        for permission_id in self.permission_ids:
            validate_dotted_identifier(permission_id, label="permission id")
        _validate_unique(self.permission_ids, label="permission_ids")
        for prerequisite_id in self.access_prerequisite_ids:
            validate_dotted_identifier(prerequisite_id, label="access prerequisite id")
        _validate_unique(self.access_prerequisite_ids, label="access_prerequisite_ids")
        if not callable(self.previewer):
            raise TypeError("previewer must be callable")
        if not isinstance(self.reboot_required, bool) or not isinstance(self.reversible, bool):
            raise TypeError("reboot_required and reversible must be booleans")
        if self.risk == RiskTier.RED:
            if any(
                handler is not None for handler in (self.applier, self.verifier, self.rollbacker)
            ):
                raise ValueError(
                    "red actions are manual-only and cannot register executable handlers"
                )
            if not self.manual_steps:
                raise ValueError("red actions must provide manual steps")
        else:
            if (
                not callable(self.precondition_checker)
                or not callable(self.applier)
                or not callable(self.verifier)
            ):
                raise ValueError(
                    "executable actions require precondition, apply, and verify handlers"
                )
            if self.risk == RiskTier.GREEN and not self.reversible:
                raise ValueError("green actions must be reversible")
            if self.reversible and not callable(self.rollbacker):
                raise ValueError("reversible actions require a rollback handler")
            if not self.reversible and not self.manual_recovery.strip():
                raise ValueError("non-reversible actions require a manual recovery path")
        if any(not isinstance(step, str) or not step.strip() for step in self.manual_steps):
            raise ValueError("manual_steps must contain non-empty strings")


@dataclass(frozen=True)
class ActionPlan:
    plan_id: str
    action_id: str
    action_revision: int
    platform_system: str
    target: ActionTarget
    created_at: datetime
    expires_at: datetime
    finding_refs: tuple[str, ...]
    permission_ids: tuple[str, ...]
    access_prerequisite_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.plan_id, label="plan id")
        validate_dotted_identifier(self.action_id, label="action id")
        if (
            not isinstance(self.action_revision, int)
            or isinstance(self.action_revision, bool)
            or self.action_revision < 1
        ):
            raise ValueError("action_revision must be positive")
        validate_nonempty_text(self.platform_system, label="plan platform", maximum=64)
        if not isinstance(self.target, ActionTarget):
            raise TypeError("target must be an ActionTarget")
        _validate_aware(self.created_at, label="created_at")
        _validate_aware(self.expires_at, label="expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("plan expiration must be after creation")
        _validate_refs(self.finding_refs, label="finding_refs")
        _validate_refs(self.permission_ids, label="permission_ids")
        _validate_refs(self.access_prerequisite_ids, label="access_prerequisite_ids")

    @property
    def digest(self) -> str:
        return _digest(
            {
                "plan_id": self.plan_id,
                "action_id": self.action_id,
                "action_revision": self.action_revision,
                "platform_system": self.platform_system,
                "target": self.target,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "finding_refs": self.finding_refs,
                "permission_ids": self.permission_ids,
                "access_prerequisite_ids": self.access_prerequisite_ids,
            }
        )


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    challenge_digest: str
    operation: str
    channel: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.approval_id, label="approval id")
        _validate_digest(self.challenge_digest, label="challenge digest")
        if self.operation not in {"apply", "rollback"}:
            raise ValueError("approval operation must be apply or rollback")
        validate_dotted_identifier(self.channel, label="approval channel")
        _validate_aware(self.approved_at, label="approved_at")
        _validate_aware(self.expires_at, label="expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiration must be after approval")


@dataclass(frozen=True)
class ActionTransition:
    from_state: ActionState | None
    to_state: ActionState
    at: datetime
    reason: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})

    def __post_init__(self) -> None:
        if self.from_state is not None and not isinstance(self.from_state, ActionState):
            raise TypeError("from_state must be an ActionState or None")
        if not isinstance(self.to_state, ActionState):
            raise TypeError("to_state must be an ActionState")
        _validate_aware(self.at, label="transition timestamp")
        validate_nonempty_text(self.reason, label="transition reason", maximum=512)


@dataclass(frozen=True)
class ActionAttempt:
    attempt_id: str
    plan: ActionPlan
    state: ActionState
    transitions: tuple[ActionTransition, ...]
    preview: PreviewResult | None = None
    apply_result: ApplyResult | None = None
    verification: VerificationResult | None = None
    rollback_result: RollbackResult | None = None
    approval: ApprovalRecord | None = None
    rollback_approval: ApprovalRecord | None = None
    error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.attempt_id, label="attempt id")
        if type(self.plan) is not ActionPlan:
            raise TypeError("plan must be an ActionPlan")
        if type(self.state) is not ActionState:
            raise TypeError("state must be an ActionState")
        if type(self.transitions) is not tuple or any(
            type(transition) is not ActionTransition for transition in self.transitions
        ):
            raise TypeError("transitions must be a tuple of ActionTransition instances")
        for value, expected, label in (
            (self.preview, PreviewResult, "preview"),
            (self.apply_result, ApplyResult, "apply_result"),
            (self.verification, VerificationResult, "verification"),
            (self.rollback_result, RollbackResult, "rollback_result"),
            (self.approval, ApprovalRecord, "approval"),
            (self.rollback_approval, ApprovalRecord, "rollback_approval"),
            (self.error, ErrorDetail, "error"),
        ):
            if value is not None and type(value) is not expected:
                raise TypeError(f"{label} must be {expected.__name__} or None")
        if not self.transitions:
            raise ValueError("an action attempt must include its initial transition")
        if self.transitions[-1].to_state != self.state:
            raise ValueError("last transition must match current action state")
        self._revalidate_nested_models()

    def to_dict(self) -> dict[str, JsonValue]:
        """Return an audit-safe representation with no executable handlers."""

        # Frozen dataclasses prevent ordinary mutation, but callers holding a
        # reference can still bypass that protection with object.__setattr__.
        # Revalidate the complete typed tree at the export boundary so a
        # substituted scalar cannot inherit a PUBLIC boolean/timestamp slot.
        self.__post_init__()
        serialized = serialize_structured(
            self,
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_ACTION_AUDIT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized

    def _revalidate_nested_models(self) -> None:
        self.plan.__post_init__()
        if type(self.plan.target) is not ActionTarget:
            raise TypeError("plan target must be an ActionTarget")
        self.plan.target.__post_init__()
        for transition in self.transitions:
            transition.__post_init__()
        if self.preview is not None:
            self.preview.__post_init__()
            if type(self.preview.changes) is not tuple or any(
                type(change) is not PlannedChange for change in self.preview.changes
            ):
                raise TypeError("preview changes must be a tuple of PlannedChange instances")
            for change in self.preview.changes:
                change.__post_init__()
        if self.apply_result is not None:
            self.apply_result.__post_init__()
        if self.verification is not None:
            self.verification.__post_init__()
        if self.rollback_result is not None:
            self.rollback_result.__post_init__()
        if self.approval is not None:
            self.approval.__post_init__()
        if self.rollback_approval is not None:
            self.rollback_approval.__post_init__()
        if self.error is not None:
            self.error.__post_init__()


class InvalidActionTransition(RuntimeError):
    pass


class ApprovalError(RuntimeError):
    pass


class PrerequisiteError(RuntimeError):
    pass


_ACTION_AUDIT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/attempt_id": Sensitivity.POTENTIAL_SECRET,
        "/plan/plan_id": Sensitivity.POTENTIAL_SECRET,
        "/plan/action_id": Sensitivity.POTENTIAL_SECRET,
        "/plan/action_revision": Sensitivity.PUBLIC,
        "/plan/platform_system": Sensitivity.POTENTIAL_SECRET,
        "/plan/target/kind": Sensitivity.POTENTIAL_SECRET,
        "/plan/created_at": Sensitivity.PUBLIC,
        "/plan/expires_at": Sensitivity.PUBLIC,
        "/plan/finding_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/plan/permission_ids/*": Sensitivity.POTENTIAL_SECRET,
        "/plan/access_prerequisite_ids/*": Sensitivity.POTENTIAL_SECRET,
        "/state": Sensitivity.PUBLIC,
        "/transitions/*/from_state": Sensitivity.PUBLIC,
        "/transitions/*/to_state": Sensitivity.PUBLIC,
        "/transitions/*/at": Sensitivity.PUBLIC,
        "/preview/changes/*/change_id": Sensitivity.POTENTIAL_SECRET,
        "/preview/changes/*/reversible": Sensitivity.PUBLIC,
        "/preview/precondition_digest": Sensitivity.PUBLIC,
        "/preview/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/apply_result/changed": Sensitivity.PUBLIC,
        "/apply_result/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/verification/successful": Sensitivity.PUBLIC,
        "/verification/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/rollback_result/successful": Sensitivity.PUBLIC,
        "/rollback_result/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/approval/approval_id": Sensitivity.POTENTIAL_SECRET,
        "/approval/operation": Sensitivity.PUBLIC,
        "/approval/channel": Sensitivity.POTENTIAL_SECRET,
        "/approval/approved_at": Sensitivity.PUBLIC,
        "/approval/expires_at": Sensitivity.PUBLIC,
        "/rollback_approval/approval_id": Sensitivity.POTENTIAL_SECRET,
        "/rollback_approval/operation": Sensitivity.PUBLIC,
        "/rollback_approval/channel": Sensitivity.POTENTIAL_SECRET,
        "/rollback_approval/approved_at": Sensitivity.PUBLIC,
        "/rollback_approval/expires_at": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)


class ActionExecutionError(RuntimeError):
    """An expected action error with an explicit mutation state."""

    def __init__(self, detail: ErrorDetail, *, changed: bool | None) -> None:
        super().__init__(detail.message)
        self.detail = detail
        self.changed = changed


@dataclass(frozen=True, slots=True)
class _ReviewedActionBinding:
    """Process-local immutable binding to the exact spec reviewed at plan time."""

    spec: ActionSpec = field(repr=False, compare=False)
    spec_fingerprint: str
    plan: ActionPlan = field(repr=False, compare=False)
    plan_digest: str
    attempt_id: str
    risk: RiskTier
    supported_systems: tuple[str, ...]
    reversible: bool
    previewer: Previewer = field(repr=False, compare=False)
    precondition_checker: PreconditionChecker | None = field(repr=False, compare=False)
    applier: Applier | None = field(repr=False, compare=False)
    verifier: Verifier | None = field(repr=False, compare=False)
    rollbacker: Rollbacker | None = field(repr=False, compare=False)

    @classmethod
    def capture(
        cls,
        spec: ActionSpec,
        plan: ActionPlan,
        attempt_id: str,
    ) -> _ReviewedActionBinding:
        return cls(
            spec=spec,
            spec_fingerprint=_action_spec_fingerprint(spec),
            plan=plan,
            plan_digest=plan.digest,
            attempt_id=attempt_id,
            risk=spec.risk,
            supported_systems=spec.supported_systems,
            reversible=spec.reversible,
            previewer=spec.previewer,
            precondition_checker=spec.precondition_checker,
            applier=spec.applier,
            verifier=spec.verifier,
            rollbacker=spec.rollbacker,
        )


class RemediationEngine:
    """Lifecycle coordinator bound to exact reviewed action specs in memory."""

    def __init__(
        self,
        *,
        now: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4().hex}")
        self._binding_lock = RLock()
        self._bindings: dict[str, _ReviewedActionBinding] = {}
        self._canonical_attempts: dict[str, ActionAttempt] = {}
        self._canonical_attempt_digests: dict[str, str] = {}

    def plan(
        self,
        spec: ActionSpec,
        target: ActionTarget,
        platform: PlatformInfo,
        *,
        finding_refs: tuple[str, ...] = (),
        ttl_seconds: float = 900,
    ) -> ActionAttempt:
        now = self._aware_now()
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
            or ttl_seconds > 86_400
        ):
            raise ValueError("plan ttl must be greater than 0 and at most one day")
        if platform.system not in spec.supported_systems:
            raise ValueError(f"{spec.action_id} does not support platform {platform.system}")
        plan = ActionPlan(
            plan_id=self._id_factory("plan"),
            action_id=spec.action_id,
            action_revision=spec.revision,
            platform_system=platform.system,
            target=target,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            finding_refs=finding_refs,
            permission_ids=spec.permission_ids,
            access_prerequisite_ids=spec.access_prerequisite_ids,
        )
        transition = ActionTransition(None, ActionState.PLANNED, now, "action plan created")
        attempt = ActionAttempt(
            attempt_id=self._id_factory("attempt"),
            plan=plan,
            state=ActionState.PLANNED,
            transitions=(transition,),
        )
        binding = _ReviewedActionBinding.capture(spec, plan, attempt.attempt_id)
        with self._binding_lock:
            if plan.plan_id in self._bindings:
                raise InvalidActionTransition("action plan identifier is already bound")
            self._bindings[plan.plan_id] = binding
            self._canonical_attempts[plan.plan_id] = attempt
            self._canonical_attempt_digests[plan.plan_id] = _digest(attempt)
        return attempt

    def preview(
        self, spec: ActionSpec, attempt: ActionAttempt, context: ActionContext
    ) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.PLANNED)
        try:
            self._require_context(binding, attempt, context)
            self._require_live_plan(attempt)
            context.cancellation.raise_if_cancelled()
            self._require_bound_spec(spec, attempt)
            result = binding.previewer(attempt.plan, context)
            if not isinstance(result, PreviewResult):
                raise TypeError("previewer did not return PreviewResult")
        except CancelledError:
            return self._transition(attempt, ActionState.CANCELLED, "preview cancelled")
        except Exception as exc:  # noqa: BLE001 - contain an action boundary.
            detail = _safe_action_error("netdiag.action.preview", exc)
            return self._transition(
                replace(attempt, error=detail),
                ActionState.PREVIEW_FAILED,
                "preview failed",
            )
        return self._transition(
            replace(attempt, preview=result, error=None),
            ActionState.PREVIEWED,
            "preview completed",
        )

    def complete_dry_run(self, attempt: ActionAttempt) -> ActionAttempt:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.PREVIEWED)
        return self._transition(
            attempt,
            ActionState.DRY_RUN_COMPLETE,
            "dry-run completed without invoking apply",
        )

    def request_approval(self, spec: ActionSpec, attempt: ActionAttempt) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.PREVIEWED)
        self._require_live_plan(attempt)
        if binding.risk == RiskTier.RED:
            return self._transition(
                attempt,
                ActionState.MANUAL_ONLY,
                "red-tier action is guidance only",
            )
        return self._transition(
            attempt,
            ActionState.AWAITING_APPROVAL,
            "explicit apply approval required",
        )

    def approval_challenge(self, attempt: ActionAttempt) -> str:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.AWAITING_APPROVAL)
        if attempt.preview is None:
            raise InvalidActionTransition("an approval challenge requires a preview")
        return _digest(
            {
                "operation": "apply",
                "plan_digest": attempt.plan.digest,
                "preview": attempt.preview,
            }
        )

    def approve(
        self,
        attempt: ActionAttempt,
        *,
        challenge_digest: str,
        channel: str,
        ttl_seconds: float = 300,
    ) -> ActionAttempt:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.AWAITING_APPROVAL)
        self._require_live_plan(attempt)
        _validate_digest(challenge_digest, label="approval challenge")
        expected = self.approval_challenge(attempt)
        if not _constant_time_equal(challenge_digest, expected):
            raise ApprovalError("approval challenge does not match this action preview")
        approval = self._approval(
            attempt,
            challenge_digest=challenge_digest,
            operation="apply",
            channel=channel,
            ttl_seconds=ttl_seconds,
        )
        return self._transition(
            replace(attempt, approval=approval),
            ActionState.APPROVED,
            "apply approved",
        )

    def decline(self, attempt: ActionAttempt) -> ActionAttempt:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.AWAITING_APPROVAL)
        return self._transition(attempt, ActionState.DECLINED, "apply declined")

    def apply(
        self, spec: ActionSpec, attempt: ActionAttempt, context: ActionContext
    ) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.APPROVED)
        self._require_context(binding, attempt, context)
        self._require_live_plan(attempt)
        self._require_valid_approval(attempt, operation="apply")
        if binding.precondition_checker is None or binding.applier is None:
            raise InvalidActionTransition("action has no executable handlers")
        try:
            context.cancellation.raise_if_cancelled()
            self._require_prerequisites(attempt.plan, context)
        except CancelledError:
            return self._transition(
                attempt, ActionState.CANCELLED, "apply cancelled before mutation"
            )
        except PrerequisiteError as exc:
            return self._transition(
                replace(
                    attempt,
                    error=ErrorDetail(
                        "netdiag.action.prerequisite_missing",
                        str(exc),
                    ),
                ),
                ActionState.APPLY_FAILED,
                "required permission or outside access is unavailable",
            )

        try:
            self._require_bound_spec(spec, attempt)
            current_preconditions = binding.precondition_checker(attempt.plan, context)
            _validate_digest(current_preconditions, label="current precondition digest")
        except Exception as exc:  # noqa: BLE001 - read-only preflight fails closed.
            return self._transition(
                replace(
                    attempt,
                    error=_safe_action_error("netdiag.action.precondition", exc),
                ),
                ActionState.APPLY_FAILED,
                "preconditions could not be revalidated",
            )
        preview = _require_preview(attempt)
        if not _constant_time_equal(current_preconditions, preview.precondition_digest):
            return self._transition(
                replace(
                    attempt,
                    error=ErrorDetail(
                        "netdiag.action.preconditions_changed",
                        "Action preconditions changed after preview",
                        retryable=True,
                    ),
                ),
                ActionState.APPLY_FAILED,
                "preconditions changed; generate and approve a new preview",
            )

        # The read-only checker may be slow or may itself observe cancellation.
        # Authority is time-bound, so never carry the earlier approval/cancellation
        # decision across that boundary into a mutation.
        try:
            context.cancellation.raise_if_cancelled()
            self._require_bound_spec(spec, attempt)
            self._require_live_plan(attempt)
            self._require_valid_approval(attempt, operation="apply")
        except CancelledError:
            return self._transition(
                attempt,
                ActionState.CANCELLED,
                "apply cancelled after precondition validation and before mutation",
            )

        applying = self._transition(attempt, ActionState.APPLYING, "apply started")
        try:
            # Recheck after recording APPLYING as well.  This is the final
            # fail-closed gate immediately before invoking a mutating handler.
            context.cancellation.raise_if_cancelled()
            self._require_bound_spec(spec, applying)
            self._require_live_plan(applying)
            self._require_valid_approval(applying, operation="apply")
        except CancelledError:
            return self._transition(
                applying,
                ActionState.CANCELLED,
                "apply cancelled at the final boundary before mutation",
            )

        # From this line onward mutation may have begun.  Even a handler-raised
        # cancellation or approval-shaped error therefore has an unknown outcome.
        try:
            result = binding.applier(applying.plan, preview, context)
            if not isinstance(result, ApplyResult):
                raise TypeError("applier did not return ApplyResult")
            if result.changed and binding.reversible and result.rollback_handle_id is None:
                detail = ErrorDetail(
                    "netdiag.action.rollback_handle_missing",
                    "Reversible action changed state without a rollback handle",
                )
                return self._transition(
                    replace(applying, apply_result=result, error=detail),
                    ActionState.OUTCOME_UNKNOWN,
                    "changed state cannot be rolled back safely",
                )
        except ActionExecutionError as exc:
            state = (
                ActionState.APPLY_FAILED if exc.changed is False else ActionState.OUTCOME_UNKNOWN
            )
            return self._transition(
                replace(applying, error=exc.detail),
                state,
                "apply reported a controlled failure"
                if state == ActionState.APPLY_FAILED
                else "apply outcome is unknown",
            )
        except Exception as exc:  # noqa: BLE001 - unknown mutation state fails closed.
            return self._transition(
                replace(applying, error=_safe_action_error("netdiag.action.apply", exc)),
                ActionState.OUTCOME_UNKNOWN,
                "apply raised after mutation boundary; outcome is unknown",
            )
        return self._transition(
            replace(applying, apply_result=result, error=None),
            ActionState.APPLIED,
            "apply completed; independent verification required",
        )

    def verify(
        self, spec: ActionSpec, attempt: ActionAttempt, context: ActionContext
    ) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.APPLIED)
        self._require_context(binding, attempt, context)
        if binding.verifier is None or attempt.apply_result is None:
            raise InvalidActionTransition("verification requires an apply result and verifier")
        verifying = self._transition(attempt, ActionState.VERIFYING, "verification started")
        try:
            context.cancellation.raise_if_cancelled()
            self._require_bound_spec(spec, verifying)
            result = binding.verifier(verifying.plan, verifying.apply_result, context)
            if not isinstance(result, VerificationResult):
                raise TypeError("verifier did not return VerificationResult")
        except CancelledError:
            return self._transition(
                verifying,
                ActionState.VERIFY_FAILED,
                "verification cancelled; applied outcome remains unverified",
            )
        except Exception as exc:  # noqa: BLE001 - contain verifier boundary.
            return self._transition(
                replace(verifying, error=_safe_action_error("netdiag.action.verify", exc)),
                ActionState.VERIFY_FAILED,
                "verification failed to complete",
            )
        state = ActionState.VERIFIED if result.successful else ActionState.VERIFY_FAILED
        return self._transition(
            replace(verifying, verification=result, error=None),
            state,
            "fresh evidence verified the change"
            if result.successful
            else "fresh evidence did not verify the change",
        )

    def offer_rollback(self, spec: ActionSpec, attempt: ActionAttempt) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.VERIFY_FAILED)
        if not binding.reversible or binding.rollbacker is None or attempt.apply_result is None:
            raise InvalidActionTransition("this action cannot be rolled back automatically")
        return self._transition(
            attempt,
            ActionState.ROLLBACK_OFFERED,
            "separate rollback approval required",
        )

    def rollback_challenge(self, attempt: ActionAttempt) -> str:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.ROLLBACK_OFFERED)
        if attempt.apply_result is None:
            raise InvalidActionTransition("rollback requires an apply result")
        return _digest(
            {
                "operation": "rollback",
                "plan_digest": attempt.plan.digest,
                "apply_result": attempt.apply_result,
                "verification": attempt.verification,
            }
        )

    def approve_rollback(
        self,
        attempt: ActionAttempt,
        *,
        challenge_digest: str,
        channel: str,
        ttl_seconds: float = 300,
    ) -> ActionAttempt:
        self._require_bound_attempt(attempt)
        self._require_state(attempt, ActionState.ROLLBACK_OFFERED)
        _validate_digest(challenge_digest, label="rollback approval challenge")
        expected = self.rollback_challenge(attempt)
        if not _constant_time_equal(challenge_digest, expected):
            raise ApprovalError("approval challenge does not match this rollback")
        approval = self._approval(
            attempt,
            challenge_digest=challenge_digest,
            operation="rollback",
            channel=channel,
            ttl_seconds=ttl_seconds,
        )
        return self._transition(
            replace(attempt, rollback_approval=approval),
            ActionState.ROLLBACK_APPROVED,
            "rollback approved",
        )

    def rollback(
        self, spec: ActionSpec, attempt: ActionAttempt, context: ActionContext
    ) -> ActionAttempt:
        binding = self._require_bound_spec(spec, attempt)
        self._require_state(attempt, ActionState.ROLLBACK_APPROVED)
        self._require_context(binding, attempt, context)
        self._require_valid_approval(attempt, operation="rollback")
        if binding.rollbacker is None or attempt.apply_result is None:
            raise InvalidActionTransition("rollback handler and apply result are required")
        try:
            context.cancellation.raise_if_cancelled()
        except CancelledError:
            return self._transition(
                attempt,
                ActionState.CANCELLED,
                "rollback cancelled before mutation",
            )
        rolling_back = self._transition(attempt, ActionState.ROLLING_BACK, "rollback started")
        try:
            # Approval and cancellation are mutable state.  Re-evaluate them at
            # the last possible moment rather than carrying an earlier decision
            # across the transition/audit write.
            context.cancellation.raise_if_cancelled()
            self._require_bound_spec(spec, rolling_back)
            self._require_valid_approval(rolling_back, operation="rollback")
        except CancelledError:
            return self._transition(
                rolling_back,
                ActionState.CANCELLED,
                "rollback cancelled at the final boundary before mutation",
            )

        try:
            result = binding.rollbacker(rolling_back.plan, rolling_back.apply_result, context)
            if not isinstance(result, RollbackResult):
                raise TypeError("rollbacker did not return RollbackResult")
        except Exception as exc:  # noqa: BLE001 - contain rollback boundary.
            return self._transition(
                replace(
                    rolling_back,
                    error=_safe_action_error("netdiag.action.rollback", exc),
                ),
                ActionState.ROLLBACK_FAILED,
                "rollback failed; manual recovery is required",
            )
        state = ActionState.ROLLED_BACK if result.successful else ActionState.ROLLBACK_FAILED
        return self._transition(
            replace(rolling_back, rollback_result=result, error=None),
            state,
            "rollback verified by handler"
            if result.successful
            else "rollback handler could not restore prior state",
        )

    def _approval(
        self,
        attempt: ActionAttempt,
        *,
        challenge_digest: str,
        operation: str,
        channel: str,
        ttl_seconds: float,
    ) -> ApprovalRecord:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
            or ttl_seconds > 3600
        ):
            raise ValueError("approval ttl must be greater than 0 and at most one hour")
        now = self._aware_now()
        # Apply authority is constrained by the preview plan. Rollback is a
        # recovery operation after a possible mutation and must remain available
        # if verification or human review outlives that original plan. Its fresh
        # approval is still short-lived and bound to the immutable plan, apply
        # result, and verification result through the rollback challenge.
        expires_at = now + timedelta(seconds=ttl_seconds)
        if operation == "apply":
            expires_at = min(attempt.plan.expires_at, expires_at)
        if expires_at <= now:
            raise ApprovalError("action plan has expired")
        return ApprovalRecord(
            approval_id=self._id_factory("approval"),
            challenge_digest=challenge_digest,
            operation=operation,
            channel=channel,
            approved_at=now,
            expires_at=expires_at,
        )

    def _require_valid_approval(self, attempt: ActionAttempt, *, operation: str) -> None:
        approval = attempt.approval if operation == "apply" else attempt.rollback_approval
        if approval is None or approval.operation != operation:
            raise ApprovalError(f"{operation} has not been approved")
        now = self._aware_now()
        if now >= approval.expires_at:
            raise ApprovalError(f"{operation} approval has expired")
        expected = (
            _digest(
                {
                    "operation": "apply",
                    "plan_digest": attempt.plan.digest,
                    "preview": attempt.preview,
                }
            )
            if operation == "apply"
            else _digest(
                {
                    "operation": "rollback",
                    "plan_digest": attempt.plan.digest,
                    "apply_result": attempt.apply_result,
                    "verification": attempt.verification,
                }
            )
        )
        if not _constant_time_equal(approval.challenge_digest, expected):
            raise ApprovalError(f"{operation} approval no longer matches the attempt")

    def _require_live_plan(self, attempt: ActionAttempt) -> None:
        if self._aware_now() >= attempt.plan.expires_at:
            raise ApprovalError("action plan has expired")

    def _require_bound_attempt(self, attempt: ActionAttempt) -> _ReviewedActionBinding:
        if type(attempt) is not ActionAttempt:
            raise InvalidActionTransition("action attempt has an invalid type")
        # Revalidate before trusting identifiers used for the process-local
        # lookup. This also prevents mutated nested PUBLIC fields from crossing
        # a lifecycle boundary.
        try:
            attempt.__post_init__()
        except (TypeError, ValueError) as exc:
            raise InvalidActionTransition("action attempt is structurally invalid") from exc
        with self._binding_lock:
            binding = self._bindings.get(attempt.plan.plan_id)
            canonical = self._canonical_attempts.get(attempt.plan.plan_id)
            canonical_digest = self._canonical_attempt_digests.get(attempt.plan.plan_id)
        if binding is None:
            raise InvalidActionTransition("action attempt is not bound to this engine")
        if canonical is None:
            raise InvalidActionTransition("action attempt has no canonical lifecycle state")
        if canonical_digest is None:
            raise InvalidActionTransition("action attempt has no canonical integrity record")
        if attempt.attempt_id != binding.attempt_id or attempt.plan is not binding.plan:
            raise InvalidActionTransition("action attempt does not match its immutable binding")
        if attempt.state != canonical.state or attempt.transitions is not canonical.transitions:
            raise InvalidActionTransition("action attempt branch is stale or already consumed")
        if not _constant_time_equal(_digest(attempt), canonical_digest):
            raise InvalidActionTransition("action attempt differs from its canonical state")
        if not _constant_time_equal(attempt.plan.digest, binding.plan_digest):
            raise InvalidActionTransition("immutable action plan has changed")
        try:
            current_fingerprint = _action_spec_fingerprint(binding.spec)
        except (TypeError, ValueError) as exc:
            raise InvalidActionTransition("reviewed action spec is structurally invalid") from exc
        if not _constant_time_equal(current_fingerprint, binding.spec_fingerprint):
            raise InvalidActionTransition("reviewed action spec has changed since planning")
        return binding

    def _require_bound_spec(
        self,
        spec: ActionSpec,
        attempt: ActionAttempt,
    ) -> _ReviewedActionBinding:
        binding = self._require_bound_attempt(attempt)
        if spec is not binding.spec:
            raise InvalidActionTransition(
                "action spec is not the exact reviewed instance bound at planning"
            )
        return binding

    @staticmethod
    def _require_context(
        binding: _ReviewedActionBinding,
        attempt: ActionAttempt,
        context: ActionContext,
    ) -> None:
        if context.platform.system != attempt.plan.platform_system:
            raise InvalidActionTransition("execution platform does not match the immutable plan")
        if context.platform.system not in binding.supported_systems:
            raise InvalidActionTransition("action is not supported on the execution platform")

    @staticmethod
    def _require_prerequisites(plan: ActionPlan, context: ActionContext) -> None:
        missing_permissions = sorted(set(plan.permission_ids) - set(context.granted_permission_ids))
        missing_access = sorted(
            set(plan.access_prerequisite_ids) - set(context.confirmed_access_prerequisite_ids)
        )
        if missing_permissions or missing_access:
            categories = []
            if missing_permissions:
                categories.append("required local permission")
            if missing_access:
                categories.append("required outside access")
            raise PrerequisiteError(" and ".join(categories) + " is not confirmed")

    @staticmethod
    def _require_state(attempt: ActionAttempt, expected: ActionState) -> None:
        if attempt.state != expected:
            raise InvalidActionTransition(
                f"expected state {expected.value}, found {attempt.state.value}"
            )

    def _transition(
        self,
        attempt: ActionAttempt,
        to_state: ActionState,
        reason: str,
    ) -> ActionAttempt:
        # The transitions tuple is the engine-issued version token. Internal
        # replace() calls may add a typed result/error while preserving that
        # exact tuple, but a stale branch cannot claim the next state twice.
        # The check-and-advance occurs under one lock, making APPLYING and
        # ROLLING_BACK one-use mutation claims even with concurrent callers.
        with self._binding_lock:
            canonical = self._canonical_attempts.get(attempt.plan.plan_id)
            if canonical is None:
                raise InvalidActionTransition("action attempt has no canonical lifecycle state")
            if (
                attempt.attempt_id != canonical.attempt_id
                or attempt.plan is not canonical.plan
                or attempt.state != canonical.state
                or attempt.transitions is not canonical.transitions
            ):
                raise InvalidActionTransition("action attempt branch is stale or already consumed")
            transition = ActionTransition(attempt.state, to_state, self._aware_now(), reason)
            advanced = replace(
                attempt,
                state=to_state,
                transitions=attempt.transitions + (transition,),
            )
            self._canonical_attempts[attempt.plan.plan_id] = advanced
            self._canonical_attempt_digests[attempt.plan.plan_id] = _digest(advanced)
            return advanced

    def _aware_now(self) -> datetime:
        now = self._now()
        _validate_aware(now, label="engine clock")
        return now


def _require_preview(attempt: ActionAttempt) -> PreviewResult:
    if attempt.preview is None:
        raise InvalidActionTransition("apply requires a preview")
    return attempt.preview


def _safe_action_error(operation: str, exc: BaseException) -> ErrorDetail:
    if isinstance(exc, ActionExecutionError):
        return exc.detail
    return ErrorDetail.unexpected(operation, exc)


def _action_spec_fingerprint(spec: ActionSpec) -> str:
    """Fingerprint every authority-bearing field and exact handler identity."""

    if type(spec) is not ActionSpec:
        raise TypeError("spec must be an ActionSpec")
    spec.__post_init__()

    def handler_identity(handler: object | None) -> dict[str, int] | None:
        if handler is None:
            return None
        # The binding retains strong references, so these identities cannot be
        # recycled during its lifetime. They complement the exact spec-object
        # identity check and detect object.__setattr__ handler substitution.
        return {"callable": id(handler), "callable_type": id(type(handler))}

    payload = {
        "action_id": spec.action_id,
        "revision": spec.revision,
        "title": spec.title,
        "description": spec.description,
        "risk": spec.risk.value,
        "supported_systems": spec.supported_systems,
        "addressed_findings": spec.addressed_findings,
        "permission_ids": spec.permission_ids,
        "access_prerequisite_ids": spec.access_prerequisite_ids,
        "expected_interruption": spec.expected_interruption,
        "estimated_duration_seconds": spec.estimated_duration_seconds,
        "reboot_required": spec.reboot_required,
        "reversible": spec.reversible,
        "previewer": handler_identity(spec.previewer),
        "precondition_checker": handler_identity(spec.precondition_checker),
        "applier": handler_identity(spec.applier),
        "verifier": handler_identity(spec.verifier),
        "rollbacker": handler_identity(spec.rollbacker),
        "manual_steps": spec.manual_steps,
        "manual_recovery": spec.manual_recovery,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: object) -> str:
    # Approval and plan digests are internal one-way commitments, not exported
    # representations. They must include potential-secret prose exactly so the
    # approval is bound to everything the user saw in the preview. Redaction is
    # applied only at output boundaries.
    raw = serialize_structured(
        value,
        policy=RedactionPolicy(potential_secret=RedactionAction.KEEP),
    )
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())


def _validate_digest(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lower-case SHA-256 digest")


def _validate_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be a timezone-aware datetime")


def _validate_refs(values: tuple[str, ...], *, label: str) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    for value in values:
        validate_dotted_identifier(value, label=label.rstrip("s"))
    _validate_unique(values, label=label)


def _validate_unique(values: tuple[str, ...], *, label: str) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")
