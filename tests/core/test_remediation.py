from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest

from netdiag.core.evidence import ErrorDetail, EvidenceStore
from netdiag.core.execution import CancellationToken, PlatformInfo
from netdiag.core.registry import ActionRegistry, DuplicateRegistrationError
from netdiag.core.remediation import (
    ActionAttempt,
    ActionContext,
    ActionExecutionError,
    ActionSpec,
    ActionState,
    ActionTarget,
    ApplyResult,
    ApprovalError,
    InvalidActionTransition,
    PlannedChange,
    PreviewResult,
    RemediationEngine,
    RollbackResult,
    VerificationResult,
    _digest,
)
from netdiag.core.status import RiskTier


@dataclass
class Clock:
    value: datetime = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


class IdFactory:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def __call__(self, prefix: str) -> str:
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]}"


def context(token: CancellationToken | None = None) -> ActionContext:
    return ActionContext(
        PlatformInfo("Darwin", "test", "arm64"),
        token or CancellationToken(),
        EvidenceStore(),
    )


def target() -> ActionTarget:
    return ActionTarget("netdiag.target.local_machine", "local", "This computer")


def build_spec(
    calls: dict[str, int],
    *,
    verify_success: bool = True,
    apply_handler=None,
    precondition_handler=None,
) -> ActionSpec:
    precondition_digest = hashlib.sha256(b"fixture preconditions").hexdigest()

    def previewer(_plan, _context):
        calls["preview"] = calls.get("preview", 0) + 1
        return PreviewResult(
            "Would perform one reversible fixture change.",
            (PlannedChange("netdiag.change.fixture", "Fixture-only change", True),),
            precondition_digest,
        )

    def default_precondition_checker(_plan, _context):
        return precondition_digest

    def default_applier(_plan, _preview, _context):
        calls["apply"] = calls.get("apply", 0) + 1
        return ApplyResult(True, "Fixture change applied.", "rollback-1")

    def verifier(_plan, _applied, _context):
        calls["verify"] = calls.get("verify", 0) + 1
        return VerificationResult(verify_success, "Fresh fixture evidence collected.")

    def rollbacker(_plan, _applied, _context):
        calls["rollback"] = calls.get("rollback", 0) + 1
        return RollbackResult(True, "Fixture state restored.")

    return ActionSpec(
        action_id="netdiag.action.fixture.reversible",
        revision=1,
        title="Fixture action",
        description="A non-mutating action used only by tests.",
        risk=RiskTier.GREEN,
        supported_systems=("Darwin", "Linux"),
        addressed_findings=("NDG.TEST.FIXTURE",),
        permission_ids=(),
        access_prerequisite_ids=(),
        expected_interruption="None",
        estimated_duration_seconds=1,
        reboot_required=False,
        reversible=True,
        previewer=previewer,
        precondition_checker=precondition_handler or default_precondition_checker,
        applier=apply_handler or default_applier,
        verifier=verifier,
        rollbacker=rollbacker,
    )


def engine(clock: Clock | None = None) -> RemediationEngine:
    return RemediationEngine(now=clock or Clock(), id_factory=IdFactory())


def previewed(engine_: RemediationEngine, spec: ActionSpec, ctx: ActionContext):
    attempt = engine_.plan(spec, target(), ctx.platform, finding_refs=("finding-1",))
    return engine_.preview(spec, attempt, ctx)


def approved(engine_: RemediationEngine, spec: ActionSpec, ctx: ActionContext):
    attempt = previewed(engine_, spec, ctx)
    attempt = engine_.request_approval(spec, attempt)
    challenge = engine_.approval_challenge(attempt)
    return engine_.approve(attempt, challenge_digest=challenge, channel="local.ui")


def test_dry_run_never_invokes_apply():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    attempt = previewed(engine_, spec, context())
    attempt = engine_.complete_dry_run(attempt)
    assert attempt.state == ActionState.DRY_RUN_COMPLETE
    assert calls == {"preview": 1}
    assert "apply" not in calls


def test_apply_requires_bound_explicit_approval_and_fresh_verification():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    attempt = previewed(engine_, spec, ctx)
    with pytest.raises(InvalidActionTransition):
        engine_.apply(spec, attempt, ctx)

    attempt = engine_.request_approval(spec, attempt)
    with pytest.raises(ApprovalError, match="does not match"):
        engine_.approve(attempt, challenge_digest="0" * 64, channel="local.ui")

    challenge = engine_.approval_challenge(attempt)
    attempt = engine_.approve(attempt, challenge_digest=challenge, channel="local.ui")
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.APPLIED
    assert attempt.transitions[-2].to_state == ActionState.APPLYING
    attempt = engine_.verify(spec, attempt, ctx)
    assert attempt.state == ActionState.VERIFIED
    assert calls == {"preview": 1, "apply": 1, "verify": 1}


def test_same_id_revision_substitute_spec_cannot_apply():
    reviewed_calls: dict[str, int] = {}
    substitute_calls: dict[str, int] = {}
    reviewed = build_spec(reviewed_calls)
    substitute = build_spec(substitute_calls)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, reviewed, ctx)

    with pytest.raises(InvalidActionTransition, match="exact reviewed instance"):
        engine_.apply(substitute, attempt, ctx)

    assert reviewed_calls == {"preview": 1}
    assert substitute_calls == {}


def test_approved_attempt_is_consumed_after_one_apply():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    approved_attempt = approved(engine_, spec, ctx)

    assert engine_.apply(spec, approved_attempt, ctx).state == ActionState.APPLIED
    with pytest.raises(InvalidActionTransition, match="stale or already consumed"):
        engine_.apply(spec, approved_attempt, ctx)

    assert calls["apply"] == 1


def test_concurrent_double_apply_claim_invokes_handler_once():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    approved_attempt = approved(engine_, spec, ctx)
    barrier = Barrier(2)
    original_transition = engine_._transition

    def synchronized_transition(current, state, reason):
        if state == ActionState.APPLYING:
            barrier.wait(timeout=3)
        return original_transition(current, state, reason)

    engine_._transition = synchronized_transition  # type: ignore[method-assign]

    def invoke():
        try:
            return engine_.apply(spec, approved_attempt, ctx)
        except InvalidActionTransition as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: invoke(), range(2)))

    assert sum(isinstance(result, ActionAttempt) for result in results) == 1
    assert sum(isinstance(result, InvalidActionTransition) for result in results) == 1
    assert calls["apply"] == 1


def test_mutated_bound_handler_cannot_cross_approval_authority():
    reviewed_calls: dict[str, int] = {}
    substitute_calls: dict[str, int] = {}
    reviewed = build_spec(reviewed_calls)
    substitute = build_spec(substitute_calls)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, reviewed, ctx)
    object.__setattr__(reviewed, "applier", substitute.applier)

    with pytest.raises(InvalidActionTransition, match="changed since planning"):
        engine_.apply(reviewed, attempt, ctx)

    assert reviewed_calls == {"preview": 1}
    assert substitute_calls == {}


def test_mutated_prerequisite_list_cannot_expand_approved_authority():
    calls: dict[str, int] = {}
    base = build_spec(calls)
    reviewed = ActionSpec(
        **{
            **base.__dict__,
            "permission_ids": ("netdiag.permission.local_admin",),
        }
    )
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, reviewed, ctx)
    object.__setattr__(reviewed, "permission_ids", ())

    with pytest.raises(InvalidActionTransition, match="changed since planning"):
        engine_.apply(reviewed, attempt, ctx)

    assert calls == {"preview": 1}


@pytest.mark.parametrize(
    "changed_preview",
    (
        lambda preview: replace(preview, summary="Different text shown to the user."),
        lambda preview: replace(
            preview,
            changes=(
                replace(
                    preview.changes[0],
                    description="A materially different change description.",
                ),
            ),
        ),
    ),
)
def test_apply_approval_digest_binds_exact_preview_prose(changed_preview):
    spec = build_spec({})
    engine_ = engine()
    attempt = previewed(engine_, spec, context())
    attempt = engine_.request_approval(spec, attempt)
    original = engine_.approval_challenge(attempt)
    changed = changed_preview(attempt.preview)

    assert (
        _digest(
            {
                "operation": "apply",
                "plan_digest": attempt.plan.digest,
                "preview": changed,
            }
        )
        != original
    )


def test_expired_approval_fails_closed_before_apply():
    clock = Clock()
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine(clock)
    attempt = approved(engine_, spec, context())
    clock.advance(301)
    with pytest.raises(ApprovalError, match="expired"):
        engine_.apply(spec, attempt, context())
    assert calls.get("apply", 0) == 0


def test_cancelled_apply_stops_before_mutation():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    ctx.cancellation.cancel("user stopped")
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.CANCELLED
    assert calls.get("apply", 0) == 0


def test_cancellation_during_precondition_check_stops_before_mutation():
    calls: dict[str, int] = {}
    ctx = context()

    def cancelling_preconditions(_plan, _context):
        ctx.cancellation.cancel("cancelled while checking preconditions")
        return hashlib.sha256(b"fixture preconditions").hexdigest()

    spec = build_spec(calls, precondition_handler=cancelling_preconditions)
    engine_ = engine()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.CANCELLED
    assert calls.get("apply", 0) == 0


def test_approval_expiring_during_precondition_check_stops_before_mutation():
    clock = Clock()
    calls: dict[str, int] = {}

    def slow_preconditions(_plan, _context):
        clock.advance(301)
        return hashlib.sha256(b"fixture preconditions").hexdigest()

    spec = build_spec(calls, precondition_handler=slow_preconditions)
    engine_ = engine(clock)
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    with pytest.raises(ApprovalError, match="expired"):
        engine_.apply(spec, attempt, ctx)
    assert calls.get("apply", 0) == 0


def test_unknown_apply_exception_never_leaks_message_and_marks_outcome_unknown():
    calls: dict[str, int] = {}

    def exploding_applier(_plan, _preview, _context):
        calls["apply"] = calls.get("apply", 0) + 1
        raise RuntimeError("password=hunter2")

    spec = build_spec(calls, apply_handler=exploding_applier)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.OUTCOME_UNKNOWN
    assert "hunter2" not in str(attempt.to_dict())


@pytest.mark.parametrize("exception", (ApprovalError("late"), RuntimeError("late")))
def test_handler_error_that_looks_like_preflight_is_still_unknown(exception):
    calls: dict[str, int] = {}

    def late_error(_plan, _preview, _context):
        calls["apply"] = calls.get("apply", 0) + 1
        raise exception

    spec = build_spec(calls, apply_handler=late_error)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.OUTCOME_UNKNOWN
    assert calls["apply"] == 1


@pytest.mark.parametrize(
    ("changed", "expected"),
    [(False, ActionState.APPLY_FAILED), (None, ActionState.OUTCOME_UNKNOWN)],
)
def test_declared_apply_failure_records_mutation_certainty(changed, expected):
    calls: dict[str, int] = {}

    def controlled_failure(_plan, _preview, _context):
        raise ActionExecutionError(
            ErrorDetail("netdiag.action.fixture_failed", "Safe fixture failure"),
            changed=changed,
        )

    spec = build_spec(calls, apply_handler=controlled_failure)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    assert engine_.apply(spec, attempt, ctx).state == expected


def test_reversible_change_without_rollback_handle_is_unknown():
    calls: dict[str, int] = {}

    def missing_handle(_plan, _preview, _context):
        return ApplyResult(True, "Changed but omitted handle.")

    spec = build_spec(calls, apply_handler=missing_handle)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.OUTCOME_UNKNOWN
    assert attempt.error.code == "netdiag.action.rollback_handle_missing"


def test_changed_preconditions_fail_before_apply():
    calls: dict[str, int] = {}

    def changed_preconditions(_plan, _context):
        return hashlib.sha256(b"changed").hexdigest()

    spec = build_spec(calls, precondition_handler=changed_preconditions)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.APPLY_FAILED
    assert attempt.error.code == "netdiag.action.preconditions_changed"
    assert calls.get("apply", 0) == 0


def test_missing_permission_or_access_fails_before_apply():
    calls: dict[str, int] = {}
    base = build_spec(calls)
    spec = ActionSpec(
        **{
            **base.__dict__,
            "permission_ids": ("netdiag.permission.local_admin",),
            "access_prerequisite_ids": ("netdiag.access.router_admin",),
        }
    )
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.APPLY_FAILED
    assert attempt.error.code == "netdiag.action.prerequisite_missing"
    assert calls.get("apply", 0) == 0


def test_confirmed_prerequisites_allow_the_bound_action():
    calls: dict[str, int] = {}
    base = build_spec(calls)
    spec = ActionSpec(
        **{
            **base.__dict__,
            "permission_ids": ("netdiag.permission.local_admin",),
            "access_prerequisite_ids": ("netdiag.access.router_admin",),
        }
    )
    ctx = ActionContext(
        PlatformInfo("Darwin", "test", "arm64"),
        CancellationToken(),
        EvidenceStore(),
        granted_permission_ids=("netdiag.permission.local_admin",),
        confirmed_access_prerequisite_ids=("netdiag.access.router_admin",),
    )
    engine_ = engine()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    assert attempt.state == ActionState.APPLIED
    assert calls["apply"] == 1


def test_audit_serialization_tokenizes_action_target_reference():
    spec = build_spec({})
    engine_ = engine()
    ctx = context()
    attempt = engine_.plan(
        spec,
        ActionTarget("netdiag.target.device", "family-mac.local", "Affected computer"),
        ctx.platform,
    )
    serialized = attempt.to_dict()
    assert serialized["plan"]["target"]["reference"] == "<device-1>"
    assert serialized["plan"]["target"]["display_name"] == "<device-2>"
    assert "family-mac.local" not in str(serialized)


def test_audit_serialization_withholds_all_adapter_controlled_prose():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    attempt = previewed(engine_, spec, ctx)
    canaries = (
        "password=preview-secret",
        "password=change-secret",
        "password=apply-secret",
        "password=verify-secret",
        "password=rollback-secret",
        "password=error-secret",
    )
    attempt = replace(
        attempt,
        transitions=attempt.transitions[:-1]
        + (replace(attempt.transitions[-1], reason="password=transition-secret"),),
        preview=replace(
            attempt.preview,
            summary=canaries[0],
            changes=(PlannedChange("netdiag.change.fixture", canaries[1], True),),
        ),
        apply_result=ApplyResult(True, canaries[2], "rollback-1"),
        verification=VerificationResult(False, canaries[3]),
        rollback_result=RollbackResult(False, canaries[4]),
        error=ErrorDetail("netdiag.action.fixture", canaries[5]),
    )
    payload = attempt.to_dict()
    for canary in canaries:
        assert canary not in str(payload)
    assert "transition-secret" not in str(payload)
    assert payload["transitions"][-1]["reason"] == "<redacted>"
    assert payload["preview"]["summary"] == "<redacted>"
    assert payload["apply_result"]["summary"] == "<redacted>"
    assert payload["error"]["message"] == "<redacted>"


def test_action_attempt_rejects_wrong_nested_model_shapes():
    spec = build_spec({})
    attempt = previewed(engine(), spec, context())

    with pytest.raises(TypeError, match="plan must be an ActionPlan"):
        replace(attempt, plan="not-a-plan")
    with pytest.raises(TypeError, match="apply_result must be ApplyResult"):
        replace(attempt, apply_result=True)
    with pytest.raises(TypeError, match="transitions must be a tuple"):
        replace(attempt, transitions=list(attempt.transitions))


@pytest.mark.parametrize(
    ("nested_name", "field_name", "unsafe_value", "expected_error"),
    (
        ("transition", "at", "password=timestamp-secret", ValueError),
        ("change", "reversible", "password=boolean-secret", TypeError),
        ("apply_result", "changed", "password=boolean-secret", TypeError),
        ("verification", "successful", "password=boolean-secret", TypeError),
        ("rollback_result", "successful", "password=boolean-secret", TypeError),
        ("approval", "approved_at", "password=timestamp-secret", ValueError),
        ("error", "retryable", "password=boolean-secret", TypeError),
    ),
)
def test_action_audit_revalidates_nested_public_fields_before_export(
    nested_name,
    field_name,
    unsafe_value,
    expected_error,
):
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = replace(
        attempt,
        apply_result=ApplyResult(True, "Applied.", "rollback-1"),
        verification=VerificationResult(False, "Not verified."),
        rollback_result=RollbackResult(False, "Not restored."),
        error=ErrorDetail("netdiag.action.fixture", "Safe failure"),
    )
    nested = {
        "transition": attempt.transitions[-1],
        "change": attempt.preview.changes[0],
        "apply_result": attempt.apply_result,
        "verification": attempt.verification,
        "rollback_result": attempt.rollback_result,
        "approval": attempt.approval,
        "error": attempt.error,
    }[nested_name]
    object.__setattr__(nested, field_name, unsafe_value)

    with pytest.raises(expected_error):
        attempt.to_dict()


def test_plan_and_execution_are_bound_to_supported_platform():
    calls: dict[str, int] = {}
    spec = build_spec(calls)
    engine_ = engine()
    windows = PlatformInfo("Windows", "test", "x86_64")
    with pytest.raises(ValueError, match="does not support"):
        engine_.plan(spec, target(), windows)

    mac = context()
    linux_context = ActionContext(
        PlatformInfo("Linux", "test", "x86_64"),
        CancellationToken(),
        EvidenceStore(),
    )
    attempt = engine_.preview(
        spec,
        engine_.plan(spec, target(), mac.platform),
        linux_context,
    )
    assert attempt.state == ActionState.PREVIEW_FAILED
    assert calls.get("preview", 0) == 0


def test_failed_verification_requires_separate_rollback_approval():
    calls: dict[str, int] = {}
    spec = build_spec(calls, verify_success=False)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    assert attempt.state == ActionState.VERIFY_FAILED
    attempt = engine_.offer_rollback(spec, attempt)
    with pytest.raises(InvalidActionTransition):
        engine_.rollback(spec, attempt, ctx)
    challenge = engine_.rollback_challenge(attempt)
    attempt = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
    )
    attempt = engine_.rollback(spec, attempt, ctx)
    assert attempt.state == ActionState.ROLLED_BACK
    assert calls["rollback"] == 1


def test_same_id_revision_substitute_spec_cannot_rollback():
    reviewed_calls: dict[str, int] = {}
    substitute_calls: dict[str, int] = {}
    reviewed = build_spec(reviewed_calls, verify_success=False)
    substitute = build_spec(substitute_calls, verify_success=False)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, reviewed, ctx)
    attempt = engine_.apply(reviewed, attempt, ctx)
    attempt = engine_.verify(reviewed, attempt, ctx)
    attempt = engine_.offer_rollback(reviewed, attempt)
    challenge = engine_.rollback_challenge(attempt)
    attempt = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
    )

    with pytest.raises(InvalidActionTransition, match="exact reviewed instance"):
        engine_.rollback(substitute, attempt, ctx)

    assert reviewed_calls == {"preview": 1, "apply": 1, "verify": 1}
    assert substitute_calls == {}


def test_rollback_approval_is_consumed_after_one_rollback():
    calls: dict[str, int] = {}
    spec = build_spec(calls, verify_success=False)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    attempt = engine_.offer_rollback(spec, attempt)
    challenge = engine_.rollback_challenge(attempt)
    approved_rollback = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
    )

    assert engine_.rollback(spec, approved_rollback, ctx).state == ActionState.ROLLED_BACK
    with pytest.raises(InvalidActionTransition, match="stale or already consumed"):
        engine_.rollback(spec, approved_rollback, ctx)

    assert calls["rollback"] == 1


def test_concurrent_double_rollback_claim_invokes_handler_once():
    calls: dict[str, int] = {}
    spec = build_spec(calls, verify_success=False)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    attempt = engine_.offer_rollback(spec, attempt)
    challenge = engine_.rollback_challenge(attempt)
    approved_rollback = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
    )
    barrier = Barrier(2)
    original_transition = engine_._transition

    def synchronized_transition(current, state, reason):
        if state == ActionState.ROLLING_BACK:
            barrier.wait(timeout=3)
        return original_transition(current, state, reason)

    engine_._transition = synchronized_transition  # type: ignore[method-assign]

    def invoke():
        try:
            return engine_.rollback(spec, approved_rollback, ctx)
        except InvalidActionTransition as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: invoke(), range(2)))

    assert sum(isinstance(result, ActionAttempt) for result in results) == 1
    assert sum(isinstance(result, InvalidActionTransition) for result in results) == 1
    assert calls["rollback"] == 1


@pytest.mark.parametrize(
    "changed_attempt",
    (
        lambda attempt: replace(
            attempt,
            apply_result=replace(
                attempt.apply_result,
                summary="Different applied-result text.",
            ),
        ),
        lambda attempt: replace(
            attempt,
            verification=replace(
                attempt.verification,
                summary="Different verification text.",
            ),
        ),
    ),
)
def test_rollback_approval_digest_binds_exact_result_prose(changed_attempt):
    calls: dict[str, int] = {}
    spec = build_spec(calls, verify_success=False)
    engine_ = engine()
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    attempt = engine_.offer_rollback(spec, attempt)
    original = engine_.rollback_challenge(attempt)
    changed = changed_attempt(attempt)

    assert (
        _digest(
            {
                "operation": "rollback",
                "plan_digest": changed.plan.digest,
                "apply_result": changed.apply_result,
                "verification": changed.verification,
            }
        )
        != original
    )


def test_cancellation_at_final_rollback_boundary_stops_handler():
    calls: dict[str, int] = {}
    clock = Clock()
    spec = build_spec(calls, verify_success=False)
    engine_ = engine(clock)
    token = CancellationToken()
    ctx = context(token)
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    attempt = engine_.offer_rollback(spec, attempt)
    challenge = engine_.rollback_challenge(attempt)
    attempt = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
    )

    original_transition = engine_._transition

    def cancelling_transition(current, state, reason):
        transitioned = original_transition(current, state, reason)
        if state == ActionState.ROLLING_BACK:
            token.cancel("cancelled at rollback boundary")
        return transitioned

    engine_._transition = cancelling_transition  # type: ignore[method-assign]
    attempt = engine_.rollback(spec, attempt, ctx)
    assert attempt.state == ActionState.CANCELLED
    assert calls.get("rollback", 0) == 0


def test_fresh_rollback_remains_available_after_original_plan_expires():
    calls: dict[str, int] = {}
    clock = Clock()
    spec = build_spec(calls, verify_success=False)
    engine_ = engine(clock)
    ctx = context()
    attempt = approved(engine_, spec, ctx)
    attempt = engine_.apply(spec, attempt, ctx)
    attempt = engine_.verify(spec, attempt, ctx)
    attempt = engine_.offer_rollback(spec, attempt)

    clock.advance(901)
    challenge = engine_.rollback_challenge(attempt)
    attempt = engine_.approve_rollback(
        attempt,
        challenge_digest=challenge,
        channel="local.ui",
        ttl_seconds=60,
    )
    attempt = engine_.rollback(spec, attempt, ctx)
    assert attempt.state == ActionState.ROLLED_BACK
    assert calls["rollback"] == 1


def test_red_action_can_only_end_in_manual_guidance():
    def previewer(_plan, _context):
        return PreviewResult(
            "Manual recovery guidance.",
            (PlannedChange("netdiag.change.manual", "Run vendor recovery", False),),
            hashlib.sha256(b"manual").hexdigest(),
        )

    spec = ActionSpec(
        "netdiag.action.rescue.manual",
        1,
        "Manual rescue",
        "Guidance only.",
        RiskTier.RED,
        ("Darwin",),
        ("NDG.RESCUE.MANUAL_REQUIRED",),
        (),
        (),
        "Computer may restart",
        60,
        True,
        False,
        previewer,
        manual_steps=("Open the supported recovery environment.",),
    )
    engine_ = engine()
    attempt = previewed(engine_, spec, context())
    attempt = engine_.request_approval(spec, attempt)
    assert attempt.state == ActionState.MANUAL_ONLY


def test_action_specs_reject_unsafe_handler_combinations():
    calls: dict[str, int] = {}
    valid = build_spec(calls)
    with pytest.raises(ValueError, match="manual-only"):
        ActionSpec(
            **{
                **valid.__dict__,
                "risk": RiskTier.RED,
                "manual_steps": ("Do it manually.",),
            }
        )
    with pytest.raises(ValueError, match="green actions must be reversible"):
        ActionSpec(
            **{
                **valid.__dict__,
                "reversible": False,
                "rollbacker": None,
                "manual_recovery": "Restore manually.",
            }
        )


def test_action_registry_is_explicit_and_duplicate_rejecting():
    spec = build_spec({})
    registry = ActionRegistry()
    registry.register(spec)
    with pytest.raises(DuplicateRegistrationError):
        registry.register(spec)


@pytest.mark.parametrize(
    "unsafe_ref",
    ("password=hunter2", "recovery-key=abc", "bad ref"),
)
def test_action_audit_references_require_identifier_syntax(unsafe_ref: str) -> None:
    with pytest.raises(ValueError, match="lower-case dotted identifier"):
        PreviewResult(
            "Fixture preview",
            (),
            hashlib.sha256(b"fixture").hexdigest(),
            (unsafe_ref,),
        )

    with pytest.raises(ValueError, match="lower-case dotted identifier"):
        engine().plan(
            build_spec({}),
            target(),
            context().platform,
            finding_refs=(unsafe_ref,),
        )


def test_action_audit_redacts_prefix_smuggled_identifiers() -> None:
    spec = build_spec({})
    attempt = previewed(engine(), spec, context())
    attempt = replace(
        attempt,
        attempt_id="attempt.family-mac.local",
        plan=replace(
            attempt.plan,
            plan_id="plan.password-hunter2",
            action_id="netdiag.action.recovery-key-abc",
            finding_refs=("finding.family-mac.local",),
        ),
        preview=replace(
            attempt.preview,
            evidence_refs=("evidence.password-hunter2",),
        ),
    )
    payload = str(attempt.to_dict())
    for canary in ("family-mac.local", "password-hunter2", "recovery-key-abc"):
        assert canary not in payload
