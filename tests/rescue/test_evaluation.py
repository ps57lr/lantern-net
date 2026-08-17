from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netdiag.core import ConfidenceLevel, OutcomeStatus, PlatformInfo
from netdiag.rescue import (
    AxisAssessment,
    AxisObservation,
    DataSafetyImpact,
    RescueAssessment,
    RescueAxis,
    RescueContext,
    build_axis_assessment,
    summarize_readiness,
)


def _axis(
    axis: RescueAxis,
    status: OutcomeStatus = OutcomeStatus.HEALTHY,
    *,
    evidence: bool = True,
):
    observations = (
        (
            AxisObservation(
                f"rescue.evidence.{axis.value}",
                status,
                ConfidenceLevel.HIGH,
                "Read-only fixture observation",
            ),
        )
        if evidence
        else ()
    )
    return build_axis_assessment(
        axis,
        observations,
        safest_next_action="Review this area before making changes.",
    )


def test_no_observation_remains_not_tested() -> None:
    result = _axis(RescueAxis.HARDWARE, evidence=False)
    assert result.status == OutcomeStatus.NOT_TESTED
    assert result.confidence.level == ConfidenceLevel.LOW
    assert not result.evidence_refs


def test_contradictory_observations_are_inconclusive() -> None:
    result = build_axis_assessment(
        RescueAxis.STORAGE_FILESYSTEM,
        (
            AxisObservation(
                "rescue.evidence.visible",
                OutcomeStatus.HEALTHY,
                ConfidenceLevel.HIGH,
                "Storage was visible",
            ),
            AxisObservation(
                "rescue.evidence.health",
                OutcomeStatus.FAILED,
                ConfidenceLevel.HIGH,
                "Supported health data reported failure",
            ),
        ),
        safest_next_action="Stop writes and ask a recovery specialist.",
    )
    assert result.status == OutcomeStatus.INCONCLUSIVE
    assert result.confidence.level == ConfidenceLevel.LOW


def test_data_stop_blocker_wins_without_claiming_failure() -> None:
    result = build_axis_assessment(
        RescueAxis.DATA_RECOVERABILITY,
        (),
        blockers=("Encrypted volume requires a separately held recovery key.",),
        data_safety_impact=DataSafetyImpact.STOP,
        safest_next_action="Verify ownership and locate the key outside Lantern.",
    )
    assert result.status == OutcomeStatus.BLOCKED
    assert result.data_safety_impact == DataSafetyImpact.STOP


def test_complete_assessment_requires_each_axis_exactly_once() -> None:
    axes = tuple(_axis(axis) for axis in RescueAxis)
    readiness, summary = summarize_readiness(axes)
    report = RescueAssessment(
        PlatformInfo("macOS", "27.0", "arm64"),
        RescueContext.NORMAL_OS,
        datetime.now(timezone.utc),
        axes,
        readiness,
        summary,
    )
    assert report.readiness == OutcomeStatus.HEALTHY
    assert len(report.to_dict()["axes"]) == 5

    with pytest.raises(ValueError, match="every rescue axis"):
        RescueAssessment(
            PlatformInfo("macOS", "27.0", "arm64"),
            RescueContext.NORMAL_OS,
            datetime.now(timezone.utc),
            axes[:-1],
            OutcomeStatus.INCONCLUSIVE,
            "Incomplete assessment",
        )


def test_unknown_axis_prevents_healthy_readiness() -> None:
    axes = tuple(_axis(axis, evidence=axis != RescueAxis.NETWORK) for axis in RescueAxis)
    readiness, _summary = summarize_readiness(axes)
    assert readiness == OutcomeStatus.INCONCLUSIVE


def test_axes_do_not_infer_one_another() -> None:
    axes = tuple(_axis(axis, evidence=axis == RescueAxis.OPERATING_SYSTEM) for axis in RescueAxis)
    by_axis = {axis.axis: axis.status for axis in axes}
    assert by_axis[RescueAxis.OPERATING_SYSTEM] == OutcomeStatus.HEALTHY
    assert by_axis[RescueAxis.HARDWARE] == OutcomeStatus.NOT_TESTED
    assert by_axis[RescueAxis.DATA_RECOVERABILITY] == OutcomeStatus.NOT_TESTED


def test_share_safe_rescue_export_withholds_arbitrary_recovery_prose() -> None:
    canary = "recovery-key-111111-222222"
    compromised = build_axis_assessment(
        RescueAxis.DATA_RECOVERABILITY,
        (),
        blockers=(f"password=hunter2 {canary}",),
        data_safety_impact=DataSafetyImpact.STOP,
        safest_next_action=f"Paste {canary}",
    )
    axis_payload = compromised.to_dict()
    assert canary not in str(axis_payload)
    assert "hunter2" not in str(axis_payload)

    axes = tuple(
        compromised if axis == RescueAxis.DATA_RECOVERABILITY else _axis(axis)
        for axis in RescueAxis
    )
    report = RescueAssessment(
        PlatformInfo("macOS", "27.0", "arm64"),
        RescueContext.NORMAL_OS,
        datetime.now(timezone.utc),
        axes,
        OutcomeStatus.BLOCKED,
        f"summary password=hunter2 {canary}",
    )
    payload = report.to_dict()
    assert canary not in str(payload)
    assert "hunter2" not in str(payload)
    assert payload["readiness_summary"] == "<redacted>"


def test_rescue_revalidates_platform_metadata_before_export() -> None:
    axes = tuple(_axis(axis) for axis in RescueAxis)
    platform = PlatformInfo("macOS", "27.0", "arm64")
    report = RescueAssessment(
        platform,
        RescueContext.NORMAL_OS,
        datetime.now(timezone.utc),
        axes,
        OutcomeStatus.HEALTHY,
        "Ready",
    )
    object.__setattr__(platform, "release", "family-mac.local")
    with pytest.raises(ValueError, match="platform release"):
        report.to_dict()


def test_rescue_axes_require_immutable_typed_shapes_at_construction_and_export() -> None:
    axes = tuple(_axis(axis) for axis in RescueAxis)
    with pytest.raises(TypeError, match="tuple of AxisAssessment"):
        RescueAssessment(
            PlatformInfo("macOS", "27.0", "arm64"),
            RescueContext.NORMAL_OS,
            datetime.now(timezone.utc),
            list(axes),  # type: ignore[arg-type]
            OutcomeStatus.HEALTHY,
            "Ready",
        )

    report = RescueAssessment(
        PlatformInfo("macOS", "27.0", "arm64"),
        RescueContext.NORMAL_OS,
        datetime.now(timezone.utc),
        axes,
        OutcomeStatus.HEALTHY,
        "Ready",
    )
    object.__setattr__(
        report,
        "axes",
        ({"axis": "password=hunter2"}, *axes[1:]),
    )
    with pytest.raises(TypeError, match="tuple of AxisAssessment"):
        report.to_dict()


def test_rescue_assessment_id_is_generation_bound_and_cannot_be_resealed() -> None:
    import netdiag.rescue.models as rescue_models

    axes = tuple(_axis(axis) for axis in RescueAxis)
    report = RescueAssessment(
        PlatformInfo("macOS", "27.0", "arm64"),
        RescueContext.NORMAL_OS,
        datetime.now(timezone.utc),
        axes,
        OutcomeStatus.HEALTHY,
        "Ready",
    )
    original_id = report.assessment_id
    original_identity = report._assessment_identity
    report.__post_init__()
    report.__post_init__()

    attacker_id = "rescue-assessment-deadbeefdeadbeefdeadbeefdeadbeef"
    assert not hasattr(rescue_models, "_ASSESSMENT_ID_UNSEALED")
    with pytest.raises(AttributeError):
        object.__setattr__(report, "assessment_id", attacker_id)
    with pytest.raises(AttributeError):
        object.__setattr__(report, "_assessment_id_seal", object())

    object.__setattr__(report, "_assessment_identity", (attacker_id, original_identity[1]))
    try:
        with pytest.raises(ValueError, match="not bound"):
            report.__post_init__()
        with pytest.raises(ValueError, match="not bound"):
            report.to_dict()
    finally:
        object.__setattr__(report, "_assessment_identity", original_identity)

    payload = report.to_dict()
    assert payload["assessment_id"] == original_id
    assert "_assessment_id_seal" not in payload


def test_rescue_assessment_requires_exact_axis_instances() -> None:
    class AxisAssessmentSubclass(AxisAssessment):
        pass

    axes = [_axis(axis) for axis in RescueAxis]
    first = axes[0]
    axes[0] = AxisAssessmentSubclass(
        first.axis,
        first.status,
        first.confidence,
        first.evidence_refs,
        first.blockers,
        first.data_safety_impact,
        first.safest_next_action,
    )
    with pytest.raises(TypeError, match="tuple of AxisAssessment"):
        RescueAssessment(
            PlatformInfo("macOS", "27.0", "arm64"),
            RescueContext.NORMAL_OS,
            datetime.now(timezone.utc),
            tuple(axes),
            OutcomeStatus.HEALTHY,
            "Ready",
        )
