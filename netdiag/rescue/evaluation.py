"""Conservative evaluation rules for read-only rescue observations."""

from __future__ import annotations

from netdiag.core import Confidence, ConfidenceLevel, OutcomeStatus
from netdiag.rescue.models import (
    AxisAssessment,
    AxisObservation,
    DataSafetyImpact,
    RescueAxis,
)

_ADVERSE = {
    OutcomeStatus.DEGRADED,
    OutcomeStatus.FAILED,
    OutcomeStatus.BLOCKED,
    OutcomeStatus.PERMISSION_DENIED,
}
_UNKNOWN = {
    OutcomeStatus.INFORMATIONAL,
    OutcomeStatus.INCONCLUSIVE,
    OutcomeStatus.NOT_TESTED,
    OutcomeStatus.UNSUPPORTED,
    OutcomeStatus.CANCELLED,
}


def build_axis_assessment(
    axis: RescueAxis,
    observations: tuple[AxisObservation, ...],
    *,
    blockers: tuple[str, ...] = (),
    data_safety_impact: DataSafetyImpact = DataSafetyImpact.NONE,
    safest_next_action: str,
) -> AxisAssessment:
    """Combine evidence without turning missing or contradictory data into a pass."""

    status = _combine_status(observations, blockers, data_safety_impact)
    confidence_level = _combine_confidence(observations, status)
    evidence_refs = tuple(observation.evidence_ref for observation in observations)
    rationale = _confidence_rationale(observations, status)
    return AxisAssessment(
        axis=axis,
        status=status,
        confidence=Confidence(confidence_level, rationale, evidence_refs),
        evidence_refs=evidence_refs,
        blockers=blockers,
        data_safety_impact=data_safety_impact,
        safest_next_action=safest_next_action,
    )


def summarize_readiness(axes: tuple[AxisAssessment, ...]) -> tuple[OutcomeStatus, str]:
    """Return a cautious headline while preserving every per-axis conclusion."""

    statuses = {axis.status for axis in axes}
    if any(axis.data_safety_impact == DataSafetyImpact.STOP for axis in axes):
        return (
            OutcomeStatus.BLOCKED,
            "Pause changes and protect data before continuing; review each viability area.",
        )
    if OutcomeStatus.FAILED in statuses:
        return (
            OutcomeStatus.FAILED,
            "At least one viability area failed; the remaining areas are reported independently.",
        )
    if statuses & {OutcomeStatus.BLOCKED, OutcomeStatus.PERMISSION_DENIED}:
        return (
            OutcomeStatus.BLOCKED,
            "One or more viability areas could not be safely evaluated or continued.",
        )
    if OutcomeStatus.DEGRADED in statuses:
        return (
            OutcomeStatus.DEGRADED,
            "At least one viability area needs attention; inspect the independent results.",
        )
    if statuses == {OutcomeStatus.HEALTHY}:
        return (
            OutcomeStatus.HEALTHY,
            "All five viability areas have supporting healthy evidence in this environment.",
        )
    return (
        OutcomeStatus.INCONCLUSIVE,
        "The computer's viability is not fully known; untested areas remain explicit.",
    )


def _combine_status(
    observations: tuple[AxisObservation, ...],
    blockers: tuple[str, ...],
    data_safety_impact: DataSafetyImpact,
) -> OutcomeStatus:
    if blockers and data_safety_impact == DataSafetyImpact.STOP:
        return OutcomeStatus.BLOCKED
    if not observations:
        return OutcomeStatus.NOT_TESTED
    statuses = {observation.status for observation in observations}
    if OutcomeStatus.HEALTHY in statuses and statuses & _ADVERSE:
        return OutcomeStatus.INCONCLUSIVE
    if OutcomeStatus.FAILED in statuses:
        return OutcomeStatus.FAILED
    if OutcomeStatus.BLOCKED in statuses or OutcomeStatus.PERMISSION_DENIED in statuses:
        return OutcomeStatus.BLOCKED
    if OutcomeStatus.DEGRADED in statuses:
        return OutcomeStatus.DEGRADED
    if statuses == {OutcomeStatus.HEALTHY}:
        return OutcomeStatus.HEALTHY
    if statuses & _UNKNOWN:
        return OutcomeStatus.INCONCLUSIVE
    return OutcomeStatus.INCONCLUSIVE


def _combine_confidence(
    observations: tuple[AxisObservation, ...], status: OutcomeStatus
) -> ConfidenceLevel:
    if not observations or status in {OutcomeStatus.NOT_TESTED, OutcomeStatus.INCONCLUSIVE}:
        return ConfidenceLevel.LOW
    levels = {observation.confidence for observation in observations}
    if ConfidenceLevel.LOW in levels:
        return ConfidenceLevel.LOW
    if ConfidenceLevel.MEDIUM in levels:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.HIGH


def _confidence_rationale(observations: tuple[AxisObservation, ...], status: OutcomeStatus) -> str:
    if not observations:
        return "No supported observation was available in this environment."
    if status == OutcomeStatus.INCONCLUSIVE:
        return "Available observations are incomplete or disagree."
    return f"Conclusion is based on {len(observations)} read-only observation(s)."
