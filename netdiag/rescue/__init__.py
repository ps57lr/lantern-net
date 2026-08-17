"""Read-only rescue assessment models and platform-specific guidance."""

from netdiag.rescue.evaluation import build_axis_assessment, summarize_readiness
from netdiag.rescue.guides import GuideStep, RescueGuide, guide_for
from netdiag.rescue.models import (
    AxisAssessment,
    AxisObservation,
    DataSafetyImpact,
    RescueAssessment,
    RescueAxis,
    RescueContext,
)

__all__ = [
    "AxisAssessment",
    "AxisObservation",
    "DataSafetyImpact",
    "GuideStep",
    "RescueAssessment",
    "RescueAxis",
    "RescueContext",
    "RescueGuide",
    "build_axis_assessment",
    "guide_for",
    "summarize_readiness",
]
