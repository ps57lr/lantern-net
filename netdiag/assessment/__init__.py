"""Disabled, offline-only authorized-assessment design foundation.

Importing this package has no runtime effect. Nothing here scans, listens,
persists, remediates, or integrates with the CLI or local UI.
"""

from .export import SHARE_SAFE_SCHEMA_VERSION, build_share_safe_export, share_safe_json
from .models import (
    ENVELOPE_SCHEMA_VERSION,
    FOUNDATION_NOTICE,
    PLAN_SCHEMA_VERSION,
    AssessmentPurpose,
    AssessmentScope,
    AssessmentWindow,
    AuthorityStatement,
    Authorization,
    CoveragePlan,
    CoveragePlanItem,
    CoverageState,
    DataPolicy,
    DataSensitivity,
    EngagementEnvelope,
    EnvironmentKind,
    ExportPolicy,
    FoundationStatus,
    ScopeRealm,
    Technique,
    TechniqueBudget,
    TechniqueState,
    VantagePoint,
    VantageRole,
)
from .planner import AssessmentPlanRejected, build_coverage_plan

__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "FOUNDATION_NOTICE",
    "PLAN_SCHEMA_VERSION",
    "SHARE_SAFE_SCHEMA_VERSION",
    "AssessmentPlanRejected",
    "AssessmentPurpose",
    "AssessmentScope",
    "AssessmentWindow",
    "AuthorityStatement",
    "Authorization",
    "CoveragePlan",
    "CoveragePlanItem",
    "CoverageState",
    "DataPolicy",
    "DataSensitivity",
    "EngagementEnvelope",
    "EnvironmentKind",
    "ExportPolicy",
    "FoundationStatus",
    "ScopeRealm",
    "Technique",
    "TechniqueBudget",
    "TechniqueState",
    "VantagePoint",
    "VantageRole",
    "build_coverage_plan",
    "build_share_safe_export",
    "share_safe_json",
]
