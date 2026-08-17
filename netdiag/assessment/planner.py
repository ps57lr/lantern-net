"""Pure, offline coverage planning for disabled assessment designs."""

from __future__ import annotations

from datetime import datetime

from ._validation import require_utc_second
from .models import (
    CoveragePlan,
    CoveragePlanItem,
    CoverageState,
    EngagementEnvelope,
    FoundationStatus,
    TechniqueState,
)


class AssessmentPlanRejected(ValueError):
    """Raised when a design record cannot safely produce a coverage plan."""


def build_coverage_plan(*, envelope: EngagementEnvelope, generated_at: datetime) -> CoveragePlan:
    """Build a deterministic description of authorized *future* coverage.

    This pure function performs validation and arithmetic only. It has no
    collector, socket, subprocess, filesystem, URL, or plugin integration.
    The resulting plan remains ``disabled`` and every item remains
    ``not_assessed_design_only``.
    """

    if type(envelope) is not EngagementEnvelope:
        raise TypeError("envelope must be an EngagementEnvelope")
    require_utc_second(generated_at, label="plan generation time")
    if envelope.status is not FoundationStatus.DISABLED:
        raise AssessmentPlanRejected("only the disabled assessment foundation is supported")
    if not envelope.authorization.is_current(now=generated_at):
        raise AssessmentPlanRejected("authorization is not current at plan generation time")
    if generated_at >= envelope.window.hard_stop_at:
        raise AssessmentPlanRejected("the assessment hard stop has already passed")

    effective_targets = envelope.scope.effective_target_count
    vantage_ids = tuple(item.vantage_id for item in envelope.vantage_points)
    items: list[CoveragePlanItem] = []
    for index, budget in enumerate(envelope.technique_budgets, start=1):
        if budget.max_targets > effective_targets:
            raise AssessmentPlanRejected(
                "a technique target budget exceeds the explicit effective scope"
            )
        target_cap = budget.max_targets
        packet_cap = target_cap * budget.max_packets_per_target
        items.append(
            CoveragePlanItem(
                step_id=f"step.{index:02d}.{budget.technique.value.replace('_', '-')}",
                technique=budget.technique,
                technique_state=TechniqueState.DESIGN_ONLY,
                coverage_state=CoverageState.NOT_ASSESSED_DESIGN_ONLY,
                vantage_ids=vantage_ids,
                authorized_target_cap=target_cap,
                packet_cap=packet_cap,
                concurrency_cap=budget.max_concurrency,
                timeout_ms=budget.timeout_ms,
                duration_cap_seconds=budget.max_duration_seconds,
            )
        )
    plan = CoveragePlan(
        engagement_id=envelope.engagement_id,
        engagement_digest=envelope.local_digest,
        generated_at=generated_at,
        items=tuple(items),
    )
    plan.assert_matches(envelope)
    return plan
