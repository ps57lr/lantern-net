from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from netdiag.assessment import (
    AssessmentPlanRejected,
    CoveragePlan,
    CoverageState,
    FoundationStatus,
    Technique,
    build_coverage_plan,
    build_share_safe_export,
    share_safe_json,
)

from .conftest import utc


def test_planner_builds_only_disabled_not_assessed_design(valid_envelope) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )

    assert plan.status is FoundationStatus.DISABLED
    assert all(item.coverage_state is CoverageState.NOT_ASSESSED_DESIGN_ONLY for item in plan.items)
    assert tuple(item.technique for item in plan.items) == valid_envelope.approved_techniques
    assert plan.items[0].packet_cap == 8
    assert plan.items[1].packet_cap == 0
    assert len(plan.plan_digest) == 64
    plan.assert_matches(valid_envelope)
    with pytest.raises(FrozenInstanceError):
        plan.plan_digest = "0" * 64


@pytest.mark.parametrize(
    "now",
    [
        utc("2026-08-18T10:00:00"),  # authorization expired
        utc("2026-08-17T12:00:00"),  # hard stop reached
    ],
)
def test_planner_fails_closed_at_expiry_and_hard_stop(valid_envelope, now) -> None:
    with pytest.raises(AssessmentPlanRejected):
        build_coverage_plan(envelope=valid_envelope, generated_at=now)


def test_arbitrary_plan_with_self_consistent_digest_cannot_bypass_envelope(valid_envelope) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    forged_item = replace(plan.items[0], authorized_target_cap=3, packet_cap=12)
    forged = CoveragePlan(
        engagement_id=plan.engagement_id,
        engagement_digest=plan.engagement_digest,
        generated_at=plan.generated_at,
        items=(forged_item, plan.items[1]),
    )
    forged.assert_integrity()  # The attacker can make a self-consistent object.
    with pytest.raises(ValueError, match="target cap"):
        forged.assert_matches(valid_envelope)
    with pytest.raises(ValueError, match="target cap"):
        build_share_safe_export(envelope=valid_envelope, plan=forged)


def test_plan_rejects_unknown_vantage_and_unapproved_technique(valid_envelope) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    unknown_vantage = replace(plan.items[0], vantage_ids=("vantage.unknown",))
    forged_vantage = CoveragePlan(
        plan.engagement_id,
        plan.engagement_digest,
        plan.generated_at,
        (unknown_vantage, plan.items[1]),
    )
    with pytest.raises(ValueError, match="vantage"):
        forged_vantage.assert_matches(valid_envelope)

    wrong_technique = replace(
        plan.items[0], technique=Technique.READ_ONLY_CONFIGURATION_REVIEW_DESIGN
    )
    forged_technique = CoveragePlan(
        plan.engagement_id,
        plan.engagement_digest,
        plan.generated_at,
        (wrong_technique, plan.items[1]),
    )
    with pytest.raises(ValueError, match="technique"):
        forged_technique.assert_matches(valid_envelope)


def test_object_level_mutation_is_detected_by_digest(valid_envelope) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    object.__setattr__(plan, "engagement_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        plan.assert_integrity()


def test_planning_and_export_never_use_io_network_commands_or_shell(
    monkeypatch, valid_envelope
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("offline assessment design attempted an external operation")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "check_call", forbidden)
    monkeypatch.setattr(subprocess, "check_output", forbidden)
    monkeypatch.setattr(os, "system", forbidden)

    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    exported = build_share_safe_export(envelope=valid_envelope, plan=plan)
    assert exported["status"] == "disabled"


def test_share_safe_export_is_structural_deterministic_and_contains_no_raw_references(
    valid_envelope,
) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    encoded = share_safe_json(envelope=valid_envelope, plan=plan)
    exported = json.loads(encoded)

    assert encoded == share_safe_json(envelope=valid_envelope, plan=plan)
    assert exported["status"] == "disabled"
    assert exported["coverage_plan"]["observation_count"] == 0
    assert exported["coverage_plan"]["conclusion_count"] == 0
    assert exported["coverage_plan"]["integrity_checked"] is True
    assert exported["scope_structure"]["exclusions_reviewed"] is True
    assert "certification conclusion was made" in " ".join(exported["limitations"])
    sensitive_values = (
        "engagement.demo-01",
        "org.customer-01",
        "principal.scope-owner",
        "principal.assessor-01",
        "principal.authorizer-01",
        "auth.written-01",
        "contact.emergency-01",
        "procedure.incident-01",
        "procedure.delete-01",
        "site.main",
        "site.vendor",
        "asset.collector-01",
        "asset.fragile-01",
        "vantage.local-01",
        "192.168.50.0/24",
        "192.168.50.10",
        "10.20.30.40",
    )
    assert all(value not in encoded for value in sensitive_values)
    assert plan.plan_digest not in encoded
    assert valid_envelope.local_digest not in encoded


def test_share_safe_export_rejects_mismatched_engagement(valid_envelope) -> None:
    plan = build_coverage_plan(
        envelope=valid_envelope,
        generated_at=utc("2026-08-17T09:00:00"),
    )
    changed = replace(valid_envelope, engagement_id="engagement.other-01")
    with pytest.raises(ValueError, match="different engagement"):
        build_share_safe_export(envelope=changed, plan=plan)


def test_plan_generation_before_authorization_issuance_is_rejected(valid_envelope) -> None:
    with pytest.raises(AssessmentPlanRejected, match="not current"):
        build_coverage_plan(
            envelope=valid_envelope,
            generated_at=valid_envelope.authorization.issued_at - timedelta(seconds=1),
        )
