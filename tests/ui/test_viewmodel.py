from __future__ import annotations

import json

import pytest

from netdiag.ui.viewmodel import UI_SCHEMA, build_ui_viewmodel, ready_ui_viewmodel


def completed_snapshot() -> dict[str, object]:
    return {
        "state": "completed",
        "duration_ms": 27,
        "run": {
            "goal": "network",
            "profile": "passive",
            "include_mdns": False,
            "cancel_requested": False,
        },
        "progress": {
            "processed": 8,
            "planned": 8,
            "percent": 100,
            "events": [],
        },
        "result": {
            "severity": "ok",
            "outcome": "healthy",
            "coverage": {"status": "complete"},
            "checks": [
                {
                    "module": "routing",
                    "execution_status": "completed",
                    "outcome_status": "healthy",
                },
                {
                    "module": "routing",
                    "execution_status": "not_run",
                    "outcome_status": "not_tested",
                },
                {
                    "module": "wifi",
                    "execution_status": "completed",
                    "outcome_status": "healthy",
                },
            ],
        },
    }


def test_ready_viewmodel_is_exact_fixed_loopback_contract() -> None:
    view = ready_ui_viewmodel()

    assert set(view) == {
        "schema",
        "product",
        "transport",
        "state",
        "summary",
        "run",
        "progress",
        "modules",
        "capabilities",
    }
    assert view["schema"] == UI_SCHEMA
    assert view["transport"] == "loopback"
    assert view["run"] is None
    assert [module["id"] for module in view["modules"]] == [
        "route",
        "wifi",
        "dns",
        "lan",
        "mdns",
        "ports",
    ]
    assert {module["status"] for module in view["modules"]} == {"not_started"}
    assert view["capabilities"] == {
        "passive_scan": True,
        "low_impact_network": True,
        "active_discovery": False,
        "remediation": False,
        "credentials": False,
        "lan_remote": False,
        "rescue_boot": False,
        "share_export": False,
    }


def test_viewmodel_drops_all_raw_report_evidence_and_finding_maps() -> None:
    snapshot = completed_snapshot()
    result = snapshot["result"]
    assert isinstance(result, dict)
    result.update(
        {
            "report_id": "password=hunter2",
            "assessment": "family-mac.local",
            "findings": [{"detail": "private-ssid"}],
            "evidence": [{"value": "recovery-key=abc"}],
            "data": {"address": "192.168.50.20"},
        }
    )

    encoded = json.dumps(build_ui_viewmodel(snapshot))
    for canary in (
        "hunter2",
        "family-mac",
        "private-ssid",
        "recovery-key",
        "192.168.50.20",
    ):
        assert canary not in encoded


def test_progress_percent_is_derived_and_duration_is_bounded() -> None:
    snapshot = completed_snapshot()
    snapshot["state"] = "running"
    snapshot["result"] = None
    snapshot["duration_ms"] = 41
    snapshot["progress"] = {
        "processed": 2,
        "planned": 8,
        "percent": 99,
        "events": [],
    }

    view = build_ui_viewmodel(snapshot)

    assert view["progress"] == {"processed": 2, "planned": 8, "percent": 25}
    assert view["run"]["duration_ms"] == 41


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("processed", True),
        ("processed", "password=hunter2"),
        ("processed", -1),
        ("processed", 129),
        ("planned", True),
        ("planned", "family-mac.local"),
        ("planned", -1),
        ("planned", 129),
    ],
)
def test_corrupt_progress_counts_fail_closed(field: str, value: object) -> None:
    snapshot = completed_snapshot()
    progress = snapshot["progress"]
    assert isinstance(progress, dict)
    progress[field] = value

    with pytest.raises(ValueError) as exc_info:
        build_ui_viewmodel(snapshot)
    assert "hunter2" not in str(exc_info.value)
    assert "family-mac" not in str(exc_info.value)


@pytest.mark.parametrize("duration", [True, "password=hunter2", -1, 2_147_483_648])
def test_corrupt_run_duration_fails_closed(duration: object) -> None:
    snapshot = completed_snapshot()
    snapshot["duration_ms"] = duration

    with pytest.raises(ValueError) as exc_info:
        build_ui_viewmodel(snapshot)
    assert "hunter2" not in str(exc_info.value)


def test_processed_progress_cannot_exceed_planned_progress() -> None:
    snapshot = completed_snapshot()
    progress = snapshot["progress"]
    assert isinstance(progress, dict)
    progress["processed"] = 9
    progress["planned"] = 8

    with pytest.raises(ValueError, match="cannot exceed"):
        build_ui_viewmodel(snapshot)


def test_combined_module_never_claims_full_success_when_a_subcheck_was_skipped() -> None:
    view = build_ui_viewmodel(completed_snapshot())
    modules = {module["id"]: module for module in view["modules"]}

    assert modules["route"]["status"] == "limited"
    assert modules["wifi"]["status"] == "ok"
    assert modules["dns"]["status"] == "not_run"


def test_running_progress_marks_completed_then_skipped_combined_module_limited() -> None:
    snapshot = completed_snapshot()
    snapshot["state"] = "running"
    snapshot["result"] = None
    snapshot["progress"] = {
        "processed": 2,
        "planned": 8,
        "percent": 25,
        "events": [
            {"module": "routing", "phase": "completed"},
            {"module": "routing_connectivity", "phase": "not_run"},
        ],
    }

    view = build_ui_viewmodel(snapshot)
    route = next(module for module in view["modules"] if module["id"] == "route")
    assert route["status"] == "limited"


@pytest.mark.parametrize(
    "outcome",
    [
        "degraded",
        "failed",
        "blocked",
        "inconclusive",
        "not_tested",
        "unsupported",
        "permission_denied",
        "cancelled",
    ],
)
def test_completed_inconclusive_outcomes_never_receive_positive_summary(outcome: str) -> None:
    snapshot = completed_snapshot()
    result = snapshot["result"]
    assert isinstance(result, dict)
    result["outcome"] = outcome

    view = build_ui_viewmodel(snapshot)

    assert view["summary"]["tone"] == "attention"
    assert "without a reported problem" not in view["summary"]["detail"]
    if outcome in {"degraded", "failed", "blocked"}:
        assert view["summary"]["headline"] == "Lantern found something to review"
        assert "not run" not in view["summary"]["detail"]


@pytest.mark.parametrize("outcome", ["degraded", "failed", "blocked"])
@pytest.mark.parametrize("coverage_status", ["partial", "none"])
def test_adverse_outcome_is_never_hidden_by_incomplete_coverage(
    outcome: str,
    coverage_status: str,
) -> None:
    snapshot = completed_snapshot()
    result = snapshot["result"]
    assert isinstance(result, dict)
    result["outcome"] = outcome
    coverage = result["coverage"]
    assert isinstance(coverage, dict)
    coverage["status"] = coverage_status

    view = build_ui_viewmodel(snapshot)

    assert view["summary"]["headline"] == "Lantern found something to review"
    assert "found a reported problem" in view["summary"]["detail"]
    assert "incomplete" in view["summary"]["detail"]


def test_rescue_goal_explicitly_disclaims_boot_storage_and_hardware_assessment() -> None:
    snapshot = completed_snapshot()
    run = snapshot["run"]
    assert isinstance(run, dict)
    run["goal"] = "rescue"

    view = build_ui_viewmodel(snapshot)

    detail = view["summary"]["detail"]
    for boundary in (
        "bootability",
        "storage or hardware health",
        "OS integrity",
        "encryption",
        "backups",
        "data recoverability",
    ):
        assert boundary in detail
    assert view["capabilities"]["rescue_boot"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile", "active_discovery"),
        ("include_mdns", 1),
        ("cancel_requested", "password=hunter2"),
    ],
)
def test_mutated_or_type_confused_run_metadata_fails_closed(
    field: str,
    value: object,
) -> None:
    snapshot = completed_snapshot()
    run = snapshot["run"]
    assert isinstance(run, dict)
    run[field] = value

    with pytest.raises((TypeError, ValueError)) as exc_info:
        build_ui_viewmodel(snapshot)
    assert "hunter2" not in str(exc_info.value)


def test_cancelled_outcome_in_completed_check_is_never_ok() -> None:
    snapshot = completed_snapshot()
    result = snapshot["result"]
    assert isinstance(result, dict)
    checks = result["checks"]
    assert isinstance(checks, list)
    checks[0]["outcome_status"] = "cancelled"

    view = build_ui_viewmodel(snapshot)
    route = next(module for module in view["modules"] if module["id"] == "route")
    assert route["status"] == "cancelled"


@pytest.mark.parametrize("other", [("partial", "cancelled"), ("cancelled", "cancelled")])
def test_known_adverse_module_result_dominates_cancelled_or_partial_subcheck(
    other: tuple[str, str],
) -> None:
    snapshot = completed_snapshot()
    result = snapshot["result"]
    assert isinstance(result, dict)
    checks = result["checks"]
    assert isinstance(checks, list)
    checks[0]["outcome_status"] = "degraded"
    checks[1]["execution_status"], checks[1]["outcome_status"] = other

    view = build_ui_viewmodel(snapshot)
    route = next(module for module in view["modules"] if module["id"] == "route")
    assert route["status"] == "attention"
