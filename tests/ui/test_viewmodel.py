from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from netdiag import application
from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, ExecutionStatus, OutcomeStatus
from netdiag.models import CheckRecord, Report, Severity
from netdiag.platform import OSInfo
from netdiag.ui.viewmodel import UI_SCHEMA, build_ui_viewmodel, ready_ui_viewmodel

PLAN = (
    "routing",
    "routing",
    "dns",
    "wifi",
    "lan",
    "mdns",
    "gateway_ports",
    "lan",
)
PROGRESS_PLAN = (
    "routing",
    "routing_connectivity",
    "dns",
    "wifi",
    "lan",
    "mdns",
    "gateway_ports",
    "lan_ping",
)


def check(
    module: str,
    execution: str = "completed",
    outcome: str = "healthy",
) -> dict[str, object]:
    return {"module": module, "execution_status": execution, "outcome_status": outcome}


def finding(
    code: str,
    severity: str,
    status: str,
    confidence: str = "high",
    **extra: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "code": code,
        "severity": severity,
        "status": status,
        "confidence": {"level": confidence},
        "title": "withheld",
        "detail": "withheld",
        "hint": "",
    }
    value.update(extra)
    return value


def progress_event(sequence: int, step: int, phase: str) -> dict[str, object]:
    return {
        "sequence": sequence,
        "module": PROGRESS_PLAN[step - 1],
        "phase": phase,
        "step": step,
        "total_steps": 8,
    }


def terminal_progress_events(phases: list[str]) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    sequence = 0
    for step, phase in enumerate(phases, start=1):
        if phase in {"completed", "failed"}:
            sequence += 1
            events.append(progress_event(sequence, step, "started"))
        sequence += 1
        events.append(progress_event(sequence, step, phase))
    return events


def passive_checks() -> list[dict[str, object]]:
    return [
        check("routing", outcome="informational"),
        check("routing", "not_run", "not_tested"),
        check("dns", "not_run", "not_tested"),
        check("wifi", outcome="informational"),
        check("lan", outcome="informational"),
        check("mdns", "not_run", "not_tested"),
        check("gateway_ports", "not_run", "not_tested"),
        check("lan", "not_run", "not_tested"),
    ]


def passive_findings() -> list[dict[str, object]]:
    return [
        finding("NDG.ROUTE.DEFAULT_ROUTE_OBSERVED", "info", "informational"),
        finding("NDG.WIFI.CONNECTED", "info", "informational"),
        finding("NDG.LAN.NEIGHBOR_CACHE_READ", "info", "informational"),
    ]


def coverage_for(checks: list[dict[str, object]]) -> dict[str, object]:
    counts = {key: 0 for key in ("completed", "partial", "failed", "cancelled", "not_run")}
    for item in checks:
        execution = item["execution_status"]
        assert isinstance(execution, str)
        counts[execution] += 1
    planned = len(checks)
    usable = counts["completed"] + counts["partial"]
    status = (
        "complete"
        if planned and counts["completed"] == planned
        else "partial"
        if usable
        else "none"
    )
    return {"status": status, "planned": planned, **counts}


def report_status(checks: list[dict[str, object]]) -> str:
    executions = [item["execution_status"] for item in checks]
    if "cancelled" in executions:
        return "cancelled"
    if executions and set(executions) == {"completed"}:
        return "completed"
    if any(item in {"completed", "partial"} for item in executions):
        return "partial"
    if "failed" in executions:
        return "failed"
    return "not_run"


def snapshot(
    *,
    checks: list[dict[str, object]] | None = None,
    findings: list[dict[str, object]] | None = None,
    severity: str = "ok",
    outcome: str = "inconclusive",
    status: str | None = None,
    goal: str = "network",
    state: str = "completed",
    truncated: bool = False,
    profile: str = "passive",
    include_mdns: bool = False,
    cancel_requested: bool | None = None,
) -> dict[str, object]:
    selected_checks = checks if checks is not None else passive_checks()
    selected_findings = findings if findings is not None else passive_findings()
    return {
        "state": state,
        "duration_ms": 27,
        "run": {
            "goal": goal,
            "profile": profile,
            "include_mdns": include_mdns,
            "cancel_requested": state == "cancelled"
            if cancel_requested is None
            else cancel_requested,
        },
        "progress": {
            "processed": len(selected_checks),
            "planned": len(selected_checks),
            "percent": 100,
            "events": [],
        },
        "result": {
            "schema_version": "1.1",
            "status": status or report_status(selected_checks),
            "outcome": outcome,
            "severity": severity,
            "coverage": coverage_for(selected_checks),
            "checks": selected_checks,
            "findings": selected_findings,
            "redacted": True,
            "truncated": truncated,
        },
    }


def ideal_low_impact_snapshot(*, goal: str = "problem") -> dict[str, object]:
    """Return the best reachable live profile: no adverse result, partial scope."""

    checks = [
        check("routing", outcome="informational"),
        check("routing", outcome="healthy"),
        check("dns", outcome="healthy"),
        check("wifi", outcome="healthy"),
        check("lan", outcome="informational"),
        check("mdns", outcome="informational"),
        check("gateway_ports", outcome="informational"),
        check("lan", "not_run", "not_tested"),
    ]
    findings = [
        finding("NDG.ROUTE.DEFAULT_ROUTE_OBSERVED", "info", "informational"),
        finding("NDG.ROUTE.GATEWAY_REACHABLE", "ok", "healthy"),
        finding("NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE", "ok", "healthy"),
        finding("NDG.DNS.RESOLUTION_SUCCEEDED", "ok", "healthy"),
        finding("NDG.WIFI.CONNECTED", "info", "informational"),
        finding("NDG.WIFI.SIGNAL_STRONG", "ok", "healthy"),
        finding("NDG.LAN.NEIGHBOR_CACHE_READ", "info", "informational"),
        finding("NDG.MDNS.SERVICES_DISCOVERED", "info", "informational"),
        finding("NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE", "info", "informational"),
    ]
    return snapshot(
        checks=checks,
        findings=findings,
        severity="ok",
        outcome="inconclusive",
        status="partial",
        goal=goal,
        profile="low_impact_network",
        include_mdns=True,
    )


def module(view: dict[str, object], module_id: str) -> dict[str, object]:
    modules = view["modules"]
    assert isinstance(modules, list)
    return next(item for item in modules if isinstance(item, dict) and item["id"] == module_id)


def node(view: dict[str, object], node_id: str) -> dict[str, object]:
    path = view["path"]
    assert isinstance(path, list)
    return next(item for item in path if isinstance(item, dict) and item["id"] == node_id)


def test_ready_viewmodel_is_exact_fixed_v2_contract() -> None:
    view = ready_ui_viewmodel()

    assert set(view) == {
        "schema",
        "product",
        "transport",
        "state",
        "summary",
        "assessment",
        "run",
        "progress",
        "issues",
        "path",
        "modules",
        "capabilities",
    }
    assert view["schema"] == UI_SCHEMA == "lantern.ui.v2"
    assert view["transport"] == "loopback"
    assert view["run"] is None
    assert view["issues"] == []
    assert view["assessment"] == {
        "sentence": "Lantern has not run a diagnostic check yet.",
        "tone": "neutral",
        "confidence": "none",
        "coverage": "none",
        "disclaimer": None,
    }
    assert [item["id"] for item in view["modules"]] == [
        "route",
        "wifi",
        "dns",
        "lan",
        "mdns",
        "ports",
    ]
    assert all(
        set(item)
        == {"id", "label", "status", "detail", "finding", "why_it_matters", "technical"}
        for item in view["modules"]
    )
    assert [item["id"] for item in view["path"]] == [
        "device",
        "gateway",
        "internet",
        "dns",
        "services",
    ]
    assert [(item["label"], item["module"]) for item in view["path"]] == [
        ("Device route", "route"),
        ("Gateway", "route"),
        ("Internet", "route"),
        ("DNS", "dns"),
        ("Local services", "mdns"),
    ]
    assert {item["status"] for item in view["path"]} == {"not_run"}
    assert view["capabilities"]["remediation"] is False
    assert view["capabilities"]["credentials"] is False
    assert view["capabilities"]["share_export"] is False


def test_terminal_states_enable_local_report_export() -> None:
    ready = ready_ui_viewmodel()
    assert ready["capabilities"]["share_export"] is False

    completed = build_ui_viewmodel(ideal_low_impact_snapshot(goal="problem"))
    assert completed["state"] == "completed"
    assert completed["capabilities"]["share_export"] is True

    cancelled_view = build_ui_viewmodel(
        snapshot(
            checks=[check("routing", "cancelled", "cancelled")]
            + [check(category, "not_run", "not_tested") for category in PLAN[1:]],
            findings=[],
            status="cancelled",
            outcome="cancelled",
            state="cancelled",
            goal="problem",
        )
    )
    assert cancelled_view["capabilities"]["share_export"] is True

    failed_view = build_ui_viewmodel(
        {
            "state": "failed",
            "duration_ms": 0,
            "run": {
                "goal": "problem",
                "profile": "passive",
                "include_mdns": False,
                "cancel_requested": False,
            },
            "progress": {"processed": 0, "planned": 0, "percent": 0, "events": []},
            "result": None,
        }
    )
    assert failed_view["capabilities"]["share_export"] is True


def test_output_contract_is_bounded_and_control_free() -> None:
    view = build_ui_viewmodel(ideal_low_impact_snapshot(goal="network"))
    assessment = view["assessment"]
    assert isinstance(assessment, dict)
    assert 1 <= len(assessment["sentence"]) <= 240
    assert 1 <= len(assessment["disclaimer"]) <= 300
    assert len(view["issues"]) <= 3
    for item in [*view["modules"], *view["path"]]:
        for value in item.values():
            if isinstance(value, str):
                assert not any(ord(character) < 32 or ord(character) == 127 for character in value)
    assert all(len(item["technical"]) <= 4 for item in view["modules"])


def test_viewmodel_drops_raw_report_prose_evidence_identifiers_and_dynamic_keys() -> None:
    value = snapshot()
    result = value["result"]
    assert isinstance(result, dict)
    findings = result["findings"]
    assert isinstance(findings, list)
    findings[0].update(
        {
            "title": "private-ssid",
            "detail": "recovery-key=abc",
            "hint": "192.168.50.20",
            "secret-key-family-mac.local": "password=hunter2",
        }
    )
    result.update(
        {
            "report_id": "family-mac.local",
            "assessment": "password=hunter2",
            "evidence": [{"value": "recovery-key=abc"}],
            "data": {"192.168.50.20": "private-ssid"},
        }
    )

    encoded = json.dumps(build_ui_viewmodel(value))
    for canary in (
        "hunter2",
        "family-mac",
        "private-ssid",
        "recovery-key",
        "192.168.50.20",
        "secret-key",
    ):
        assert canary not in encoded


def test_progress_percent_is_derived_and_duration_is_bounded() -> None:
    value = snapshot()
    value["state"] = "running"
    value["result"] = None
    value["duration_ms"] = 41
    value["progress"] = {
        "processed": 2,
        "planned": 8,
        "percent": 99,
        "events": [
            progress_event(1, 1, "started"),
            progress_event(2, 1, "completed"),
            progress_event(3, 2, "not_run"),
        ],
    }

    view = build_ui_viewmodel(value)

    assert view["progress"] == {"processed": 2, "planned": 8, "percent": 25}
    assert view["run"]["duration_ms"] == 41
    assert view["assessment"]["confidence"] == "none"


def test_progress_scope_rejects_passive_dns_probe() -> None:
    item = snapshot()
    item["state"] = "running"
    item["result"] = None
    item["progress"] = {
        "processed": 2,
        "planned": 8,
        "percent": 25,
        "events": [
            progress_event(1, 1, "started"),
            progress_event(2, 1, "completed"),
            progress_event(3, 2, "not_run"),
            progress_event(4, 3, "started"),
        ],
    }
    with pytest.raises(ValueError, match="authorized diagnostic scope"):
        build_ui_viewmodel(item)


def test_later_route_progress_cannot_erase_an_earlier_failed_route_step() -> None:
    item = snapshot(profile="low_impact_network")
    item["state"] = "running"
    item["result"] = None
    item["progress"] = {
        "processed": 2,
        "planned": 8,
        "percent": 25,
        "events": [
            progress_event(1, 1, "started"),
            progress_event(2, 1, "failed"),
            progress_event(3, 2, "started"),
            progress_event(4, 2, "completed"),
            progress_event(5, 3, "started"),
        ],
    }

    view = build_ui_viewmodel(item)

    assert module(view, "route")["status"] == "unavailable"
    assert module(view, "dns")["status"] == "running"


def test_progress_scope_rejects_mdns_when_option_is_off() -> None:
    item = snapshot(profile="low_impact_network")
    item["state"] = "running"
    item["result"] = None
    events = terminal_progress_events(["completed"] * 5)
    events.append(progress_event(len(events) + 1, 6, "started"))
    item["progress"] = {
        "processed": 5,
        "planned": 8,
        "percent": 63,
        "events": events,
    }
    with pytest.raises(ValueError, match="authorized diagnostic scope"):
        build_ui_viewmodel(item)


def test_progress_scope_rejects_active_lan_for_low_impact_profile() -> None:
    item = snapshot(profile="low_impact_network", include_mdns=True)
    item["state"] = "running"
    item["result"] = None
    events = terminal_progress_events(["completed"] * 7)
    events.append(progress_event(len(events) + 1, 8, "started"))
    item["progress"] = {
        "processed": 7,
        "planned": 8,
        "percent": 88,
        "events": events,
    }
    with pytest.raises(ValueError, match="authorized diagnostic scope"):
        build_ui_viewmodel(item)


def test_terminal_progress_must_match_result_executions() -> None:
    item = ideal_low_impact_snapshot()
    item["progress"] = {
        "processed": 8,
        "planned": 8,
        "percent": 100,
        "events": terminal_progress_events(
            [
                "completed",
                "completed",
                "failed",
                "completed",
                "completed",
                "completed",
                "completed",
                "not_run",
            ]
        ),
    }
    with pytest.raises(ValueError, match="progress does not match"):
        build_ui_viewmodel(item)


def test_progress_event_shape_rejects_type_confusion_and_secret_keys() -> None:
    for mutation in (
        lambda event: event.update({"step": True}),
        lambda event: event.update({"password=hunter2": "private-ssid"}),
    ):
        item = snapshot()
        item["state"] = "running"
        item["result"] = None
        event = progress_event(1, 1, "started")
        mutation(event)
        item["progress"] = {
            "processed": 0,
            "planned": 8,
            "percent": 0,
            "events": [event],
        }
        with pytest.raises(ValueError):
            build_ui_viewmodel(item)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("processed", True),
        ("processed", "password=hunter2"),
        ("processed", -1),
        ("processed", 129),
        ("planned", True),
        ("planned", []),
        ("planned", -1),
        ("planned", 129),
    ],
)
def test_corrupt_progress_counts_fail_closed(field: str, value: object) -> None:
    item = snapshot()
    progress = item["progress"]
    assert isinstance(progress, dict)
    progress[field] = value
    with pytest.raises(ValueError):
        build_ui_viewmodel(item)


@pytest.mark.parametrize("duration", [True, "password=hunter2", [], -1, 2_147_483_648])
def test_corrupt_run_duration_fails_closed(duration: object) -> None:
    item = snapshot()
    item["duration_ms"] = duration
    with pytest.raises(ValueError):
        build_ui_viewmodel(item)


def test_processed_progress_cannot_exceed_plan() -> None:
    item = snapshot()
    item["progress"] = {"processed": 9, "planned": 8, "percent": 100, "events": []}
    with pytest.raises(ValueError, match="cannot exceed"):
        build_ui_viewmodel(item)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile", "active_discovery"),
        ("include_mdns", 1),
        ("cancel_requested", "password=hunter2"),
        ("goal", "compliance"),
    ],
)
def test_mutated_run_metadata_fails_closed(field: str, value: object) -> None:
    item = snapshot()
    run = item["run"]
    assert isinstance(run, dict)
    run[field] = value
    with pytest.raises((TypeError, ValueError)):
        build_ui_viewmodel(item)


def test_coverage_requires_exact_counts_status_and_integer_types() -> None:
    for mutate in (
        lambda value: value.update({"planned": True}),
        lambda value: value.update({"completed": []}),
        lambda value: value.update({"planned": 7}),
        lambda value: value.update({"status": "complete"}),
        lambda value: value.update({"secret": 1}),
    ):
        item = snapshot()
        result = item["result"]
        assert isinstance(result, dict)
        coverage = result["coverage"]
        assert isinstance(coverage, dict)
        mutate(coverage)
        with pytest.raises((TypeError, ValueError)):
            build_ui_viewmodel(item)


def test_nontruncated_coverage_must_exactly_match_check_executions() -> None:
    item = snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    result["coverage"] = {
        "status": "complete",
        "planned": 8,
        "completed": 8,
        "partial": 0,
        "failed": 0,
        "cancelled": 0,
        "not_run": 0,
    }
    with pytest.raises(ValueError, match="coverage does not match check execution"):
        build_ui_viewmodel(item)


@pytest.mark.parametrize("severity", ["info", "warn", "crit"])
def test_top_level_severity_cannot_drift_from_registered_findings(severity: str) -> None:
    item = snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    result["severity"] = severity
    with pytest.raises(ValueError, match="severity does not match"):
        build_ui_viewmodel(item)


@pytest.mark.parametrize(
    ("execution", "outcome"),
    [("not_run", "healthy"), ("cancelled", "not_tested")],
)
def test_scanner_execution_outcome_pairs_fail_closed(execution: str, outcome: str) -> None:
    item = snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    checks = result["checks"]
    assert isinstance(checks, list)
    checks[0] = check("routing", execution, outcome)
    result["coverage"] = coverage_for(checks)
    result["status"] = report_status(checks)
    with pytest.raises(ValueError, match="check must have"):
        build_ui_viewmodel(item)


def test_report_check_plan_order_is_a_fail_closed_positional_invariant() -> None:
    for mutation in ("swap", "duplicate", "missing"):
        item = snapshot()
        result = item["result"]
        assert isinstance(result, dict)
        checks = result["checks"]
        assert isinstance(checks, list)
        if mutation == "swap":
            checks[1], checks[2] = checks[2], checks[1]
        elif mutation == "duplicate":
            checks[2]["module"] = "routing"
        else:
            checks.pop(3)
            result["coverage"] = coverage_for(checks)
        with pytest.raises(ValueError, match="declared Report 1.1 plan"):
            build_ui_viewmodel(item)


def test_truncated_check_plan_allows_only_a_prefix() -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    result["truncated"] = True
    result["checks"] = result["checks"][:3]
    result["findings"] = result["findings"][:4]
    view = build_ui_viewmodel(item)
    assert view["assessment"]["tone"] == "attention"

    result["checks"] = [check("routing"), check("dns")]
    with pytest.raises(ValueError, match="declared Report 1.1 plan"):
        build_ui_viewmodel(item)


def test_truncated_multi_finding_subset_is_limited_not_rejected_or_positive() -> None:
    item = ideal_low_impact_snapshot()
    item["progress"] = {
        "processed": 8,
        "planned": 8,
        "percent": 100,
        "events": terminal_progress_events(
            [
                "completed",
                "completed",
                "completed",
                "completed",
                "completed",
                "completed",
                "completed",
                "not_run",
            ]
        ),
    }
    result = item["result"]
    assert isinstance(result, dict)
    result["truncated"] = True
    findings = result["findings"]
    assert isinstance(findings, list)
    result["findings"] = [value for value in findings if value["code"] != "NDG.WIFI.SIGNAL_STRONG"]

    view = build_ui_viewmodel(item)

    assert view["assessment"]["tone"] == "attention"
    assert module(view, "wifi")["status"] == "limited"
    assert all(item["status"] != "ok" for item in view["path"])


def test_nontruncated_empty_finding_group_cannot_green_an_executed_step() -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    findings = result["findings"]
    assert isinstance(findings, list)
    result["findings"] = [
        value for value in findings if value["code"] != "NDG.DNS.RESOLUTION_SUCCEEDED"
    ]
    with pytest.raises(ValueError, match="outcomes do not match their exact plan step"):
        build_ui_viewmodel(item)


def test_unknown_or_type_confused_finding_fails_closed_without_rendering() -> None:
    for bad in (
        finding("NDG.SECRET.UNKNOWN", "warn", "degraded"),
        {"code": True, "severity": "warn", "status": "degraded", "confidence": {"level": "high"}},
        {
            "code": "NDG.WIFI.SIGNAL_WEAK",
            "severity": [],
            "status": "degraded",
            "confidence": {"level": "high"},
        },
        {
            "code": "NDG.WIFI.SIGNAL_WEAK",
            "severity": "warn",
            "status": "degraded",
            "confidence": ["high"],
        },
    ):
        item = snapshot(findings=[bad])
        with pytest.raises((TypeError, ValueError)):
            build_ui_viewmodel(item)


def test_issue_code_is_bound_to_registered_module_severity_and_status() -> None:
    for field, bad in (("severity", "crit"), ("status", "failed")):
        issue = finding("NDG.WIFI.SIGNAL_WEAK", "warn", "degraded")
        issue[field] = bad
        with pytest.raises(ValueError, match="registered UI meaning"):
            build_ui_viewmodel(snapshot(findings=[issue], severity="warn"))

    reassuring = finding("NDG.WIFI.CONNECTED", "warn", "degraded")
    with pytest.raises(ValueError, match="registered UI meaning"):
        build_ui_viewmodel(snapshot(findings=[reassuring], severity="warn"))


def test_priority_finding_requires_a_matching_typed_check_outcome() -> None:
    issue = finding("NDG.DNS.RESOLUTION_FAILED", "crit", "failed")
    with pytest.raises(ValueError, match="exact plan step"):
        build_ui_viewmodel(snapshot(findings=[issue], severity="crit", outcome="failed"))


@pytest.mark.parametrize(
    ("code", "severity", "outcome"),
    [
        ("NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE", "ok", "healthy"),
        ("NDG.ROUTE.GATEWAY_REACHABLE", "ok", "healthy"),
        ("NDG.MDNS.SERVICES_DISCOVERED", "info", "informational"),
    ],
)
def test_passive_result_rejects_success_findings_from_unexecuted_steps(
    code: str, severity: str, outcome: str
) -> None:
    with pytest.raises(ValueError, match="exact plan step"):
        build_ui_viewmodel(
            snapshot(findings=[*passive_findings(), finding(code, severity, outcome)])
        )


def test_generic_check_failed_requires_failed_execution() -> None:
    checks = passive_checks()
    checks[2] = check("dns", "completed", "inconclusive")
    findings = [
        *passive_findings(),
        finding("NDG.DNS.CHECK_FAILED", "warn", "inconclusive"),
    ]
    with pytest.raises(ValueError, match="failed-collector finding"):
        build_ui_viewmodel(
            snapshot(
                checks=checks,
                findings=findings,
                severity="warn",
                profile="low_impact_network",
            )
        )


def test_failed_step_cannot_support_a_success_or_observation_finding() -> None:
    checks = passive_checks()
    checks[0] = check("routing", "failed", "informational")
    with pytest.raises(ValueError, match="failed plan step cannot support"):
        build_ui_viewmodel(snapshot(checks=checks))


@pytest.mark.parametrize(
    ("code", "severity", "outcome"),
    [
        ("NDG.LAN.ACTIVE_DISCOVERY_NO_SCOPE", "warn", "not_tested"),
        ("NDG.LAN.ACTIVE_DISCOVERY_SCOPE_TOO_LARGE", "warn", "not_tested"),
        ("NDG.LAN.ACTIVE_DISCOVERY_COMPLETED", "info", "informational"),
    ],
)
def test_local_ui_rejects_all_active_discovery_finding_codes(
    code: str, severity: str, outcome: str
) -> None:
    with pytest.raises(ValueError, match="active discovery findings"):
        build_ui_viewmodel(
            snapshot(findings=[*passive_findings(), finding(code, severity, outcome)])
        )


def test_result_profile_scope_rejects_passive_dns_execution() -> None:
    checks = passive_checks()
    checks[2] = check("dns", outcome="not_tested")
    with pytest.raises(ValueError, match="authorized run scope"):
        build_ui_viewmodel(snapshot(checks=checks))


def test_result_profile_scope_rejects_low_impact_active_lan_execution() -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    checks = result["checks"]
    assert isinstance(checks, list)
    checks[7] = check("lan", outcome="not_tested")
    result["coverage"] = coverage_for(checks)
    result["status"] = report_status(checks)
    with pytest.raises(ValueError, match="authorized run scope"):
        build_ui_viewmodel(item)


def test_result_profile_scope_rejects_mdns_when_option_is_off() -> None:
    checks = passive_checks()
    checks[5] = check("mdns", outcome="not_tested")
    with pytest.raises(ValueError, match="authorized run scope"):
        build_ui_viewmodel(
            snapshot(checks=checks, profile="low_impact_network", include_mdns=False)
        )


def test_passive_route_observation_never_confirms_gateway_internet_or_dns() -> None:
    view = build_ui_viewmodel(snapshot())

    assert node(view, "gateway")["status"] == "limited"
    assert "not confirmed" in node(view, "gateway")["detail"]
    assert node(view, "internet")["status"] == "not_run"
    assert "not tested" in node(view, "internet")["detail"]
    assert node(view, "dns")["status"] == "not_run"
    assert view["assessment"]["tone"] == "attention"
    assert view["assessment"]["coverage"] == "partial"


def test_failed_connectivity_step_cannot_be_softened_to_gateway_limited() -> None:
    checks = passive_checks()
    checks[1] = check("routing", "failed", "inconclusive")
    findings = [
        *passive_findings(),
        finding("NDG.ROUTE.CHECK_FAILED", "warn", "inconclusive"),
    ]
    view = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=findings,
            severity="warn",
            profile="low_impact_network",
        )
    )

    assert node(view, "gateway")["status"] == "unavailable"
    assert node(view, "internet")["status"] == "unavailable"
    assert view["issues"][0]["code"] == "NDG.ROUTE.CHECK_FAILED"


def test_partial_success_observation_cannot_green_a_diagnostic_layer() -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    checks = result["checks"]
    assert isinstance(checks, list)
    checks[1]["execution_status"] = "partial"
    result["coverage"] = coverage_for(checks)

    view = build_ui_viewmodel(item)

    assert node(view, "gateway")["status"] == "limited"
    assert node(view, "internet")["status"] == "limited"


def test_empty_ipv4_route_is_attention_without_claiming_total_outage() -> None:
    checks = passive_checks()
    checks[0]["outcome_status"] = "inconclusive"
    findings = [
        finding("NDG.ROUTE.DEFAULT_ROUTE_MISSING", "warn", "inconclusive"),
        *passive_findings()[1:],
    ]
    view = build_ui_viewmodel(
        snapshot(checks=checks, findings=findings, severity="warn", outcome="inconclusive")
    )

    assert [item["code"] for item in view["issues"]] == ["NDG.ROUTE.DEFAULT_ROUTE_MISSING"]
    assert node(view, "device")["status"] == "attention"
    assert "IPv6" in node(view, "device")["detail"]
    assert node(view, "gateway")["status"] == "attention"
    assert "does not establish total Internet failure" in node(view, "gateway")["detail"]
    assert node(view, "internet")["status"] == "not_run"


def test_wifi_not_connected_does_not_claim_an_ethernet_host_is_offline() -> None:
    checks = passive_checks()
    checks[3]["outcome_status"] = "not_tested"
    findings = [
        passive_findings()[0],
        finding("NDG.WIFI.NOT_CONNECTED", "info", "not_tested", "medium"),
        passive_findings()[2],
    ]
    view = build_ui_viewmodel(snapshot(checks=checks, findings=findings))

    assert module(view, "wifi")["status"] == "unavailable"
    assert node(view, "device")["status"] == "ok"
    assert all(item["code"] != "NDG.WIFI.NOT_CONNECTED" for item in view["issues"])
    assert "offline" not in json.dumps(view).lower()


def test_lan_visibility_failure_does_not_degrade_the_route_linked_device_layer() -> None:
    checks = passive_checks()
    checks[4]["outcome_status"] = "inconclusive"
    findings = [
        passive_findings()[0],
        passive_findings()[1],
        finding("NDG.LAN.NEIGHBOR_CACHE_FAILED", "warn", "inconclusive"),
    ]
    view = build_ui_viewmodel(
        snapshot(checks=checks, findings=findings, severity="warn", outcome="inconclusive")
    )

    assert node(view, "device")["status"] == "ok"
    assert module(view, "lan")["status"] == "attention"
    assert view["issues"][0]["module"] == "lan"


def test_incomplete_neighbor_visibility_is_not_called_a_network_problem() -> None:
    checks = passive_checks()
    checks[4]["outcome_status"] = "inconclusive"
    findings = [
        passive_findings()[0],
        passive_findings()[1],
        finding("NDG.LAN.NEIGHBOR_CACHE_PARTIAL", "info", "inconclusive"),
    ]
    view = build_ui_viewmodel(
        snapshot(checks=checks, findings=findings, severity="ok", outcome="inconclusive")
    )

    assert view["assessment"]["tone"] == "attention"
    assert "reported problem" not in view["assessment"]["sentence"]
    assert "incomplete coverage" in view["assessment"]["sentence"]


def test_unsupported_wifi_on_an_ethernet_host_does_not_degrade_device_route() -> None:
    checks = passive_checks()
    checks[3]["outcome_status"] = "unsupported"
    findings = [
        passive_findings()[0],
        finding("NDG.WIFI.UNSUPPORTED", "info", "unsupported"),
        passive_findings()[2],
    ]
    view = build_ui_viewmodel(snapshot(checks=checks, findings=findings))

    assert node(view, "device")["status"] == "ok"
    assert module(view, "wifi")["status"] == "unavailable"
    assert view["issues"][0]["code"] == "NDG.WIFI.UNSUPPORTED"
    assert "Ethernet may still be active" in view["issues"][0]["next_step"]


def test_empty_mdns_window_never_claims_local_services_are_absent() -> None:
    checks = passive_checks()
    checks[5] = check("mdns", outcome="informational")
    findings = [
        *passive_findings(),
        finding("NDG.MDNS.NO_SERVICES_OBSERVED", "info", "informational", "medium"),
    ]
    view = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=findings,
            profile="low_impact_network",
            include_mdns=True,
        )
    )

    assert node(view, "services")["status"] == "limited"
    assert "does not prove" in node(view, "services")["detail"]
    assert not view["issues"]


def test_gateway_ports_unreachable_remains_distinct_from_reachable_and_closed() -> None:
    checks = passive_checks()
    checks[6] = check("gateway_ports", outcome="inconclusive")
    unreachable = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=[
                *passive_findings(),
                finding("NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED", "warn", "inconclusive"),
            ],
            severity="warn",
            profile="low_impact_network",
        )
    )
    assert module(unreachable, "ports")["status"] == "attention"
    assert unreachable["issues"][0]["code"] == "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED"
    assert "indistinguishable" in unreachable["issues"][0]["explanation"]

    checks[6] = check("gateway_ports", outcome="informational")
    reachable = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=[
                *passive_findings(),
                finding("NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE", "info", "informational"),
            ],
            profile="low_impact_network",
        )
    )
    assert module(reachable, "ports")["status"] == "ok"
    assert not reachable["issues"]


def test_priority_issues_are_deduplicated_deterministic_and_capped_at_three() -> None:
    checks = [check(category, outcome="not_tested") for category in PLAN]
    checks[0]["outcome_status"] = "not_tested"
    checks[1]["outcome_status"] = "degraded"
    checks[2]["outcome_status"] = "failed"
    checks[3]["outcome_status"] = "degraded"
    checks[4]["outcome_status"] = "degraded"
    checks[7] = check("lan", "not_run", "not_tested")
    findings = [
        finding("NDG.WIFI.SIGNAL_WEAK", "warn", "degraded"),
        finding("NDG.DNS.RESOLUTION_FAILED", "crit", "failed"),
        finding("NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED", "warn", "degraded"),
        finding("NDG.ROUTE.OUTBOUND_HTTPS_FAILED", "warn", "degraded", "medium"),
        finding("NDG.WIFI.SIGNAL_WEAK", "warn", "degraded"),
    ]
    view = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=findings,
            severity="crit",
            outcome="failed",
            profile="low_impact_network",
            include_mdns=True,
        )
    )

    assert [item["code"] for item in view["issues"]] == [
        "NDG.DNS.RESOLUTION_FAILED",
        "NDG.ROUTE.OUTBOUND_HTTPS_FAILED",
        "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED",
    ]
    assert view["assessment"]["tone"] == view["summary"]["tone"] == "critical"
    assert all(
        set(item) == {"code", "title", "explanation", "next_step", "module", "severity"}
        for item in view["issues"]
    )


def test_goal_changes_only_registered_copy_and_order_not_evidence_or_scope() -> None:
    checks = passive_checks()
    checks[0] = check("routing", "failed", "inconclusive")
    checks[2] = check("dns", "failed", "inconclusive")
    checks[3] = check("wifi", "failed", "inconclusive")
    findings = [
        finding("NDG.ROUTE.CHECK_FAILED", "warn", "inconclusive"),
        finding("NDG.DNS.CHECK_FAILED", "warn", "inconclusive"),
        finding("NDG.WIFI.CHECK_FAILED", "warn", "inconclusive"),
        finding("NDG.LAN.NEIGHBOR_CACHE_READ", "info", "informational"),
    ]
    views = {
        goal: build_ui_viewmodel(
            snapshot(
                checks=checks,
                findings=findings,
                severity="warn",
                outcome="inconclusive",
                goal=goal,
                profile="low_impact_network",
            )
        )
        for goal in ("problem", "network", "rescue")
    }

    assert [item["id"] for item in views["problem"]["modules"]] == [
        "route",
        "wifi",
        "dns",
        "lan",
        "mdns",
        "ports",
    ]
    assert [item["id"] for item in views["network"]["modules"]] == [
        "route",
        "dns",
        "ports",
        "lan",
        "wifi",
        "mdns",
    ]
    assert [item["id"] for item in views["rescue"]["modules"]] == [
        "route",
        "wifi",
        "lan",
        "dns",
        "mdns",
        "ports",
    ]
    assert [item["code"] for item in views["network"]["issues"]] == [
        "NDG.ROUTE.CHECK_FAILED",
        "NDG.DNS.CHECK_FAILED",
        "NDG.WIFI.CHECK_FAILED",
    ]
    assert [item["code"] for item in views["rescue"]["issues"]] == [
        "NDG.ROUTE.CHECK_FAILED",
        "NDG.WIFI.CHECK_FAILED",
        "NDG.DNS.CHECK_FAILED",
    ]
    assert views["problem"]["path"] == views["network"]["path"] == views["rescue"]["path"]
    for view in views.values():
        assert view["run"]["profile"] == "low_impact_network"
        assert view["run"]["include_mdns"] is False


def test_network_goal_is_endpoint_limited_evaluation_not_certification() -> None:
    view = build_ui_viewmodel(snapshot(goal="network"))
    disclaimer = view["assessment"]["disclaimer"]
    assert isinstance(disclaimer, str)
    for phrase in (
        "informational evaluation from one endpoint",
        "not a whole-network assessment",
        "security audit",
        "compliance certification",
        "business",
        "financial system",
        "municipality",
    ):
        assert phrase in disclaimer


def test_rescue_goal_disclaims_viability_recovery_and_sensitive_axes() -> None:
    view = build_ui_viewmodel(snapshot(goal="rescue"))
    disclaimer = view["assessment"]["disclaimer"]
    assert isinstance(disclaimer, str)
    for boundary in (
        "bootability",
        "storage or hardware health",
        "OS integrity",
        "encryption",
        "backups",
        "data recoverability",
        "does not perform recovery",
    ):
        assert boundary in disclaimer
    assert view["capabilities"]["rescue_boot"] is False


@pytest.mark.parametrize(
    "outcome", ["healthy", "not_tested", "unsupported", "permission_denied", "cancelled", "failed"]
)
def test_mutated_overall_outcome_fails_closed(outcome: str) -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    result["outcome"] = outcome
    with pytest.raises(ValueError, match="outcome does not match"):
        build_ui_viewmodel(item)


@pytest.mark.parametrize("status", ["completed", "failed", "not_run", "cancelled"])
def test_mutated_report_status_fails_closed(status: str) -> None:
    item = ideal_low_impact_snapshot()
    result = item["result"]
    assert isinstance(result, dict)
    result["status"] = status
    with pytest.raises(ValueError, match="status does not match"):
        build_ui_viewmodel(item)


def test_application_state_and_cancelled_report_must_agree() -> None:
    item = snapshot(state="cancelled", status="partial")
    with pytest.raises(ValueError, match="cancelled report"):
        build_ui_viewmodel(item)

    item = snapshot(status="cancelled")
    with pytest.raises(ValueError):
        build_ui_viewmodel(item)


def test_cancelled_report_requires_recorded_cancellation_request_even_without_events() -> None:
    checks = [
        check("routing", "cancelled", "cancelled"),
        *[check(category, "not_run", "not_tested") for category in PLAN[1:]],
    ]
    item = snapshot(
        checks=checks,
        findings=[],
        status="cancelled",
        outcome="cancelled",
        state="cancelled",
        cancel_requested=False,
    )
    with pytest.raises(ValueError, match="cancellation request"):
        build_ui_viewmodel(item)


def test_valid_cancelled_report_retains_only_honest_partial_conclusion() -> None:
    checks = [
        check("routing", "cancelled", "cancelled"),
        *[check(category, "not_run", "not_tested") for category in PLAN[1:]],
    ]
    view = build_ui_viewmodel(
        snapshot(
            checks=checks,
            findings=[],
            status="cancelled",
            outcome="cancelled",
            state="cancelled",
            cancel_requested=True,
        )
    )
    assert view["assessment"]["tone"] == "attention"
    assert view["assessment"]["coverage"] == "none"
    assert "stopped" in view["assessment"]["sentence"]


def test_best_reachable_low_impact_run_is_honestly_partial_and_limited() -> None:
    view = build_ui_viewmodel(ideal_low_impact_snapshot())
    assert view["assessment"]["tone"] == view["summary"]["tone"] == "attention"
    assert view["assessment"]["coverage"] == "partial"
    assert view["assessment"]["confidence"] == "low"
    assert view["issues"] == []
    assert module(view, "lan")["status"] == "limited"
    assert {item["status"] for item in view["path"]} == {"ok"}
    assert "coverage was too limited" in view["assessment"]["sentence"]
    assert view["capabilities"]["active_discovery"] is False


def _typed_report(checks: list[CheckRecord], findings: list[object]) -> Report:
    return Report(
        "fixture.invalid",
        OSInfo("Linux", "6.8.0", "x86_64"),
        datetime.now(timezone.utc).isoformat(),
        findings=findings,  # type: ignore[arg-type]
        checks=checks,
    )


def _snapshot_from_report(
    report: Report,
    *,
    goal: str = "network",
    profile: str = "low_impact_network",
    include_mdns: bool = True,
) -> dict[str, object]:
    projection = application._safe_report_projection(report, 384 * 1024)
    return {
        "state": "cancelled"
        if report.execution_status == ExecutionStatus.CANCELLED
        else "completed",
        "duration_ms": report.duration_ms,
        "run": {
            "goal": goal,
            "profile": profile,
            "include_mdns": include_mdns,
            "cancel_requested": report.execution_status == ExecutionStatus.CANCELLED,
        },
        "progress": {"processed": 8, "planned": 8, "percent": 100, "events": []},
        "result": projection,
    }


def test_report_11_presentation_and_ui_tone_cannot_drift_on_critical_dns_fixture() -> None:
    checks = [
        CheckRecord(
            f"netdiag.check.{category}",
            category,
            ExecutionStatus.NOT_RUN if index == 7 else ExecutionStatus.COMPLETED,
            OutcomeStatus.FAILED if index == 2 else OutcomeStatus.NOT_TESTED,
            0 if index == 7 else 1,
        )
        for index, category in enumerate(PLAN)
    ]
    report = _typed_report(
        checks,
        [
            make_finding(
                "NDG.DNS.RESOLUTION_FAILED",
                Severity.CRIT,
                OutcomeStatus.FAILED,
                parameters={"domain": "example.com"},
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    presentation = report.to_dict(redact=True)
    view = build_ui_viewmodel(_snapshot_from_report(report))

    assert presentation["schema_version"] == "1.1"
    assert presentation["outcome"] == "failed"
    assert presentation["severity"] == "crit"
    assert presentation["status"] == "partial"
    assert view["assessment"]["tone"] == view["summary"]["tone"] == "critical"
    assert view["issues"][0]["code"] == "NDG.DNS.RESOLUTION_FAILED"
    assert module(view, "dns")["status"] == "attention"
    assert node(view, "dns")["status"] == "attention"


def test_real_passive_report_projection_preserves_second_routing_slot_as_not_run() -> None:
    executions = (
        ExecutionStatus.COMPLETED,
        ExecutionStatus.NOT_RUN,
        ExecutionStatus.NOT_RUN,
        ExecutionStatus.COMPLETED,
        ExecutionStatus.COMPLETED,
        ExecutionStatus.NOT_RUN,
        ExecutionStatus.NOT_RUN,
        ExecutionStatus.NOT_RUN,
    )
    checks = [
        CheckRecord(
            f"netdiag.check.{category}",
            category,
            execution,
            OutcomeStatus.INFORMATIONAL
            if execution == ExecutionStatus.COMPLETED
            else OutcomeStatus.NOT_TESTED,
            1 if execution == ExecutionStatus.COMPLETED else 0,
        )
        for category, execution in zip(PLAN, executions, strict=True)
    ]
    report = _typed_report(
        checks,
        [
            make_finding(
                "NDG.ROUTE.DEFAULT_ROUTE_OBSERVED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                confidence=ConfidenceLevel.HIGH,
            ),
            make_finding(
                "NDG.WIFI.CONNECTED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"ssid": "fixture", "summary": "no details"},
                confidence=ConfidenceLevel.HIGH,
            ),
            make_finding(
                "NDG.LAN.NEIGHBOR_CACHE_READ",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"count": 0, "interface": "fixture", "addresses": ""},
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    view = build_ui_viewmodel(_snapshot_from_report(report, profile="passive", include_mdns=False))

    assert report.to_dict(redact=True)["coverage"]["status"] == "partial"
    assert node(view, "gateway")["status"] == "limited"
    assert node(view, "internet")["status"] == "not_run"
    assert node(view, "dns")["status"] == "not_run"
    assert view["assessment"]["tone"] == "attention"
