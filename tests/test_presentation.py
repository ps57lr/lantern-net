from __future__ import annotations

import ast
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from netdiag.catalog import FINDING_REGISTRY, make_finding
from netdiag.core.diagnostics import Confidence
from netdiag.core.evidence import ErrorDetail, Evidence
from netdiag.core.status import (
    ConfidenceLevel,
    ExecutionStatus,
    OutcomeStatus,
    Sensitivity,
)
from netdiag.core.values import DiagnosticValue
from netdiag.models import CheckRecord, Finding, Report, Severity
from netdiag.platform import OSInfo
from netdiag.presentation import (
    evidence_kind_for,
    serialize_command_result,
    serialize_finding,
)
from netdiag.scanner import run_full_scan

_EXECUTION_STATUSES = {"completed", "partial", "failed", "cancelled", "not_run"}
_OUTCOME_STATUSES = {
    "healthy",
    "informational",
    "degraded",
    "failed",
    "blocked",
    "inconclusive",
    "not_tested",
    "unsupported",
    "permission_denied",
    "cancelled",
}


def _assert_lightweight_report_11_contract(payload: dict) -> None:
    """Check the emitted contract without adding a runtime schema dependency."""

    assert payload["schema_version"] == "1.1"
    assert isinstance(payload["tool_version"], str) and payload["tool_version"]
    assert isinstance(payload["report_id"], str) and payload["report_id"]
    assert isinstance(payload["hostname"], str)
    assert set(payload["os"]) >= {"system", "release", "machine"}
    assert payload["status"] in _EXECUTION_STATUSES
    assert payload["outcome"] in _OUTCOME_STATUSES
    assert payload["severity"] in {"ok", "info", "warn", "crit"}
    assert isinstance(payload["assessment"], str) and payload["assessment"]
    assert isinstance(payload["duration_ms"], int) and payload["duration_ms"] >= 0
    assert isinstance(payload["redacted"], bool)

    coverage = payload["coverage"]
    assert coverage["status"] in {"complete", "partial", "none"}
    count_keys = {"completed", "partial", "failed", "cancelled", "not_run"}
    assert all(isinstance(coverage[key], int) and coverage[key] >= 0 for key in count_keys)
    assert sum(coverage[key] for key in count_keys) == coverage["planned"]

    evidence_ids = {item["evidence_id"] for item in payload["evidence"]}
    for finding in payload["findings"]:
        assert finding["code"] is None or re.fullmatch(
            r"NDG(?:\.[A-Z][A-Z0-9_]*){2,}", finding["code"]
        )
        assert finding["severity"] in {"ok", "info", "warn", "crit"}
        assert finding["status"] in _OUTCOME_STATUSES
        assert finding["confidence"]["level"] in {"low", "medium", "high"}
        assert isinstance(finding["confidence"]["rationale"], str)
        assert set(finding["evidence_refs"]) <= evidence_ids
        assert set(finding["confidence"]["evidence_refs"]) <= evidence_ids
        assert all(isinstance(finding[key], str) for key in ("title", "detail", "hint"))
        assert isinstance(finding["data"], dict)

    for check in payload["checks"]:
        assert check["execution_status"] in _EXECUTION_STATUSES
        assert check["outcome_status"] in _OUTCOME_STATUSES
        assert set(check["evidence_refs"]) <= evidence_ids
        assert check["error"] is None or set(check["error"]) == {
            "code",
            "message",
            "retryable",
            "native_exit_code",
        }
    for evidence in payload["evidence"]:
        assert evidence["status"] in _OUTCOME_STATUSES
        assert evidence["error"] is None or set(evidence["error"]) == {
            "code",
            "message",
            "retryable",
            "native_exit_code",
        }
    assert isinstance(payload["access_prerequisites"], list)
    assert set(payload["remediation"]) >= {"available_actions", "attempts"}
    assert isinstance(payload["data"], dict)
    json.dumps(payload)


def _wifi_finding() -> Finding:
    return make_finding(
        "NDG.WIFI.CONNECTED",
        Severity.INFO,
        OutcomeStatus.INFORMATIONAL,
        parameters={"ssid": "pi", "summary": "no details"},
        confidence=ConfidenceLevel.HIGH,
    )


def _report_with_canaries() -> Report:
    routing_data = {
        "default_gateway": "192.168.1.1",
        "default_interface": "en0",
        "has_default_route": True,
        "password": "hunter2",
        "password=hunter2": "secret-key-value",
        "nested": {
            "recovery_key": "do-not-print",
            "hostname=private-router.internal": "hostname-key-value",
            "<field-1>": "collision-secret",
        },
    }
    evidence = Evidence(
        "evidence.routing.observation",
        evidence_kind_for("routing"),
        "netdiag.check.routing",
        OutcomeStatus.HEALTHY,
        "netdiag.source.routing_legacy",
        datetime(2026, 8, 16, tzinfo=timezone.utc),
        10,
        routing_data,
    )
    return Report(
        hostname="family-mac.local",
        os=OSInfo("Darwin", "test", "arm64"),
        started_at="2026-08-16T22:00:00+00:00",
        duration_ms=10,
        findings=[
            _wifi_finding(),
            make_finding(
                "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={"target": "1.1.1.1"},
            ),
        ],
        checks=[
            CheckRecord(
                "netdiag.check.routing",
                "routing",
                ExecutionStatus.COMPLETED,
                OutcomeStatus.HEALTHY,
                10,
                ("evidence.routing.observation",),
            )
        ],
        evidence=[evidence],
        data={
            "routing": routing_data,
            "wifi": {"ssid": "pi", "bssid": "aa:bb:cc:dd:ee:ff"},
            "dns": {
                "queries": [
                    {
                        "domain": "family.internal",
                        "answers": [
                            {
                                "resolver": "192.168.1.1",
                                "domain": "family.internal",
                                "addresses": ["192.168.1.20"],
                                "error": None,
                                "blocked": False,
                                "response_ms": 2,
                            }
                        ],
                    }
                ]
            },
        },
        remediation={
            "available_actions": [],
            "attempts": [],
        },
    )


def test_schema_11_preserves_compatibility_fields_and_adds_typed_dimensions():
    payload = _report_with_canaries().to_dict()
    _assert_lightweight_report_11_contract(payload)
    assert payload["schema_version"] == "1.1"
    assert {
        "hostname",
        "os",
        "started_at",
        "duration_ms",
        "severity",
        "findings",
        "data",
    }.issubset(payload)
    assert payload["status"] == "completed"
    assert payload["outcome"] == "healthy"
    assert payload["coverage"] == {
        "status": "complete",
        "planned": 1,
        "completed": 1,
        "partial": 0,
        "failed": 0,
        "cancelled": 0,
        "not_run": 0,
    }
    finding = payload["findings"][0]
    assert finding["code"] == "NDG.WIFI.CONNECTED"
    assert finding["status"] == "informational"
    assert finding["confidence"]["level"] == "high"
    assert "evidence_refs" in finding
    assert "remediation_refs" in finding
    json.dumps(payload)


def test_report_id_is_random_opaque_and_stable_across_export_modes() -> None:
    first = _report_with_canaries()
    raw = first.to_dict()
    shared = first.to_dict(redact=True)
    assert raw["report_id"] == shared["report_id"] == first.report_id
    assert re.fullmatch(r"report-[0-9a-f]{32}", raw["report_id"])
    assert "family-mac" not in raw["report_id"]

    second = _report_with_canaries()
    assert second.report_id != first.report_id
    second.hostname = "another-family-device.local"
    assert second.to_dict()["report_id"] == second.report_id


@pytest.mark.parametrize(
    "unsafe_id",
    ("family-device", "report-family-device", "report-" + "a" * 16, "report-" + "g" * 32),
)
def test_report_id_is_generation_only_and_cannot_be_supplied(unsafe_id: str) -> None:
    with pytest.raises(TypeError, match="report_id"):
        Report(
            hostname="family-mac.local",
            os=OSInfo("Darwin", "test", "arm64"),
            started_at="2026-08-16T22:00:00+00:00",
            report_id=unsafe_id,
        )


@pytest.mark.parametrize("redact", [False, True])
def test_report_id_binding_cannot_be_mutated_or_reauthorized(redact: bool) -> None:
    report = _report_with_canaries()
    original = report.report_id

    with pytest.raises(AttributeError):
        report._report_id = "family-mac.local"  # type: ignore[misc]
    assert report.to_dict(redact=redact)["report_id"] == original

    object.__setattr__(
        report,
        "_report_identity",
        ("report-" + "deadbeef" * 4, report._report_identity[1]),
    )
    with pytest.raises(ValueError, match="generated binding"):
        report.__post_init__()
    with pytest.raises(ValueError, match="generated binding"):
        report.to_dict(redact=redact)


@pytest.mark.parametrize("redact", [False, True])
def test_report_revalidates_nested_execution_models_at_export(redact: bool) -> None:
    report = _report_with_canaries()
    check = report.checks[0]
    object.__setattr__(check, "duration_ms", "password=hunter2")
    with pytest.raises(TypeError, match="duration_ms"):
        report.to_dict(redact=redact)

    report = _report_with_canaries()
    check = report.checks[0]
    object.__setattr__(
        check,
        "error",
        {"retryable": "family-mac.local", "native_exit_code": "recovery-key=abc"},
    )
    with pytest.raises(TypeError, match="ErrorDetail"):
        report.to_dict(redact=redact)

    report = _report_with_canaries()
    check = report.checks[0]
    error = ErrorDetail("netdiag.fixture.failed", "Expected fixture error")
    object.__setattr__(error, "retryable", "family-mac.local")
    object.__setattr__(check, "error", error)
    with pytest.raises(TypeError, match="retryable"):
        report.to_dict(redact=redact)


@pytest.mark.parametrize("redact", [False, True])
def test_report_revalidates_evidence_error_at_export(redact: bool) -> None:
    report = _report_with_canaries()
    evidence = report.evidence[0]
    object.__setattr__(evidence, "status", OutcomeStatus.FAILED)
    object.__setattr__(
        evidence,
        "error",
        {"retryable": "family-mac.local", "native_exit_code": "recovery-key=abc"},
    )
    with pytest.raises(TypeError, match="ErrorDetail"):
        report.to_dict(redact=redact)


@pytest.mark.parametrize("share_safe", [False, True])
def test_registered_finding_semantics_are_revalidated_at_export(share_safe: bool) -> None:
    finding = _wifi_finding()
    finding.parameters["summary"] = DiagnosticValue(
        "password=hunter2",
        Sensitivity.PUBLIC,
    )
    with pytest.raises(ValueError, match="not normalized"):
        serialize_finding(finding, share_safe=share_safe)

    finding = _wifi_finding()
    finding.parameters.pop("summary")
    with pytest.raises(ValueError, match="exactly match"):
        serialize_finding(finding, share_safe=share_safe)


def test_structural_redaction_is_fail_closed_in_raw_and_share_safe_exports():
    report = _report_with_canaries()
    before = copy.deepcopy(report.data)

    raw = report.to_dict()
    shared = report.to_dict(redact=True)
    raw_text = json.dumps(raw)
    shared_text = json.dumps(shared)

    for secret in (
        "hunter2",
        "do-not-print",
        "secret-key-value",
        "hostname-key-value",
        "collision-secret",
    ):
        assert secret not in raw_text
        assert secret not in shared_text
    for secret_key in (
        "password=hunter2",
        "hostname=private-router.internal",
    ):
        assert secret_key not in raw_text
        assert secret_key not in shared_text
    assert raw["hostname"] == "family-mac.local"
    assert raw["data"]["dns"]["queries"][0]["domain"] == "family.internal"
    assert shared["hostname"].startswith("<device-")
    assert "family.internal" not in shared_text
    assert "aa:bb:cc:dd:ee:ff" not in shared_text
    assert "Connected to <device-" in shared["findings"][0]["title"]
    # Structural redaction must not corrupt an unrelated word when the SSID is "pi".
    assert shared["findings"][0]["detail"] == "no details"
    assert shared["data"]["routing"]["default_gateway"] == "192.168.1.1"
    assert report.data == before


@pytest.mark.parametrize("redact", [False, True])
def test_report_rejects_scalar_shape_confusion_before_export(redact: bool) -> None:
    finding = Finding(Severity.INFO, "wifi", "title", "detail")
    finding.data = "password=hunter2"  # type: ignore[assignment]
    report = Report(
        "host",
        OSInfo("Darwin", "test", "arm64"),
        "2026-08-16T00:00:00Z",
        findings=[finding],
    )
    with pytest.raises(TypeError, match="finding data must be a JSON object"):
        report.to_dict(redact=redact)

    report = Report(
        "host",
        OSInfo("Darwin", "test", "arm64"),
        "2026-08-16T00:00:00Z",
    )
    report.access_prerequisites = [
        {
            "prerequisite_id": "password=hunter2",
            "kind": "credential.secret",
            "state": "required",
            "related_refs": [],
        }
    ]
    with pytest.raises(TypeError, match="AccessPrerequisite"):
        report.to_dict(redact=redact)

    report.access_prerequisites = []
    report.remediation = {
        "available_actions": "router-password=hunter2",
        "attempts": [],
    }
    with pytest.raises(TypeError, match="available_actions"):
        report.to_dict(redact=redact)


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("system", "password=hunter2"),
        ("release", "family-mac.local"),
        ("machine", "recovery-key=abc"),
    ],
)
def test_report_revalidates_platform_metadata_at_export(
    redact: bool,
    field: str,
    value: str,
) -> None:
    osinfo = OSInfo("Darwin", "test", "arm64")
    object.__setattr__(osinfo, field, value)
    report = Report(
        "host",
        osinfo,
        "2026-08-16T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="platform"):
        report.to_dict(redact=redact)


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("hostname", 7, "hostname"),
        ("started_at", "wifi-password=hunter2", "started_at"),
        ("duration_ms", "password=hunter2", "duration_ms"),
        ("duration_ms", True, "duration_ms"),
    ],
)
def test_report_rejects_mutated_top_level_shapes(
    redact: bool,
    field: str,
    value: object,
    message: str,
) -> None:
    report = Report(
        "host",
        OSInfo("Darwin", "test", "arm64"),
        "2026-08-16T00:00:00+00:00",
    )
    setattr(report, field, value)
    with pytest.raises((TypeError, ValueError), match=message):
        report.to_dict(redact=redact)


@pytest.mark.parametrize(
    "unsafe_ref",
    ("password=hunter2", "recovery-key=abc", "bad ref"),
)
def test_finding_references_require_identifier_syntax(unsafe_ref: str) -> None:
    with pytest.raises(ValueError, match="lower-case dotted identifier"):
        Finding(
            Severity.INFO,
            "wifi",
            "title",
            "detail",
            evidence_refs=(unsafe_ref,),
        )


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("category", ["family-mac.local", "password-hunter2"])
def test_standalone_legacy_finding_uses_fixed_category(redact: bool, category: str) -> None:
    finding = Finding(
        Severity.INFO,
        category,
        "Legacy title",
        "Legacy detail",
    )
    payload = serialize_finding(finding, share_safe=redact)
    rendered = json.dumps(payload)
    assert payload["category"] == "diagnostic"
    assert category not in rendered


@pytest.mark.parametrize("redact", [False, True])
def test_report_aliases_prefix_smuggled_logical_references(redact: bool) -> None:
    logical_id = "evidence.family-mac.local"
    canaries = (
        "family-mac.local",
        "password-hunter2",
        "recovery-key-abc",
    )
    item = Evidence(
        logical_id,
        evidence_kind_for("wifi"),
        "netdiag.check.wifi",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.wifi_legacy",
        datetime(2026, 8, 16, tzinfo=timezone.utc),
        1,
        {},
    )
    finding = Finding(
        Severity.INFO,
        "wifi",
        "Legacy title",
        "Legacy detail",
        evidence_refs=(logical_id,),
        confidence=Confidence(
            ConfidenceLevel.LOW,
            "Legacy rationale",
            (logical_id,),
        ),
        finding_id="finding.recovery-key-abc",
    )
    report = Report(
        "host",
        OSInfo("Linux", "test", "x86_64"),
        "2026-08-16T00:00:00Z",
        findings=[finding],
        checks=[
            CheckRecord(
                "netdiag.check.wifi",
                "wifi",
                ExecutionStatus.COMPLETED,
                OutcomeStatus.INFORMATIONAL,
                1,
                (logical_id,),
            )
        ],
        evidence=[item],
    )
    payload_text = json.dumps(report.to_dict(redact=redact))
    standalone_text = json.dumps(serialize_finding(finding, share_safe=redact))
    for canary in canaries:
        assert canary not in payload_text
        assert canary not in standalone_text


@pytest.mark.parametrize("share_safe", [False, True])
def test_dynamic_network_dictionary_keys_are_validated_and_collision_safe(share_safe):
    routing = serialize_command_result(
        [],
        {
            "tcp_443_errors": {
                "1.1.1.1": "expected bounded collector detail",
                "hostname=private-router.internal": "hostname-key-secret",
                "<field-1>": "collision-secret",
            }
        },
        category="routing",
        share_safe=share_safe,
    )
    errors = routing["data"]["tcp_443_errors"]
    assert isinstance(errors, dict)
    assert errors["1.1.1.1"] == "<redacted>"
    assert set(errors) == {"1.1.1.1", "<field-2>", "<field-3>"}
    routing_text = json.dumps(routing)
    for canary in (
        "hostname=private-router.internal",
        "hostname-key-secret",
        "collision-secret",
    ):
        assert canary not in routing_text

    ports = serialize_command_result(
        [],
        {
            "host": "family-router.internal",
            "ports": {
                "80": {
                    "open": True,
                    "state": "open",
                    "error": None,
                    "service": "http",
                    "response_ms": 3,
                },
                "080": {"open": True, "password=hunter2": "port-key-secret"},
                "password=hunter2": {"open": False, "state": "closed"},
            },
            "open": [80],
        },
        category="ports",
        share_safe=share_safe,
    )
    port_results = ports["data"]["ports"]
    assert isinstance(port_results, dict)
    assert port_results["80"] == {
        "open": True,
        "state": "open",
        "error": None,
        "service": "http",
        "response_ms": 3,
    }
    ports_text = json.dumps(ports)
    for canary in ('"080"', "password=hunter2", "port-key-secret"):
        assert canary not in ports_text


@pytest.mark.parametrize("share_safe", [False, True])
@pytest.mark.parametrize(
    ("category", "data", "message"),
    [
        ("routing", {"has_default_route": "password=hunter2"}, "has_default_route"),
        ("routing", {"duration_ms": "recovery-key=abc"}, "duration_ms"),
        ("dns", {"resolvers": ["family-router.local"]}, "resolver"),
        (
            "dns",
            {
                "answers": [
                    {
                        "resolver": "1.1.1.1",
                        "domain": "example.com",
                        "addresses": ["192.0.2.1"],
                        "blocked": "password=hunter2",
                        "response_ms": 1,
                    }
                ]
            },
            "blocked",
        ),
        ("wifi", {"connected": "password=hunter2"}, "connected"),
        ("wifi", {"security": "family-mac.local"}, "security"),
        ("lan", {"arp_status": "password=hunter2"}, "arp_status"),
        (
            "lan",
            {
                "arp": [
                    {
                        "hostname": "router",
                        "ip": "192.168.1.1",
                        "mac": "aa:bb:cc:dd:ee:fe",
                        "ifindex": "recovery-key=abc",
                    }
                ]
            },
            "ifindex",
        ),
        ("mdns", {"raw_count": "password=hunter2"}, "raw_count"),
        (
            "mdns",
            {"services": [{"type": "_password-hunter2._tcp"}]},
            "service type",
        ),
        (
            "ports",
            {"host": "192.168.1.1", "ports": {"80": {"open": "password=hunter2"}}},
            "open",
        ),
        (
            "gateway_ports",
            {"host": "192.168.1.1", "ports": {"443": {"state": "family-mac.local"}}},
            "state",
        ),
    ],
)
def test_classified_section_leaves_require_their_semantic_runtime_types(
    share_safe: bool,
    category: str,
    data: dict,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        serialize_command_result([], data, category=category, share_safe=share_safe)


@pytest.mark.parametrize("redact", [False, True])
def test_report_and_evidence_revalidate_classified_payloads_at_export(redact: bool) -> None:
    report = Report(
        "host",
        OSInfo("Linux", "test", "x86_64"),
        "2026-08-16T00:00:00+00:00",
        data={"routing": {"has_default_route": "password=hunter2"}},
    )
    with pytest.raises(TypeError, match="has_default_route"):
        report.to_dict(redact=redact)

    item = Evidence(
        "evidence.routing.observation",
        evidence_kind_for("routing"),
        "netdiag.check.routing",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.routing_legacy",
        datetime(2026, 8, 16, tzinfo=timezone.utc),
        1,
        {"has_default_route": True},
    )
    assert isinstance(item.payload, dict)
    item.payload["has_default_route"] = "password=hunter2"
    report = Report(
        "host",
        OSInfo("Linux", "test", "x86_64"),
        "2026-08-16T00:00:00+00:00",
        evidence=[item],
    )
    with pytest.raises(TypeError, match="has_default_route"):
        report.to_dict(redact=redact)


def test_passive_routing_truth_fields_survive_registered_serialization() -> None:
    payload = serialize_command_result(
        [],
        {
            "has_default_route": True,
            "network_probes": False,
            "connectivity_status": "not_run",
        },
        category="routing",
        share_safe=True,
    )
    assert payload["data"] == {
        "has_default_route": True,
        "network_probes": False,
        "connectivity_status": "not_run",
    }


def test_registered_finding_constructor_bypass_is_rejected_before_rendering():
    bypass = Finding(
        Severity.INFO,
        "wifi",
        "unsafe",
        "unsafe",
        code="NDG.WIFI.CONNECTED",
        status=OutcomeStatus.INFORMATIONAL,
        confidence=Confidence(ConfidenceLevel.LOW, "password=hunter2"),
        parameters={"ssid": "hunter2", "summary": "password=hunter2"},
    )
    with pytest.raises(TypeError, match="unclassified template parameter"):
        serialize_finding(bypass, share_safe=True)


def test_registered_finding_cannot_override_catalog_parameter_sensitivity():
    bypass = Finding(
        Severity.INFO,
        "wifi",
        "unsafe",
        "unsafe",
        code="NDG.WIFI.CONNECTED",
        status=OutcomeStatus.INFORMATIONAL,
        parameters={
            "ssid": DiagnosticValue("hunter2", Sensitivity.PUBLIC),
            "summary": DiagnosticValue("password=hunter2", Sensitivity.PUBLIC),
        },
    )
    with pytest.raises(ValueError, match="ssid must use device_identifier sensitivity"):
        serialize_finding(bypass, share_safe=True)


def test_catalog_rejects_unreviewed_template_parameters():
    with pytest.raises(ValueError, match="no sensitivity classification"):
        make_finding(
            "NDG.WIFI.NOT_CONNECTED",
            Severity.INFO,
            OutcomeStatus.NOT_TESTED,
            parameters={"password": "hunter2"},
        )


def test_legacy_finding_prose_is_withheld_in_share_safe_output():
    finding = Finding(
        Severity.INFO,
        "wifi",
        "Connected to family-secret",
        "password=hunter2",
    )
    payload = serialize_finding(finding, share_safe=True)
    assert "family-secret" not in json.dumps(payload)
    assert "hunter2" not in json.dumps(payload)
    assert payload["title"] == "Unstructured diagnostic finding withheld"


def test_empty_and_all_not_run_reports_do_not_claim_health():
    empty = Report("host", OSInfo("Darwin", "test", "arm64"), "2026-08-16T00:00:00Z")
    empty_payload = empty.to_dict(redact=True)
    assert empty_payload["status"] == "not_run"
    assert empty_payload["outcome"] == "not_tested"
    assert empty_payload["coverage"]["status"] == "none"
    assert "healthy" not in empty_payload["assessment"].lower()

    not_run = Report(
        "host",
        OSInfo("Linux", "test", "x86_64"),
        "2026-08-16T00:00:00Z",
        checks=[
            CheckRecord(
                "netdiag.check.wifi",
                "wifi",
                ExecutionStatus.NOT_RUN,
                OutcomeStatus.PERMISSION_DENIED,
                0,
            )
        ],
    ).to_dict(redact=True)
    assert not_run["status"] == "not_run"
    assert not_run["outcome"] == "permission_denied"
    assert not_run["coverage"]["not_run"] == 1


def test_partial_execution_is_separate_from_diagnostic_outcome():
    report = Report(
        "host",
        OSInfo("Linux", "test", "x86_64"),
        "2026-08-16T00:00:00Z",
        findings=[
            make_finding(
                "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={"target": "1.1.1.1"},
            )
        ],
        checks=[
            CheckRecord(
                "netdiag.check.routing",
                "routing",
                ExecutionStatus.COMPLETED,
                OutcomeStatus.HEALTHY,
                1,
            ),
            CheckRecord(
                "netdiag.check.dns",
                "dns",
                ExecutionStatus.FAILED,
                OutcomeStatus.INCONCLUSIVE,
                1,
            ),
        ],
    )
    payload = report.to_dict(redact=True)
    _assert_lightweight_report_11_contract(payload)
    assert payload["status"] == "partial"
    assert payload["coverage"]["status"] == "partial"
    assert payload["outcome"] == "inconclusive"
    assert payload["severity"] == "ok"


def test_cancelled_report_retains_truthful_execution_and_outcome_states():
    report = Report(
        "host",
        OSInfo("Darwin", "test", "arm64"),
        "2026-08-16T00:00:00Z",
        checks=[
            CheckRecord(
                "netdiag.check.routing",
                "routing",
                ExecutionStatus.CANCELLED,
                OutcomeStatus.CANCELLED,
                1,
            )
        ],
    )
    payload = report.to_dict(redact=True)
    _assert_lightweight_report_11_contract(payload)
    assert payload["status"] == "cancelled"
    assert payload["outcome"] == "cancelled"
    assert payload["coverage"]["status"] == "none"


def test_full_scan_registers_codes_and_referential_evidence(monkeypatch):
    route = (
        [
            make_finding(
                "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={"target": "1.1.1.1"},
            )
        ],
        {"default_gateway": None},
    )
    empty = ([], {})
    with (
        patch("netdiag.scanner.detect_os", return_value=OSInfo("Darwin", "test", "arm64")),
        patch("netdiag.scanner.check_routing", return_value=route),
        patch("netdiag.scanner.check_dns", return_value=empty),
        patch("netdiag.scanner.check_wifi", return_value=empty),
        patch("netdiag.scanner.scan_lan", return_value=empty),
    ):
        report = run_full_scan(mdns=False)
    payload = report.to_dict(redact=True)
    assert len(payload["checks"]) == 4
    assert len(payload["evidence"]) == 4
    evidence_ids = {item["evidence_id"] for item in payload["evidence"]}
    for finding in payload["findings"]:
        assert FINDING_REGISTRY.require(finding["code"])
        assert set(finding["evidence_refs"]) <= evidence_ids
        assert set(finding["confidence"]["evidence_refs"]) <= evidence_ids


def test_unexpected_collector_error_is_bounded_and_does_not_copy_exception_text():
    family_error = type("FamilyMacHunter2Error", (RuntimeError,), {})
    empty = ([], {})
    with (
        patch("netdiag.scanner.detect_os", return_value=OSInfo("Darwin", "test", "arm64")),
        patch(
            "netdiag.scanner.check_routing",
            side_effect=family_error("password=hunter2 hostname=family-mac.local"),
        ),
        patch("netdiag.scanner.check_dns", return_value=empty),
        patch("netdiag.scanner.check_wifi", return_value=empty),
        patch("netdiag.scanner.scan_lan", return_value=empty),
    ):
        report = run_full_scan(mdns=False)
    raw = json.dumps(report.to_dict())
    shared = json.dumps(report.to_dict(redact=True))
    assert "hunter2" not in raw + shared
    assert "family-mac.local" not in raw + shared
    assert "FamilyMacHunter2Error" not in raw + shared
    error = report.data["routing"]["error"]
    assert error["type"] == "UnexpectedError"
    assert error["message"] == "Unexpected collector error"
    assert len(error["message"]) <= 1024


def test_product_sources_do_not_emit_unregistered_bare_findings():
    root = Path(__file__).parents[1]
    product_files = [
        *sorted((root / "netdiag" / "checks").glob("*.py")),
        root / "netdiag" / "scanner.py",
    ]
    offenders: list[str] = []
    for path in product_files:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Finding"
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_schema_artifact_describes_the_emitted_required_contract():
    schema_path = Path(__file__).parents[1] / "netdiag" / "schemas" / "report-1.1.schema.json"
    schema = json.loads(schema_path.read_text())
    payload = _report_with_canaries().to_dict(redact=True)
    _assert_lightweight_report_11_contract(payload)
    assert schema["properties"]["schema_version"]["const"] == "1.1"
    assert set(schema["required"]) <= payload.keys()
    assert set(schema["$defs"]["finding"]["required"]) <= payload["findings"][0].keys()
    assert set(schema["$defs"]["check"]["required"]) <= payload["checks"][0].keys()
    assert set(schema["$defs"]["evidence"]["required"]) <= payload["evidence"][0].keys()
