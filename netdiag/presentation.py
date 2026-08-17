"""One versioned, structural serialization boundary for CLI and UI reports."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import cast

from netdiag import __version__
from netdiag.catalog.findings import (
    FINDING_REGISTRY,
    finding_parameter_names,
    validate_finding_parameter_value,
)
from netdiag.core.access import AccessPrerequisite
from netdiag.core.evidence import ErrorDetail, Evidence
from netdiag.core.redaction import (
    RedactionPolicy,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.remediation import ActionAttempt
from netdiag.core.status import OutcomeStatus, Sensitivity
from netdiag.core.values import (
    DiagnosticValue,
    JsonValue,
    validate_json_value,
    validate_platform_identity,
)
from netdiag.models import CheckRecord, CoverageStatus, Finding, Report, worst_severity
from netdiag.platform import OSInfo

SCHEMA_VERSION = "1.1"


# Explicit legacy compatibility classifications. Share-safe export treats every
# unlisted leaf as POTENTIAL_SECRET. Paths are relative to one section payload.
_SECTION_CLASSIFICATIONS: dict[str, dict[str, Sensitivity]] = {
    "routing": {
        "/default_gateway": Sensitivity.NETWORK_ADDRESS,
        "/default_interface": Sensitivity.DEVICE_IDENTIFIER,
        "/has_default_route": Sensitivity.PUBLIC,
        "/network_probes": Sensitivity.PUBLIC,
        "/collector_status": Sensitivity.PUBLIC,
        "/connectivity_status": Sensitivity.PUBLIC,
        "/interfaces/*/name": Sensitivity.DEVICE_IDENTIFIER,
        "/interfaces/*/addresses/*": Sensitivity.NETWORK_ADDRESS,
        "/interfaces/*/networks/*": Sensitivity.NETWORK_ADDRESS,
        "/interfaces/*/state": Sensitivity.PUBLIC,
        "/gateway_ping/ok": Sensitivity.PUBLIC,
        "/gateway_ping/output": Sensitivity.POTENTIAL_SECRET,
        "/ping_1.1.1.1": Sensitivity.PUBLIC,
        "/ping_8.8.8.8": Sensitivity.PUBLIC,
        "/tcp_443": Sensitivity.PUBLIC,
        "/tcp_443_target": Sensitivity.NETWORK_ADDRESS,
        "/tcp_443_errors/*": Sensitivity.POTENTIAL_SECRET,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "dns": {
        "/resolvers/*": Sensitivity.NETWORK_ADDRESS,
        "/queries/*/domain": Sensitivity.DEVICE_IDENTIFIER,
        "/queries/*/answers/*/resolver": Sensitivity.NETWORK_ADDRESS,
        "/queries/*/answers/*/domain": Sensitivity.DEVICE_IDENTIFIER,
        "/queries/*/answers/*/addresses/*": Sensitivity.NETWORK_ADDRESS,
        "/queries/*/answers/*/error": Sensitivity.POTENTIAL_SECRET,
        "/queries/*/answers/*/blocked": Sensitivity.PUBLIC,
        "/queries/*/answers/*/response_ms": Sensitivity.PUBLIC,
        "/domain": Sensitivity.DEVICE_IDENTIFIER,
        "/answers/*/resolver": Sensitivity.NETWORK_ADDRESS,
        "/answers/*/domain": Sensitivity.DEVICE_IDENTIFIER,
        "/answers/*/addresses/*": Sensitivity.NETWORK_ADDRESS,
        "/answers/*/error": Sensitivity.POTENTIAL_SECRET,
        "/answers/*/blocked": Sensitivity.PUBLIC,
        "/answers/*/response_ms": Sensitivity.PUBLIC,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "wifi": {
        "/connected": Sensitivity.PUBLIC,
        "/ssid": Sensitivity.DEVICE_IDENTIFIER,
        "/bssid": Sensitivity.DEVICE_IDENTIFIER,
        "/interface": Sensitivity.DEVICE_IDENTIFIER,
        "/rssi": Sensitivity.PUBLIC,
        "/signal_quality_percent": Sensitivity.PUBLIC,
        "/channel": Sensitivity.PUBLIC,
        "/tx_rate": Sensitivity.PUBLIC,
        "/band": Sensitivity.PUBLIC,
        "/security": Sensitivity.PUBLIC,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "lan": {
        "/default_interface": Sensitivity.DEVICE_IDENTIFIER,
        "/network": Sensitivity.NETWORK_ADDRESS,
        "/networks/*": Sensitivity.NETWORK_ADDRESS,
        "/arp_source": Sensitivity.PUBLIC,
        "/arp_status": Sensitivity.PUBLIC,
        "/arp_detail": Sensitivity.POTENTIAL_SECRET,
        "/arp/*/hostname": Sensitivity.DEVICE_IDENTIFIER,
        "/arp/*/ip": Sensitivity.NETWORK_ADDRESS,
        "/arp/*/mac": Sensitivity.DEVICE_IDENTIFIER,
        "/arp/*/ifindex": Sensitivity.PUBLIC,
        "/ping_alive/*": Sensitivity.NETWORK_ADDRESS,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "mdns": {
        "/services/*/type": Sensitivity.DEVICE_IDENTIFIER,
        "/services/*/instance": Sensitivity.DEVICE_IDENTIFIER,
        "/raw_count": Sensitivity.PUBLIC,
        "/unique_count": Sensitivity.PUBLIC,
        "/collector_status": Sensitivity.PUBLIC,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "ports": {
        "/host": Sensitivity.DEVICE_IDENTIFIER,
        "/ports/*/open": Sensitivity.PUBLIC,
        "/ports/*/state": Sensitivity.PUBLIC,
        "/ports/*/error": Sensitivity.POTENTIAL_SECRET,
        "/ports/*/service": Sensitivity.PUBLIC,
        "/ports/*/response_ms": Sensitivity.PUBLIC,
        "/open/*": Sensitivity.PUBLIC,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
    "gateway_ports": {
        "/host": Sensitivity.DEVICE_IDENTIFIER,
        "/ports/*/open": Sensitivity.PUBLIC,
        "/ports/*/state": Sensitivity.PUBLIC,
        "/ports/*/error": Sensitivity.POTENTIAL_SECRET,
        "/ports/*/service": Sensitivity.PUBLIC,
        "/ports/*/response_ms": Sensitivity.PUBLIC,
        "/open/*": Sensitivity.PUBLIC,
        "/duration_ms": Sensitivity.PUBLIC,
        "/error/code": Sensitivity.POTENTIAL_SECRET,
        "/error/type": Sensitivity.POTENTIAL_SECRET,
        "/error/message": Sensitivity.POTENTIAL_SECRET,
        "/error/retryable": Sensitivity.PUBLIC,
        "/error/native_exit_code": Sensitivity.PUBLIC,
    },
}

_EVIDENCE_KIND_BY_CATEGORY = {
    category: f"netdiag.evidence.{category}.legacy_snapshot"
    for category in _SECTION_CLASSIFICATIONS
}


def serialize_report(report: Report, *, share_safe: bool = False) -> dict[str, JsonValue]:
    """Serialize schema 1.1 without mutating source evidence.

    Share-safe mode has a fail-closed default for legacy leaves. Only explicit
    structural classifications and typed ``DiagnosticValue`` wrappers can emit
    content. Finding text is rendered from transformed parameters afterwards.
    """

    access_prerequisites, remediation, evidence_aliases = _validate_report_shapes(report)
    _validate_evidence_catalog(report.evidence)
    report_id = report.report_id
    intermediate: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "report_id": report_id,
        "hostname": report.hostname,
        "os": {
            "system": report.os.system,
            "release": report.os.release,
            "machine": report.os.machine,
        },
        "started_at": report.started_at,
        "duration_ms": report.duration_ms,
        "status": report.execution_status.value,
        "outcome": report.outcome_status.value,
        "assessment": _assessment(report),
        "severity": report.severity,
        "coverage": report.coverage,
        "findings": [
            _finding_intermediate(item, index, evidence_aliases=evidence_aliases)
            for index, item in enumerate(report.findings)
        ],
        "checks": [_check_intermediate(item, evidence_aliases) for item in report.checks],
        "evidence": [
            _evidence_intermediate(item, evidence_aliases[item.evidence_id])
            for item in report.evidence
        ],
        "access_prerequisites": access_prerequisites,
        "remediation": remediation,
        "data": report.data,
        "redacted": share_safe,
    }
    sensitivity_map = _report_sensitivity_map(
        report,
        share_safe=share_safe,
        remediation=remediation,
    )
    serialized = serialize_structured(
        intermediate,
        policy=RedactionPolicy.share_safe() if share_safe else RedactionPolicy.raw(),
        sensitivity_map=sensitivity_map,
    )
    assert isinstance(serialized, dict)
    findings = serialized.get("findings")
    assert isinstance(findings, list)
    serialized["findings"] = [
        _render_serialized_finding(item, share_safe=share_safe) for item in findings
    ]
    return cast(dict[str, JsonValue], serialized)


def serialize_finding(
    finding: Finding,
    *,
    share_safe: bool = False,
) -> dict[str, JsonValue]:
    """Serialize one finding with the same safe prose rules as a full report."""

    intermediate = {"findings": [_finding_intermediate(finding, 0)]}
    pointer_map = _base_pointer_map()
    _add_finding_parameter_pointers(pointer_map, finding, 0)
    default = Sensitivity.POTENTIAL_SECRET
    serialized = serialize_structured(
        intermediate,
        policy=RedactionPolicy.share_safe() if share_safe else RedactionPolicy.raw(),
        sensitivity_map=StructuralSensitivityMap.from_json_pointers(
            pointer_map,
            default_leaf_sensitivity=default,
        ),
    )
    assert isinstance(serialized, dict)
    items = serialized["findings"]
    assert isinstance(items, list) and isinstance(items[0], dict)
    return _render_serialized_finding(items[0], share_safe=share_safe)


def serialize_command_result(
    findings: list[Finding],
    data: dict,
    *,
    category: str,
    share_safe: bool = False,
) -> dict[str, JsonValue]:
    """Build an additive schema 1.1 envelope for one legacy CLI subcommand."""

    finding_payloads = [serialize_finding(item, share_safe=share_safe) for item in findings]
    data_payload = _serialize_section_data(category, data, share_safe=share_safe)
    statuses = {item.status for item in findings}
    if not findings or statuses == {OutcomeStatus.INFORMATIONAL}:
        outcome = OutcomeStatus.INCONCLUSIVE
    elif statuses <= {OutcomeStatus.INFORMATIONAL, OutcomeStatus.UNSUPPORTED}:
        outcome = OutcomeStatus.UNSUPPORTED
    elif statuses <= {OutcomeStatus.INFORMATIONAL, OutcomeStatus.NOT_TESTED}:
        outcome = OutcomeStatus.NOT_TESTED
    else:
        outcome = _outcome_from_findings(findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "status": "completed",
        "outcome": outcome.value,
        "coverage": {
            "status": CoverageStatus.COMPLETE.value,
            "planned": 1,
            "completed": 1,
            "partial": 0,
            "failed": 0,
            "cancelled": 0,
            "not_run": 0,
        },
        "severity": worst_severity(findings).value,
        "findings": finding_payloads,
        "data": data_payload,
        "redacted": share_safe,
    }


def evidence_kind_for(category: str) -> str:
    """Return the allowlisted legacy evidence kind for a report section."""

    try:
        return _EVIDENCE_KIND_BY_CATEGORY[category]
    except KeyError as exc:
        raise ValueError(f"no registered legacy evidence classification for {category}") from exc


def _finding_intermediate(
    finding: Finding,
    index: int,
    *,
    evidence_aliases: dict[str, str] | None = None,
) -> dict[str, object]:
    finding.__post_init__()
    finding.confidence.__post_init__()
    if finding.code is not None:
        expected_names = finding_parameter_names(finding.code)
        if set(finding.parameters) != expected_names:
            raise ValueError(
                f"{finding.code} parameters must exactly match its registered template"
            )
        for name, value in finding.parameters.items():
            if not isinstance(value, DiagnosticValue):
                raise TypeError(
                    f"{finding.code} contains an unclassified template parameter; "
                    "construct product findings through the registered catalog"
                )
            validate_finding_parameter_value(finding.code, name, value)
    # Confidence rationale is presentation prose too. Do not trust arbitrary
    # adapter strings: registered findings get deterministic safe wording and
    # legacy callers get a conservative compatibility explanation.
    rationale = (
        f"Registered diagnostic rule {finding.code} matched the referenced evidence."
        if finding.code is not None
        else "Legacy finding confidence is not evidence-backed."
    )
    if evidence_aliases is None:
        evidence_refs = tuple("<redacted>" for _ in finding.evidence_refs)
        confidence_refs = tuple("<redacted>" for _ in finding.confidence.evidence_refs)
    else:
        evidence_refs = tuple(evidence_aliases[ref] for ref in finding.evidence_refs)
        confidence_refs = tuple(evidence_aliases[ref] for ref in finding.confidence.evidence_refs)
    confidence = {
        "level": finding.confidence.level.value,
        "rationale": rationale,
        "evidence_refs": confidence_refs,
    }
    definition = FINDING_REGISTRY.require(finding.code) if finding.code is not None else None
    category = (
        definition.category
        if definition is not None
        else finding.category
        if evidence_aliases is not None
        else "diagnostic"
    )
    return {
        "finding_id": f"finding-{index + 1:04d}",
        "code": finding.code,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "confidence": confidence,
        "category": category,
        # These compatibility strings are never reused for a registered finding
        # after structural transformation; its template parameters are rendered.
        "title": finding.title,
        "detail": finding.detail,
        "hint": finding.hint,
        "data": finding.data,
        "evidence_refs": evidence_refs,
        "remediation_refs": tuple("<redacted>" for _ in finding.remediation_refs),
        "_parameters": finding.parameters,
        "_structured": finding.code is not None,
    }


def _render_serialized_finding(
    value: JsonValue,
    *,
    share_safe: bool,
) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise TypeError("serialized finding must be an object")
    structured = value.pop("_structured", False)
    parameters = value.pop("_parameters", {})
    if structured:
        code = value.get("code")
        if not isinstance(code, str):
            raise ValueError("structured finding is missing its registered code")
        definition = FINDING_REGISTRY.require(code)
        if not isinstance(parameters, dict):
            raise TypeError(f"{code} parameters must serialize as an object")
        try:
            value["title"] = definition.title_template.format_map(parameters)
            value["detail"] = definition.detail_template.format_map(parameters)
            value["hint"] = (
                definition.hint_template.format_map(parameters) if definition.hint_template else ""
            )
        except KeyError as exc:
            raise ValueError(f"{code} is missing rendered parameter {exc.args[0]}") from exc
    elif share_safe:
        category = value.get("category")
        safe_category = category if isinstance(category, str) else "diagnostic"
        value["title"] = f"Unstructured {safe_category} finding withheld"
        value["detail"] = "Details are unavailable in a share-safe export."
        value["hint"] = ""
    return cast(dict[str, JsonValue], value)


def _check_intermediate(
    check: CheckRecord,
    evidence_aliases: dict[str, str],
) -> dict[str, object]:
    return {
        "check_id": f"netdiag.check.{check.category}",
        "category": check.category,
        "execution_status": check.execution_status.value,
        "outcome_status": check.outcome_status.value,
        "duration_ms": check.duration_ms,
        "evidence_refs": tuple(evidence_aliases[ref] for ref in check.evidence_refs),
        "error": check.error,
    }


def _evidence_intermediate(
    evidence: Evidence[object],
    export_id: str,
) -> dict[str, object]:
    payload = evidence._payload_value()
    return {
        "evidence_id": export_id,
        "kind": evidence.kind,
        "check_id": evidence.check_id,
        "status": evidence.status.value,
        "source": evidence.source,
        "observed_at": evidence.observed_at,
        "duration_ms": evidence.duration_ms,
        "payload": payload,
        "error": evidence.error,
        "sensitivity": evidence.sensitivity.value,
    }


def _validate_evidence_catalog(evidence: list[Evidence[object]]) -> None:
    allowed = set(_EVIDENCE_KIND_BY_CATEGORY.values())
    for item in evidence:
        item.__post_init__()
        if item.duration_ms > _MAX_DURATION_MS:
            raise ValueError("evidence duration_ms exceeds the report bound")
        if item.kind not in allowed:
            raise ValueError(f"evidence kind has no export classification: {item.kind}")
        category = _category_for_evidence_kind(item.kind)
        if item.check_id != f"netdiag.check.{category}":
            raise ValueError("evidence check identifier does not match its registered kind")
        if item.source != f"netdiag.source.{category}_legacy":
            raise ValueError("evidence source does not match its registered kind")
        payload = item._payload_value()
        if payload is not None and not isinstance(payload, dict):
            raise ValueError(f"legacy evidence {item.kind} must use an object payload or null")
        if isinstance(payload, dict):
            _validate_section_data(category, payload)


def _validate_report_shapes(
    report: Report,
) -> tuple[list[AccessPrerequisite], dict[str, object], dict[str, str]]:
    """Reject runtime shape confusion before any public path can preserve it.

    Report remains mutable for the legacy scanner, so construction-time typing
    alone cannot protect the export boundary.  Remediation attempts cross that
    boundary only through their independently fail-closed audit serializer.
    """

    if type(report.hostname) is not str or not report.hostname or len(report.hostname) > 255:
        raise TypeError("report hostname must be a non-empty bounded string")
    if any(ord(character) < 32 or ord(character) == 127 for character in report.hostname):
        raise ValueError("report hostname contains control characters")
    if type(report.os) is not OSInfo:
        raise TypeError("report os must be an OSInfo instance")
    report.os.__post_init__()
    validate_platform_identity(report.os.system, report.os.release, report.os.machine)
    if type(report.started_at) is not str or len(report.started_at) > 64:
        raise TypeError("report started_at must be a bounded ISO timestamp")
    try:
        started_at = datetime.fromisoformat(report.started_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("report started_at must be an ISO timestamp") from exc
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise ValueError("report started_at must include a timezone")
    if type(report.duration_ms) is not int or not 0 <= report.duration_ms <= 86_400_000:
        raise TypeError("report duration_ms must be a non-negative bounded integer")

    if not isinstance(report.findings, list) or any(
        type(item) is not Finding for item in report.findings
    ):
        raise TypeError("report findings must be a list of Finding instances")
    for finding in report.findings:
        if not isinstance(finding.data, dict):
            raise TypeError("finding data must be a JSON object")
        validate_json_value(finding.data)
        if finding.code is not None:
            definition = FINDING_REGISTRY.require(finding.code)
            if finding.category != definition.category:
                raise ValueError("registered finding category does not match its catalog entry")
        elif finding.category not in {item.category for item in FINDING_REGISTRY}:
            raise ValueError("legacy finding category is not registered for report export")

    if not isinstance(report.data, dict):
        raise TypeError("report data must be a JSON object")
    validate_json_value(report.data)
    for section, section_data in report.data.items():
        category = "routing" if section == "route" else section
        if category not in _SECTION_CLASSIFICATIONS:
            continue
        if not isinstance(section_data, dict):
            raise TypeError(f"report {section} section must be a JSON object")
        _validate_section_data(category, section_data)
    if not isinstance(report.checks, list) or any(
        type(item) is not CheckRecord for item in report.checks
    ):
        raise TypeError("report checks must be a list of CheckRecord instances")
    if not isinstance(report.evidence, list) or any(
        type(item) is not Evidence for item in report.evidence
    ):
        raise TypeError("report evidence must be a list of Evidence instances")
    evidence_ids = {item.evidence_id for item in report.evidence}
    if len(evidence_ids) != len(report.evidence):
        raise ValueError("report evidence identifiers must be unique")
    for finding in report.findings:
        if not set(finding.evidence_refs) <= evidence_ids:
            raise ValueError("finding references evidence outside this report")
        if not set(finding.confidence.evidence_refs) <= evidence_ids:
            raise ValueError("finding confidence references evidence outside this report")
    for check in report.checks:
        check.__post_init__()
        if check.duration_ms > _MAX_DURATION_MS:
            raise ValueError("check duration_ms exceeds the report bound")
        if check.error is not None:
            if type(check.error) is not ErrorDetail:
                raise TypeError("check error must be an ErrorDetail or None")
            check.error.__post_init__()
        if check.category not in _SECTION_CLASSIFICATIONS:
            raise ValueError("check category is not registered for report export")
        if check.check_id != f"netdiag.check.{check.category}":
            raise ValueError("check identifier does not match its registered category")
        if not set(check.evidence_refs) <= evidence_ids:
            raise ValueError("check references evidence outside this report")
    if not isinstance(report.access_prerequisites, list) or any(
        type(item) is not AccessPrerequisite for item in report.access_prerequisites
    ):
        raise TypeError(
            "report access_prerequisites must be a list of AccessPrerequisite instances"
        )
    for prerequisite in report.access_prerequisites:
        prerequisite.__post_init__()

    remediation = report.remediation
    if not isinstance(remediation, dict) or set(remediation) != {
        "available_actions",
        "attempts",
    }:
        raise TypeError("report remediation must contain only available_actions and attempts")
    available_actions = remediation["available_actions"]
    attempts = remediation["attempts"]
    if not isinstance(available_actions, list) or any(
        not isinstance(action_id, str) for action_id in available_actions
    ):
        raise TypeError("available_actions must be a list of registered action identifiers")
    if available_actions or attempts:
        raise ValueError(
            "live report remediation export is disabled until a registry-bound adapter is reviewed"
        )
    if len(set(available_actions)) != len(available_actions):
        raise ValueError("available_actions must contain unique identifiers")
    for finding in report.findings:
        if not set(finding.remediation_refs) <= set(available_actions):
            raise ValueError("finding references remediation outside this report")
    if not isinstance(attempts, list) or any(
        not isinstance(attempt, ActionAttempt) for attempt in attempts
    ):
        raise TypeError("remediation attempts must be a list of ActionAttempt instances")

    # ActionAttempt owns the audit-safe classification of handler-controlled
    # prose.  Never traverse a caller-provided attempt-shaped dictionary here.
    safe_attempts = [attempt.to_dict() for attempt in attempts]
    evidence_aliases = {
        item.evidence_id: f"evidence-{index + 1:04d}" for index, item in enumerate(report.evidence)
    }
    return (
        list(report.access_prerequisites),
        {
            "available_actions": list(available_actions),
            "attempts": safe_attempts,
        },
        evidence_aliases,
    )


def _report_sensitivity_map(
    report: Report,
    *,
    share_safe: bool,
    remediation: dict[str, object],
) -> StructuralSensitivityMap:
    pointers = _base_pointer_map()
    pointers["/hostname"] = Sensitivity.DEVICE_IDENTIFIER
    for index, finding in enumerate(report.findings):
        _add_finding_parameter_pointers(pointers, finding, index)
    for section, rules in _SECTION_CLASSIFICATIONS.items():
        for suffix, sensitivity in rules.items():
            pointers[f"/data/{section}{suffix}"] = sensitivity
            if section == "routing":
                # v0.2 callers sometimes used the singular compatibility key.
                pointers[f"/data/route{suffix}"] = sensitivity
        section_data = report.data.get(section)
        if isinstance(section_data, dict):
            _expand_dynamic_dictionary_keys(
                pointers,
                f"/data/{section}",
                section,
                section_data,
            )
            _allow_empty_optional_values(pointers, f"/data/{section}", section, section_data)
        if section == "routing":
            legacy_route = report.data.get("route")
            if isinstance(legacy_route, dict):
                _expand_dynamic_dictionary_keys(
                    pointers,
                    "/data/route",
                    section,
                    legacy_route,
                )
                _allow_empty_optional_values(pointers, "/data/route", section, legacy_route)
    for index, evidence in enumerate(report.evidence):
        category = _category_for_evidence_kind(evidence.kind)
        for suffix, sensitivity in _SECTION_CLASSIFICATIONS[category].items():
            pointers[f"/evidence/{index}/payload{suffix}"] = sensitivity
        evidence_payload = evidence._payload_value()
        if evidence_payload is None:
            pointers[f"/evidence/{index}/payload"] = Sensitivity.PUBLIC
        elif isinstance(evidence_payload, dict):
            _expand_dynamic_dictionary_keys(
                pointers,
                f"/evidence/{index}/payload",
                category,
                evidence_payload,
            )
            _allow_empty_optional_values(
                pointers,
                f"/evidence/{index}/payload",
                category,
                evidence_payload,
            )
    attempts = remediation["attempts"]
    assert isinstance(attempts, list)
    for index, attempt in enumerate(attempts):
        _declare_reviewed_json_tree(
            pointers,
            f"/remediation/attempts/{index}",
            attempt,
        )
    default = Sensitivity.POTENTIAL_SECRET
    return StructuralSensitivityMap.from_json_pointers(
        pointers,
        default_leaf_sensitivity=default,
    )


def _base_pointer_map() -> dict[str, Sensitivity]:
    public_paths = {
        "/schema_version",
        "/tool_version",
        "/report_id",
        "/os/system",
        "/os/release",
        "/os/machine",
        "/started_at",
        "/duration_ms",
        "/status",
        "/outcome",
        "/assessment",
        "/severity",
        "/redacted",
        "/coverage/status",
        "/coverage/planned",
        "/coverage/completed",
        "/coverage/partial",
        "/coverage/failed",
        "/coverage/cancelled",
        "/coverage/not_run",
        "/data",
        "/findings/*/finding_id",
        "/findings/*/code",
        "/findings/*/severity",
        "/findings/*/status",
        "/findings/*/confidence/level",
        "/findings/*/confidence/rationale",
        "/findings/*/confidence/evidence_refs/*",
        "/findings/*/category",
        "/findings/*/data",
        "/findings/*/evidence_refs/*",
        "/findings/*/remediation_refs/*",
        "/findings/*/_parameters",
        "/findings/*/_structured",
        "/checks/*/check_id",
        "/checks/*/category",
        "/checks/*/execution_status",
        "/checks/*/outcome_status",
        "/checks/*/duration_ms",
        "/checks/*/evidence_refs/*",
        "/checks/*/error",
        "/checks/*/error/retryable",
        "/checks/*/error/native_exit_code",
        "/evidence/*/evidence_id",
        "/evidence/*/kind",
        "/evidence/*/check_id",
        "/evidence/*/status",
        "/evidence/*/source",
        "/evidence/*/observed_at",
        "/evidence/*/duration_ms",
        "/evidence/*/payload",
        "/evidence/*/error",
        "/evidence/*/error/retryable",
        "/evidence/*/error/native_exit_code",
        "/evidence/*/sensitivity",
        "/access_prerequisites/*/state",
        "/remediation/available_actions",
        "/remediation/available_actions/*",
        "/remediation/attempts",
    }
    mapping = {path: Sensitivity.PUBLIC for path in public_paths}
    mapping["/findings/*/title"] = Sensitivity.POTENTIAL_SECRET
    mapping["/findings/*/detail"] = Sensitivity.POTENTIAL_SECRET
    mapping["/findings/*/hint"] = Sensitivity.POTENTIAL_SECRET
    mapping["/access_prerequisites/*/scope"] = Sensitivity.DEVICE_IDENTIFIER
    mapping["/access_prerequisites/*/label"] = Sensitivity.POTENTIAL_SECRET
    mapping["/access_prerequisites/*/reason"] = Sensitivity.POTENTIAL_SECRET
    mapping["/checks/*/error/message"] = Sensitivity.POTENTIAL_SECRET
    mapping["/checks/*/error/code"] = Sensitivity.POTENTIAL_SECRET
    mapping["/evidence/*/error/message"] = Sensitivity.POTENTIAL_SECRET
    mapping["/evidence/*/error/code"] = Sensitivity.POTENTIAL_SECRET
    mapping["/access_prerequisites/*/prerequisite_id"] = Sensitivity.POTENTIAL_SECRET
    mapping["/access_prerequisites/*/kind"] = Sensitivity.POTENTIAL_SECRET
    mapping["/access_prerequisites/*/related_refs/*"] = Sensitivity.POTENTIAL_SECRET
    return mapping


def _declare_reviewed_json_tree(
    pointers: dict[str, Sensitivity],
    base: str,
    value: object,
) -> None:
    """Declare keys from an already audit-safe typed serializer as public."""

    if isinstance(value, dict):
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            _declare_reviewed_json_tree(pointers, f"{base}/{escaped}", child)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _declare_reviewed_json_tree(pointers, f"{base}/{index}", child)
        return
    pointers[base] = Sensitivity.PUBLIC


_MAX_DURATION_MS = 86_400_000
_MAX_OBSERVATIONS = 4096
_PORT_STATES = frozenset({"open", "closed", "filtered_or_unreachable", "unreachable"})
_PORT_SERVICES = frozenset({"?", "ssh", "dns", "http", "https", "http-alt", "https-alt"})
_WIFI_BANDS = frozenset({"2.4GHz", "5GHz", "6GHz", "5/6GHz"})
_WIFI_SECURITY = frozenset({"Open", "OWE", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "Unknown"})


def _validate_section_data(category: str, data: object) -> None:
    """Revalidate first-party legacy payload semantics before classification.

    A sensitivity label is not a runtime type.  Every leaf that can be kept or
    tokenized therefore has to prove its intended meaning here; unregistered
    keys remain fail-closed under the structural serializer.
    """

    if category not in _SECTION_CLASSIFICATIONS:
        raise ValueError(f"section category is not registered: {category}")
    if type(data) is not dict:
        raise TypeError(f"{category} data must be a JSON object")
    validate_json_value(data)
    if "duration_ms" in data:
        _bounded_int(data["duration_ms"], f"{category}.duration_ms", maximum=_MAX_DURATION_MS)
    if "error" in data:
        _validate_error_data(data["error"], f"{category}.error")

    validators = {
        "routing": _validate_routing_data,
        "dns": _validate_dns_data,
        "wifi": _validate_wifi_data,
        "lan": _validate_lan_data,
        "mdns": _validate_mdns_data,
        "ports": _validate_ports_data,
        "gateway_ports": _validate_ports_data,
    }
    validators[category](data)


def _validate_routing_data(data: dict) -> None:
    if "default_gateway" in data and data["default_gateway"] is not None:
        _canonical_ip(data["default_gateway"], "routing.default_gateway")
    if "default_interface" in data and data["default_interface"] is not None:
        _device_text(data["default_interface"], "routing.default_interface", maximum=64)
    for field in (
        "has_default_route",
        "network_probes",
        "ping_1.1.1.1",
        "ping_8.8.8.8",
        "tcp_443",
    ):
        if field in data and data[field] is not None:
            _exact_bool(data[field], f"routing.{field}")
    if "collector_status" in data and data["collector_status"] not in {"ok", "failed"}:
        raise ValueError("routing.collector_status is not a registered state")
    if "connectivity_status" in data and data["connectivity_status"] != "not_run":
        raise ValueError("routing.connectivity_status is not a registered state")

    if "interfaces" in data:
        interfaces = _bounded_list(data["interfaces"], "routing.interfaces", maximum=256)
        for index, interface in enumerate(interfaces):
            label = f"routing.interfaces[{index}]"
            if type(interface) is not dict:
                raise TypeError(f"{label} must be an object")
            if "name" in interface:
                _device_text(interface["name"], f"{label}.name", maximum=64)
            if "addresses" in interface:
                addresses = _bounded_list(interface["addresses"], f"{label}.addresses", maximum=64)
                for address in addresses:
                    _canonical_ip(address, f"{label}.addresses")
            if "networks" in interface:
                networks = _bounded_list(interface["networks"], f"{label}.networks", maximum=64)
                for network in networks:
                    _canonical_network(network, f"{label}.networks")
            if "state" in interface and interface["state"] not in {"up", "down", "unknown"}:
                raise ValueError(f"{label}.state is not a registered state")

    if "gateway_ping" in data:
        gateway_ping = data["gateway_ping"]
        if type(gateway_ping) is not dict:
            raise TypeError("routing.gateway_ping must be an object")
        if "ok" in gateway_ping and gateway_ping["ok"] is not None:
            _exact_bool(gateway_ping["ok"], "routing.gateway_ping.ok")
        if "output" in gateway_ping:
            _bounded_text(
                gateway_ping["output"],
                "routing.gateway_ping.output",
                maximum=4096,
                allow_empty=True,
            )
    if "tcp_443_target" in data and data["tcp_443_target"] is not None:
        _canonical_ip(data["tcp_443_target"], "routing.tcp_443_target")
    if "tcp_443_errors" in data:
        errors = data["tcp_443_errors"]
        if type(errors) is not dict or len(errors) > 16:
            raise TypeError("routing.tcp_443_errors must be a bounded object")
        for target, detail in errors.items():
            try:
                _canonical_ip(target, "routing.tcp_443_errors target")
            except (TypeError, ValueError):
                # Unregistered keys remain structurally redacted/tokenized.
                continue
            _bounded_text(
                detail,
                "routing.tcp_443_errors detail",
                maximum=1024,
                allow_empty=True,
            )


def _validate_dns_data(data: dict) -> None:
    if "resolvers" in data:
        resolvers = _bounded_list(data["resolvers"], "dns.resolvers", maximum=8)
        for resolver in resolvers:
            _canonical_ip(resolver, "dns.resolver")
        if len(set(resolvers)) != len(resolvers):
            raise ValueError("dns.resolvers must be unique")
    if "domain" in data:
        _canonical_dns_name(data["domain"], "dns.domain")
    if "answers" in data:
        _validate_dns_answers(data["answers"], "dns.answers")
    if "queries" in data:
        queries = _bounded_list(data["queries"], "dns.queries", maximum=64)
        for index, query in enumerate(queries):
            label = f"dns.queries[{index}]"
            if type(query) is not dict:
                raise TypeError(f"{label} must be an object")
            if "domain" in query:
                _canonical_dns_name(query["domain"], f"{label}.domain")
            if "answers" in query:
                _validate_dns_answers(query["answers"], f"{label}.answers")


def _validate_dns_answers(value: object, label: str) -> None:
    answers = _bounded_list(value, label, maximum=8)
    for index, answer in enumerate(answers):
        item_label = f"{label}[{index}]"
        if type(answer) is not dict:
            raise TypeError(f"{item_label} must be an object")
        if "resolver" in answer:
            resolver = answer["resolver"]
            if resolver != "system":
                _canonical_ip(resolver, f"{item_label}.resolver")
        if "domain" in answer:
            _canonical_dns_name(answer["domain"], f"{item_label}.domain")
        if "addresses" in answer:
            addresses = _bounded_list(answer["addresses"], f"{item_label}.addresses", maximum=256)
            for address in addresses:
                _canonical_ip(address, f"{item_label}.addresses", version=4)
        if "error" in answer and answer["error"] is not None:
            _bounded_text(answer["error"], f"{item_label}.error", maximum=1024, allow_empty=True)
        if "blocked" in answer:
            _exact_bool(answer["blocked"], f"{item_label}.blocked")
        if "response_ms" in answer and answer["response_ms"] is not None:
            _bounded_int(answer["response_ms"], f"{item_label}.response_ms", maximum=300_000)


def _validate_wifi_data(data: dict) -> None:
    if "connected" in data:
        _exact_bool(data["connected"], "wifi.connected")
    for field, maximum in (("ssid", 255), ("interface", 64)):
        if field in data and data[field] is not None:
            _device_text(data[field], f"wifi.{field}", maximum=maximum, allow_empty=False)
    if "bssid" in data and data["bssid"] is not None:
        _canonical_mac(data["bssid"], "wifi.bssid")
    if "rssi" in data and data["rssi"] is not None:
        rssi = data["rssi"]
        if isinstance(rssi, str) and re.fullmatch(r"-?(?:0|[1-9][0-9]{0,2})", rssi):
            rssi = int(rssi)
        if not isinstance(rssi, int) or isinstance(rssi, bool) or not -127 <= rssi <= 0:
            raise ValueError("wifi.rssi must be a canonical dBm value")
    if "signal_quality_percent" in data:
        _bounded_int(data["signal_quality_percent"], "wifi.signal_quality_percent", maximum=100)
    if "channel" in data and data["channel"] is not None:
        channel = data["channel"]
        if not isinstance(channel, str) or not re.fullmatch(r"[1-9][0-9]{0,2}", channel):
            raise ValueError("wifi.channel must be a canonical channel number")
        if int(channel) > 233:
            raise ValueError("wifi.channel is outside the supported range")
    if "tx_rate" in data and data["tx_rate"] is not None:
        rate = data["tx_rate"]
        if not isinstance(rate, str) or not re.fullmatch(
            r"(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,3})?", rate
        ):
            raise ValueError("wifi.tx_rate must be a canonical Mbps value")
    if "band" in data and data["band"] is not None and data["band"] not in _WIFI_BANDS:
        raise ValueError("wifi.band is not a registered band")
    if (
        "security" in data
        and data["security"] is not None
        and data["security"] not in _WIFI_SECURITY
    ):
        raise ValueError("wifi.security is not a registered security mode")


def _validate_lan_data(data: dict) -> None:
    if "default_interface" in data and data["default_interface"] is not None:
        _device_text(data["default_interface"], "lan.default_interface", maximum=64)
    if "network" in data and data["network"] is not None:
        _canonical_network(data["network"], "lan.network", version=4)
    if "networks" in data:
        networks = _bounded_list(data["networks"], "lan.networks", maximum=64)
        for network in networks:
            _canonical_network(network, "lan.networks", version=4)
    if "arp_source" in data and data["arp_source"] not in {"ip_neigh", "sysctl_rtm"}:
        raise ValueError("lan.arp_source is not a registered collector")
    if "arp_status" in data and data["arp_status"] not in {"ok", "partial", "empty", "error"}:
        raise ValueError("lan.arp_status is not a registered state")
    if "arp_detail" in data:
        _bounded_text(data["arp_detail"], "lan.arp_detail", maximum=4096, allow_empty=True)
    if "arp" in data:
        neighbors = _bounded_list(data["arp"], "lan.arp", maximum=_MAX_OBSERVATIONS)
        for index, neighbor in enumerate(neighbors):
            label = f"lan.arp[{index}]"
            if type(neighbor) is not dict:
                raise TypeError(f"{label} must be an object")
            if "hostname" in neighbor:
                _device_text(neighbor["hostname"], f"{label}.hostname", maximum=255)
            if "ip" in neighbor:
                _canonical_ip(neighbor["ip"], f"{label}.ip", version=4)
            if "mac" in neighbor:
                _canonical_mac(neighbor["mac"], f"{label}.mac", allow_incomplete=True)
            if "ifindex" in neighbor:
                _bounded_int(neighbor["ifindex"], f"{label}.ifindex", minimum=1, maximum=2**31 - 1)
    if "ping_alive" in data:
        alive = _bounded_list(data["ping_alive"], "lan.ping_alive", maximum=_MAX_OBSERVATIONS)
        for address in alive:
            _canonical_ip(address, "lan.ping_alive", version=4)
        if len(set(alive)) != len(alive):
            raise ValueError("lan.ping_alive must contain unique addresses")


def _validate_mdns_data(data: dict) -> None:
    if "services" in data:
        services = _bounded_list(data["services"], "mdns.services", maximum=256)
        from netdiag.checks.mdns_normalize import normalize_mdns_type

        for index, service in enumerate(services):
            label = f"mdns.services[{index}]"
            if type(service) is not dict:
                raise TypeError(f"{label} must be an object")
            if "type" in service:
                service_type = service["type"]
                if (
                    not isinstance(service_type, str)
                    or normalize_mdns_type(service_type) != service_type
                ):
                    raise ValueError(f"{label}.type must be a canonical DNS-SD service type")
            if "instance" in service:
                _device_text(service["instance"], f"{label}.instance", maximum=255)
    for field in ("raw_count", "unique_count"):
        if field in data:
            _bounded_int(data[field], f"mdns.{field}", maximum=256)
    if "raw_count" in data and "unique_count" in data and data["unique_count"] > data["raw_count"]:
        raise ValueError("mdns.unique_count cannot exceed raw_count")
    if "collector_status" in data and data["collector_status"] not in {
        "completed",
        "failed",
        "unsupported",
    }:
        raise ValueError("mdns.collector_status is not a registered state")


def _validate_ports_data(data: dict) -> None:
    if "host" in data:
        _network_target(data["host"], "ports.host")
    valid_keys: set[str] = set()
    if "ports" in data:
        ports = data["ports"]
        if type(ports) is not dict or len(ports) > 1024:
            raise TypeError("ports.ports must be a bounded object")
        for port, observation in ports.items():
            if not _is_valid_port_key(port):
                continue
            valid_keys.add(port)
            label = f"ports.ports[{port}]"
            if type(observation) is not dict:
                raise TypeError(f"{label} must be an object")
            if "open" in observation:
                _exact_bool(observation["open"], f"{label}.open")
            if "state" in observation and observation["state"] not in _PORT_STATES:
                raise ValueError(f"{label}.state is not a registered state")
            if "error" in observation and observation["error"] is not None:
                _bounded_text(
                    observation["error"], f"{label}.error", maximum=1024, allow_empty=True
                )
            if "service" in observation and observation["service"] not in _PORT_SERVICES:
                raise ValueError(f"{label}.service is not a registered service label")
            if "response_ms" in observation:
                _bounded_int(observation["response_ms"], f"{label}.response_ms", maximum=300_000)
    if "open" in data:
        open_ports = _bounded_list(data["open"], "ports.open", maximum=1024)
        normalized: list[str] = []
        for port in open_ports:
            number = _bounded_int(port, "ports.open", minimum=1, maximum=65535)
            normalized.append(str(number))
        if len(set(normalized)) != len(normalized):
            raise ValueError("ports.open must contain unique ports")
        if valid_keys and not set(normalized) <= valid_keys:
            raise ValueError("ports.open references a port without an observation")


def _validate_error_data(value: object, label: str) -> None:
    if type(value) is not dict:
        raise TypeError(f"{label} must be an object")
    if "code" in value:
        _bounded_text(value["code"], f"{label}.code", maximum=160)
    if "type" in value and value["type"] != "UnexpectedError":
        raise ValueError(f"{label}.type is not a registered compatibility type")
    if "message" in value:
        _bounded_text(value["message"], f"{label}.message", maximum=1024)
    if "retryable" in value:
        _exact_bool(value["retryable"], f"{label}.retryable")
    if "native_exit_code" in value and value["native_exit_code"] is not None:
        _bounded_int(
            value["native_exit_code"],
            f"{label}.native_exit_code",
            minimum=-(2**31),
            maximum=2**31 - 1,
        )


def _bounded_list(value: object, label: str, *, maximum: int) -> list:
    if type(value) is not list:
        raise TypeError(f"{label} must be a list")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds its {maximum}-item limit")
    return value


def _bounded_int(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside its supported range")
    return value


def _exact_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be a boolean")


def _bounded_text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        raise TypeError(f"{label} must be a bounded string")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValueError(f"{label} contains control characters")
    return value


def _device_text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    return _bounded_text(value, label, maximum=maximum, allow_empty=allow_empty)


def _canonical_ip(value: object, label: str, *, version: int | None = None) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be an IP address string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical IP address") from exc
    if str(address) != value or (version is not None and address.version != version):
        raise ValueError(f"{label} must be a canonical IPv{version or '4/6'} address")
    return value


def _canonical_network(value: object, label: str, *, version: int | None = None) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a network string")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical network") from exc
    if str(network) != value or (version is not None and network.version != version):
        raise ValueError(f"{label} must be a canonical network")
    return value


def _canonical_mac(value: object, label: str, *, allow_incomplete: bool = False) -> str:
    if allow_incomplete and value == "(incomplete)":
        return value
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value) is None:
        raise ValueError(f"{label} must be a canonical hardware address")
    first_octet = int(value[:2], 16)
    if value in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"} or first_octet & 1:
        raise ValueError(f"{label} must be a unicast hardware address")
    return value


def _canonical_dns_name(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a DNS name string")
    from netdiag.checks.dns import normalize_query_name

    normalized = normalize_query_name(value)
    if normalized is None or normalized != value:
        raise ValueError(f"{label} must be a canonical DNS name or IP address")
    return value


def _network_target(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a network target string")
    from netdiag.checks.dns import normalize_query_name

    if normalize_query_name(value) is None:
        raise ValueError(f"{label} must be a DNS name or IP address")
    return value


def _serialize_section_data(
    category: str,
    data: dict,
    *,
    share_safe: bool,
) -> dict[str, JsonValue]:
    _validate_section_data(category, data)
    rules = _SECTION_CLASSIFICATIONS.get(category, {})
    pointers = {f"/data{suffix}": sensitivity for suffix, sensitivity in rules.items()}
    pointers["/data"] = Sensitivity.PUBLIC
    _expand_dynamic_dictionary_keys(pointers, "/data", category, data)
    _allow_empty_optional_values(pointers, "/data", category, data)
    default = Sensitivity.POTENTIAL_SECRET
    value = serialize_structured(
        {"data": data},
        policy=RedactionPolicy.share_safe() if share_safe else RedactionPolicy.raw(),
        sensitivity_map=StructuralSensitivityMap.from_json_pointers(
            pointers,
            default_leaf_sensitivity=default,
        ),
    )
    assert isinstance(value, dict) and isinstance(value["data"], dict)
    return cast(dict[str, JsonValue], value["data"])


def _allow_empty_optional_values(
    pointers: dict[str, Sensitivity],
    prefix: str,
    category: str,
    data: dict,
) -> None:
    """Preserve truthful null/empty error fields without trusting non-empty prose."""

    if category == "dns":
        query_groups: list[tuple[str, object]] = [
            ("answers", data.get("answers")),
        ]
        queries = data.get("queries")
        if isinstance(queries, list):
            query_groups.extend(
                (f"queries/{query_index}/answers", query.get("answers"))
                for query_index, query in enumerate(queries)
                if isinstance(query, dict)
            )
        for group_path, answers in query_groups:
            if not isinstance(answers, list):
                continue
            for answer_index, answer in enumerate(answers):
                if isinstance(answer, dict) and not answer.get("error"):
                    pointers[f"{prefix}/{group_path}/{answer_index}/error"] = Sensitivity.PUBLIC
    elif category in {"ports", "gateway_ports"}:
        ports = data.get("ports")
        if isinstance(ports, dict):
            for port, observation in ports.items():
                if (
                    _is_valid_port_key(port)
                    and isinstance(observation, dict)
                    and not observation.get("error")
                ):
                    escaped_port = _json_pointer_segment(port)
                    pointers[f"{prefix}/ports/{escaped_port}/error"] = Sensitivity.PUBLIC
    elif category == "lan" and not data.get("arp_detail"):
        pointers[f"{prefix}/arp_detail"] = Sensitivity.PUBLIC


def _add_finding_parameter_pointers(
    pointers: dict[str, Sensitivity],
    finding: Finding,
    index: int,
) -> None:
    """Declare only typed parameters from this concrete registered finding."""

    for name, value in finding.parameters.items():
        if not isinstance(value, DiagnosticValue):
            continue
        segment = _json_pointer_segment(name)
        pointers[f"/findings/{index}/_parameters/{segment}"] = value.sensitivity


def _expand_dynamic_dictionary_keys(
    pointers: dict[str, Sensitivity],
    prefix: str,
    category: str,
    data: dict,
) -> None:
    """Authorize validated dynamic keys without broad wildcard key trust."""

    if category in {"ports", "gateway_ports"}:
        ports = data.get("ports")
        if isinstance(ports, dict):
            for port, observation in ports.items():
                if not _is_valid_port_key(port) or not isinstance(observation, dict):
                    continue
                escaped_port = _json_pointer_segment(port)
                pointers[f"{prefix}/ports/{escaped_port}"] = Sensitivity.PUBLIC
                field_sensitivities = {
                    "open": Sensitivity.PUBLIC,
                    "state": Sensitivity.PUBLIC,
                    "error": Sensitivity.POTENTIAL_SECRET,
                    "service": Sensitivity.PUBLIC,
                    "response_ms": Sensitivity.PUBLIC,
                }
                for field, sensitivity in field_sensitivities.items():
                    if field in observation:
                        pointers[f"{prefix}/ports/{escaped_port}/{field}"] = sensitivity

    if category == "routing":
        errors = data.get("tcp_443_errors")
        if isinstance(errors, dict):
            for target in errors:
                if not isinstance(target, str):
                    continue
                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    continue
                segment = _json_pointer_segment(target)
                pointers[f"{prefix}/tcp_443_errors/{segment}"] = Sensitivity.POTENTIAL_SECRET


def _is_valid_port_key(value: object) -> bool:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        return False
    number = int(value)
    return 1 <= number <= 65535 and str(number) == value


def _json_pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _category_for_evidence_kind(kind: str) -> str:
    for category, expected in _EVIDENCE_KIND_BY_CATEGORY.items():
        if kind == expected:
            return category
    raise ValueError(f"evidence kind has no export classification: {kind}")


def _assessment(report: Report) -> str:
    if report.outcome_status == OutcomeStatus.PERMISSION_DENIED:
        return "Required access was denied, so Lantern could not reach a health conclusion."
    if report.outcome_status == OutcomeStatus.CANCELLED:
        return "The scan was cancelled; completed results were retained."
    if report.outcome_status == OutcomeStatus.UNSUPPORTED:
        return "The planned checks are not supported on this system."
    if report.coverage.status == CoverageStatus.NONE:
        return "No diagnostic checks produced usable results."
    if report.outcome_status == OutcomeStatus.HEALTHY:
        return "No problem was detected in the completed checks."
    if report.outcome_status == OutcomeStatus.INCONCLUSIVE:
        return "Completed checks did not support a complete health conclusion."
    if report.outcome_status == OutcomeStatus.DEGRADED:
        return "One or more completed checks found degraded network behavior."
    if report.outcome_status == OutcomeStatus.FAILED:
        return "One or more completed checks found a failed network function."
    if report.outcome_status == OutcomeStatus.BLOCKED:
        return "A completed check observed behavior consistent with intentional blocking."
    return "Review the completed checks and their coverage before taking action."


def _outcome_from_findings(findings: list[Finding]) -> OutcomeStatus:
    statuses = {finding.status for finding in findings}
    for status in (
        OutcomeStatus.FAILED,
        OutcomeStatus.DEGRADED,
        OutcomeStatus.BLOCKED,
        OutcomeStatus.PERMISSION_DENIED,
        OutcomeStatus.CANCELLED,
        OutcomeStatus.INCONCLUSIVE,
    ):
        if status in statuses:
            return status
    return OutcomeStatus.HEALTHY


__all__ = [
    "SCHEMA_VERSION",
    "evidence_kind_for",
    "serialize_command_result",
    "serialize_finding",
    "serialize_report",
]
