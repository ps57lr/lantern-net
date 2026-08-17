"""Consent-bound diagnostic orchestration and legacy CLI compatibility."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeAlias

from netdiag.catalog import make_finding
from netdiag.checks.dns import check_dns
from netdiag.checks.lan import ping_sweep, scan_lan
from netdiag.checks.mdns import browse_mdns
from netdiag.checks.routing import check_routing
from netdiag.checks.wifi import check_wifi
from netdiag.core.evidence import ErrorDetail, Evidence
from netdiag.core.execution import CancellationToken, ScanPolicy
from netdiag.core.status import (
    ActivityLevel,
    ConfidenceLevel,
    ExecutionStatus,
    OutcomeStatus,
)
from netdiag.core.values import validate_json_value
from netdiag.findings import Finding, Severity, exit_code
from netdiag.models import CheckRecord, Report
from netdiag.platform import OSInfo, detect_os
from netdiag.presentation import evidence_kind_for

CollectorResult: TypeAlias = tuple[list[Finding], dict[str, Any]]
ProgressSink: TypeAlias = Callable[["ScanProgress"], None]

_GATEWAY_PORTS = [53, 80, 443, 8080, 8443]
_DIRECT_LAN_INTERFACE = re.compile(
    r"^(?:en\d+|eth\d+|eno\d+|ens\d+|enp\d+s\d+(?:f\d+)?|"
    r"wlan\d+|wlp\d+s\d+(?:f\d+)?|wlx[0-9a-f]{12})$",
    re.IGNORECASE,
)
_CHECK_FAILURE_CODES = {
    "routing": "NDG.ROUTE.CHECK_FAILED",
    "routing_connectivity": "NDG.ROUTE.CHECK_FAILED",
    "dns": "NDG.DNS.CHECK_FAILED",
    "wifi": "NDG.WIFI.CHECK_FAILED",
    "lan": "NDG.LAN.CHECK_FAILED",
    "lan_ping": "NDG.LAN.CHECK_FAILED",
    "mdns": "NDG.MDNS.CHECK_FAILED",
    "gateway_ports": "NDG.PORTS.CHECK_FAILED",
}
_PROGRESS_MODULES = frozenset(_CHECK_FAILURE_CODES)


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """One bounded event emitted at a declared module boundary."""

    module: str
    phase: str
    step: int
    total_steps: int

    def __post_init__(self) -> None:
        if self.module not in _PROGRESS_MODULES:
            raise ValueError("invalid scan progress module")
        if self.phase not in {"started", "completed", "failed", "cancelled", "not_run"}:
            raise ValueError("invalid scan progress phase")
        if (
            not isinstance(self.step, int)
            or isinstance(self.step, bool)
            or not isinstance(self.total_steps, int)
            or isinstance(self.total_steps, bool)
        ):
            raise TypeError("scan progress counters must be integers")
        if self.total_steps > 64:
            raise ValueError("scan progress plan exceeds the bounded module count")
        if not 1 <= self.step <= self.total_steps:
            raise ValueError("scan progress step is outside the declared plan")


@dataclass(frozen=True, slots=True)
class ScanCollectors:
    """Injectable seam for deterministic policy and cancellation tests."""

    detect_platform: Callable[[], OSInfo]
    routing: Callable[[OSInfo, bool], CollectorResult]
    dns: Callable[[OSInfo], CollectorResult]
    wifi: Callable[[OSInfo], CollectorResult]
    lan: Callable[[OSInfo, bool, int], CollectorResult]
    mdns: Callable[[OSInfo], CollectorResult]
    ports: Callable[[str, list[int]], CollectorResult]
    active_ping: Callable[[ipaddress.IPv4Network, int], list[str]]


def default_collectors() -> ScanCollectors:
    """Resolve adapters at call time so tests and platform plugins can replace them."""

    from netdiag.checks import ports as ports_module

    return ScanCollectors(
        detect_platform=detect_os,
        routing=lambda osinfo, probes: check_routing(osinfo, network_probes=probes),
        dns=check_dns,
        wifi=check_wifi,
        lan=lambda osinfo, do_ping, max_hosts: scan_lan(
            osinfo, do_ping=do_ping, max_hosts=max_hosts
        ),
        mdns=browse_mdns,
        ports=lambda host, ports: ports_module.scan_ports(host, ports=ports),
        active_ping=lambda network, max_hosts: ping_sweep(network, max_hosts=max_hosts),
    )


@dataclass(frozen=True, slots=True)
class _Step:
    module: str
    check_id: str
    category: str
    activity: ActivityLevel
    data_section: str
    evidence_category: str
    collect: Callable[[], CollectorResult]
    ready: Callable[[], tuple[bool, str]] = lambda: (True, "ready")


def run_policy_scan(
    policy: ScanPolicy,
    *,
    cancellation: CancellationToken | None = None,
    progress: ProgressSink | None = None,
    collectors: ScanCollectors | None = None,
    include_mdns: bool = True,
    active_requested: bool | None = None,
) -> Report:
    """Execute the complete declared plan under one immutable policy.

    Passive runs still inspect local routing, Wi-Fi state, and the neighbor
    cache, but never call a collector capable of emitting DNS, mDNS, ICMP, or
    TCP traffic. Every denied, disabled, or dependency-blocked module remains
    visible as ``NOT_RUN``/``NOT_TESTED`` so incomplete coverage cannot be
    presented as a healthy whole-run assessment.
    """

    if not isinstance(policy, ScanPolicy):
        raise TypeError("policy must be a ScanPolicy")
    token = cancellation or CancellationToken()
    adapters = collectors or default_collectors()
    osinfo = adapters.detect_platform()
    report = _new_report(osinfo)
    started = time.monotonic()
    wants_active = (
        policy.maximum_activity == ActivityLevel.ACTIVE_DISCOVERY
        if active_requested is None
        else active_requested
    )
    if not isinstance(wants_active, bool):
        raise TypeError("active_requested must be a boolean or None")

    def routing_data() -> dict[str, Any]:
        value = report.data.get("routing", {})
        return value if isinstance(value, dict) else {}

    def gateway_ready() -> tuple[bool, str]:
        gateway = routing_data().get("default_gateway")
        return (bool(gateway), "No explicit default gateway was available.")

    def active_scope_ready() -> tuple[bool, str]:
        if not wants_active:
            return False, "Active discovery was not requested."
        return _validated_active_scope(policy, routing_data())[:2]

    def collect_gateway_ports() -> CollectorResult:
        gateway = routing_data().get("default_gateway")
        if not isinstance(gateway, str) or not gateway:
            raise RuntimeError("gateway dependency was not validated")
        return adapters.ports(gateway, list(_GATEWAY_PORTS))

    def collect_active_ping() -> CollectorResult:
        allowed, _reason, network = _validated_active_scope(policy, routing_data())
        if not allowed or network is None:
            raise RuntimeError("active scope was not validated")
        alive = adapters.active_ping(network, policy.max_hosts)
        findings = [
            make_finding(
                "NDG.LAN.ACTIVE_DISCOVERY_COMPLETED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={
                    "network": str(network),
                    "count": len(alive),
                    "addresses": ", ".join(alive[:12]) + ("…" if len(alive) > 12 else ""),
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The bounded ping sweep completed over the authorized network.",
            )
        ]
        return findings, {"ping_alive": alive}

    steps = (
        _Step(
            "routing",
            "netdiag.check.routing",
            "routing",
            ActivityLevel.PASSIVE,
            "routing",
            "routing",
            lambda: adapters.routing(osinfo, False),
        ),
        _Step(
            "routing_connectivity",
            "netdiag.check.routing",
            "routing",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "routing",
            "routing",
            lambda: adapters.routing(osinfo, True),
            ready=lambda: (
                bool(routing_data().get("has_default_route")),
                "No default route was available for connectivity probes.",
            ),
        ),
        _Step(
            "dns",
            "netdiag.check.dns",
            "dns",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "dns",
            "dns",
            lambda: adapters.dns(osinfo),
        ),
        _Step(
            "wifi",
            "netdiag.check.wifi",
            "wifi",
            ActivityLevel.PASSIVE,
            "wifi",
            "wifi",
            lambda: adapters.wifi(osinfo),
        ),
        _Step(
            "lan",
            "netdiag.check.lan",
            "lan",
            ActivityLevel.PASSIVE,
            "lan",
            "lan",
            lambda: adapters.lan(osinfo, False, policy.max_hosts),
        ),
        _Step(
            "mdns",
            "netdiag.check.mdns",
            "mdns",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "mdns",
            "mdns",
            lambda: adapters.mdns(osinfo),
            ready=lambda: (include_mdns, "mDNS browsing was disabled for this run."),
        ),
        _Step(
            "gateway_ports",
            "netdiag.check.gateway_ports",
            "gateway_ports",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "gateway_ports",
            "gateway_ports",
            collect_gateway_ports,
            ready=gateway_ready,
        ),
        _Step(
            "lan_ping",
            "netdiag.check.lan",
            "lan",
            ActivityLevel.ACTIVE_DISCOVERY,
            "lan",
            "lan",
            collect_active_ping,
            ready=active_scope_ready,
        ),
    )

    total = len(steps)
    for index, step in enumerate(steps, start=1):
        if token.is_cancelled:
            _record_cancelled(report, step, index, total, progress)
            for remainder_index, remainder in enumerate(steps[index:], start=index + 1):
                _record_not_run(report, remainder, remainder_index, total, progress)
            break

        if not policy.maximum_activity.permits(step.activity):
            _record_not_run(report, step, index, total, progress)
            continue
        ready, _reason = step.ready()
        if not ready:
            _record_not_run(report, step, index, total, progress)
            continue
        _execute_step(report, step, index, total, progress)

    report.duration_ms = round((time.monotonic() - started) * 1000)
    return report


def run_full_scan(*, lan_ping: bool = False, mdns: bool = True) -> Report:
    """Run the legacy CLI plan with explicit low-impact authorization.

    ``netdiag run`` itself is the user's low-impact request. ``--ping`` is a
    separate active request; its exact RFC1918 interface/network is derived
    from the completed route preflight and the sweep is executed against that
    immutable derived network rather than asking the LAN collector to discover
    a potentially different target later.
    """

    if not isinstance(lan_ping, bool) or not isinstance(mdns, bool):
        raise TypeError("lan_ping and mdns must be booleans")
    adapters = default_collectors()
    osinfo = adapters.detect_platform()
    report = _new_report(osinfo)
    started = time.monotonic()
    policy = ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK)

    legacy_steps: list[_Step] = [
        _Step(
            "routing",
            "netdiag.check.routing",
            "routing",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "routing",
            "routing",
            lambda: adapters.routing(osinfo, True),
        ),
        _Step(
            "dns",
            "netdiag.check.dns",
            "dns",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "dns",
            "dns",
            lambda: adapters.dns(osinfo),
        ),
        _Step(
            "wifi",
            "netdiag.check.wifi",
            "wifi",
            ActivityLevel.PASSIVE,
            "wifi",
            "wifi",
            lambda: adapters.wifi(osinfo),
        ),
        _Step(
            "lan",
            "netdiag.check.lan",
            "lan",
            ActivityLevel.PASSIVE,
            "lan",
            "lan",
            lambda: adapters.lan(osinfo, False, policy.max_hosts),
        ),
    ]
    if mdns:
        legacy_steps.append(
            _Step(
                "mdns",
                "netdiag.check.mdns",
                "mdns",
                ActivityLevel.LOW_IMPACT_NETWORK,
                "mdns",
                "mdns",
                lambda: adapters.mdns(osinfo),
            )
        )

    for index, step in enumerate(legacy_steps, start=1):
        _execute_step(report, step, index, len(legacy_steps), None)

    route_data = report.data.get("routing", {})
    gateway = route_data.get("default_gateway") if isinstance(route_data, dict) else None
    if isinstance(gateway, str) and gateway:
        ports_step = _Step(
            "gateway_ports",
            "netdiag.check.gateway_ports",
            "gateway_ports",
            ActivityLevel.LOW_IMPACT_NETWORK,
            "gateway_ports",
            "gateway_ports",
            lambda: adapters.ports(gateway, list(_GATEWAY_PORTS)),
        )
        _execute_step(report, ports_step, 1, 1, None)

    if lan_ping:
        derived = _derive_cli_active_policy(route_data, max_hosts=policy.max_hosts)
        active_step = _Step(
            "lan_ping",
            "netdiag.check.lan",
            "lan",
            ActivityLevel.ACTIVE_DISCOVERY,
            "lan",
            "lan",
            lambda: _collect_active_with_policy(adapters, derived),
        )
        if derived is None:
            _record_not_run(report, active_step, 1, 1, None)
        else:
            _execute_step(report, active_step, 1, 1, None)

    report.duration_ms = round((time.monotonic() - started) * 1000)
    return report


def report_exit_code(report: Report) -> int:
    return exit_code(report.findings)


def _new_report(osinfo: OSInfo) -> Report:
    return Report(
        hostname=socket.gethostname(),
        os=osinfo,
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def _execute_step(
    report: Report,
    step: _Step,
    index: int,
    total: int,
    progress: ProgressSink | None,
) -> None:
    _emit(progress, ScanProgress(step.module, "started", index, total))
    section_started = time.monotonic()
    observed_at = datetime.now(timezone.utc)
    normalized_error: ErrorDetail | None = None
    execution_status = ExecutionStatus.COMPLETED
    try:
        findings, data = step.collect()
        if (
            not isinstance(findings, list)
            or any(not isinstance(finding, Finding) for finding in findings)
            or not isinstance(data, dict)
        ):
            raise TypeError("collector returned an invalid result")
        validate_json_value(data)
    except Exception as exc:  # noqa: BLE001 - independent adapters are isolated.
        normalized_error = ErrorDetail.unexpected(step.check_id, exc)
        findings = [
            make_finding(
                _CHECK_FAILURE_CODES[step.module],
                Severity.WARN,
                OutcomeStatus.INCONCLUSIVE,
                parameters={"error_summary": normalized_error.message},
                confidence=ConfidenceLevel.HIGH,
                rationale="The collector raised an unexpected bounded error.",
            )
        ]
        data = {"error": _compatibility_error(normalized_error)}
        execution_status = ExecutionStatus.FAILED
    duration_ms = round((time.monotonic() - section_started) * 1000)
    data["duration_ms"] = duration_ms
    if data.get("collector_status") == "failed":
        execution_status = ExecutionStatus.FAILED
    outcome = _section_outcome(findings)
    evidence_id = f"evidence.{step.module}.observation"
    findings = [finding.with_evidence(evidence_id) for finding in findings]
    evidence = Evidence(
        evidence_id,
        evidence_kind_for(step.evidence_category),
        step.check_id,
        outcome,
        f"netdiag.source.{step.evidence_category}_legacy",
        observed_at,
        duration_ms,
        data,
        error=normalized_error,
    )
    report.findings.extend(findings)
    _merge_section_data(report, step.data_section, data)
    report.evidence.append(evidence)
    report.checks.append(
        CheckRecord(
            step.check_id,
            step.category,
            execution_status,
            outcome,
            duration_ms,
            (evidence_id,),
            normalized_error,
        )
    )
    phase = "failed" if execution_status == ExecutionStatus.FAILED else "completed"
    _emit(progress, ScanProgress(step.module, phase, index, total))


def _record_not_run(
    report: Report,
    step: _Step,
    index: int,
    total: int,
    progress: ProgressSink | None,
) -> None:
    report.checks.append(
        CheckRecord(
            step.check_id,
            step.category,
            ExecutionStatus.NOT_RUN,
            OutcomeStatus.NOT_TESTED,
            0,
        )
    )
    _emit(progress, ScanProgress(step.module, "not_run", index, total))


def _record_cancelled(
    report: Report,
    step: _Step,
    index: int,
    total: int,
    progress: ProgressSink | None,
) -> None:
    report.checks.append(
        CheckRecord(
            step.check_id,
            step.category,
            ExecutionStatus.CANCELLED,
            OutcomeStatus.CANCELLED,
            0,
        )
    )
    _emit(progress, ScanProgress(step.module, "cancelled", index, total))


def _emit(progress: ProgressSink | None, event: ScanProgress) -> None:
    if progress is None:
        return
    try:
        progress(event)
    except Exception:  # noqa: BLE001 - UI observation cannot invalidate diagnostic evidence.
        return


def _merge_section_data(report: Report, section: str, data: dict[str, Any]) -> None:
    existing = report.data.get(section)
    if isinstance(existing, dict):
        existing.update(data)
    else:
        report.data[section] = data


def _validated_active_scope(
    policy: ScanPolicy,
    routing_data: dict[str, Any],
) -> tuple[bool, str, ipaddress.IPv4Network | None]:
    if policy.maximum_activity != ActivityLevel.ACTIVE_DISCOVERY:
        return False, "Active discovery authorization is absent.", None
    if len(policy.allowed_interfaces) != 1 or len(policy.allowed_networks) != 1:
        return False, "Active discovery requires exactly one interface and network.", None
    interface = policy.allowed_interfaces[0]
    if not _is_direct_lan_interface(interface):
        return False, "Active discovery excludes tunnel and virtual interfaces.", None
    try:
        candidate = ipaddress.ip_network(policy.allowed_networks[0], strict=False)
    except ValueError:
        return False, "The authorized network is invalid.", None
    if not isinstance(candidate, ipaddress.IPv4Network) or not _is_rfc1918(candidate):
        return False, "Active discovery is restricted to one RFC1918 IPv4 network.", None
    host_count = max(0, candidate.num_addresses - 2)
    if host_count > policy.max_hosts:
        return False, "The authorized network exceeds its host budget.", None
    if routing_data.get("default_interface") != interface:
        return False, "The authorized interface no longer matches the route preflight.", None
    interfaces = routing_data.get("interfaces")
    if not isinstance(interfaces, list):
        return False, "The route preflight did not produce interface scope.", None
    for item in interfaces:
        if not isinstance(item, dict) or item.get("name") != interface:
            continue
        networks = item.get("networks")
        if not isinstance(networks, list):
            continue
        canonical: set[str] = set()
        for network in networks:
            try:
                canonical.add(str(ipaddress.ip_network(network, strict=False)))
            except (TypeError, ValueError):
                continue
        if str(candidate) in canonical:
            return True, "Authorized scope matches the route preflight.", candidate
    return False, "The authorized network no longer matches the route preflight.", None


def _derive_cli_active_policy(
    routing_data: object,
    *,
    max_hosts: int,
) -> ScanPolicy | None:
    if not isinstance(routing_data, dict):
        return None
    interface = routing_data.get("default_interface")
    interfaces = routing_data.get("interfaces")
    if not isinstance(interface, str) or not interface or not isinstance(interfaces, list):
        return None
    if not _is_direct_lan_interface(interface):
        return None
    for item in interfaces:
        if not isinstance(item, dict) or item.get("name") != interface:
            continue
        networks = item.get("networks")
        if not isinstance(networks, list):
            return None
        valid: list[ipaddress.IPv4Network] = []
        for raw in networks:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except (TypeError, ValueError):
                continue
            if (
                isinstance(network, ipaddress.IPv4Network)
                and _is_rfc1918(network)
                and max(0, network.num_addresses - 2) <= max_hosts
            ):
                valid.append(network)
        if len(valid) != 1:
            return None
        return ScanPolicy(
            maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
            allowed_interfaces=(interface,),
            allowed_networks=(str(valid[0]),),
            max_hosts=max_hosts,
        )
    return None


def _collect_active_with_policy(
    adapters: ScanCollectors,
    policy: ScanPolicy | None,
) -> CollectorResult:
    if policy is None or len(policy.allowed_networks) != 1:
        raise RuntimeError("active scope is unavailable")
    network = ipaddress.ip_network(policy.allowed_networks[0], strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise TypeError("active scope is not IPv4")
    alive = adapters.active_ping(network, policy.max_hosts)
    return (
        [
            make_finding(
                "NDG.LAN.ACTIVE_DISCOVERY_COMPLETED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={
                    "network": str(network),
                    "count": len(alive),
                    "addresses": ", ".join(alive[:12]) + ("…" if len(alive) > 12 else ""),
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The bounded ping sweep completed over the authorized network.",
            )
        ],
        {"ping_alive": alive},
    )


def _is_rfc1918(network: ipaddress.IPv4Network) -> bool:
    return any(
        network.subnet_of(block)
        for block in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )


def _is_direct_lan_interface(name: str) -> bool:
    """Fail closed to conventional physical Ethernet/Wi-Fi interface names."""

    return bool(_DIRECT_LAN_INTERFACE.fullmatch(name))


def _section_outcome(findings: list[Finding]) -> OutcomeStatus:
    if not findings:
        return OutcomeStatus.NOT_TESTED
    statuses = {finding.status for finding in findings}
    for status in (
        OutcomeStatus.FAILED,
        OutcomeStatus.DEGRADED,
        OutcomeStatus.BLOCKED,
        OutcomeStatus.PERMISSION_DENIED,
        OutcomeStatus.CANCELLED,
        OutcomeStatus.INCONCLUSIVE,
        OutcomeStatus.HEALTHY,
        OutcomeStatus.INFORMATIONAL,
        OutcomeStatus.NOT_TESTED,
        OutcomeStatus.UNSUPPORTED,
    ):
        if status in statuses:
            return status
    return OutcomeStatus.INCONCLUSIVE


def _compatibility_error(error: ErrorDetail) -> dict[str, object]:
    return {
        "code": error.code,
        "type": "UnexpectedError",
        "message": error.message,
        "retryable": error.retryable,
        "native_exit_code": error.native_exit_code,
    }
