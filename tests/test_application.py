from __future__ import annotations

import ipaddress
import json
import threading
from concurrent.futures import Future
from datetime import datetime, timezone
from typing import Any

import pytest

from netdiag.application import (
    ApplicationState,
    DiagnosticController,
    RunAuthorization,
    ScanAlreadyRunning,
)
from netdiag.catalog import make_finding
from netdiag.consent import DiagnosticGoal, issue_consent
from netdiag.core import ActivityLevel, CancellationToken, ScanPolicy
from netdiag.core.status import ConfidenceLevel, ExecutionStatus, OutcomeStatus
from netdiag.models import Report, Severity
from netdiag.platform import OSInfo
from netdiag.scanner import ScanCollectors, ScanProgress, run_full_scan, run_policy_scan
from netdiag.ui.controller import StatusProvider

OS_INFO = OSInfo("Darwin", "test", "arm64")
ROUTE_DATA: dict[str, Any] = {
    "default_gateway": "192.168.50.1",
    "default_interface": "en0",
    "has_default_route": True,
    "interfaces": [
        {
            "name": "en0",
            "addresses": ["192.168.50.25"],
            "networks": ["192.168.50.0/24"],
            "state": "up",
        }
    ],
}


class FakeCollectors:
    def __init__(self, *, route_data: dict[str, Any] | None = None) -> None:
        self.calls: list[object] = []
        self.active_result = ["192.168.50.20"]
        self.route_data = route_data or ROUTE_DATA

    def bundle(self) -> ScanCollectors:
        return ScanCollectors(
            detect_platform=self.detect_platform,
            routing=self.routing,
            dns=self.dns,
            wifi=self.wifi,
            lan=self.lan,
            mdns=self.mdns,
            ports=self.ports,
            active_ping=self.active_ping,
        )

    def detect_platform(self) -> OSInfo:
        self.calls.append("platform")
        return OS_INFO

    def routing(self, _osinfo: OSInfo, probes: bool) -> tuple[list, dict]:
        self.calls.append(("routing", probes))
        if not probes:
            return [], dict(self.route_data)
        return (
            [
                make_finding(
                    "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
                    Severity.OK,
                    OutcomeStatus.HEALTHY,
                    parameters={"target": "1.1.1.1"},
                    confidence=ConfidenceLevel.HIGH,
                )
            ],
            {**self.route_data, "tcp_443": True, "tcp_443_target": "1.1.1.1"},
        )

    def dns(self, _osinfo: OSInfo) -> tuple[list, dict]:
        self.calls.append("dns")
        return (
            [
                make_finding(
                    "NDG.DNS.RESOLUTION_SUCCEEDED",
                    Severity.OK,
                    OutcomeStatus.HEALTHY,
                    parameters={"domain": "example.com", "count": 1},
                )
            ],
            {"resolvers": ["192.168.50.1"], "queries": []},
        )

    def wifi(self, _osinfo: OSInfo) -> tuple[list, dict]:
        self.calls.append("wifi")
        return [], {"connected": False}

    def lan(self, _osinfo: OSInfo, do_ping: bool, max_hosts: int) -> tuple[list, dict]:
        self.calls.append(("lan", do_ping, max_hosts))
        return [], {
            "default_interface": "en0",
            "network": "192.168.50.0/24",
            "networks": ["192.168.50.0/24"],
            "arp_source": "ip_neigh",
            "arp_status": "ok",
            "arp_detail": "",
            "arp": [],
            "ping_alive": [],
        }

    def mdns(self, _osinfo: OSInfo) -> tuple[list, dict]:
        self.calls.append("mdns")
        return [], {"services": [], "raw_count": 0, "unique_count": 0}

    def ports(self, host: str, ports: list[int]) -> tuple[list, dict]:
        self.calls.append(("ports", host, tuple(ports)))
        return [], {"host": host, "ports": {}, "open": []}

    def active_ping(self, network: ipaddress.IPv4Network, max_hosts: int) -> list[str]:
        self.calls.append(("active_ping", str(network), max_hosts))
        return list(self.active_result)


class ImmediateExecutor:
    def submit(self, fn):
        future: Future[None] = Future()
        try:
            fn()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover - Future parity
            future.set_exception(exc)
        else:
            future.set_result(None)
        return future


def consent(*, active: bool = False, basic: bool = True):
    return issue_consent(
        consent_id="consent.runtime.fixture",
        scan_id="scan.runtime.fixture",
        goal=DiagnosticGoal.NETWORK,
        basic_network_checks=basic,
        active_interface="en0" if active else None,
        active_network="192.168.50.0/24" if active else None,
        max_hosts=254,
        now=datetime.now(timezone.utc),
    )


def check_statuses(report: Report) -> dict[str, list[ExecutionStatus]]:
    result: dict[str, list[ExecutionStatus]] = {}
    for check in report.checks:
        result.setdefault(check.category, []).append(check.execution_status)
    return result


def test_passive_policy_never_calls_network_capable_collectors() -> None:
    fake = FakeCollectors()
    report = run_policy_scan(
        ScanPolicy(maximum_activity=ActivityLevel.PASSIVE),
        collectors=fake.bundle(),
    )

    assert fake.calls == [
        "platform",
        ("routing", False),
        "wifi",
        ("lan", False, 256),
    ]
    assert len(report.checks) == 8
    assert sum(check.execution_status == ExecutionStatus.NOT_RUN for check in report.checks) == 5
    assert report.outcome_status == OutcomeStatus.INCONCLUSIVE


def test_low_impact_policy_runs_bounded_network_checks_but_not_lan_ping() -> None:
    fake = FakeCollectors()
    report = run_policy_scan(
        ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK),
        collectors=fake.bundle(),
    )

    assert ("routing", False) in fake.calls
    assert ("routing", True) in fake.calls
    assert "dns" in fake.calls
    assert "mdns" in fake.calls
    assert ("ports", "192.168.50.1", (53, 80, 443, 8080, 8443)) in fake.calls
    assert not any(isinstance(call, tuple) and call[0] == "active_ping" for call in fake.calls)
    assert report.checks[-1].execution_status == ExecutionStatus.NOT_RUN
    assert report.outcome_status == OutcomeStatus.INCONCLUSIVE


def test_progress_terminal_events_follow_declared_module_order() -> None:
    fake = FakeCollectors()
    events: list[ScanProgress] = []
    run_policy_scan(
        ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK),
        collectors=fake.bundle(),
        progress=events.append,
    )

    terminal = [event for event in events if event.phase != "started"]
    assert [event.module for event in terminal] == [
        "routing",
        "routing_connectivity",
        "dns",
        "wifi",
        "lan",
        "mdns",
        "gateway_ports",
        "lan_ping",
    ]
    assert [event.step for event in terminal] == list(range(1, 9))
    assert {event.total_steps for event in events} == {8}
    assert len(events) <= 16


def test_active_discovery_uses_only_exact_authorized_preflight_scope() -> None:
    fake = FakeCollectors()
    policy = ScanPolicy(
        maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
        allowed_interfaces=("en0",),
        allowed_networks=("192.168.50.0/24",),
        max_hosts=254,
    )
    report = run_policy_scan(policy, collectors=fake.bundle())

    assert ("active_ping", "192.168.50.0/24", 254) in fake.calls
    assert report.checks[-1].execution_status == ExecutionStatus.COMPLETED

    mismatch = FakeCollectors()
    mismatched_policy = ScanPolicy(
        maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
        allowed_interfaces=("en1",),
        allowed_networks=("192.168.50.0/24",),
        max_hosts=254,
    )
    denied = run_policy_scan(mismatched_policy, collectors=mismatch.bundle())
    assert not any(isinstance(call, tuple) and call[0] == "active_ping" for call in mismatch.calls)
    assert denied.checks[-1].execution_status == ExecutionStatus.NOT_RUN
    assert denied.outcome_status == OutcomeStatus.INCONCLUSIVE


def test_active_discovery_enforces_host_budget_even_for_direct_policy() -> None:
    fake = FakeCollectors()
    policy = ScanPolicy(
        maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
        allowed_interfaces=("en0",),
        allowed_networks=("192.168.50.0/24",),
        max_hosts=10,
    )
    report = run_policy_scan(policy, collectors=fake.bundle())

    assert not any(isinstance(call, tuple) and call[0] == "active_ping" for call in fake.calls)
    assert report.checks[-1].execution_status == ExecutionStatus.NOT_RUN


@pytest.mark.parametrize("interface", ["utun0", "bridge0"])
def test_active_discovery_rejects_tunnel_and_virtual_interfaces(interface: str) -> None:
    route_data = {
        **ROUTE_DATA,
        "default_interface": interface,
        "interfaces": [
            {
                "name": interface,
                "addresses": ["192.168.50.25"],
                "networks": ["192.168.50.0/24"],
                "state": "up",
            }
        ],
    }
    fake = FakeCollectors(route_data=route_data)
    policy = ScanPolicy(
        maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
        allowed_interfaces=(interface,),
        allowed_networks=("192.168.50.0/24",),
        max_hosts=254,
    )
    report = run_policy_scan(policy, collectors=fake.bundle())

    assert not any(isinstance(call, tuple) and call[0] == "active_ping" for call in fake.calls)
    assert report.checks[-1].execution_status == ExecutionStatus.NOT_RUN


def test_cancellation_at_boundary_retains_completed_evidence_and_order() -> None:
    fake = FakeCollectors()
    token = CancellationToken()
    events: list[ScanProgress] = []

    def progress(event: ScanProgress) -> None:
        events.append(event)
        if event.module == "routing" and event.phase == "completed":
            token.cancel("test_boundary")

    report = run_policy_scan(
        ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK),
        cancellation=token,
        progress=progress,
        collectors=fake.bundle(),
    )

    assert [(item.module, item.phase) for item in events[:3]] == [
        ("routing", "started"),
        ("routing", "completed"),
        ("routing_connectivity", "cancelled"),
    ]
    assert len(events) == 9
    assert len(report.evidence) == 1
    assert report.evidence[0].evidence_id == "evidence.routing.observation"
    assert report.checks[0].execution_status == ExecutionStatus.COMPLETED
    assert report.checks[1].execution_status == ExecutionStatus.CANCELLED
    assert report.execution_status == ExecutionStatus.CANCELLED
    assert fake.calls == ["platform", ("routing", False)]


def test_invalid_collector_payload_is_isolated_as_normalized_module_failure() -> None:
    fake = FakeCollectors()

    def invalid_dns(_osinfo: OSInfo) -> tuple[list, dict]:
        return [], {"password=hunter2": object()}

    bundle = fake.bundle()
    bundle = ScanCollectors(
        detect_platform=bundle.detect_platform,
        routing=bundle.routing,
        dns=invalid_dns,
        wifi=bundle.wifi,
        lan=bundle.lan,
        mdns=bundle.mdns,
        ports=bundle.ports,
        active_ping=bundle.active_ping,
    )
    report = run_policy_scan(
        ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK),
        collectors=bundle,
    )

    dns_check = next(check for check in report.checks if check.category == "dns")
    assert dns_check.execution_status == ExecutionStatus.FAILED
    assert report.data["dns"]["error"]["message"] == "Unexpected collector error"
    assert "hunter2" not in json.dumps(report.to_dict(redact=True))


def test_legacy_ping_derives_one_scope_and_never_asks_lan_collector_to_ping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeCollectors()
    monkeypatch.setattr("netdiag.scanner.default_collectors", fake.bundle)
    report = run_full_scan(lan_ping=True, mdns=False)

    assert ("lan", False, 256) in fake.calls
    assert ("active_ping", "192.168.50.0/24", 256) in fake.calls
    assert report.checks[-1].execution_status == ExecutionStatus.COMPLETED


def test_legacy_run_is_explicit_low_impact_but_not_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeCollectors()
    monkeypatch.setattr("netdiag.scanner.default_collectors", fake.bundle)
    run_full_scan(lan_ping=False, mdns=True)

    assert ("routing", True) in fake.calls
    assert "dns" in fake.calls
    assert "mdns" in fake.calls
    assert ("lan", False, 256) in fake.calls
    assert not any(isinstance(call, tuple) and call[0] == "active_ping" for call in fake.calls)


def test_controller_binds_immutable_consent_and_produces_share_safe_snapshot() -> None:
    fake = FakeCollectors()
    seen: list[ScanPolicy] = []

    def runner(policy: ScanPolicy, **kwargs) -> Report:
        seen.append(policy)
        return run_policy_scan(policy, **kwargs)

    controller = DiagnosticController(
        scan_runner=runner,
        collectors=fake.bundle(),
        executor=ImmediateExecutor(),
    )
    assert isinstance(controller, StatusProvider)
    controller.start(consent(active=True))
    snapshot = controller.snapshot()

    assert controller.state == ApplicationState.COMPLETED
    assert seen[0].maximum_activity == ActivityLevel.ACTIVE_DISCOVERY
    assert seen[0].allowed_interfaces == ("en0",)
    assert snapshot["state"] == "completed"
    assert snapshot["result"]["redacted"] is True
    serialized = json.dumps(snapshot)
    for forbidden in ("192.168.50.1", "192.168.50.20", "en0", "evidence."):
        assert forbidden not in serialized


def test_authorization_rejects_policy_that_does_not_match_consent() -> None:
    record = consent(basic=False)
    with pytest.raises(ValueError, match="does not match"):
        RunAuthorization(
            record,
            ScanPolicy(maximum_activity=ActivityLevel.LOW_IMPACT_NETWORK),
        )


def test_controller_rejects_concurrent_run_without_waiting_or_sleeping() -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocking_runner(_policy: ScanPolicy, **_kwargs) -> Report:
        entered.set()
        assert release.wait(2)
        return Report("host", OS_INFO, datetime.now(timezone.utc).isoformat())

    controller = DiagnosticController(scan_runner=blocking_runner)
    try:
        controller.start(consent())
        assert entered.wait(1)
        with pytest.raises(ScanAlreadyRunning):
            controller.start(consent())
        release.set()
        assert controller.wait(timeout=2)
    finally:
        release.set()
        controller.close(timeout=2)


def test_worker_start_failure_is_normalized_and_close_never_joins_unstarted_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = DiagnosticController()
    monkeypatch.setattr(
        threading.Thread,
        "start",
        lambda _thread: (_ for _ in ()).throw(RuntimeError("password=hunter2")),
    )

    with pytest.raises(RuntimeError, match="could not be started"):
        controller.start(consent())
    assert controller.state == ApplicationState.FAILED
    assert controller.close(timeout=0.1)
    assert "hunter2" not in json.dumps(controller.snapshot())


def test_controller_normalizes_errors_and_never_exposes_tracebacks_or_canaries() -> None:
    def failing_runner(_policy: ScanPolicy, **_kwargs) -> Report:
        raise RuntimeError("password=hunter2 hostname=family-mac.local")

    controller = DiagnosticController(
        scan_runner=failing_runner,
        executor=ImmediateExecutor(),
        max_snapshot_bytes=2048,
    )
    controller.start(consent())
    snapshot = controller.snapshot()
    encoded = json.dumps(snapshot)

    assert snapshot["state"] == "failed"
    assert snapshot["error"] == {
        "code": "scan_failed",
        "message": "The diagnostic run could not be completed.",
    }
    assert len(encoded.encode()) <= 2048
    assert "hunter2" not in encoded
    assert "family-mac" not in encoded
    assert "Traceback" not in encoded


def test_progress_module_and_public_parameter_canaries_never_cross_status_boundary() -> None:
    class FakeProgress:
        module = "password=hunter2"
        phase = "started"
        step = 1
        total_steps = 1

    def runner(_policy: ScanPolicy, **kwargs) -> Report:
        kwargs["progress"](FakeProgress())
        report = Report("family-mac.local", OS_INFO, datetime.now(timezone.utc).isoformat())
        report.findings.append(
            make_finding(
                "NDG.WIFI.CONNECTED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"ssid": "family-secret", "summary": "password=hunter2"},
            )
        )
        return report

    controller = DiagnosticController(scan_runner=runner, executor=ImmediateExecutor())
    controller.start(consent())
    encoded = json.dumps(controller.snapshot())

    assert "hunter2" not in encoded
    assert "family-secret" not in encoded
    assert "family-mac" not in encoded


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("phase", "password=hunter2"),
        ("step", "family-mac.local"),
        ("total_steps", "recovery-key=abc"),
        ("step", True),
        ("total_steps", True),
    ],
)
def test_mutated_progress_events_are_rejected_at_status_boundary(
    field: str,
    value: object,
) -> None:
    def runner(_policy: ScanPolicy, **kwargs) -> Report:
        event = ScanProgress("routing", "started", 1, 1)
        object.__setattr__(event, field, value)
        kwargs["progress"](event)
        return Report("host", OS_INFO, datetime.now(timezone.utc).isoformat())

    controller = DiagnosticController(scan_runner=runner, executor=ImmediateExecutor())
    controller.start(consent())
    encoded = json.dumps(controller.snapshot())
    assert "hunter2" not in encoded
    assert "family-mac" not in encoded
    assert "recovery-key" not in encoded
    assert '"events": []' in encoded


def test_completed_provider_snapshot_is_bounded_under_large_finding_volume() -> None:
    def runner(_policy: ScanPolicy, **_kwargs) -> Report:
        report = Report("host", OS_INFO, datetime.now(timezone.utc).isoformat())
        for _ in range(200):
            report.findings.append(
                make_finding(
                    "NDG.WIFI.CONNECTED",
                    Severity.INFO,
                    OutcomeStatus.INFORMATIONAL,
                    parameters={"ssid": "private-ssid", "summary": "no details"},
                )
            )
        return report

    controller = DiagnosticController(
        scan_runner=runner,
        executor=ImmediateExecutor(),
        max_snapshot_bytes=2048,
    )
    controller.start(consent())
    snapshot = controller.snapshot()
    encoded = json.dumps(snapshot, separators=(",", ":")).encode()

    assert len(encoded) <= 2048
    assert b"private-ssid" not in encoded
    assert b'"truncated":true' in encoded


def test_cancelled_controller_keeps_completed_summary_and_closes_deterministically() -> None:
    fake = FakeCollectors()
    controller: DiagnosticController

    def runner(policy: ScanPolicy, **kwargs) -> Report:
        original_progress = kwargs["progress"]

        def progress(event: ScanProgress) -> None:
            original_progress(event)
            if event.module == "routing" and event.phase == "completed":
                kwargs["cancellation"].cancel("fixture")

        kwargs["progress"] = progress
        return run_policy_scan(policy, **kwargs)

    controller = DiagnosticController(
        scan_runner=runner,
        collectors=fake.bundle(),
        executor=ImmediateExecutor(),
    )
    controller.start(consent())
    snapshot = controller.snapshot()

    assert snapshot["state"] == "cancelled"
    assert snapshot["result"] is not None
    assert snapshot["result"]["coverage"]["cancelled"] == 1
    assert controller.close(timeout=0.1)
