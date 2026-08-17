"""Run full diagnostic suite."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netdiag import __version__
from netdiag.checks.dns import check_dns
from netdiag.checks.lan import scan_lan
from netdiag.checks.mdns import browse_mdns
from netdiag.checks.routing import check_routing, get_routes
from netdiag.checks.wifi import check_wifi
from netdiag.findings import Finding, Severity, exit_code, worst_severity
from netdiag.platform import OSInfo, detect_os


@dataclass
class Report:
    hostname: str
    os: OSInfo
    started_at: str
    duration_ms: int = 0
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return worst_severity(self.findings).value

    def to_dict(self, *, redact: bool = False) -> dict[str, Any]:
        payload = {
            "schema_version": "1.0",
            "tool_version": __version__,
            "hostname": self.hostname,
            "os": {"system": self.os.system, "release": self.os.release, "machine": self.os.machine},
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }
        return _redact(payload) if redact else payload


_SENSITIVE_KEYS = {"ssid", "bssid", "mac", "hostname", "instance"}


def _redact(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove device identifiers while retaining diagnostic network addresses."""
    secrets: set[str] = set()

    def collect(value: Any, key: str = "") -> None:
        if key.lower() in _SENSITIVE_KEYS and isinstance(value, str) and value not in {"", "?"}:
            secrets.add(value)
        if isinstance(value, dict):
            for child_key, child in value.items():
                collect(child, str(child_key))
        elif isinstance(value, list):
            for child in value:
                collect(child, key)

    collect(payload)
    secrets.update(
        value for value in [payload.get("hostname", "")] if isinstance(value, str) and value
    )

    def clean(value: Any, key: str = "") -> Any:
        if key.lower() in _SENSITIVE_KEYS and isinstance(value, str) and value not in {"", "?"}:
            return "<redacted>"
        if isinstance(value, str):
            for secret in sorted(secrets, key=len, reverse=True):
                value = value.replace(secret, "<redacted>")
            return value
        if isinstance(value, dict):
            return {child_key: clean(child, str(child_key)) for child_key, child in value.items()}
        if isinstance(value, list):
            return [clean(child, key) for child in value]
        return value

    return clean(payload)


def run_full_scan(*, lan_ping: bool = False, mdns: bool = True) -> Report:
    scan_started = time.monotonic()
    osinfo = detect_os()
    report = Report(
        hostname=socket.gethostname(),
        os=osinfo,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    sections = [
        ("routing", lambda: check_routing(osinfo)),
        ("dns", lambda: check_dns(osinfo)),
        ("wifi", lambda: check_wifi(osinfo)),
        ("lan", lambda: scan_lan(osinfo, do_ping=lan_ping)),
    ]
    if mdns:
        sections.append(("mdns", lambda: browse_mdns(osinfo)))

    routes = get_routes(osinfo)
    if routes.default_gateway:
        from netdiag.checks.ports import scan_ports

        sections.append(
            (
                "gateway_ports",
                lambda: scan_ports(
                    routes.default_gateway,
                    ports=[53, 80, 443, 8080, 8443],
                ),
            )
        )

    for name, fn in sections:
        section_started = time.monotonic()
        try:
            findings, data = fn()
        except Exception as exc:  # noqa: BLE001 - isolate independent diagnostic plugins.
            findings = [
                Finding(
                    Severity.WARN,
                    name,
                    f"{name.replace('_', ' ').title()} check could not complete",
                    f"{type(exc).__name__}: {exc}",
                    hint="Re-run this check by itself for more detail.",
                )
            ]
            data = {"error": {"type": type(exc).__name__, "message": str(exc)}}
        data["duration_ms"] = round((time.monotonic() - section_started) * 1000)
        report.findings.extend(findings)
        report.data[name] = data

    report.duration_ms = round((time.monotonic() - scan_started) * 1000)

    return report


def report_exit_code(report: Report) -> int:
    return exit_code(report.findings)
