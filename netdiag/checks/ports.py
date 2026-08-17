"""TCP port checks for common services."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity

COMMON_PORTS: dict[int, str] = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
}

_FINDING_PORT_LIMIT = 64


def check_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, str, str, int]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, "open", "", round((time.monotonic() - started) * 1000)
    except ConnectionRefusedError as exc:
        return port, "closed", str(exc), round((time.monotonic() - started) * 1000)
    except TimeoutError as exc:
        return port, "filtered_or_unreachable", str(exc), round((time.monotonic() - started) * 1000)
    except OSError as exc:
        state = "closed" if getattr(exc, "errno", None) in {61, 111} else "unreachable"
        return port, state, str(exc), round((time.monotonic() - started) * 1000)


def scan_ports(
    host: str, ports: list[int] | None = None, timeout: float = 2.0
) -> tuple[list[Finding], dict]:
    ports = ports or sorted(COMMON_PORTS.keys())
    results: dict[int, dict] = {}
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        futs = [pool.submit(check_port, host, p, timeout) for p in ports]
        for fut in as_completed(futs):
            port, state, err, latency = fut.result()
            results[port] = {
                "open": state == "open",
                "state": state,
                "error": err,
                "service": COMMON_PORTS.get(port, "?"),
                "response_ms": latency,
            }
            if state == "open":
                open_ports.append(port)

    findings: list[Finding] = []
    if open_ports:
        sorted_open_ports = sorted(open_ports)
        displayed_ports = sorted_open_ports[:_FINDING_PORT_LIMIT]
        summary = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in displayed_ports)
        omitted_count = len(sorted_open_ports) - len(displayed_ports)
        omitted = (
            f"; {omitted_count} additional open "
            f"{'port' if omitted_count == 1 else 'ports'} omitted from this summary"
            if omitted_count
            else ""
        )
        findings.append(
            make_finding(
                "NDG.PORTS.OPEN_PORTS_OBSERVED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={
                    "host": host,
                    "count": len(sorted_open_ports),
                    "ports": summary,
                    "omitted": omitted,
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The listed TCP connection attempts completed successfully.",
            )
        )
    else:
        reachable = any(result["state"] == "closed" for result in results.values())
        findings.append(
            make_finding(
                (
                    "NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE"
                    if reachable
                    else "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED"
                ),
                Severity.INFO if reachable else Severity.WARN,
                OutcomeStatus.INFORMATIONAL if reachable else OutcomeStatus.INCONCLUSIVE,
                parameters={"host": host},
                confidence=ConfidenceLevel.HIGH if reachable else ConfidenceLevel.MEDIUM,
                rationale=(
                    "At least one target port actively refused a TCP connection."
                    if reachable
                    else "No tested port completed or actively refused a TCP connection."
                ),
            )
        )

    return findings, {
        "host": host,
        "ports": {str(port): results[port] for port in sorted(results)},
        "open": sorted(open_ports),
    }
