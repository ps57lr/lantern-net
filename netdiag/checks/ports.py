"""TCP port checks for common services."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from netdiag.findings import Finding, Severity

COMMON_PORTS: dict[int, str] = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
}


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


def scan_ports(host: str, ports: list[int] | None = None, timeout: float = 2.0) -> tuple[list[Finding], dict]:
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
        summary = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in sorted(open_ports))
        findings.append(
            Finding(
                Severity.INFO,
                "ports",
                f"{host}: {len(open_ports)} open port(s)",
                summary,
            )
        )
    else:
        reachable = any(result["state"] == "closed" for result in results.values())
        findings.append(
            Finding(
                Severity.INFO if reachable else Severity.WARN,
                "ports",
                f"{host}: no tested ports open",
                (
                    "The host actively refused a connection, so it is reachable."
                    if reachable
                    else "The host may be offline, unreachable, or filtering probes."
                ),
            )
        )

    return findings, {
        "host": host,
        "ports": {port: results[port] for port in sorted(results)},
        "open": sorted(open_ports),
    }
