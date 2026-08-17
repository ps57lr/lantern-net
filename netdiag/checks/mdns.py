"""mDNS / Bonjour service discovery."""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import time

from netdiag.catalog import make_finding
from netdiag.checks.mdns_normalize import dedupe_mdns_records
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, which

_MAX_RECORDS = 256
_MAX_LINE_LENGTH = 1024
_MAX_CAPTURE_BYTES = 256 * 1024


def _capture_for(
    cmd: list[str],
    timeout: float,
    *,
    max_output_bytes: int = _MAX_CAPTURE_BYTES,
) -> str:
    """Capture a browser with hard time and in-flight byte limits."""

    if timeout <= 0:
        raise ValueError("capture timeout must be positive")
    if max_output_bytes < 1 or max_output_bytes > _MAX_CAPTURE_BYTES:
        raise ValueError("capture byte limit is outside the supported range")
    command_env = os.environ.copy()
    command_env["LC_ALL"] = "C"
    command_env["LANG"] = "C"
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=command_env,
    )
    if proc.stdout is None:
        _stop_process(proc)
        return ""
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(proc.stdout.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ)
        eof = False
        while not eof and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            events = selector.select(min(0.1, remaining))
            if not events and proc.poll() is not None:
                events = selector.select(0)
                if not events:
                    break
            for key, _mask in events:
                while True:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 8192)
                    except BlockingIOError:
                        break
                    if not chunk:
                        eof = True
                        break
                    room = max_output_bytes - len(output)
                    output.extend(chunk[:room])
                    if len(chunk) > room or len(output) >= max_output_bytes:
                        _stop_process(proc)
                        eof = True
                        break
        if proc.poll() is None:
            _stop_process(proc)
    finally:
        selector.close()
        try:
            proc.stdout.close()
        except OSError:
            pass
        _stop_process(proc)
    if not output:
        return ""
    return bytes(output).decode("utf-8", errors="replace")


def _stop_process(proc: subprocess.Popen[bytes]) -> None:
    """Stop and reap one collector process without relying on pipe draining."""

    if proc.poll() is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=1)


def browse_mdns(osinfo: OSInfo, timeout: float = 5.0) -> tuple[list[Finding], dict]:
    services: list[dict] = []
    findings: list[Finding] = []
    browse_failed = False

    if osinfo.is_mac and which("dns-sd"):
        try:
            text = _capture_for(["dns-sd", "-B", "_services._dns-sd._udp", "local."], timeout)
            for line in text.splitlines():
                if len(services) >= _MAX_RECORDS:
                    break
                if len(line) > _MAX_LINE_LENGTH:
                    continue
                m = re.search(r"Add\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+?)\s*$", line)
                if m:
                    services.append({"type": m.group(1)})
        except (subprocess.SubprocessError, OSError) as exc:
            browse_failed = True
            findings.append(
                make_finding(
                    "NDG.MDNS.BROWSE_FAILED",
                    Severity.WARN,
                    OutcomeStatus.INCONCLUSIVE,
                    confidence=ConfidenceLevel.HIGH,
                    rationale=f"The bounded collector raised {type(exc).__name__}.",
                )
            )
    elif osinfo.is_linux and which("avahi-browse"):
        try:
            text = _capture_for(["avahi-browse", "-atr"], timeout)
            for line in text.splitlines():
                if len(services) >= _MAX_RECORDS:
                    break
                if len(line) > _MAX_LINE_LENGTH:
                    continue
                if not line.startswith(("+", "=")):
                    continue
                # "+ eth0 IPv4 Hostname _service._tcp local" (optional [MAC] before service)
                m = re.search(
                    r"^\+\s+\S+\s+IPv4\s+(.+?)\s+(_\S+)\s+local\s*$",
                    line,
                )
                if m:
                    services.append({"instance": m.group(1), "type": m.group(2)})
                    continue
                if ";IPv4;" in line:
                    parts = line.split(";")
                    if len(parts) >= 5:
                        services.append({"type": parts[4], "instance": parts[3]})
        except (subprocess.SubprocessError, OSError) as exc:
            browse_failed = True
            findings.append(
                make_finding(
                    "NDG.MDNS.BROWSE_FAILED",
                    Severity.WARN,
                    OutcomeStatus.INCONCLUSIVE,
                    confidence=ConfidenceLevel.HIGH,
                    rationale=f"The bounded collector raised {type(exc).__name__}.",
                )
            )
    else:
        findings.append(
            make_finding(
                "NDG.MDNS.UNSUPPORTED",
                Severity.INFO,
                OutcomeStatus.UNSUPPORTED,
                confidence=ConfidenceLevel.HIGH,
                rationale="No supported platform service-discovery command was available.",
            )
        )
        return findings, {
            "services": [],
            "raw_count": 0,
            "unique_count": 0,
            "collector_status": "unsupported",
        }

    unique_services = dedupe_mdns_records(services)
    if browse_failed:
        return findings, {
            "services": unique_services,
            "raw_count": len(services),
            "unique_count": len(unique_services),
            "collector_status": "failed",
        }
    if unique_services:
        types = sorted({service["type"] for service in unique_services})[:15]
        findings.append(
            make_finding(
                "NDG.MDNS.SERVICES_DISCOVERED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={
                    "count": len(unique_services),
                    "types": ", ".join(types) + ("…" if len(unique_services) > 15 else ""),
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="Service advertisements were parsed and normalized within the window.",
            )
        )
    else:
        findings.append(
            make_finding(
                "NDG.MDNS.NO_SERVICES_OBSERVED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                confidence=ConfidenceLevel.MEDIUM,
                rationale="No advertisement was parsed during the bounded browse window.",
            )
        )

    return findings, {
        "services": unique_services,
        "raw_count": len(services),
        "unique_count": len(unique_services),
        "collector_status": "completed",
    }
