"""mDNS / Bonjour service discovery."""

from __future__ import annotations

import re
import subprocess

from netdiag.checks.mdns_normalize import dedupe_mdns_records
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, which


def _capture_for(cmd: list[str], timeout: float) -> str:
    """Capture a long-running browser for a bounded interval."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        raw, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            raw, _ = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            raw, _ = proc.communicate()
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def browse_mdns(osinfo: OSInfo, timeout: float = 5.0) -> tuple[list[Finding], dict]:
    services: list[dict] = []
    findings: list[Finding] = []

    if osinfo.is_mac and which("dns-sd"):
        try:
            text = _capture_for(["dns-sd", "-B", "_services._dns-sd._udp", "local."], timeout)
            for line in text.splitlines():
                m = re.search(r"Add\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+?)\s*$", line)
                if m:
                    services.append({"type": m.group(1)})
        except (subprocess.SubprocessError, OSError) as exc:
            findings.append(
                Finding(
                    Severity.WARN,
                    "mdns",
                    "mDNS browse failed",
                    str(exc)[:120],
                )
            )
    elif osinfo.is_linux and which("avahi-browse"):
        try:
            text = _capture_for(["avahi-browse", "-atr"], timeout)
            for line in text.splitlines():
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
            findings.append(Finding(Severity.WARN, "mdns", "avahi-browse failed", str(exc)))
    else:
        findings.append(
            Finding(
                Severity.INFO,
                "mdns",
                "mDNS browse skipped",
                "Install avahi-utils on Linux; dns-sd is built into macOS.",
            )
        )
        return findings, {"services": [], "raw_count": 0, "unique_count": 0}

    unique_services = dedupe_mdns_records(services)
    if unique_services:
        types = sorted({service["type"] for service in unique_services})[:15]
        findings.append(
            Finding(
                Severity.INFO,
                "mdns",
                f"Found {len(unique_services)} unique mDNS service advertisement(s)",
                ", ".join(types) + ("…" if len(unique_services) > 15 else ""),
            )
        )
    else:
        findings.append(
            Finding(
                Severity.INFO,
                "mdns",
                "No mDNS services seen (brief scan)",
                "Normal if scan timed out quickly.",
            )
        )

    return findings, {
        "services": unique_services,
        "raw_count": len(services),
        "unique_count": len(unique_services),
    }
