"""mDNS / Bonjour service discovery."""

from __future__ import annotations

import re
import subprocess

from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, which


def _capture_for(cmd: list[str], timeout: float) -> str:
    """Capture a long-running browser for a bounded interval."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
    return output or ""


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
                if line.startswith("=") and ";IPv4;" in line:
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
        return findings, {"services": services}

    if services:
        types = sorted({s["type"] for s in services})[:15]
        findings.append(
            Finding(
                Severity.INFO,
                "mdns",
                f"Found {len(services)} mDNS service advertisement(s)",
                ", ".join(types) + ("…" if len(services) > 15 else ""),
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

    return findings, {"services": services}
