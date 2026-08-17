"""Local LAN discovery via ARP and optional ping sweep."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import subprocess

from netdiag.checks.routing import local_ipv4_networks
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, run_ok, which


def parse_arp_table(osinfo: OSInfo) -> list[dict]:
    hosts: list[dict] = []
    if osinfo.is_mac:
        text = run_ok(["arp", "-a"], timeout=10)
        for line in text.splitlines():
            m = re.match(r"(\?\S+|\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)", line)
            if m:
                hosts.append({"hostname": m.group(1), "ip": m.group(2), "mac": m.group(3)})
    else:
        text = run_ok(["ip", "neigh"], timeout=10)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].count(".") == 3:
                hosts.append({"ip": parts[0], "mac": parts[4], "hostname": "?"})
    return hosts


def _ping_one(ip: str, timeout: float = 1.0) -> str | None:
    if not which("ping"):
        return None
    import sys

    if sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(max(1, int(timeout))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=timeout + 2, check=False)
        return ip if cp.returncode == 0 else None
    except (subprocess.SubprocessError, OSError):
        return None


def ping_sweep(network: ipaddress.IPv4Network, *, max_hosts: int = 256) -> list[str]:
    host_count = max(0, network.num_addresses - 2)
    if host_count > max_hosts:
        raise ValueError(f"{network} has {host_count} hosts; safety limit is {max_hosts}")
    hosts = list(network.hosts())
    alive: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futs = {pool.submit(_ping_one, str(h)): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs, timeout=120):
            ip = fut.result()
            if ip:
                alive.append(ip)
    return sorted(alive, key=lambda x: ipaddress.ip_address(x))


def scan_lan(
    osinfo: OSInfo, *, do_ping: bool = False, max_hosts: int = 256
) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    arp = parse_arp_table(osinfo)
    nets = local_ipv4_networks(osinfo)
    data: dict = {"networks": [str(n) for n in nets], "arp": arp, "ping_alive": []}

    findings.append(
        Finding(
            Severity.INFO,
            "lan",
            f"ARP table: {len(arp)} entries",
            ", ".join(n["ip"] for n in arp[:8]) + ("…" if len(arp) > 8 else ""),
        )
    )

    if do_ping and nets:
        net = nets[0]
        try:
            alive = ping_sweep(net, max_hosts=max_hosts)
        except ValueError as exc:
            findings.append(
                Finding(
                    Severity.WARN,
                    "lan",
                    "Ping sweep skipped for a large network",
                    str(exc),
                    hint="Narrow the scan scope before actively probing an enterprise network.",
                )
            )
        else:
            data["ping_alive"] = alive
            findings.append(
                Finding(
                    Severity.INFO,
                    "lan",
                    f"Ping sweep {net}: {len(alive)} hosts responded",
                    ", ".join(alive[:12]) + ("…" if len(alive) > 12 else ""),
                )
            )

    # Flag duplicate IPs in ARP (possible conflict)
    macs_by_ip: dict[str, set[str]] = {}
    for host in arp:
        mac = host.get("mac", "").lower()
        if mac not in {"", "(incomplete)", "incomplete", "failed"}:
            macs_by_ip.setdefault(host["ip"], set()).add(mac)
    conflicts = {ip: macs for ip, macs in macs_by_ip.items() if len(macs) > 1}
    if conflicts:
        findings.append(
            Finding(
                Severity.WARN,
                "lan",
                "Possible duplicate IP address",
                "; ".join(f"{ip}: {', '.join(sorted(macs))}" for ip, macs in conflicts.items()),
                hint="Confirm DHCP reservations and static address assignments.",
            )
        )

    return findings, data
