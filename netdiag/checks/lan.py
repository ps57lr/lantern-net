"""Local LAN discovery via ARP and optional ping sweep."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import subprocess

from netdiag.checks.routing import get_routes, primary_lan_network
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, run_ok, which

_INCOMPLETE_MACS = {"", "(incomplete)", "incomplete", "failed"}


def parse_arp_legacy_table(text: str) -> list[dict]:
    """Parse macOS `arp -a` legacy output."""
    hosts: list[dict] = []
    for line in text.splitlines():
        match = re.match(r"(\?\S+|\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)", line)
        if match:
            hosts.append(
                {
                    "hostname": match.group(1),
                    "ip": match.group(2),
                    "mac": match.group(3),
                }
            )
    return hosts


def parse_arp_table_output(text: str) -> list[dict]:
    """Parse macOS `arp -l -a` table output."""
    hosts: list[dict] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("Neighbor"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        hostname = parts[0]
        mac = parts[1]
        ip = hostname
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if match:
                ip = match.group(1)
            else:
                continue
        hosts.append({"hostname": hostname, "ip": ip, "mac": mac})
    return hosts


def parse_linux_neigh(text: str, *, interface: str | None = None) -> list[dict]:
    hosts: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].count(".") != 3:
            continue
        if interface is not None:
            try:
                dev_index = parts.index("dev")
            except ValueError:
                continue
            if parts[dev_index + 1] != interface:
                continue
        hosts.append({"ip": parts[0], "mac": parts[4], "hostname": "?"})
    return hosts


def filter_neighbors(
    hosts: list[dict],
    *,
    network: ipaddress.IPv4Network | None,
    ifindex: int | None = None,
) -> list[dict]:
    filtered: list[dict] = []
    for host in hosts:
        if ifindex is not None and host.get("ifindex") not in {None, ifindex}:
            continue
        if network is not None:
            try:
                if ipaddress.ip_address(host["ip"]) not in network:
                    continue
            except ValueError:
                continue
        filtered.append(host)
    return filtered


def _resolve_ifindex(name: str | None) -> int | None:
    if not name:
        return None
    try:
        return int(__import__("socket").if_nametoindex(name))
    except OSError:
        return None


def _collect_arp(osinfo: OSInfo, *, interface: str | None) -> tuple[list[dict], str, str, str]:
    if osinfo.is_mac:
        from netdiag.checks.arp_macos import probe_arp_table

        probe = probe_arp_table()
        entries = [
            {
                "hostname": entry.get("hostname", "?"),
                "ip": entry["ip"],
                "mac": entry.get("mac", "(incomplete)"),
                "ifindex": entry.get("ifindex"),
            }
            for entry in probe.entries
        ]
        return entries, probe.source, probe.status, probe.detail

    text = run_ok(["ip", "neigh"], timeout=10)
    entries = parse_linux_neigh(text, interface=interface)
    if not text.strip() or text.startswith("(command failed"):
        return [], "ip_neigh", "error", text.strip() or "ip neigh returned no data"
    return entries, "ip_neigh", "ok", ""


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
        futs = {pool.submit(_ping_one, str(host)): host for host in hosts}
        for fut in concurrent.futures.as_completed(futs, timeout=120):
            ip = fut.result()
            if ip:
                alive.append(ip)
    return sorted(alive, key=lambda x: ipaddress.ip_address(x))


def scan_lan(
    osinfo: OSInfo, *, do_ping: bool = False, max_hosts: int = 256
) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    routes = get_routes(osinfo)
    default_iface = routes.default_iface
    network = primary_lan_network(osinfo)
    ifindex = _resolve_ifindex(default_iface)

    arp, arp_source, arp_status, arp_detail = _collect_arp(osinfo, interface=default_iface)
    arp = filter_neighbors(arp, network=network, ifindex=ifindex if osinfo.is_mac else None)

    data: dict = {
        "default_interface": default_iface,
        "network": str(network) if network is not None else None,
        "networks": [str(network)] if network is not None else [],
        "arp_source": arp_source,
        "arp_status": arp_status,
        "arp_detail": arp_detail,
        "arp": arp,
        "ping_alive": [],
    }

    if arp_status == "ok":
        detail_ips = ", ".join(entry["ip"] for entry in arp[:8])
        if len(arp) > 8:
            detail_ips += "…"
        findings.append(
            Finding(
                Severity.INFO,
                "lan",
                f"ARP table: {len(arp)} entries on {default_iface or 'primary LAN'}",
                detail_ips,
            )
        )
    elif arp_status in {"partial", "empty"}:
        findings.append(
            Finding(
                Severity.INFO,
                "lan",
                f"ARP table unavailable or incomplete ({arp_status})",
                arp_detail or "Neighbor cache could not be read completely.",
            )
        )
    else:
        findings.append(
            Finding(
                Severity.WARN,
                "lan",
                "ARP table could not be read",
                arp_detail or "Neighbor discovery failed.",
                hint="Re-run `netdiag lan --json` and inspect arp_source/arp_status.",
            )
        )

    if do_ping:
        if network is None:
            findings.append(
                Finding(
                    Severity.WARN,
                    "lan",
                    "Ping sweep skipped",
                    "No primary LAN network detected on the default interface.",
                )
            )
        else:
            try:
                alive = ping_sweep(network, max_hosts=max_hosts)
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
                        f"Ping sweep {network}: {len(alive)} hosts responded",
                        ", ".join(alive[:12]) + ("…" if len(alive) > 12 else ""),
                    )
                )

    macs_by_ip: dict[str, set[str]] = {}
    for host in arp:
        mac = host.get("mac", "").lower()
        if mac not in _INCOMPLETE_MACS:
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
