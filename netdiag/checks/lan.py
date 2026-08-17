"""Local LAN discovery via ARP and optional ping sweep."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import subprocess

from netdiag.catalog import make_finding
from netdiag.checks.routing import get_routes, primary_lan_network
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, run_ok, which

_INCOMPLETE_MACS = {"", "(incomplete)", "<incomplete>", "incomplete", "failed"}
_MAC_COMPONENT = re.compile(r"^[0-9a-f]{1,2}$", re.IGNORECASE)
_MAX_ACTIVE_HOSTS = 4096


def normalize_neighbor_ipv4(value: object) -> str | None:
    """Return a canonical IPv4 neighbor address or reject the value."""

    if not isinstance(value, str) or value != value.strip():
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return None
    if int(address) == (1 << 32) - 1:
        return None
    return str(address)


def normalize_neighbor_mac(value: object) -> str | None:
    """Return a canonical unicast EUI-48 value or a reviewed incomplete marker."""

    if not isinstance(value, str) or value != value.strip():
        return None
    lowered = value.lower()
    if lowered in _INCOMPLETE_MACS:
        return "(incomplete)"
    parts = re.split(r"[:-]", lowered)
    if len(parts) != 6 or any(not _MAC_COMPONENT.fullmatch(part) for part in parts):
        return None
    octets = bytes(int(part, 16) for part in parts)
    if octets == bytes(6) or octets == bytes([0xFF]) * 6 or octets[0] & 1:
        return None
    return ":".join(f"{octet:02x}" for octet in octets)


def _normalized_hostname(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        return "?"
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        return "?"
    return value


def _validated_neighbor(host: object) -> dict | None:
    if not isinstance(host, dict):
        return None
    address = normalize_neighbor_ipv4(host.get("ip"))
    mac = normalize_neighbor_mac(host.get("mac", "(incomplete)"))
    if address is None or mac is None:
        return None
    normalized: dict = {"ip": address, "mac": mac}
    if "hostname" in host:
        normalized["hostname"] = _normalized_hostname(host["hostname"])
    if "ifindex" in host:
        ifindex = host["ifindex"]
        if isinstance(ifindex, int) and not isinstance(ifindex, bool) and ifindex > 0:
            normalized["ifindex"] = ifindex
    return normalized


def parse_arp_legacy_table(text: str) -> list[dict]:
    """Parse macOS `arp -a` legacy output."""
    hosts: list[dict] = []
    for line in text.splitlines():
        match = re.match(r"(\?\S+|\S+)\s+\(([^)]+)\)\s+at\s+(\S+)", line)
        if match:
            neighbor = _validated_neighbor(
                {"hostname": match.group(1), "ip": match.group(2), "mac": match.group(3)}
            )
            if neighbor is not None:
                hosts.append(neighbor)
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
        ip = normalize_neighbor_ipv4(hostname)
        if ip is None:
            match = re.search(r"\(([^)]+)\)", line)
            if match:
                ip = normalize_neighbor_ipv4(match.group(1))
            else:
                continue
        neighbor = _validated_neighbor({"hostname": hostname, "ip": ip, "mac": parts[1]})
        if neighbor is not None:
            hosts.append(neighbor)
    return hosts


def parse_linux_neigh(text: str, *, interface: str | None = None) -> list[dict]:
    hosts: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            dev_index = parts.index("dev")
        except ValueError:
            continue
        if dev_index + 1 >= len(parts) or (
            interface is not None and parts[dev_index + 1] != interface
        ):
            continue
        try:
            mac_index = parts.index("lladdr")
        except ValueError:
            mac = "(incomplete)"
        else:
            if mac_index + 1 >= len(parts):
                continue
            mac = parts[mac_index + 1]
        neighbor = _validated_neighbor({"ip": parts[0], "mac": mac, "hostname": "?"})
        if neighbor is not None:
            hosts.append(neighbor)
    return hosts


def filter_neighbors(
    hosts: list[dict],
    *,
    network: ipaddress.IPv4Network | None,
    ifindex: int | None = None,
) -> list[dict]:
    filtered: list[dict] = []
    for host in hosts:
        normalized = _validated_neighbor(host)
        if normalized is None:
            continue
        if ifindex is not None and normalized.get("ifindex") != ifindex:
            continue
        if network is not None and ipaddress.ip_address(normalized["ip"]) not in network:
            continue
        filtered.append(normalized)
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
    if (
        not isinstance(max_hosts, int)
        or isinstance(max_hosts, bool)
        or not 1 <= max_hosts <= _MAX_ACTIVE_HOSTS
    ):
        raise ValueError(f"max_hosts must be from 1 to {_MAX_ACTIVE_HOSTS}")
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
    if (
        not isinstance(max_hosts, int)
        or isinstance(max_hosts, bool)
        or not 1 <= max_hosts <= _MAX_ACTIVE_HOSTS
    ):
        raise ValueError(f"max_hosts must be from 1 to {_MAX_ACTIVE_HOSTS}")
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
            make_finding(
                "NDG.LAN.NEIGHBOR_CACHE_READ",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={
                    "count": len(arp),
                    "interface": default_iface or "primary LAN",
                    "addresses": detail_ips or "No cached neighbors were in scope.",
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform neighbor cache was read and scoped to the primary LAN.",
            )
        )
    elif arp_status in {"partial", "empty"}:
        findings.append(
            make_finding(
                "NDG.LAN.NEIGHBOR_CACHE_PARTIAL",
                Severity.INFO,
                OutcomeStatus.INCONCLUSIVE,
                parameters={
                    "cache_status": arp_status,
                    "reason": arp_detail or "Neighbor cache could not be read completely.",
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform neighbor adapter reported partial or empty coverage.",
            )
        )
    else:
        findings.append(
            make_finding(
                "NDG.LAN.NEIGHBOR_CACHE_FAILED",
                Severity.WARN,
                OutcomeStatus.INCONCLUSIVE,
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform neighbor adapter reported an execution error.",
            )
        )

    if do_ping:
        if network is None:
            findings.append(
                make_finding(
                    "NDG.LAN.ACTIVE_DISCOVERY_NO_SCOPE",
                    Severity.WARN,
                    OutcomeStatus.NOT_TESTED,
                    confidence=ConfidenceLevel.HIGH,
                    rationale="No bounded primary LAN network was available for active discovery.",
                )
            )
        else:
            try:
                alive = ping_sweep(network, max_hosts=max_hosts)
            except ValueError:
                findings.append(
                    make_finding(
                        "NDG.LAN.ACTIVE_DISCOVERY_SCOPE_TOO_LARGE",
                        Severity.WARN,
                        OutcomeStatus.NOT_TESTED,
                        confidence=ConfidenceLevel.HIGH,
                        rationale="The computed host count exceeded the configured safety limit.",
                    )
                )
            else:
                data["ping_alive"] = alive
                findings.append(
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
                )

    macs_by_ip: dict[str, set[str]] = {}
    for host in arp:
        mac = host.get("mac", "").lower()
        if mac not in _INCOMPLETE_MACS:
            macs_by_ip.setdefault(host["ip"], set()).add(mac)
    conflicts = {ip: macs for ip, macs in macs_by_ip.items() if len(macs) > 1}
    if conflicts:
        findings.append(
            make_finding(
                "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED",
                Severity.WARN,
                OutcomeStatus.DEGRADED,
                parameters={
                    "conflicts": "; ".join(
                        f"{ip}: {', '.join(sorted(macs))}" for ip, macs in conflicts.items()
                    )
                },
                confidence=ConfidenceLevel.MEDIUM,
                rationale="The same IP address appeared with multiple hardware addresses.",
            )
        )

    return findings, data
