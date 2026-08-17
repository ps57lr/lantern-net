"""Routing, interfaces, and gateway checks."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass

from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, first_match, run, run_ok, which


@dataclass
class Interface:
    name: str
    addresses: list[str]
    state: str = "unknown"
    networks: list[str] | None = None


@dataclass
class RouteInfo:
    default_gateway: str | None
    default_iface: str | None
    interfaces: list[Interface]
    has_default_route: bool | None = None


def _ping_host(host: str, count: int = 3) -> tuple[bool, str]:
    if which("ping"):
        flag = "-c" if not __import__("sys").platform.startswith("win") else "-n"
        try:
            cp = run(["ping", flag, str(count), host], timeout=count * 3 + 5)
            ok = cp.returncode == 0
            summary = (cp.stdout or cp.stderr or "").splitlines()[-3:]
            return ok, "\n".join(summary)
        except (subprocess.SubprocessError, OSError) as exc:
            return False, str(exc)
    return False, "ping not found"


def get_routes(osinfo: OSInfo) -> RouteInfo:
    interfaces: list[Interface] = []
    gateway: str | None = None
    iface: str | None = None
    has_default_route = False

    if osinfo.is_mac:
        text = run_ok(["route", "-n", "get", "default"], timeout=10)
        gateway = first_match(r"^\s*gateway:\s*(\d+\.\d+\.\d+\.\d+)", text)
        iface = first_match(r"^\s*interface:\s*(\S+)", text)
        has_default_route = bool(gateway or iface)
        if_text = run_ok(["ifconfig"], timeout=10)
        for block in re.split(r"\n(?=\S)", if_text):
            name = block.split(":")[0].split()[0]
            addrs = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", block)
            if addrs:
                state = "up" if "status: active" in block or "UP" in block else "down"
                networks: list[str] = []
                for address, mask in re.findall(
                    r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)",
                    block,
                ):
                    try:
                        if mask.startswith("0x"):
                            mask = str(ipaddress.IPv4Address(int(mask, 16)))
                        networks.append(
                            str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
                        )
                    except ValueError:
                        continue
                interfaces.append(Interface(name, addrs, state, networks))
    else:
        text = run_ok(["ip", "-4", "route"], timeout=10)
        default_line = first_match(r"^(default\b.*)$", text)
        has_default_route = default_line is not None
        if default_line:
            gateway = first_match(r"\bvia (\d+\.\d+\.\d+\.\d+)", default_line)
            iface = first_match(r"\bdev (\S+)", default_line)
        addr_text = run_ok(["ip", "-4", "addr"], timeout=10)
        for block in re.split(r"\n(?=\d+:)", addr_text):
            m = re.match(r"\d+:\s+(\S+?):", block)
            if not m:
                continue
            name = m.group(1)
            cidrs = re.findall(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", block)
            addrs = [cidr.split("/", 1)[0] for cidr in cidrs]
            if addrs and name != "lo":
                networks = []
                for cidr in cidrs:
                    try:
                        networks.append(str(ipaddress.ip_network(cidr, strict=False)))
                    except ValueError:
                        continue
                interfaces.append(
                    Interface(name, addrs, "up" if "UP" in block else "down", networks)
                )

    return RouteInfo(gateway, iface, interfaces, has_default_route)


def is_virtual_bridge_interface(name: str) -> bool:
    lower = name.lower()
    return lower == "docker0" or lower.startswith(("br-", "virbr"))


def _private_ipv4_network(network: str) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return None
    if net.is_private and not net.is_loopback and not net.is_link_local:
        return net
    return None


def primary_lan_network(osinfo: OSInfo) -> ipaddress.IPv4Network | None:
    """Return the IPv4 network for the default route interface."""
    routes = get_routes(osinfo)
    if routes.default_iface:
        for iface in routes.interfaces:
            if iface.name != routes.default_iface:
                continue
            for network in iface.networks or []:
                net = _private_ipv4_network(network)
                if net is not None:
                    return net
    for iface in routes.interfaces:
        if is_virtual_bridge_interface(iface.name):
            continue
        for network in iface.networks or []:
            net = _private_ipv4_network(network)
            if net is not None:
                return net
    return None


def local_ipv4_networks(osinfo: OSInfo) -> list[ipaddress.IPv4Network]:
    primary = primary_lan_network(osinfo)
    return [primary] if primary is not None else []


def check_routing(osinfo: OSInfo, *, network_probes: bool = True) -> tuple[list[Finding], dict]:
    """Inspect routing state and, when authorized, test bounded connectivity.

    ``network_probes=False`` is the passive contract used by Lantern's
    consent-bound application runtime.  It reads only local route/interface
    state and returns before any gateway or public ICMP/TCP traffic can be
    emitted.  The default remains ``True`` for the explicitly-invoked legacy
    CLI route command.
    """

    if not isinstance(network_probes, bool):
        raise TypeError("network_probes must be a boolean")
    findings: list[Finding] = []
    routes = get_routes(osinfo)
    has_default_route = (
        routes.has_default_route
        if routes.has_default_route is not None
        else bool(routes.default_gateway or routes.default_iface)
    )
    data = {
        "default_gateway": routes.default_gateway,
        "default_interface": routes.default_iface,
        "has_default_route": has_default_route,
        "interfaces": [
            {
                "name": i.name,
                "addresses": i.addresses,
                "networks": i.networks or [],
                "state": i.state,
            }
            for i in routes.interfaces
        ],
        "network_probes": network_probes,
    }

    if not has_default_route:
        findings.append(
            make_finding(
                "NDG.ROUTE.DEFAULT_ROUTE_MISSING",
                Severity.CRIT,
                OutcomeStatus.FAILED,
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform route table contained no default route.",
            )
        )
        return findings, data

    if not network_probes:
        data["connectivity_status"] = "not_run"
        return findings, data

    gateway_ping_ok: bool | None = None
    ping_out = ""
    if routes.default_gateway:
        gateway_ping_ok, ping_out = _ping_host(routes.default_gateway, count=3)
        data["gateway_ping"] = {"ok": gateway_ping_ok, "output": ping_out}
    else:
        data["gateway_ping"] = {
            "ok": None,
            "output": "No next-hop address is present on this default route.",
        }

    # External connectivity
    ping_results: list[tuple[str, str, bool, str]] = []
    for label, host in [("Cloudflare DNS", "1.1.1.1"), ("Google DNS", "8.8.8.8")]:
        ok, out = _ping_host(host, count=2)
        data[f"ping_{host}"] = ok
        ping_results.append((label, host, ok, out))

    tcp_attempts: dict[str, str] = {}
    tcp_target: str | None = None
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((host, 443), timeout=4):
                tcp_target = host
                break
        except OSError as exc:
            tcp_attempts[host] = str(exc)
    data["tcp_443"] = tcp_target is not None
    data["tcp_443_target"] = tcp_target
    data["tcp_443_errors"] = tcp_attempts
    if tcp_target:
        findings.append(
            make_finding(
                "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={"target": tcp_target},
                confidence=ConfidenceLevel.HIGH,
                rationale="A TCP connection to a public endpoint completed.",
            )
        )
    else:
        findings.append(
            make_finding(
                "NDG.ROUTE.OUTBOUND_HTTPS_FAILED",
                Severity.WARN,
                OutcomeStatus.DEGRADED,
                confidence=ConfidenceLevel.MEDIUM,
                rationale="Both bounded TCP connection attempts failed.",
            )
        )

    internet_ok = bool(data["tcp_443"])
    if gateway_ping_ok is True:
        findings.insert(
            0,
            make_finding(
                "NDG.ROUTE.GATEWAY_REACHABLE",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={
                    "gateway": routes.default_gateway,
                    "interface": routes.default_iface or "unknown interface",
                },
                confidence=ConfidenceLevel.HIGH,
                rationale="The default gateway answered an ICMP echo probe.",
            ),
        )
    elif gateway_ping_ok is False:
        gateway_code = (
            "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP"
            if internet_ok
            else "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED"
        )
        findings.insert(
            0,
            make_finding(
                gateway_code,
                Severity.INFO if internet_ok else Severity.WARN,
                OutcomeStatus.INCONCLUSIVE if internet_ok else OutcomeStatus.DEGRADED,
                parameters={"gateway": routes.default_gateway},
                confidence=ConfidenceLevel.HIGH if internet_ok else ConfidenceLevel.MEDIUM,
                rationale="Gateway ICMP did not answer and was compared with the TCP path.",
            ),
        )
    else:
        findings.insert(
            0,
            make_finding(
                "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"interface": routes.default_iface or "unknown interface"},
                confidence=ConfidenceLevel.HIGH,
                rationale="The default route had an interface but no explicit next-hop address.",
            ),
        )

    for label, host, ping_ok, out in ping_results:
        if not ping_ok:
            ping_code = (
                "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP"
                if internet_ok
                else "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED"
            )
            findings.append(
                make_finding(
                    ping_code,
                    Severity.INFO if internet_ok else Severity.WARN,
                    OutcomeStatus.INCONCLUSIVE if internet_ok else OutcomeStatus.DEGRADED,
                    parameters={"label": label, "target": host},
                    confidence=ConfidenceLevel.HIGH if internet_ok else ConfidenceLevel.MEDIUM,
                    rationale="ICMP behavior was compared with a bounded TCP connection test.",
                )
            )

    return findings, data
