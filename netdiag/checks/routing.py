"""Routing, interfaces, and gateway checks."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass

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

    if osinfo.is_mac:
        text = run_ok(["route", "-n", "get", "default"], timeout=10)
        gateway = first_match(r"^\s*gateway:\s*(\d+\.\d+\.\d+\.\d+)", text)
        iface = first_match(r"^\s*interface:\s*(\S+)", text)
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
                        networks.append(str(ipaddress.ip_network(f"{address}/{mask}", strict=False)))
                    except ValueError:
                        continue
                interfaces.append(Interface(name, addrs, state, networks))
    else:
        text = run_ok(["ip", "-4", "route"], timeout=10)
        gateway = first_match(r"default via (\d+\.\d+\.\d+\.\d+)", text)
        iface = first_match(r"default via \d+\.\d+\.\d+\.\d+ dev (\S+)", text)
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
                interfaces.append(Interface(name, addrs, "up" if "UP" in block else "down", networks))

    return RouteInfo(gateway, iface, interfaces)


def local_ipv4_networks(osinfo: OSInfo) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    routes = get_routes(osinfo)
    for iface in routes.interfaces:
        for network in iface.networks or []:
            try:
                net = ipaddress.ip_network(network, strict=False)
                if net.is_private and not net.is_loopback and not net.is_link_local:
                    nets.append(net)
            except ValueError:
                continue
    return list(dict.fromkeys(nets))


def check_routing(osinfo: OSInfo) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    routes = get_routes(osinfo)
    data = {
        "default_gateway": routes.default_gateway,
        "default_interface": routes.default_iface,
        "interfaces": [
            {
                "name": i.name,
                "addresses": i.addresses,
                "networks": i.networks or [],
                "state": i.state,
            }
            for i in routes.interfaces
        ],
    }

    if not routes.default_gateway:
        findings.append(
            Finding(
                Severity.CRIT,
                "route",
                "No default gateway",
                "This machine has no default route — no internet.",
                hint="Check cable/Wi‑Fi association and DHCP.",
            )
        )
        return findings, data

    ok, ping_out = _ping_host(routes.default_gateway, count=3)
    data["gateway_ping"] = {"ok": ok, "output": ping_out}
    gateway_ping_ok = ok

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
            Finding(
                Severity.OK,
                "route",
                "Outbound TCP/443 works",
                f"Internet path appears up via {tcp_target}.",
            )
        )
    else:
        findings.append(
            Finding(
                Severity.WARN,
                "route",
                "Outbound TCP/443 failed",
                "; ".join(f"{host}: {error}" for host, error in tcp_attempts.items()),
                hint="Check firewall, captive portal, or WAN outage.",
            )
        )

    internet_ok = bool(data["tcp_443"])
    if gateway_ping_ok:
        findings.insert(
            0,
            Finding(
                Severity.OK,
                "route",
                f"Default gateway reachable ({routes.default_gateway})",
                f"Via {routes.default_iface or 'unknown interface'}",
            ),
        )
    else:
        findings.insert(
            0,
            Finding(
                Severity.INFO if internet_ok else Severity.WARN,
                "route",
                f"Default gateway did not answer ping ({routes.default_gateway})",
                ping_out,
                hint=(
                    "Internet still works; the router likely blocks ICMP."
                    if internet_ok
                    else "Check the router, local link, VLAN, and DHCP settings."
                ),
            ),
        )

    for label, host, ping_ok, out in ping_results:
        if not ping_ok:
            findings.append(
                Finding(
                    Severity.INFO if internet_ok else Severity.WARN,
                    "route",
                    f"Cannot ping {label} ({host})",
                    out[:300],
                    hint="ICMP may be blocked; TCP and DNS checks are more conclusive.",
                )
            )

    return findings, data
