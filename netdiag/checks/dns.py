"""DNS resolver discovery and comparison checks."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import time
from dataclasses import dataclass

from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, first_match, run_ok


@dataclass
class DNSAnswer:
    resolver: str
    domain: str
    addresses: list[str]
    error: str | None = None
    blocked: bool = False
    response_ms: int | None = None

    def to_dict(self) -> dict:
        return {
            "resolver": self.resolver,
            "domain": self.domain,
            "addresses": self.addresses,
            "error": self.error,
            "blocked": self.blocked,
            "response_ms": self.response_ms,
        }


def system_resolvers(osinfo: OSInfo) -> list[str]:
    resolvers: list[str] = []
    if osinfo.is_mac:
        text = run_ok(["scutil", "--dns"], timeout=10)
        for line in text.splitlines():
            if "nameserver" in line.lower():
                ip = first_match(r":\s*(\S+)", line) or first_match(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip and ip not in resolvers:
                    resolvers.append(ip)
    elif osinfo.is_linux:
        text = run_ok(["resolvectl", "status"], timeout=10)
        if "(command failed" in text:
            text = run_ok(["cat", "/etc/resolv.conf"], timeout=5)
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2 and parts[1] not in resolvers:
                    resolvers.append(parts[1])
            m = first_match(r"DNS Servers:\s*(.+)", line)
            if m:
                for ip in m.replace(",", " ").split():
                    if ip not in resolvers:
                        resolvers.append(ip)
    return resolvers[:8]


def query_via(resolver: str, domain: str, timeout: float = 3.0) -> DNSAnswer:
    """Query A records, never silently substituting a different resolver."""
    from netdiag.platform import run, which

    domain = domain.rstrip(".")
    if not domain or any(c.isspace() for c in domain):
        return DNSAnswer(resolver, domain, [], "invalid domain name")

    started = time.monotonic()
    if resolver != "system" and which("dig"):
        try:
            cp = run(
                ["dig", f"@{resolver}", "+time=2", "+tries=1", "+short", domain, "A"],
                timeout=timeout + 2,
            )
            lines = [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]
            addrs = []
            for line in lines:
                try:
                    addr = ipaddress.ip_address(line)
                except ValueError:  # Ignore CNAMEs printed by ``dig +short``.
                    continue
                if addr.version == 4:
                    addrs.append(str(addr))
            addrs = sorted(set(addrs), key=ipaddress.ip_address)
            blocked = any(_is_block_address(a) for a in addrs)
            err = None
            if cp.returncode != 0 and not addrs:
                err = (cp.stderr or cp.stdout or "dig failed").strip()[:200]
            return DNSAnswer(
                resolver, domain, addrs, err, blocked,
                round((time.monotonic() - started) * 1000),
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return DNSAnswer(
                resolver, domain, [], str(exc), False,
                round((time.monotonic() - started) * 1000),
            )

    if resolver != "system":
        return DNSAnswer(
            resolver,
            domain,
            [],
            "the 'dig' command is required to query a specific resolver",
            response_ms=round((time.monotonic() - started) * 1000),
        )

    # The stdlib can query only the system resolver.
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        addrs = sorted({item[4][0] for item in infos})
        blocked = any(_is_block_address(a) for a in addrs)
        return DNSAnswer(
            "system", domain, addrs, None, blocked,
            round((time.monotonic() - started) * 1000),
        )
    except socket.gaierror as exc:
        return DNSAnswer(
            "system", domain, [], str(exc), False,
            round((time.monotonic() - started) * 1000),
        )


def _is_block_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_unspecified or ip.is_loopback


def analyze_answers(domain: str, answers: list[DNSAnswer]) -> list[Finding]:
    """Turn resolver answers into findings without treating normal CDN variance as failure."""
    findings: list[Finding] = []
    successful = [a for a in answers if a.addresses and not a.blocked]
    failed = [a for a in answers if a.error or not a.addresses]
    blocked = [a for a in answers if a.blocked]

    if blocked:
        findings.append(
            Finding(
                Severity.WARN,
                "dns",
                f"{domain} is blocked by {len(blocked)} resolver(s)",
                ", ".join(f"{a.resolver}→{a.addresses}" for a in blocked),
                hint="This may be intentional filtering. Compare with a trusted public resolver.",
            )
        )
    if failed and successful:
        findings.append(
            Finding(
                Severity.WARN,
                "dns",
                f"{domain} resolves inconsistently",
                ", ".join(f"{a.resolver}→{a.error or 'no A record'}" for a in failed),
                hint="One resolver failed while another returned an address.",
            )
        )
    elif failed and not successful and not blocked:
        findings.append(
            Finding(
                Severity.CRIT,
                "dns",
                f"{domain} did not resolve",
                ", ".join(f"{a.resolver}→{a.error or 'no A record'}" for a in failed),
                hint="Check DNS settings, filtering, and internet connectivity.",
            )
        )

    answer_sets = {frozenset(a.addresses) for a in successful}
    if len(answer_sets) > 1:
        findings.append(
            Finding(
                Severity.INFO,
                "dns",
                f"{domain} returned different valid addresses",
                "This is commonly caused by CDNs, load balancing, or resolver location.",
            )
        )
    elif successful and not blocked and not failed:
        findings.append(
            Finding(
                Severity.OK,
                "dns",
                f"{domain} resolved successfully",
                f"Answered by {len(successful)} resolver(s).",
            )
        )
    return findings


def check_dns(osinfo: OSInfo, domains: list[str] | None = None) -> tuple[list[Finding], dict]:
    domains = domains or ["google.com", "cloudflare.com"]
    resolvers = system_resolvers(osinfo)
    findings: list[Finding] = []
    data: dict = {"resolvers": resolvers, "queries": []}

    if not resolvers:
        findings.append(
            Finding(
                Severity.CRIT,
                "dns",
                "No DNS resolvers configured",
                "System reports no nameservers.",
                hint="Check Wi‑Fi/Ethernet settings or DHCP.",
            )
        )
        return findings, data

    findings.append(
        Finding(
            Severity.INFO,
            "dns",
            f"System DNS resolvers: {', '.join(resolvers)}",
            "Order matters — the first resolver is tried first.",
        )
    )

    from netdiag.platform import which

    query_resolvers = resolvers[:3] if which("dig") else ["system"]
    for domain in domains:
        answers = [query_via(r, domain) for r in query_resolvers]
        data["queries"].append(
            {
                "domain": domain,
                "answers": [a.to_dict() for a in answers],
            }
        )
        findings.extend(analyze_answers(domain, answers))

    return findings, data


def compare_resolvers(domain: str, resolvers: list[str]) -> list[DNSAnswer]:
    return [query_via(r, domain) for r in resolvers]
