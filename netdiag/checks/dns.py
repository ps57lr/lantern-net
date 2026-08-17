"""DNS resolver discovery and comparison checks."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from dataclasses import dataclass

from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, run_ok

SYSTEM_RESOLVER = "system"
MAX_RESOLVERS = 8
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


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


def normalize_resolver(value: str) -> str | None:
    """Return one canonical, usable IP-literal resolver address.

    Both IPv4 and IPv6 literals are supported. Loopback is deliberately valid
    because local DNS stubs commonly listen there. Unspecified, multicast, and
    interface-scoped IPv6 values are rejected: a scope identifier is a separate
    device identifier and must never travel in a NETWORK_ADDRESS field.
    """

    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or "%" in candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if address.version == 4 and int(address) == (1 << 32) - 1:
        return None
    return str(address)


def normalize_query_name(value: str) -> str | None:
    """Validate and canonicalize a DNS name or IP literal before execution.

    Unicode labels are converted with the standard-library IDNA codec. The
    wire-format limits are enforced after conversion, and option-like strings,
    empty labels, wildcards, underscores, control characters, and scope IDs are
    rejected. One conventional trailing root dot is accepted and removed.
    """

    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        return None
    candidate = value.removesuffix(".")
    if not candidate:
        return None

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        return str(address)

    # Do not reinterpret a malformed dotted-quad as an ordinary DNS name.
    if "." in candidate and re.fullmatch(r"[0-9.]+", candidate):
        return None
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not ascii_name or len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        return None
    return ascii_name


def _append_resolver(resolvers: list[str], candidate: str) -> None:
    normalized = normalize_resolver(candidate)
    if normalized is not None and normalized not in resolvers and len(resolvers) < MAX_RESOLVERS:
        resolvers.append(normalized)


def system_resolvers(osinfo: OSInfo) -> list[str]:
    """Read system resolver configuration, returning only canonical IP literals."""

    resolvers: list[str] = []
    if osinfo.is_mac:
        text = run_ok(["scutil", "--dns"], timeout=10)
        for line in text.splitlines():
            match = re.fullmatch(r"\s*nameserver(?:\[\d+\])?\s*:\s*(\S+)\s*", line, re.IGNORECASE)
            if match:
                _append_resolver(resolvers, match.group(1))
    elif osinfo.is_linux:
        text = run_ok(["resolvectl", "status"], timeout=10)
        if "(command failed" in text:
            text = run_ok(["cat", "/etc/resolv.conf"], timeout=5)
        dns_server_continuation = False
        for raw_line in text.splitlines():
            line = raw_line.strip()
            parts = line.split()
            if parts and parts[0].lower() == "nameserver":
                if len(parts) >= 2:
                    _append_resolver(resolvers, parts[1])
                dns_server_continuation = False
                continue

            match = re.fullmatch(r"(?:Current\s+)?DNS Server(?:s)?:\s*(.*)", line, re.IGNORECASE)
            if match:
                for token in match.group(1).replace(",", " ").split():
                    _append_resolver(resolvers, token)
                dns_server_continuation = line.lower().startswith("dns servers:")
                continue

            # resolvectl prints additional addresses on indented continuation
            # lines. A new labelled property ends that list.
            if dns_server_continuation:
                if re.match(r"^[A-Za-z][A-Za-z ]+:", line):
                    dns_server_continuation = False
                else:
                    for token in line.replace(",", " ").split():
                        _append_resolver(resolvers, token)
    return resolvers


def query_via(resolver: str, domain: str, timeout: float = 3.0) -> DNSAnswer:
    """Query A records, never silently substituting a different resolver."""
    from netdiag.platform import run, which

    normalized_domain = normalize_query_name(domain)
    if normalized_domain is None:
        raise ValueError("invalid DNS query name")
    domain = normalized_domain

    if resolver == SYSTEM_RESOLVER:
        normalized_resolver = SYSTEM_RESOLVER
    else:
        normalized_resolver = normalize_resolver(resolver)
        if normalized_resolver is None:
            raise ValueError("resolver must be an IPv4 or IPv6 address literal")
    resolver = normalized_resolver

    started = time.monotonic()
    if resolver != SYSTEM_RESOLVER and which("dig"):
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
                resolver,
                domain,
                addrs,
                err,
                blocked,
                round((time.monotonic() - started) * 1000),
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return DNSAnswer(
                resolver,
                domain,
                [],
                str(exc),
                False,
                round((time.monotonic() - started) * 1000),
            )

    if resolver != SYSTEM_RESOLVER:
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
            SYSTEM_RESOLVER,
            domain,
            addrs,
            None,
            blocked,
            round((time.monotonic() - started) * 1000),
        )
    except socket.gaierror as exc:
        return DNSAnswer(
            SYSTEM_RESOLVER,
            domain,
            [],
            str(exc),
            False,
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
            make_finding(
                "NDG.DNS.FILTERING_DETECTED",
                Severity.WARN,
                OutcomeStatus.BLOCKED,
                parameters={"domain": domain, "count": len(blocked)},
                confidence=ConfidenceLevel.HIGH,
                rationale="A resolver returned a loopback or unspecified IPv4 address.",
            )
        )
    if failed and successful:
        findings.append(
            make_finding(
                "NDG.DNS.RESOLVER_INCONSISTENT",
                Severity.WARN,
                OutcomeStatus.DEGRADED,
                parameters={"domain": domain},
                confidence=ConfidenceLevel.HIGH,
                rationale="The same domain succeeded and failed across tested resolvers.",
            )
        )
    elif failed and not successful and not blocked:
        findings.append(
            make_finding(
                "NDG.DNS.RESOLUTION_FAILED",
                Severity.CRIT,
                OutcomeStatus.FAILED,
                parameters={"domain": domain},
                confidence=ConfidenceLevel.HIGH,
                rationale="Every tested resolver failed to return a usable IPv4 address.",
            )
        )

    answer_sets = {frozenset(a.addresses) for a in successful}
    if len(answer_sets) > 1:
        findings.append(
            make_finding(
                "NDG.DNS.ANSWER_VARIANCE",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"domain": domain},
                confidence=ConfidenceLevel.HIGH,
                rationale="Multiple successful resolvers returned different valid address sets.",
            )
        )
    elif successful and not blocked and not failed:
        findings.append(
            make_finding(
                "NDG.DNS.RESOLUTION_SUCCEEDED",
                Severity.OK,
                OutcomeStatus.HEALTHY,
                parameters={"domain": domain, "count": len(successful)},
                confidence=ConfidenceLevel.HIGH,
                rationale="Every tested resolver returned a usable IPv4 address.",
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
            make_finding(
                "NDG.DNS.NO_RESOLVERS_CONFIGURED",
                Severity.CRIT,
                OutcomeStatus.FAILED,
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform resolver configuration exposed no nameserver.",
            )
        )
        return findings, data

    findings.append(
        make_finding(
            "NDG.DNS.RESOLVER_CONFIGURATION",
            Severity.INFO,
            OutcomeStatus.INFORMATIONAL,
            parameters={"resolvers": ", ".join(resolvers)},
            confidence=ConfidenceLevel.HIGH,
            rationale="Resolver addresses came from the platform network configuration.",
        )
    )

    from netdiag.platform import which

    query_resolvers = resolvers[:3] if which("dig") else [SYSTEM_RESOLVER]
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
    normalized_domain = normalize_query_name(domain)
    if normalized_domain is None:
        raise ValueError("invalid DNS query name")
    normalized_resolvers: list[str] = []
    for resolver in resolvers:
        if resolver == SYSTEM_RESOLVER:
            normalized = SYSTEM_RESOLVER
        else:
            normalized = normalize_resolver(resolver)
            if normalized is None:
                raise ValueError("resolver must be an IPv4 or IPv6 address literal")
        if normalized not in normalized_resolvers:
            normalized_resolvers.append(normalized)
    if not normalized_resolvers:
        raise ValueError("at least one resolver is required")
    if len(normalized_resolvers) > MAX_RESOLVERS:
        raise ValueError(f"no more than {MAX_RESOLVERS} resolvers may be queried")
    return [query_via(resolver, normalized_domain) for resolver in normalized_resolvers]
