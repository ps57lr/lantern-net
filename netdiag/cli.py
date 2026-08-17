"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys

from netdiag import __version__
from netdiag.checks.dns import (
    MAX_RESOLVERS,
    SYSTEM_RESOLVER,
    analyze_answers,
    compare_resolvers,
    normalize_query_name,
    normalize_resolver,
    system_resolvers,
)
from netdiag.checks.lan import scan_lan
from netdiag.checks.mdns import browse_mdns
from netdiag.checks.ports import scan_ports
from netdiag.checks.routing import check_routing
from netdiag.checks.wifi import check_wifi
from netdiag.findings import Finding, exit_code
from netdiag.platform import detect_os, maybe_reexec_macos_system_python, which
from netdiag.presentation import serialize_command_result
from netdiag.report import print_report
from netdiag.scanner import report_exit_code, run_full_scan
from netdiag.terminal import terminal_safe


def _json_result(findings: list[Finding], data: dict, *, category: str) -> None:
    print(json.dumps(serialize_command_result(findings, data, category=category), indent=2))


def _print_findings(findings: list[Finding]) -> None:
    for finding in findings:
        print(f"[{finding.severity.value.upper()}] {terminal_safe(finding.title)}")
        if finding.detail:
            print(f"  {terminal_safe(finding.detail)}")
        if finding.hint:
            print(f"  → {terminal_safe(finding.hint)}")


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="JSON output")


def _host_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number from 1 to 1024") from exc
    if not 1 <= limit <= 1024:
        raise argparse.ArgumentTypeError("must be from 1 to 1024")
    return limit


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if timeout <= 0 or timeout > 60:
        raise argparse.ArgumentTypeError("must be greater than 0 and no more than 60 seconds")
    return timeout


def cmd_run(args: argparse.Namespace) -> int:
    report = run_full_scan(lan_ping=args.ping, mdns=not args.no_mdns)
    print_report(report, json_out=args.json, redact=args.redact)
    return report_exit_code(report)


def cmd_dns(args: argparse.Namespace) -> int:
    osinfo = detect_os()
    domain = normalize_query_name(args.domain)
    if domain is None:
        print("netdiag: domain must be a valid DNS name or IP address", file=sys.stderr)
        return 2
    if args.resolvers is not None:
        requested = [item.strip() for item in args.resolvers.split(",") if item.strip()]
        resolvers = [normalized for item in requested if (normalized := normalize_resolver(item))]
        if (
            not requested
            or len(resolvers) != len(requested)
            or len(set(resolvers)) != len(resolvers)
            or len(resolvers) > MAX_RESOLVERS
        ):
            print(
                f"netdiag: --resolvers requires 1-{MAX_RESOLVERS} unique IPv4/IPv6 address literals",
                file=sys.stderr,
            )
            return 2
    else:
        configured = system_resolvers(osinfo)
        resolvers = configured if configured and which("dig") else [SYSTEM_RESOLVER]

    answers = compare_resolvers(domain, resolvers)
    findings = analyze_answers(domain, answers)
    if args.json:
        _json_result(
            findings,
            {"domain": domain, "answers": [a.to_dict() for a in answers]},
            category="dns",
        )
        return exit_code(findings)

    print(f"DNS compare: {terminal_safe(domain)}\n")
    for a in answers:
        status = (
            ", ".join(terminal_safe(address) for address in a.addresses)
            if a.addresses
            else "ERROR: no usable IPv4 answer was returned"
        )
        flag = " [BLOCKED?]" if a.blocked else ""
        latency = f" ({a.response_ms} ms)" if a.response_ms is not None else ""
        resolver = terminal_safe(a.resolver)
        print(f"  @{resolver:17} → {status}{flag}{latency}")

    if findings:
        print()
        _print_findings(findings)
    return exit_code(findings)


def cmd_wifi(args: argparse.Namespace) -> int:
    osinfo = detect_os()
    findings, data = check_wifi(osinfo)
    if args.json:
        _json_result(findings, data, category="wifi")
    else:
        _print_findings(findings)
    return exit_code(findings)


def cmd_route(args: argparse.Namespace) -> int:
    osinfo = detect_os()
    findings, data = check_routing(osinfo)
    if args.json:
        _json_result(findings, data, category="routing")
    else:
        _print_findings(findings)
    return exit_code(findings)


def cmd_lan(args: argparse.Namespace) -> int:
    osinfo = detect_os()
    findings, data = scan_lan(osinfo, do_ping=args.ping, max_hosts=args.max_hosts)
    if args.json:
        _json_result(findings, data, category="lan")
    else:
        _print_findings(findings)
    return exit_code(findings)


def cmd_ports(args: argparse.Namespace) -> int:
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("netdiag: --ports must be comma-separated numbers", file=sys.stderr)
            return 2
        if not ports or len(ports) > 1024 or any(not 1 <= p <= 65535 for p in ports):
            print("netdiag: ports must be 1-65535 (maximum 1024 ports)", file=sys.stderr)
            return 2
    findings, data = scan_ports(args.host, ports=ports)
    if args.json:
        _json_result(findings, data, category="ports")
    else:
        _print_findings(findings)
    return exit_code(findings)


def cmd_mdns(args: argparse.Namespace) -> int:
    osinfo = detect_os()
    findings, data = browse_mdns(osinfo, timeout=args.timeout)
    if args.json:
        _json_result(findings, data, category="mdns")
    else:
        _print_findings(findings)
    return exit_code(findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netdiag",
        description="Cross-platform network scan and troubleshooting (macOS + Linux)",
    )
    p.add_argument("--version", action="version", version=f"netdiag {__version__}")
    sub = p.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Full diagnostic scan (default)")
    _add_common(run_p)
    run_p.add_argument(
        "--redact",
        action="store_true",
        help="Hide hostnames, SSIDs, service names, and MAC addresses for sharing",
    )
    run_p.add_argument("--ping", action="store_true", help="Ping-sweep the local subnet (slower)")
    run_p.add_argument("--no-mdns", action="store_true", help="Skip mDNS browse")
    run_p.set_defaults(func=cmd_run)

    dns_p = sub.add_parser("dns", help="Compare DNS answers across resolvers")
    _add_common(dns_p)
    dns_p.add_argument("domain", nargs="?", default="google.com")
    dns_p.add_argument("--resolvers", help="Comma-separated resolvers, e.g. 192.168.0.183,1.1.1.1")
    dns_p.set_defaults(func=cmd_dns)

    wifi_p = sub.add_parser("wifi", help="Wi-Fi link details")
    _add_common(wifi_p)
    wifi_p.set_defaults(func=cmd_wifi)
    rt = sub.add_parser("route", help="Routing and gateway checks")
    _add_common(rt)
    rt.set_defaults(func=cmd_route)

    lan_p = sub.add_parser("lan", help="Local ARP table and optional ping sweep")
    _add_common(lan_p)
    lan_p.add_argument("--ping", action="store_true", help="Actively ping the local subnet")
    lan_p.add_argument(
        "--max-hosts",
        type=_host_limit,
        default=256,
        metavar="N",
        help="Safety limit for active ping scan (1-1024; default: 256)",
    )
    lan_p.set_defaults(func=cmd_lan)

    port_p = sub.add_parser("ports", help="Scan common TCP ports on a host")
    _add_common(port_p)
    port_p.add_argument("host")
    port_p.add_argument("--ports", help="Comma-separated ports (default: common set)")
    port_p.set_defaults(func=cmd_ports)

    mdns_p = sub.add_parser("mdns", help="Browse mDNS/Bonjour services")
    _add_common(mdns_p)
    mdns_p.add_argument("--timeout", type=_positive_timeout, default=5.0)
    mdns_p.set_defaults(func=cmd_mdns)

    return p


def main(argv: list[str] | None = None) -> int:
    maybe_reexec_macos_system_python(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        args.command = "run"
        args.func = cmd_run
        args.json = False
        args.ping = False
        args.no_mdns = False
        args.redact = False
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
