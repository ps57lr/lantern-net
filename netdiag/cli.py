"""Command-line interface."""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import re
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from collections.abc import Callable

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
from netdiag.platform import detect_os, which
from netdiag.presentation import serialize_command_result
from netdiag.report import print_report
from netdiag.scanner import report_exit_code, run_full_scan
from netdiag.terminal import terminal_safe

_UI_SESSION_LIFETIME_SECONDS = 15 * 60.0
_UI_WAIT_SLICE_SECONDS = 0.25
_UI_BROWSER_OPEN_TIMEOUT_SECONDS = 10.0
_MACOS_OSASCRIPT = "/usr/bin/osascript"
_MACOS_OPEN = "/usr/bin/open"
_MACOS_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_MACOS_CORE_SERVICES = "/System/Library/Frameworks/CoreServices.framework/CoreServices"
_MACOS_LAUNCH_ENV = {"LANG": "C", "LC_ALL": "C"}
_CF_STRING_ENCODING_UTF8 = 0x08000100
_MACOS_LAUNCH_URL = re.compile(
    r"http://lantern-[a-f0-9]{32}\.localhost:"
    r"(?P<port>[1-9][0-9]{0,4})/app/#launch=[A-Za-z0-9_-]{32,256}",
    flags=re.ASCII,
)
_MACOS_BUNDLE_ID = re.compile(
    r"(?=.{3,255}\Z)[A-Za-z0-9][A-Za-z0-9-]*"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+",
    flags=re.ASCII,
)


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


def _create_ui_runtime():
    """Create one shared service/server pair without importing UI code at CLI startup."""

    from netdiag.ui import LanternLocalServer, LocalDiagnosticService

    service = LocalDiagnosticService()
    return service, LanternLocalServer(diagnostic_service=service)


def _install_ui_signal_handlers(
    stop_requested: threading.Event,
) -> dict[signal.Signals, object]:
    previous: dict[signal.Signals, object] = {}

    def request_stop(_signum: int, _frame: object) -> None:
        stop_requested.set()

    for name in ("SIGINT", "SIGTERM"):
        member = getattr(signal, name, None)
        if member is None:
            continue
        try:
            previous[member] = signal.getsignal(member)
            signal.signal(member, request_stop)
        except (OSError, ValueError):
            previous.pop(member, None)
    return previous


def _restore_ui_signal_handlers(previous: dict[signal.Signals, object]) -> None:
    for member, handler in previous.items():
        try:
            signal.signal(member, handler)
        except (OSError, ValueError):
            continue


def _wait_for_ui_exit(
    server: object,
    stop_requested: threading.Event,
    *,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> bool:
    """Wait for revoke or a signal, bounded by the absolute local-session lifetime."""

    wait = getattr(server, "wait", None)
    if not callable(wait):
        raise TypeError("local UI server does not provide a wait lifecycle")
    while not stop_requested.is_set():
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        if wait(min(_UI_WAIT_SLICE_SECONDS, remaining)):
            return True
    return True


def _valid_macos_launch_url(url: object) -> bool:
    """Accept only the canonical, local, capability-bearing URL the server issues."""

    if type(url) is not str:
        return False
    match = _MACOS_LAUNCH_URL.fullmatch(url)
    return match is not None and int(match.group("port")) <= 65535


def _valid_macos_bundle_id(bundle_id: object) -> bool:
    """Restrict LaunchServices output to one ordinary bundle identifier argument."""

    return type(bundle_id) is str and _MACOS_BUNDLE_ID.fullmatch(bundle_id) is not None


def _macos_default_http_handler() -> str | None:
    """Read the user's default HTTP handler directly from macOS LaunchServices."""

    scheme_ref: int | None = None
    handler_ref: int | None = None
    try:
        core_foundation = ctypes.CDLL(_MACOS_CORE_FOUNDATION)
        core_services = ctypes.CDLL(_MACOS_CORE_SERVICES)

        create_string = core_foundation.CFStringCreateWithCString
        create_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        create_string.restype = ctypes.c_void_p
        get_length = core_foundation.CFStringGetLength
        get_length.argtypes = [ctypes.c_void_p]
        get_length.restype = ctypes.c_long
        get_maximum_size = core_foundation.CFStringGetMaximumSizeForEncoding
        get_maximum_size.argtypes = [ctypes.c_long, ctypes.c_uint32]
        get_maximum_size.restype = ctypes.c_long
        get_c_string = core_foundation.CFStringGetCString
        get_c_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
        get_c_string.restype = ctypes.c_bool
        release = core_foundation.CFRelease
        release.argtypes = [ctypes.c_void_p]
        release.restype = None

        copy_default_handler = core_services.LSCopyDefaultHandlerForURLScheme
        copy_default_handler.argtypes = [ctypes.c_void_p]
        copy_default_handler.restype = ctypes.c_void_p

        scheme_ref = create_string(None, b"http", _CF_STRING_ENCODING_UTF8)
        if not scheme_ref:
            return None
        handler_ref = copy_default_handler(scheme_ref)
        if not handler_ref:
            return None

        length = get_length(handler_ref)
        maximum_size = get_maximum_size(length, _CF_STRING_ENCODING_UTF8)
        if maximum_size < 0 or maximum_size >= 1024:
            return None
        buffer = ctypes.create_string_buffer(maximum_size + 1)
        if not get_c_string(
            handler_ref,
            buffer,
            len(buffer),
            _CF_STRING_ENCODING_UTF8,
        ):
            return None
        bundle_id = buffer.value.decode("ascii", errors="strict")
        return bundle_id if _valid_macos_bundle_id(bundle_id) else None
    except Exception:  # noqa: BLE001 - platform failures must not expose local state.
        return None
    finally:
        if handler_ref:
            try:
                core_foundation.CFRelease(handler_ref)
            except Exception:  # noqa: BLE001, S110 - cleanup cannot make launch unsafe.
                pass
        if scheme_ref:
            try:
                core_foundation.CFRelease(scheme_ref)
            except Exception:  # noqa: BLE001, S110 - cleanup cannot make launch unsafe.
                pass


def _bounded_macos_default_http_handler(*, deadline: float) -> str | None:
    """Resolve the browser within the launch deadline, without any URL side effect."""

    completed = threading.Event()
    bundle_id: str | None = None

    def lookup() -> None:
        nonlocal bundle_id
        try:
            candidate = _macos_default_http_handler()
            if _valid_macos_bundle_id(candidate):
                bundle_id = candidate
        except Exception:  # noqa: BLE001 - normalize platform lookup failures.
            bundle_id = None
        finally:
            completed.set()

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    thread = threading.Thread(
        target=lookup,
        name="lantern-default-browser-lookup",
        daemon=True,
    )
    try:
        thread.start()
    except Exception:  # noqa: BLE001 - normalize platform thread-launch failure.
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    if not completed.wait(remaining):
        return None
    thread.join(timeout=0)
    return bundle_id


def _open_macos_ui_browser(url: str, *, timeout: float) -> bool:
    """Open a local URL without putting its launch capability in a process argument."""

    if not _valid_macos_launch_url(url):
        return False
    deadline = time.monotonic() + timeout

    # Resolve and validate the target before exposing the one-use launch URL to
    # another process. A lookup failure must not open a page whose local session
    # will immediately be closed.
    bundle_id = _bounded_macos_default_http_handler(deadline=deadline)
    if not _valid_macos_bundle_id(bundle_id):
        return False
    script = f'open location "{url}"\n'.encode("ascii", errors="strict")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        opened = subprocess.run(
            (_MACOS_OSASCRIPT, "-"),
            input=script,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env=_MACOS_LAUNCH_ENV,
            close_fds=True,
            shell=False,
            timeout=remaining,
            check=False,
        )
    except Exception:  # noqa: BLE001 - subprocess errors may include sensitive input.
        return False
    if opened.returncode != 0:
        return False

    # `open location` honors the user's default browser but may leave it behind
    # the current app. Foreground the browser resolved through LaunchServices
    # without repeating the capability-bearing URL.
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        activated = subprocess.run(
            (_MACOS_OPEN, "-b", bundle_id),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env=_MACOS_LAUNCH_ENV,
            close_fds=True,
            shell=False,
            timeout=remaining,
            check=False,
        )
    except Exception:  # noqa: BLE001 - normalize launcher failures without details.
        return False
    return activated.returncode == 0


def _open_non_macos_ui_browser(url: str, *, timeout: float) -> bool:
    """Bound a potentially blocking platform browser launcher in a daemon thread."""

    completed = threading.Event()
    opened = False

    def launch() -> None:
        nonlocal opened
        try:
            opened = webbrowser.open(url, new=1, autoraise=True) is True
        except Exception:  # noqa: BLE001 - launcher errors may contain paths or arguments.
            opened = False
        finally:
            completed.set()

    thread = threading.Thread(
        target=launch,
        name="lantern-browser-launch",
        daemon=True,
    )
    try:
        thread.start()
    except Exception:  # noqa: BLE001 - normalize platform thread-launch failure.
        return False
    if not completed.wait(timeout):
        return False
    thread.join(timeout=0)
    return opened


def _open_ui_browser(url: str, *, timeout: float) -> bool:
    """Open Lantern in the platform browser within one absolute time bound."""

    if (
        type(url) is not str
        or not url
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        return False
    if sys.platform == "darwin":
        return _open_macos_ui_browser(url, timeout=float(timeout))
    return _open_non_macos_ui_browser(url, timeout=float(timeout))


def cmd_ui(args: argparse.Namespace) -> int:
    """Open the local-only development UI without starting a diagnostic."""

    del args
    service = None
    server = None
    result = 0
    stop_requested = threading.Event()
    previous_handlers = _install_ui_signal_handlers(stop_requested)
    deadline = time.monotonic() + _UI_SESSION_LIFETIME_SECONDS
    try:
        service, server = _create_ui_runtime()
        server.start()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print("Lantern's local session expired and was closed.")
        elif not _open_ui_browser(
            server.launch_url,
            timeout=min(_UI_BROWSER_OPEN_TIMEOUT_SECONDS, remaining),
        ):
            print(
                "netdiag: Lantern could not open the local browser interface.",
                file=sys.stderr,
            )
            result = 1
        else:
            print("Lantern local developer preview is open in your browser.")
            print("No scan or repair starts automatically, and nothing is uploaded.")
            print("Choose End local session or press Ctrl-C to close Lantern.")
            try:
                ended = _wait_for_ui_exit(
                    server,
                    stop_requested,
                    deadline=deadline,
                    monotonic=time.monotonic,
                )
            except KeyboardInterrupt:
                ended = True
            if not ended:
                print("Lantern's local session expired and was closed.")
    except KeyboardInterrupt:
        result = 0
    except Exception:  # noqa: BLE001 - never echo local paths, launch tokens, or adapter errors.
        print("netdiag: Lantern's local interface could not be started.", file=sys.stderr)
        result = 1
    finally:
        _restore_ui_signal_handlers(previous_handlers)
        if server is not None:
            try:
                server.close()
            except Exception:  # noqa: BLE001 - cleanup errors are normalized.
                result = 1
        if service is not None:
            try:
                if not service.close(timeout=3.0):
                    result = 1
            except Exception:  # noqa: BLE001 - cleanup errors are normalized.
                result = 1
    return result


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

    ui_p = sub.add_parser("ui", help="Open the local browser interface (development preview)")
    ui_p.set_defaults(func=cmd_ui)

    return p


def main(argv: list[str] | None = None) -> int:
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
