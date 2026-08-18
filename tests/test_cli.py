import json
import signal
import threading
from argparse import Namespace

import pytest

from netdiag import cli
from netdiag.checks.dns import DNSAnswer
from netdiag.findings import Finding, Severity

_LAUNCH_TOKEN = "do-not-print-token-" + ("A" * 32)
_LAUNCH_URL = f"http://lantern-{'a' * 32}.localhost:1234/app/#launch={_LAUNCH_TOKEN}"


class _FakeUIService:
    def __init__(self, events: list[str], *, closes: bool = True) -> None:
        self.events = events
        self.closes = closes

    def close(self, *, timeout: float) -> bool:
        assert timeout == 3.0
        self.events.append("service.close")
        return self.closes


class _FakeUIServer:
    launch_url = _LAUNCH_URL

    def __init__(
        self,
        events: list[str],
        *,
        wait_result: bool = True,
        start_error: Exception | None = None,
        wait_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.wait_result = wait_result
        self.start_error = start_error
        self.wait_error = wait_error
        self.wait_timeouts: list[float] = []

    def start(self):
        self.events.append("server.start")
        if self.start_error is not None:
            raise self.start_error
        return self

    def wait(self, timeout: float | None = None) -> bool:
        self.events.append("server.wait")
        assert timeout is not None and timeout >= 0
        self.wait_timeouts.append(timeout)
        if self.wait_error is not None:
            raise self.wait_error
        return self.wait_result

    def close(self) -> None:
        self.events.append("server.close")


def test_cli_reports_dev5_version(capsys):
    with pytest.raises(SystemExit) as exited:
        cli.main(["--version"])

    assert exited.value.code == 0
    assert capsys.readouterr().out == "netdiag 0.3.0.dev5\n"


def test_lan_json_serializes_severity(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "scan_lan",
        lambda *_args, **_kwargs: ([Finding(Severity.INFO, "lan", "fine", "")], {"arp": []}),
    )
    assert cli.main(["lan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["severity"] == "info"


def test_ports_rejects_out_of_range_values(capsys):
    assert cli.main(["ports", "localhost", "--ports", "0,70000"]) == 2
    assert "1-65535" in capsys.readouterr().err


def test_dns_exit_status_uses_displayed_comparison(monkeypatch, capsys):
    monkeypatch.setattr(cli, "system_resolvers", lambda _os: ["local", "public"])
    monkeypatch.setattr(
        cli,
        "compare_resolvers",
        lambda *_args: [
            DNSAnswer("local", "example.com", [], "timeout"),
            DNSAnswer("public", "example.com", ["192.0.2.1"]),
        ],
    )
    assert cli.main(["dns", "example.com"]) == 1
    assert "resolves inconsistently" in capsys.readouterr().out


def test_dns_rejects_invalid_resolver_without_echoing_it(monkeypatch, capsys):
    called = False

    def compare(*_args):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(cli, "compare_resolvers", compare)
    assert cli.main(["dns", "example.com", "--resolvers", "password=hunter2"]) == 2
    captured = capsys.readouterr()
    assert "password=hunter2" not in captured.err
    assert not called


def test_dns_rejects_option_like_domain_without_running_query(monkeypatch, capsys):
    called = False

    def compare(*_args):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(cli, "compare_resolvers", compare)
    assert cli.main(["dns", "+trace", "--resolvers", "1.1.1.1"]) == 2
    captured = capsys.readouterr()
    assert "+trace" not in captured.err
    assert not called


def test_ui_revoke_lifecycle_opens_without_echoing_launch_url_and_closes_in_order(
    monkeypatch,
    capsys,
) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))

    def open_browser(url: str, *, timeout: float) -> bool:
        assert url == server.launch_url
        assert 0 < timeout <= cli._UI_BROWSER_OPEN_TIMEOUT_SECONDS
        events.append("browser.open")
        return True

    monkeypatch.setattr(cli, "_open_ui_browser", open_browser)
    assert cli.cmd_ui(Namespace()) == 0
    captured = capsys.readouterr()
    assert "developer preview" in captured.out
    assert "do-not-print-token" not in captured.out + captured.err
    assert events == [
        "server.start",
        "browser.open",
        "server.wait",
        "server.close",
        "service.close",
    ]


def test_ui_browser_failure_is_generic_and_closes_everything(monkeypatch, capsys) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli, "_open_ui_browser", lambda *_args, **_kwargs: False)

    assert cli.cmd_ui(Namespace()) == 1
    captured = capsys.readouterr()
    assert "could not open" in captured.err
    assert "hunter2" not in captured.out + captured.err
    assert "do-not-print-token" not in captured.out + captured.err
    assert events == ["server.start", "server.close", "service.close"]


def test_ui_start_failure_is_generic_and_still_closes_owned_service(monkeypatch, capsys) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(
        events,
        start_error=RuntimeError("family-mac.local password=hunter2"),
    )
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))

    assert cli.cmd_ui(Namespace()) == 1
    captured = capsys.readouterr()
    assert "could not be started" in captured.err
    assert "family-mac" not in captured.out + captured.err
    assert "hunter2" not in captured.out + captured.err
    assert events == ["server.start", "server.close", "service.close"]


def test_ui_keyboard_interrupt_closes_server_then_service(monkeypatch) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events, wait_error=KeyboardInterrupt())
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli, "_open_ui_browser", lambda *_args, **_kwargs: True)

    assert cli.cmd_ui(Namespace()) == 0
    assert events == ["server.start", "server.wait", "server.close", "service.close"]


def test_ui_absolute_session_lifetime_prevents_orphaned_process(monkeypatch, capsys) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events, wait_result=False)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli, "_UI_SESSION_LIFETIME_SECONDS", 0.0)

    assert cli.cmd_ui(Namespace()) == 0
    captured = capsys.readouterr()
    assert "expired" in captured.out
    assert "server.wait" not in events
    assert events[-2:] == ["server.close", "service.close"]


def test_ui_cleanup_failure_returns_error_without_exception_text(monkeypatch, capsys) -> None:
    events: list[str] = []
    service = _FakeUIService(events, closes=False)
    server = _FakeUIServer(events)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli, "_open_ui_browser", lambda *_args, **_kwargs: True)

    assert cli.cmd_ui(Namespace()) == 1
    assert "do-not-print-token" not in capsys.readouterr().out


def test_ui_runtime_injects_the_exact_same_service_into_status_and_mutations(
    monkeypatch,
) -> None:
    import netdiag.ui

    service = object()
    received: list[object] = []

    monkeypatch.setattr(netdiag.ui, "LocalDiagnosticService", lambda: service)

    class Server:
        def __init__(self, *, diagnostic_service: object) -> None:
            received.append(diagnostic_service)

    monkeypatch.setattr(netdiag.ui, "LanternLocalServer", Server)
    created_service, _server = cli._create_ui_runtime()
    assert created_service is service
    assert received == [service]


def test_ui_signal_handlers_include_sigterm_and_restore_prior_handlers(monkeypatch) -> None:
    previous = {
        signal.SIGINT: object(),
        signal.SIGTERM: object(),
    }
    calls: list[tuple[signal.Signals, object]] = []
    monkeypatch.setattr(cli.signal, "getsignal", lambda member: previous[member])
    monkeypatch.setattr(
        cli.signal,
        "signal",
        lambda member, handler: calls.append((member, handler)),
    )

    installed = cli._install_ui_signal_handlers(threading.Event())
    assert installed == previous
    assert {member for member, _handler in calls} == {signal.SIGINT, signal.SIGTERM}
    cli._restore_ui_signal_handlers(installed)
    assert calls[-2:] == list(previous.items())


def test_ui_browser_open_is_bounded_when_platform_launcher_hangs(monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked_open(*_args, **_kwargs) -> bool:
        entered.set()
        release.wait()
        return True

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.webbrowser, "open", blocked_open)
    assert cli._open_ui_browser("http://lantern-fixture.localhost/app/", timeout=0.01) is False
    assert entered.is_set()
    release.set()


def test_macos_browser_launch_keeps_capability_on_stdin_and_foregrounds_default(
    monkeypatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def run(command: tuple[str, ...], **kwargs: object):
        calls.append((command, kwargs))
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "com.example.Browser")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=5.0) is True
    assert calls == [
        (
            ("/usr/bin/osascript", "-"),
            {
                "input": f'open location "{_LAUNCH_URL}"\n'.encode(),
                "stdout": cli.subprocess.DEVNULL,
                "stderr": cli.subprocess.DEVNULL,
                "cwd": "/",
                "env": {"LANG": "C", "LC_ALL": "C"},
                "close_fds": True,
                "shell": False,
                "timeout": 5.0,
                "check": False,
            },
        ),
        (
            ("/usr/bin/open", "-b", "com.example.Browser"),
            {
                "stdin": cli.subprocess.DEVNULL,
                "stdout": cli.subprocess.DEVNULL,
                "stderr": cli.subprocess.DEVNULL,
                "cwd": "/",
                "env": {"LANG": "C", "LC_ALL": "C"},
                "close_fds": True,
                "shell": False,
                "timeout": 5.0,
                "check": False,
            },
        ),
    ]
    assert all(_LAUNCH_TOKEN not in repr(command) for command, _kwargs in calls)
    assert all(
        not (
            {
                "BROWSER",
                "PATH",
                "PYTHONPATH",
                "PYTHONHOME",
                "DYLD_LIBRARY_PATH",
                "DYLD_INSERT_LIBRARIES",
            }
            & kwargs["env"].keys()
        )
        for _command, kwargs in calls
    )


def test_macos_browser_launch_shares_one_absolute_timeout(monkeypatch) -> None:
    timeouts: list[float] = []
    moments = iter((100.0, 101.0, 102.0, 103.0, 104.0))

    def run(command: tuple[str, ...], **kwargs: object):
        timeouts.append(kwargs["timeout"])
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "com.example.Browser")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=10.0) is True
    assert timeouts == [7.0, 6.0]


def test_macos_default_handler_lookup_timeout_never_exposes_url(monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    commands: list[tuple[str, ...]] = []

    def lookup() -> str:
        entered.set()
        release.wait()
        finished.set()
        return "com.example.Browser"

    def run(command: tuple[str, ...], **_kwargs: object):
        commands.append(command)
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lookup)
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=0.01) is False
    assert entered.is_set()
    assert commands == []
    release.set()
    assert finished.wait(1.0)
    assert commands == []


def test_macos_default_handler_lookup_exception_never_exposes_url(monkeypatch) -> None:
    def lookup() -> str:
        raise RuntimeError(f"private lookup detail {_LAUNCH_TOKEN}")

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lookup)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a browser command must not run"),
    )

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=5.0) is False


@pytest.mark.parametrize(
    ("handler_ref", "maximum_size", "handler_bytes", "expected", "expected_releases"),
    [
        (202, 64, b"com.example.Browser", "com.example.Browser", [202, 101]),
        (None, 64, b"", None, [101]),
        (202, 1024, b"com.example.Browser", None, [202, 101]),
        (202, 64, b"\xff", None, [202, 101]),
    ],
)
def test_macos_launchservices_lookup_owns_core_foundation_references(
    monkeypatch,
    handler_ref: int | None,
    maximum_size: int,
    handler_bytes: bytes,
    expected: str | None,
    expected_releases: list[int],
) -> None:
    releases: list[int] = []
    loads: list[str] = []

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    class Library:
        pass

    core_foundation = Library()
    core_services = Library()

    def create_string(allocator, value: bytes, encoding: int) -> int:
        assert allocator is None
        assert value == b"http"
        assert encoding == cli._CF_STRING_ENCODING_UTF8
        return 101

    def get_c_string(_ref: int, buffer, _size: int, _encoding: int) -> bool:
        buffer.value = handler_bytes
        return True

    core_foundation.CFStringCreateWithCString = Function(create_string)
    core_foundation.CFStringGetLength = Function(lambda _ref: len(handler_bytes))
    core_foundation.CFStringGetMaximumSizeForEncoding = Function(
        lambda _length, _encoding: maximum_size
    )
    core_foundation.CFStringGetCString = Function(get_c_string)
    core_foundation.CFRelease = Function(releases.append)
    core_services.LSCopyDefaultHandlerForURLScheme = Function(lambda _scheme: handler_ref)

    def load(path: str):
        loads.append(path)
        if path == cli._MACOS_CORE_FOUNDATION:
            return core_foundation
        if path == cli._MACOS_CORE_SERVICES:
            return core_services
        pytest.fail(f"unexpected framework path: {path}")

    monkeypatch.setattr(cli.ctypes, "CDLL", load)

    assert cli._macos_default_http_handler() == expected
    assert loads == [cli._MACOS_CORE_FOUNDATION, cli._MACOS_CORE_SERVICES]
    assert releases == expected_releases


@pytest.mark.parametrize(
    "url",
    [
        _LAUNCH_URL.replace("http://", "https://"),
        _LAUNCH_URL.replace(":1234/", ":65536/"),
        _LAUNCH_URL.replace("lantern-" + ("a" * 32), "attacker"),
        _LAUNCH_URL + '"\ndo shell script "false"',
        _LAUNCH_URL.replace("#launch=", "?launch="),
    ],
)
def test_macos_browser_rejects_malformed_or_injectable_urls_without_launching(
    monkeypatch,
    url: str,
) -> None:
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a browser command must not run"),
    )

    assert cli._open_ui_browser(url, timeout=5.0) is False


def test_macos_browser_rejects_untrusted_handler_before_activation(monkeypatch) -> None:
    commands: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object):
        commands.append(command)
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "-b attacker --args")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=5.0) is False
    assert commands == []


@pytest.mark.parametrize(
    "bundle_id",
    ["com..example.Browser", ".com.example.Browser", "com.example.", "com.example Browser"],
)
def test_macos_bundle_id_validation_rejects_empty_or_unsafe_segments(bundle_id: str) -> None:
    assert cli._valid_macos_bundle_id(bundle_id) is False


def test_macos_browser_open_timeout_does_not_try_to_activate(monkeypatch) -> None:
    commands: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object):
        commands.append(command)
        raise cli.subprocess.TimeoutExpired(command, 0.01)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "com.example.Browser")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=0.01) is False
    assert commands == [("/usr/bin/osascript", "-")]


def test_macos_browser_activation_failure_is_reported(monkeypatch) -> None:
    results = iter((0, 1))

    def run(command: tuple[str, ...], **_kwargs: object):
        return cli.subprocess.CompletedProcess(command, next(results))

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "com.example.Browser")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=5.0) is False


def test_macos_browser_activation_timeout_is_reported(monkeypatch) -> None:
    calls = 0

    def run(command: tuple[str, ...], **_kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise cli.subprocess.TimeoutExpired(command, 0.01)
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli, "_macos_default_http_handler", lambda: "com.example.Browser")
    monkeypatch.setattr(cli.subprocess, "run", run)

    assert cli._open_ui_browser(_LAUNCH_URL, timeout=5.0) is False
    assert calls == 2


def test_ui_browser_rejects_invalid_timeouts_without_launching(monkeypatch) -> None:
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a browser command must not run"),
    )
    for timeout in (True, 0.0, -1.0, float("nan"), float("inf")):
        assert cli._open_ui_browser(_LAUNCH_URL, timeout=timeout) is False


def test_ui_delayed_browser_launch_uses_only_remaining_absolute_lifetime(
    monkeypatch,
) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events)
    moments = iter((100.0, 100.0, 994.0, 994.0))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(cli, "_UI_WAIT_SLICE_SECONDS", 1000.0)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli, "_open_ui_browser", lambda *_args, **_kwargs: True)

    assert cli.cmd_ui(Namespace()) == 0
    assert server.wait_timeouts == [6.0]
