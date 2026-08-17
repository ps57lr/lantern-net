import json
import signal
import threading
from argparse import Namespace

from netdiag import cli
from netdiag.checks.dns import DNSAnswer
from netdiag.findings import Finding, Severity


class _FakeUIService:
    def __init__(self, events: list[str], *, closes: bool = True) -> None:
        self.events = events
        self.closes = closes

    def close(self, *, timeout: float) -> bool:
        assert timeout == 3.0
        self.events.append("service.close")
        return self.closes


class _FakeUIServer:
    launch_url = "http://lantern-fixture.localhost:1234/app/#launch=do-not-print-token"

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

    def open_browser(url: str, *, new: int, autoraise: bool) -> bool:
        assert url == server.launch_url
        assert new == 1 and autoraise is True
        events.append("browser.open")
        return True

    monkeypatch.setattr(cli.webbrowser, "open", open_browser)
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
    monkeypatch.setattr(
        cli.webbrowser,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("password=hunter2 do-not-print-token")
        ),
    )

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
    monkeypatch.setattr(cli.webbrowser, "open", lambda *_args, **_kwargs: True)

    assert cli.cmd_ui(Namespace()) == 0
    assert events == ["server.start", "server.wait", "server.close", "service.close"]


def test_ui_absolute_session_lifetime_prevents_orphaned_process(monkeypatch, capsys) -> None:
    events: list[str] = []
    service = _FakeUIService(events)
    server = _FakeUIServer(events, wait_result=False)
    monkeypatch.setattr(cli, "_create_ui_runtime", lambda: (service, server))
    monkeypatch.setattr(cli.webbrowser, "open", lambda *_args, **_kwargs: True)
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
    monkeypatch.setattr(cli.webbrowser, "open", lambda *_args, **_kwargs: True)

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

    monkeypatch.setattr(cli.webbrowser, "open", blocked_open)
    assert cli._open_ui_browser("http://lantern-fixture.localhost/app/", timeout=0.01) is False
    assert entered.is_set()
    release.set()


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
