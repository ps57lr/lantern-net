import json

from netdiag import cli
from netdiag.checks.dns import DNSAnswer
from netdiag.findings import Finding, Severity


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
