import json
from unittest.mock import Mock, patch

import pytest

from netdiag.checks.dns import (
    DNSAnswer,
    analyze_answers,
    check_dns,
    normalize_query_name,
    normalize_resolver,
    query_via,
    system_resolvers,
)
from netdiag.findings import Finding, Severity, exit_code, worst_severity
from netdiag.platform import OSInfo
from netdiag.presentation import serialize_command_result

LINUX = OSInfo("Linux", "test", "x86_64")
MAC = OSInfo("Darwin", "test", "arm64")


def test_exit_code_crit():
    assert exit_code([Finding(Severity.CRIT, "t", "x", "")]) == 2


def test_exit_code_warn():
    assert exit_code([Finding(Severity.WARN, "t", "x", "")]) == 1


def test_worst_severity():
    fs = [Finding(Severity.OK, "a", "b", ""), Finding(Severity.WARN, "a", "b", "")]
    assert worst_severity(fs) == Severity.WARN


def test_info_is_not_an_unhealthy_overall_state():
    assert worst_severity([Finding(Severity.INFO, "a", "context", "")]) == Severity.OK


def test_query_via_localhost_resolver():
    # dig @127.0.0.1 may fail; ensure no exception
    ans = query_via("127.0.0.1", "localhost")
    assert ans.domain == "localhost"


def test_custom_resolver_is_not_silently_replaced_without_dig():
    with patch("netdiag.platform.which", return_value=None):
        ans = query_via("1.1.1.1", "example.com")
    assert not ans.addresses
    assert "dig" in (ans.error or "")


def test_resolver_literals_are_canonical_and_scoped_ipv6_is_rejected():
    assert normalize_resolver("2001:0DB8:0:0::53") == "2001:db8::53"
    assert normalize_resolver("127.000.000.001") is None
    assert normalize_resolver("fe80::1%en0") is None
    assert normalize_resolver("0.0.0.0") is None
    assert normalize_resolver("family-router.local") is None


def test_query_names_apply_idna_and_wire_length_rules():
    assert normalize_query_name("BÜCHER.example.") == "xn--bcher-kva.example"
    assert normalize_query_name("localhost") == "localhost"
    assert normalize_query_name("+trace") is None
    assert normalize_query_name("_service.example") is None
    assert normalize_query_name(f"{'a' * 64}.example") is None


@pytest.mark.parametrize("option_like", ["+trace", "-f", "@family-router.local", "*.example"])
def test_option_like_query_never_reaches_dig(option_like):
    runner = Mock()
    with (
        patch("netdiag.platform.which", return_value="/usr/bin/dig"),
        patch("netdiag.platform.run", runner),
        pytest.raises(ValueError, match="invalid DNS query name"),
    ):
        query_via("1.1.1.1", option_like)
    runner.assert_not_called()


def test_invalid_resolver_never_reaches_dig():
    runner = Mock()
    with (
        patch("netdiag.platform.which", return_value="/usr/bin/dig"),
        patch("netdiag.platform.run", runner),
        pytest.raises(ValueError, match="resolver must be"),
    ):
        query_via("password=hunter2", "example.com")
    runner.assert_not_called()


def test_system_resolvers_accept_only_canonical_literals(monkeypatch):
    output = """
nameserver password=hunter2
nameserver family-router.local
nameserver 192.168.001.001
nameserver 192.168.1.1
DNS Servers: 2001:0DB8:0:0::53 family-router.local
             1.1.1.1 password=hunter2
DNS Domain: ~.
"""
    monkeypatch.setattr("netdiag.checks.dns.run_ok", lambda *_args, **_kwargs: output)
    assert system_resolvers(LINUX) == ["192.168.1.1", "2001:db8::53", "1.1.1.1"]


def test_macos_system_resolvers_reject_non_addresses(monkeypatch):
    output = """
  nameserver[0] : password=hunter2
  nameserver[1] : family-router.local
  nameserver[2] : 192.168.1.1
  nameserver[3] : 2001:0DB8::53
"""
    monkeypatch.setattr("netdiag.checks.dns.run_ok", lambda *_args, **_kwargs: output)
    assert system_resolvers(MAC) == ["192.168.1.1", "2001:db8::53"]


def test_system_resolver_canaries_never_enter_raw_or_share_safe_report(monkeypatch):
    output = """
nameserver password=hunter2
nameserver family-router.local
nameserver 192.168.1.1
"""
    monkeypatch.setattr("netdiag.checks.dns.run_ok", lambda *_args, **_kwargs: output)
    monkeypatch.setattr("netdiag.platform.which", lambda _name: None)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("192.0.2.1", 0))],
    )

    findings, data = check_dns(LINUX, domains=["example.com"])
    raw = json.dumps(serialize_command_result(findings, data, category="dns"))
    shared = json.dumps(serialize_command_result(findings, data, category="dns", share_safe=True))
    for payload in (raw, shared):
        assert "password=hunter2" not in payload
        assert "family-router.local" not in payload
        assert "192.168.1.1" in payload


def test_valid_cdn_variance_is_informational():
    findings = analyze_answers(
        "example.com",
        [
            DNSAnswer("1.1.1.1", "example.com", ["192.0.2.1"]),
            DNSAnswer("8.8.8.8", "example.com", ["192.0.2.2"]),
        ],
    )
    assert [f.severity for f in findings] == [Severity.INFO]


def test_one_resolver_failure_is_warning():
    findings = analyze_answers(
        "example.com",
        [
            DNSAnswer("local", "example.com", [], "timed out"),
            DNSAnswer("1.1.1.1", "example.com", ["192.0.2.1"]),
        ],
    )
    assert any(f.severity == Severity.WARN for f in findings)


def test_all_resolvers_failure_is_critical():
    findings = analyze_answers(
        "example.com",
        [DNSAnswer("local", "example.com", [], "timed out")],
    )
    assert exit_code(findings) == 2
