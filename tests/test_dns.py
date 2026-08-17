from unittest.mock import patch

from netdiag.checks.dns import DNSAnswer, analyze_answers, query_via
from netdiag.findings import Finding, Severity, exit_code, worst_severity


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
