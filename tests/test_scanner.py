from unittest.mock import patch

from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo
from netdiag.scanner import run_full_scan


def test_probe_failure_is_contained_in_full_report():
    okay = ([], {})
    with (
        patch("netdiag.scanner.detect_os", return_value=OSInfo("Darwin", "test", "arm64")),
        patch("netdiag.scanner.check_routing", side_effect=RuntimeError("probe exploded")),
        patch("netdiag.scanner.check_dns", return_value=okay),
        patch("netdiag.scanner.check_wifi", return_value=okay),
        patch("netdiag.scanner.scan_lan", return_value=okay),
    ):
        report = run_full_scan(mdns=False)
    assert report.severity == Severity.WARN.value
    assert report.findings[0].severity == Severity.WARN
    assert report.data["routing"]["error"]["type"] == "UnexpectedError"


def test_gateway_port_failure_is_contained_and_uses_routing_result():
    routing = (
        [Finding(Severity.OK, "route", "route okay", "")],
        {"default_gateway": "192.168.50.1"},
    )
    okay = ([], {})
    with (
        patch("netdiag.scanner.check_routing", return_value=routing),
        patch("netdiag.scanner.check_dns", return_value=okay),
        patch("netdiag.scanner.check_wifi", return_value=okay),
        patch("netdiag.scanner.scan_lan", return_value=okay),
        patch(
            "netdiag.checks.ports.scan_ports", side_effect=RuntimeError("port probe failed")
        ) as ports,
    ):
        report = run_full_scan(mdns=False)
    ports.assert_called_once_with("192.168.50.1", ports=[53, 80, 443, 8080, 8443])
    assert report.data["gateway_ports"]["error"]["type"] == "UnexpectedError"
    assert report.severity == Severity.WARN.value
