from unittest.mock import patch

from netdiag.checks.routing import RouteInfo
from netdiag.findings import Severity
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
        patch("netdiag.scanner.get_routes", return_value=RouteInfo(None, None, [])),
    ):
        report = run_full_scan(mdns=False)
    assert report.severity == Severity.WARN.value
    assert report.findings[0].severity == Severity.WARN
    assert report.data["routing"]["error"]["type"] == "RuntimeError"
