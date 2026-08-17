from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo
from netdiag.scanner import Report


def test_redaction_removes_identifiers_but_keeps_diagnostic_ips():
    report = Report(
        hostname="family-mac.local",
        os=OSInfo("Darwin", "1", "arm64"),
        started_at="2026-01-01T00:00:00+00:00",
        findings=[Finding(Severity.INFO, "wifi", "Connected to 'Family WiFi'", "")],
        data={
            "wifi": {"ssid": "Family WiFi", "bssid": "aa:bb:cc:dd:ee:ff"},
            "route": {"default_gateway": "192.168.1.1"},
        },
    )
    payload = report.to_dict(redact=True)
    rendered = str(payload)
    assert "family-mac.local" not in rendered
    assert "Family WiFi" not in rendered
    assert "aa:bb:cc:dd:ee:ff" not in rendered
    assert "192.168.1.1" in rendered
    assert payload["schema_version"] == "1.1"
