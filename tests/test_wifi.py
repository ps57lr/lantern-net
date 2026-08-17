from __future__ import annotations

import json
from unittest.mock import patch

from netdiag.checks.wifi import _parse_nmcli_terse, check_wifi
from netdiag.platform import OSInfo
from netdiag.presentation import serialize_command_result


def test_nmcli_terse_parser_honors_escaped_separator_and_backslash() -> None:
    line = r"yes|Family\|Secret\\Lab|80|54 Mbit/s|AA:BB:CC:DD:EE:FF|WPA2"
    assert _parse_nmcli_terse(line, expected_fields=6) == [
        "yes",
        r"Family|Secret\Lab",
        "80",
        "54 Mbit/s",
        "AA:BB:CC:DD:EE:FF",
        "WPA2",
    ]
    assert _parse_nmcli_terse("yes|trailing\\", expected_fields=2) is None


def test_linux_wifi_public_fields_are_normalized_before_share_safe_export() -> None:
    output = r"yes|Family\|Secret|80|54 Mbit/s|AA:BB:CC:DD:EE:FF|WPA2"
    with (
        patch("netdiag.checks.wifi.which", side_effect=lambda name: name == "nmcli"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        findings, data = check_wifi(OSInfo("Linux", "test", "x86_64"))

    assert data == {
        "connected": True,
        "ssid": "Family|Secret",
        "signal_quality_percent": 80,
        "tx_rate": "54",
        "bssid": "aa:bb:cc:dd:ee:ff",
        "security": "WPA2",
    }
    shared = serialize_command_result(
        findings,
        data,
        category="wifi",
        share_safe=True,
    )
    rendered = json.dumps(shared)
    assert "Family|Secret" not in rendered
    assert "AA:BB:CC:DD:EE:FF" not in rendered
    assert "aa:bb:cc:dd:ee:ff" not in rendered
    assert "rssi" not in shared["data"]
    assert shared["data"]["signal_quality_percent"] == 80
    assert shared["data"]["security"] == "WPA2"
    finding_text = json.dumps(shared["findings"])
    assert "54 Mbit/s Mbps" not in finding_text
    assert "54 Mbps" in finding_text


def test_linux_signal_quality_is_not_mislabeled_as_rssi() -> None:
    output = "yes|Family|42|1.2 Gbit/s|AA:BB:CC:DD:EE:FF|WPA3"
    with (
        patch("netdiag.checks.wifi.which", side_effect=lambda name: name == "nmcli"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        findings, data = check_wifi(OSInfo("Linux", "test", "x86_64"))
    assert data["signal_quality_percent"] == 42
    assert data["tx_rate"] == "1200"
    assert "rssi" not in data
    assert not any(finding.code and "SIGNAL_" in finding.code for finding in findings)


def test_invalid_nmcli_public_fields_are_not_copied() -> None:
    output = "yes|Family|Secret|not-a-rate|not-a-mac|hunter2"
    with (
        patch("netdiag.checks.wifi.which", side_effect=lambda name: name == "nmcli"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        _findings, data = check_wifi(OSInfo("Linux", "test", "x86_64"))
    assert data == {"connected": False}


def test_macos_wifi_normalizes_common_wdutil_variants_before_findings() -> None:
    output = """
        SSID : Family Network
        BSSID : AA:BB:CC:DD:EE:FE
        RSSI : -58 dBm
        Channel : 149 (5GHz, 80MHz)
        Band : 5 GHz
        Security : WPA2/WPA3 Personal
        Tx Rate : 1.2 Gbps
        Interface Name : en0
    """
    with (
        patch("netdiag.checks.wifi.which", return_value="/usr/bin/wdutil"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        findings, data = check_wifi(OSInfo("Darwin", "test", "arm64"))

    assert data == {
        "connected": True,
        "ssid": "Family Network",
        "interface": "en0",
        "bssid": "aa:bb:cc:dd:ee:fe",
        "rssi": -58,
        "channel": "149",
        "band": "5GHz",
        "tx_rate": "1200",
        "security": "WPA2/WPA3",
    }
    assert {finding.code for finding in findings} >= {
        "NDG.WIFI.CONNECTED",
        "NDG.WIFI.SIGNAL_STRONG",
        "NDG.WIFI.FIVE_GHZ_LINK",
        "NDG.WIFI.LINK_RATE_OBSERVED",
    }


def test_macos_wifi_normalizes_wpa2_personal_without_crashing() -> None:
    output = """
        SSID : Family Network
        Security : WPA2 Personal
        Channel : 6/20
        Band : 2.4 GHz
    """
    with (
        patch("netdiag.checks.wifi.which", return_value="/usr/bin/wdutil"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        findings, data = check_wifi(OSInfo("Darwin", "test", "arm64"))

    assert data["security"] == "WPA2"
    assert data["channel"] == "6"
    assert data["band"] == "2.4GHz"
    assert any(finding.code == "NDG.WIFI.CONNECTED" for finding in findings)


def test_macos_wifi_malformed_optional_fields_are_omitted_or_degraded() -> None:
    output = """
        SSID : Family Network
        BSSID : family-mac.local
        RSSI : password=hunter2
        Channel : recovery-key=abc
        Band : private label
        Security : password=hunter2
        Tx Rate : recovery-key=abc
    """
    with (
        patch("netdiag.checks.wifi.which", return_value="/usr/bin/wdutil"),
        patch("netdiag.checks.wifi.run_ok", return_value=output),
    ):
        findings, data = check_wifi(OSInfo("Darwin", "test", "arm64"))

    assert data == {
        "connected": True,
        "ssid": "Family Network",
        "security": "Unknown",
    }
    rendered = json.dumps([finding.to_dict() for finding in findings]) + json.dumps(data)
    assert "password=hunter2" not in rendered
    assert "recovery-key=abc" not in rendered
    assert "family-mac.local" not in rendered
