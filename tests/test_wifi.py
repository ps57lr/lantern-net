from __future__ import annotations

import json
import os
import subprocess
from unittest.mock import patch

from netdiag.checks import wifi as wifi_module
from netdiag.checks.wifi import (
    _capture_macos_output,
    _parse_macos_ipconfig_summary,
    _parse_macos_wifi_interface,
    _parse_nmcli_terse,
    _run_macos_command,
    check_wifi,
)
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
        patch(
            "netdiag.checks.wifi.os.path.isfile",
            side_effect=lambda path: path == wifi_module._MAC_WDUTIL,
        ),
        patch("netdiag.checks.wifi._run_macos_command", return_value=output),
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
        patch(
            "netdiag.checks.wifi.os.path.isfile",
            side_effect=lambda path: path == wifi_module._MAC_WDUTIL,
        ),
        patch("netdiag.checks.wifi._run_macos_command", return_value=output),
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
        patch(
            "netdiag.checks.wifi.os.path.isfile",
            side_effect=lambda path: path == wifi_module._MAC_WDUTIL,
        ),
        patch("netdiag.checks.wifi._run_macos_command", return_value=output),
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


def test_macos_ipconfig_fallback_recovers_active_wifi_without_inventing_radio_metrics() -> None:
    hardware = """
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: aa:bb:cc:dd:ee:fe

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff
""".strip()
    summary = """<dictionary> {
  BSSID : AA:BB:CC:DD:EE:FE
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : Family Network
  Security : WPA3_SAE
}"""
    calls: list[tuple[str, ...]] = []

    def passive_command(command: tuple[str, ...], *, timeout: float = 5.0) -> str:
        del timeout
        calls.append(command)
        if command == (wifi_module._MAC_NETWORKSETUP, "-listallhardwareports"):
            return hardware
        if command == (wifi_module._MAC_NETWORKSETUP, "-getairportnetwork", "en0"):
            return "You are not associated with an AirPort network.\n"
        if command == (wifi_module._MAC_IPCONFIG, "getsummary", "en0"):
            return summary
        raise AssertionError(f"unexpected command shape: {command!r}")

    with (
        patch("netdiag.checks.wifi.os.path.isfile", return_value=False),
        patch("netdiag.checks.wifi._run_macos_command", side_effect=passive_command),
    ):
        findings, data = check_wifi(OSInfo("Darwin", "test", "arm64"))

    assert data == {
        "connected": True,
        "ssid": "Family Network",
        "interface": "en0",
        "bssid": "aa:bb:cc:dd:ee:fe",
        "security": "WPA3",
    }
    assert "rssi" not in data
    assert "channel" not in data
    assert "tx_rate" not in data
    assert [finding.code for finding in findings] == ["NDG.WIFI.CONNECTED"]
    assert calls == [
        (wifi_module._MAC_NETWORKSETUP, "-listallhardwareports"),
        (wifi_module._MAC_NETWORKSETUP, "-getairportnetwork", "en0"),
        (wifi_module._MAC_IPCONFIG, "getsummary", "en0"),
    ]


def test_macos_wifi_interface_parser_requires_one_exact_wifi_stanza() -> None:
    valid = "Hardware Port: Wi-Fi\nDevice: en12\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
    assert _parse_macos_wifi_interface(valid) == "en12"
    assert _parse_macos_wifi_interface(valid + "\n" + valid.replace("en12", "en0")) is None
    assert _parse_macos_wifi_interface(valid.replace("en12", "en0;touch /tmp/canary")) is None
    assert _parse_macos_wifi_interface("Hardware Port: Wi-Fi\nDevice: lo0\n") is None
    assert _parse_macos_wifi_interface("Hardware Port: Wi-Fi\nDevice: en0\nDevice: en1\n") is None
    assert _parse_macos_wifi_interface("Hardware Port: Wi-Fi\nDevice: en0\x1b[31m\n") is None
    assert _parse_macos_wifi_interface("\ud800") is None


def test_macos_ipconfig_parser_rejects_duplicate_conflicting_and_malformed_fields() -> None:
    base = """<dictionary> {
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : Family Network
}"""
    assert _parse_macos_ipconfig_summary(base, interface="en0") == {
        "connected": True,
        "interface": "en0",
        "ssid": "Family Network",
    }
    assert (
        _parse_macos_ipconfig_summary(
            base.replace("  SSID", "  SSID : Other\n  SSID"), interface="en0"
        )
        == {}
    )
    assert _parse_macos_ipconfig_summary(base.replace("TRUE", "FALSE"), interface="en0") == {}
    assert (
        _parse_macos_ipconfig_summary(base + "\n  BSSID : 01:00:5e:00:00:01", interface="en0") == {}
    )
    assert _parse_macos_ipconfig_summary(base, interface="en0;id") == {}
    assert _parse_macos_ipconfig_summary("\ud800", interface="en0") == {}


def test_macos_ipconfig_parser_accepts_exact_privacy_redaction_without_copying_it() -> None:
    redacted = """<dictionary> {
  BSSID : <redacted>
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : <redacted>
  Security : FT_PSK
}"""
    assert _parse_macos_ipconfig_summary(redacted, interface="en0") == {
        "connected": True,
        "interface": "en0",
        "security": "FT_PSK",
    }


def test_macos_command_allowlist_rejects_mutating_and_type_confused_shapes() -> None:
    invalid: list[object] = [
        (wifi_module._MAC_IPCONFIG, "set", "en0"),
        (wifi_module._MAC_NETWORKSETUP, "-setairportpower", "en0", "on"),
        (wifi_module._MAC_IPCONFIG, "getsummary", "en0", "extra"),
        (wifi_module._MAC_IPCONFIG, "getsummary", "en0;touch"),
        [wifi_module._MAC_IPCONFIG, "getsummary", "en0"],
        (wifi_module._MAC_NETWORKSETUP,),
    ]
    with patch("netdiag.checks.wifi.subprocess.Popen") as popen:
        for command in invalid:
            assert _run_macos_command(command) == ""  # type: ignore[arg-type]
    popen.assert_not_called()


def test_macos_command_uses_fixed_environment_and_bounds_output(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv("PYTHONPATH", "/tmp/shadow")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/canary.dylib")
    monkeypatch.setenv("HOME", "/tmp/canary-home")

    process = object()

    def fake_popen(command: list[str], **kwargs: object) -> object:
        captured.update(command=command, **kwargs)
        return process

    monkeypatch.setattr(wifi_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        wifi_module,
        "_capture_macos_output",
        lambda child, *, timeout: b"bounded output" if child is process and timeout == 5 else None,
    )
    result = _run_macos_command((wifi_module._MAC_IPCONFIG, "getsummary", "en0"))

    assert result == "bounded output"
    assert captured["command"] == [wifi_module._MAC_IPCONFIG, "getsummary", "en0"]
    assert captured["env"] == wifi_module._MAC_COMMAND_ENV
    assert captured["cwd"] == "/"
    assert captured["shell"] is False
    assert captured["close_fds"] is True
    assert captured["stderr"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.PIPE
    assert captured["bufsize"] == 0


class _FakeMacProcess:
    def __init__(self, stdout, *, returncode: int = 0, stubborn: bool = False) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stubborn = stubborn
        self.terminated = False
        self.killed = False
        self.wait_calls = 0
        self.reaped = False

    def poll(self):
        return None if not self.reaped else self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout=None) -> int:
        self.wait_calls += 1
        if self.stubborn and self.terminated and not self.killed:
            raise subprocess.TimeoutExpired("fixed-macos-command", timeout)
        self.reaped = True
        return self.returncode


def test_macos_command_capture_hard_caps_output_and_reaps(monkeypatch) -> None:
    monkeypatch.setattr(wifi_module, "_MAC_COMMAND_MAX_BYTES", 16)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"x" * 17)
    os.close(write_fd)
    process = _FakeMacProcess(os.fdopen(read_fd, "rb", buffering=0))

    assert _capture_macos_output(process, timeout=0.5) is None  # type: ignore[arg-type]
    assert process.terminated is True
    assert process.reaped is True
    assert process.wait_calls >= 1


def test_macos_command_capture_timeout_kills_and_reaps_stubborn_child() -> None:
    read_fd, write_fd = os.pipe()
    process = _FakeMacProcess(os.fdopen(read_fd, "rb", buffering=0), stubborn=True)
    try:
        assert _capture_macos_output(process, timeout=0.01) is None  # type: ignore[arg-type]
    finally:
        os.close(write_fd)
    assert process.terminated is True
    assert process.killed is True
    assert process.reaped is True
    assert process.wait_calls >= 2


def test_macos_command_cleanup_reaps_across_signal_races() -> None:
    class SignalRaceProcess(_FakeMacProcess):
        def terminate(self) -> None:
            self.terminated = True
            raise ProcessLookupError

        def kill(self) -> None:
            self.killed = True
            raise ProcessLookupError

        def wait(self, timeout=None) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("fixed-macos-command", timeout)
            self.reaped = True
            return 0

    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    process = SignalRaceProcess(os.fdopen(read_fd, "rb", buffering=0))
    wifi_module._stop_macos_process(process)  # type: ignore[arg-type]

    assert process.terminated is True
    assert process.killed is True
    assert process.wait_calls == 2
    assert process.reaped is True


def test_macos_command_nonzero_and_invalid_utf8_fail_closed(monkeypatch) -> None:
    for output, returncode in ((b"ok", 9), (b"\xff", 0)):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, output)
        os.close(write_fd)
        process = _FakeMacProcess(os.fdopen(read_fd, "rb", buffering=0), returncode=returncode)
        monkeypatch.setattr(
            wifi_module.subprocess,
            "Popen",
            lambda *_args, child=process, **_kwargs: child,
        )
        assert _run_macos_command((wifi_module._MAC_IPCONFIG, "getsummary", "en0")) == ""
        assert process.reaped is True
