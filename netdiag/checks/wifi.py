"""Wi-Fi / wireless link diagnostics."""

from __future__ import annotations

import re

from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, first_match, run_ok, which


def check_wifi(osinfo: OSInfo) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    data: dict = {}

    if osinfo.is_mac:
        data = _wifi_mac()
    elif osinfo.is_linux:
        data = _wifi_linux()
    else:
        findings.append(
            Finding(Severity.INFO, "wifi", "Wi‑Fi check skipped", f"Unsupported OS: {osinfo.system}")
        )
        return findings, data

    if not data.get("connected") and osinfo.is_mac:
        hw = run_ok(["networksetup", "-listallhardwareports"], timeout=5)
        m = re.search(r"Hardware Port: Wi-Fi\s+Device: (\S+)", hw)
        wifi_dev = m.group(1) if m else "en0"
        ns = run_ok(["networksetup", "-getairportnetwork", wifi_dev], timeout=5)
        if "Current Wi-Fi Network:" in ns:
            data["connected"] = True
            data["ssid"] = ns.split("Current Wi-Fi Network:")[-1].strip()
            data["interface"] = wifi_dev
        # Signal details via airport when SSID known
        if data.get("connected") and not data.get("rssi"):
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if __import__("os").path.isfile(airport):
                text = run_ok([airport, "-I"], timeout=10)
                data["rssi"] = first_match(r"\sagrCtlRSSI:\s*(-?\d+)", text)
                data["channel"] = first_match(r"\schannel:\s*(\S+)", text)
                data["tx_rate"] = first_match(r"\slastTxRate:\s*(\d+)", text)

    if not data.get("connected"):
        findings.append(
            Finding(
                Severity.INFO,
                "wifi",
                "No active Wi‑Fi connection detected",
                "This is normal when using Ethernet or when Wi‑Fi is turned off.",
            )
        )
        return findings, data

    ssid = data.get("ssid", "?")
    findings.append(
        Finding(
            Severity.INFO,
            "wifi",
            f"Connected to {ssid!r}",
            _wifi_summary(data),
        )
    )

    rssi = data.get("rssi")
    if rssi is not None:
        try:
            r = int(rssi)
            if r >= -60:
                findings.append(Finding(Severity.OK, "wifi", f"Signal strong ({r} dBm)", ""))
            elif r >= -72:
                findings.append(Finding(Severity.INFO, "wifi", f"Signal fair ({r} dBm)", ""))
            else:
                findings.append(
                    Finding(
                        Severity.WARN,
                        "wifi",
                        f"Signal weak ({r} dBm)",
                        "Expect lower throughput and IoT pairing issues.",
                        hint="Move closer to AP or check 2.4 GHz coverage for smart devices.",
                    )
                )
        except ValueError:
            pass

    channel = data.get("channel")
    band = data.get("band")
    if band and "5" in str(band) and "2" not in str(band):
        findings.append(
            Finding(
                Severity.INFO,
                "wifi",
                "On 5 GHz",
                f"Channel {channel or '?'} — many IoT devices require 2.4 GHz SSID.",
            )
        )

    tx = data.get("tx_rate")
    if tx:
        findings.append(Finding(Severity.INFO, "wifi", f"Link rate ~{tx} Mbps", ""))

    return findings, data


def _wifi_summary(data: dict) -> str:
    parts = []
    for key in ("band", "channel", "rssi", "tx_rate", "security", "bssid"):
        if data.get(key):
            parts.append(f"{key}={data[key]}")
    return ", ".join(parts) or "no details"


def _wifi_mac() -> dict:
    data: dict = {"connected": False}
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    # wdutil often needs root on newer macOS — try but don't stop if empty
    if which("wdutil"):
        text = run_ok(["wdutil", "info"], timeout=10)
        if "SSID" in text:
            data["ssid"] = first_match(r"SSID\s*:\s*(.+)", text)
            data["bssid"] = first_match(r"BSSID\s*:\s*(\S+)", text)
            data["rssi"] = first_match(r"RSSI\s*:\s*(-?\d+)", text)
            data["channel"] = first_match(r"Channel\s*:\s*(\S+)", text)
            data["band"] = first_match(r"Band\s*:\s*(\S+)", text)
            data["security"] = first_match(r"Security\s*:\s*(.+)", text)
            data["tx_rate"] = first_match(r"Tx Rate\s*:\s*(\d+)", text)
            if data.get("ssid"):
                data["connected"] = True
                return data

    if __import__("os").path.isfile(airport):
        text = run_ok([airport, "-I"], timeout=10)
        data["ssid"] = first_match(r"\sSSID:\s*(.+)", text)
        data["bssid"] = first_match(r"\sBSSID:\s*(\S+)", text)
        data["rssi"] = first_match(r"\sagrCtlRSSI:\s*(-?\d+)", text)
        data["channel"] = first_match(r"\schannel:\s*(\S+)", text)
        data["tx_rate"] = first_match(r"\slastTxRate:\s*(\d+)", text)
        if data.get("ssid"):
            data["connected"] = True
        ch = data.get("channel") or ""
        channel_match = re.match(r"\d+", ch)
        if channel_match:
            channel_number = int(channel_match.group())
            data["band"] = "2.4GHz" if channel_number <= 14 else "5/6GHz"
    return data


def _wifi_linux() -> dict:
    data: dict = {"connected": False}
    if which("nmcli"):
        text = run_ok(
            [
                "nmcli", "-t", "--separator", "|", "-f",
                "ACTIVE,SSID,SIGNAL,RATE,BSSID,SECURITY", "dev", "wifi",
            ],
            timeout=10,
        )
        for line in text.splitlines():
            if line.startswith("yes|"):
                parts = line.split("|")
                if len(parts) >= 6:
                    data["connected"] = True
                    data["ssid"] = parts[1]
                    data["rssi"] = str(-100 + int(parts[2]) // 2) if parts[2].isdigit() else parts[2]
                    data["tx_rate"] = parts[3]
                    data["bssid"] = parts[4]
                    data["security"] = parts[5]
                break
        return data
    if which("iwgetid"):
        ssid = run_ok(["iwgetid", "-r"], timeout=5).strip()
        if ssid:
            data["connected"] = True
            data["ssid"] = ssid
    return data
