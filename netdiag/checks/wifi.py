"""Wi-Fi / wireless link diagnostics."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
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
            make_finding(
                "NDG.WIFI.UNSUPPORTED",
                Severity.INFO,
                OutcomeStatus.UNSUPPORTED,
                parameters={"platform": osinfo.system},
                confidence=ConfidenceLevel.HIGH,
                rationale="The current Wi-Fi adapter has no collector for this platform.",
            )
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

    # Treat platform command output as untrusted input.  Findings contain a
    # handful of PUBLIC fields, so normalize the complete observation before
    # any of those values are used to build finding prose.
    data = _normalize_wifi_observation(data)

    if not data.get("connected"):
        findings.append(
            make_finding(
                "NDG.WIFI.NOT_CONNECTED",
                Severity.INFO,
                OutcomeStatus.NOT_TESTED,
                confidence=ConfidenceLevel.MEDIUM,
                rationale="No active Wi-Fi association was visible to the platform adapters.",
            )
        )
        return findings, data

    ssid = data.get("ssid", "?")
    findings.append(
        make_finding(
            "NDG.WIFI.CONNECTED",
            Severity.INFO,
            OutcomeStatus.INFORMATIONAL,
            parameters={"ssid": ssid, "summary": _wifi_summary(data)},
            confidence=ConfidenceLevel.HIGH,
            rationale="The platform Wi-Fi adapter reported an active association.",
        )
    )

    rssi = data.get("rssi")
    if rssi is not None:
        try:
            r = int(rssi)
            if r >= -60:
                findings.append(
                    make_finding(
                        "NDG.WIFI.SIGNAL_STRONG",
                        Severity.OK,
                        OutcomeStatus.HEALTHY,
                        parameters={"rssi": r},
                        confidence=ConfidenceLevel.HIGH,
                        rationale="The adapter reported RSSI at or above -60 dBm.",
                    )
                )
            elif r >= -72:
                findings.append(
                    make_finding(
                        "NDG.WIFI.SIGNAL_FAIR",
                        Severity.INFO,
                        OutcomeStatus.INFORMATIONAL,
                        parameters={"rssi": r},
                        confidence=ConfidenceLevel.HIGH,
                        rationale="The adapter reported RSSI between -72 and -60 dBm.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        "NDG.WIFI.SIGNAL_WEAK",
                        Severity.WARN,
                        OutcomeStatus.DEGRADED,
                        parameters={"rssi": r},
                        confidence=ConfidenceLevel.HIGH,
                        rationale="The adapter reported RSSI below -72 dBm.",
                    )
                )
        except ValueError:
            pass

    channel = data.get("channel")
    band = data.get("band")
    if band == "5GHz":
        findings.append(
            make_finding(
                "NDG.WIFI.FIVE_GHZ_LINK",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"channel": channel or "unknown"},
                confidence=ConfidenceLevel.HIGH,
                rationale="The platform adapter reported a 5 GHz-only band label.",
            )
        )

    tx = data.get("tx_rate")
    if tx:
        findings.append(
            make_finding(
                "NDG.WIFI.LINK_RATE_OBSERVED",
                Severity.INFO,
                OutcomeStatus.INFORMATIONAL,
                parameters={"rate": tx},
                confidence=ConfidenceLevel.MEDIUM,
                rationale="The adapter reported a negotiated link rate.",
            )
        )

    return findings, data


def _wifi_summary(data: dict) -> str:
    parts = []
    # SSID/BSSID are rendered or serialized through separately classified fields.
    labels = (
        ("band", "band"),
        ("channel", "channel"),
        ("rssi", "rssi_dbm"),
        ("signal_quality_percent", "signal_quality_percent"),
        ("tx_rate", "tx_rate_mbps"),
        ("security", "security"),
    )
    for key, label in labels:
        if data.get(key) is not None:
            parts.append(f"{label}={data[key]}")
    return ", ".join(parts) or "no details"


def _wifi_mac() -> dict:
    data: dict = {"connected": False}
    airport = (
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    )

    # wdutil often needs root on newer macOS — try but don't stop if empty
    if which("wdutil"):
        text = run_ok(["wdutil", "info"], timeout=10)
        if re.search(r"^\s*SSID\s*:", text, re.MULTILINE | re.IGNORECASE):
            data["ssid"] = first_match(r"^\s*SSID\s*:\s*(.+)", text)
            data["bssid"] = first_match(r"^\s*BSSID\s*:\s*(\S+)", text)
            data["rssi"] = first_match(r"^\s*RSSI\s*:\s*(.+)", text)
            data["channel"] = first_match(r"^\s*Channel\s*:\s*(.+)", text)
            data["band"] = first_match(r"^\s*Band\s*:\s*(.+)", text)
            data["security"] = first_match(r"^\s*Security\s*:\s*(.+)", text)
            data["tx_rate"] = first_match(r"^\s*Tx Rate\s*:\s*(.+)", text)
            data["interface"] = first_match(r"^\s*Interface Name\s*:\s*(.+)", text)
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
                "nmcli",
                "-t",
                "--separator",
                "|",
                "-f",
                "ACTIVE,SSID,SIGNAL,RATE,BSSID,SECURITY",
                "dev",
                "wifi",
            ],
            timeout=10,
        )
        for line in text.splitlines():
            if line.startswith("yes|"):
                parts = _parse_nmcli_terse(line, expected_fields=6)
                if parts is not None and parts[0] == "yes":
                    signal = _normalized_signal(parts[2])
                    if signal is None:
                        continue
                    data["connected"] = True
                    data["ssid"] = parts[1]
                    # NetworkManager SIGNAL is a 0-100 quality percentage, not
                    # RSSI in dBm. Preserve the reported unit and do not invent
                    # a radio measurement or feed it into RSSI thresholds.
                    data["signal_quality_percent"] = signal
                    rate = _normalized_rate(parts[3], allow_bare=False)
                    if rate is not None:
                        data["tx_rate"] = rate
                    if re.fullmatch(r"(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}", parts[4]):
                        data["bssid"] = parts[4].lower()
                    data["security"] = _normalized_security(parts[5])
                break
        return data
    if which("iwgetid"):
        ssid = run_ok(["iwgetid", "-r"], timeout=5).strip()
        if ssid:
            data["connected"] = True
            data["ssid"] = ssid
    return data


def _parse_nmcli_terse(line: str, *, expected_fields: int) -> list[str] | None:
    """Parse one nmcli terse row, honoring backslash-escaped separators."""

    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        return None
    fields.append("".join(current))
    return fields if len(fields) == expected_fields else None


def _normalized_signal(value: str) -> int | None:
    if not re.fullmatch(r"\d{1,3}", value):
        return None
    signal = int(value)
    return signal if 0 <= signal <= 100 else None


def _normalized_rate(value: object, *, allow_bare: bool = True) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    match = re.fullmatch(
        r"\s*(?P<rate>\d{1,6}(?:\.\d{1,3})?"
        r"|\d{1,3}(?:,\d{3})+(?:\.\d{1,3})?)"
        r"\s*(?P<unit>Mbit/s|Mbps|Gbit/s|Gbps)?\s*",
        value,
        re.IGNORECASE,
    )
    if match is None:
        return None
    unit = match.group("unit")
    if unit is None and not allow_bare:
        return None
    try:
        rate = Decimal(match.group("rate").replace(",", ""))
    except InvalidOperation:
        return None
    if unit is not None and unit.lower() in {"gbit/s", "gbps"}:
        rate *= 1000
    if rate <= 0 or rate > 999_999:
        return None
    normalized = format(rate.normalize(), "f")
    return normalized.rstrip("0").rstrip(".") if "." in normalized else normalized


def _normalized_security(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 128 or _contains_controls(value):
        return None
    normalized = value.strip().upper()
    if not normalized or normalized in {"--", "OPEN", "NONE", "NO SECURITY"}:
        return "Open"
    tokens = set(re.findall(r"WPA3|WPA2|WPA1|WPA|SAE|OWE|WEP", normalized))
    if "WPA2" in tokens and "WPA3" in tokens:
        return "WPA2/WPA3"
    if tokens & {"WPA3", "SAE"}:
        return "WPA3"
    if "WPA2" in tokens:
        return "WPA2"
    if "WPA1" in tokens:
        return "WPA"
    if "OWE" in tokens:
        return "OWE"
    if "WEP" in tokens:
        return "WEP"
    return "Unknown"


def _normalize_wifi_observation(data: object) -> dict:
    """Return the canonical, bounded Wi-Fi fields understood by Lantern."""

    if not isinstance(data, dict):
        return {"connected": False}
    normalized: dict = {"connected": data.get("connected") is True}

    ssid = _bounded_text(data.get("ssid"), maximum=255)
    if ssid is not None:
        normalized["ssid"] = ssid
    interface = _bounded_text(data.get("interface"), maximum=64)
    if interface is not None and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface):
        normalized["interface"] = interface

    bssid = _normalized_bssid(data.get("bssid"))
    if bssid is not None:
        normalized["bssid"] = bssid
    rssi = _normalized_rssi(data.get("rssi"))
    if rssi is not None:
        normalized["rssi"] = rssi
    signal = data.get("signal_quality_percent")
    if isinstance(signal, int) and not isinstance(signal, bool) and 0 <= signal <= 100:
        normalized["signal_quality_percent"] = signal

    raw_channel = data.get("channel")
    channel = _normalized_channel(raw_channel)
    if channel is not None:
        normalized["channel"] = channel
    band = _normalized_band(data.get("band"), raw_channel=raw_channel, channel=channel)
    if band is not None:
        normalized["band"] = band

    tx_rate = _normalized_rate(data.get("tx_rate"))
    if tx_rate is not None:
        normalized["tx_rate"] = tx_rate
    if "security" in data:
        security = _normalized_security(data.get("security"))
        if security is not None:
            normalized["security"] = security
    return normalized


def _normalized_rssi(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        rssi = value
    elif isinstance(value, str) and len(value) <= 32:
        match = re.fullmatch(r"\s*(-?\d{1,3})(?:\s*dBm)?\s*", value, re.IGNORECASE)
        if match is None:
            return None
        rssi = int(match.group(1))
    else:
        return None
    return rssi if -127 <= rssi <= 0 else None


def _normalized_channel(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        channel = value
    elif isinstance(value, str) and len(value) <= 96:
        match = re.fullmatch(
            r"\s*(\d{1,3})"
            r"(?:\s*[,/]\s*(?:20|40|80|160|320))?"
            r"(?:\s*\(\s*(?:2\.4|5|6)\s*GHz"
            r"(?:\s*,\s*(?:20|40|80|160|320)\s*MHz)?\s*\))?\s*",
            value,
            re.IGNORECASE,
        )
        if match is None:
            return None
        channel = int(match.group(1))
    else:
        return None
    return str(channel) if 1 <= channel <= 233 else None


def _normalized_band(value: object, *, raw_channel: object, channel: str | None) -> str | None:
    candidates: list[str] = []
    for candidate in (value, raw_channel):
        if (
            isinstance(candidate, str)
            and len(candidate) <= 96
            and not _contains_controls(candidate)
        ):
            candidates.append(candidate)
    joined = " ".join(candidates)
    bands: list[str] = []
    if re.search(r"(?<![\d.])2\.4\s*GHz", joined, re.IGNORECASE):
        bands.append("2.4")
    if re.search(r"(?<![\d.])5\s*GHz", joined, re.IGNORECASE):
        bands.append("5")
    if re.search(r"(?<![\d.])6\s*GHz", joined, re.IGNORECASE):
        bands.append("6")
    if bands:
        return f"{'/'.join(bands)}GHz"
    if channel is not None:
        return "2.4GHz" if int(channel) <= 14 else "5GHz"
    return None


def _normalized_bssid(value: object) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    if re.fullmatch(r"(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value) is None:
        return None
    octets = bytes(int(part, 16) for part in value.split(":"))
    if octets == bytes(6) or octets == bytes([0xFF]) * 6 or octets[0] & 1:
        return None
    return value.lower()


def _bounded_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum or _contains_controls(value):
        return None
    return value


def _contains_controls(value: str) -> bool:
    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
