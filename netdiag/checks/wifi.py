"""Wi-Fi / wireless link diagnostics."""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import time
from decimal import Decimal, InvalidOperation

from netdiag.catalog import make_finding
from netdiag.core.status import ConfidenceLevel, OutcomeStatus
from netdiag.findings import Finding, Severity
from netdiag.platform import OSInfo, first_match, run_ok, which

_MAC_NETWORKSETUP = "/usr/sbin/networksetup"
_MAC_IPCONFIG = "/usr/sbin/ipconfig"
_MAC_WDUTIL = "/usr/bin/wdutil"
_MAC_AIRPORT = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)
_MAC_WIFI_INTERFACE = re.compile(r"en(?:0|[1-9][0-9]{0,2})\Z")
_MAC_PRIVATE_VALUE = "<redacted>"
_MAC_COMMAND_MAX_BYTES = 32 * 1024
_MAC_COMMAND_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}


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
        hw = _run_macos_command((_MAC_NETWORKSETUP, "-listallhardwareports"))
        wifi_dev = _parse_macos_wifi_interface(hw)
        if wifi_dev is not None:
            ns = _run_macos_command((_MAC_NETWORKSETUP, "-getairportnetwork", wifi_dev))
            prefix = "Current Wi-Fi Network:"
            if ns.startswith(prefix) and "\n" not in ns.rstrip("\n"):
                ssid = ns[len(prefix) :].strip()
                if _bounded_text(ssid, maximum=255) is not None:
                    data["connected"] = True
                    data["ssid"] = ssid
                    data["interface"] = wifi_dev

            if not data.get("connected"):
                summary = _run_macos_command((_MAC_IPCONFIG, "getsummary", wifi_dev))
                fallback = _parse_macos_ipconfig_summary(summary, interface=wifi_dev)
                if fallback.get("connected") is True:
                    data.update(fallback)
        # Signal details via airport when SSID known
        if data.get("connected") and not data.get("rssi") and os.path.isfile(_MAC_AIRPORT):
            text = _run_macos_command((_MAC_AIRPORT, "-I"), timeout=10)
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


def _run_macos_command(command: tuple[str, ...], *, timeout: float = 5.0) -> str:
    """Run one fixed passive macOS inventory command with no ambient Python state."""

    if (
        type(command) is not tuple
        or not command
        or any(type(part) is not str or not part for part in command)
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= 10
    ):
        return ""
    exact = command in {
        (_MAC_NETWORKSETUP, "-listallhardwareports"),
        (_MAC_WDUTIL, "info"),
        (_MAC_AIRPORT, "-I"),
    }
    scoped = (
        len(command) == 3
        and command[:2]
        in {
            (_MAC_NETWORKSETUP, "-getairportnetwork"),
            (_MAC_IPCONFIG, "getsummary"),
        }
        and _MAC_WIFI_INTERFACE.fullmatch(command[2]) is not None
    )
    if not exact and not scoped:
        return ""
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            cwd="/",
            env=dict(_MAC_COMMAND_ENV),
            bufsize=0,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    output = _capture_macos_output(process, timeout=float(timeout))
    if output is None:
        return ""
    try:
        return output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ""


def _stop_macos_process(process: subprocess.Popen[bytes]) -> None:
    stream = process.stdout
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=0.2)
        return
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        # A signal race can report that the process disappeared before wait.
        # Still make the final bounded wait attempt below.
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=0.5)
    except (OSError, subprocess.SubprocessError):
        pass


def _capture_macos_output(
    process: subprocess.Popen[bytes],
    *,
    timeout: float,
) -> bytes | None:
    """Read a child pipe incrementally and kill/reap at the hard byte/time bounds."""

    stream = process.stdout
    if stream is None:
        _stop_macos_process(process)
        return None
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        selector.register(stream, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_macos_process(process)
                return None
            events = selector.select(min(remaining, 0.1))
            if not events:
                continue
            try:
                chunk = os.read(
                    stream.fileno(), min(8192, _MAC_COMMAND_MAX_BYTES + 1 - len(output))
                )
            except (OSError, ValueError):
                _stop_macos_process(process)
                return None
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _MAC_COMMAND_MAX_BYTES:
                _stop_macos_process(process)
                return None

        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except (OSError, subprocess.SubprocessError):
            _stop_macos_process(process)
            return None
        if returncode != 0:
            return None
        return bytes(output)
    except (OSError, ValueError):
        _stop_macos_process(process)
        return None
    finally:
        selector.close()
        try:
            stream.close()
        except OSError:
            pass


def _parse_macos_wifi_interface(text: object) -> str | None:
    """Return one exact Wi-Fi hardware interface from bounded networksetup output."""

    if not _bounded_utf8_text(text, maximum=_MAC_COMMAND_MAX_BYTES):
        return None
    if _contains_controls(text.replace("\n", "")):
        return None
    candidates: list[str] = []
    for block in re.split(r"\n[ \t]*\n", text.strip()):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines or lines[0] != "Hardware Port: Wi-Fi":
            continue
        devices = [line[len("Device: ") :] for line in lines if line.startswith("Device: ")]
        if len(devices) != 1 or _MAC_WIFI_INTERFACE.fullmatch(devices[0]) is None:
            return None
        candidates.append(devices[0])
    return candidates[0] if len(candidates) == 1 else None


def _parse_macos_ipconfig_summary(text: object, *, interface: str) -> dict:
    """Parse top-level typed fields from ``ipconfig getsummary`` fail-closed."""

    if (
        not _bounded_utf8_text(text, maximum=_MAC_COMMAND_MAX_BYTES)
        or type(interface) is not str
        or _MAC_WIFI_INTERFACE.fullmatch(interface) is None
    ):
        return {}
    assert isinstance(text, str)
    fields: dict[str, str] = {}
    allowed = {"BSSID", "InterfaceType", "LinkStatusActive", "SSID", "Security"}
    for line in text.splitlines():
        if len(line) > 1024:
            return {}
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9]*) : (.*)", line)
        if match is None or match.group(1) not in allowed:
            continue
        key, value = match.groups()
        if key in fields or value != value.strip() or _contains_controls(value):
            return {}
        fields[key] = value

    if fields.get("InterfaceType") != "WiFi" or fields.get("LinkStatusActive") != "TRUE":
        return {}
    result: dict = {"connected": True, "interface": interface}
    if "SSID" in fields and fields["SSID"] != _MAC_PRIVATE_VALUE:
        ssid = _bounded_text(fields["SSID"], maximum=255)
        if ssid is None:
            return {}
        result["ssid"] = ssid
    if "BSSID" in fields and fields["BSSID"] != _MAC_PRIVATE_VALUE:
        bssid = _normalized_bssid(fields["BSSID"])
        if bssid is None:
            return {}
        result["bssid"] = bssid
    if "Security" in fields:
        security = fields["Security"]
        if len(security) > 128 or re.fullmatch(r"[A-Za-z0-9_ /().+-]+", security) is None:
            return {}
        result["security"] = security
    return result


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

    # wdutil often needs root on newer macOS — try but don't stop if empty.
    if os.path.isfile(_MAC_WDUTIL):
        text = _run_macos_command((_MAC_WDUTIL, "info"), timeout=10)
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

    if os.path.isfile(_MAC_AIRPORT):
        text = _run_macos_command((_MAC_AIRPORT, "-I"), timeout=10)
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


def _bounded_utf8_text(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= maximum
    except UnicodeEncodeError:
        return False


def _contains_controls(value: str) -> bool:
    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
