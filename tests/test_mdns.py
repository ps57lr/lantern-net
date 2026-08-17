"""Tests for mDNS normalization and deduplication."""

import sys

from netdiag.checks import mdns
from netdiag.checks.mdns_normalize import dedupe_mdns_records, normalize_mdns_type
from netdiag.platform import OSInfo


def test_normalize_bare_mac_types_to_tcp():
    assert normalize_mdns_type("_hue") == "_hue._tcp"
    assert normalize_mdns_type("_meshcop") == "_meshcop._udp"


def test_normalize_rejects_hostile_or_nonstandard_service_types():
    for value in (
        "_password-hunter2._tcp",
        "prefix._http._tcp",
        "_http._tcp.local",
        "_123._tcp",
        "_bad--name._udp",
        "_sixteen-lettersx._tcp",
        "_http._sctp",
    ):
        assert normalize_mdns_type(value) == ""


def test_dedupe_mdns_records():
    raw = [
        {"type": "_hue", "instance": "Bedroom"},
        {"type": "_hue._tcp", "instance": "Bedroom"},
        {"type": "_googlecast._tcp", "instance": "Kitchen"},
        {"type": "_googlecast._tcp", "instance": "Kitchen"},
    ]
    unique = dedupe_mdns_records(raw)
    assert unique == [
        {"type": "_googlecast._tcp", "instance": "Kitchen"},
        {"type": "_hue._tcp", "instance": "Bedroom"},
    ]


def test_macos_service_type_parsing(monkeypatch):
    sample = (
        "Timestamp A/R Flags if Domain Service Type Instance Name\n"
        "12:00:00 Add 2 14 local. _tcp.local. _http\n"
        "12:00:01 Add 2 14 local. _udp.local. _spotify-connect\n"
        "12:00:02 Add 2 14 local. _udp.local. _meshcop\n"
        "12:00:03 Add 2 14 local. _tcp.local. _http\n"
    )
    monkeypatch.setattr(mdns, "which", lambda _name: "/usr/bin/dns-sd")
    monkeypatch.setattr(mdns, "_capture_for", lambda *_args: sample)
    _findings, data = mdns.browse_mdns(OSInfo("Darwin", "test", "arm64"))
    assert data["raw_count"] == 4
    assert data["unique_count"] == 3
    assert data["services"] == [
        {"type": "_http._tcp"},
        {"type": "_meshcop._udp"},
        {"type": "_spotify-connect._tcp"},
    ]


def test_linux_avahi_parsing_and_dedupe(monkeypatch):
    sample = """
+;eth0;IPv4;Hue Bridge;_hue._tcp;local
+;eth0;IPv4;Kitchen display;_googlecast._tcp;local
+;eth0;IPv4;Kitchen display;_googlecast._tcp;local
+ eth0 IPv4 Hue Bridge _hue._tcp local
""".strip()
    monkeypatch.setattr(
        mdns, "which", lambda name: "/usr/bin/avahi-browse" if name == "avahi-browse" else None
    )
    monkeypatch.setattr(mdns, "_capture_for", lambda *_args: sample)
    _findings, data = mdns.browse_mdns(OSInfo("Linux", "test", "aarch64"))
    assert data["unique_count"] == 2
    assert {entry["type"] for entry in data["services"]} == {
        "_googlecast._tcp",
        "_hue._tcp",
    }


def test_hostile_advertisements_are_dropped_and_record_count_is_bounded(monkeypatch):
    lines = [
        "+;eth0;IPv4;Secret;_password-hunter2._tcp;local",
        "+;eth0;IPv4;Router;_http._tcp;local",
        *(f"+;eth0;IPv4;Device {index};_http._tcp;local" for index in range(400)),
    ]
    monkeypatch.setattr(mdns, "which", lambda name: name == "avahi-browse")
    monkeypatch.setattr(mdns, "_capture_for", lambda *_args: "\n".join(lines))
    findings, data = mdns.browse_mdns(OSInfo("Linux", "test", "x86_64"))
    rendered = str(findings) + str(data)
    assert "password-hunter2" not in rendered
    assert data["raw_count"] <= 256


def test_capture_enforces_in_flight_byte_budget() -> None:
    output = mdns._capture_for(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 1048576); sys.stdout.flush()",
        ],
        2,
        max_output_bytes=1024,
    )
    assert output == "x" * 1024
