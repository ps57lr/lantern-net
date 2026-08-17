"""Tests for mDNS normalization and deduplication."""

from netdiag.checks import mdns
from netdiag.checks.mdns_normalize import dedupe_mdns_records, normalize_mdns_type
from netdiag.platform import OSInfo


def test_normalize_bare_mac_types_to_tcp():
    assert normalize_mdns_type("_hue") == "_hue._tcp"
    assert normalize_mdns_type("_meshcop") == "_meshcop._udp"


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
+;eth0;IPv4;Hue Bridge;Hue Bridge._hue._tcp;local
+;eth0;IPv4;Kitchen display;Kitchen display._googlecast._tcp;local
+;eth0;IPv4;Kitchen display;Kitchen display._googlecast._tcp;local
+ eth0 IPv4 Hue Bridge _hue._tcp local
""".strip()
    monkeypatch.setattr(mdns, "which", lambda name: "/usr/bin/avahi-browse" if name == "avahi-browse" else None)
    monkeypatch.setattr(mdns, "_capture_for", lambda *_args: sample)
    _findings, data = mdns.browse_mdns(OSInfo("Linux", "test", "aarch64"))
    assert data["unique_count"] == 2
    assert {entry["type"] for entry in data["services"]} == {
        "_googlecast._tcp",
        "_hue._tcp",
    }
