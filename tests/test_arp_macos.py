"""Tests for macOS ARP sysctl parsing."""

from netdiag.checks import arp_macos


def test_parse_mac_from_sockaddr_dl():
    raw = bytes(
        [
            20,
            18,
            0,
            0,
            0,
            4,
            6,
            0,
            ord("e"),
            ord("n"),
            ord("0"),
            ord("0"),
            0x78,
            0x45,
            0x58,
            0xC0,
            0x2F,
            0x99,
        ]
    )
    assert arp_macos._parse_mac(raw, 0) == "78:45:58:c0:2f:99"


def test_read_arp_table_sysctl_parses_buffer(monkeypatch):
    header = arp_macos.RtMsgHdr()
    header.rtm_msglen = arp_macos.RT_MSGHDR_SIZE + 16 + 16
    header.rtm_index = 14

    sin = bytes([16, 2, 0, 0, 192, 168, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
    sdl = bytes(
        [
            20,
            18,
            0,
            0,
            0,
            4,
            6,
            0,
            ord("e"),
            ord("n"),
            ord("0"),
            ord("0"),
            0x78,
            0x45,
            0x58,
            0xC0,
            0x2F,
            0x99,
            0,
            0,
        ]
    )
    payload = bytes(header) + sin + sdl
    monkeypatch.setattr(arp_macos, "_sysctl_raw_buffer", lambda **kwargs: payload)

    entries = arp_macos.read_arp_table_sysctl()
    assert entries == [
        {
            "ip": "192.168.0.1",
            "mac": "78:45:58:c0:2f:99",
            "hostname": "?",
            "ifindex": 14,
        }
    ]


def test_probe_arp_table_marks_partial_without_macs(monkeypatch):
    scrubbed = [{"ip": "192.168.0.1", "mac": "(incomplete)", "hostname": "?", "ifindex": 14}]
    monkeypatch.setattr(arp_macos, "read_arp_table_sysctl", lambda **kwargs: scrubbed)

    probe = arp_macos.probe_arp_table()
    assert probe.source == "sysctl_rtm"
    assert probe.status == "partial"
    assert probe.entries == scrubbed
