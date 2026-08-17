"""Tests for LAN scoping and neighbor parsing."""

import ipaddress
import json
from unittest.mock import patch

from netdiag.checks.lan import (
    filter_neighbors,
    normalize_neighbor_mac,
    parse_arp_legacy_table,
    parse_arp_table_output,
    parse_linux_neigh,
    scan_lan,
)
from netdiag.platform import OSInfo
from netdiag.presentation import serialize_command_result

LINUX = OSInfo("Linux", "test", "aarch64")
MAC = OSInfo("Darwin", "test", "arm64")
NETWORK = ipaddress.ip_network("192.168.0.0/24")


def test_parse_linux_neigh_filters_interface():
    sample = """
192.168.0.1 dev eth0 lladdr 78:45:58:c0:2f:99 REACHABLE
172.20.0.2 dev br-f637459facb8 lladdr 02:42:ac:14:00:02 STALE
192.168.0.30 dev eth0 lladdr 00:00:c0:44:7e:d4 REACHABLE
""".strip()
    parsed = parse_linux_neigh(sample, interface="eth0")
    assert [entry["ip"] for entry in parsed] == ["192.168.0.1", "192.168.0.30"]


def test_linux_neigh_rejects_type_confusion_without_network_scope():
    sample = """
password=hunter2.1.1.1 dev eth0 lladdr 78:45:58:c0:2f:98 REACHABLE
192.168.0.10 dev eth0 lladdr family-router.local REACHABLE
192.168.0.11 dev eth0 lladdr AA-BB-CC-DD-EE-FE REACHABLE
"""
    assert parse_linux_neigh(sample, interface="eth0") == [
        {"hostname": "?", "ip": "192.168.0.11", "mac": "aa:bb:cc:dd:ee:fe"}
    ]


def test_filter_neighbors_to_primary_network():
    hosts = [
        {"ip": "192.168.0.30", "mac": "aa:bb:cc:dd:ee:fe", "ifindex": 14},
        {"ip": "172.20.0.2", "mac": "02:42:ac:14:00:02", "ifindex": 99},
    ]
    filtered = filter_neighbors(hosts, network=NETWORK, ifindex=14)
    assert filtered == [{"ip": "192.168.0.30", "mac": "aa:bb:cc:dd:ee:fe", "ifindex": 14}]


def test_parse_arp_table_output_reads_macos_table():
    sample = """
Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs
192.168.0.1             78:45:58:c0:2f:99 1m49s     1m48s          en0    1
udm                     78:45:58:c0:2f:99 1m49s     1m48s          en0    1
""".strip()
    parsed = parse_arp_table_output(sample)
    assert parsed[0]["ip"] == "192.168.0.1"
    assert parsed[0]["mac"] == "78:45:58:c0:2f:99"


def test_macos_arp_parsers_reject_invalid_addresses_and_macs():
    legacy = """
family-router.local (password=hunter2.1.1.1) at 78:45:58:c0:2f:98 on en0
? (192.168.0.10) at family-router.local on en0
? (192.168.0.11) at 78-45-58-C0-2F-98 on en0
"""
    assert parse_arp_legacy_table(legacy) == [
        {"hostname": "?", "ip": "192.168.0.11", "mac": "78:45:58:c0:2f:98"}
    ]


def test_neighbor_mac_policy_accepts_only_unicast_eui48():
    assert normalize_neighbor_mac("A-B-C-D-E-FE") == "0a:0b:0c:0d:0e:fe"
    assert normalize_neighbor_mac("01:00:5e:00:00:01") is None
    assert normalize_neighbor_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalize_neighbor_mac("family-router.local") is None


def test_scan_lan_scopes_linux_neighbors(monkeypatch):
    routes = type("Routes", (), {"default_gateway": "192.168.0.1", "default_iface": "eth0"})()
    probe = type(
        "Probe",
        (),
        {
            "entries": [
                {"ip": "192.168.0.30", "mac": "00:00:c0:44:7e:d4", "hostname": "?", "ifindex": 2},
                {"ip": "172.20.0.2", "mac": "02:42:ac:14:00:02", "hostname": "?", "ifindex": 9},
            ],
            "source": "ip_neigh",
            "status": "ok",
            "detail": "",
        },
    )()

    with (
        patch("netdiag.checks.lan.get_routes", return_value=routes),
        patch("netdiag.checks.lan.primary_lan_network", return_value=NETWORK),
        patch(
            "netdiag.checks.lan._collect_arp",
            return_value=(probe.entries, probe.source, probe.status, probe.detail),
        ),
    ):
        _findings, data = scan_lan(LINUX)

    assert data["default_interface"] == "eth0"
    assert data["network"] == "192.168.0.0/24"
    assert data["arp_source"] == "ip_neigh"
    assert [entry["ip"] for entry in data["arp"]] == ["192.168.0.30"]


def test_no_primary_network_still_validates_neighbors_before_raw_and_share_export():
    routes = type("Routes", (), {"default_gateway": None, "default_iface": "eth0"})()
    entries = [
        {"ip": "password=hunter2.1.1.1", "mac": "00:00:c0:44:7e:d4", "hostname": "?"},
        {"ip": "192.168.0.9", "mac": "family-router.local", "hostname": "?"},
        {"ip": "192.168.0.10", "mac": "AA-BB-CC-DD-EE-FE", "hostname": "?"},
    ]
    with (
        patch("netdiag.checks.lan.get_routes", return_value=routes),
        patch("netdiag.checks.lan.primary_lan_network", return_value=None),
        patch(
            "netdiag.checks.lan._collect_arp",
            return_value=(entries, "ip_neigh", "ok", ""),
        ),
    ):
        findings, data = scan_lan(LINUX)

    assert data["network"] is None
    assert data["arp"] == [{"hostname": "?", "ip": "192.168.0.10", "mac": "aa:bb:cc:dd:ee:fe"}]
    raw = json.dumps(serialize_command_result(findings, data, category="lan"))
    shared = json.dumps(serialize_command_result(findings, data, category="lan", share_safe=True))
    for payload in (raw, shared):
        assert "password=hunter2" not in payload
        assert "family-router.local" not in payload
        assert "192.168.0.10" in payload


def test_active_discovery_finding_accepts_257_authorized_hosts() -> None:
    network = ipaddress.ip_network("192.168.0.0/23")
    alive = [str(address) for address in list(network.hosts())[:257]]
    routes = type("Routes", (), {"default_gateway": "192.168.0.1", "default_iface": "eth0"})()
    with (
        patch("netdiag.checks.lan.get_routes", return_value=routes),
        patch("netdiag.checks.lan.primary_lan_network", return_value=network),
        patch("netdiag.checks.lan._collect_arp", return_value=([], "ip_neigh", "ok", "")),
        patch("netdiag.checks.lan.ping_sweep", return_value=alive),
    ):
        findings, data = scan_lan(LINUX, do_ping=True, max_hosts=257)

    active = next(
        finding for finding in findings if finding.code == "NDG.LAN.ACTIVE_DISCOVERY_COMPLETED"
    )
    assert "257 hosts responded" in active.title
    assert len(data["ping_alive"]) == 257
