"""Tests for LAN scoping and neighbor parsing."""

import ipaddress
from unittest.mock import patch

from netdiag.checks.lan import (
    filter_neighbors,
    parse_arp_table_output,
    parse_linux_neigh,
    scan_lan,
)
from netdiag.platform import OSInfo

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


def test_filter_neighbors_to_primary_network():
    hosts = [
        {"ip": "192.168.0.30", "mac": "aa", "ifindex": 14},
        {"ip": "172.20.0.2", "mac": "bb", "ifindex": 99},
    ]
    filtered = filter_neighbors(hosts, network=NETWORK, ifindex=14)
    assert filtered == [{"ip": "192.168.0.30", "mac": "aa", "ifindex": 14}]


def test_parse_arp_table_output_reads_macos_table():
    sample = """
Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs
192.168.0.1             78:45:58:c0:2f:99 1m49s     1m48s          en0    1
udm                     78:45:58:c0:2f:99 1m49s     1m48s          en0    1
""".strip()
    parsed = parse_arp_table_output(sample)
    assert parsed[0]["ip"] == "192.168.0.1"
    assert parsed[0]["mac"] == "78:45:58:c0:2f:99"


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
        patch("netdiag.checks.lan._collect_arp", return_value=(probe.entries, probe.source, probe.status, probe.detail)),
    ):
        _findings, data = scan_lan(LINUX)

    assert data["default_interface"] == "eth0"
    assert data["network"] == "192.168.0.0/24"
    assert data["arp_source"] == "ip_neigh"
    assert [entry["ip"] for entry in data["arp"]] == ["192.168.0.30"]
