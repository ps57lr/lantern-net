import subprocess
import unicodedata
from contextlib import nullcontext
from unittest.mock import patch

from netdiag.checks.routing import (
    RouteInfo,
    _ping_host,
    check_routing,
    get_routes,
    local_ipv4_networks,
)
from netdiag.findings import Severity
from netdiag.platform import OSInfo

MAC = OSInfo("Darwin", "test", "arm64")
LINUX = OSInfo("Linux", "test", "x86_64")


def test_ping_summary_canonicalizes_realistic_multiline_output() -> None:
    output = (
        "PING gateway (192.168.1.1): 56 data bytes\n"
        "--- gateway ping statistics ---\n"
        "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
        "round-trip min/avg/max/stddev = 1.000/2.000/3.000/0.500 ms\n"
    )
    completed = subprocess.CompletedProcess(["ping"], 0, stdout=output, stderr="")

    with (
        patch("netdiag.checks.routing.which", return_value="/sbin/ping"),
        patch("netdiag.checks.routing.run", return_value=completed),
    ):
        ok, summary = _ping_host("192.168.1.1")

    assert ok is True
    assert summary == (
        r"--- gateway ping statistics ---\n"
        r"3 packets transmitted, 3 packets received, 0.0% packet loss\n"
        r"round-trip min/avg/max/stddev = 1.000/2.000/3.000/0.500 ms"
    )
    assert "\n" not in summary


def test_ping_summary_visibly_escapes_malicious_controls_and_remains_bounded() -> None:
    output = "gateway\n\x1b[31mspoof\x00\x7f\x85\u202ereversed\t" + ("\x1b" * 1000)
    completed = subprocess.CompletedProcess(["ping"], 1, stdout=output, stderr="")

    with (
        patch("netdiag.checks.routing.which", return_value="/sbin/ping"),
        patch("netdiag.checks.routing.run", return_value=completed),
    ):
        ok, summary = _ping_host("192.168.1.1")

    assert ok is False
    assert not any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in summary)
    assert all(separator not in summary for separator in ("\n", "\r", "\u2028", "\u2029"))
    assert all(marker in summary for marker in (r"\n", r"\x1b", r"\x00", r"\x7f", r"\u202e", r"\t"))
    assert len(summary) <= 4096


def test_macos_route_and_netmask_parsing():
    route = "   route to: default\n gateway: 192.168.1.1\n interface: en0\n"
    interfaces = (
        "lo0: flags=8049<UP,LOOPBACK>\n\tinet 127.0.0.1 netmask 0xff000000\n"
        "en0: flags=8863<UP>\n\tinet 192.168.1.25 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "\tstatus: active\n"
    )
    with patch("netdiag.checks.routing.run_ok", side_effect=[route, interfaces]):
        parsed = get_routes(MAC)
    assert parsed.default_gateway == "192.168.1.1"
    assert parsed.default_iface == "en0"
    assert parsed.interfaces[1].networks == ["192.168.1.0/24"]


def test_linux_preserves_real_prefix():
    routes = "default via 10.20.0.1 dev eth0\n"
    addresses = "2: eth0: <BROADCAST,MULTICAST,UP>\n    inet 10.20.4.9/20 brd 10.20.15.255\n"
    with patch("netdiag.checks.routing.run_ok", side_effect=[routes, addresses]):
        assert [str(n) for n in local_ipv4_networks(LINUX)] == ["10.20.0.0/20"]


def test_primary_lan_network_uses_default_interface():
    routes = "default via 192.168.0.1 dev eth0\n"
    addresses = (
        "2: eth0: <BROADCAST,MULTICAST,UP>\n    inet 192.168.0.183/24 brd 192.168.0.255\n"
        "3: docker0: <BROADCAST,MULTICAST,UP>\n    inet 172.17.0.1/16 brd 172.17.255.255\n"
    )
    with patch("netdiag.checks.routing.run_ok", side_effect=[routes, addresses]):
        from netdiag.checks.routing import primary_lan_network

        assert str(primary_lan_network(LINUX)) == "192.168.0.0/24"


def test_blocked_gateway_ping_is_not_an_outage_when_tcp_works():
    route_info = RouteInfo("192.168.1.1", "en0", [])
    with (
        patch("netdiag.checks.routing.get_routes", return_value=route_info),
        patch("netdiag.checks.routing._ping_host", return_value=(False, "timed out")),
        patch("netdiag.checks.routing.socket.create_connection", return_value=nullcontext()),
    ):
        findings, _data = check_routing(MAC)
    gateway = findings[0]
    assert gateway.severity == Severity.INFO
    assert "likely blocks ICMP" in gateway.hint


def test_linux_point_to_point_default_route_is_not_reported_missing():
    routes = "default dev ppp0 scope link\n"
    addresses = "2: ppp0: <POINTOPOINT,UP>\n    inet 10.0.0.2/32 scope global ppp0\n"
    with patch("netdiag.checks.routing.run_ok", side_effect=[routes, addresses]):
        parsed = get_routes(LINUX)
    assert parsed.has_default_route is True
    assert parsed.default_gateway is None
    assert parsed.default_iface == "ppp0"


def test_point_to_point_route_continues_external_connectivity_checks():
    route_info = RouteInfo(None, "ppp0", [], True)
    with (
        patch("netdiag.checks.routing.get_routes", return_value=route_info),
        patch("netdiag.checks.routing._ping_host", return_value=(False, "timed out")),
        patch("netdiag.checks.routing.socket.create_connection", return_value=nullcontext()),
    ):
        findings, data = check_routing(LINUX)
    assert data["tcp_443"] is True
    assert findings[0].severity == Severity.INFO
    assert findings[0].code == "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP"
    assert "no explicit next-hop" in findings[0].title.lower()
    assert not any(f.severity == Severity.CRIT for f in findings)


def test_linux_on_link_default_route_is_detected_without_calling_it_point_to_point():
    routes = "default dev eth0 proto static scope link\n"
    addresses = "2: eth0: <BROADCAST,MULTICAST,UP>\n    inet 192.0.2.10/24 scope global eth0\n"
    with patch("netdiag.checks.routing.run_ok", side_effect=[routes, addresses]):
        parsed = get_routes(LINUX)
    assert parsed.has_default_route is True
    assert parsed.default_iface == "eth0"
    assert parsed.default_gateway is None


def test_passive_routing_inventory_never_emits_icmp_or_tcp() -> None:
    route_info = RouteInfo(
        "192.168.1.1",
        "en0",
        [],
        True,
    )
    with (
        patch("netdiag.checks.routing.get_routes", return_value=route_info),
        patch("netdiag.checks.routing._ping_host") as ping,
        patch("netdiag.checks.routing.socket.create_connection") as tcp,
    ):
        findings, data = check_routing(MAC, network_probes=False)

    ping.assert_not_called()
    tcp.assert_not_called()
    assert [finding.code for finding in findings] == ["NDG.ROUTE.DEFAULT_ROUTE_OBSERVED"]
    assert findings[0].status.value == "informational"
    assert "Internet and DNS reachability were not tested" in findings[0].detail
    assert data["has_default_route"] is True
    assert data["network_probes"] is False
    assert data["connectivity_status"] == "not_run"


def test_route_command_failure_is_unavailable_not_a_missing_route() -> None:
    with (
        patch(
            "netdiag.checks.routing.run_ok",
            side_effect=[
                "(command failed: exit 1: password=hunter2)",
                "en0: flags=8863<UP>\n\tinet 192.168.1.25 netmask 0xffffff00\n",
            ],
        ),
        patch("netdiag.checks.routing._ping_host") as ping,
        patch("netdiag.checks.routing.socket.create_connection") as tcp,
    ):
        findings, data = check_routing(MAC, network_probes=True)

    ping.assert_not_called()
    tcp.assert_not_called()
    assert data["collector_status"] == "failed"
    assert data["has_default_route"] is None
    assert data["connectivity_status"] == "not_run"
    assert [finding.code for finding in findings] == ["NDG.ROUTE.CHECK_FAILED"]
    rendered = str([finding.to_dict() for finding in findings]) + str(data)
    assert "DEFAULT_ROUTE_MISSING" not in rendered
    assert "password=hunter2" not in rendered


def test_successful_linux_inventory_can_positively_observe_no_ipv4_default_route() -> None:
    with patch(
        "netdiag.checks.routing.run_ok",
        side_effect=[
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.25\n",
            "2: eth0: <BROADCAST,MULTICAST,UP>\n    inet 192.168.1.25/24 scope global eth0\n",
        ],
    ):
        findings, data = check_routing(LINUX, network_probes=False)

    assert data["collector_status"] == "ok"
    assert data["has_default_route"] is False
    assert [finding.code for finding in findings] == ["NDG.ROUTE.DEFAULT_ROUTE_MISSING"]
    assert "IPv4" in findings[0].title
    assert "IPv6 and Internet reachability were not tested" in findings[0].detail


def test_linux_route_command_failure_is_not_treated_as_observed_absence() -> None:
    with patch(
        "netdiag.checks.routing.run_ok",
        side_effect=[
            "(command failed: timed out)",
            "(command failed: ip command unavailable)",
        ],
    ):
        findings, data = check_routing(LINUX, network_probes=False)

    assert data["collector_status"] == "failed"
    assert data["has_default_route"] is None
    assert data["connectivity_status"] == "not_run"
    assert [finding.code for finding in findings] == ["NDG.ROUTE.CHECK_FAILED"]
