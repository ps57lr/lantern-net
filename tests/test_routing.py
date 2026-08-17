from contextlib import nullcontext
from unittest.mock import patch

from netdiag.checks.routing import RouteInfo, check_routing, get_routes, local_ipv4_networks
from netdiag.findings import Severity
from netdiag.platform import OSInfo

MAC = OSInfo("Darwin", "test", "arm64")
LINUX = OSInfo("Linux", "test", "x86_64")


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
