from __future__ import annotations

from unittest.mock import patch

from netdiag.checks.ports import scan_ports


def test_large_open_port_result_has_bounded_honest_finding_summary() -> None:
    ports = list(range(1, 301))

    def open_port(_host: str, port: int, _timeout: float) -> tuple[int, str, str, int]:
        return port, "open", "", 1

    with patch("netdiag.checks.ports.check_port", side_effect=open_port):
        findings, data = scan_ports("192.0.2.1", ports=ports)

    assert len(data["ports"]) == 300
    assert data["open"] == ports
    finding = findings[0]
    assert finding.code == "NDG.PORTS.OPEN_PORTS_OBSERVED"
    assert "300 tested port(s) open" in finding.title
    assert "236 additional open ports omitted from this summary" in finding.detail
    assert len(finding.detail) < 4096
