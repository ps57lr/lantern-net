from netdiag.checks import mdns
from netdiag.platform import OSInfo


def test_macos_service_type_parsing(monkeypatch):
    sample = (
        "Timestamp A/R Flags if Domain Service Type Instance Name\n"
        "12:00:00 Add 2 14 local. _tcp.local. _http\n"
        "12:00:01 Add 2 14 local. _udp.local. _spotify-connect\n"
    )
    monkeypatch.setattr(mdns, "which", lambda _name: "/usr/bin/dns-sd")
    monkeypatch.setattr(mdns, "_capture_for", lambda *_args: sample)
    _findings, data = mdns.browse_mdns(OSInfo("Darwin", "test", "arm64"))
    assert data["services"] == [{"type": "_http"}, {"type": "_spotify-connect"}]
