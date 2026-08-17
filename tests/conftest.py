import pytest


@pytest.fixture(autouse=True)
def _disable_macos_reexec(monkeypatch):
    monkeypatch.setenv("NETDIAG_MACOS_REEXEC", "1")
    from netdiag.platform import maybe_reexec_macos_system_python

    monkeypatch.setattr(
        "netdiag.cli.maybe_reexec_macos_system_python",
        maybe_reexec_macos_system_python,
    )
