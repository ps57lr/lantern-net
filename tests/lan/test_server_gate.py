from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import netdiag.lan.server as server_module
from netdiag.lan.pairing import PairingAuthority
from netdiag.lan.policy import InterfaceCandidate, LanScopePolicy, select_interface
from netdiag.lan.server import (
    LAN_CAPABILITY_STATUS,
    NON_LOOPBACK_BINDING_ENABLED,
    LanExposureDisabled,
    LanResponderFoundation,
    LifecycleState,
    ResponderConfig,
)
from netdiag.lan.sessions import SessionAuthority
from netdiag.lan.tls import EphemeralTlsProvider
from tests.lan.helpers import CounterRandom, FakeCertificateGenerator, FakeClock, aware_now


def scope() -> LanScopePolicy:
    selected = select_interface(
        (
            InterfaceCandidate(
                "en0",
                "192.168.50.10",
                24,
                True,
                is_default=True,
            ),
        )
    )
    return LanScopePolicy(
        selected,
        ("network.passive", "network.path"),
        ("192.168.50.1",),
    )


def foundation(*, tls_provider=None) -> LanResponderFoundation:  # type: ignore[no-untyped-def]
    pairing = PairingAuthority(
        source_network="192.168.50.0/24",
        clock=FakeClock(),
        random_bytes=CounterRandom(),
    )
    return LanResponderFoundation(
        ResponderConfig(scope()),
        tls_provider=tls_provider,
        pairing=pairing,
        sessions=SessionAuthority(
            source_network="192.168.50.0/24",
            pairing=pairing,
            clock=FakeClock(),
            random_bytes=CounterRandom(start=80),
        ),
    )


def test_non_loopback_listener_is_explicitly_disabled_and_not_implemented(monkeypatch) -> None:
    calls = 0

    def forbidden_socket(*_args: object, **_kwargs: object):
        nonlocal calls
        calls += 1
        raise AssertionError("test must never create a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    responder = foundation()
    with pytest.raises(LanExposureDisabled, match="disabled pending independent review"):
        responder.start()
    assert calls == 0
    assert responder.state is LifecycleState.EXPOSURE_BLOCKED
    assert NON_LOOPBACK_BINDING_ENABLED is False
    assert LAN_CAPABILITY_STATUS == "designed_security_foundation_listener_disabled"
    responder.shutdown()


def test_server_module_imports_no_socket_or_http_server() -> None:
    source = Path(server_module.__file__).read_text()
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "socket" not in imports
    assert "http.server" not in imports


def test_preview_truthfully_reports_every_absent_remote_capability() -> None:
    preview = foundation().preview()
    assert not preview.binding_enabled
    assert preview.exact_interface == "en0"
    assert preview.exact_address == "192.168.50.10"
    assert preview.exact_network == "192.168.50.0/24"
    assert preview.tls_required
    assert preview.read_only
    assert not preview.arbitrary_targets_allowed
    assert not preview.commands_allowed
    assert not preview.file_access_allowed
    assert not preview.remediation_allowed
    assert not preview.credentials_accepted


def test_start_fails_before_tls_generation() -> None:
    generator = FakeCertificateGenerator()
    responder = foundation(
        tls_provider=EphemeralTlsProvider(generator=generator, wall_clock=aware_now)
    )
    with pytest.raises(LanExposureDisabled):
        responder.start()
    assert generator.calls == 0
    responder.shutdown()


def test_tls_can_be_prepared_for_review_without_network_and_is_deleted(tmp_path) -> None:
    generator = FakeCertificateGenerator()
    responder = foundation(
        tls_provider=EphemeralTlsProvider(generator=generator, wall_clock=aware_now)
    )
    material = responder.prepare_tls_for_review(base_directory=tmp_path)
    assert responder.state is LifecycleState.TLS_PREPARED_FOR_REVIEW
    assert material.private_key_path.exists()
    responder.shutdown()
    assert responder.state is LifecycleState.STOPPED
    assert not material.private_key_path.exists()
    assert list(tmp_path.iterdir()) == []


def test_shutdown_invalidates_pairing_sessions_audit_and_is_idempotent() -> None:
    responder = foundation()
    display = responder.issue_pairing_for_host_display()
    accepted = responder.pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    assert accepted.grant is not None
    credentials = responder.sessions.issue(
        accepted.grant,
        capabilities=("network.read", "session.end"),
    )
    responder.shutdown()
    responder.shutdown()
    assert responder.pairing.host_status()["issued"] is False
    assert (
        responder.sessions.authenticate(
            credentials.token,
            source_address="192.168.50.20",
        )
        is None
    )
    assert responder.audit.snapshot() == ()


def test_injected_authority_cannot_widen_selected_network() -> None:
    with pytest.raises(ValueError, match="exact selected network"):
        LanResponderFoundation(
            ResponderConfig(scope()),
            pairing=PairingAuthority(source_network="192.168.0.0/16"),
            sessions=SessionAuthority(source_network="192.168.50.0/24"),
        )


def test_config_duration_and_port_are_bounded() -> None:
    with pytest.raises(ValueError):
        ResponderConfig(scope(), port=80)
    with pytest.raises(ValueError):
        ResponderConfig(scope(), duration_seconds=3601)
