from __future__ import annotations

import base64

import pytest

from netdiag.lan.pairing import PairingGrant
from netdiag.lan.sessions import SessionAuthority, SessionConfigurationError
from tests.lan.helpers import FakeClock, issue_session, paired_session_authority


def authority(*, clock: FakeClock | None = None, **overrides: object) -> SessionAuthority:
    return paired_session_authority(clock=clock, **overrides)


def test_session_token_is_256_bits_and_cookie_is_strict() -> None:
    credentials = issue_session(authority())
    decoded = base64.urlsafe_b64decode(credentials.token + "=")
    assert len(decoded) == 32
    assert credentials.cookie_header.startswith("lantern_lan_session=")
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=300"):
        assert flag in credentials.cookie_header
    assert "Domain=" not in credentials.cookie_header
    assert credentials.token not in repr(credentials)
    assert credentials.csrf_token not in repr(credentials)


def test_session_is_bound_to_socket_source_and_exact_subnet() -> None:
    sessions = authority()
    credentials = issue_session(sessions)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is not None
    assert sessions.authenticate(credentials.token, source_address="192.168.50.21") is None
    with pytest.raises(PermissionError):
        sessions.authenticate(credentials.token, source_address="192.168.51.20")


def test_csrf_is_required_for_mutation_and_only_valid_proof_touches_session() -> None:
    clock = FakeClock()
    sessions = authority(clock=clock, idle_ttl=5, absolute_ttl=20)
    credentials = issue_session(sessions)
    clock.advance(4)
    assert (
        sessions.verify_csrf(
            credentials.token,
            "wrong",
            source_address="192.168.50.20",
        )
        is None
    )
    clock.advance(1)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is None

    credentials = issue_session(sessions)
    clock.advance(4)
    view = sessions.verify_csrf(
        credentials.token,
        credentials.csrf_token,
        source_address="192.168.50.20",
    )
    assert view is not None
    clock.advance(4)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is not None


def test_idle_timeout_and_absolute_timeout_are_independent() -> None:
    clock = FakeClock()
    sessions = authority(clock=clock, idle_ttl=5, absolute_ttl=12)
    credentials = issue_session(sessions)
    clock.advance(4)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is not None
    clock.advance(4)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is not None
    clock.advance(4)
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is None


def test_expire_returns_non_secret_ids() -> None:
    clock = FakeClock()
    sessions = authority(clock=clock, idle_ttl=2, absolute_ttl=10)
    credentials = issue_session(sessions)
    clock.advance(2)
    assert sessions.expire() == (credentials.session_id,)
    assert sessions.list_clients() == ()


def test_rotation_invalidates_old_token_and_changes_scope() -> None:
    sessions = authority()
    first = issue_session(sessions)
    approval = sessions.approve_scope_change(
        first.session_id,
        capabilities=("network.read", "network.run.path", "session.end"),
    )
    rotated = sessions.rotate(
        first.token,
        source_address="192.168.50.20",
        approval=approval,
    )
    assert rotated is not None
    assert rotated.token != first.token
    assert sessions.authenticate(first.token, source_address="192.168.50.20") is None
    view = sessions.authenticate(rotated.token, source_address="192.168.50.20")
    assert view is not None
    assert view.capabilities == ("network.read", "network.run.path", "session.end")


def test_bearer_alone_cannot_rotate_or_elevate_scope() -> None:
    sessions = authority()
    credentials = issue_session(sessions)
    with pytest.raises(TypeError):
        sessions.rotate(  # type: ignore[call-arg]
            credentials.token,
            source_address="192.168.50.20",
            capabilities=("network.read", "network.run.path"),
        )

    approval = sessions.approve_scope_change(
        credentials.session_id,
        capabilities=("network.read", "network.run.path"),
    )
    assert (
        sessions.rotate(
            credentials.token,
            source_address="192.168.50.20",
            approval=approval,
        )
        is not None
    )
    with pytest.raises(PermissionError, match="fresh local host approval"):
        sessions.rotate(
            credentials.token,
            source_address="192.168.50.20",
            approval=approval,
        )


def test_host_and_client_revocation_are_immediate() -> None:
    sessions = authority()
    first = issue_session(sessions)
    assert sessions.revoke(first.session_id)
    assert sessions.authenticate(first.token, source_address="192.168.50.20") is None

    second = issue_session(sessions)
    assert sessions.revoke_token(second.token, source_address="192.168.50.20")
    assert not sessions.revoke_token(second.token, source_address="192.168.50.20")


def test_restart_has_no_session_state_even_with_repeated_test_randomness() -> None:
    first_authority = authority()
    credentials = issue_session(first_authority)
    first_authority.close()
    restarted = authority()
    assert restarted.authenticate(credentials.token, source_address="192.168.50.20") is None


def test_client_listing_has_identity_and_expiry_but_no_bearer() -> None:
    sessions = authority()
    credentials = issue_session(sessions, label="Family helper")
    views = sessions.list_clients()
    assert len(views) == 1
    assert views[0].session_id == credentials.session_id
    assert views[0].client_label == "Family helper"
    assert credentials.token not in repr(views)
    assert credentials.csrf_token not in repr(views)


def test_session_limit_and_capability_allowlist_fail_closed() -> None:
    sessions = authority(maximum_sessions=1)
    issue_session(sessions)
    with pytest.raises(PermissionError, match="session limit"):
        issue_session(sessions, source="192.168.50.21")

    fresh = authority()
    with pytest.raises(ValueError, match="unknown capability"):
        issue_session(fresh, capabilities=("shell.execute",))
    with pytest.raises(ValueError, match="at least one"):
        issue_session(fresh, capabilities=())


def test_issue_requires_verified_grant_type_and_safe_lifetimes() -> None:
    sessions = authority()
    with pytest.raises(TypeError):
        sessions.issue(object(), capabilities=("network.read",))  # type: ignore[arg-type]
    forged = PairingGrant("192.168.50.20", "Phone", "a" * 24, "b" * 24, object())
    with pytest.raises(PermissionError, match="invalid, replayed"):
        sessions.issue(forged, capabilities=("network.read",))
    with pytest.raises(SessionConfigurationError):
        authority(idle_ttl=20, absolute_ttl=10)
    with pytest.raises(SessionConfigurationError):
        authority(absolute_ttl=3601)
    with pytest.raises(SessionConfigurationError):
        SessionAuthority(source_network="0.0.0.0/0")


def test_close_clears_sessions_and_prevents_reuse() -> None:
    sessions = authority()
    credentials = issue_session(sessions)
    pairing = sessions.pairing_authority
    assert pairing is not None
    display = pairing.issue()
    unconsumed = pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    assert unconsumed.grant is not None
    sessions.close()
    assert sessions.list_clients() == ()
    assert sessions.authenticate(credentials.token, source_address="192.168.50.20") is None
    with pytest.raises(RuntimeError, match="closed"):
        sessions.issue(
            unconsumed.grant,
            capabilities=("network.read",),
        )
