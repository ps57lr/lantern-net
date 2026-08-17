from __future__ import annotations

import math
import threading

import pytest

import netdiag.lan.pairing as pairing_module
from netdiag.lan.pairing import (
    PAIRING_CODE_LENGTH,
    UNAMBIGUOUS_ALPHABET,
    PairingAuthority,
    PairingConfigurationError,
)
from tests.lan.helpers import CounterRandom, FakeClock


def authority(
    *,
    clock: FakeClock | None = None,
    random_bytes: CounterRandom | None = None,
    **overrides: object,
) -> PairingAuthority:
    values: dict[str, object] = {
        "source_network": "192.168.50.0/24",
        "clock": clock or FakeClock(),
        "random_bytes": random_bytes or CounterRandom(),
    }
    values.update(overrides)
    return PairingAuthority(**values)  # type: ignore[arg-type]


def test_code_has_eight_unambiguous_characters_and_nearly_40_bits() -> None:
    display = authority().issue()
    assert len(display.code) == PAIRING_CODE_LENGTH == 8
    assert set(display.code) <= set(UNAMBIGUOUS_ALPHABET)
    assert math.log2(len(UNAMBIGUOUS_ALPHABET) ** PAIRING_CODE_LENGTH) > 39
    assert display.code not in repr(display)
    assert display.expires_in == 600


def test_pairing_is_single_use_and_source_identity_is_preserved() -> None:
    pairing = authority()
    display = pairing.issue()
    accepted = pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Technician phone",
    )
    assert accepted.accepted
    assert accepted.grant is not None
    assert accepted.grant.source_address == "192.168.50.20"
    assert accepted.grant.client_label == "Technician phone"

    replay = pairing.attempt(
        display.code,
        source_address="192.168.50.21",
        client_label="Another device",
    )
    assert not replay.accepted
    assert replay.reason == "pairing_failed"


def test_expired_wrong_and_replayed_codes_have_same_remote_reason() -> None:
    clock = FakeClock()
    pairing = authority(clock=clock)
    display = pairing.issue()
    wrong = pairing.attempt(
        "Z" * 8,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    pairing.issue()
    clock.advance(601)
    expired = pairing.attempt(
        display.code,
        source_address="192.168.50.21",
        client_label="Phone",
    )
    assert wrong.reason == expired.reason == "pairing_failed"


def test_rotation_invalidates_old_code_without_resetting_global_failures() -> None:
    random_bytes = CounterRandom()
    pairing = authority(random_bytes=random_bytes)
    first = pairing.issue()
    pairing.attempt("Z" * 8, source_address="192.168.50.20", client_label="Phone")
    second = pairing.issue()
    assert first.code != second.code
    old = pairing.attempt(first.code, source_address="192.168.50.21", client_label="Phone")
    new = pairing.attempt(second.code, source_address="192.168.50.22", client_label="Phone")
    assert not old.accepted
    assert new.accepted


def test_five_failures_lock_code_until_host_rotates() -> None:
    pairing = authority()
    display = pairing.issue()
    for suffix in range(20, 25):
        result = pairing.attempt(
            "Z" * 8,
            source_address=f"192.168.50.{suffix}",
            client_label="Phone",
        )
        assert not result.accepted
    assert pairing.host_status()["usable"] is False
    denied = pairing.attempt(
        display.code,
        source_address="192.168.50.30",
        client_label="Phone",
    )
    assert not denied.accepted

    rotated = pairing.issue()
    accepted = pairing.attempt(
        rotated.code,
        source_address="192.168.50.31",
        client_label="Phone",
    )
    assert accepted.accepted


def test_per_source_backoff_increases_and_is_deterministic() -> None:
    clock = FakeClock()
    pairing = authority(clock=clock)
    pairing.issue()
    first = pairing.attempt("Z" * 8, source_address="192.168.50.20", client_label="Phone")
    second = pairing.attempt("Z" * 8, source_address="192.168.50.20", client_label="Phone")
    assert first.retry_after == 0
    assert second.retry_after == 1
    blocked = pairing.attempt("Z" * 8, source_address="192.168.50.20", client_label="Phone")
    assert blocked.retry_after == 1
    clock.advance(1)
    third = pairing.attempt("Z" * 8, source_address="192.168.50.20", client_label="Phone")
    assert third.retry_after == 3


def test_global_failure_window_rate_limits_other_sources() -> None:
    clock = FakeClock()
    pairing = authority(
        clock=clock,
        code_failure_limit=5,
        source_failure_limit=5,
        global_failure_limit=5,
    )
    pairing.issue()
    for suffix in range(20, 25):
        pairing.attempt(
            "Z" * 8,
            source_address=f"192.168.50.{suffix}",
            client_label="Phone",
        )
    assert pairing.retry_after("192.168.50.99") == 60
    clock.advance(60)
    assert pairing.retry_after("192.168.50.99") == 0


def test_candidate_always_passes_through_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    original = pairing_module.hmac.compare_digest

    def observed(left: bytes, right: bytes) -> bool:
        calls.append((len(left), len(right)))
        return original(left, right)

    monkeypatch.setattr(pairing_module.hmac, "compare_digest", observed)
    pairing = authority()
    pairing.issue()
    pairing.attempt(object(), source_address="192.168.50.20", client_label="Phone")
    assert calls == [(32, 32)]


def test_concurrent_exchange_has_exactly_one_winner() -> None:
    pairing = authority()
    display = pairing.issue()
    barrier = threading.Barrier(8)
    results: list[bool] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        barrier.wait(timeout=2)
        decision = pairing.attempt(
            display.code,
            source_address=f"192.168.50.{index + 20}",
            client_label=f"Client {index}",
        )
        with lock:
            results.append(decision.accepted)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert results.count(True) == 1


def test_pairing_refuses_out_of_scope_source_and_unsafe_label() -> None:
    pairing = authority()
    code = pairing.issue().code
    with pytest.raises(PermissionError):
        pairing.attempt(code, source_address="192.168.51.20", client_label="Phone")
    with pytest.raises(ValueError):
        pairing.attempt(code, source_address="192.168.50.20", client_label="bad\nlabel")
    with pytest.raises(TypeError):
        pairing.attempt(code, source_address="192.168.50.20", client_label=123)
    for hostile_label in (
        "helper\u202eexe",
        "helper\u2066admin",
        "helper\u0085line",
        "helper\ud800",
    ):
        with pytest.raises(ValueError, match="control"):
            pairing.attempt(
                code,
                source_address="192.168.50.20",
                client_label=hostile_label,
            )


def test_configuration_and_randomness_fail_closed() -> None:
    with pytest.raises(PairingConfigurationError):
        PairingAuthority(source_network="0.0.0.0/0")
    with pytest.raises(PairingConfigurationError):
        authority(code_ttl=601)
    with pytest.raises(PairingConfigurationError):
        PairingAuthority(
            source_network="192.168.50.0/24",
            random_bytes=lambda _count: b"short",
        )
    stuck = authority(random_bytes=lambda count: bytes([255]) * count)
    with pytest.raises(PairingConfigurationError, match="unbiased pairing code"):
        stuck.issue()


def test_invalidate_removes_code_and_rate_state() -> None:
    pairing = authority()
    display = pairing.issue()
    pairing.invalidate()
    assert pairing.host_status() == {"issued": False, "usable": False, "expires_in": 0}
    denied = pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    assert not denied.accepted


def test_grant_is_one_use_and_close_permanently_erases_authority() -> None:
    pairing = authority()
    display = pairing.issue()
    decision = pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    assert decision.grant is not None
    assert pairing.consume_grant(decision.grant)
    assert not pairing.consume_grant(decision.grant)
    pairing.close()
    assert pairing.host_status()["issued"] is False
    with pytest.raises(RuntimeError, match="closed"):
        pairing.issue()
    assert not pairing.attempt(
        display.code,
        source_address="192.168.50.20",
        client_label="Phone",
    ).accepted
