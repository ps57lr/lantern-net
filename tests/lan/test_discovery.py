from __future__ import annotations

import pytest

from netdiag.lan.discovery import (
    SERVICE_TYPE,
    DiscoveryController,
    DiscoveryDescriptor,
    discovery_authenticates,
)
from netdiag.lan.pairing import PairingAuthority
from tests.lan.helpers import CounterRandom, FakeClock


class FakePublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, DiscoveryDescriptor, float]] = []
        self.withdrawn: list[tuple[object, float]] = []

    def publish(self, *, service_type, descriptor, timeout_seconds):  # type: ignore[no-untyped-def]
        self.published.append((service_type, descriptor, timeout_seconds))
        return "advertisement-handle"

    def withdraw(self, handle, *, timeout_seconds):  # type: ignore[no-untyped-def]
        self.withdrawn.append((handle, timeout_seconds))


def descriptor() -> DiscoveryDescriptor:
    return DiscoveryDescriptor("a" * 24, "192.168.50.10", 38443)


def test_discovery_txt_is_minimal_and_contains_no_pairing_secret() -> None:
    record = descriptor()
    assert record.txt == (
        ("proto", "1"),
        ("port", "38443"),
        ("tls", "required"),
        ("instance", "a" * 24),
    )
    serialized = repr(record.txt).lower()
    for forbidden in ("code", "token", "password", "session", "credential"):
        assert forbidden not in serialized


def test_publish_and_withdraw_lifecycle_is_bounded_and_idempotent() -> None:
    publisher = FakePublisher()
    controller = DiscoveryController(operation_timeout=1.5)
    lease = controller.publish(publisher, descriptor())
    assert publisher.published == [(SERVICE_TYPE, descriptor(), 1.5)]
    lease.close()
    lease.close()
    assert publisher.withdrawn == [("advertisement-handle", 1.5)]


def test_spoofed_discovery_never_authenticates_or_bypasses_pairing() -> None:
    spoofed = descriptor()
    assert not discovery_authenticates(spoofed)
    pairing = PairingAuthority(
        source_network="192.168.50.0/24",
        clock=FakeClock(),
        random_bytes=CounterRandom(),
    )
    real_code = pairing.issue().code
    denied = pairing.attempt(
        spoofed.instance_id,
        source_address="192.168.50.20",
        client_label="Phone",
    )
    assert not denied.accepted
    accepted = pairing.attempt(
        real_code,
        source_address="192.168.50.21",
        client_label="Phone",
    )
    assert accepted.accepted


@pytest.mark.parametrize(
    "record",
    [
        ("short", "192.168.50.10", 38443),
        ("a" * 24, "8.8.8.8", 38443),
        ("a" * 24, "127.0.0.1", 38443),
        ("a" * 24, "192.168.50.10", 80),
    ],
)
def test_discovery_descriptor_fails_closed(record: tuple[str, str, int]) -> None:
    with pytest.raises(ValueError):
        DiscoveryDescriptor(*record)
