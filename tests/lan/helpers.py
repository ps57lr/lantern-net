from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netdiag.lan.pairing import PairingAuthority
from netdiag.lan.sessions import SessionAuthority
from netdiag.lan.tls import GeneratedCertificate


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class CounterRandom:
    """Deterministic exact-length source whose calls never repeat."""

    def __init__(self, start: int = 1) -> None:
        self.cursor = start

    def __call__(self, count: int) -> bytes:
        result = bytes((self.cursor + index) % 256 for index in range(count))
        self.cursor = (self.cursor + count + 7) % 256
        return result


class FakeCertificateGenerator:
    def __init__(self, *, san: str | None = None, algorithm: str = "ECDSA-P256") -> None:
        self.san = san
        self.algorithm = algorithm
        self.calls = 0

    def generate(
        self,
        *,
        address: str,
        not_before: datetime,
        not_after: datetime,
    ) -> GeneratedCertificate:
        self.calls += 1
        return GeneratedCertificate(
            certificate_pem=b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
            private_key_pem=b"-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n",
            certificate_der=b"lantern-development-certificate",
            not_before=not_before,
            not_after=not_after,
            san_addresses=(self.san or address,),
            algorithm=self.algorithm,
        )


def aware_now() -> datetime:
    return datetime(2026, 8, 16, 20, 0, tzinfo=timezone.utc)


def wall_clock_after(seconds: int):
    return lambda: aware_now() + timedelta(seconds=seconds)


def issue_session(
    authority: SessionAuthority,
    *,
    source: str = "192.168.50.20",
    label: str = "Technician phone",
    capabilities: tuple[str, ...] = (
        "network.read",
        "network.run.passive",
        "report.export.redacted",
        "session.end",
    ),
):
    pairing = authority.pairing_authority
    if pairing is None:
        raise AssertionError("test session authority has no pairing authority")
    display = pairing.issue()
    decision = pairing.attempt(
        display.code,
        source_address=source,
        client_label=label,
    )
    if decision.grant is None:
        raise AssertionError("test pairing unexpectedly failed")
    return authority.issue(
        decision.grant,
        capabilities=capabilities,
    )


def paired_session_authority(
    *,
    source_network: str = "192.168.50.0/24",
    clock=None,  # type: ignore[no-untyped-def]
    session_random: CounterRandom | None = None,
    pairing_random: CounterRandom | None = None,
    **overrides: object,
) -> SessionAuthority:
    active_clock = clock or FakeClock()
    pairing = PairingAuthority(
        source_network=source_network,
        clock=active_clock,
        random_bytes=pairing_random or CounterRandom(start=130),
    )
    return SessionAuthority(
        source_network=source_network,
        pairing=pairing,
        clock=active_clock,
        random_bytes=session_random or CounterRandom(),
        **overrides,  # type: ignore[arg-type]
    )
