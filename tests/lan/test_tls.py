from __future__ import annotations

import builtins
import hashlib
import os
import ssl
import stat
from datetime import timedelta

import pytest

import netdiag.lan.tls as tls_module
from netdiag.lan.tls import (
    DEVELOPMENT_TLS_LABEL,
    CryptographyCertificateGenerator,
    EphemeralTlsProvider,
    GeneratedCertificate,
    TlsMaterialError,
    TlsUnavailableError,
)
from tests.lan.helpers import FakeCertificateGenerator, aware_now


def provider(generator: FakeCertificateGenerator | None = None) -> EphemeralTlsProvider:
    return EphemeralTlsProvider(
        generator=generator or FakeCertificateGenerator(),
        certificate_ttl=900,
        wall_clock=aware_now,
    )


def test_material_is_owner_only_labeled_and_deleted(tmp_path) -> None:
    lease = provider().prepare(interface_address="192.168.50.10", base_directory=tmp_path)
    assert stat.S_IMODE(lease.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(lease.certificate_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lease.private_key_path.stat().st_mode) == 0o600
    assert lease.identity.label == DEVELOPMENT_TLS_LABEL
    assert lease.identity.self_signed
    assert not lease.identity.production_trusted
    assert lease.identity.interface_address == "192.168.50.10"
    expected = hashlib.sha256(b"lantern-development-certificate").hexdigest().upper()
    expected = ":".join(expected[index : index + 2] for index in range(0, 64, 2))
    assert lease.identity.fingerprint_sha256 == expected

    directory = lease.directory
    certificate = lease.certificate_path
    private_key = lease.private_key_path
    lease.close()
    lease.close()
    assert lease.closed
    assert not private_key.exists()
    assert not certificate.exists()
    assert not directory.exists()


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "169.254.2.3", "8.8.8.8", "fd00::2"])
def test_tls_refuses_non_rfc1918_or_ambiguous_identity(address: str, tmp_path) -> None:
    with pytest.raises(ValueError, match="RFC1918"):
        provider().prepare(interface_address=address, base_directory=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_generator_san_algorithm_and_lifetime_are_verified(tmp_path) -> None:
    with pytest.raises(TlsMaterialError, match="SAN"):
        provider(FakeCertificateGenerator(san="192.168.50.11")).prepare(
            interface_address="192.168.50.10",
            base_directory=tmp_path,
        )
    with pytest.raises(TlsMaterialError, match="ECDSA"):
        provider(FakeCertificateGenerator(algorithm="RSA-1024")).prepare(
            interface_address="192.168.50.10",
            base_directory=tmp_path,
        )

    class LongCertificate(FakeCertificateGenerator):
        def generate(self, *, address, not_before, not_after):  # type: ignore[no-untyped-def]
            result = super().generate(
                address=address,
                not_before=not_before,
                not_after=not_after + timedelta(days=2),
            )
            return result

    with pytest.raises(TlsMaterialError, match="lifetime"):
        provider(LongCertificate()).prepare(
            interface_address="192.168.50.10",
            base_directory=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


def test_tls_context_requires_12_and_disables_compression(monkeypatch, tmp_path) -> None:
    lease = provider().prepare(interface_address="192.168.50.10", base_directory=tmp_path)

    class FakeContext:
        def __init__(self, protocol: object) -> None:
            self.protocol = protocol
            self.minimum_version = None
            self.options = 0
            self.loaded: tuple[str, str] | None = None

        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            self.loaded = (certfile, keyfile)

    created: list[FakeContext] = []

    def context_factory(protocol: object) -> FakeContext:
        context = FakeContext(protocol)
        created.append(context)
        return context

    monkeypatch.setattr(tls_module.ssl, "SSLContext", context_factory)
    context = EphemeralTlsProvider.create_server_context(lease)
    assert context is created[0]
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert context.options & ssl.OP_NO_COMPRESSION
    assert context.loaded == (str(lease.certificate_path), str(lease.private_key_path))
    lease.close()


def test_missing_optional_generator_never_falls_back_to_plaintext(monkeypatch) -> None:
    original_import = builtins.__import__

    def blocked_import(name: str, *args: object, **kwargs: object):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(TlsUnavailableError, match="plaintext fallback is forbidden"):
        CryptographyCertificateGenerator().generate(
            address="192.168.50.10",
            not_before=aware_now(),
            not_after=aware_now() + timedelta(minutes=15),
        )


def test_partial_write_failure_cleans_ephemeral_directory(monkeypatch, tmp_path) -> None:
    original = tls_module._write_private_file
    calls = 0

    def fail_second(path, content):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated disk failure")
        return original(path, content)

    monkeypatch.setattr(tls_module, "_write_private_file", fail_second)
    with pytest.raises(OSError, match="simulated"):
        provider().prepare(interface_address="192.168.50.10", base_directory=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_changed_key_path_fails_closed_without_following_symlink(tmp_path) -> None:
    lease = provider().prepare(interface_address="192.168.50.10", base_directory=tmp_path)
    lease.private_key_path.unlink()
    target = tmp_path / "unrelated"
    target.write_text("do not touch")
    os.symlink(target, lease.private_key_path)
    with pytest.raises(TlsMaterialError, match="changed type"):
        lease.close()
    assert target.read_text() == "do not touch"
    lease.private_key_path.unlink()
    lease.certificate_path.unlink()
    lease.directory.rmdir()


def test_generated_certificate_private_key_is_not_in_repr() -> None:
    generated = GeneratedCertificate(
        b"-----BEGIN CERTIFICATE-----\n",
        b"PRIVATE-CANARY",
        b"DER",
        aware_now(),
        aware_now() + timedelta(minutes=5),
        ("192.168.50.10",),
        "ECDSA-P256",
    )
    assert "PRIVATE-CANARY" not in repr(generated)
