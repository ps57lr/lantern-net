"""Ephemeral development TLS material for the gated Lantern LAN prototype.

There is deliberately no HTTP or plaintext fallback in this module.  Production
trust is not claimed: the generated self-signed certificate is short-lived and its
SHA-256 fingerprint must be visibly verified by both people.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import ssl
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final, Protocol

DEVELOPMENT_TLS_LABEL: Final[str] = "Development secure session — self-signed prototype"
MAX_CERTIFICATE_LIFETIME: Final[int] = 24 * 60 * 60
_MAX_CERTIFICATE_BYTES: Final[int] = 128 * 1024
_MAX_PRIVATE_KEY_BYTES: Final[int] = 64 * 1024

WallClock = Callable[[], datetime]


class TlsUnavailableError(RuntimeError):
    """Raised instead of degrading the responder to plaintext."""


class TlsMaterialError(RuntimeError):
    """Raised when generated material fails the strict prototype policy."""


@dataclass(frozen=True, slots=True)
class GeneratedCertificate:
    """In-memory output of an injected certificate generator."""

    certificate_pem: bytes
    private_key_pem: bytes = field(repr=False)
    certificate_der: bytes = field(repr=False)
    not_before: datetime
    not_after: datetime
    san_addresses: tuple[str, ...]
    algorithm: str


class CertificateGenerator(Protocol):
    def generate(
        self,
        *,
        address: str,
        not_before: datetime,
        not_after: datetime,
    ) -> GeneratedCertificate: ...


@dataclass(frozen=True, slots=True)
class DevelopmentCertificate:
    """Host-visible TLS identity and explicit trust limitation."""

    label: str
    fingerprint_sha256: str
    valid_from: str
    valid_until: str
    interface_address: str
    self_signed: bool = True
    production_trusted: bool = False


class TlsMaterialLease:
    """Owner of the exact temporary certificate files for one process lifetime."""

    def __init__(
        self,
        *,
        directory: Path,
        certificate_path: Path,
        private_key_path: Path,
        identity: DevelopmentCertificate,
    ) -> None:
        self.directory = directory
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.identity = identity
        self._closed = False
        self._lock = threading.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Delete only the known ephemeral files; safe and idempotent."""
        with self._lock:
            if self._closed:
                return
            _erase_and_unlink(self.private_key_path)
            _unlink_if_regular(self.certificate_path)
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise TlsMaterialError("ephemeral TLS directory was not empty") from exc
            self._closed = True

    def __enter__(self) -> TlsMaterialLease:  # noqa: PYI034 -- Python 3.10 supports no typing.Self
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class EphemeralTlsProvider:
    """Create and remove one exact-interface development certificate."""

    def __init__(
        self,
        *,
        generator: CertificateGenerator | None = None,
        certificate_ttl: int = 3600,
        wall_clock: WallClock = lambda: datetime.now(timezone.utc),
    ) -> None:
        if (
            not isinstance(certificate_ttl, int)
            or not 60 <= certificate_ttl <= MAX_CERTIFICATE_LIFETIME
        ):
            raise ValueError("certificate lifetime must be between 60 seconds and 24 hours")
        self._generator = generator or CryptographyCertificateGenerator()
        self._certificate_ttl = certificate_ttl
        self._wall_clock = wall_clock

    def prepare(
        self,
        *,
        interface_address: str,
        base_directory: Path | None = None,
    ) -> TlsMaterialLease:
        """Generate protected material, or fail without offering plaintext."""
        address = _validate_private_address(interface_address)
        now = self._wall_clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("TLS clock must return a timezone-aware datetime")
        now = now.astimezone(timezone.utc)
        not_before = now - timedelta(seconds=30)
        not_after = now + timedelta(seconds=self._certificate_ttl)
        generated = self._generator.generate(
            address=address,
            not_before=not_before,
            not_after=not_after,
        )
        _validate_generated(generated, address=address, now=now)
        directory = Path(
            tempfile.mkdtemp(
                prefix="lantern-lan-tls-",
                dir=str(base_directory) if base_directory is not None else None,
            )
        )
        certificate_path = directory / "certificate.pem"
        private_key_path = directory / "private-key.pem"
        try:
            os.chmod(directory, 0o700)
            _write_private_file(certificate_path, generated.certificate_pem)
            _write_private_file(private_key_path, generated.private_key_pem)
            fingerprint = hashlib.sha256(generated.certificate_der).hexdigest().upper()
            display_fingerprint = ":".join(
                fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2)
            )
            identity = DevelopmentCertificate(
                label=DEVELOPMENT_TLS_LABEL,
                fingerprint_sha256=display_fingerprint,
                valid_from=generated.not_before.astimezone(timezone.utc).isoformat(),
                valid_until=generated.not_after.astimezone(timezone.utc).isoformat(),
                interface_address=address,
            )
            return TlsMaterialLease(
                directory=directory,
                certificate_path=certificate_path,
                private_key_path=private_key_path,
                identity=identity,
            )
        except BaseException:
            _erase_and_unlink(private_key_path)
            _unlink_if_regular(certificate_path)
            try:
                directory.rmdir()
            except OSError:
                pass
            raise

    @staticmethod
    def create_server_context(material: TlsMaterialLease) -> ssl.SSLContext:
        """Create a TLS-only server context and load the ephemeral identity."""
        if material.closed:
            raise TlsMaterialError("TLS material has already been deleted")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if hasattr(ssl, "OP_NO_COMPRESSION"):
            context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(
            certfile=str(material.certificate_path),
            keyfile=str(material.private_key_path),
        )
        return context


class CryptographyCertificateGenerator:
    """Optional in-process ECDSA generator; import failure is explicit."""

    def generate(
        self,
        *,
        address: str,
        not_before: datetime,
        not_after: datetime,
    ) -> GeneratedCertificate:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        except ImportError as exc:
            raise TlsUnavailableError(
                "LAN TLS generation requires the optional cryptography package; "
                "plaintext fallback is forbidden"
            ) from exc

        parsed_address = ipaddress.ip_address(address)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Lantern Development Prototype")]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(parsed_address)]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .sign(key, hashes.SHA256())
        )
        return GeneratedCertificate(
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            private_key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            certificate_der=certificate.public_bytes(serialization.Encoding.DER),
            not_before=not_before,
            not_after=not_after,
            san_addresses=(address,),
            algorithm="ECDSA-P256",
        )


def _validate_generated(generated: GeneratedCertificate, *, address: str, now: datetime) -> None:
    if not isinstance(generated, GeneratedCertificate):
        raise TlsMaterialError("certificate generator returned an unknown type")
    if not generated.certificate_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise TlsMaterialError("generator did not return a PEM certificate")
    if not generated.private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"):
        raise TlsMaterialError("generator did not return a PKCS#8 PEM private key")
    if not generated.certificate_der:
        raise TlsMaterialError("generator did not return DER certificate bytes")
    if len(generated.certificate_pem) > _MAX_CERTIFICATE_BYTES:
        raise TlsMaterialError("certificate exceeds the size limit")
    if len(generated.private_key_pem) > _MAX_PRIVATE_KEY_BYTES:
        raise TlsMaterialError("private key exceeds the size limit")
    if generated.algorithm != "ECDSA-P256":
        raise TlsMaterialError("development certificate must use ECDSA P-256")
    if generated.san_addresses != (address,):
        raise TlsMaterialError("certificate SAN must contain only the selected interface")
    if generated.not_before.tzinfo is None or generated.not_after.tzinfo is None:
        raise TlsMaterialError("certificate validity must be timezone aware")
    lifetime = (generated.not_after - generated.not_before).total_seconds()
    if generated.not_before > now or generated.not_after <= now:
        raise TlsMaterialError("certificate is not currently valid")
    if lifetime <= 0 or lifetime > MAX_CERTIFICATE_LIFETIME + 30:
        raise TlsMaterialError("certificate lifetime exceeds the prototype policy")


def _validate_private_address(raw: str) -> str:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError("TLS interface address is invalid") from exc
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if address.version != 4 or not any(address in network for network in private_networks):
        raise ValueError("TLS identity requires an exact RFC1918 IPv4 address")
    return str(address)


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600, follow_symlinks=False)


def _erase_and_unlink(path: Path) -> None:
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        return
    if not path.is_file() or path.is_symlink():
        raise TlsMaterialError("ephemeral private key path changed type")
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        remaining = stat_result.st_size
        zeroes = bytes(min(4096, max(1, remaining)))
        while remaining > 0:
            written = os.write(descriptor, zeroes[: min(len(zeroes), remaining)])
            if written <= 0:
                raise TlsMaterialError("could not clear ephemeral private key")
            remaining -= written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.unlink()


def _unlink_if_regular(path: Path) -> None:
    try:
        if not path.is_file() or path.is_symlink():
            raise TlsMaterialError("ephemeral certificate path changed type")
        path.unlink()
    except FileNotFoundError:
        return
