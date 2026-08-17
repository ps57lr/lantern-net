"""Source-bound, short-lived session authority for Lantern LAN."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import math
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

from netdiag.lan.pairing import PairingAuthority, PairingGrant

Clock = Callable[[], float]
RandomBytes = Callable[[int], bytes]

SESSION_COOKIE_NAME: Final[str] = "lantern_lan_session"
CSRF_HEADER_NAME: Final[str] = "X-Lantern-CSRF"
ALLOWED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "network.read",
        "network.run.passive",
        "network.run.path",
        "network.run.scoped-discovery",
        "report.read.redacted",
        "report.export.redacted",
        "session.end",
    }
)


class SessionConfigurationError(ValueError):
    """Raised when session policy or randomness is unsafe."""


@dataclass(frozen=True, slots=True)
class SessionCredentials:
    """Credentials returned only to the newly paired HTTPS client."""

    session_id: str
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    cookie_header: str = field(repr=False)
    expires_in: int


@dataclass(frozen=True, slots=True)
class HostScopeApproval:
    """One-use, process-local approval created only by the host control plane."""

    session_id: str
    capabilities: tuple[str, ...]
    _authority_marker: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class SessionView:
    """Non-secret session state safe for the paired client and host UI."""

    session_id: str
    source_address: str
    client_label: str
    capabilities: tuple[str, ...]
    idle_expires_in: int
    absolute_expires_in: int
    issued_age: int


@dataclass(slots=True)
class _Session:
    session_id: str
    source_address: str
    client_label: str
    capabilities: tuple[str, ...]
    csrf_digest: bytes
    issued_at: float
    last_seen_at: float
    absolute_expires_at: float


class SessionAuthority:
    """Thread-safe session store with idle, absolute, source, and CSRF binding."""

    def __init__(
        self,
        *,
        source_network: str,
        idle_ttl: int = 300,
        absolute_ttl: int = 900,
        maximum_sessions: int = 8,
        pairing: PairingAuthority | None = None,
        clock: Clock = time.monotonic,
        random_bytes: RandomBytes = secrets.token_bytes,
    ) -> None:
        network = ipaddress.ip_network(source_network, strict=True)
        if network.version != 4 or not _is_rfc1918_network(network):
            raise SessionConfigurationError("session source network must be exact RFC1918 IPv4")
        if not isinstance(idle_ttl, int) or not isinstance(absolute_ttl, int):
            raise SessionConfigurationError("session lifetimes must be integers")
        if idle_ttl <= 0 or absolute_ttl <= 0 or idle_ttl > absolute_ttl:
            raise SessionConfigurationError("idle lifetime must fit within absolute lifetime")
        if absolute_ttl > 3600:
            raise SessionConfigurationError("absolute session lifetime cannot exceed one hour")
        if not isinstance(maximum_sessions, int) or not 1 <= maximum_sessions <= 32:
            raise SessionConfigurationError("maximum sessions must be between 1 and 32")
        self._network = network
        self._idle_ttl = idle_ttl
        self._absolute_ttl = absolute_ttl
        self._maximum_sessions = maximum_sessions
        self._pairing = pairing
        self._clock = clock
        self._random_bytes = random_bytes
        self._digest_key = bytearray(self._random_exact(32))
        self._lock = threading.RLock()
        self._sessions: dict[bytes, _Session] = {}
        self._host_marker = object()
        self._scope_approvals: dict[str, int] = {}
        self._closed = False

    @property
    def source_network(self) -> str:
        """Exact network to which bearer tokens are source-bound."""
        return str(self._network)

    @property
    def pairing_authority(self) -> PairingAuthority | None:
        """Authority whose one-use grants are accepted for session issuance."""
        return self._pairing

    def issue(
        self,
        grant: PairingGrant,
        *,
        capabilities: Iterable[str],
    ) -> SessionCredentials:
        """Mint 256-bit credentials for a successfully paired socket source."""
        if not isinstance(grant, PairingGrant):
            raise TypeError("session issuance requires a verified PairingGrant")
        source = self._validate_source(grant.source_address)
        capability_tuple = _validate_capabilities(capabilities)
        now = self._clock()
        with self._lock:
            self._require_open()
            self._prune(now)
            if len(self._sessions) >= self._maximum_sessions:
                raise PermissionError("temporary LAN session limit reached")
            if self._pairing is None or not self._pairing.consume_grant(grant):
                raise PermissionError(
                    "pairing grant is invalid, replayed, or from another authority"
                )
            return self._mint_locked(
                source_address=source,
                client_label=grant.client_label,
                capabilities=capability_tuple,
                now=now,
            )

    def authenticate(
        self,
        token: object,
        *,
        source_address: str,
        touch: bool = True,
    ) -> SessionView | None:
        """Authenticate one request and optionally extend only its idle deadline."""
        source = self._validate_source(source_address)
        token_digest = self._token_digest(token)
        now = self._clock()
        with self._lock:
            if self._closed:
                return None
            self._prune(now)
            session = self._sessions.get(token_digest)
            if session is None or session.source_address != source:
                return None
            if touch:
                session.last_seen_at = now
            return self._view(session, now)

    def verify_csrf(
        self,
        token: object,
        csrf_candidate: object,
        *,
        source_address: str,
    ) -> SessionView | None:
        """Require session, source, and CSRF proof before a mutation."""
        source = self._validate_source(source_address)
        token_digest = self._token_digest(token)
        csrf_digest = self._csrf_digest(csrf_candidate)
        now = self._clock()
        with self._lock:
            if self._closed:
                return None
            self._prune(now)
            session = self._sessions.get(token_digest)
            valid = bool(
                session is not None
                and session.source_address == source
                and hmac.compare_digest(session.csrf_digest, csrf_digest)
            )
            if not valid or session is None:
                return None
            session.last_seen_at = now
            return self._view(session, now)

    def approve_scope_change(
        self,
        session_id: str,
        *,
        capabilities: Iterable[str],
    ) -> HostScopeApproval:
        """Create a one-use approval from the local host control plane.

        The LAN API exposes no route to this method.  A remote bearer token alone
        therefore cannot request broader capabilities.
        """
        capability_tuple = _validate_capabilities(capabilities)
        with self._lock:
            self._require_open()
            if not any(session.session_id == session_id for session in self._sessions.values()):
                raise ValueError("scope approval session does not exist")
            approval = HostScopeApproval(session_id, capability_tuple, self._host_marker)
            # At most one outstanding approval per active session prevents an
            # accidental local-control loop from growing state without bound.
            self._scope_approvals[session_id] = id(approval)
            return approval

    def rotate(
        self,
        token: object,
        *,
        source_address: str,
        approval: HostScopeApproval,
    ) -> SessionCredentials | None:
        """Invalidate the old bearer token while applying a host-approved scope change."""
        source = self._validate_source(source_address)
        token_digest = self._token_digest(token)
        now = self._clock()
        with self._lock:
            if self._closed:
                return None
            if (
                not isinstance(approval, HostScopeApproval)
                or approval._authority_marker is not self._host_marker
                or self._scope_approvals.get(approval.session_id) != id(approval)
            ):
                raise PermissionError("scope rotation requires fresh local host approval")
            self._scope_approvals.pop(approval.session_id, None)
            self._prune(now)
            session = self._sessions.get(token_digest)
            if (
                session is None
                or session.source_address != source
                or session.session_id != approval.session_id
            ):
                return None
            del self._sessions[token_digest]
            return self._mint_locked(
                source_address=session.source_address,
                client_label=session.client_label,
                capabilities=approval.capabilities,
                now=now,
            )

    def revoke(self, session_id: str) -> bool:
        """Immediately revoke one session by its non-secret host-visible ID."""
        with self._lock:
            for digest, session in tuple(self._sessions.items()):
                if hmac.compare_digest(session.session_id, session_id):
                    del self._sessions[digest]
                    self._scope_approvals.pop(session.session_id, None)
                    return True
            return False

    def revoke_token(self, token: object, *, source_address: str) -> bool:
        """Let an authenticated client end only its own source-bound session."""
        source = self._validate_source(source_address)
        token_digest = self._token_digest(token)
        with self._lock:
            session = self._sessions.get(token_digest)
            if session is None or session.source_address != source:
                return False
            del self._sessions[token_digest]
            self._scope_approvals.pop(session.session_id, None)
            return True

    def list_clients(self) -> tuple[SessionView, ...]:
        """Return active sessions without tokens or CSRF capabilities."""
        now = self._clock()
        with self._lock:
            if self._closed:
                return ()
            self._prune(now)
            return tuple(
                self._view(session, now)
                for session in sorted(self._sessions.values(), key=lambda item: item.session_id)
            )

    def expire(self) -> tuple[str, ...]:
        """Prune expired sessions and return their non-secret IDs for audit."""
        now = self._clock()
        with self._lock:
            if self._closed:
                return ()
            return self._prune(now)

    def revoke_all(self) -> tuple[str, ...]:
        """Revoke every active token without closing the authority."""
        with self._lock:
            identifiers = tuple(session.session_id for session in self._sessions.values())
            self._sessions.clear()
            self._scope_approvals.clear()
            return identifiers

    def close(self) -> None:
        """Permanently invalidate restart-era tokens and erase the digest key buffer."""
        with self._lock:
            self._sessions.clear()
            self._scope_approvals.clear()
            for index in range(len(self._digest_key)):
                self._digest_key[index] = 0
            self._closed = True

    def _mint_locked(
        self,
        *,
        source_address: str,
        client_label: str,
        capabilities: tuple[str, ...],
        now: float,
    ) -> SessionCredentials:
        token = _encode_token(self._random_exact(32))
        csrf_token = _encode_token(self._random_exact(32))
        session_id = self._random_exact(12).hex()
        token_digest = self._token_digest(token)
        if token_digest in self._sessions:
            raise SessionConfigurationError("random source repeated a session token")
        self._sessions[token_digest] = _Session(
            session_id=session_id,
            source_address=source_address,
            client_label=client_label,
            capabilities=capabilities,
            csrf_digest=self._csrf_digest(csrf_token),
            issued_at=now,
            last_seen_at=now,
            absolute_expires_at=now + self._absolute_ttl,
        )
        max_age = min(self._idle_ttl, self._absolute_ttl)
        cookie = (
            f"{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; "
            "Secure; HttpOnly; SameSite=Strict"
        )
        return SessionCredentials(
            session_id=session_id,
            token=token,
            csrf_token=csrf_token,
            cookie_header=cookie,
            expires_in=max_age,
        )

    def _prune(self, now: float) -> tuple[str, ...]:
        expired: list[str] = []
        for digest, session in tuple(self._sessions.items()):
            idle_expires_at = session.last_seen_at + self._idle_ttl
            if now >= min(idle_expires_at, session.absolute_expires_at):
                expired.append(session.session_id)
                del self._sessions[digest]
                self._scope_approvals.pop(session.session_id, None)
        return tuple(expired)

    def _view(self, session: _Session, now: float) -> SessionView:
        return SessionView(
            session_id=session.session_id,
            source_address=session.source_address,
            client_label=session.client_label,
            capabilities=session.capabilities,
            idle_expires_in=max(0, math.ceil(session.last_seen_at + self._idle_ttl - now)),
            absolute_expires_in=max(0, math.ceil(session.absolute_expires_at - now)),
            issued_age=max(0, int(now - session.issued_at)),
        )

    def _token_digest(self, candidate: object) -> bytes:
        token = candidate if _valid_encoded_token(candidate) else "?" * 43
        return hmac.new(self._digest_key, token.encode("ascii"), hashlib.sha256).digest()

    def _csrf_digest(self, candidate: object) -> bytes:
        token = candidate if _valid_encoded_token(candidate) else "?" * 43
        return hmac.new(
            self._digest_key,
            b"csrf\0" + token.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _random_exact(self, count: int) -> bytes:
        value = self._random_bytes(count)
        if not isinstance(value, bytes) or len(value) != count:
            raise SessionConfigurationError("random source returned the wrong number of bytes")
        return value

    def _validate_source(self, raw: str) -> str:
        try:
            source = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("source address is invalid") from exc
        if source.version != 4 or source not in self._network:
            raise PermissionError("source is outside the selected LAN scope")
        if source in (self._network.network_address, self._network.broadcast_address):
            raise PermissionError("source is not a usable LAN host")
        return str(source)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("session authority is closed")


def _encode_token(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _valid_encoded_token(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == 32


def _validate_capabilities(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("capabilities must be an iterable of stable identifiers")
    capabilities = tuple(sorted(set(values)))
    if not capabilities:
        raise ValueError("session must have at least one capability")
    if any(capability not in ALLOWED_CAPABILITIES for capability in capabilities):
        raise ValueError("session includes an unknown capability")
    return capabilities


_PRIVATE_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918_network(network: ipaddress._BaseNetwork) -> bool:
    return network.version == 4 and any(network.subnet_of(parent) for parent in _PRIVATE_NETWORKS)
