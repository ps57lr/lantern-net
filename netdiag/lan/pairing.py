"""One-use, rate-limited pairing authority for Lantern LAN.

Pairing codes are intended to be displayed only on the host.  The authority keeps
only a keyed digest, compares candidates in constant time, and deliberately gives
the remote caller no expired/replayed/wrong-code oracle.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import secrets
import threading
import time
import unicodedata
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Final

Clock = Callable[[], float]
RandomBytes = Callable[[int], bytes]

PAIRING_CODE_LENGTH: Final[int] = 8
UNAMBIGUOUS_ALPHABET: Final[str] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
_PAIRING_CODE_BYTES: Final[int] = 32
_MAX_PENDING_GRANTS: Final[int] = 8


class PairingConfigurationError(ValueError):
    """Raised when pairing policy would weaken the security boundary."""


@dataclass(frozen=True, slots=True)
class PairingDisplay:
    """Host-only value returned exactly once after issuing or rotating a code."""

    code: str = dataclass_field(repr=False)
    expires_in: int
    generation: str


@dataclass(frozen=True, slots=True)
class PairingGrant:
    """Non-secret verified identity passed to the local session authority."""

    source_address: str
    client_label: str
    generation: str
    grant_id: str
    _authority_marker: object = dataclass_field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class PairingDecision:
    """Uniform pairing result safe for translation at the HTTP boundary."""

    accepted: bool
    retry_after: int
    reason: str
    grant: PairingGrant | None = None


@dataclass(slots=True)
class _CodeState:
    digest: bytes
    generation: str
    expires_at: float
    failures: int = 0
    consumed: bool = False
    locked: bool = False


@dataclass(slots=True)
class _SourceState:
    failures: deque[float]
    blocked_until: float = 0.0


class PairingAuthority:
    """Thread-safe authority for one temporary responder's pairing code.

    ``source_network`` must be the exact private network selected by the local
    owner.  Forwarded headers must never be supplied as ``source_address``; it is
    expected to come from the accepted socket peer.
    """

    def __init__(
        self,
        *,
        source_network: str,
        code_ttl: int = 600,
        code_failure_limit: int = 5,
        source_failure_limit: int = 5,
        global_failure_limit: int = 25,
        failure_window: int = 60,
        maximum_backoff: int = 30,
        clock: Clock = time.monotonic,
        random_bytes: RandomBytes = secrets.token_bytes,
    ) -> None:
        network = ipaddress.ip_network(source_network, strict=True)
        if network.version != 4 or not _is_rfc1918_network(network):
            raise PairingConfigurationError("pairing source network must be exact RFC1918 IPv4")
        numeric = (
            code_ttl,
            code_failure_limit,
            source_failure_limit,
            global_failure_limit,
            failure_window,
            maximum_backoff,
        )
        if any(not isinstance(value, int) or value <= 0 for value in numeric):
            raise PairingConfigurationError("pairing limits must be positive integers")
        if code_ttl > 600:
            raise PairingConfigurationError("pairing code lifetime cannot exceed ten minutes")
        if code_failure_limit > source_failure_limit:
            raise PairingConfigurationError("per-code limit cannot exceed per-source limit")
        if global_failure_limit < source_failure_limit:
            raise PairingConfigurationError("global limit cannot be below per-source limit")
        self._network = network
        self._code_ttl = code_ttl
        self._code_failure_limit = code_failure_limit
        self._source_failure_limit = source_failure_limit
        self._global_failure_limit = global_failure_limit
        self._failure_window = failure_window
        self._maximum_backoff = maximum_backoff
        self._clock = clock
        self._random_bytes = random_bytes
        self._digest_key = bytearray(self._random_exact(32))
        self._lock = threading.RLock()
        self._code: _CodeState | None = None
        self._sources: dict[str, _SourceState] = {}
        self._global_failures: deque[float] = deque()
        self._grant_marker = object()
        self._pending_grants: dict[int, str] = {}
        self._closed = False

    @property
    def source_network(self) -> str:
        """Exact peer network used to check transport-injected source addresses."""
        return str(self._network)

    def issue(self) -> PairingDisplay:
        """Rotate the code and return its raw display value once to the host."""
        now = self._clock()
        with self._lock:
            if self._closed:
                raise RuntimeError("pairing authority is closed")
            self._prune(now)
            previous = self._code.digest if self._code is not None else None
            for _attempt in range(8):
                code = self._new_code()
                digest = self._code_digest(code)
                if previous is None or not hmac.compare_digest(previous, digest):
                    break
            else:
                raise PairingConfigurationError("random source repeated the pairing code")
            generation = self._new_identifier()
            self._code = _CodeState(
                digest=digest,
                generation=generation,
                expires_at=now + self._code_ttl,
            )
        return PairingDisplay(code=code, expires_in=self._code_ttl, generation=generation)

    def attempt(
        self,
        candidate: object,
        *,
        source_address: str,
        client_label: object,
    ) -> PairingDecision:
        """Attempt a constant-time exchange from one socket-derived source."""
        source = self._validate_source(source_address)
        label = validate_client_label(client_label)
        now = self._clock()
        with self._lock:
            if self._closed:
                return PairingDecision(False, 0, "pairing_failed")
            candidate_digest = self._candidate_digest(candidate)
            self._prune(now)
            retry_after = self._retry_after_locked(source, now)
            if retry_after > 0:
                return PairingDecision(False, retry_after, "pairing_failed")

            code = self._code
            expected = code.digest if code is not None else bytes(hashlib.sha256().digest_size)
            digest_matches = hmac.compare_digest(expected, candidate_digest)
            accepted = bool(
                code is not None
                and not code.consumed
                and not code.locked
                and code.expires_at > now
                and digest_matches
                and len(self._pending_grants) < _MAX_PENDING_GRANTS
            )
            if not accepted:
                self._record_failure_locked(source, now)
                retry_after = self._retry_after_locked(source, now)
                return PairingDecision(False, retry_after, "pairing_failed")

            code.consumed = True
            self._sources.pop(source, None)
            grant_id = self._new_identifier()
            grant = PairingGrant(
                source_address=source,
                client_label=label,
                generation=code.generation,
                grant_id=grant_id,
                _authority_marker=self._grant_marker,
            )
            self._pending_grants[id(grant)] = grant_id
            return PairingDecision(True, 0, "accepted", grant)

    def consume_grant(self, grant: PairingGrant) -> bool:
        """Consume exactly one process-local proof before session issuance."""
        if not isinstance(grant, PairingGrant):
            return False
        with self._lock:
            if self._closed:
                return False
            valid = bool(
                grant._authority_marker is self._grant_marker
                and self._pending_grants.get(id(grant)) == grant.grant_id
            )
            if valid:
                self._pending_grants.pop(id(grant), None)
            return valid

    def retry_after(self, source_address: str) -> int:
        """Return a bounded delay without revealing code state."""
        source = self._validate_source(source_address)
        now = self._clock()
        with self._lock:
            if self._closed:
                return 0
            self._prune(now)
            return self._retry_after_locked(source, now)

    def invalidate(self) -> None:
        """Destroy code state and rate-limit history during service shutdown."""
        with self._lock:
            self._code = None
            self._sources.clear()
            self._global_failures.clear()
            self._pending_grants.clear()

    def close(self) -> None:
        """Permanently destroy pairing state and erase its digest-key buffer."""
        with self._lock:
            self._code = None
            self._sources.clear()
            self._global_failures.clear()
            self._pending_grants.clear()
            for index in range(len(self._digest_key)):
                self._digest_key[index] = 0
            self._closed = True

    def host_status(self) -> dict[str, object]:
        """Return host-safe state without the code or its digest."""
        now = self._clock()
        with self._lock:
            if self._closed:
                return {"issued": False, "usable": False, "expires_in": 0}
            self._prune(now)
            code = self._code
            if code is None:
                return {"issued": False, "usable": False, "expires_in": 0}
            return {
                "issued": True,
                "usable": not code.consumed and not code.locked and code.expires_at > now,
                "expires_in": max(0, math.ceil(code.expires_at - now)),
                "generation": code.generation,
                "failed_attempts": code.failures,
            }

    def _record_failure_locked(self, source: str, now: float) -> None:
        state = self._sources.setdefault(source, _SourceState(deque()))
        state.failures.append(now)
        self._global_failures.append(now)
        consecutive = len(state.failures)
        delay = min(self._maximum_backoff, max(0, (2 ** min(consecutive - 1, 10)) - 1))
        state.blocked_until = max(state.blocked_until, now + delay)
        if self._code is not None:
            self._code.failures += 1
            if self._code.failures >= self._code_failure_limit:
                self._code.locked = True

    def _retry_after_locked(self, source: str, now: float) -> int:
        state = self._sources.get(source)
        waits: list[float] = []
        if state is not None:
            waits.append(state.blocked_until - now)
            if len(state.failures) >= self._source_failure_limit:
                waits.append(state.failures[0] + self._failure_window - now)
        if len(self._global_failures) >= self._global_failure_limit:
            waits.append(self._global_failures[0] + self._failure_window - now)
        positive = [wait for wait in waits if wait > 0]
        return max(0, math.ceil(max(positive, default=0.0)))

    def _prune(self, now: float) -> None:
        threshold = now - self._failure_window
        while self._global_failures and self._global_failures[0] <= threshold:
            self._global_failures.popleft()
        for source, state in tuple(self._sources.items()):
            while state.failures and state.failures[0] <= threshold:
                state.failures.popleft()
            if not state.failures and state.blocked_until <= now:
                del self._sources[source]

    def _candidate_digest(self, candidate: object) -> bytes:
        normalized = candidate if isinstance(candidate, str) else ""
        if len(normalized) != PAIRING_CODE_LENGTH or any(
            character not in UNAMBIGUOUS_ALPHABET for character in normalized
        ):
            normalized = "?" * PAIRING_CODE_LENGTH
        return self._code_digest(normalized)

    def _code_digest(self, code: str) -> bytes:
        return hmac.new(self._digest_key, code.encode("ascii"), hashlib.sha256).digest()

    def _new_code(self) -> str:
        # Rejection sampling avoids modulo bias because the alphabet has 31 symbols.
        limit = 256 - (256 % len(UNAMBIGUOUS_ALPHABET))
        characters: list[str] = []
        for _batch in range(32):
            for value in self._random_exact(16):
                if value < limit:
                    characters.append(UNAMBIGUOUS_ALPHABET[value % len(UNAMBIGUOUS_ALPHABET)])
                    if len(characters) == PAIRING_CODE_LENGTH:
                        return "".join(characters)
        raise PairingConfigurationError("random source could not produce an unbiased pairing code")

    def _new_identifier(self) -> str:
        return self._random_exact(12).hex()

    def _random_exact(self, count: int) -> bytes:
        value = self._random_bytes(count)
        if not isinstance(value, bytes) or len(value) != count:
            raise PairingConfigurationError("random source returned the wrong number of bytes")
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


def validate_client_label(value: object) -> str:
    """Normalize a friendly label while rejecting controls and visual-spoof marks."""
    if not isinstance(value, str):
        raise TypeError("client label must be text")
    label = unicodedata.normalize("NFC", value.strip())
    if not label or len(label) > 64:
        raise ValueError("client label must contain 1-64 characters")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in label
    ):
        raise ValueError("client label contains control characters")
    return label


_PRIVATE_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918_network(network: ipaddress._BaseNetwork) -> bool:
    return network.version == 4 and any(network.subnet_of(parent) for parent in _PRIVATE_NETWORKS)
