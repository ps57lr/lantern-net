"""Security primitives for Lantern's loopback-only local application.

This module deliberately has no networking code.  It owns short-lived launch
capabilities, authenticated browser sessions, CSRF verification, and bounded
failed-exchange tracking so those rules can be tested deterministically.
Secrets are generated with :mod:`secrets` by default and retained only as
SHA-256 digests after issuance.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

Clock = Callable[[], float]
TokenFactory = Callable[[int], str]

SESSION_COOKIE_NAME: Final[str] = "lantern_session"
CSRF_HEADER_NAME: Final[str] = "X-Lantern-CSRF"

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii", errors="strict")).digest()


def _valid_token_shape(value: object) -> bool:
    return isinstance(value, str) and _TOKEN_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ExchangeResult:
    """The browser credentials produced by a successful one-use exchange."""

    session_id: str
    csrf_token: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class SessionView:
    """Non-secret state about an authenticated browser session."""

    expires_in: int


@dataclass(slots=True)
class _LaunchCapability:
    digest: bytes
    expires_at: float
    consumed: bool = False


@dataclass(slots=True)
class _Session:
    expires_at: float


@dataclass(slots=True)
class _AttemptWindow:
    started_at: float
    failures: int = 0
    blocked_until: float = 0.0


class LocalSessionSecurity:
    """Thread-safe one-use launch and local browser-session authority.

    ``client_key`` is supplied by the HTTP boundary.  For a loopback service it
    is normally the peer IP plus a stable server-specific label.  The class
    accepts an injected monotonic clock and token factory only to make security
    behavior deterministic under test.
    """

    def __init__(
        self,
        *,
        launch_ttl: int = 120,
        session_ttl: int = 900,
        failure_limit: int = 5,
        failure_window: int = 60,
        lockout_seconds: int = 30,
        clock: Clock = time.monotonic,
        token_factory: TokenFactory = secrets.token_urlsafe,
    ) -> None:
        if launch_ttl <= 0 or session_ttl <= 0:
            raise ValueError("security lifetimes must be positive")
        if failure_limit <= 0 or failure_window <= 0 or lockout_seconds <= 0:
            raise ValueError("rate-limit settings must be positive")
        self._launch_ttl = launch_ttl
        self._session_ttl = session_ttl
        self._failure_limit = failure_limit
        self._failure_window = failure_window
        self._lockout_seconds = lockout_seconds
        self._clock = clock
        self._token_factory = token_factory
        self._csrf_signing_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._launch: _LaunchCapability | None = None
        self._sessions: dict[bytes, _Session] = {}
        self._attempts: dict[str, _AttemptWindow] = {}

    @property
    def session_ttl(self) -> int:
        return self._session_ttl

    def issue_launch_token(self) -> str:
        """Replace any prior launch capability and return a new raw token once."""
        raw = self._new_token()
        now = self._clock()
        with self._lock:
            self._launch = _LaunchCapability(
                digest=_digest(raw),
                expires_at=now + self._launch_ttl,
            )
            self._attempts.clear()
        return raw

    def exchange(self, candidate: object, *, client_key: str) -> ExchangeResult | None:
        """Consume a valid launch token and mint a browser session.

        Invalid, expired, malformed, and replayed capabilities all produce the
        same ``None`` result.  A caller should check :meth:`retry_after` first
        and record failures through this method only, preventing token-oracle
        differences at the HTTP boundary.
        """
        now = self._clock()
        with self._lock:
            self._prune(now)
            if self._retry_after_locked(client_key, now) > 0:
                return None

            launch = self._launch
            candidate_digest = self._candidate_digest(candidate)
            valid = (
                launch is not None
                and not launch.consumed
                and launch.expires_at > now
                and hmac.compare_digest(launch.digest, candidate_digest)
            )
            if not valid:
                self._record_failure_locked(client_key, now)
                return None

            launch.consumed = True
            self._attempts.pop(client_key, None)
            session_id = self._new_token()
            csrf_token = self._csrf_for_session(session_id)
            self._sessions[_digest(session_id)] = _Session(
                expires_at=now + self._session_ttl,
            )
            return ExchangeResult(
                session_id=session_id,
                csrf_token=csrf_token,
                expires_in=self._session_ttl,
            )

    def retry_after(self, client_key: str) -> int:
        """Return whole seconds until exchanges may resume, or zero."""
        now = self._clock()
        with self._lock:
            self._prune(now)
            remaining = self._retry_after_locked(client_key, now)
            if remaining <= 0:
                return 0
            return max(1, int(remaining + 0.999))

    def authenticate(self, session_id: object) -> SessionView | None:
        """Validate a session cookie without extending its absolute lifetime."""
        if not _valid_token_shape(session_id):
            return None
        now = self._clock()
        session_digest = _digest(session_id)
        with self._lock:
            self._prune(now)
            session = self._sessions.get(session_digest)
            if session is None or session.expires_at <= now:
                return None
            return SessionView(expires_in=max(1, int(session.expires_at - now + 0.999)))

    def verify_csrf(self, session_id: object, candidate: object) -> bool:
        """Validate an authenticated session and its anti-CSRF capability."""
        if not _valid_token_shape(session_id) or not _valid_token_shape(candidate):
            return False
        now = self._clock()
        session_digest = _digest(session_id)
        with self._lock:
            self._prune(now)
            session = self._sessions.get(session_digest)
            return bool(
                session is not None
                and session.expires_at > now
                and hmac.compare_digest(self._csrf_for_session(session_id), candidate)
            )

    def session_csrf(self, session_id: object) -> str | None:
        """Derive the stable CSRF token for an authenticated session."""
        if not _valid_token_shape(session_id):
            return None
        now = self._clock()
        session_digest = _digest(session_id)
        with self._lock:
            self._prune(now)
            session = self._sessions.get(session_digest)
            if session is None or session.expires_at <= now:
                return None
            return self._csrf_for_session(session_id)

    def revoke(self, session_id: object) -> bool:
        """Revoke a session immediately; return whether one existed."""
        if not _valid_token_shape(session_id):
            return False
        with self._lock:
            return self._sessions.pop(_digest(session_id), None) is not None

    def revoke_all(self) -> None:
        """Destroy every launch and browser capability during server shutdown."""
        with self._lock:
            self._launch = None
            self._sessions.clear()
            self._attempts.clear()

    def _new_token(self) -> str:
        token = self._token_factory(32)
        if not _valid_token_shape(token):
            raise ValueError("token factory returned an unsafe token")
        return token

    def _csrf_for_session(self, session_id: str) -> str:
        digest = hmac.new(
            self._csrf_signing_key,
            session_id.encode("ascii", errors="strict"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def _candidate_digest(candidate: object) -> bytes:
        if not _valid_token_shape(candidate):
            # Keep the comparison path fixed-size without hashing unbounded or
            # non-ASCII attacker input.
            return b"\x00" * hashlib.sha256().digest_size
        return _digest(candidate)

    def _retry_after_locked(self, client_key: str, now: float) -> float:
        window = self._attempts.get(client_key)
        if window is None:
            return 0.0
        return max(0.0, window.blocked_until - now)

    def _record_failure_locked(self, client_key: str, now: float) -> None:
        window = self._attempts.get(client_key)
        if window is None or now - window.started_at >= self._failure_window:
            window = _AttemptWindow(started_at=now)
            self._attempts[client_key] = window
        window.failures += 1
        if window.failures >= self._failure_limit:
            window.blocked_until = now + self._lockout_seconds

    def _prune(self, now: float) -> None:
        expired_sessions = [
            digest for digest, session in self._sessions.items() if session.expires_at <= now
        ]
        for digest in expired_sessions:
            self._sessions.pop(digest, None)

        expired_attempts = [
            key
            for key, window in self._attempts.items()
            if window.blocked_until <= now and now - window.started_at >= self._failure_window
        ]
        for key in expired_attempts:
            self._attempts.pop(key, None)
