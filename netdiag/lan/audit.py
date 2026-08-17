"""Bounded, structurally safe security-event audit for Lantern LAN.

The audit API intentionally has no free-form detail or metadata field.  It cannot
accept pairing codes, bearer tokens, credentials, report bodies, SSIDs, MACs, or
client labels.  Socket addresses are represented by a per-run keyed pseudonym.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Final

WallClock = Callable[[], datetime]
RandomBytes = Callable[[int], bytes]


_AUDIT_EVENT_ISSUANCE_KEY: Final[bytes] = secrets.token_bytes(32)


def _audit_event_seal(
    *,
    sequence: int,
    event_id: str,
    occurred_at: str,
    kind: str,
    outcome: str,
    source_ref: str | None,
    session_ref: str | None,
    action: str | None,
    reason: str | None,
) -> bytes:
    """Bind an event's complete reviewed representation to this process."""
    payload = json.dumps(
        [
            sequence,
            event_id,
            occurred_at,
            kind,
            outcome,
            source_ref,
            session_ref,
            action,
            reason,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hmac.new(_AUDIT_EVENT_ISSUANCE_KEY, payload, hashlib.sha256).digest()


class AuditEventKind(str, Enum):
    SERVICE_STARTED = "service_started"
    CONNECTION_OBSERVED = "connection_observed"
    PAIRING_ATTEMPT = "pairing_attempt"
    PAIRING_SUCCEEDED = "pairing_succeeded"
    PAIRING_ROTATED = "pairing_rotated"
    SESSION_SCOPE_CHANGED = "session_scope_changed"
    SCAN_REQUESTED = "scan_requested"
    REPORT_EXPORTED = "report_exported"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    SERVICE_STOPPED = "service_stopped"


class AuditOutcome(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"


class AuditAction(str, Enum):
    PAIR = "pair"
    ROTATE_PAIRING = "rotate_pairing"
    READ_NETWORK_SUMMARY = "read_network_summary"
    RUN_PASSIVE = "run_passive"
    RUN_PATH = "run_path"
    RUN_SCOPED_DISCOVERY = "run_scoped_discovery"
    EXPORT_REDACTED_REPORT = "export_redacted_report"
    CHANGE_SESSION_SCOPE = "change_session_scope"
    END_SESSION = "end_session"
    STOP_SERVICE = "stop_service"


class AuditReason(str, Enum):
    HOST_APPROVED = "host_approved"
    INVALID_PROOF = "invalid_proof"
    RATE_LIMITED = "rate_limited"
    POLICY_DENIED = "policy_denied"
    SOURCE_MISMATCH = "source_mismatch"
    IDLE_TIMEOUT = "idle_timeout"
    ABSOLUTE_TIMEOUT = "absolute_timeout"
    HOST_REVOKED = "host_revoked"
    CLIENT_ENDED = "client_ended"
    SHUTDOWN = "shutdown"
    INTERNAL_FAILURE = "internal_failure"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    event_id: str
    occurred_at: str
    kind: str
    outcome: str
    source_ref: str | None
    session_ref: str | None
    action: str | None
    reason: str | None
    _issuance_seal: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or not 1 <= self.sequence <= 2**63 - 1
        ):
            raise ValueError("audit sequence must be a positive integer")
        if self.event_id != f"event-{self.sequence:08d}":
            raise ValueError("audit event ID must match its sequence")
        if not isinstance(self.occurred_at, str) or len(self.occurred_at) > 40:
            raise ValueError("audit timestamp must be a bounded string")
        try:
            occurred_at = datetime.fromisoformat(self.occurred_at)
        except ValueError as exc:
            raise ValueError("audit timestamp must be ISO-8601") from exc
        if occurred_at.tzinfo is None or occurred_at.utcoffset() != timezone.utc.utcoffset(None):
            raise ValueError("audit timestamp must use an explicit UTC offset")
        if occurred_at.isoformat() != self.occurred_at:
            raise ValueError("audit timestamp must use canonical ISO-8601 form")
        if self.kind not in {kind.value for kind in AuditEventKind}:
            raise ValueError("audit event kind is not registered")
        if self.outcome not in {outcome.value for outcome in AuditOutcome}:
            raise ValueError("audit outcome is not registered")
        if (
            self.source_ref is not None
            and re.fullmatch(r"source-[a-f0-9]{16}", self.source_ref) is None
        ):
            raise ValueError("audit source reference is not a generated pseudonym")
        if self.session_ref is not None and _SAFE_SESSION_RE.fullmatch(self.session_ref) is None:
            raise ValueError("audit session reference is invalid")
        if self.action is not None and self.action not in {action.value for action in AuditAction}:
            raise ValueError("audit action is not registered")
        if self.reason is not None and self.reason not in {reason.value for reason in AuditReason}:
            raise ValueError("audit reason is not registered")
        expected_seal = _audit_event_seal(
            sequence=self.sequence,
            event_id=self.event_id,
            occurred_at=self.occurred_at,
            kind=self.kind,
            outcome=self.outcome,
            source_ref=self.source_ref,
            session_ref=self.session_ref,
            action=self.action,
            reason=self.reason,
        )
        if not isinstance(self._issuance_seal, bytes) or not hmac.compare_digest(
            self._issuance_seal,
            expected_seal,
        ):
            raise ValueError("audit event was not issued by AuditLog or was modified")

    def as_dict(self) -> dict[str, int | str | None]:
        # Revalidate at export because object.__setattr__ can bypass a frozen
        # dataclass in privileged or extension code.
        self.__post_init__()
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "kind": self.kind,
            "outcome": self.outcome,
            "source_ref": self.source_ref,
            "session_ref": self.session_ref,
            "action": self.action,
            "reason": self.reason,
        }


_SAFE_SESSION_RE: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{24}$")


class AuditLog:
    """Thread-safe bounded audit ring with per-run address pseudonyms."""

    def __init__(
        self,
        *,
        maximum_events: int = 512,
        wall_clock: WallClock = lambda: datetime.now(timezone.utc),
        random_bytes: RandomBytes = secrets.token_bytes,
    ) -> None:
        if not isinstance(maximum_events, int) or not 16 <= maximum_events <= 4096:
            raise ValueError("audit capacity must be between 16 and 4096 events")
        self._maximum_events = maximum_events
        self._wall_clock = wall_clock
        key = random_bytes(32)
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("audit random source returned the wrong number of bytes")
        self._source_key = bytearray(key)
        self._events: deque[AuditEvent] = deque(maxlen=maximum_events)
        self._sequence = 0
        self._closed = False
        self._lock = threading.RLock()

    @property
    def maximum_events(self) -> int:
        return self._maximum_events

    def record(
        self,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        *,
        source_address: str | None = None,
        session_id: str | None = None,
        action: AuditAction | None = None,
        reason: AuditReason | None = None,
    ) -> AuditEvent:
        """Append one typed event; arbitrary text is not part of this contract."""
        if not isinstance(kind, AuditEventKind) or not isinstance(outcome, AuditOutcome):
            raise TypeError("audit kind and outcome must be typed enum values")
        if action is not None and not isinstance(action, AuditAction):
            raise TypeError("audit action must be an AuditAction")
        if reason is not None and not isinstance(reason, AuditReason):
            raise TypeError("audit reason must be an AuditReason")
        source_ref = self.source_reference(source_address) if source_address is not None else None
        if session_id is not None and _SAFE_SESSION_RE.fullmatch(session_id) is None:
            raise ValueError("session ID is not a safe audit reference")
        occurred_at = self._wall_clock()
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("audit clock must return a timezone-aware datetime")
        with self._lock:
            if self._closed:
                raise RuntimeError("audit log is closed")
            self._sequence += 1
            event_fields = {
                "sequence": self._sequence,
                "event_id": f"event-{self._sequence:08d}",
                "occurred_at": occurred_at.astimezone(timezone.utc).isoformat(),
                "kind": kind.value,
                "outcome": outcome.value,
                "source_ref": source_ref,
                "session_ref": session_id,
                "action": action.value if action is not None else None,
                "reason": reason.value if reason is not None else None,
            }
            event = AuditEvent(
                **event_fields,
                _issuance_seal=_audit_event_seal(**event_fields),
            )
            self._events.append(event)
            return event

    def source_reference(self, source_address: str) -> str:
        """Return a per-run pseudonym, never a reversible/truncated address."""
        try:
            canonical = str(ipaddress.ip_address(source_address))
        except ValueError as exc:
            raise ValueError("audit source address is invalid") from exc
        with self._lock:
            if self._closed:
                raise RuntimeError("audit log is closed")
            digest = hmac.new(
                self._source_key,
                canonical.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            return f"source-{digest[:16]}"

    def snapshot(self, *, limit: int | None = None) -> tuple[AuditEvent, ...]:
        """Return an immutable oldest-to-newest snapshot."""
        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise ValueError("audit snapshot limit must be a non-negative integer")
        with self._lock:
            events = tuple(self._events)
            if limit is None:
                return events
            return events[-limit:] if limit else ()

    def close(self) -> None:
        """Clear retained events and erase the per-run pseudonym key buffer."""
        with self._lock:
            self._events.clear()
            for index in range(len(self._source_key)):
                self._source_key[index] = 0
            self._closed = True
