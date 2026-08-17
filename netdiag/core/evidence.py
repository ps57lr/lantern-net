"""Typed observation envelopes and an append-only evidence store."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from threading import RLock
from typing import Generic, Protocol, TypeVar, runtime_checkable

from netdiag.core.redaction import (
    RedactionPolicy,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.status import OutcomeStatus, Sensitivity
from netdiag.core.values import (
    JsonValue,
    validate_dotted_identifier,
    validate_nonempty_text,
)

PayloadT = TypeVar("PayloadT")


@runtime_checkable
class EvidencePayload(Protocol):
    """Optional marker protocol for explicitly serializable typed payloads."""

    def to_evidence_dict(self) -> dict[str, JsonValue]: ...


@dataclass(frozen=True)
class ErrorDetail:
    """Normalized, report-safe failure detail."""

    code: str
    message: str = field(metadata={"sensitivity": Sensitivity.POTENTIAL_SECRET})
    retryable: bool = False
    native_exit_code: int | None = None

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.code, label="error code")
        validate_nonempty_text(self.message, label="error message", maximum=1024)
        if not isinstance(self.retryable, bool):
            raise TypeError("retryable must be a boolean")
        if self.native_exit_code is not None and (
            not isinstance(self.native_exit_code, int) or isinstance(self.native_exit_code, bool)
        ):
            raise TypeError("native_exit_code must be an integer or None")

    @classmethod
    def unexpected(cls, operation: str, exc: BaseException) -> ErrorDetail:
        """Create a conservative detail without copying an exception message.

        Native exception strings may contain paths, hostnames, arguments, or
        secrets. Known adapters should construct a more specific safe detail.
        """

        validate_dotted_identifier(operation, label="operation")
        return cls(
            code=f"{operation}.unexpected",
            message="Unexpected collector error",
            retryable=False,
        )


@dataclass(frozen=True)
class Evidence(Generic[PayloadT]):
    """One immutable observation produced by one registered check."""

    evidence_id: str
    kind: str
    check_id: str
    status: OutcomeStatus
    source: str
    observed_at: datetime
    duration_ms: int
    payload: PayloadT | None
    error: ErrorDetail | None = None
    sensitivity: Sensitivity = Sensitivity.PUBLIC

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.evidence_id, label="evidence id")
        validate_dotted_identifier(self.kind, label="evidence kind")
        validate_dotted_identifier(self.check_id, label="check id")
        validate_dotted_identifier(self.source, label="evidence source")
        if not isinstance(self.status, OutcomeStatus):
            raise TypeError("status must be an OutcomeStatus")
        if not isinstance(self.sensitivity, Sensitivity):
            raise TypeError("sensitivity must be a Sensitivity")
        if not isinstance(self.observed_at, datetime):
            raise TypeError("observed_at must be a datetime")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if not isinstance(self.duration_ms, int) or isinstance(self.duration_ms, bool):
            raise TypeError("duration_ms must be an integer")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if self.status == OutcomeStatus.HEALTHY and self.payload is None:
            raise ValueError("healthy evidence must include a payload")
        if self.status == OutcomeStatus.HEALTHY and self.error is not None:
            raise ValueError("healthy evidence cannot include an error")
        if self.error is not None:
            if type(self.error) is not ErrorDetail:
                raise TypeError("error must be an ErrorDetail or None")
            self.error.__post_init__()
        if self.payload is not None:
            # Validate supported structure at construction time. Potential-secret
            # wrappers remain redacted by the raw policy and are never exposed.
            serialize_structured(self._payload_value(), policy=RedactionPolicy.raw())

    def _payload_value(self) -> object:
        if isinstance(self.payload, EvidencePayload):
            return self.payload.to_evidence_dict()
        return self.payload

    def to_dict(
        self,
        *,
        policy: RedactionPolicy | None = None,
        sensitivity_map: StructuralSensitivityMap | None = None,
    ) -> dict[str, JsonValue]:
        """Serialize with structural redaction and dynamic payload sensitivity."""

        self.__post_init__()
        selected_policy = policy or RedactionPolicy.raw()
        selected_map = sensitivity_map
        if selected_map is None:
            # A PUBLIC envelope is not proof that every nested leaf is public.
            # The caller must provide a registered map; otherwise unknown leaves
            # fail closed under every policy. A non-public whole-payload envelope
            # is already explicitly classified and can retain its raw local form.
            default_sensitivity = (
                Sensitivity.PUBLIC
                if self.sensitivity != Sensitivity.PUBLIC
                else Sensitivity.POTENTIAL_SECRET
            )
            selected_map = StructuralSensitivityMap(default_leaf_sensitivity=default_sensitivity)
        payload = serialize_structured(
            self._payload_value(),
            policy=selected_policy,
            sensitivity_map=selected_map,
        )
        if self.sensitivity != Sensitivity.PUBLIC:
            from netdiag.core.values import DiagnosticValue

            payload = serialize_structured(
                DiagnosticValue(payload, self.sensitivity),
                policy=selected_policy,
            )
        result = {
            # Logical adapter identifiers are useful in trusted in-memory
            # registries, but a standalone Evidence instance carries no proof
            # that they came from one. Report presentation assigns opaque local
            # aliases after catalog validation; this fail-closed API does not
            # publish caller-controlled identifier prose.
            "evidence_id": "<redacted>",
            "kind": "<redacted>",
            "check_id": "<redacted>",
            "status": self.status.value,
            "source": "<redacted>",
            "observed_at": self.observed_at.isoformat(),
            "duration_ms": self.duration_ms,
            "payload": payload,
            "error": (
                {
                    "code": "<redacted>",
                    "message": "<redacted>",
                    "retryable": self.error.retryable,
                    "native_exit_code": self.error.native_exit_code,
                }
                if self.error is not None
                else None
            ),
            "sensitivity": self.sensitivity.value,
        }
        return result


class DuplicateEvidenceError(ValueError):
    """Raised when a report-local evidence identifier is reused."""


class EvidenceStore:
    """Thread-safe, append-only, insertion-ordered evidence collection."""

    def __init__(self, evidence: Iterable[Evidence[object]] = ()) -> None:
        self._items: dict[str, Evidence[object]] = {}
        self._lock = RLock()
        self.extend(evidence)

    def add(self, evidence: Evidence[object]) -> None:
        self.extend((evidence,))

    def extend(self, evidence: Iterable[Evidence[object]]) -> None:
        """Atomically add a batch, rejecting duplicates before mutation."""

        batch = tuple(evidence)
        if any(not isinstance(item, Evidence) for item in batch):
            raise TypeError("EvidenceStore accepts only Evidence instances")
        identifiers = [item.evidence_id for item in batch]
        seen: set[str] = set()
        duplicate: str | None = None
        for identifier in identifiers:
            if identifier in seen:
                duplicate = identifier
                break
            seen.add(identifier)
        if duplicate is not None:
            raise DuplicateEvidenceError(f"duplicate evidence id in batch: {duplicate}")
        with self._lock:
            conflict = next(
                (identifier for identifier in identifiers if identifier in self._items), None
            )
            if conflict is not None:
                raise DuplicateEvidenceError(f"duplicate evidence id: {conflict}")
            self._items.update((item.evidence_id, item) for item in batch)

    def require(self, evidence_id: str) -> Evidence[object]:
        with self._lock:
            try:
                return self._items[evidence_id]
            except KeyError as exc:
                raise KeyError(f"unknown evidence id: {evidence_id}") from exc

    def by_kind(self, kind: str) -> tuple[Evidence[object], ...]:
        return tuple(item for item in self.snapshot() if item.kind == kind)

    def by_check(self, check_id: str) -> tuple[Evidence[object], ...]:
        return tuple(item for item in self.snapshot() if item.check_id == check_id)

    def snapshot(self) -> tuple[Evidence[object], ...]:
        with self._lock:
            return tuple(self._items.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def __iter__(self) -> Iterator[Evidence[object]]:
        return iter(self.snapshot())
