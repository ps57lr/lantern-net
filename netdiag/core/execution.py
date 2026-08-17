"""Check metadata, scan policy, cancellation, and execution contracts."""

from __future__ import annotations

import ipaddress
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from threading import Event, Lock
from typing import Protocol

from netdiag.core.evidence import ErrorDetail, Evidence, EvidenceStore
from netdiag.core.status import ActivityLevel, ExecutionStatus
from netdiag.core.values import (
    JsonValue,
    validate_dotted_identifier,
    validate_json_value,
    validate_platform_identity,
)


class CancelledError(RuntimeError):
    """Cooperative cancellation at a declared safe checkpoint."""


class CancellationToken:
    """Thread-safe cancellation token with an optional monotonic deadline."""

    def __init__(
        self,
        *,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if deadline is not None and (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
        ):
            raise ValueError("deadline must be a finite number")
        self._deadline = deadline
        self._clock = clock
        self._event = Event()
        self._reason: str | None = None
        self._lock = Lock()

    @classmethod
    def with_timeout(
        cls,
        seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> CancellationToken:
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or seconds <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        return cls(deadline=clock() + seconds, clock=clock)

    @property
    def deadline(self) -> float | None:
        return self._deadline

    @property
    def reason(self) -> str | None:
        if self._deadline_reached():
            return "deadline exceeded"
        with self._lock:
            return self._reason

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set() or self._deadline_reached()

    def remaining_seconds(self) -> float | None:
        if self._event.is_set():
            return 0.0
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - self._clock())

    def cancel(self, reason: str = "cancelled") -> bool:
        """Cancel once. Return ``True`` only for the first caller."""

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("cancellation reason must not be empty")
        if len(reason) > 256:
            raise ValueError("cancellation reason must be no longer than 256 characters")
        with self._lock:
            if self._event.is_set() or self._deadline_reached():
                return False
            self._reason = reason
            self._event.set()
            return True

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise CancelledError(self.reason or "cancelled")

    def wait(self, timeout: float | None = None) -> bool:
        """Wait until cancellation/deadline; return whether cancellation occurred."""

        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative finite number or None")
        remaining = self.remaining_seconds()
        effective = timeout
        if remaining is not None:
            effective = remaining if effective is None else min(remaining, effective)
        self._event.wait(effective)
        return self.is_cancelled

    def _deadline_reached(self) -> bool:
        return self._deadline is not None and self._clock() >= self._deadline


@dataclass(frozen=True)
class PlatformInfo:
    system: str
    release: str
    machine: str

    def __post_init__(self) -> None:
        validate_platform_identity(self.system, self.release, self.machine)


@dataclass(frozen=True)
class CommandResult:
    """Structured native-command result; stdout and stderr stay separate."""

    stdout: str
    stderr: str
    return_code: int | None
    duration_ms: int
    timed_out: bool = False
    cancelled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be strings")
        if not isinstance(self.duration_ms, int) or isinstance(self.duration_ms, bool):
            raise TypeError("duration_ms must be an integer")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if self.return_code is not None and (
            not isinstance(self.return_code, int) or isinstance(self.return_code, bool)
        ):
            raise TypeError("return_code must be an integer or None")
        if not isinstance(self.timed_out, bool) or not isinstance(self.cancelled, bool):
            raise TypeError("timed_out and cancelled must be booleans")
        if self.timed_out and self.cancelled:
            raise ValueError("a command result cannot be both timed out and cancelled")


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cancellation: CancellationToken,
    ) -> CommandResult: ...


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ScanPolicy:
    """Consent and scope bound to one diagnostic scan."""

    maximum_activity: ActivityLevel = ActivityLevel.PASSIVE
    allowed_interfaces: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    allowed_targets: tuple[str, ...] = ()
    max_hosts: int = 256
    per_check_timeout_seconds: float = 15.0
    remediation_planning: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.maximum_activity, ActivityLevel):
            raise TypeError("maximum_activity must be an ActivityLevel")
        for label, value in (
            ("allowed_interfaces", self.allowed_interfaces),
            ("allowed_networks", self.allowed_networks),
            ("allowed_targets", self.allowed_targets),
        ):
            if type(value) is not tuple:
                raise TypeError(f"{label} must be an immutable tuple")
        if not isinstance(self.remediation_planning, bool):
            raise TypeError("remediation_planning must be a boolean")
        if not isinstance(self.max_hosts, int) or isinstance(self.max_hosts, bool):
            raise TypeError("max_hosts must be an integer")
        if not 1 <= self.max_hosts <= 4096:
            raise ValueError("max_hosts must be from 1 to 4096")
        if (
            isinstance(self.per_check_timeout_seconds, bool)
            or not isinstance(self.per_check_timeout_seconds, (int, float))
            or not math.isfinite(self.per_check_timeout_seconds)
            or self.per_check_timeout_seconds <= 0
            or self.per_check_timeout_seconds > 300
        ):
            raise ValueError("per_check_timeout_seconds must be greater than 0 and at most 300")
        _validate_scope_strings(self.allowed_interfaces, label="interface")
        _validate_scope_strings(self.allowed_targets, label="target")
        if any(not isinstance(network, str) for network in self.allowed_networks):
            raise TypeError("allowed networks must be canonical CIDR strings")
        for label, values in (
            ("interfaces", self.allowed_interfaces),
            ("networks", self.allowed_networks),
            ("targets", self.allowed_targets),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"allowed {label} must be unique")
        for network in self.allowed_networks:
            try:
                parsed = ipaddress.ip_network(network, strict=True)
            except ValueError as exc:
                raise ValueError("allowed network must be an exact canonical CIDR") from exc
            if str(parsed) != network:
                raise ValueError("allowed network must use canonical CIDR notation")

    @property
    def has_explicit_scope(self) -> bool:
        return bool(self.allowed_interfaces or self.allowed_networks or self.allowed_targets)

    def evaluate(self, check: CheckSpec) -> PolicyDecision:
        if not self.maximum_activity.permits(check.activity):
            return PolicyDecision(
                False,
                f"{check.check_id} requires {check.activity.value} authorization",
            )
        if check.requires_explicit_scope and not self.has_explicit_scope:
            return PolicyDecision(False, f"{check.check_id} requires an explicit target scope")
        return PolicyDecision(True, "authorized by scan policy")


@dataclass(frozen=True)
class CheckContext:
    platform: PlatformInfo
    runner: CommandRunner
    cancellation: CancellationToken
    policy: ScanPolicy
    evidence: EvidenceStore


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    execution_status: ExecutionStatus
    evidence: tuple[Evidence[object], ...]
    started_at: datetime
    duration_ms: int
    legacy_data: dict[str, JsonValue] = field(default_factory=dict)
    error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.check_id, label="check id")
        if not isinstance(self.execution_status, ExecutionStatus):
            raise TypeError("execution_status must be an ExecutionStatus")
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, Evidence) for item in self.evidence
        ):
            raise TypeError("evidence must be a tuple of Evidence instances")
        if not isinstance(self.started_at, datetime):
            raise TypeError("started_at must be a datetime")
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("started_at must include a timezone")
        if not isinstance(self.duration_ms, int) or isinstance(self.duration_ms, bool):
            raise TypeError("duration_ms must be an integer")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if not isinstance(self.legacy_data, dict):
            raise TypeError("legacy_data must be a dictionary")
        validate_json_value(self.legacy_data)
        if any(item.check_id != self.check_id for item in self.evidence):
            raise ValueError("all evidence in a CheckResult must belong to its check_id")
        if self.execution_status == ExecutionStatus.FAILED and self.error is None:
            raise ValueError("failed CheckResult must include an error")
        if self.execution_status == ExecutionStatus.COMPLETED and self.error is not None:
            raise ValueError("completed CheckResult cannot include an error")


class Collector(Protocol):
    def __call__(self, context: CheckContext) -> CheckResult: ...


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    collector: Collector
    activity: ActivityLevel
    supported_systems: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    requires_explicit_scope: bool = False
    default_enabled: bool = True

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.check_id, label="check id")
        if not callable(self.collector):
            raise TypeError("collector must be callable")
        if not isinstance(self.activity, ActivityLevel):
            raise TypeError("activity must be an ActivityLevel")
        if not isinstance(self.supported_systems, tuple):
            raise TypeError("supported_systems must be a tuple")
        if not self.supported_systems or any(
            not isinstance(system, str) or not system.strip() for system in self.supported_systems
        ):
            raise ValueError("supported_systems must contain non-empty platform names")
        if not isinstance(self.dependencies, tuple):
            raise TypeError("dependencies must be a tuple")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("check dependencies must be unique")
        for dependency in self.dependencies:
            validate_dotted_identifier(dependency, label="check dependency")
        if self.check_id in self.dependencies:
            raise ValueError("a check cannot depend on itself")
        if self.activity == ActivityLevel.ACTIVE_DISCOVERY and not self.requires_explicit_scope:
            raise ValueError("active discovery checks must require explicit scope")
        if not isinstance(self.requires_explicit_scope, bool):
            raise TypeError("requires_explicit_scope must be a boolean")
        if not isinstance(self.default_enabled, bool):
            raise TypeError("default_enabled must be a boolean")


def _validate_scope_strings(values: tuple[str, ...], *, label: str) -> None:
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"allowed {label}s must be strings")
        if not value:
            raise ValueError(f"allowed {label}s must be non-empty strings")
        if len(value) > 255 or any(
            character.isspace() or ord(character) < 33 for character in value
        ):
            raise ValueError(f"allowed {label} contains invalid characters")
