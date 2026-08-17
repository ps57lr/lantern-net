"""Thread-safe consent-bound runtime for Lantern's local application.

The controller is deliberately transport-neutral.  It exposes a read-only,
share-safe ``snapshot`` compatible with ``netdiag.ui.controller.StatusProvider``
and explicit start/cancel lifecycle methods for a hardened transport adapter.
It does not accept credentials and has no remediation surface.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from concurrent.futures import Executor, Future
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, TypeAlias

from netdiag.catalog import FINDING_REGISTRY
from netdiag.consent import ConsentRecord
from netdiag.core.execution import CancellationToken, ScanPolicy
from netdiag.core.status import ExecutionStatus
from netdiag.models import Report
from netdiag.scanner import ScanCollectors, ScanProgress, run_policy_scan

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
ScanRunner: TypeAlias = Callable[..., Report]

_MAX_EVENTS = 32
_DEFAULT_MAX_SNAPSHOT_BYTES = 384 * 1024
_MIN_MAX_SNAPSHOT_BYTES = 1024
_MAX_FINDINGS = 64
_MAX_CHECKS = 32
_MAX_TEXT = 2048
_REPORT_ID = re.compile(r"report-[0-9a-f]{32}\Z")
_SAFE_MODULES = {
    "routing",
    "dns",
    "wifi",
    "lan",
    "mdns",
    "gateway_ports",
}
_SAFE_PROGRESS_MODULES = _SAFE_MODULES | {"routing_connectivity", "lan_ping"}
_SAFE_EXECUTION = {item.value for item in ExecutionStatus}
_SAFE_OUTCOMES = {
    "healthy",
    "informational",
    "degraded",
    "failed",
    "blocked",
    "inconclusive",
    "not_tested",
    "unsupported",
    "permission_denied",
    "cancelled",
}
_SAFE_SEVERITIES = {"ok", "info", "warn", "crit"}
_SAFE_CONFIDENCE = {"low", "medium", "high"}


class ApplicationState(str, Enum):
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanAlreadyRunning(RuntimeError):
    """Raised when a second run is requested before the first reaches a terminal state."""


class ControllerClosed(RuntimeError):
    """Raised when work is submitted after deterministic controller shutdown."""


@dataclass(frozen=True, slots=True)
class RunAuthorization:
    """Immutable binding retained for the lifetime of one run."""

    consent: ConsentRecord
    policy: ScanPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.consent, ConsentRecord):
            raise TypeError("consent must be a ConsentRecord")
        if not isinstance(self.policy, ScanPolicy):
            raise TypeError("policy must be a ScanPolicy")
        expected = self.consent.to_scan_policy(now=self.consent.issued_at)
        if self.policy != expected:
            raise ValueError("scan policy does not match its immutable consent record")


class _Submitter(Protocol):
    def submit(self, fn: Callable[[], None]) -> Future[None]: ...


class _DaemonExecutor:
    """Single-purpose daemon executor with bounded close semantics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: set[threading.Thread] = set()
        self._closed = False

    def submit(self, fn: Callable[[], None]) -> Future[None]:
        future: Future[None] = Future()

        def run() -> None:
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        fn()
                    except Exception as exc:  # noqa: BLE001 - Future parity is required.
                        future.set_exception(exc)
                    else:
                        future.set_result(None)
            finally:
                with self._lock:
                    self._threads.discard(threading.current_thread())

        with self._lock:
            if self._closed:
                raise ControllerClosed("controller executor is closed")
            thread = threading.Thread(
                target=run,
                name="lantern-diagnostic",
                daemon=True,
            )
            self._threads.add(thread)
            try:
                thread.start()
            except Exception:
                self._threads.discard(thread)
                raise
        return future

    def close(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._lock:
            self._closed = True
            threads = tuple(self._threads)
        for thread in threads:
            remaining = max(0.0, deadline - time.monotonic())
            thread.join(remaining)
        return not any(thread.is_alive() for thread in threads)


class DiagnosticController:
    """Coordinate one consent-bound diagnostic at a time.

    Snapshots contain an exact allowlist projection of the structurally
    redacted report.  Raw evidence payloads, arbitrary IDs/references, finding
    ``data``, access objects, remediation objects, consent scope, and exception
    text never cross this provider boundary.
    """

    def __init__(
        self,
        *,
        scan_runner: ScanRunner = run_policy_scan,
        collectors: ScanCollectors | None = None,
        executor: Executor | _Submitter | None = None,
        max_snapshot_bytes: int = _DEFAULT_MAX_SNAPSHOT_BYTES,
    ) -> None:
        if not callable(scan_runner):
            raise TypeError("scan_runner must be callable")
        if (
            not isinstance(max_snapshot_bytes, int)
            or isinstance(max_snapshot_bytes, bool)
            or max_snapshot_bytes < _MIN_MAX_SNAPSHOT_BYTES
        ):
            raise ValueError(f"max_snapshot_bytes must be at least {_MIN_MAX_SNAPSHOT_BYTES}")
        self._scan_runner = scan_runner
        self._collectors = collectors
        self._max_snapshot_bytes = max_snapshot_bytes
        self._executor: Executor | _Submitter = executor or _DaemonExecutor()
        self._owns_executor = executor is None
        self._lock = threading.RLock()
        self._state = ApplicationState.READY
        self._authorization: RunAuthorization | None = None
        self._cancellation: CancellationToken | None = None
        self._future: Future[None] | None = None
        self._events: deque[dict[str, JsonValue]] = deque(maxlen=_MAX_EVENTS)
        self._event_sequence = 0
        self._generation = 0
        self._presentation: dict[str, JsonValue] | None = None
        self._error: dict[str, JsonValue] | None = None
        self._closed = False
        self._started_monotonic: float | None = None
        self._duration_ms = 0

    @property
    def state(self) -> ApplicationState:
        with self._lock:
            return self._state

    def start(
        self,
        consent: ConsentRecord,
        *,
        include_mdns: bool = True,
    ) -> None:
        """Start one run without echoing caller-controlled identifiers."""

        if not isinstance(consent, ConsentRecord):
            raise TypeError("consent must be a ConsentRecord")
        if not isinstance(include_mdns, bool):
            raise TypeError("include_mdns must be a boolean")
        policy = consent.to_scan_policy()
        authorization = RunAuthorization(consent, policy)
        token = CancellationToken()

        with self._lock:
            if self._closed:
                raise ControllerClosed("diagnostic controller is closed")
            if self._state == ApplicationState.RUNNING:
                raise ScanAlreadyRunning("a diagnostic run is already in progress")
            self._generation += 1
            generation = self._generation
            self._state = ApplicationState.RUNNING
            self._authorization = authorization
            self._cancellation = token
            self._future = None
            self._events.clear()
            self._event_sequence = 0
            self._presentation = None
            self._error = None
            self._started_monotonic = time.monotonic()
            self._duration_ms = 0

        def worker() -> None:
            self._run_worker(
                generation,
                authorization,
                token,
                include_mdns=include_mdns,
            )

        try:
            future = self._executor.submit(worker)
        except Exception:  # noqa: BLE001 - executor details are never exposed.
            with self._lock:
                if generation == self._generation:
                    self._state = ApplicationState.FAILED
                    self._error = _normalized_error("start_failed")
                    self._duration_ms = self._elapsed_ms()
            raise RuntimeError("the diagnostic worker could not be started") from None
        with self._lock:
            if generation == self._generation:
                self._future = future

    def cancel(self) -> bool:
        """Request cooperative cancellation at the next module boundary."""

        with self._lock:
            if self._state != ApplicationState.RUNNING or self._cancellation is None:
                return False
            return self._cancellation.cancel("user_requested")

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the active worker; return ``False`` on the caller's timeout."""

        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative finite number or None")
        with self._lock:
            future = self._future
            running = self._state == ApplicationState.RUNNING
        if future is None:
            return not running
        try:
            future.result(timeout=timeout)
        except FutureTimeout:
            return False
        except Exception:  # noqa: BLE001 - worker errors were already normalized.
            # Worker exceptions are normalized into state before completing its
            # Future.  No exception text crosses this lifecycle boundary.
            return True
        return True

    def close(self, *, timeout: float = 3.0) -> bool:
        """Cancel and join for at most ``timeout`` seconds; never wait forever."""

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative finite number")
        with self._lock:
            if self._closed:
                return self._state != ApplicationState.RUNNING
            self._closed = True
        self.cancel()
        started = time.monotonic()
        completed = self.wait(timeout=timeout)
        remaining = max(0.0, timeout - (time.monotonic() - started))
        if self._owns_executor:
            executor = self._executor
            assert isinstance(executor, _DaemonExecutor)
            completed = executor.close(remaining) and completed
        return completed

    def snapshot(self) -> Mapping[str, JsonValue]:
        """Return one bounded, JSON-safe, non-secret presentation snapshot."""

        with self._lock:
            state = self._state.value
            duration_ms = (
                self._elapsed_ms() if self._state == ApplicationState.RUNNING else self._duration_ms
            )
            events = [dict(item) for item in self._events]
            presentation = (
                _copy_json_object(self._presentation) if self._presentation is not None else None
            )
            error = dict(self._error) if self._error is not None else None
        terminal_events = sum(
            item.get("phase") in {"completed", "failed", "cancelled", "not_run"} for item in events
        )
        planned = max(
            (value for item in events if isinstance((value := item.get("total_steps")), int)),
            default=0,
        )
        processed = min(terminal_events, planned) if planned else 0
        snapshot: dict[str, JsonValue] = {
            "product": "Lantern",
            "state": state,
            "transport": "loopback",
            "duration_ms": duration_ms,
            "progress": {
                "processed": processed,
                "planned": planned,
                "percent": round(processed * 100 / planned) if planned else 0,
                "events": events,
            },
            "result": presentation,
            "error": error,
        }
        return _fit_snapshot(snapshot, self._max_snapshot_bytes)

    def __enter__(self) -> DiagnosticController:  # noqa: PYI034 - Python 3.10 support
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _run_worker(
        self,
        generation: int,
        authorization: RunAuthorization,
        token: CancellationToken,
        *,
        include_mdns: bool,
    ) -> None:
        def observe(event: ScanProgress) -> None:
            self._observe_progress(generation, event)

        try:
            report = self._scan_runner(
                authorization.policy,
                cancellation=token,
                progress=observe,
                collectors=self._collectors,
                include_mdns=include_mdns,
                active_requested=(
                    authorization.policy.maximum_activity.value == "active_discovery"
                ),
            )
            if not isinstance(report, Report):
                raise TypeError("scan runner returned an invalid report")
            presentation = _safe_report_projection(report, self._max_snapshot_bytes)
        except Exception:  # noqa: BLE001 - errors are normalized without exception detail.
            with self._lock:
                if generation != self._generation:
                    return
                self._state = ApplicationState.FAILED
                self._presentation = None
                self._error = _normalized_error("scan_failed")
                self._duration_ms = self._elapsed_ms()
            return

        with self._lock:
            if generation != self._generation:
                return
            self._presentation = presentation
            self._error = None
            self._duration_ms = self._elapsed_ms()
            self._state = (
                ApplicationState.CANCELLED
                if report.execution_status == ExecutionStatus.CANCELLED
                else ApplicationState.COMPLETED
            )

    def _observe_progress(self, generation: int, event: ScanProgress) -> None:
        if type(event) is not ScanProgress:
            return
        try:
            event.__post_init__()
        except (TypeError, ValueError):
            return
        if event.module not in _SAFE_PROGRESS_MODULES:
            return
        with self._lock:
            if generation != self._generation or self._state != ApplicationState.RUNNING:
                return
            self._event_sequence += 1
            self._events.append(
                {
                    "sequence": self._event_sequence,
                    "module": event.module,
                    "phase": event.phase,
                    "step": event.step,
                    "total_steps": event.total_steps,
                }
            )

    def _elapsed_ms(self) -> int:
        if self._started_monotonic is None:
            return 0
        return max(0, round((time.monotonic() - self._started_monotonic) * 1000))


def _safe_report_projection(report: Report, max_bytes: int) -> dict[str, JsonValue]:
    """Project only registered, redacted presentation fields from a report."""

    serialized = report.to_dict(redact=True)
    if not isinstance(serialized, dict):
        raise TypeError("redacted report must serialize to an object")
    report_id = serialized.get("report_id")
    projection: dict[str, JsonValue] = {
        "schema_version": _safe_choice(serialized.get("schema_version"), {"1.1"}, "1.1"),
        "report_id": report_id
        if isinstance(report_id, str) and _REPORT_ID.fullmatch(report_id)
        else None,
        "status": _safe_choice(serialized.get("status"), _SAFE_EXECUTION, "failed"),
        "outcome": _safe_choice(serialized.get("outcome"), _SAFE_OUTCOMES, "inconclusive"),
        "severity": _safe_choice(serialized.get("severity"), _SAFE_SEVERITIES, "warn"),
        "assessment": _bounded_text(
            serialized.get("assessment"), fallback="Assessment unavailable."
        ),
        "duration_ms": _safe_nonnegative_int(serialized.get("duration_ms")),
        "coverage": _safe_coverage(serialized.get("coverage")),
        "findings": [],
        "checks": [],
        "redacted": True,
        "truncated": False,
    }
    findings = serialized.get("findings")
    if isinstance(findings, list):
        projected_findings = projection["findings"]
        assert isinstance(projected_findings, list)
        for item in findings[:_MAX_FINDINGS]:
            safe = _safe_finding(item)
            if safe is not None:
                projected_findings.append(safe)
        if len(findings) > _MAX_FINDINGS:
            projection["truncated"] = True
    checks = serialized.get("checks")
    if isinstance(checks, list):
        projected_checks = projection["checks"]
        assert isinstance(projected_checks, list)
        for item in checks[:_MAX_CHECKS]:
            safe = _safe_check(item)
            if safe is not None:
                projected_checks.append(safe)
        if len(checks) > _MAX_CHECKS:
            projection["truncated"] = True

    while _json_size(projection) > max_bytes and projection["findings"]:
        assert isinstance(projection["findings"], list)
        projection["findings"].pop()
        projection["truncated"] = True
    while _json_size(projection) > max_bytes and projection["checks"]:
        assert isinstance(projection["checks"], list)
        projection["checks"].pop()
        projection["truncated"] = True
    if _json_size(projection) > max_bytes:
        projection["assessment"] = "A bounded diagnostic result is available."
        projection["findings"] = []
        projection["checks"] = []
        projection["truncated"] = True
    if _json_size(projection) > max_bytes:
        raise ValueError("safe presentation exceeds its response budget")
    return projection


def _safe_finding(value: object) -> dict[str, JsonValue] | None:
    if not isinstance(value, dict):
        return None
    code = value.get("code")
    if not isinstance(code, str):
        return None
    try:
        FINDING_REGISTRY.require(code)
    except KeyError:
        return None
    neutral_title = code.rsplit(".", 1)[-1].replace("_", " ").title()
    return {
        "code": code,
        "severity": _safe_choice(value.get("severity"), _SAFE_SEVERITIES, "warn"),
        "status": _safe_choice(value.get("status"), _SAFE_OUTCOMES, "inconclusive"),
        "confidence": _safe_confidence(value.get("confidence")),
        # Registered prose may still contain adapter-provided values classified
        # PUBLIC by an upstream catalog.  The local status boundary has no way
        # to prove those values are semantically public, so it exposes a stable
        # code-derived label and withholds parameterized prose.
        "title": neutral_title,
        "detail": "Lantern recorded this registered diagnostic result.",
        "hint": "",
    }


def _safe_check(value: object) -> dict[str, JsonValue] | None:
    if not isinstance(value, dict):
        return None
    category = value.get("category")
    if not isinstance(category, str) or category not in _SAFE_MODULES:
        return None
    return {
        "module": category,
        "execution_status": _safe_choice(value.get("execution_status"), _SAFE_EXECUTION, "failed"),
        "outcome_status": _safe_choice(value.get("outcome_status"), _SAFE_OUTCOMES, "inconclusive"),
        "duration_ms": _safe_nonnegative_int(value.get("duration_ms")),
    }


def _safe_confidence(value: object) -> dict[str, JsonValue]:
    level = value.get("level") if isinstance(value, dict) else None
    return {"level": _safe_choice(level, _SAFE_CONFIDENCE, "low")}


def _safe_coverage(value: object) -> dict[str, JsonValue]:
    source = value if isinstance(value, dict) else {}
    return {
        "status": _safe_choice(source.get("status"), {"complete", "partial", "none"}, "none"),
        "planned": _safe_nonnegative_int(source.get("planned")),
        "completed": _safe_nonnegative_int(source.get("completed")),
        "partial": _safe_nonnegative_int(source.get("partial")),
        "failed": _safe_nonnegative_int(source.get("failed")),
        "cancelled": _safe_nonnegative_int(source.get("cancelled")),
        "not_run": _safe_nonnegative_int(source.get("not_run")),
    }


def _safe_choice(value: object, choices: set[str], fallback: str) -> str:
    return value if isinstance(value, str) and value in choices else fallback


def _safe_nonnegative_int(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return min(value, 2_147_483_647)
    return 0


def _bounded_text(value: object, *, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    cleaned = "".join(
        character for character in value if character in "\n\t" or ord(character) >= 32
    )
    return cleaned[:_MAX_TEXT]


def _normalized_error(code: str) -> dict[str, JsonValue]:
    messages = {
        "start_failed": "The diagnostic worker could not be started.",
        "scan_failed": "The diagnostic run could not be completed.",
    }
    return {"code": code, "message": messages[code]}


def _fit_snapshot(snapshot: dict[str, JsonValue], limit: int) -> dict[str, JsonValue]:
    if _json_size(snapshot) <= limit:
        return snapshot
    progress = snapshot.get("progress")
    if isinstance(progress, dict):
        progress["events"] = []
    result = snapshot.get("result")
    if isinstance(result, dict):
        result["findings"] = []
        result["checks"] = []
        result["assessment"] = "A bounded diagnostic result is available."
        result["truncated"] = True
    if _json_size(snapshot) > limit:
        snapshot["result"] = None
        snapshot["error"] = {
            "code": "result_too_large",
            "message": "The diagnostic summary exceeded its display budget.",
        }
    if _json_size(snapshot) > limit:
        raise ValueError("status snapshot exceeds its response budget")
    return snapshot


def _json_size(value: object) -> int:
    return len(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _copy_json_object(value: Mapping[str, Any]) -> dict[str, JsonValue]:
    # Round-tripping also rejects custom containers/non-finite floats and
    # guarantees callers cannot mutate the controller's stored presentation.
    copied = json.loads(
        json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    )
    if not isinstance(copied, dict):
        raise TypeError("presentation copy must be an object")
    return copied
