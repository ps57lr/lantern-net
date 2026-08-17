"""Versioned diagnostic report domain models.

These models keep the v0.2 positional ``Finding`` API intact while adding the
orthogonal execution, outcome, confidence, evidence, and coverage dimensions
needed by Lantern's CLI and UI presentation layers.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from netdiag.core.diagnostics import Confidence
from netdiag.core.evidence import ErrorDetail, Evidence
from netdiag.core.status import ConfidenceLevel, ExecutionStatus, OutcomeStatus
from netdiag.core.values import (
    JsonValue,
    validate_dotted_identifier,
    validate_finding_code,
    validate_json_value,
)
from netdiag.platform import OSInfo

_REPORT_ID_KEY = secrets.token_bytes(32)
_REPORT_ID_RE = re.compile(r"^report-[0-9a-f]{32}$")


def _seal_report_id(report_id: str) -> bytes:
    return hmac.new(_REPORT_ID_KEY, report_id.encode("ascii"), hashlib.sha256).digest()


def _new_report_identity() -> tuple[str, bytes]:
    """Mint one immutable, generation-only report identity binding."""

    report_id = f"report-{secrets.token_hex(16)}"
    return report_id, _seal_report_id(report_id)


class Severity(str, Enum):
    """Presentation/exit-code severity; independent from diagnostic outcome."""

    OK = "ok"
    INFO = "info"
    WARN = "warn"
    CRIT = "crit"


class CoverageStatus(str, Enum):
    """How much of the declared diagnostic plan produced usable results."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NONE = "none"


def legacy_confidence() -> Confidence:
    """Conservative confidence for third-party findings using the v0.2 API."""

    return Confidence(
        ConfidenceLevel.LOW,
        "Legacy finding has not supplied structured evidence.",
    )


@dataclass
class Finding:
    """One diagnostic interpretation.

    The first six fields deliberately preserve the v0.2 positional signature.
    Product findings use a registered ``code`` and typed ``parameters`` so the
    presentation layer can redact parameters before rendering prose.
    """

    severity: Severity
    category: str
    title: str
    detail: str
    hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    code: str | None = field(default=None, kw_only=True)
    status: OutcomeStatus = field(default=OutcomeStatus.INFORMATIONAL, kw_only=True)
    confidence: Confidence = field(default_factory=legacy_confidence, kw_only=True)
    evidence_refs: tuple[str, ...] = field(default=(), kw_only=True)
    remediation_refs: tuple[str, ...] = field(default=(), kw_only=True)
    parameters: dict[str, object] = field(default_factory=dict, kw_only=True, repr=False)
    finding_id: str | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        validate_dotted_identifier(self.category, label="finding category")
        if self.code is not None:
            validate_finding_code(self.code)
        if not isinstance(self.status, OutcomeStatus):
            raise TypeError("finding status must be an OutcomeStatus")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("finding confidence must be a Confidence")
        if not isinstance(self.data, dict):
            raise TypeError("finding data must be a JSON object")
        validate_json_value(self.data)
        for label, refs in (
            ("evidence_refs", self.evidence_refs),
            ("remediation_refs", self.remediation_refs),
        ):
            if not isinstance(refs, tuple):
                raise TypeError(f"{label} must be a tuple")
            for ref in refs:
                validate_dotted_identifier(ref, label=label[:-1])
            if len(set(refs)) != len(refs):
                raise ValueError(f"{label} must contain unique references")
        if not isinstance(self.parameters, dict) or any(
            not isinstance(name, str) or not name.isidentifier() for name in self.parameters
        ):
            raise ValueError("finding parameters must use identifier-like string keys")
        if self.finding_id is not None:
            validate_dotted_identifier(self.finding_id, label="finding id")

    def with_evidence(self, evidence_ref: str, *, rationale: str | None = None) -> Finding:
        """Return a copy bound to report-local evidence without mutating the source."""

        validate_dotted_identifier(evidence_ref, label="evidence reference")
        confidence = Confidence(
            self.confidence.level,
            rationale or self.confidence.rationale,
            (evidence_ref,),
        )
        return replace(self, evidence_refs=(evidence_ref,), confidence=confidence)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the raw additive representation used by legacy callers."""

        from netdiag.presentation import serialize_finding

        return serialize_finding(self)


@dataclass(frozen=True)
class CheckRecord:
    """Execution and diagnostic outcome for one declared check."""

    check_id: str
    category: str
    execution_status: ExecutionStatus
    outcome_status: OutcomeStatus
    duration_ms: int
    evidence_refs: tuple[str, ...] = ()
    error: ErrorDetail | None = None

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.check_id, label="check id")
        validate_dotted_identifier(self.category, label="check category")
        if not isinstance(self.execution_status, ExecutionStatus):
            raise TypeError("execution_status must be an ExecutionStatus")
        if not isinstance(self.outcome_status, OutcomeStatus):
            raise TypeError("outcome_status must be an OutcomeStatus")
        if not isinstance(self.duration_ms, int) or isinstance(self.duration_ms, bool):
            raise TypeError("duration_ms must be an integer")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("evidence_refs must be unique")
        for ref in self.evidence_refs:
            validate_dotted_identifier(ref, label="check evidence reference")
        if self.error is not None and type(self.error) is not ErrorDetail:
            raise TypeError("error must be an ErrorDetail or None")
        if self.error is not None:
            self.error.__post_init__()


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate plan coverage; never conflated with health severity."""

    status: CoverageStatus
    planned: int
    completed: int
    partial: int
    failed: int
    cancelled: int
    not_run: int

    @classmethod
    def from_checks(cls, checks: list[CheckRecord]) -> CoverageSummary:
        counts = {status: 0 for status in ExecutionStatus}
        for check in checks:
            counts[check.execution_status] += 1
        planned = len(checks)
        usable = counts[ExecutionStatus.COMPLETED] + counts[ExecutionStatus.PARTIAL]
        if planned > 0 and counts[ExecutionStatus.COMPLETED] == planned:
            status = CoverageStatus.COMPLETE
        elif usable > 0:
            status = CoverageStatus.PARTIAL
        else:
            status = CoverageStatus.NONE
        return cls(
            status,
            planned,
            counts[ExecutionStatus.COMPLETED],
            counts[ExecutionStatus.PARTIAL],
            counts[ExecutionStatus.FAILED],
            counts[ExecutionStatus.CANCELLED],
            counts[ExecutionStatus.NOT_RUN],
        )


@dataclass
class Report:
    """In-memory report model serialized as additive schema 1.1."""

    hostname: str
    os: OSInfo
    started_at: str
    duration_ms: int = 0
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    checks: list[CheckRecord] = field(default_factory=list)
    evidence: list[Evidence[object]] = field(default_factory=list)
    access_prerequisites: list[object] = field(default_factory=list)
    remediation: dict[str, Any] = field(
        default_factory=lambda: {"available_actions": [], "attempts": []}
    )
    _report_identity: tuple[str, bytes] = field(
        init=False,
        repr=False,
        default_factory=_new_report_identity,
    )

    def __post_init__(self) -> None:
        self._validate_report_id_binding()

    def _validate_report_id_binding(self) -> None:
        identity = self._report_identity
        if not isinstance(identity, tuple) or len(identity) != 2:
            raise ValueError("report identity is not a generated opaque binding")
        report_id, seal = identity
        if not isinstance(report_id, str) or _REPORT_ID_RE.fullmatch(report_id) is None:
            raise ValueError("report ID is not a generated opaque identifier")
        if not isinstance(seal, bytes) or not hmac.compare_digest(
            seal,
            _seal_report_id(report_id),
        ):
            raise ValueError("report ID no longer matches its generated binding")

    @property
    def _report_id(self) -> str:
        """Read-only compatibility view of the generation-only identifier."""

        self._validate_report_id_binding()
        return self._report_identity[0]

    @property
    def report_id(self) -> str:
        """Generation-only public correlation handle for this in-memory report."""

        self._validate_report_id_binding()
        return self._report_identity[0]

    @property
    def severity(self) -> str:
        return worst_severity(self.findings).value

    @property
    def coverage(self) -> CoverageSummary:
        return CoverageSummary.from_checks(self.checks)

    @property
    def execution_status(self) -> ExecutionStatus:
        coverage = self.coverage
        if coverage.planned == 0 or coverage.status == CoverageStatus.NONE:
            if coverage.cancelled:
                return ExecutionStatus.CANCELLED
            if coverage.failed:
                return ExecutionStatus.FAILED
            return ExecutionStatus.NOT_RUN
        if coverage.cancelled:
            return ExecutionStatus.CANCELLED
        if coverage.status == CoverageStatus.COMPLETE:
            return ExecutionStatus.COMPLETED
        return ExecutionStatus.PARTIAL

    @property
    def outcome_status(self) -> OutcomeStatus:
        statuses = {finding.status for finding in self.findings}
        check_statuses = {check.outcome_status for check in self.checks}
        for status in (
            OutcomeStatus.FAILED,
            OutcomeStatus.DEGRADED,
            OutcomeStatus.BLOCKED,
            OutcomeStatus.PERMISSION_DENIED,
            OutcomeStatus.CANCELLED,
        ):
            if status in statuses:
                return status
        if OutcomeStatus.PERMISSION_DENIED in check_statuses:
            return OutcomeStatus.PERMISSION_DENIED
        if OutcomeStatus.CANCELLED in check_statuses:
            return OutcomeStatus.CANCELLED
        if self.coverage.status == CoverageStatus.NONE:
            if check_statuses == {OutcomeStatus.UNSUPPORTED}:
                return OutcomeStatus.UNSUPPORTED
            if check_statuses.intersection(
                {
                    OutcomeStatus.INCONCLUSIVE,
                    OutcomeStatus.FAILED,
                    OutcomeStatus.DEGRADED,
                    OutcomeStatus.BLOCKED,
                }
            ):
                return OutcomeStatus.INCONCLUSIVE
            return OutcomeStatus.NOT_TESTED
        if self.coverage.status != CoverageStatus.COMPLETE:
            return OutcomeStatus.INCONCLUSIVE
        if not self.findings or statuses <= {
            OutcomeStatus.INFORMATIONAL,
            OutcomeStatus.NOT_TESTED,
            OutcomeStatus.UNSUPPORTED,
        }:
            return OutcomeStatus.INCONCLUSIVE
        if statuses.union(check_statuses).intersection(
            {
                OutcomeStatus.INCONCLUSIVE,
                OutcomeStatus.NOT_TESTED,
                OutcomeStatus.UNSUPPORTED,
            }
        ):
            return OutcomeStatus.INCONCLUSIVE
        return OutcomeStatus.HEALTHY

    def to_dict(self, *, redact: bool = False) -> dict[str, JsonValue]:
        from netdiag.presentation import serialize_report

        return serialize_report(self, share_safe=redact)


def worst_severity(findings: list[Finding]) -> Severity:
    for severity in (Severity.CRIT, Severity.WARN):
        if any(finding.severity == severity for finding in findings):
            return severity
    # INFO is context, not a degraded health state. Coverage is represented
    # separately and must be consulted before claiming a healthy outcome.
    return Severity.OK


def exit_code(findings: list[Finding]) -> int:
    worst = worst_severity(findings)
    if worst == Severity.CRIT:
        return 2
    if worst == Severity.WARN:
        return 1
    return 0
