"""Structured finding for reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    CRIT = "crit"


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    detail: str
    hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-safe representation."""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "hint": self.hint,
            "data": self.data,
        }


def worst_severity(findings: list[Finding]) -> Severity:
    for sev in (Severity.CRIT, Severity.WARN):
        if any(f.severity == sev for f in findings):
            return sev
    # INFO is context, not a degraded health state.
    if findings:
        return Severity.OK
    return Severity.OK


def exit_code(findings: list[Finding]) -> int:
    w = worst_severity(findings)
    if w == Severity.CRIT:
        return 2
    if w == Severity.WARN:
        return 1
    return 0
