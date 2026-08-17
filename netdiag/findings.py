"""Backward-compatible imports for diagnostic report models."""

from netdiag.models import Finding, Severity, exit_code, worst_severity

__all__ = ["Finding", "Severity", "exit_code", "worst_severity"]
