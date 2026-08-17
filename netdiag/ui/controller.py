"""Consent-bound integration seam for the Lantern local application."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from typing import Protocol, TypeAlias, runtime_checkable

from netdiag.application import DiagnosticController
from netdiag.consent import DiagnosticGoal, issue_consent

from .viewmodel import build_ui_viewmodel, ready_ui_viewmodel

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | Mapping[str, "JsonValue"]

_START_FIELDS = frozenset({"goal", "profile", "include_mdns"})
_PROFILES = frozenset({"passive", "low_impact_network"})


@runtime_checkable
class StatusProvider(Protocol):
    """Provide a JSON-safe, non-secret, read-only application snapshot."""

    def snapshot(self) -> Mapping[str, JsonValue]:
        """Return the current presentation snapshot without changing state."""
        ...


class ReadyStatusProvider:
    """Safe default used before the diagnostic application adapter is wired."""

    def snapshot(self) -> Mapping[str, JsonValue]:
        return ready_ui_viewmodel()


@runtime_checkable
class DiagnosticService(StatusProvider, Protocol):
    """Start and cancel the two allowlisted local diagnostic profiles."""

    def start(self, request: Mapping[str, object]) -> None:
        """Validate an exact request and start one consent-bound diagnostic."""
        ...

    def cancel(self) -> bool:
        """Request cancellation at the scanner's next safe boundary."""
        ...


class InvalidDiagnosticRequest(ValueError):
    """A browser start object did not match the fixed local contract."""


class LocalDiagnosticService:
    """Own one local controller and issue fresh, server-derived consent.

    Browser input selects only a goal and one of two fixed profiles.  It cannot
    provide targets, interfaces, commands, credentials, actions, or active
    discovery scope.  The low-impact profile permits the scanner's bounded
    external path/DNS checks and gateway-port checks, plus optional mDNS.  It
    still cannot authorize the active LAN ping step.
    """

    def __init__(self, controller: DiagnosticController | None = None) -> None:
        if controller is not None and not isinstance(controller, DiagnosticController):
            raise TypeError("controller must be a DiagnosticController")
        self._controller = controller or DiagnosticController()

    def snapshot(self) -> Mapping[str, JsonValue]:
        return build_ui_viewmodel(self._controller.snapshot())

    def start(self, request: Mapping[str, object]) -> None:
        goal, profile, include_mdns = _parse_start_request(request)
        token = secrets.token_hex(16)
        record = issue_consent(
            consent_id=f"consent.ui.{token}",
            scan_id=f"scan.ui.{secrets.token_hex(16)}",
            goal=goal,
            basic_network_checks=profile == "low_impact_network",
            ttl_seconds=900,
        )
        self._controller.start(record, include_mdns=include_mdns)

    def cancel(self) -> bool:
        return self._controller.cancel()

    def close(self, *, timeout: float = 3.0) -> bool:
        return self._controller.close(timeout=timeout)


def _parse_start_request(
    request: Mapping[str, object],
) -> tuple[DiagnosticGoal, str, bool]:
    if type(request) is not dict or set(request) != _START_FIELDS:
        raise InvalidDiagnosticRequest("the diagnostic request has an invalid shape")
    goal_value = request.get("goal")
    profile = request.get("profile")
    include_mdns = request.get("include_mdns")
    if type(goal_value) is not str or type(profile) is not str:
        raise InvalidDiagnosticRequest("the diagnostic selections are invalid")
    if type(include_mdns) is not bool:
        raise InvalidDiagnosticRequest("include_mdns must be a boolean")
    try:
        goal = DiagnosticGoal(goal_value)
    except ValueError:
        raise InvalidDiagnosticRequest("the diagnostic goal is invalid") from None
    if profile not in _PROFILES:
        raise InvalidDiagnosticRequest("the diagnostic profile is invalid")
    if profile == "passive" and include_mdns:
        raise InvalidDiagnosticRequest("passive diagnostics cannot browse mDNS")
    return goal, profile, include_mdns


def validate_start_request(request: Mapping[str, object]) -> None:
    """Validate the browser object at a transport boundary without executing it."""

    _parse_start_request(request)


__all__ = [
    "DiagnosticService",
    "InvalidDiagnosticRequest",
    "JsonValue",
    "LocalDiagnosticService",
    "ReadyStatusProvider",
    "StatusProvider",
    "validate_start_request",
]
