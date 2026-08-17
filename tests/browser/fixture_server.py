"""Deterministic, synthetic loopback fixture for browser acceptance tests.

This process never invokes a diagnostic collector.  It exercises the real
session, HTTP, presentation, and packaged-asset boundaries with a reviewed
identifier-free status projection.
"""

from __future__ import annotations

import argparse
import copy
import signal
import threading
from collections.abc import Mapping

from netdiag.ui.controller import InvalidDiagnosticRequest, JsonValue, validate_start_request
from netdiag.ui.server import LanternLocalServer
from netdiag.ui.viewmodel import build_ui_viewmodel, ready_ui_viewmodel

_SCENARIOS = ("attention", "positive", "failed", "cancel")
_PLAN = ("routing", "routing", "dns", "wifi", "lan", "mdns", "gateway_ports", "lan")


def _check(module: str, execution: str, outcome: str) -> dict[str, object]:
    return {
        "module": module,
        "execution_status": execution,
        "outcome_status": outcome,
    }


def _finding(code: str, severity: str, status: str) -> dict[str, object]:
    return {
        "code": code,
        "severity": severity,
        "status": status,
        "confidence": {"level": "high"},
        # Report prose is deliberately not trusted by the browser projection.
        "title": "synthetic source prose withheld",
        "detail": "synthetic source prose withheld",
        "hint": "",
    }


def _synthetic_passive_snapshot(goal: str) -> dict[str, object]:
    checks = [
        _check("routing", "completed", "informational"),
        _check("routing", "not_run", "not_tested"),
        _check("dns", "not_run", "not_tested"),
        _check("wifi", "completed", "degraded"),
        _check("lan", "completed", "informational"),
        _check("mdns", "not_run", "not_tested"),
        _check("gateway_ports", "not_run", "not_tested"),
        _check("lan", "not_run", "not_tested"),
    ]
    return {
        "state": "completed",
        "duration_ms": 41,
        "run": {
            "goal": goal,
            "profile": "passive",
            "include_mdns": False,
            "cancel_requested": False,
        },
        "progress": {
            "processed": 8,
            "planned": 8,
            "percent": 100,
            "events": [],
        },
        "result": {
            "schema_version": "1.1",
            "status": "partial",
            "outcome": "degraded",
            "severity": "warn",
            "coverage": {
                "status": "partial",
                "planned": 8,
                "completed": 3,
                "partial": 0,
                "failed": 0,
                "cancelled": 0,
                "not_run": 5,
            },
            "checks": checks,
            "findings": [
                _finding("NDG.ROUTE.DEFAULT_ROUTE_OBSERVED", "info", "informational"),
                _finding("NDG.WIFI.CONNECTED", "info", "informational"),
                _finding("NDG.WIFI.SIGNAL_WEAK", "warn", "degraded"),
                _finding("NDG.LAN.NEIGHBOR_CACHE_READ", "info", "informational"),
            ],
            "redacted": True,
            "truncated": False,
        },
    }


def _synthetic_positive_view(goal: str) -> dict[str, JsonValue]:
    """Return presentation-only positive v2 data that no live profile can emit."""

    view = copy.deepcopy(build_ui_viewmodel(_synthetic_passive_snapshot(goal)))
    view["summary"] = {
        "tone": "positive",
        "headline": "Synthetic positive presentation fixture",
        "detail": "This all-clear state exists only to test Lantern's presentation branch.",
    }
    assessment = view["assessment"]
    assert isinstance(assessment, dict)
    assessment.update(
        {
            "sentence": (
                "Synthetic presentation-only data reported no issue across every diagnostic layer."
            ),
            "tone": "positive",
            "confidence": "high",
            "coverage": "complete",
        }
    )
    view["issues"] = []
    path = view["path"]
    assert isinstance(path, list)
    for node in path:
        assert isinstance(node, dict)
        node["status"] = "ok"
        node["detail"] = "Synthetic presentation-only data reported no issue for this layer."
    modules = view["modules"]
    assert isinstance(modules, list)
    for module in modules:
        assert isinstance(module, dict)
        module["status"] = "ok"
        module["detail"] = "Synthetic presentation-only module data completed."
        module["finding"] = "Synthetic presentation-only data reported no issue in this module."
        module["technical"] = [
            "This deterministic all-clear result is unreachable from current live profiles."
        ]
    return view


def _failed_snapshot(goal: str) -> dict[str, object]:
    return {
        "state": "failed",
        "duration_ms": 17,
        "run": {
            "goal": goal,
            "profile": "passive",
            "include_mdns": False,
            "cancel_requested": False,
        },
        "progress": {
            "processed": 0,
            "planned": 0,
            "percent": 0,
            "events": [],
        },
        "result": None,
    }


def _running_snapshot(goal: str) -> dict[str, object]:
    return {
        "state": "running",
        "duration_ms": 0,
        "run": {
            "goal": goal,
            "profile": "passive",
            "include_mdns": False,
            "cancel_requested": False,
        },
        "progress": {
            "processed": 0,
            "planned": 0,
            "percent": 0,
            "events": [],
        },
        "result": None,
    }


def _cancelled_snapshot(goal: str) -> dict[str, object]:
    checks = [
        _check(
            module,
            "cancelled" if index == 0 else "not_run",
            "cancelled" if index == 0 else "not_tested",
        )
        for index, module in enumerate(_PLAN)
    ]
    return {
        "state": "cancelled",
        "duration_ms": 23,
        "run": {
            "goal": goal,
            "profile": "passive",
            "include_mdns": False,
            "cancel_requested": True,
        },
        "progress": {
            "processed": 8,
            "planned": 8,
            "percent": 100,
            "events": [],
        },
        "result": {
            "schema_version": "1.1",
            "status": "cancelled",
            "outcome": "cancelled",
            "severity": "ok",
            "coverage": {
                "status": "none",
                "planned": 8,
                "completed": 0,
                "partial": 0,
                "failed": 0,
                "cancelled": 1,
                "not_run": 7,
            },
            "checks": checks,
            "findings": [],
            "redacted": True,
            "truncated": False,
        },
    }


class SyntheticDiagnosticService:
    """Deterministic service that cannot authorize any packet activity."""

    def __init__(self, scenario: str) -> None:
        if scenario not in _SCENARIOS:
            raise ValueError("synthetic fixture scenario is not allowlisted")
        self._lock = threading.Lock()
        self._scenario = scenario
        self._goal: str | None = None
        self._view: Mapping[str, JsonValue] = ready_ui_viewmodel()

    def snapshot(self) -> Mapping[str, JsonValue]:
        with self._lock:
            return self._view

    def start(self, request: Mapping[str, object]) -> None:
        validate_start_request(request)
        if request.get("profile") != "passive" or request.get("include_mdns") is not False:
            raise InvalidDiagnosticRequest("the synthetic fixture accepts passive checks only")
        goal = request.get("goal")
        if not isinstance(goal, str):
            raise InvalidDiagnosticRequest("the synthetic fixture requires a diagnostic goal")
        if self._scenario == "attention":
            view = build_ui_viewmodel(_synthetic_passive_snapshot(goal))
        elif self._scenario == "positive":
            view = _synthetic_positive_view(goal)
        elif self._scenario == "failed":
            view = build_ui_viewmodel(_failed_snapshot(goal))
        else:
            view = build_ui_viewmodel(_running_snapshot(goal))
        with self._lock:
            self._goal = goal
            self._view = view

    def cancel(self) -> bool:
        with self._lock:
            if (
                self._scenario != "cancel"
                or self._goal is None
                or self._view.get("state") != "running"
            ):
                return False
            self._view = build_ui_viewmodel(_cancelled_snapshot(self._goal))
            return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic Lantern browser fixture.")
    parser.add_argument("--scenario", choices=_SCENARIOS, default="attention")
    args = parser.parse_args()
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    service = SyntheticDiagnosticService(args.scenario)
    server = LanternLocalServer(
        diagnostic_service=service,
        max_lifetime_seconds=60,
    )
    try:
        server.start()
        print(f"LANTERN_FIXTURE_URL={server.launch_url}", flush=True)
        while not stop.wait(0.05):
            if server.wait(timeout=0):
                break
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    raise SystemExit(main())
