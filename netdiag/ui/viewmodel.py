"""Fixed, non-secret presentation model for Lantern's local browser UI.

The application controller intentionally retains more diagnostic structure than
the browser needs.  This module is the one-way boundary between that internal
snapshot and the small public UI contract.  It copies no report, evidence,
finding, host, address, interface, or exception fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

UI_SCHEMA: Final[str] = "lantern.ui.v1"

_STATES: Final[frozenset[str]] = frozenset({"ready", "running", "completed", "cancelled", "failed"})
_GOALS: Final[frozenset[str]] = frozenset({"problem", "network", "rescue"})
_PROFILES: Final[frozenset[str]] = frozenset({"passive", "low_impact_network"})
_MODULE_SPECS: Final[tuple[tuple[str, str], ...]] = (
    ("route", "Connection path"),
    ("wifi", "Wi-Fi"),
    ("dns", "Name lookup"),
    ("lan", "Nearby devices"),
    ("mdns", "Local services"),
    ("ports", "Gateway services"),
)
_CATEGORY_TO_MODULE: Final[dict[str, str]] = {
    "routing": "route",
    "routing_connectivity": "route",
    "wifi": "wifi",
    "dns": "dns",
    "lan": "lan",
    "lan_ping": "lan",
    "mdns": "mdns",
    "gateway_ports": "ports",
}
_EXECUTION: Final[frozenset[str]] = frozenset(
    {"completed", "partial", "failed", "cancelled", "not_run"}
)
_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
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
)
_PROGRESS_PHASES: Final[frozenset[str]] = frozenset(
    {"started", "completed", "failed", "cancelled", "not_run"}
)
_DETAILS: Final[dict[str, str]] = {
    "not_started": "Not checked yet.",
    "queued": "Waiting for its turn.",
    "running": "Checking now.",
    "ok": "The check completed without a reported problem.",
    "limited": "Part of this module ran; another check was not included.",
    "attention": "Lantern found something worth reviewing.",
    "unavailable": "Lantern could not complete this check.",
    "not_run": "This check was not included in the selected profile.",
    "cancelled": "The check stopped at a safe boundary.",
}


def build_ui_viewmodel(snapshot: Mapping[str, object]) -> dict[str, JsonValue]:
    """Return the exact bounded ``lantern.ui.v1`` browser contract.

    Invalid or mutated controller snapshots fail closed.  Callers must
    translate validation failures into a generic availability response rather
    than serializing exception details.
    """

    if not isinstance(snapshot, Mapping):
        raise TypeError("diagnostic snapshot must be a mapping")
    state = _required_choice(snapshot.get("state"), _STATES, "application state")
    run = _run_view(snapshot.get("run"), state, snapshot.get("duration_ms"))
    progress = _progress_view(snapshot.get("progress"))
    result = snapshot.get("result")
    modules = _module_views(state, result, snapshot.get("progress"))
    summary = _summary_view(state, result, run)

    return {
        "schema": UI_SCHEMA,
        "product": "Lantern",
        "transport": "loopback",
        "state": state,
        "summary": summary,
        "run": run,
        "progress": progress,
        "modules": modules,
        "capabilities": {
            "passive_scan": True,
            "low_impact_network": True,
            "active_discovery": False,
            "remediation": False,
            "credentials": False,
            "lan_remote": False,
            "rescue_boot": False,
            "share_export": False,
        },
    }


def ready_ui_viewmodel() -> dict[str, JsonValue]:
    """Return a fresh safe view for an application with no diagnostic run."""

    return build_ui_viewmodel(
        {
            "state": "ready",
            "run": None,
            "progress": {"processed": 0, "planned": 0, "percent": 0, "events": []},
            "result": None,
        }
    )


def _run_view(
    value: object,
    state: str,
    duration_ms: object,
) -> dict[str, JsonValue] | None:
    if value is None:
        if state != "ready":
            raise ValueError("a non-ready diagnostic snapshot requires run metadata")
        return None
    if not isinstance(value, Mapping):
        raise TypeError("run metadata must be a mapping")
    if set(value) != {"goal", "profile", "include_mdns", "cancel_requested"}:
        raise ValueError("run metadata has an invalid shape")
    goal = _required_choice(value.get("goal"), _GOALS, "diagnostic goal")
    profile = _required_choice(value.get("profile"), _PROFILES, "diagnostic profile")
    include_mdns = value.get("include_mdns")
    cancel_requested = value.get("cancel_requested")
    if type(include_mdns) is not bool or type(cancel_requested) is not bool:
        raise TypeError("run flags must be booleans")
    if profile == "passive" and include_mdns:
        raise ValueError("passive diagnostics cannot include mDNS")
    return {
        "goal": goal,
        "profile": profile,
        "include_mdns": include_mdns,
        "cancel_requested": cancel_requested,
        "duration_ms": _required_bounded_integer(
            duration_ms,
            maximum=2_147_483_647,
            label="run duration",
        ),
    }


def _progress_view(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise TypeError("progress must be a mapping")
    processed = _required_bounded_integer(
        value.get("processed"), maximum=128, label="processed progress"
    )
    planned = _required_bounded_integer(value.get("planned"), maximum=128, label="planned progress")
    if processed > planned:
        raise ValueError("processed progress cannot exceed planned progress")
    if not planned:
        processed = 0
        percent = 0
    else:
        percent = round(processed * 100 / planned)
    return {"processed": processed, "planned": planned, "percent": percent}


def _module_views(
    state: str,
    result: object,
    progress: object,
) -> list[JsonValue]:
    statuses = {module_id: "not_started" for module_id, _label in _MODULE_SPECS}
    if state == "running":
        statuses = {module_id: "queued" for module_id, _label in _MODULE_SPECS}
        _apply_progress(statuses, progress)
    elif result is not None:
        statuses = _statuses_from_result(result)
    elif state == "cancelled":
        statuses = {module_id: "cancelled" for module_id, _label in _MODULE_SPECS}
    elif state == "failed":
        statuses = {module_id: "unavailable" for module_id, _label in _MODULE_SPECS}

    return [
        {
            "id": module_id,
            "label": label,
            "status": statuses[module_id],
            "detail": _DETAILS[statuses[module_id]],
        }
        for module_id, label in _MODULE_SPECS
    ]


def _apply_progress(statuses: dict[str, str], progress: object) -> None:
    if not isinstance(progress, Mapping):
        raise TypeError("progress must be a mapping")
    events = progress.get("events")
    if type(events) is not list or len(events) > 32:
        raise ValueError("progress events must be a bounded list")
    for event in events:
        if not isinstance(event, Mapping):
            raise TypeError("progress event must be a mapping")
        module = event.get("module")
        phase = event.get("phase")
        if type(module) is not str or module not in _CATEGORY_TO_MODULE:
            raise ValueError("progress event has an unknown module")
        if type(phase) is not str or phase not in _PROGRESS_PHASES:
            raise ValueError("progress event has an unknown phase")
        slot = _CATEGORY_TO_MODULE[module]
        replacement = {
            "started": "running",
            "completed": "ok",
            "failed": "unavailable",
            "cancelled": "cancelled",
            "not_run": "not_run",
        }[phase]
        current = statuses[slot]
        if replacement == "not_run" and current == "ok":
            statuses[slot] = "limited"
            continue
        if replacement == "not_run" and current in {
            "running",
            "attention",
            "limited",
            "unavailable",
            "cancelled",
        }:
            continue
        statuses[slot] = replacement


def _statuses_from_result(result: object) -> dict[str, str]:
    if not isinstance(result, Mapping):
        raise TypeError("diagnostic result must be a mapping")
    checks = result.get("checks")
    if type(checks) is not list or len(checks) > 32:
        raise ValueError("diagnostic checks must be a bounded list")
    grouped: dict[str, list[tuple[str, str]]] = {
        module_id: [] for module_id, _label in _MODULE_SPECS
    }
    for check in checks:
        if not isinstance(check, Mapping):
            raise TypeError("diagnostic check must be a mapping")
        category = check.get("module")
        execution = check.get("execution_status")
        outcome = check.get("outcome_status")
        if type(category) is not str or category not in _CATEGORY_TO_MODULE:
            raise ValueError("diagnostic check has an unknown module")
        if type(execution) is not str or execution not in _EXECUTION:
            raise ValueError("diagnostic check has an invalid execution status")
        if type(outcome) is not str or outcome not in _OUTCOMES:
            raise ValueError("diagnostic check has an invalid outcome status")
        grouped[_CATEGORY_TO_MODULE[category]].append((execution, outcome))

    return {module_id: _aggregate_checks(items) for module_id, items in grouped.items()}


def _aggregate_checks(items: list[tuple[str, str]]) -> str:
    if not items:
        return "not_run"
    completed = [item for item in items if item[0] in {"completed", "partial"}]
    if any(outcome in {"degraded", "failed", "blocked"} for _execution, outcome in completed):
        return "attention"
    if any(outcome == "cancelled" for _execution, outcome in completed):
        return "cancelled"
    if any(execution == "failed" for execution, _outcome in items):
        return "unavailable"
    if any(
        outcome in {"inconclusive", "not_tested", "unsupported", "permission_denied"}
        for _execution, outcome in completed
    ):
        return "unavailable"
    if any(execution == "partial" for execution, _outcome in completed):
        return "limited"
    if completed:
        if any(execution == "cancelled" for execution, _outcome in items):
            return "cancelled"
        if any(execution == "not_run" for execution, _outcome in items):
            return "limited"
        return "ok"
    if any(execution == "cancelled" for execution, _outcome in items):
        return "cancelled"
    return "not_run"


def _summary_view(
    state: str,
    result: object,
    run: Mapping[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    if state == "ready":
        summary = {
            "tone": "neutral",
            "headline": "Ready to check this computer",
            "detail": "Choose a read-only diagnostic profile when you are ready.",
        }
    elif state == "running":
        summary = {
            "tone": "neutral",
            "headline": "Diagnostic check in progress",
            "detail": "Lantern is moving through the selected checks one at a time.",
        }
    elif state == "cancelled":
        summary = {
            "tone": "neutral",
            "headline": "Diagnostic check stopped",
            "detail": "Completed checks are shown; remaining checks were not run.",
        }
    elif state == "failed":
        summary = {
            "tone": "attention",
            "headline": "Diagnostic check could not finish",
            "detail": "No automatic changes were made. You can safely try again.",
        }
    else:
        if not isinstance(result, Mapping):
            raise TypeError("a completed diagnostic requires a result")
        severity = result.get("severity")
        outcome = result.get("outcome")
        coverage = result.get("coverage")
        coverage_status = coverage.get("status") if isinstance(coverage, Mapping) else None
        if type(severity) is not str or severity not in {"ok", "info", "warn", "crit"}:
            raise ValueError("diagnostic result has an invalid severity")
        if type(outcome) is not str or outcome not in _OUTCOMES:
            raise ValueError("diagnostic result has an invalid outcome")
        if type(coverage_status) is not str or coverage_status not in {
            "complete",
            "partial",
            "none",
        }:
            raise ValueError("diagnostic result has invalid coverage")
        if outcome in {"degraded", "failed", "blocked"}:
            summary = {
                "tone": "critical" if severity == "crit" else "attention",
                "headline": "Lantern found something to review",
                "detail": (
                    "Lantern found a reported problem, and some selected checks were also "
                    "incomplete."
                    if coverage_status != "complete"
                    else "Review the module results before deciding what to do next."
                ),
            }
        elif coverage_status != "complete" or outcome in {
            "inconclusive",
            "not_tested",
            "unsupported",
            "permission_denied",
            "cancelled",
        }:
            summary = {
                "tone": "attention",
                "headline": "Check complete with limited coverage",
                "detail": "Some checks were not run or could not reach a clear result.",
            }
        elif severity in {"warn", "crit"}:
            summary = {
                "tone": "critical" if severity == "crit" else "attention",
                "headline": "Lantern found something to review",
                "detail": "Review the module results before deciding what to do next.",
            }
        else:
            summary = {
                "tone": "positive",
                "headline": "Diagnostic check complete",
                "detail": "The selected checks completed without a reported problem.",
            }

    if run is not None and run.get("goal") == "rescue":
        summary = {
            "tone": summary["tone"],
            "headline": summary["headline"],
            "detail": (
                "This run checks only the current computer and network; it does not test "
                "bootability, storage or hardware health, OS integrity, encryption, "
                "backups, or data recoverability."
            ),
        }
    return summary


def _required_choice(value: object, choices: frozenset[str], label: str) -> str:
    if type(value) is not str or value not in choices:
        raise ValueError(f"{label} is invalid")
    return value


def _required_bounded_integer(value: object, *, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


__all__ = ["UI_SCHEMA", "build_ui_viewmodel", "ready_ui_viewmodel"]
