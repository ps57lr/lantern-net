"""Fixed, identifier-free presentation model for Lantern's local browser UI.

The controller retains a bounded, redacted Report 1.1 projection. This module
is a second one-way boundary: only typed status enums and registered finding
codes enter; only reviewed, parameter-free prose leaves. Report prose,
evidence, identifiers, addresses, interfaces, parameters, and errors never
cross into the browser contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, TypeAlias

from netdiag.catalog import FINDING_REGISTRY

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

UI_SCHEMA: Final[str] = "lantern.ui.v2"

_STATES = frozenset({"ready", "running", "completed", "cancelled", "failed"})
_GOALS = frozenset({"problem", "network", "rescue"})
_PROFILES = frozenset({"passive", "low_impact_network"})
_MODULE_SPECS: Final[dict[str, str]] = {
    "route": "Connection path",
    "wifi": "Wi-Fi",
    "dns": "Name lookup",
    "lan": "Nearby devices",
    "mdns": "Local services",
    "ports": "Gateway services",
}
_GOAL_MODULE_ORDER: Final[dict[str, tuple[str, ...]]] = {
    "problem": ("route", "wifi", "dns", "lan", "mdns", "ports"),
    "network": ("route", "dns", "ports", "lan", "wifi", "mdns"),
    "rescue": ("route", "wifi", "lan", "dns", "mdns", "ports"),
}
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
_FINDING_CATEGORY_TO_MODULE: Final[dict[str, str]] = {
    "route": "route",
    "wifi": "wifi",
    "dns": "dns",
    "lan": "lan",
    "mdns": "mdns",
    "ports": "ports",
    "gateway_ports": "ports",
}
_EXECUTION = frozenset({"completed", "partial", "failed", "cancelled", "not_run"})
_OUTCOMES = frozenset(
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
_ADVERSE_OUTCOMES = frozenset({"degraded", "failed", "blocked"})
_UNCLEAR_OUTCOMES = frozenset(
    {"inconclusive", "not_tested", "unsupported", "permission_denied", "cancelled"}
)
_CONFIDENCE = frozenset({"low", "medium", "high"})
_SEVERITIES = frozenset({"ok", "info", "warn", "crit"})
_COVERAGE = frozenset({"complete", "partial", "none"})
_PROGRESS_PHASES = frozenset({"started", "completed", "failed", "cancelled", "not_run"})
_REPORT_CHECK_SEQUENCE: Final[tuple[str, ...]] = (
    "routing",
    "routing",
    "dns",
    "wifi",
    "lan",
    "mdns",
    "gateway_ports",
    "lan",
)
_PROGRESS_MODULE_SEQUENCE: Final[tuple[str, ...]] = (
    "routing",
    "routing_connectivity",
    "dns",
    "wifi",
    "lan",
    "mdns",
    "gateway_ports",
    "lan_ping",
)
_DETAILS: Final[dict[str, str]] = {
    "not_started": "Not checked yet.",
    "queued": "Waiting for its turn.",
    "running": "Checking now.",
    "ok": "The check completed without a reported problem.",
    "limited": "Part of this module ran; another check was not included or was incomplete.",
    "attention": "Lantern found something worth reviewing.",
    "unavailable": "Lantern could not reach a clear result for this module.",
    "not_run": "This check was not included in the selected profile.",
    "cancelled": "The check stopped at a safe boundary.",
}
_MODULE_FINDINGS: Final[dict[str, str]] = {
    "not_started": "No result is available for this module yet.",
    "queued": "This module has not started.",
    "running": "This module is still being evaluated.",
    "ok": "Completed observations reported no problem in this module.",
    "limited": "Usable observations exist, but this module has incomplete coverage.",
    "attention": "A registered diagnostic result in this module needs review.",
    "unavailable": "This module did not produce a clear diagnostic result.",
    "not_run": "This module was outside the selected diagnostic profile.",
    "cancelled": "This module stopped before producing a complete result.",
}
_TECHNICAL_BY_EXECUTION: Final[dict[str, str]] = {
    "completed": "At least one planned check completed.",
    "partial": "At least one planned check returned partial coverage.",
    "failed": "At least one planned check could not complete.",
    "cancelled": "At least one planned check was cancelled.",
    "not_run": "At least one planned check was not run.",
}
_NETWORK_DISCLAIMER: Final[str] = (
    "This is an informational evaluation from one endpoint, not a whole-network "
    "assessment, security audit, or compliance certification for a home, business, "
    "financial system, or municipality."
)
_RESCUE_DISCLAIMER: Final[str] = (
    "This is current-device and network guidance only; it does not determine bootability, "
    "storage or hardware health, OS integrity, encryption, backups, or data recoverability, "
    "and it does not perform recovery."
)


@dataclass(frozen=True, slots=True)
class _IssueSpec:
    module: str
    source_severity: str
    source_status: str
    title: str
    explanation: str
    next_step: str

    @property
    def severity(self) -> str:
        return "critical" if self.source_severity == "crit" else "attention"


@dataclass(frozen=True, slots=True)
class _CheckSignal:
    category: str
    module: str
    execution: str
    outcome: str


@dataclass(frozen=True, slots=True)
class _FindingSignal:
    code: str
    module: str
    severity: str
    status: str
    confidence: str


@dataclass(frozen=True, slots=True)
class _ResultSignals:
    status: str
    outcome: str
    severity: str
    coverage: str
    checks: tuple[_CheckSignal, ...]
    findings: tuple[_FindingSignal, ...]
    truncated: bool


def _issue(
    module: str,
    severity: str,
    status: str,
    title: str,
    explanation: str,
    next_step: str,
) -> _IssueSpec:
    return _IssueSpec(module, severity, status, title, explanation, next_step)


# Explicit reviewed product copy. A broader registry entry is not enough to
# authorize an issue card; it must also appear in this fixed catalog.
_ISSUE_SPECS: Final[dict[str, _IssueSpec]] = {
    "NDG.ROUTE.DEFAULT_ROUTE_MISSING": _issue(
        "route",
        "warn",
        "inconclusive",
        "No IPv4 default route observed",
        "The inspected IPv4 route table had no default path. IPv6 and Internet reachability were not tested by that observation.",
        "Review the active connection and its IPv4 configuration before changing network settings.",
    ),
    "NDG.ROUTE.OUTBOUND_HTTPS_FAILED": _issue(
        "route",
        "warn",
        "degraded",
        "Tested outbound HTTPS path did not complete",
        "Neither bounded outbound TCP connection completed; WAN, captive-portal, or firewall behavior may be involved.",
        "Confirm whether a captive portal is waiting, then review WAN and firewall status with the network owner.",
    ),
    "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED": _issue(
        "route",
        "warn",
        "degraded",
        "Gateway path was not confirmed",
        "Neither the bounded gateway ping nor the tested outbound path completed.",
        "Review the local link, VLAN, DHCP, and gateway status with the network owner.",
    ),
    "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED": _issue(
        "route",
        "warn",
        "degraded",
        "External path was not confirmed",
        "Neither the bounded external ping nor the tested outbound path completed.",
        "Check for a captive portal, then review the local link, firewall, and WAN status.",
    ),
    "NDG.ROUTE.CHECK_FAILED": _issue(
        "route",
        "warn",
        "inconclusive",
        "Connection-path check could not complete",
        "Lantern could not collect a complete connection-path observation.",
        "Retry the read-only check once; if it repeats, review coverage before making changes.",
    ),
    "NDG.DNS.FILTERING_DETECTED": _issue(
        "dns",
        "warn",
        "blocked",
        "DNS filtering was observed",
        "A tested resolver returned an address form commonly used for intentional blocking.",
        "Confirm the organization's DNS policy and compare it with an approved resolver before changing DNS settings.",
    ),
    "NDG.DNS.RESOLVER_INCONSISTENT": _issue(
        "dns",
        "warn",
        "degraded",
        "DNS resolvers responded inconsistently",
        "At least one resolver query failed while another returned a usable answer.",
        "Compare resolver reachability and the intended DNS policy before changing configuration.",
    ),
    "NDG.DNS.RESOLUTION_FAILED": _issue(
        "dns",
        "crit",
        "failed",
        "Tested DNS lookup did not complete",
        "None of the tested resolvers returned a usable IPv4 answer.",
        "Review Internet reachability, configured resolvers, and intentional filtering with the network owner.",
    ),
    "NDG.DNS.NO_RESOLVERS_CONFIGURED": _issue(
        "dns",
        "crit",
        "failed",
        "No DNS resolver was reported",
        "The operating system did not report a configured DNS nameserver.",
        "Review the active connection and its DHCP or DNS assignment before changing settings.",
    ),
    "NDG.DNS.CHECK_FAILED": _issue(
        "dns",
        "warn",
        "inconclusive",
        "DNS check could not complete",
        "Lantern could not collect a complete name-resolution observation.",
        "Retry the read-only check once; if it repeats, review resolver and network availability.",
    ),
    "NDG.WIFI.UNSUPPORTED": _issue(
        "wifi",
        "info",
        "unsupported",
        "Wi-Fi observation is unavailable",
        "Lantern cannot collect a supported Wi-Fi link observation on this system.",
        "Use the operating system's trusted network controls to review link state; Ethernet may still be active.",
    ),
    "NDG.WIFI.SIGNAL_WEAK": _issue(
        "wifi",
        "warn",
        "degraded",
        "Observed Wi-Fi signal was weak",
        "The observed signal level can reduce throughput and reliability, especially for nearby smart devices.",
        "Compare performance closer to the access point and review coverage before changing radio settings.",
    ),
    "NDG.WIFI.CHECK_FAILED": _issue(
        "wifi",
        "warn",
        "inconclusive",
        "Wi-Fi check could not complete",
        "Lantern could not collect a complete Wi-Fi link observation.",
        "Retry the read-only check once and review the operating system's link status if it repeats.",
    ),
    "NDG.LAN.NEIGHBOR_CACHE_PARTIAL": _issue(
        "lan",
        "info",
        "inconclusive",
        "Nearby-device visibility was incomplete",
        "The neighbor cache was empty or partly available; that does not mean the network has no other devices.",
        "Treat the device list as incomplete and compare with an approved router or switch inventory if available.",
    ),
    "NDG.LAN.NEIGHBOR_CACHE_FAILED": _issue(
        "lan",
        "warn",
        "inconclusive",
        "Nearby-device cache could not be read",
        "Lantern could not obtain a usable local neighbor-cache observation.",
        "Retry the read-only check once and compare with an approved network inventory if it repeats.",
    ),
    "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED": _issue(
        "lan",
        "warn",
        "degraded",
        "Possible duplicate network address",
        "A bounded observation was consistent with more than one device using the same address.",
        "Compare DHCP reservations and documented static assignments before changing any address.",
    ),
    "NDG.LAN.CHECK_FAILED": _issue(
        "lan",
        "warn",
        "inconclusive",
        "Local-network check could not complete",
        "Lantern could not collect a complete local-network observation.",
        "Retry the read-only check once and review module coverage if it repeats.",
    ),
    "NDG.MDNS.BROWSE_FAILED": _issue(
        "mdns",
        "warn",
        "inconclusive",
        "Local-service browse did not complete",
        "The brief multicast service browse failed before producing a usable result.",
        "Retry only on a network where multicast browsing is approved; completed modules remain valid.",
    ),
    "NDG.MDNS.UNSUPPORTED": _issue(
        "mdns",
        "info",
        "unsupported",
        "Local-service browsing is unavailable",
        "This system does not currently provide Lantern's supported multicast browsing capability.",
        "Use an approved local-service inventory or have an administrator confirm platform support.",
    ),
    "NDG.MDNS.CHECK_FAILED": _issue(
        "mdns",
        "warn",
        "inconclusive",
        "Local-service check could not complete",
        "Lantern could not collect a complete local-service observation.",
        "Retry only where multicast browsing is approved and review module coverage if it repeats.",
    ),
    "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED": _issue(
        "ports",
        "warn",
        "inconclusive",
        "Gateway service response was inconclusive",
        "None of the few tested gateway ports connected or actively refused, so filtering and unreachability remain indistinguishable.",
        "Confirm gateway reachability first, then review approved firewall policy without assuming the ports are closed.",
    ),
    "NDG.PORTS.CHECK_FAILED": _issue(
        "ports",
        "warn",
        "inconclusive",
        "Gateway-service check could not complete",
        "Lantern could not collect a complete result for the bounded gateway-port check.",
        "Retry once on an authorized network and review gateway reachability if it repeats.",
    ),
}

# Registered results that are useful for aggregation or a diagnostic-layer
# state but are intentionally not priority issues. Exact bindings prevent a
# future or mutated Report from reinterpreting a reassuring code as adverse.
_NON_ISSUE_MEANINGS: Final[dict[str, tuple[str, str, str]]] = {
    "NDG.ROUTE.DEFAULT_ROUTE_OBSERVED": ("route", "info", "informational"),
    "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE": ("route", "ok", "healthy"),
    "NDG.ROUTE.GATEWAY_REACHABLE": ("route", "ok", "healthy"),
    "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP": ("route", "info", "inconclusive"),
    "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP": ("route", "info", "informational"),
    "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP": ("route", "info", "inconclusive"),
    "NDG.DNS.ANSWER_VARIANCE": ("dns", "info", "informational"),
    "NDG.DNS.RESOLUTION_SUCCEEDED": ("dns", "ok", "healthy"),
    "NDG.DNS.RESOLVER_CONFIGURATION": ("dns", "info", "informational"),
    "NDG.WIFI.NOT_CONNECTED": ("wifi", "info", "not_tested"),
    "NDG.WIFI.CONNECTED": ("wifi", "info", "informational"),
    "NDG.WIFI.SIGNAL_STRONG": ("wifi", "ok", "healthy"),
    "NDG.WIFI.SIGNAL_FAIR": ("wifi", "info", "informational"),
    "NDG.WIFI.FIVE_GHZ_LINK": ("wifi", "info", "informational"),
    "NDG.WIFI.LINK_RATE_OBSERVED": ("wifi", "info", "informational"),
    "NDG.LAN.NEIGHBOR_CACHE_READ": ("lan", "info", "informational"),
    "NDG.MDNS.SERVICES_DISCOVERED": ("mdns", "info", "informational"),
    "NDG.MDNS.NO_SERVICES_OBSERVED": ("mdns", "info", "informational"),
    "NDG.PORTS.OPEN_PORTS_OBSERVED": ("ports", "info", "informational"),
    "NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE": ("ports", "info", "informational"),
}
_FORBIDDEN_UI_FINDING_CODES: Final[frozenset[str]] = frozenset(
    {
        "NDG.LAN.ACTIVE_DISCOVERY_NO_SCOPE",
        "NDG.LAN.ACTIVE_DISCOVERY_SCOPE_TOO_LARGE",
        "NDG.LAN.ACTIVE_DISCOVERY_COMPLETED",
    }
)
# Every browser-visible finding is tied to the exact policy-plan slot that can
# produce it. The two route collectors serialize to the same Report category,
# so this separate fixed map prevents a passive route observation from being
# confused with an outbound connectivity result.
_FINDING_STEPS: Final[dict[str, tuple[int, ...]]] = {
    "NDG.ROUTE.DEFAULT_ROUTE_MISSING": (1,),
    "NDG.ROUTE.DEFAULT_ROUTE_OBSERVED": (1,),
    "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE": (2,),
    "NDG.ROUTE.OUTBOUND_HTTPS_FAILED": (2,),
    "NDG.ROUTE.GATEWAY_REACHABLE": (2,),
    "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP": (2,),
    "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED": (2,),
    "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP": (2,),
    "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP": (2,),
    "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED": (2,),
    "NDG.ROUTE.CHECK_FAILED": (1, 2),
    "NDG.DNS.FILTERING_DETECTED": (3,),
    "NDG.DNS.RESOLVER_INCONSISTENT": (3,),
    "NDG.DNS.RESOLUTION_FAILED": (3,),
    "NDG.DNS.ANSWER_VARIANCE": (3,),
    "NDG.DNS.RESOLUTION_SUCCEEDED": (3,),
    "NDG.DNS.NO_RESOLVERS_CONFIGURED": (3,),
    "NDG.DNS.RESOLVER_CONFIGURATION": (3,),
    "NDG.DNS.CHECK_FAILED": (3,),
    "NDG.WIFI.UNSUPPORTED": (4,),
    "NDG.WIFI.NOT_CONNECTED": (4,),
    "NDG.WIFI.CONNECTED": (4,),
    "NDG.WIFI.SIGNAL_STRONG": (4,),
    "NDG.WIFI.SIGNAL_FAIR": (4,),
    "NDG.WIFI.SIGNAL_WEAK": (4,),
    "NDG.WIFI.FIVE_GHZ_LINK": (4,),
    "NDG.WIFI.LINK_RATE_OBSERVED": (4,),
    "NDG.WIFI.CHECK_FAILED": (4,),
    "NDG.LAN.NEIGHBOR_CACHE_READ": (5,),
    "NDG.LAN.NEIGHBOR_CACHE_PARTIAL": (5,),
    "NDG.LAN.NEIGHBOR_CACHE_FAILED": (5,),
    "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED": (5,),
    "NDG.LAN.CHECK_FAILED": (5,),
    "NDG.MDNS.BROWSE_FAILED": (6,),
    "NDG.MDNS.UNSUPPORTED": (6,),
    "NDG.MDNS.SERVICES_DISCOVERED": (6,),
    "NDG.MDNS.NO_SERVICES_OBSERVED": (6,),
    "NDG.MDNS.CHECK_FAILED": (6,),
    "NDG.PORTS.OPEN_PORTS_OBSERVED": (7,),
    "NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE": (7,),
    "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED": (7,),
    "NDG.PORTS.CHECK_FAILED": (7,),
}
_FAILED_EXECUTION_FINDING_CODES: Final[frozenset[str]] = frozenset(
    {
        "NDG.ROUTE.CHECK_FAILED",
        "NDG.DNS.CHECK_FAILED",
        "NDG.WIFI.CHECK_FAILED",
        "NDG.LAN.CHECK_FAILED",
        "NDG.MDNS.BROWSE_FAILED",
        "NDG.MDNS.CHECK_FAILED",
        "NDG.PORTS.CHECK_FAILED",
    }
)
_REGISTERED_FINDING_CODES = frozenset(definition.code for definition in FINDING_REGISTRY.snapshot())
if (
    frozenset(_ISSUE_SPECS) | frozenset(_NON_ISSUE_MEANINGS) | _FORBIDDEN_UI_FINDING_CODES
    != _REGISTERED_FINDING_CODES
):
    raise RuntimeError("the UI finding meaning registry is incomplete")
if frozenset(_FINDING_STEPS) != _REGISTERED_FINDING_CODES - _FORBIDDEN_UI_FINDING_CODES:
    raise RuntimeError("the UI finding source-step registry is incomplete")


def build_ui_viewmodel(snapshot: Mapping[str, object]) -> dict[str, JsonValue]:
    """Return the exact bounded ``lantern.ui.v2`` browser contract."""

    if not isinstance(snapshot, Mapping):
        raise TypeError("diagnostic snapshot must be a mapping")
    state = _required_choice(snapshot.get("state"), _STATES, "application state")
    run = _run_view(snapshot.get("run"), state, snapshot.get("duration_ms"))
    progress_value = snapshot.get("progress")
    progress = _progress_view(progress_value)
    _validate_progress_scope(progress_value, progress, run, state)
    value = snapshot.get("result")
    result = _result_signals(value) if value is not None else None
    if state in {"completed", "cancelled"} and result is None:
        raise ValueError("a terminal diagnostic snapshot requires a result")
    if state in {"ready", "running", "failed"} and result is not None:
        raise ValueError("this application state cannot expose a diagnostic result")
    if state == "cancelled" and result is not None and result.status != "cancelled":
        raise ValueError("cancelled application state requires a cancelled report")
    if state == "completed" and result is not None and result.status == "cancelled":
        raise ValueError("completed application state cannot contain a cancelled report")
    _validate_result_scope(run, result)
    _validate_progress_result(progress_value, result, state)

    goal = str(run["goal"]) if run is not None else "problem"
    issues = _issue_views(result, goal)
    modules = _module_views(state, result, snapshot.get("progress"), goal, issues)
    path = _path_views(state, result)
    assessment = _assessment_view(state, result, run, modules, path, issues)
    summary = _summary_view(state, result, run, assessment)

    return {
        "schema": UI_SCHEMA,
        "product": "Lantern",
        "transport": "loopback",
        "state": state,
        "summary": summary,
        "assessment": assessment,
        "run": run,
        "progress": progress,
        "issues": issues,
        "path": path,
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
    return build_ui_viewmodel(
        {
            "state": "ready",
            "run": None,
            "progress": {"processed": 0, "planned": 0, "percent": 0, "events": []},
            "result": None,
        }
    )


def _run_view(value: object, state: str, duration_ms: object) -> dict[str, JsonValue] | None:
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
            duration_ms, maximum=2_147_483_647, label="run duration"
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
    return {
        "processed": processed if planned else 0,
        "planned": planned,
        "percent": round(processed * 100 / planned) if planned else 0,
    }


def _authorized_steps(run: Mapping[str, JsonValue] | None) -> frozenset[int]:
    if run is None:
        return frozenset()
    if run["profile"] == "passive":
        return frozenset({1, 4, 5})
    allowed = {1, 2, 3, 4, 5, 7}
    if run["include_mdns"] is True:
        allowed.add(6)
    return frozenset(allowed)


def _validate_progress_scope(
    value: object,
    progress: Mapping[str, JsonValue],
    run: Mapping[str, JsonValue] | None,
    state: str,
) -> None:
    if not isinstance(value, Mapping):
        raise TypeError("progress must be a mapping")
    events = value.get("events")
    if type(events) is not list or len(events) > 32:
        raise ValueError("progress events must be a bounded list")
    processed, planned = progress["processed"], progress["planned"]
    assert isinstance(processed, int) and isinstance(planned, int)
    if state == "ready":
        if run is not None or events or processed or planned:
            raise ValueError("ready progress must be empty")
        return
    if not events:
        if state in {"running", "failed"} and (processed or planned):
            raise ValueError("empty live progress cannot claim completed work")
        if state in {"completed", "cancelled"} and (processed, planned) != (8, 8):
            raise ValueError("terminal progress must cover the declared plan")
        if state == "cancelled" and (run is None or run["cancel_requested"] is not True):
            raise ValueError("cancelled progress requires a cancellation request")
        return
    if run is None or planned != 8:
        raise ValueError("diagnostic progress is missing its authorized plan")

    authorized = _authorized_steps(run)
    phases_by_step: dict[int, list[str]] = {}
    last_step = 0
    terminal_count = 0
    for expected_sequence, event in enumerate(events, start=1):
        if not isinstance(event, Mapping) or set(event) != {
            "sequence",
            "module",
            "phase",
            "step",
            "total_steps",
        }:
            raise ValueError("progress event has an invalid shape")
        sequence = event.get("sequence")
        module = event.get("module")
        phase = event.get("phase")
        step = event.get("step")
        total_steps = event.get("total_steps")
        if type(sequence) is not int or sequence != expected_sequence:
            raise ValueError("progress event sequence is invalid")
        if type(step) is not int or not 1 <= step <= 8 or type(total_steps) is not int:
            raise ValueError("progress event step is invalid")
        if total_steps != 8 or step < last_step:
            raise ValueError("progress events do not follow the declared plan")
        if type(module) is not str or module != _PROGRESS_MODULE_SEQUENCE[step - 1]:
            raise ValueError("progress event module does not match its plan step")
        if type(phase) is not str or phase not in _PROGRESS_PHASES:
            raise ValueError("progress event phase is invalid")
        if step not in authorized and phase not in {"not_run", "cancelled"}:
            raise ValueError("progress event exceeds the authorized diagnostic scope")
        if phase == "cancelled" and run["cancel_requested"] is not True:
            raise ValueError("progress cannot be cancelled without a cancellation request")
        phases_by_step.setdefault(step, []).append(phase)
        last_step = step
        if phase in {"completed", "failed", "cancelled", "not_run"}:
            terminal_count += 1

    if set(phases_by_step) != set(range(1, last_step + 1)):
        raise ValueError("progress events skipped a declared plan step")
    for step, phases in phases_by_step.items():
        valid = phases in (
            ["not_run"],
            ["cancelled"],
            ["started", "completed"],
            ["started", "failed"],
        )
        if state in {"running", "failed"} and step == last_step:
            valid = valid or phases == ["started"]
        if not valid:
            raise ValueError("progress phases are inconsistent for a plan step")
    if terminal_count != processed:
        raise ValueError("processed progress does not match terminal events")
    if state in {"completed", "cancelled"}:
        if last_step != 8 or terminal_count != 8:
            raise ValueError("terminal progress did not cover the declared plan")
        if state == "completed" and any(
            phase == "cancelled" for phases in phases_by_step.values() for phase in phases
        ):
            raise ValueError("completed progress cannot contain cancellation")
        cancelled_steps = [
            step for step, phases in phases_by_step.items() if phases == ["cancelled"]
        ]
        if state == "cancelled":
            if len(cancelled_steps) != 1:
                raise ValueError("cancelled progress requires one cancellation boundary")
            if any(
                phases_by_step[step] != ["not_run"] for step in range(cancelled_steps[0] + 1, 9)
            ):
                raise ValueError("checks after cancellation must remain not run")


def _validate_progress_result(progress: object, result: _ResultSignals | None, state: str) -> None:
    if result is None or not isinstance(progress, Mapping):
        return
    events = progress.get("events")
    if not events or type(events) is not list:
        return
    terminal_by_step: dict[int, str] = {}
    for event in events:
        if not isinstance(event, Mapping):
            return
        phase, step = event.get("phase"), event.get("step")
        if type(step) is int and phase in {"completed", "failed", "cancelled", "not_run"}:
            assert isinstance(phase, str)
            terminal_by_step[step] = phase
    expected_execution = {
        "completed": "completed",
        "failed": "failed",
        "cancelled": "cancelled",
        "not_run": "not_run",
    }
    for step, check in enumerate(result.checks, start=1):
        phase = terminal_by_step.get(step)
        if phase is not None and check.execution != expected_execution[phase]:
            raise ValueError("progress does not match the terminal diagnostic result")
    if (
        state in {"completed", "cancelled"}
        and not result.truncated
        and len(terminal_by_step) != len(result.checks)
    ):
        raise ValueError("terminal progress does not match the diagnostic result plan")


def _validate_result_scope(
    run: Mapping[str, JsonValue] | None, result: _ResultSignals | None
) -> None:
    if result is None:
        return
    if run is None:
        raise ValueError("a diagnostic result requires authorized run metadata")
    cancellation_observed = result.status == "cancelled" or any(
        check.execution == "cancelled" for check in result.checks
    )
    if cancellation_observed and run["cancel_requested"] is not True:
        raise ValueError("a cancelled result requires a cancellation request")
    authorized = _authorized_steps(run)
    cancelled_steps = [
        step for step, check in enumerate(result.checks, start=1) if check.execution == "cancelled"
    ]
    if result.status == "cancelled":
        if (not result.truncated and len(cancelled_steps) != 1) or len(cancelled_steps) > 1:
            raise ValueError("a cancelled report requires one cancellation boundary")
        if cancelled_steps and any(
            check.execution != "not_run" for check in result.checks[cancelled_steps[0] :]
        ):
            raise ValueError("checks after cancellation must remain not run")
    for step, check in enumerate(result.checks, start=1):
        if step not in authorized and check.execution not in {"not_run", "cancelled"}:
            raise ValueError("diagnostic result exceeds the authorized run scope")
        if check.execution == "cancelled" and result.status != "cancelled":
            raise ValueError("a cancelled check requires a cancelled report")
    if result.truncated:
        return
    executions = [check.execution for check in result.checks]
    if "cancelled" in executions:
        expected_status = "cancelled"
    elif all(execution == "completed" for execution in executions):
        expected_status = "completed"
    elif any(execution in {"completed", "partial"} for execution in executions):
        expected_status = "partial"
    elif "failed" in executions:
        expected_status = "failed"
    else:
        expected_status = "not_run"
    if result.status != expected_status:
        raise ValueError("diagnostic report status does not match check execution")


def _result_signals(value: object) -> _ResultSignals:
    if not isinstance(value, Mapping):
        raise TypeError("diagnostic result must be a mapping")
    if value.get("schema_version") != "1.1" or value.get("redacted") is not True:
        raise ValueError("diagnostic result is not a redacted Report 1.1 projection")
    status = _required_choice(value.get("status"), _EXECUTION, "diagnostic execution")
    outcome = _required_choice(value.get("outcome"), _OUTCOMES, "diagnostic outcome")
    severity = _required_choice(value.get("severity"), _SEVERITIES, "diagnostic severity")
    truncated = value.get("truncated")
    if type(truncated) is not bool:
        raise TypeError("diagnostic truncation state must be a boolean")
    checks = _check_signals(value.get("checks"), truncated=truncated)
    findings = _finding_signals(value.get("findings"))
    coverage_value = value.get("coverage")
    coverage = _coverage_view(coverage_value)
    _validate_finding_check_bindings(checks, findings, truncated=truncated)
    if not truncated:
        _validate_coverage_check_bindings(coverage_value, checks)
        _validate_report_aggregates(
            status=status,
            outcome=outcome,
            severity=severity,
            coverage=coverage,
            checks=checks,
            findings=findings,
        )
    return _ResultSignals(
        status,
        outcome,
        severity,
        coverage,
        checks,
        findings,
        truncated,
    )


def _coverage_view(value: object) -> str:
    if not isinstance(value, Mapping):
        raise TypeError("diagnostic coverage must be a mapping")
    keys = {"status", "planned", "completed", "partial", "failed", "cancelled", "not_run"}
    if set(value) != keys:
        raise ValueError("diagnostic coverage has an invalid shape")
    status = _required_choice(value.get("status"), _COVERAGE, "diagnostic coverage")
    counts = [
        _required_bounded_integer(value.get(key), maximum=128, label=f"coverage {key}")
        for key in ("completed", "partial", "failed", "cancelled", "not_run")
    ]
    planned = _required_bounded_integer(value.get("planned"), maximum=128, label="coverage planned")
    if sum(counts) != planned:
        raise ValueError("diagnostic coverage counts do not match the plan")
    usable = counts[0] + counts[1]
    expected = "complete" if planned and counts[0] == planned else "partial" if usable else "none"
    if status != expected:
        raise ValueError("diagnostic coverage status does not match its counts")
    return status


def _check_signals(value: object, *, truncated: bool) -> tuple[_CheckSignal, ...]:
    if type(value) is not list or len(value) > 32:
        raise ValueError("diagnostic checks must be a bounded list")
    signals: list[_CheckSignal] = []
    for check in value:
        if not isinstance(check, Mapping):
            raise TypeError("diagnostic check must be a mapping")
        category = check.get("module")
        if type(category) is not str or category not in _CATEGORY_TO_MODULE:
            raise ValueError("diagnostic check has an unknown module")
        execution = _required_choice(check.get("execution_status"), _EXECUTION, "check execution")
        outcome = _required_choice(check.get("outcome_status"), _OUTCOMES, "check outcome")
        if execution == "not_run" and outcome != "not_tested":
            raise ValueError("a not-run check must have a not-tested outcome")
        if execution == "cancelled" and outcome != "cancelled":
            raise ValueError("a cancelled check must have a cancelled outcome")
        signals.append(_CheckSignal(category, _CATEGORY_TO_MODULE[category], execution, outcome))
    categories = tuple(signal.category for signal in signals)
    expected = _REPORT_CHECK_SEQUENCE[: len(categories)] if truncated else _REPORT_CHECK_SEQUENCE
    if categories != expected:
        raise ValueError("diagnostic checks do not match the declared Report 1.1 plan")
    return tuple(signals)


def _finding_signals(value: object) -> tuple[_FindingSignal, ...]:
    if type(value) is not list or len(value) > 64:
        raise ValueError("diagnostic findings must be a bounded list")
    signals: list[_FindingSignal] = []
    for finding in value:
        if not isinstance(finding, Mapping):
            raise TypeError("diagnostic finding must be a mapping")
        code = finding.get("code")
        if type(code) is not str:
            raise ValueError("diagnostic finding code is invalid")
        if code in _FORBIDDEN_UI_FINDING_CODES:
            raise ValueError("active discovery findings are unavailable in the local UI")
        try:
            definition = FINDING_REGISTRY.require(code)
        except KeyError:
            raise ValueError("diagnostic finding code is not registered") from None
        module = _FINDING_CATEGORY_TO_MODULE.get(definition.category)
        if module is None:
            raise ValueError("diagnostic finding module is not registered for the UI")
        severity = _required_choice(finding.get("severity"), _SEVERITIES, "finding severity")
        status = _required_choice(finding.get("status"), _OUTCOMES, "finding outcome")
        confidence = finding.get("confidence")
        if not isinstance(confidence, Mapping) or set(confidence) != {"level"}:
            raise ValueError("diagnostic finding confidence has an invalid shape")
        level = _required_choice(confidence.get("level"), _CONFIDENCE, "finding confidence")
        if code in _ISSUE_SPECS:
            spec = _ISSUE_SPECS[code]
            expected = (spec.module, spec.source_severity, spec.source_status)
        else:
            expected = _NON_ISSUE_MEANINGS.get(code)
        if expected is None or (module, severity, status) != expected:
            raise ValueError("diagnostic finding does not match its registered UI meaning")
        signals.append(_FindingSignal(code, module, severity, status, level))
    return tuple(signals)


def _validate_finding_check_bindings(
    checks: tuple[_CheckSignal, ...],
    findings: tuple[_FindingSignal, ...],
    *,
    truncated: bool,
) -> None:
    statuses_by_step: dict[int, list[str]] = {}
    used_ambiguous_steps: set[int] = set()
    for finding in findings:
        candidates = _FINDING_STEPS[finding.code]
        eligible = [
            step
            for step in candidates
            if step <= len(checks) and checks[step - 1].execution not in {"not_run", "cancelled"}
        ]
        if not eligible:
            raise ValueError("diagnostic finding is not supported by its exact plan step")
        if len(candidates) == 1:
            step = eligible[0]
        else:
            failed = [
                item
                for item in eligible
                if checks[item - 1].execution == "failed"
                and checks[item - 1].outcome == "inconclusive"
            ]
            if not failed:
                raise ValueError("route failure finding is not supported by an exact route step")
            step = next((item for item in failed if item not in used_ambiguous_steps), failed[0])
            used_ambiguous_steps.add(step)
        if (
            finding.code in _FAILED_EXECUTION_FINDING_CODES
            and checks[step - 1].execution != "failed"
        ):
            raise ValueError("failed-collector finding requires a failed exact plan step")
        if (
            finding.code not in _FAILED_EXECUTION_FINDING_CODES
            and checks[step - 1].execution == "failed"
        ):
            raise ValueError("a failed plan step cannot support an observation finding")
        statuses_by_step.setdefault(step, []).append(finding.status)

    if truncated:
        return
    for step, check in enumerate(checks, start=1):
        if check.execution in {"not_run", "cancelled"}:
            continue
        expected = _aggregate_source_outcome(statuses_by_step.get(step, []))
        if checks[step - 1].outcome != expected:
            raise ValueError("diagnostic finding outcomes do not match their exact plan step")


def _aggregate_source_outcome(statuses: list[str]) -> str:
    if not statuses:
        return "not_tested"
    for status in (
        "failed",
        "degraded",
        "blocked",
        "permission_denied",
        "cancelled",
        "inconclusive",
        "healthy",
        "informational",
        "not_tested",
        "unsupported",
    ):
        if status in statuses:
            return status
    return "inconclusive"


def _validate_coverage_check_bindings(value: object, checks: tuple[_CheckSignal, ...]) -> None:
    assert isinstance(value, Mapping)
    expected = {key: 0 for key in ("completed", "partial", "failed", "cancelled", "not_run")}
    for check in checks:
        expected[check.execution] += 1
    if value.get("planned") != len(checks) or any(
        value.get(key) != count for key, count in expected.items()
    ):
        raise ValueError("diagnostic coverage does not match check execution")


def _validate_report_aggregates(
    *,
    status: str,
    outcome: str,
    severity: str,
    coverage: str,
    checks: tuple[_CheckSignal, ...],
    findings: tuple[_FindingSignal, ...],
) -> None:
    expected_severity = (
        "crit"
        if any(finding.severity == "crit" for finding in findings)
        else "warn"
        if any(finding.severity == "warn" for finding in findings)
        else "ok"
    )
    if severity != expected_severity:
        raise ValueError("diagnostic severity does not match registered findings")

    executions = [check.execution for check in checks]
    if "cancelled" in executions:
        expected_status = "cancelled"
    elif executions and all(execution == "completed" for execution in executions):
        expected_status = "completed"
    elif any(execution in {"completed", "partial"} for execution in executions):
        expected_status = "partial"
    elif "failed" in executions:
        expected_status = "failed"
    else:
        expected_status = "not_run"
    if status != expected_status:
        raise ValueError("diagnostic report status does not match check execution")

    finding_statuses = {finding.status for finding in findings}
    check_outcomes = {check.outcome for check in checks}
    for candidate in ("failed", "degraded", "blocked", "permission_denied", "cancelled"):
        if candidate in finding_statuses:
            expected_outcome = candidate
            break
    else:
        if "permission_denied" in check_outcomes:
            expected_outcome = "permission_denied"
        elif "cancelled" in check_outcomes:
            expected_outcome = "cancelled"
        elif coverage == "none":
            if check_outcomes == {"unsupported"}:
                expected_outcome = "unsupported"
            elif check_outcomes & {"inconclusive", "failed", "degraded", "blocked"}:
                expected_outcome = "inconclusive"
            else:
                expected_outcome = "not_tested"
        elif (
            coverage != "complete"
            or not findings
            or finding_statuses <= {"informational", "not_tested", "unsupported"}
            or (finding_statuses | check_outcomes) & {"inconclusive", "not_tested", "unsupported"}
        ):
            expected_outcome = "inconclusive"
        else:
            expected_outcome = "healthy"
    if outcome != expected_outcome:
        raise ValueError("diagnostic outcome does not match typed child results")


def _module_views(
    state: str,
    result: _ResultSignals | None,
    progress: object,
    goal: str,
    issues: list[JsonValue],
) -> list[JsonValue]:
    statuses = {module: "not_started" for module in _MODULE_SPECS}
    checks_by_module: dict[str, list[_CheckSignal]] = {module: [] for module in _MODULE_SPECS}
    if state == "running":
        statuses = {module: "queued" for module in _MODULE_SPECS}
        _apply_progress(statuses, progress)
    elif result is not None:
        for check in result.checks:
            checks_by_module[check.module].append(check)
        statuses = {module: _aggregate_checks(checks_by_module[module]) for module in _MODULE_SPECS}
        if result.truncated:
            expected_counts = {
                "route": 2,
                "wifi": 1,
                "dns": 1,
                "lan": 2,
                "mdns": 1,
                "ports": 1,
            }
            for module, expected_count in expected_counts.items():
                observed_count = len(checks_by_module[module])
                if observed_count >= expected_count:
                    continue
                if observed_count == 0:
                    statuses[module] = "unavailable"
                elif statuses[module] not in {"attention", "unavailable", "cancelled"}:
                    statuses[module] = "limited"
        _apply_finding_statuses(statuses, result.findings)
        if result.truncated:
            statuses = {
                module: "limited" if status == "ok" else status
                for module, status in statuses.items()
            }
    elif state == "failed":
        statuses = {module: "unavailable" for module in _MODULE_SPECS}

    issue_title_by_module: dict[str, str] = {}
    for issue in issues:
        if isinstance(issue, dict):
            module, title = issue.get("module"), issue.get("title")
            if isinstance(module, str) and isinstance(title, str):
                issue_title_by_module.setdefault(module, title)

    return [
        {
            "id": module,
            "label": _MODULE_SPECS[module],
            "status": statuses[module],
            "detail": _DETAILS[statuses[module]],
            "finding": issue_title_by_module.get(module, _MODULE_FINDINGS[statuses[module]]),
            "technical": _technical_view(statuses[module], checks_by_module[module]),
        }
        for module in _GOAL_MODULE_ORDER[goal]
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
        category, phase = event.get("module"), event.get("phase")
        if type(category) is not str or category not in _CATEGORY_TO_MODULE:
            raise ValueError("progress event has an unknown module")
        if type(phase) is not str or phase not in _PROGRESS_PHASES:
            raise ValueError("progress event has an unknown phase")
        module = _CATEGORY_TO_MODULE[category]
        replacement = {
            "started": "running",
            "completed": "ok",
            "failed": "unavailable",
            "cancelled": "cancelled",
            "not_run": "not_run",
        }[phase]
        current = statuses[module]
        if replacement == "unavailable":
            statuses[module] = "unavailable"
        elif current == "unavailable":
            continue
        elif replacement == "cancelled":
            statuses[module] = "cancelled"
        elif current == "cancelled":
            continue
        elif replacement == "not_run":
            statuses[module] = "limited" if current in {"running", "ok", "limited"} else "not_run"
        elif replacement == "running":
            if current != "limited":
                statuses[module] = "running"
        else:
            statuses[module] = "limited" if current == "limited" else "ok"


def _aggregate_checks(items: list[_CheckSignal]) -> str:
    if not items:
        return "not_run"
    usable = [item for item in items if item.execution in {"completed", "partial"}]
    if any(item.outcome in _ADVERSE_OUTCOMES for item in usable):
        return "attention"
    if any(item.outcome == "cancelled" for item in usable):
        return "cancelled"
    if any(item.execution == "failed" for item in items):
        return "unavailable"
    if any(item.outcome in _UNCLEAR_OUTCOMES for item in usable):
        return "unavailable"
    if any(item.execution == "partial" for item in usable):
        return "limited"
    if usable:
        if any(item.execution == "cancelled" for item in items):
            return "cancelled"
        if any(item.execution == "not_run" for item in items):
            return "limited"
        return "ok"
    if any(item.execution == "cancelled" for item in items):
        return "cancelled"
    return "not_run"


def _apply_finding_statuses(statuses: dict[str, str], findings: tuple[_FindingSignal, ...]) -> None:
    for finding in findings:
        if finding.severity in {"warn", "crit"} or finding.status in _ADVERSE_OUTCOMES:
            statuses[finding.module] = "attention"
        elif finding.status in _UNCLEAR_OUTCOMES and statuses[finding.module] in {"ok", "not_run"}:
            statuses[finding.module] = "unavailable"


def _technical_view(status: str, checks: list[_CheckSignal]) -> list[JsonValue]:
    if not checks:
        return [_DETAILS[status]]
    lines: list[JsonValue] = []
    for execution in ("failed", "partial", "cancelled", "not_run", "completed"):
        if any(check.execution == execution for check in checks):
            lines.append(_TECHNICAL_BY_EXECUTION[execution])
        if len(lines) == 4:
            break
    return lines


def _issue_views(result: _ResultSignals | None, goal: str) -> list[JsonValue]:
    if result is None:
        return []
    module_rank = {module: index for index, module in enumerate(_GOAL_MODULE_ORDER[goal])}
    status_rank = {
        "failed": 0,
        "degraded": 1,
        "blocked": 2,
        "permission_denied": 3,
        "inconclusive": 4,
        "unsupported": 5,
        "not_tested": 6,
        "cancelled": 7,
        "healthy": 8,
        "informational": 9,
    }
    eligible = [finding for finding in result.findings if finding.code in _ISSUE_SPECS]
    eligible.sort(
        key=lambda finding: (
            0 if _ISSUE_SPECS[finding.code].severity == "critical" else 1,
            status_rank[finding.status],
            module_rank[finding.module],
            finding.code,
        )
    )
    views: list[JsonValue] = []
    emitted: set[str] = set()
    for finding in eligible:
        if finding.code in emitted:
            continue
        spec = _ISSUE_SPECS[finding.code]
        views.append(
            {
                "code": finding.code,
                "title": spec.title,
                "explanation": spec.explanation,
                "next_step": spec.next_step,
                "module": spec.module,
                "severity": spec.severity,
            }
        )
        emitted.add(finding.code)
        if len(views) == 3:
            break
    return views


def _path_views(state: str, result: _ResultSignals | None) -> list[JsonValue]:
    node_ids = ("device", "gateway", "internet", "dns", "services")
    if state in {"ready", "running"}:
        statuses = {node: "not_run" for node in node_ids}
        details = {node: "No diagnostic-layer conclusion is available yet." for node in node_ids}
    elif state == "failed" or result is None:
        statuses = {node: "unavailable" for node in node_ids}
        details = {node: "Lantern could not evaluate this diagnostic layer." for node in node_ids}
    else:
        statuses, details = _completed_path(result)
        if result.truncated:
            for node, status in tuple(statuses.items()):
                if status == "ok":
                    statuses[node] = "limited"
                    details[node] = (
                        "A usable observation was retained, but the bounded result was truncated."
                    )
    # These are independent diagnostic layers, not a causal or physical
    # topology. The UI renders them without connector arrows.
    specs = (
        ("device", "Device route", "route"),
        ("gateway", "Gateway", "route"),
        ("internet", "Internet", "route"),
        ("dns", "DNS", "dns"),
        ("services", "Local services", "mdns"),
    )
    return [
        {
            "id": node,
            "label": label,
            "status": statuses[node],
            "detail": details[node],
            "module": module,
        }
        for node, label, module in specs
    ]


def _completed_path(result: _ResultSignals) -> tuple[dict[str, str], dict[str, str]]:
    by_category: dict[str, list[_CheckSignal]] = {}
    for check in result.checks:
        by_category.setdefault(check.category, []).append(check)
    routing = by_category.get("routing", [])
    local_route = routing[0] if routing else None
    connectivity = routing[1] if len(routing) > 1 else None
    dns = _first_check(by_category, "dns")
    mdns = _first_check(by_category, "mdns")
    codes = {finding.code for finding in result.findings}

    if "NDG.ROUTE.DEFAULT_ROUTE_MISSING" in codes:
        device_status = "attention"
        device_detail = (
            "No IPv4 default path was observed; IPv6 and total Internet viability remain untested."
        )
    elif (
        local_route is not None
        and local_route.execution == "completed"
        and "NDG.ROUTE.DEFAULT_ROUTE_OBSERVED" in codes
    ):
        device_status = "ok"
        device_detail = "A local IPv4 route was observed; gateway and Internet reachability were not tested by that observation."
    else:
        device_status = _check_path_status(local_route, missing_unavailable=result.truncated)
        if device_status == "ok":
            device_status = "limited"
        device_detail = _path_detail("device", device_status)

    if "NDG.ROUTE.DEFAULT_ROUTE_MISSING" in codes:
        gateway_status = "attention"
        gateway_detail = "No IPv4 default gateway path was observed; this does not establish total Internet failure."
    elif connectivity is not None and (
        "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED" in codes
    ):
        gateway_status, gateway_detail = "attention", "The bounded gateway path was not confirmed."
    elif (
        connectivity is not None
        and connectivity.execution == "completed"
        and "NDG.ROUTE.GATEWAY_REACHABLE" in codes
    ):
        gateway_status, gateway_detail = "ok", "The bounded gateway reachability check completed."
    elif connectivity is not None and "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP" in codes:
        gateway_status = "limited"
        gateway_detail = (
            "The gateway did not answer ping, while a separate outbound path completed."
        )
    elif connectivity is not None and connectivity.execution == "failed":
        gateway_status = "unavailable"
        gateway_detail = "The gateway-path check did not produce a clear result."
    elif local_route is None or _check_path_status(
        local_route, missing_unavailable=result.truncated
    ) in {"not_run", "unavailable"}:
        gateway_status = _check_path_status(local_route, missing_unavailable=result.truncated)
        gateway_detail = _path_detail("gateway", gateway_status)
    else:
        gateway_status = "limited"
        gateway_detail = "A local route was observed, but gateway reachability was not confirmed."

    if (
        connectivity is not None
        and connectivity.execution == "completed"
        and "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE" in codes
    ):
        internet_status, internet_detail = "ok", "The bounded outbound TCP connection completed."
    elif (
        connectivity is not None
        and {
            "NDG.ROUTE.OUTBOUND_HTTPS_FAILED",
            "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        }
        & codes
    ):
        internet_status = "attention"
        internet_detail = "The bounded outbound path did not complete; broader Internet availability was not exhaustively tested."
    else:
        internet_status = _check_path_status(connectivity, missing_unavailable=result.truncated)
        if internet_status == "ok":
            internet_status = "limited"
        internet_detail = _path_detail("internet", internet_status)

    dns_status = _check_path_status(dns, missing_unavailable=result.truncated)
    dns_detail = _path_detail("dns", dns_status)

    if (
        mdns is not None
        and mdns.execution == "completed"
        and "NDG.MDNS.SERVICES_DISCOVERED" in codes
    ):
        services_status = "ok"
        services_detail = (
            "The brief approved browse observed one or more local service advertisements."
        )
    elif mdns is not None and "NDG.MDNS.NO_SERVICES_OBSERVED" in codes:
        services_status = "limited"
        services_detail = (
            "The brief browse saw no advertisements; that does not prove local services are absent."
        )
    else:
        services_status = _check_path_status(mdns, missing_unavailable=result.truncated)
        if services_status == "ok":
            services_status = "limited"
        services_detail = _path_detail("services", services_status)

    return (
        {
            "device": device_status,
            "gateway": gateway_status,
            "internet": internet_status,
            "dns": dns_status,
            "services": services_status,
        },
        {
            "device": device_detail,
            "gateway": gateway_detail,
            "internet": internet_detail,
            "dns": dns_detail,
            "services": services_detail,
        },
    )


def _first_check(
    by_category: Mapping[str, list[_CheckSignal]], category: str
) -> _CheckSignal | None:
    items = by_category.get(category, [])
    return items[0] if items else None


def _check_path_status(check: _CheckSignal | None, *, missing_unavailable: bool = False) -> str:
    if check is None:
        return "unavailable" if missing_unavailable else "not_run"
    if check.execution == "not_run":
        return "not_run"
    if check.execution == "failed":
        return "unavailable"
    if check.outcome in _ADVERSE_OUTCOMES:
        return "attention"
    if check.execution in {"partial", "cancelled"}:
        return "limited"
    if check.outcome in _UNCLEAR_OUTCOMES:
        return "unavailable"
    return "ok"


def _path_detail(node: str, status: str) -> str:
    details = {
        "device": {
            "ok": "A local IPv4 route was observed without testing gateway or Internet reachability.",
            "attention": "The local IPv4 route observation needs review.",
            "limited": "A local routing check ran without establishing a clear IPv4 route observation.",
            "not_run": "The local route observation was not completed.",
            "unavailable": "The local route observation did not produce a clear result.",
        },
        "gateway": {
            "ok": "The bounded gateway reachability check completed.",
            "attention": "The selected gateway observation needs review.",
            "limited": "A local route was observed, but gateway reachability was not confirmed.",
            "not_run": "Gateway reachability was not tested.",
            "unavailable": "Gateway reachability did not produce a clear result.",
        },
        "internet": {
            "ok": "The bounded outbound path check completed.",
            "attention": "The bounded outbound path observation needs review.",
            "limited": "An Internet-path observation completed without proving broad availability.",
            "not_run": "Internet reachability was not tested by this profile.",
            "unavailable": "The bounded Internet-path check did not produce a clear result.",
        },
        "dns": {
            "ok": "The selected DNS lookup completed without a reported problem.",
            "attention": "The selected DNS observation needs review.",
            "limited": "Some DNS observations completed, but coverage is incomplete.",
            "not_run": "DNS resolution was not tested by this profile.",
            "unavailable": "The DNS check did not produce a clear result.",
        },
        "services": {
            "ok": "The brief approved local-service browse observed advertisements.",
            "attention": "The local-service observation needs review.",
            "limited": "The brief browse cannot establish a complete local-service inventory.",
            "not_run": "Local-service browsing was not included.",
            "unavailable": "Local-service browsing did not produce a clear result.",
        },
    }
    return details[node][status]


def _assessment_view(
    state: str,
    result: _ResultSignals | None,
    run: Mapping[str, JsonValue] | None,
    modules: list[JsonValue],
    path: list[JsonValue],
    issues: list[JsonValue],
) -> dict[str, JsonValue]:
    goal = str(run["goal"]) if run is not None else "problem"
    disclaimer = _disclaimer(goal, run is not None)
    if state == "ready":
        return {
            "sentence": "Lantern has not run a diagnostic check yet.",
            "tone": "neutral",
            "confidence": "none",
            "coverage": "none",
            "disclaimer": None,
        }
    if state == "running":
        return {
            "sentence": "Lantern is checking only the selected diagnostic scope; no conclusion is available yet.",
            "tone": "neutral",
            "confidence": "none",
            "coverage": "none",
            "disclaimer": disclaimer,
        }
    if state == "failed" or result is None:
        return {
            "sentence": "Lantern could not complete the diagnostic check, so no health conclusion is available.",
            "tone": "attention",
            "confidence": "none",
            "coverage": "none",
            "disclaimer": disclaimer,
        }

    non_ok_module = any(
        isinstance(module, dict) and module.get("status") != "ok" for module in modules
    )
    non_ok_path = any(isinstance(node, dict) and node.get("status") != "ok" for node in path)
    critical_issue = any(
        isinstance(issue, dict) and issue.get("severity") == "critical" for issue in issues
    )
    adverse = result.outcome in _ADVERSE_OUTCOMES
    unclear = result.outcome in _UNCLEAR_OUTCOMES
    adverse_issue = any(
        finding.code in _ISSUE_SPECS
        and _ISSUE_SPECS[finding.code].source_status in _ADVERSE_OUTCOMES
        for finding in result.findings
    )
    if critical_issue or result.severity == "crit":
        tone = "critical"
    elif (
        state == "cancelled"
        or adverse
        or unclear
        or result.status != "completed"
        or result.severity == "warn"
        or result.coverage != "complete"
        or result.truncated
        or issues
        or non_ok_module
        or non_ok_path
    ):
        tone = "attention"
    else:
        tone = "positive"

    if state == "cancelled":
        sentence = (
            "The diagnostic check stopped; completed results remain valid, but no complete "
            "conclusion is available."
        )
    elif adverse or adverse_issue:
        sentence = _goal_sentence(goal, "problem")
    elif result.severity in {"warn", "crit"}:
        sentence = _goal_sentence(goal, "review")
    elif result.coverage == "none":
        sentence = "No selected diagnostic check produced a usable result."
    elif (
        result.coverage != "complete"
        or unclear
        or result.status != "completed"
        or non_ok_module
        or non_ok_path
        or result.truncated
    ):
        sentence = _goal_sentence(goal, "limited")
    else:
        sentence = _goal_sentence(goal, "clear")

    return {
        "sentence": sentence,
        "tone": tone,
        "confidence": _assessment_confidence(result),
        "coverage": result.coverage,
        "disclaimer": disclaimer,
    }


def _goal_sentence(goal: str, result_kind: str) -> str:
    return {
        "problem": {
            "problem": "Lantern found a reported problem in the selected checks.",
            "review": "Lantern found a diagnostic result that needs review in the selected checks.",
            "limited": "Lantern completed some selected checks, but coverage was too limited for a complete conclusion.",
            "clear": "Lantern found no reported problem in the selected checks.",
        },
        "network": {
            "problem": "Lantern found a reported problem in the selected network evaluation checks.",
            "review": "Lantern found a result that needs review in the selected network evaluation checks.",
            "limited": "The selected network evaluation has incomplete coverage, so it cannot support a complete conclusion.",
            "clear": "Lantern found no reported problem in the selected network evaluation checks.",
        },
        "rescue": {
            "problem": "Lantern found a reported problem in the selected current-device or network checks.",
            "review": "Lantern found a result that needs review in the selected current-device or network checks.",
            "limited": "The selected current-device and network checks have incomplete coverage, so they cannot establish viability.",
            "clear": "Lantern found no reported problem in the selected current-device and network checks.",
        },
    }[goal][result_kind]


def _assessment_confidence(result: _ResultSignals) -> str:
    if result.coverage == "none":
        return "none"
    if result.coverage != "complete" or result.truncated:
        return "low"
    levels = {finding.confidence for finding in result.findings}
    if "low" in levels:
        return "low"
    if levels and levels == {"high"}:
        return "high"
    return "medium"


def _disclaimer(goal: str, has_run: bool) -> str | None:
    if not has_run or goal == "problem":
        return None
    return _NETWORK_DISCLAIMER if goal == "network" else _RESCUE_DISCLAIMER


def _summary_view(
    state: str,
    result: _ResultSignals | None,
    run: Mapping[str, JsonValue] | None,
    assessment: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    tone = str(assessment["tone"])
    if state == "ready":
        return {
            "tone": tone,
            "headline": "Ready to check this computer",
            "detail": "Choose a read-only diagnostic profile when you are ready.",
        }
    if state == "running":
        return {
            "tone": tone,
            "headline": "Diagnostic check in progress",
            "detail": "Lantern is moving through the selected checks one at a time.",
        }
    if state == "failed":
        return {
            "tone": tone,
            "headline": "Diagnostic check could not finish",
            "detail": "No automatic changes were made. You can safely try again.",
        }
    if state == "cancelled":
        return {
            "tone": tone,
            "headline": "Diagnostic check stopped",
            "detail": "Completed checks are shown; remaining checks were not run.",
        }
    if result is None:
        raise TypeError("a completed diagnostic requires a result")
    if tone in {"critical", "attention"}:
        if result.outcome in _ADVERSE_OUTCOMES:
            headline = "Lantern found something to review"
            detail = (
                "Lantern found a reported problem, and some selected checks were also incomplete."
                if result.coverage != "complete"
                else "Review the safe priority items before deciding what to do next."
            )
        else:
            headline = "Check complete with limited coverage"
            detail = "Some checks were not run or could not reach a clear result."
    else:
        headline = "Diagnostic check complete"
        detail = "The selected checks completed without a reported problem."
    if run is not None and run.get("goal") == "rescue":
        detail = (
            "This run checks only the current computer and network; it does not test "
            "bootability, storage or hardware health, OS integrity, encryption, backups, "
            "or data recoverability."
        )
    return {"tone": tone, "headline": headline, "detail": detail}


def _required_choice(value: object, choices: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{label} is invalid")
    # Report domain enums inherit from ``str``. Canonicalize them to one of the
    # exact base-string allowlist members before anything reaches the browser.
    return next(choice for choice in choices if value == choice)


def _required_bounded_integer(value: object, *, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


__all__ = ["UI_SCHEMA", "build_ui_viewmodel", "ready_ui_viewmodel"]
