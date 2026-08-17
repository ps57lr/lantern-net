"""Contract tests for the deterministic browser-scenario service."""

from __future__ import annotations

import pytest

from netdiag.ui.controller import InvalidDiagnosticRequest
from tests.browser.fixture_server import _SCENARIOS, SyntheticDiagnosticService

_PASSIVE_REQUEST = {
    "goal": "problem",
    "profile": "passive",
    "include_mdns": False,
}


@pytest.mark.parametrize(
    ("scenario", "state", "tone", "coverage"),
    [
        ("attention", "completed", "attention", "partial"),
        ("positive", "completed", "positive", "complete"),
        ("failed", "failed", "attention", "none"),
        ("cancel", "running", "neutral", "none"),
    ],
)
def test_allowlisted_scenarios_are_deterministic_and_bounded(
    scenario: str, state: str, tone: str, coverage: str
) -> None:
    service = SyntheticDiagnosticService(scenario)
    service.start(_PASSIVE_REQUEST)
    view = service.snapshot()

    assert view["schema"] == "lantern.ui.v2"
    assert view["state"] == state
    assert view["assessment"]["tone"] == tone
    assert view["assessment"]["coverage"] == coverage
    assert len(view["issues"]) <= 3
    assert view["capabilities"]["active_discovery"] is False
    assert view["capabilities"]["remediation"] is False
    assert view["capabilities"]["credentials"] is False

    encoded = repr(view)
    assert "synthetic source prose withheld" not in encoded
    assert "192.168." not in encoded
    assert "00:11:22:33:44:55" not in encoded


def test_positive_is_explicitly_presentation_only_and_unreachable_live() -> None:
    service = SyntheticDiagnosticService("positive")
    service.start(_PASSIVE_REQUEST)
    view = service.snapshot()

    assert "Synthetic presentation-only" in view["assessment"]["sentence"]
    assert all(item["status"] == "ok" for item in view["modules"])
    assert all(item["status"] == "ok" for item in view["path"])
    assert view["issues"] == []


def test_cancel_remains_running_until_one_explicit_honest_cancellation() -> None:
    service = SyntheticDiagnosticService("cancel")
    service.start(_PASSIVE_REQUEST)
    assert service.snapshot()["state"] == "running"

    assert service.cancel() is True
    cancelled = service.snapshot()
    assert cancelled["state"] == "cancelled"
    assert cancelled["run"]["cancel_requested"] is True
    assert cancelled["assessment"]["tone"] == "attention"
    assert cancelled["assessment"]["coverage"] == "none"
    assert service.cancel() is False


def test_fixture_rejects_unknown_scenarios_and_packet_activity() -> None:
    assert _SCENARIOS == ("attention", "positive", "failed", "cancel")
    with pytest.raises(ValueError, match="not allowlisted"):
        SyntheticDiagnosticService("unknown")

    service = SyntheticDiagnosticService("attention")
    with pytest.raises(InvalidDiagnosticRequest, match="passive checks only"):
        service.start(
            {
                "goal": "problem",
                "profile": "low_impact_network",
                "include_mdns": False,
            }
        )
