from __future__ import annotations

import pytest

from netdiag.core import RiskTier
from netdiag.rescue import GuideStep, RescueGuide, guide_for
from netdiag.rescue.guides import GuideStepKind


@pytest.mark.parametrize(
    ("platform", "branch"),
    (
        ("macos", "apple_silicon"),
        ("macos", "intel"),
        ("windows", "winre"),
        ("linux", "live_environment"),
    ),
)
def test_every_supported_branch_is_complete_and_exportable(platform: str, branch: str) -> None:
    guide = guide_for(platform, branch)
    payload = guide.to_dict()
    assert payload["platform"]
    assert payload["limitations"]
    assert payload["steps"]
    assert any(step["kind"] == "stop_condition" for step in payload["steps"])


def test_apple_silicon_and_intel_startup_guidance_is_not_ambiguous() -> None:
    apple = guide_for("macos", "apple_silicon").to_dict()
    intel = guide_for("macos", "intel").to_dict()
    assert apple["steps"] != intel["steps"]
    assert "power button" in str(apple["steps"])
    assert "Command-R" in str(intel["steps"])


def test_unknown_branch_fails_closed() -> None:
    with pytest.raises(KeyError, match="unsupported rescue guide branch"):
        guide_for("macos", "generic")


def test_direct_unreviewed_guide_cannot_export_secret_prose() -> None:
    canary = "password=hunter2 recovery-key-111111"
    guide = RescueGuide(
        "rescue.fixture.unreviewed",
        "Fixture",
        "fixture",
        canary,
        (canary,),
        (
            GuideStep(
                "rescue.fixture.stop",
                "Stop",
                canary,
                GuideStepKind.STOP_CONDITION,
                RiskTier.YELLOW,
                canary,
            ),
        ),
    )
    with pytest.raises(ValueError, match="reviewed, registered"):
        guide.to_dict()


def test_guidance_has_no_executable_or_secret_capture_schema() -> None:
    for platform, branch in (
        ("macos", "apple_silicon"),
        ("macos", "intel"),
        ("windows", "winre"),
        ("linux", "live_environment"),
    ):
        payload = guide_for(platform, branch).to_dict()
        keys = _all_keys(payload)
        for forbidden_field in (
            "command",
            "script",
            "password",
            "credential_value",
            "recovery_key_value",
        ):
            assert forbidden_field not in keys
        assert all(step["risk"] in {tier.value for tier in RiskTier} for step in payload["steps"])


def test_content_never_presents_high_risk_operations_as_automatic() -> None:
    guide_text = " ".join(
        repr(guide_for(platform, branch).to_dict()).lower()
        for platform, branch in (
            ("macos", "apple_silicon"),
            ("macos", "intel"),
            ("windows", "winre"),
            ("linux", "live_environment"),
        )
    )
    assert "disable secure boot" not in guide_text
    assert "universal boot" not in guide_text
    assert "automatically repair" not in guide_text
    assert "run chkdsk" not in guide_text
    assert "set bcd" not in guide_text
    assert "mount read-write" not in guide_text


def test_registered_guide_detects_nested_step_mutation_and_recovers_after_restore() -> None:
    guide = guide_for("macos", "apple_silicon")
    step = guide.steps[1]
    original = step.instruction
    object.__setattr__(step, "instruction", "Changed but still valid manual guidance.")
    try:
        step.__post_init__()
        with pytest.raises(ValueError, match="integrity"):
            guide.to_dict()
        with pytest.raises(ValueError, match="integrity"):
            guide_for("macos", "apple_silicon")
    finally:
        object.__setattr__(step, "instruction", original)

    assert guide_for("macos", "apple_silicon").to_dict()["guide_id"] == guide.guide_id


def test_registered_guide_detects_limitation_mutation_and_recovers_after_restore() -> None:
    guide = guide_for("windows", "winre")
    original = guide.limitations
    object.__setattr__(
        guide,
        "limitations",
        (*original[:-1], "Changed but still valid limitation text."),
    )
    try:
        guide.__post_init__()
        with pytest.raises(ValueError, match="integrity"):
            guide.to_dict()
        with pytest.raises(ValueError, match="integrity"):
            guide_for("windows", "winre")
    finally:
        object.__setattr__(guide, "limitations", original)

    assert guide_for("windows", "winre").to_dict()["limitations"]


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).lower() for key in value} | {
            key for child in value.values() for key in _all_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _all_keys(child)}
    return set()
