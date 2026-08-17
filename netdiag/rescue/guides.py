"""Reviewed, platform-specific manual rescue guidance.

The guide model contains no executable command, script, or credential field.  All
steps are instructions for supported operating-system recovery facilities and are
explicitly classified as read-only observations or manual guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netdiag.core import JsonValue, RiskTier, serialize_structured
from netdiag.core.values import validate_dotted_identifier, validate_nonempty_text


class GuideStepKind(str, Enum):
    READ_ONLY_OBSERVATION = "read_only_observation"
    MANUAL_GUIDANCE = "manual_guidance"
    STOP_CONDITION = "stop_condition"


@dataclass(frozen=True, slots=True)
class GuideStep:
    step_id: str
    title: str
    instruction: str
    kind: GuideStepKind
    risk: RiskTier
    data_warning: str | None = None

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.step_id, label="rescue step id")
        validate_nonempty_text(self.title, label="rescue step title", maximum=160)
        validate_nonempty_text(self.instruction, label="rescue instruction", maximum=2048)
        if not isinstance(self.kind, GuideStepKind):
            raise TypeError("guide step kind must be GuideStepKind")
        if not isinstance(self.risk, RiskTier):
            raise TypeError("guide step risk must be RiskTier")
        if self.data_warning is not None:
            validate_nonempty_text(self.data_warning, label="data warning", maximum=1024)
        if self.risk != RiskTier.GREEN and not self.data_warning:
            raise ValueError("yellow and red guidance requires a data warning")


@dataclass(frozen=True, slots=True)
class RescueGuide:
    guide_id: str
    platform: str
    branch: str
    capability_label: str
    limitations: tuple[str, ...]
    steps: tuple[GuideStep, ...]

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.guide_id, label="rescue guide id")
        validate_nonempty_text(self.platform, label="guide platform", maximum=64)
        validate_dotted_identifier(self.branch, label="guide branch")
        validate_nonempty_text(self.capability_label, label="capability label", maximum=256)
        if type(self.limitations) is not tuple:
            raise TypeError("guide limitations must be a tuple")
        if not self.limitations:
            raise ValueError("guides must state at least one limitation")
        for limitation in self.limitations:
            if type(limitation) is not str:
                raise TypeError("guide limitations must contain strings")
            validate_nonempty_text(
                limitation,
                label="guide limitation",
                maximum=1024,
            )
        if type(self.steps) is not tuple:
            raise TypeError("guide steps must be a tuple")
        if not self.steps:
            raise ValueError("guides must include at least one step")
        if any(type(step) is not GuideStep for step in self.steps):
            raise TypeError("guide steps must contain exact GuideStep instances")
        for step in self.steps:
            step.__post_init__()
        step_ids = tuple(step.step_id for step in self.steps)
        if len(set(step_ids)) != len(step_ids):
            raise ValueError("guide step ids must be unique")
        if not any(step.kind == GuideStepKind.STOP_CONDITION for step in self.steps):
            raise ValueError("guides must include a data-protection stop condition")

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        key = (self.platform.lower(), self.branch.lower())
        _validate_registered_guide(key, self)
        serialized = serialize_structured(self)
        assert isinstance(serialized, dict)
        return serialized


def guide_for(platform: str, branch: str) -> RescueGuide:
    """Return one exact reviewed branch; there is no ambiguous generic fallback."""

    key = (platform.strip().lower(), branch.strip().lower())
    try:
        guide = _GUIDES[key]
    except KeyError as exc:
        raise KeyError(f"unsupported rescue guide branch: {key[0]}/{key[1]}") from exc
    _validate_registered_guide(key, guide)
    return guide


def _step(
    step_id: str,
    title: str,
    instruction: str,
    *,
    kind: GuideStepKind = GuideStepKind.READ_ONLY_OBSERVATION,
    risk: RiskTier = RiskTier.GREEN,
    warning: str | None = None,
) -> GuideStep:
    return GuideStep(step_id, title, instruction, kind, risk, warning)


_DATA_STOP = _step(
    "rescue.stop.data_first",
    "Stop if the data may be at risk",
    "If storage disappears, reports hardware errors, asks for an unknown recovery key, or makes unusual mechanical sounds, stop. Do not repair, erase, unlock, or repeatedly restart it; preserve the current state and seek data-recovery help.",
    kind=GuideStepKind.STOP_CONDITION,
    risk=RiskTier.YELLOW,
    warning="Continuing can reduce the chance of recovering important data.",
)


def _mac_guide(branch: str, startup: str) -> RescueGuide:
    return RescueGuide(
        guide_id=f"rescue.macos.{branch}",
        platform="macOS",
        branch=branch,
        capability_label="Manual guide using Apple's built-in recovery and diagnostics",
        limitations=(
            "Lantern does not run inside every macOS Recovery version.",
            "This guide does not change startup security, NVRAM, FileVault, partitions, or disks.",
        ),
        steps=(
            _DATA_STOP,
            _step(
                f"rescue.macos.{branch}.recovery",
                "Open macOS Recovery",
                startup,
                kind=GuideStepKind.MANUAL_GUIDANCE,
            ),
            _step(
                f"rescue.macos.{branch}.inspect",
                "Inspect before changing anything",
                "In Recovery, confirm whether the internal storage and expected volumes are visible. Use Disk Utility's information view only; do not erase, partition, restore, or run repair from this step.",
            ),
            _step(
                f"rescue.macos.{branch}.diagnostics",
                "Use Apple Diagnostics separately",
                "Follow Apple's startup flow for Apple Diagnostics and record only the displayed reference code. Absence of a code does not prove every hardware component healthy.",
                kind=GuideStepKind.MANUAL_GUIDANCE,
            ),
        ),
    )


_GUIDES: dict[tuple[str, str], RescueGuide] = {
    (
        "macos",
        "apple_silicon",
    ): _mac_guide(
        "apple_silicon",
        "Shut down the Mac. Press and hold the power button until startup options appear, then choose Options. Keep the Mac connected to power.",
    ),
    (
        "macos",
        "intel",
    ): _mac_guide(
        "intel",
        "Shut down the Mac. Turn it on and immediately hold Command-R until Recovery appears. Keep the Mac connected to power.",
    ),
    (
        "windows",
        "winre",
    ): RescueGuide(
        guide_id="rescue.windows.winre",
        platform="Windows",
        branch="winre",
        capability_label="Manual guide using Windows Recovery Environment",
        limitations=(
            "No Microsoft recovery binaries are included.",
            "Lantern never captures a BitLocker recovery key or changes BCD, Secure Boot, partitions, or disks.",
        ),
        steps=(
            _DATA_STOP,
            _step(
                "rescue.windows.winre.open",
                "Use Windows Recovery Environment",
                "Open the computer's supported Windows Recovery Environment and begin with Startup Settings or the manufacturer's diagnostics. Avoid reset, reinstall, command-line repair, and disk changes during assessment.",
                kind=GuideStepKind.MANUAL_GUIDANCE,
            ),
            _step(
                "rescue.windows.winre.encryption",
                "Treat encryption as a boundary",
                "If Windows asks for a BitLocker recovery key, do not enter it into Lantern. Confirm key ownership through Microsoft's supported account or organizational process on a trusted device.",
                kind=GuideStepKind.STOP_CONDITION,
                risk=RiskTier.YELLOW,
                warning="Repeated guesses or untrusted key handling can expose data or delay recovery.",
            ),
            _step(
                "rescue.windows.winre.observe",
                "Record read-only observations",
                "Record whether firmware diagnostics complete, the internal drive is visible, Safe Mode is offered, and networking is available. Keep each result independent.",
            ),
        ),
    ),
    (
        "linux",
        "live_environment",
    ): RescueGuide(
        guide_id="rescue.linux.live_environment",
        platform="Linux",
        branch="live_environment",
        capability_label="Read-only assessment from an existing reputable live environment",
        limitations=(
            "Lantern does not provide or claim a signed boot image in this development build.",
            "Driver, Secure Boot, storage-controller, and architecture coverage are not universal.",
        ),
        steps=(
            _DATA_STOP,
            _step(
                "rescue.linux.live_environment.boot",
                "Use a trusted live environment",
                "Use a currently supported, reputable distribution image that boots without disabling Secure Boot when the computer supports it. Do not install it to the internal drive.",
                kind=GuideStepKind.MANUAL_GUIDANCE,
            ),
            _step(
                "rescue.linux.live_environment.read_only",
                "Keep storage read-only",
                "Inspect whether storage devices and filesystems are visible without mounting them read-write, replaying a journal, assembling unknown arrays, or running repair tools.",
            ),
            _step(
                "rescue.linux.live_environment.observe",
                "Evaluate each viability area",
                "Record device visibility, supported health information, operating-system boot evidence, encryption state, backup evidence, and recovery-environment network results separately.",
            ),
        ),
    ),
}


def _guide_signature(guide: RescueGuide) -> tuple[object, ...]:
    """Capture every byte of reviewed guide content in immutable values."""

    if type(guide) is not RescueGuide:
        raise TypeError("registered rescue guides must be exact RescueGuide instances")
    return (
        guide.guide_id,
        guide.platform,
        guide.branch,
        guide.capability_label,
        guide.limitations,
        tuple(
            (
                step.step_id,
                step.title,
                step.instruction,
                step.kind,
                step.risk,
                step.data_warning,
            )
            for step in guide.steps
        ),
    )


_GUIDE_SIGNATURES: dict[tuple[str, str], tuple[object, ...]] = {
    key: _guide_signature(guide) for key, guide in _GUIDES.items()
}


def _validate_registered_guide(key: tuple[str, str], guide: RescueGuide) -> None:
    registered = _GUIDES.get(key)
    expected = _GUIDE_SIGNATURES.get(key)
    if registered is not guide or expected is None:
        raise ValueError("only reviewed, registered rescue guide content can be exported")
    guide.__post_init__()
    if _guide_signature(guide) != expected:
        raise ValueError("reviewed rescue guide integrity check failed")
