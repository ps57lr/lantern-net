"""Transport-neutral, unknown-preserving rescue viability models.

Rescue deliberately reports five independent axes.  A booting operating system
does not prove healthy hardware, disk visibility does not prove recoverable data,
and a network result never masks storage or encryption blockers.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from netdiag.core import (
    Confidence,
    ConfidenceLevel,
    JsonValue,
    OutcomeStatus,
    PlatformInfo,
    RedactionPolicy,
    Sensitivity,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.values import (
    validate_dotted_identifier,
    validate_nonempty_text,
    validate_platform_identity,
)

_ASSESSMENT_ID_KEY = secrets.token_bytes(32)
_ASSESSMENT_ID_RE = re.compile(r"^rescue-assessment-[0-9a-f]{32}$")


def _seal_assessment_id(assessment_id: str) -> bytes:
    return hmac.new(
        _ASSESSMENT_ID_KEY,
        assessment_id.encode("ascii"),
        hashlib.sha256,
    ).digest()


def _new_assessment_identity() -> tuple[str, bytes]:
    """Mint one construction-only identity and its inseparable binding."""

    assessment_id = f"rescue-assessment-{secrets.token_hex(16)}"
    return assessment_id, _seal_assessment_id(assessment_id)


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class RescueAxis(_StringEnum):
    HARDWARE = "hardware"
    STORAGE_FILESYSTEM = "storage_filesystem"
    OPERATING_SYSTEM = "operating_system"
    DATA_RECOVERABILITY = "data_recoverability"
    NETWORK = "network"


class DataSafetyImpact(_StringEnum):
    NONE = "none"
    CAUTION = "caution"
    STOP = "stop"


class RescueContext(_StringEnum):
    NORMAL_OS = "normal_os"
    MACOS_RECOVERY = "macos_recovery"
    WINDOWS_RECOVERY = "windows_recovery"
    LINUX_LIVE = "linux_live"
    COMPANION_DEVICE = "companion_device"


@dataclass(frozen=True, slots=True)
class AxisObservation:
    """One read-only observation that contributes to one rescue axis."""

    evidence_ref: str
    status: OutcomeStatus
    confidence: ConfidenceLevel
    summary: str

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.evidence_ref, label="rescue evidence reference")
        if not isinstance(self.status, OutcomeStatus):
            raise TypeError("observation status must be OutcomeStatus")
        if not isinstance(self.confidence, ConfidenceLevel):
            raise TypeError("observation confidence must be ConfidenceLevel")
        validate_nonempty_text(self.summary, label="observation summary", maximum=512)


@dataclass(frozen=True, slots=True)
class AxisAssessment:
    """A conclusion about exactly one independent viability axis."""

    axis: RescueAxis
    status: OutcomeStatus
    confidence: Confidence
    evidence_refs: tuple[str, ...]
    blockers: tuple[str, ...]
    data_safety_impact: DataSafetyImpact
    safest_next_action: str

    def __post_init__(self) -> None:
        if not isinstance(self.axis, RescueAxis):
            raise TypeError("axis must be RescueAxis")
        if not isinstance(self.status, OutcomeStatus):
            raise TypeError("axis status must be OutcomeStatus")
        if not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be Confidence")
        if not isinstance(self.data_safety_impact, DataSafetyImpact):
            raise TypeError("data_safety_impact must be DataSafetyImpact")
        _validate_unique_text(self.evidence_refs, "evidence_refs", dotted=True)
        _validate_unique_text(self.blockers, "blockers")
        validate_nonempty_text(
            self.safest_next_action,
            label="safest next action",
            maximum=1024,
        )
        if self.status == OutcomeStatus.HEALTHY and not self.evidence_refs:
            raise ValueError("healthy rescue axes require supporting evidence")
        if self.data_safety_impact == DataSafetyImpact.STOP and not self.blockers:
            raise ValueError("a stop-level assessment requires a blocker")

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        self.confidence.__post_init__()
        serialized = serialize_structured(
            self,
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_AXIS_EXPORT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized


@dataclass(frozen=True, slots=True)
class RescueAssessment:
    """A complete read-only assessment containing every rescue axis once."""

    platform: PlatformInfo
    context: RescueContext
    observed_at: datetime
    axes: tuple[AxisAssessment, ...]
    readiness: OutcomeStatus
    readiness_summary: str
    _assessment_identity: tuple[str, bytes] = field(
        init=False,
        repr=False,
        compare=False,
        default_factory=_new_assessment_identity,
    )

    def __post_init__(self) -> None:
        self._validate_assessment_id_binding()
        if type(self.platform) is not PlatformInfo:
            raise TypeError("platform must be PlatformInfo")
        self.platform.__post_init__()
        if not isinstance(self.context, RescueContext):
            raise TypeError("context must be RescueContext")
        if not isinstance(self.observed_at, datetime):
            raise TypeError("observed_at must be a datetime")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if not isinstance(self.readiness, OutcomeStatus):
            raise TypeError("readiness must be OutcomeStatus")
        validate_nonempty_text(
            self.readiness_summary,
            label="readiness summary",
            maximum=1024,
        )
        if type(self.axes) is not tuple or any(
            type(assessment) is not AxisAssessment for assessment in self.axes
        ):
            raise TypeError("axes must be a tuple of AxisAssessment instances")
        for assessment in self.axes:
            assessment.__post_init__()
            assessment.confidence.__post_init__()
        required = set(RescueAxis)
        supplied = {assessment.axis for assessment in self.axes}
        if len(self.axes) != len(required) or supplied != required:
            raise ValueError("a rescue assessment must contain every rescue axis exactly once")

    def _validate_assessment_id_binding(self) -> None:
        identity = self._assessment_identity
        if not isinstance(identity, tuple) or len(identity) != 2:
            raise ValueError("assessment identity is not a generated opaque binding")
        assessment_id, seal = identity
        if not isinstance(assessment_id, str) or _ASSESSMENT_ID_RE.fullmatch(assessment_id) is None:
            raise ValueError("assessment id must be a generated opaque identifier")
        if not isinstance(seal, bytes) or not hmac.compare_digest(
            seal,
            _seal_assessment_id(assessment_id),
        ):
            raise ValueError("assessment id is not bound to this generated assessment")

    @property
    def assessment_id(self) -> str:
        """Read-only correlation handle for this generated assessment."""

        self._validate_assessment_id_binding()
        return self._assessment_identity[0]

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        for axis in self.axes:
            axis.__post_init__()
            axis.confidence.__post_init__()
        if type(self.platform) is not PlatformInfo:
            raise TypeError("platform must be PlatformInfo")
        self.platform.__post_init__()
        validate_platform_identity(
            self.platform.system,
            self.platform.release,
            self.platform.machine,
        )
        # Serialize an explicit public projection so the private generation
        # binding is never part of the output schema, even as a redacted key.
        serialized = serialize_structured(
            {
                "assessment_id": self.assessment_id,
                "platform": self.platform,
                "context": self.context,
                "observed_at": self.observed_at,
                "axes": self.axes,
                "readiness": self.readiness,
                "readiness_summary": self.readiness_summary,
            },
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_ASSESSMENT_EXPORT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized


def _validate_unique_text(values: tuple[str, ...], label: str, *, dotted: bool = False) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")
    for value in values:
        if dotted:
            validate_dotted_identifier(value, label=label)
        else:
            validate_nonempty_text(value, label=label, maximum=512)


_AXIS_EXPORT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/axis": Sensitivity.PUBLIC,
        "/status": Sensitivity.PUBLIC,
        "/confidence/level": Sensitivity.PUBLIC,
        "/confidence/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/data_safety_impact": Sensitivity.PUBLIC,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)

_ASSESSMENT_EXPORT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/assessment_id": Sensitivity.PUBLIC,
        "/platform/system": Sensitivity.PUBLIC,
        "/platform/release": Sensitivity.PUBLIC,
        "/platform/machine": Sensitivity.PUBLIC,
        "/context": Sensitivity.PUBLIC,
        "/observed_at": Sensitivity.PUBLIC,
        "/axes/*/axis": Sensitivity.PUBLIC,
        "/axes/*/status": Sensitivity.PUBLIC,
        "/axes/*/confidence/level": Sensitivity.PUBLIC,
        "/axes/*/confidence/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/axes/*/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
        "/axes/*/data_safety_impact": Sensitivity.PUBLIC,
        "/readiness": Sensitivity.PUBLIC,
        "/readiness_summary": Sensitivity.POTENTIAL_SECRET,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)
