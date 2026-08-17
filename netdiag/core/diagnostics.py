"""Small diagnosis-domain value objects shared by finding implementations."""

from __future__ import annotations

from dataclasses import dataclass

from netdiag.core.redaction import (
    RedactionPolicy,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.status import ConfidenceLevel, Sensitivity
from netdiag.core.values import JsonValue, validate_dotted_identifier, validate_nonempty_text


@dataclass(frozen=True)
class Confidence:
    """Qualitative confidence with an evidence-backed rationale."""

    level: ConfidenceLevel
    rationale: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.level, ConfidenceLevel):
            raise TypeError("confidence level must be a ConfidenceLevel")
        validate_nonempty_text(self.rationale, label="confidence rationale", maximum=1024)
        if not isinstance(self.evidence_refs, tuple):
            raise TypeError("confidence evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            validate_dotted_identifier(ref, label="confidence evidence reference")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("confidence evidence_refs must be unique")

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        serialized = serialize_structured(
            self,
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_CONFIDENCE_EXPORT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized


_CONFIDENCE_EXPORT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/level": Sensitivity.PUBLIC,
        "/evidence_refs/*": Sensitivity.POTENTIAL_SECRET,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)
