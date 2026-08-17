"""Local permission and external-access prerequisite contracts.

These models describe access requirements only. They intentionally have no
field capable of storing a password, token, recovery key, or secret answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netdiag.core.redaction import (
    RedactionPolicy,
    StructuralSensitivityMap,
    serialize_structured,
)
from netdiag.core.status import Sensitivity
from netdiag.core.values import (
    JsonValue,
    validate_dotted_identifier,
    validate_nonempty_text,
    validate_platform_system,
)


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class PermissionState(_StringEnum):
    GRANTED = "granted"
    DENIED = "denied"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class AccessState(_StringEnum):
    REQUIRED = "required"
    CONFIRMED_AVAILABLE = "confirmed_available"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class PermissionRequirement:
    """A local operating-system capability required for a check or action."""

    permission_id: str
    kind: str
    platform: str
    scope: str
    state: PermissionState
    reason: str
    acquisition_hint: str = ""

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.permission_id, label="permission id")
        validate_dotted_identifier(self.kind, label="permission kind")
        validate_platform_system(self.platform, label="permission platform")
        validate_nonempty_text(self.scope, label="permission scope", maximum=512)
        if not isinstance(self.state, PermissionState):
            raise TypeError("permission state must be a PermissionState")
        validate_nonempty_text(self.reason, label="permission reason", maximum=1024)
        if len(self.acquisition_hint) > 2048:
            raise ValueError("acquisition_hint must be no longer than 2048 characters")

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        serialized = serialize_structured(
            self,
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_PERMISSION_EXPORT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized


@dataclass(frozen=True)
class AccessPrerequisite:
    """A declaration that outside access is needed, never the access value."""

    prerequisite_id: str
    kind: str
    label: str
    scope: str
    state: AccessState
    reason: str
    related_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.prerequisite_id, label="prerequisite id")
        validate_dotted_identifier(self.kind, label="prerequisite kind")
        validate_nonempty_text(self.label, label="prerequisite label", maximum=160)
        validate_nonempty_text(self.scope, label="prerequisite scope", maximum=512)
        if not isinstance(self.state, AccessState):
            raise TypeError("access state must be an AccessState")
        validate_nonempty_text(self.reason, label="prerequisite reason", maximum=1024)
        if not isinstance(self.related_refs, tuple):
            raise TypeError("related_refs must be a tuple")
        for ref in self.related_refs:
            validate_dotted_identifier(ref, label="access related reference")
        if len(set(self.related_refs)) != len(self.related_refs):
            raise ValueError("related_refs must be unique")

    def to_dict(self) -> dict[str, JsonValue]:
        self.__post_init__()
        serialized = serialize_structured(
            self,
            policy=RedactionPolicy.share_safe(),
            sensitivity_map=_ACCESS_EXPORT_MAP,
        )
        assert isinstance(serialized, dict)
        return serialized


_PERMISSION_EXPORT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/permission_id": Sensitivity.POTENTIAL_SECRET,
        "/kind": Sensitivity.POTENTIAL_SECRET,
        "/platform": Sensitivity.PUBLIC,
        "/state": Sensitivity.PUBLIC,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)

_ACCESS_EXPORT_MAP = StructuralSensitivityMap.from_json_pointers(
    {
        "/prerequisite_id": Sensitivity.POTENTIAL_SECRET,
        "/kind": Sensitivity.POTENTIAL_SECRET,
        "/state": Sensitivity.PUBLIC,
        "/related_refs/*": Sensitivity.POTENTIAL_SECRET,
    },
    default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
)
