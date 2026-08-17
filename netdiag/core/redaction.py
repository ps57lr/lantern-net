"""Structural serialization and sensitivity-aware redaction.

Redaction is applied to typed values, dataclass field metadata, or explicit
structural paths. It never searches or replaces substrings in rendered text.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum

from netdiag.core.status import Sensitivity
from netdiag.core.values import DiagnosticValue, JsonValue, validate_json_value


class RedactionAction(str, Enum):
    KEEP = "keep"
    TOKENIZE = "tokenize"
    REDACT = "redact"


@dataclass(frozen=True)
class RedactionPolicy:
    """Action to take for each sensitivity class."""

    public: RedactionAction = RedactionAction.KEEP
    network_address: RedactionAction = RedactionAction.KEEP
    device_identifier: RedactionAction = RedactionAction.KEEP
    user_identifier: RedactionAction = RedactionAction.KEEP
    potential_secret: RedactionAction = RedactionAction.REDACT

    def __post_init__(self) -> None:
        if any(
            not isinstance(action, RedactionAction)
            for action in (
                self.public,
                self.network_address,
                self.device_identifier,
                self.user_identifier,
                self.potential_secret,
            )
        ):
            raise TypeError("redaction policy values must be RedactionAction members")

    @classmethod
    def raw(cls) -> RedactionPolicy:
        """Preserve identifiers but still refuse to emit potential secrets."""

        return cls()

    @classmethod
    def share_safe(cls) -> RedactionPolicy:
        """Keep diagnostic addresses while tokenizing device/user identifiers."""

        return cls(
            device_identifier=RedactionAction.TOKENIZE,
            user_identifier=RedactionAction.TOKENIZE,
        )

    @classmethod
    def strict(cls) -> RedactionPolicy:
        """Also tokenize network addresses."""

        return cls(
            network_address=RedactionAction.TOKENIZE,
            device_identifier=RedactionAction.TOKENIZE,
            user_identifier=RedactionAction.TOKENIZE,
        )

    def action_for(self, sensitivity: Sensitivity) -> RedactionAction:
        return {
            Sensitivity.PUBLIC: self.public,
            Sensitivity.NETWORK_ADDRESS: self.network_address,
            Sensitivity.DEVICE_IDENTIFIER: self.device_identifier,
            Sensitivity.USER_IDENTIFIER: self.user_identifier,
            Sensitivity.POTENTIAL_SECRET: self.potential_secret,
        }[sensitivity]


@dataclass(frozen=True)
class SensitivityRule:
    """A structural path rule; ``*`` matches exactly one segment."""

    path: tuple[str, ...]
    sensitivity: Sensitivity

    def __post_init__(self) -> None:
        if not isinstance(self.path, tuple) or any(
            not isinstance(segment, str) for segment in self.path
        ):
            raise ValueError("sensitivity rule path must contain string segments")
        if not isinstance(self.sensitivity, Sensitivity):
            raise TypeError("rule sensitivity must be a Sensitivity")


class StructuralSensitivityMap:
    """Exact/wildcard rules used while legacy dictionaries are migrated."""

    def __init__(
        self,
        rules: tuple[SensitivityRule, ...] = (),
        *,
        default_leaf_sensitivity: Sensitivity = Sensitivity.PUBLIC,
    ) -> None:
        if not isinstance(rules, tuple) or any(
            not isinstance(rule, SensitivityRule) for rule in rules
        ):
            raise TypeError("rules must be a tuple of SensitivityRule instances")
        if not isinstance(default_leaf_sensitivity, Sensitivity):
            raise TypeError("default_leaf_sensitivity must be a Sensitivity")
        paths: set[tuple[str, ...]] = set()
        for rule in rules:
            if rule.path in paths:
                raise ValueError(f"duplicate sensitivity path: {rule.path!r}")
            paths.add(rule.path)
        self._rules = rules
        self.default_leaf_sensitivity = default_leaf_sensitivity

    @classmethod
    def from_json_pointers(
        cls,
        mapping: Mapping[str, Sensitivity],
        *,
        default_leaf_sensitivity: Sensitivity = Sensitivity.PUBLIC,
    ) -> StructuralSensitivityMap:
        rules = tuple(
            SensitivityRule(_parse_json_pointer(pointer), sensitivity)
            for pointer, sensitivity in mapping.items()
        )
        return cls(rules, default_leaf_sensitivity=default_leaf_sensitivity)

    def classify(self, path: tuple[str, ...], *, is_leaf: bool) -> Sensitivity:
        candidates: list[tuple[int, int, Sensitivity]] = []
        for index, rule in enumerate(self._rules):
            if len(rule.path) != len(path):
                continue
            if all(
                expected == "*" or expected == actual for expected, actual in zip(rule.path, path)
            ):
                wildcards = sum(segment == "*" for segment in rule.path)
                candidates.append((wildcards, index, rule.sensitivity))
        if candidates:
            # The most specific rule wins; declaration order breaks equal-specificity ties.
            return min(candidates, key=lambda item: (item[0], item[1]))[2]
        return self.default_leaf_sensitivity if is_leaf else Sensitivity.PUBLIC

    def declares_key(self, parent_path: tuple[str, ...], key: str) -> bool:
        """Return whether an exact schema segment declares this object key.

        Wildcards may match already-established ancestor segments (for example a
        list index), but a wildcard in the key's own position does not authorize
        arbitrary dictionary keys. Exporters must expand legitimate dynamic-key
        containers to exact paths after validating those keys.
        """

        depth = len(parent_path)
        for rule in self._rules:
            if len(rule.path) <= depth or rule.path[depth] != key:
                continue
            if all(
                expected == "*" or expected == actual
                for expected, actual in zip(rule.path[:depth], parent_path)
            ):
                return True
        return False


class StructuralSerializationError(ValueError):
    """Raised for cycles, unsupported values, or unsafe timestamps."""


class _SerializationSession:
    def __init__(
        self,
        policy: RedactionPolicy,
        sensitivity_map: StructuralSensitivityMap,
        max_depth: int,
    ) -> None:
        self.policy = policy
        self.sensitivity_map = sensitivity_map
        self.max_depth = max_depth
        self.active: set[int] = set()
        self.tokens: dict[tuple[Sensitivity, str], str] = {}
        self.token_counts: dict[Sensitivity, int] = {}
        self.key_token_count = 0

    def visit(
        self,
        value: object,
        *,
        path: tuple[str, ...],
        depth: int,
        forced_sensitivity: Sensitivity | None = None,
    ) -> JsonValue:
        if depth > self.max_depth:
            raise StructuralSerializationError(
                f"{_display_path(path)}: maximum depth {self.max_depth} exceeded"
            )

        if isinstance(value, DiagnosticValue):
            forced_sensitivity = value.sensitivity
            value = value.value

        is_leaf = value is None or isinstance(value, (str, bool, int, float, Enum, datetime))
        sensitivity = forced_sensitivity or self.sensitivity_map.classify(path, is_leaf=is_leaf)
        action = self.policy.action_for(sensitivity)
        if action == RedactionAction.REDACT:
            return "<redacted>"
        if action == RedactionAction.TOKENIZE:
            return self._token(sensitivity, value)

        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise StructuralSerializationError(
                    f"{_display_path(path)}: non-finite floats are not valid JSON"
                )
            return value
        if isinstance(value, datetime):
            if value.tzinfo is None or value.utcoffset() is None:
                raise StructuralSerializationError(
                    f"{_display_path(path)}: datetime must include a timezone"
                )
            return value.isoformat()
        if isinstance(value, Enum):
            return self.visit(value.value, path=path, depth=depth + 1)
        if is_dataclass(value) and not isinstance(value, type):
            return self._dataclass(value, path=path, depth=depth)
        if isinstance(value, dict):
            return self._dict(value, path=path, depth=depth)
        if isinstance(value, (list, tuple)):
            return self._sequence(value, path=path, depth=depth)
        raise StructuralSerializationError(
            f"{_display_path(path)}: unsupported type {type(value).__name__}"
        )

    def _dataclass(self, value: object, *, path: tuple[str, ...], depth: int) -> JsonValue:
        identity = id(value)
        self._enter(identity, path)
        try:
            result: dict[str, JsonValue] = {}
            for model_field in fields(value):
                child = getattr(value, model_field.name)
                metadata_sensitivity = model_field.metadata.get("sensitivity")
                if metadata_sensitivity is not None and not isinstance(
                    metadata_sensitivity, Sensitivity
                ):
                    try:
                        metadata_sensitivity = Sensitivity(metadata_sensitivity)
                    except (TypeError, ValueError) as exc:
                        raise StructuralSerializationError(
                            f"{_display_path(path + (model_field.name,))}: invalid sensitivity metadata"
                        ) from exc
                result[model_field.name] = self.visit(
                    child,
                    path=path + (model_field.name,),
                    depth=depth + 1,
                    forced_sensitivity=metadata_sensitivity,
                )
            return result
        finally:
            self.active.remove(identity)

    def _dict(self, value: dict[object, object], *, path: tuple[str, ...], depth: int) -> JsonValue:
        identity = id(value)
        self._enter(identity, path)
        try:
            result: dict[str, JsonValue] = {}
            reserved = {key for key in value if isinstance(key, str)}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise StructuralSerializationError(
                        f"{_display_path(path)}: object keys must be strings"
                    )
                output_key = key
                default_action = self.policy.action_for(
                    self.sensitivity_map.default_leaf_sensitivity
                )
                if default_action != RedactionAction.KEEP and not self.sensitivity_map.declares_key(
                    path, key
                ):
                    output_key = self._next_key_token(reserved | set(result))
                if output_key in result:
                    raise StructuralSerializationError(
                        f"{_display_path(path)}: object key collision after redaction"
                    )
                result[output_key] = self.visit(
                    child,
                    path=path + (key,),
                    depth=depth + 1,
                )
            return result
        finally:
            self.active.remove(identity)

    def _sequence(
        self, value: list[object] | tuple[object, ...], *, path: tuple[str, ...], depth: int
    ) -> JsonValue:
        identity = id(value)
        self._enter(identity, path)
        try:
            return [
                self.visit(child, path=path + (str(index),), depth=depth + 1)
                for index, child in enumerate(value)
            ]
        finally:
            self.active.remove(identity)

    def _enter(self, identity: int, path: tuple[str, ...]) -> None:
        if identity in self.active:
            raise StructuralSerializationError(f"{_display_path(path)}: cyclic value")
        self.active.add(identity)

    def _token(self, sensitivity: Sensitivity, value: object) -> str:
        raw_value = serialize_structured(
            value,
            policy=RedactionPolicy(
                potential_secret=RedactionAction.KEEP,
            ),
            sensitivity_map=StructuralSensitivityMap(),
            max_depth=self.max_depth,
        )
        canonical = json.dumps(raw_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        key = (sensitivity, canonical)
        if key not in self.tokens:
            number = self.token_counts.get(sensitivity, 0) + 1
            self.token_counts[sensitivity] = number
            label = {
                Sensitivity.NETWORK_ADDRESS: "network",
                Sensitivity.DEVICE_IDENTIFIER: "device",
                Sensitivity.USER_IDENTIFIER: "user",
                Sensitivity.POTENTIAL_SECRET: "secret",
                Sensitivity.PUBLIC: "value",
            }[sensitivity]
            self.tokens[key] = f"<{label}-{number}>"
        return self.tokens[key]

    def _next_key_token(self, reserved: set[str]) -> str:
        while True:
            self.key_token_count += 1
            candidate = f"<field-{self.key_token_count}>"
            if candidate not in reserved:
                return candidate


def serialize_structured(
    value: object,
    *,
    policy: RedactionPolicy | None = None,
    sensitivity_map: StructuralSensitivityMap | None = None,
    max_depth: int = 64,
) -> JsonValue:
    """Serialize supported values and apply redaction by structure/classification."""

    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    session = _SerializationSession(
        policy or RedactionPolicy.raw(),
        sensitivity_map or StructuralSensitivityMap(),
        max_depth,
    )
    result = session.visit(value, path=(), depth=0)
    validate_json_value(result, max_depth=max_depth + 1)
    return result


def _parse_json_pointer(pointer: str) -> tuple[str, ...]:
    if not isinstance(pointer, str):
        raise TypeError("JSON pointer must be a string")
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'")
    if re.search(r"~(?![01])", pointer):
        raise ValueError("JSON pointer contains an invalid '~' escape")
    return tuple(
        segment.replace("~1", "/").replace("~0", "~") for segment in pointer[1:].split("/")
    )


def _display_path(path: tuple[str, ...]) -> str:
    if not path:
        return "$"
    return "$" + "".join(f"[{segment!r}]" for segment in path)
