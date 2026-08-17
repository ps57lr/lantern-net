"""JSON-safe value primitives and validation."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Generic, TypeAlias, TypeVar, cast

from netdiag.core.status import Sensitivity

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

ValueT = TypeVar("ValueT", bound=JsonValue)

_DOTTED_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_FINDING_CODE_RE = re.compile(r"^NDG(?:\.[A-Z][A-Z0-9_]*){2,}$")
_PLATFORM_RELEASE_RE = re.compile(r"^[0-9][A-Za-z0-9._+-]{0,127}$")
_PLATFORM_SYSTEMS = frozenset({"Darwin", "macOS", "Linux", "Windows"})
_PLATFORM_MACHINES = frozenset(
    {
        "AMD64",
        "aarch64",
        "amd64",
        "arm64",
        "armv7l",
        "armv8l",
        "i386",
        "i686",
        "ppc64le",
        "riscv64",
        "s390x",
        "universal2",
        "x86_64",
    }
)


class JsonValidationError(ValueError):
    """Raised when a value cannot be represented faithfully as JSON."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


def validate_json_value(value: object, *, max_depth: int = 64) -> JsonValue:
    """Validate without coercion and return ``value`` with a JSON-safe type.

    Tuples, sets, bytes, non-string mapping keys, non-finite floats, cycles,
    and arbitrary objects are rejected. Shared acyclic substructures are valid.
    """

    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")

    active: set[int] = set()

    def visit(item: object, path: str, depth: int) -> None:
        if depth > max_depth:
            raise JsonValidationError(path, f"maximum depth {max_depth} exceeded")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise JsonValidationError(path, "non-finite floats are not valid JSON")
            return
        if isinstance(item, list):
            identity = id(item)
            if identity in active:
                raise JsonValidationError(path, "cyclic list")
            active.add(identity)
            try:
                for index, child in enumerate(item):
                    visit(child, f"{path}[{index}]", depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(item, dict):
            identity = id(item)
            if identity in active:
                raise JsonValidationError(path, "cyclic object")
            active.add(identity)
            try:
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise JsonValidationError(path, "object keys must be strings")
                    visit(child, _join_path(path, key), depth + 1)
            finally:
                active.remove(identity)
            return
        raise JsonValidationError(path, f"unsupported type {type(item).__name__}")

    visit(value, "$", 0)
    return cast(JsonValue, value)


def validate_dotted_identifier(value: str, *, label: str = "identifier") -> str:
    """Return a validated lower-case dotted identifier."""

    if not isinstance(value, str) or not _DOTTED_ID_RE.fullmatch(value):
        raise ValueError(
            f"{label} must be a lower-case dotted identifier using letters, digits, '_', or '-'"
        )
    if len(value) > 160:
        raise ValueError(f"{label} must be no longer than 160 characters")
    return value


def validate_finding_code(value: str) -> str:
    """Return a validated stable finding code."""

    if not isinstance(value, str) or not _FINDING_CODE_RE.fullmatch(value):
        raise ValueError("finding code must match NDG.DOMAIN.CONDITION")
    if len(value) > 160:
        raise ValueError("finding code must be no longer than 160 characters")
    return value


def validate_nonempty_text(value: str, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{label} must be no longer than {maximum} characters")
    return value


def validate_platform_system(value: str, *, label: str = "platform system") -> str:
    if value not in _PLATFORM_SYSTEMS:
        raise ValueError(f"{label} is not a supported canonical platform name")
    return value


def validate_platform_identity(system: str, release: str, machine: str) -> None:
    """Validate platform metadata before it is eligible for public export."""

    validate_platform_system(system)
    if release != "test" and (
        not isinstance(release, str) or _PLATFORM_RELEASE_RE.fullmatch(release) is None
    ):
        raise ValueError("platform release must be a bounded canonical version")
    if machine not in _PLATFORM_MACHINES:
        raise ValueError("platform machine is not a supported canonical architecture")


@dataclass(frozen=True)
class DiagnosticValue(Generic[ValueT]):
    """A JSON value carrying an explicit sensitivity classification."""

    value: ValueT
    sensitivity: Sensitivity = Sensitivity.PUBLIC

    def __post_init__(self) -> None:
        if not isinstance(self.sensitivity, Sensitivity):
            raise TypeError("sensitivity must be a Sensitivity")
        validate_json_value(self.value)


def _join_path(parent: str, key: str) -> str:
    if key.isidentifier():
        return f"{parent}.{key}"
    escaped = key.replace("\\", "\\\\").replace("'", "\\'")
    return f"{parent}['{escaped}']"
