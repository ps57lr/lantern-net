"""Explicit, duplicate-rejecting registries for core definitions."""

from __future__ import annotations

import heapq
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Generic, TypeVar

from netdiag.core.evidence import Evidence
from netdiag.core.execution import CheckSpec
from netdiag.core.remediation import ActionSpec
from netdiag.core.status import Sensitivity
from netdiag.core.values import (
    validate_dotted_identifier,
    validate_finding_code,
    validate_nonempty_text,
)

ItemT = TypeVar("ItemT")


class DuplicateRegistrationError(ValueError):
    pass


class UnknownRegistrationError(KeyError):
    pass


class FrozenRegistryError(RuntimeError):
    pass


class RegistryValidationError(ValueError):
    pass


class ExplicitRegistry(Generic[ItemT]):
    """Small allowlist registry; never performs module or entry-point discovery."""

    def __init__(self, key: Callable[[ItemT], str]) -> None:
        self._key = key
        self._items: dict[str, ItemT] = {}
        self._frozen = False
        self._lock = RLock()

    @property
    def frozen(self) -> bool:
        with self._lock:
            return self._frozen

    def register(self, item: ItemT) -> ItemT:
        self.register_many((item,))
        return item

    def register_many(self, items: Iterable[ItemT]) -> None:
        """Atomically register a batch after checking every key."""

        batch = tuple(items)
        keyed: list[tuple[str, ItemT]] = []
        for item in batch:
            identifier = self._key(item)
            if not isinstance(identifier, str) or not identifier:
                raise RegistryValidationError("registry keys must be non-empty strings")
            keyed.append((identifier, item))
        identifiers = [identifier for identifier, _ in keyed]
        duplicate = _first_duplicate(identifiers)
        if duplicate is not None:
            raise DuplicateRegistrationError(f"duplicate identifier in batch: {duplicate}")
        with self._lock:
            if self._frozen:
                raise FrozenRegistryError("registry is frozen")
            conflict = next(
                (identifier for identifier in identifiers if identifier in self._items), None
            )
            if conflict is not None:
                raise DuplicateRegistrationError(f"duplicate identifier: {conflict}")
            self._items.update(keyed)

    def get(self, identifier: str) -> ItemT | None:
        with self._lock:
            return self._items.get(identifier)

    def require(self, identifier: str) -> ItemT:
        with self._lock:
            try:
                return self._items[identifier]
            except KeyError as exc:
                raise UnknownRegistrationError(identifier) from exc

    def freeze(self) -> ExplicitRegistry[ItemT]:
        with self._lock:
            if not self._frozen:
                self._validate_snapshot(tuple(self._items.values()))
                self._frozen = True
        return self

    def snapshot(self) -> tuple[ItemT, ...]:
        with self._lock:
            return tuple(self._items.values())

    def identifiers(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._items)

    def _validate_snapshot(self, items: tuple[ItemT, ...]) -> None:
        del items

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def __iter__(self) -> Iterator[ItemT]:
        return iter(self.snapshot())


@dataclass(frozen=True)
class EvidenceKindDefinition:
    kind: str
    payload_type: type[object]
    default_sensitivity: Sensitivity = Sensitivity.PUBLIC
    description: str = ""

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.kind, label="evidence kind")
        if not isinstance(self.payload_type, type):
            raise TypeError("payload_type must be a type")
        if not isinstance(self.default_sensitivity, Sensitivity):
            raise TypeError("default_sensitivity must be a Sensitivity")
        if self.description:
            validate_nonempty_text(self.description, label="evidence description", maximum=1024)


class DefinitionState(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"


@dataclass(frozen=True)
class FindingDefinition:
    code: str
    category: str
    title_template: str
    detail_template: str
    hint_template: str = ""
    documentation_url: str = ""
    state: DefinitionState = DefinitionState.ACTIVE
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        validate_finding_code(self.code)
        validate_dotted_identifier(self.category, label="finding category")
        if not isinstance(self.state, DefinitionState):
            raise TypeError("finding definition state must be a DefinitionState")
        validate_nonempty_text(self.title_template, label="title template", maximum=512)
        validate_nonempty_text(self.detail_template, label="detail template", maximum=2048)
        if len(self.hint_template) > 2048:
            raise ValueError("hint_template must be no longer than 2048 characters")
        if len(self.documentation_url) > 2048:
            raise ValueError("documentation_url must be no longer than 2048 characters")
        if self.superseded_by is not None:
            validate_finding_code(self.superseded_by)
            if self.state != DefinitionState.DEPRECATED:
                raise ValueError("only deprecated findings may specify superseded_by")
            if self.superseded_by == self.code:
                raise ValueError("a finding cannot supersede itself")


class EvidenceKindRegistry(ExplicitRegistry[EvidenceKindDefinition]):
    def __init__(self) -> None:
        super().__init__(lambda definition: definition.kind)

    def validate_evidence(self, evidence: Evidence[object]) -> None:
        definition = self.require(evidence.kind)
        if evidence.payload is not None and not isinstance(
            evidence.payload, definition.payload_type
        ):
            raise RegistryValidationError(
                f"{evidence.kind} expects {definition.payload_type.__name__}, "
                f"received {type(evidence.payload).__name__}"
            )
        if evidence.sensitivity not in {
            definition.default_sensitivity,
            Sensitivity.POTENTIAL_SECRET,
        }:
            raise RegistryValidationError(
                f"{evidence.kind} sensitivity {evidence.sensitivity.value} does not match "
                f"registered {definition.default_sensitivity.value}"
            )


class FindingRegistry(ExplicitRegistry[FindingDefinition]):
    def __init__(self) -> None:
        super().__init__(lambda definition: definition.code)
        # Frozen dataclasses still permit deliberate mutation through
        # ``object.__setattr__``.  Keep an independent, immutable snapshot of
        # every reviewed definition so a mutated template can never silently
        # become trusted registry content.
        self._definition_signatures: dict[str, tuple[object, ...]] = {}

    def get(self, identifier: str) -> FindingDefinition | None:
        with self._lock:
            self._assert_integrity_locked()
            return self._items.get(identifier)

    def require(self, identifier: str) -> FindingDefinition:
        with self._lock:
            self._assert_integrity_locked()
            try:
                return self._items[identifier]
            except KeyError as exc:
                raise UnknownRegistrationError(identifier) from exc

    def freeze(self) -> FindingRegistry:
        with self._lock:
            if not self._frozen:
                items = tuple(self._items.values())
                self._validate_snapshot(items)
                if any(
                    identifier != definition.code for identifier, definition in self._items.items()
                ):
                    raise RegistryValidationError(
                        "finding definition code changed after registration"
                    )
                self._definition_signatures = {
                    identifier: _finding_definition_signature(definition)
                    for identifier, definition in self._items.items()
                }
                self._frozen = True
            else:
                self._assert_integrity_locked()
        return self

    def snapshot(self) -> tuple[FindingDefinition, ...]:
        with self._lock:
            self._assert_integrity_locked()
            return tuple(self._items.values())

    def identifiers(self) -> tuple[str, ...]:
        with self._lock:
            self._assert_integrity_locked()
            return tuple(self._items)

    def _validate_snapshot(self, items: tuple[FindingDefinition, ...]) -> None:
        for item in items:
            _finding_definition_signature(item)
        definitions = {item.code: item for item in items}
        if len(definitions) != len(items):
            raise RegistryValidationError("finding definitions must have unique codes")
        for item in items:
            if item.superseded_by is not None and item.superseded_by not in definitions:
                raise RegistryValidationError(
                    f"{item.code} references unknown successor {item.superseded_by}"
                )
        for item in items:
            visited: set[str] = set()
            current = item
            while current.superseded_by is not None:
                if current.code in visited:
                    raise RegistryValidationError("finding supersession graph contains a cycle")
                visited.add(current.code)
                current = definitions[current.superseded_by]

    def _assert_integrity_locked(self) -> None:
        if not self._frozen:
            return
        if tuple(self._items) != tuple(self._definition_signatures):
            raise RegistryValidationError("frozen finding registry integrity check failed")
        for identifier, definition in self._items.items():
            if definition.code != identifier:
                raise RegistryValidationError("frozen finding registry integrity check failed")
            expected = self._definition_signatures.get(identifier)
            try:
                actual = _finding_definition_signature(definition)
            except (TypeError, ValueError) as exc:
                raise RegistryValidationError(
                    "frozen finding registry integrity check failed"
                ) from exc
            if expected != actual:
                raise RegistryValidationError("frozen finding registry integrity check failed")


def _finding_definition_signature(definition: FindingDefinition) -> tuple[object, ...]:
    """Return a complete immutable representation of reviewed finding content."""

    if type(definition) is not FindingDefinition:
        raise RegistryValidationError("finding registries require exact FindingDefinition values")
    definition.__post_init__()
    return (
        definition.code,
        definition.category,
        definition.title_template,
        definition.detail_template,
        definition.hint_template,
        definition.documentation_url,
        definition.state,
        definition.superseded_by,
    )


class CheckRegistry(ExplicitRegistry[CheckSpec]):
    def __init__(self) -> None:
        super().__init__(lambda check: check.check_id)

    def _validate_snapshot(self, items: tuple[CheckSpec, ...]) -> None:
        identifiers = {item.check_id for item in items}
        for check in items:
            missing = [
                dependency for dependency in check.dependencies if dependency not in identifiers
            ]
            if missing:
                raise RegistryValidationError(
                    f"{check.check_id} has unknown dependencies: {', '.join(missing)}"
                )
        _topological_order(items)

    def ordered(self) -> tuple[CheckSpec, ...]:
        items = self.snapshot()
        self._validate_snapshot(items)
        return _topological_order(items)


class ActionRegistry(ExplicitRegistry[ActionSpec]):
    def __init__(self) -> None:
        super().__init__(lambda action: action.action_id)


def _topological_order(items: tuple[CheckSpec, ...]) -> tuple[CheckSpec, ...]:
    by_id = {item.check_id: item for item in items}
    indegree = {item.check_id: len(item.dependencies) for item in items}
    dependents: dict[str, list[str]] = {identifier: [] for identifier in by_id}
    for item in items:
        for dependency in item.dependencies:
            if dependency not in by_id:
                raise RegistryValidationError(
                    f"{item.check_id} has unknown dependency {dependency}"
                )
            dependents[dependency].append(item.check_id)

    ready = [identifier for identifier, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    ordered: list[CheckSpec] = []
    while ready:
        identifier = heapq.heappop(ready)
        ordered.append(by_id[identifier])
        for dependent in sorted(dependents[identifier]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered) != len(items):
        blocked = sorted(identifier for identifier, degree in indegree.items() if degree > 0)
        raise RegistryValidationError(
            f"check dependency graph contains a cycle involving: {', '.join(blocked)}"
        )
    return tuple(ordered)


def _first_duplicate(values: list[str]) -> str | None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return value
        seen.add(value)
    return None
