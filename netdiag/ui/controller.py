"""Typed, read-only integration seam for the Lantern local application."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, TypeAlias, runtime_checkable

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | Mapping[str, "JsonValue"]


@runtime_checkable
class StatusProvider(Protocol):
    """Provide a JSON-safe, non-secret, read-only application snapshot."""

    def snapshot(self) -> Mapping[str, JsonValue]:
        """Return the current presentation snapshot without changing state."""
        ...


class ReadyStatusProvider:
    """Safe default used before the diagnostic application adapter is wired."""

    def snapshot(self) -> Mapping[str, JsonValue]:
        return {
            "product": "Lantern",
            "state": "ready",
            "transport": "loopback",
            "capabilities": ["read_only_status"],
        }
