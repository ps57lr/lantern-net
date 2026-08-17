"""Strict value validation for the inert assessment design package."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TypeVar

_REFERENCE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_REFERENCE_FORBIDDEN_PARTS = frozenset(
    {
        "apikey",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "recoverykey",
        "secret",
        "token",
    }
)
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PRIVATE_BLOCKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

EnumT = TypeVar("EnumT", bound=Enum)


def require_exact_bool(value: object, *, label: str, required: bool | None = None) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{label} must be a boolean")
    if required is not None and value is not required:
        raise ValueError(f"{label} must be {str(required).lower()}")
    return value


def require_bounded_int(
    value: object,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be from {minimum} to {maximum}")
    return value


def require_reference(value: object, *, label: str, prefix: str | None = None) -> str:
    """Validate an opaque reference, never a display name, email, or secret."""

    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    if not 3 <= len(value) <= 80 or not value.isascii() or _REFERENCE_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be an opaque lowercase ASCII reference")
    if prefix is not None and not value.startswith(f"{prefix}."):
        raise ValueError(f"{label} must use the {prefix}. reference namespace")
    collapsed = value.replace("-", "").replace(".", "")
    if any(forbidden in collapsed for forbidden in _REFERENCE_FORBIDDEN_PARTS):
        raise ValueError(f"{label} must not contain secret or credential material")
    return value


def require_tuple(value: object, *, label: str, maximum: int, allow_empty: bool = True) -> tuple:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{label} cannot contain more than {maximum} entries")
    return value


def require_sorted_unique(values: tuple, *, label: str, key=None) -> None:
    comparison = tuple(sorted(values, key=key))
    if values != comparison:
        raise ValueError(f"{label} must use canonical sorted order")
    try:
        if len(set(values)) != len(values):
            raise ValueError(f"{label} must contain unique entries")
    except TypeError as exc:
        raise TypeError(f"{label} entries must be immutable values") from exc


def require_enum(value: object, enum_type: type[EnumT], *, label: str) -> EnumT:
    if type(value) is not enum_type:
        raise TypeError(f"{label} must be {enum_type.__name__}")
    return value


def parse_enum(value: object, enum_type: type[EnumT], *, label: str) -> EnumT:
    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not an allowed value") from exc


def require_utc_second(value: object, *, label: str) -> datetime:
    if type(value) is not datetime:
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must use UTC")
    if value.microsecond != 0:
        raise ValueError(f"{label} must use whole-second precision")
    return value


def format_utc_second(value: datetime) -> str:
    require_utc_second(value, label="timestamp")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_second(value: object, *, label: str) -> datetime:
    if type(value) is not str or _TIME_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must use canonical YYYY-MM-DDTHH:MM:SSZ form")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid UTC timestamp") from exc


def require_private_network(value: object, *, label: str) -> str:
    if type(value) is not str or not value.isascii():
        raise TypeError(f"{label} must be an ASCII string")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an exact canonical IPv4 network") from exc
    if type(network) is not ipaddress.IPv4Network or str(network) != value:
        raise ValueError(f"{label} must be an exact canonical IPv4 network")
    if not any(network.subnet_of(block) for block in _PRIVATE_BLOCKS):
        raise ValueError(f"{label} must be a directly managed RFC1918 private network")
    if network.num_addresses > 4096:
        raise ValueError(f"{label} is broader than this design foundation permits")
    return value


def require_private_host(value: object, *, label: str) -> str:
    if type(value) is not str or not value.isascii():
        raise TypeError(f"{label} must be an ASCII string")
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a canonical IPv4 address") from exc
    if type(address) is not ipaddress.IPv4Address or str(address) != value:
        raise ValueError(f"{label} must be a canonical IPv4 address")
    if not any(address in block for block in _PRIVATE_BLOCKS):
        raise ValueError(f"{label} must be a directly managed RFC1918 private address")
    return value


def expect_exact_dict(value: object, *, label: str, keys: frozenset[str]) -> dict:
    if type(value) is not dict:
        raise TypeError(f"{label} must be an object")
    actual = frozenset(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if unknown:
            detail.append(f"unknown {unknown}")
        raise ValueError(f"{label} has invalid fields: {', '.join(detail)}")
    return value


def json_array_as_tuple(value: object, *, label: str, maximum: int) -> tuple:
    if type(value) is not list:
        raise TypeError(f"{label} must be a JSON array")
    if len(value) > maximum:
        raise ValueError(f"{label} cannot contain more than {maximum} entries")
    return tuple(value)
