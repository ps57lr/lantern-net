"""Normalize and deduplicate mDNS service records across platforms."""

from __future__ import annotations

import re

UDP_BASE_TYPES = {
    "_asquic",
    "_meshcop",
    "_sleep-proxy",
    "_trel",
    "_airdrop",
    "_rdlink",
}

_SERVICE_TYPE_RE = re.compile(r"^_([A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?)\._(tcp|udp)$")
_BARE_SERVICE_RE = re.compile(r"^_?([A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?)$")


def normalize_mdns_type(raw_type: str) -> str:
    """Return a strict canonical DNS-SD service type, or ``""`` if invalid.

    Service names follow the RFC 6335 shape: 1-15 ASCII letters/digits/hyphens,
    no leading/trailing or adjacent hyphens, and at least one ASCII letter.
    Substring extraction is deliberately forbidden because advertisements are
    controlled by LAN peers.
    """

    if not isinstance(raw_type, str) or len(raw_type) > 32:
        return ""
    cleaned = raw_type.strip().rstrip(".")
    if not cleaned:
        return ""

    match = _SERVICE_TYPE_RE.fullmatch(cleaned)
    if match:
        service, transport = match.groups()
        if "--" in service or not any(character.isalpha() for character in service):
            return ""
        return f"_{service.lower()}._{transport.lower()}"

    bare = _BARE_SERVICE_RE.fullmatch(cleaned)
    if bare is None:
        return ""
    service = bare.group(1)
    if "--" in service or not any(character.isalpha() for character in service):
        return ""
    base = f"_{service.lower()}"

    if base in UDP_BASE_TYPES:
        return f"{base}._udp"
    return f"{base}._tcp"


def normalize_mdns_record(record: dict) -> dict | None:
    normalized = {"type": normalize_mdns_type(record.get("type", ""))}
    if not normalized["type"]:
        return None
    instance = record.get("instance")
    if (
        isinstance(instance, str)
        and 0 < len(instance) <= 255
        and not any(ord(character) < 32 or ord(character) == 127 for character in instance)
    ):
        normalized["instance"] = instance
    return normalized


def dedupe_mdns_records(records: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        normalized = normalize_mdns_record(record)
        if normalized is None:
            continue
        key = (normalized["type"], normalized.get("instance", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return sorted(unique, key=lambda item: (item["type"], item.get("instance", "")))
