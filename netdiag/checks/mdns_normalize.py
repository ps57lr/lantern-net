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

_SERVICE_TYPE_RE = re.compile(r"(_[\w-]+)\._(?:tcp|udp)$")


def normalize_mdns_type(raw_type: str) -> str:
    """Return a canonical `_service._tcp` or `_service._udp` type string."""
    cleaned = raw_type.strip().rstrip(".")
    if not cleaned:
        return cleaned

    match = _SERVICE_TYPE_RE.search(cleaned)
    if match:
        return match.group(0)

    base = cleaned.split(".")[0]
    if not base.startswith("_"):
        base = f"_{base.lstrip('_')}"

    if base in UDP_BASE_TYPES:
        return f"{base}._udp"
    return f"{base}._tcp"


def normalize_mdns_record(record: dict) -> dict:
    normalized = {"type": normalize_mdns_type(record.get("type", ""))}
    instance = record.get("instance")
    if instance:
        normalized["instance"] = instance
    return normalized


def dedupe_mdns_records(records: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        normalized = normalize_mdns_record(record)
        key = (normalized["type"], normalized.get("instance", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return sorted(unique, key=lambda item: (item["type"], item.get("instance", "")))
