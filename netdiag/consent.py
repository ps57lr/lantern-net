"""Short-lived, explicit diagnostic scope authorization.

Consent records contain choices and bounded scope only.  They never contain a
password, recovery key, administrator credential, or browser/session token.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from netdiag.core import ActivityLevel, ScanPolicy
from netdiag.core.values import validate_dotted_identifier, validate_nonempty_text


class DiagnosticGoal(str, Enum):
    PROBLEM = "problem"
    NETWORK = "network"
    RESCUE = "rescue"


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    """One immutable authorization for one diagnostic run."""

    consent_id: str
    scan_id: str
    goal: DiagnosticGoal
    activity: ActivityLevel
    issued_at: datetime
    expires_at: datetime
    interface: str | None = None
    network: str | None = None
    max_hosts: int = 256
    consent_version: str = "lantern.consent.v1"

    def __post_init__(self) -> None:
        validate_dotted_identifier(self.consent_id, label="consent id")
        validate_dotted_identifier(self.scan_id, label="scan id")
        validate_dotted_identifier(self.consent_version, label="consent version")
        if not isinstance(self.goal, DiagnosticGoal):
            raise TypeError("goal must be DiagnosticGoal")
        if not isinstance(self.activity, ActivityLevel):
            raise TypeError("activity must be ActivityLevel")
        for label, value in (("issued_at", self.issued_at), ("expires_at", self.expires_at)):
            if not isinstance(value, datetime):
                raise TypeError(f"{label} must be a datetime")
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{label} must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("consent expiry must be after issuance")
        if self.expires_at - self.issued_at > timedelta(hours=1):
            raise ValueError("consent cannot remain valid for more than one hour")
        if not isinstance(self.max_hosts, int) or isinstance(self.max_hosts, bool):
            raise TypeError("max_hosts must be an integer")
        if not 1 <= self.max_hosts <= 1024:
            raise ValueError("max_hosts must be from 1 to 1024")

        canonical_network = None
        if self.network is not None:
            if not isinstance(self.network, str):
                raise TypeError("consent network must be a string")
            try:
                parsed = ipaddress.ip_network(self.network, strict=True)
            except (TypeError, ValueError) as exc:
                raise ValueError("consent network must be an exact canonical network") from exc
            if not isinstance(parsed, ipaddress.IPv4Network):
                raise ValueError("active discovery currently supports scoped IPv4 only")
            if str(parsed) != self.network:
                raise ValueError("consent network must use canonical CIDR notation")
            if not _is_rfc1918(parsed) or parsed.is_loopback or parsed.is_link_local:
                raise ValueError("consent network must be an RFC1918 private network")
            canonical_network = str(parsed)
            object.__setattr__(self, "network", canonical_network)

        if self.interface is not None:
            if not isinstance(self.interface, str):
                raise TypeError("consent interface must be a string")
            validate_nonempty_text(self.interface, label="consent interface", maximum=64)
            if any(character.isspace() or ord(character) < 33 for character in self.interface):
                raise ValueError("consent interface contains unsafe characters")

        if self.activity == ActivityLevel.ACTIVE_DISCOVERY:
            if self.interface is None or canonical_network is None:
                raise ValueError(
                    "active discovery requires the exact interface and network shown to the user"
                )
            host_count = max(0, ipaddress.ip_network(canonical_network).num_addresses - 2)
            if host_count > self.max_hosts:
                raise ValueError("active discovery scope exceeds its authorized host limit")
        elif self.interface is not None or canonical_network is not None:
            raise ValueError("passive/basic consent must not silently retain active scope")

    def is_valid(self, *, now: datetime | None = None) -> bool:
        current = now if now is not None else datetime.now(timezone.utc)
        if not isinstance(current, datetime):
            raise TypeError("validation time must be a datetime")
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("validation time must include a timezone")
        return self.issued_at <= current < self.expires_at

    def to_scan_policy(self, *, now: datetime | None = None) -> ScanPolicy:
        if not self.is_valid(now=now):
            raise ConsentExpired("diagnostic consent is not currently valid")
        interfaces = (self.interface,) if self.interface is not None else ()
        networks = (self.network,) if self.network is not None else ()
        return ScanPolicy(
            maximum_activity=self.activity,
            allowed_interfaces=interfaces,
            allowed_networks=networks,
            max_hosts=self.max_hosts,
        )


class ConsentExpired(RuntimeError):
    pass


def issue_consent(
    *,
    consent_id: str,
    scan_id: str,
    goal: DiagnosticGoal,
    basic_network_checks: bool,
    active_interface: str | None = None,
    active_network: str | None = None,
    max_hosts: int = 256,
    ttl_seconds: float = 900,
    now: datetime | None = None,
) -> ConsentRecord:
    """Issue passive/basic consent or a separately scoped active approval."""

    if not isinstance(basic_network_checks, bool):
        raise TypeError("basic_network_checks must be a boolean")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, (int, float))
        or not math.isfinite(ttl_seconds)
        or ttl_seconds <= 0
        or ttl_seconds > 3600
    ):
        raise ValueError("consent ttl must be greater than 0 and at most one hour")
    issued = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(issued, datetime):
        raise TypeError("consent issuance time must be a datetime")
    if active_interface is not None or active_network is not None:
        activity = ActivityLevel.ACTIVE_DISCOVERY
    elif basic_network_checks:
        activity = ActivityLevel.LOW_IMPACT_NETWORK
    else:
        activity = ActivityLevel.PASSIVE
    return ConsentRecord(
        consent_id=consent_id,
        scan_id=scan_id,
        goal=goal,
        activity=activity,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=ttl_seconds),
        interface=active_interface,
        network=active_network,
        max_hosts=max_hosts,
    )


def _is_rfc1918(network: ipaddress.IPv4Network) -> bool:
    private_blocks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return any(network.subnet_of(block) for block in private_blocks)
