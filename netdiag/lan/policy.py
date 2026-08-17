"""Fail-closed interface, target, and profile policy for Lantern LAN.

This module does not enumerate or bind interfaces.  Platform adapters may supply
observations, but only an exact RFC1918 IPv4 interface that passes this policy can
be selected.  IPv6 is deliberately unsupported by the prototype rather than
being accepted with ambiguous scope semantics.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Final


class InterfacePolicyError(ValueError):
    """Raised when an interface cannot be proven safe for a LAN listener."""


class SelectionReason(str, Enum):
    """Stable reason codes for rejected interface selections."""

    NOT_ACTIVE = "not_active"
    WILDCARD = "wildcard"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    PUBLIC = "public"
    IPV6_UNSUPPORTED = "ipv6_unsupported"
    VPN_OR_TUNNEL = "vpn_or_tunnel"
    BRIDGE_OR_VIRTUAL = "bridge_or_virtual"
    POINT_TO_POINT = "point_to_point"
    INVALID_PREFIX = "invalid_prefix"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not_found"
    OWNER_APPROVAL_REQUIRED = "owner_approval_required"


@dataclass(frozen=True, slots=True)
class InterfaceCandidate:
    """Platform-neutral observation about one configured interface address."""

    name: str
    address: str
    prefix_length: int
    is_up: bool
    is_default: bool = False
    is_point_to_point: bool = False
    is_vpn: bool = False
    is_bridge: bool = False
    is_virtual: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError("interface name must be a string")
        if not self.name or len(self.name) > 64 or any(ord(char) < 33 for char in self.name):
            raise ValueError("interface name must be 1-64 visible characters")
        if not isinstance(self.address, str):
            raise TypeError("interface address must be a string")
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError("interface address is invalid") from exc
        if str(parsed) != self.address:
            raise ValueError("interface address must be canonical")
        if not isinstance(self.prefix_length, int) or isinstance(self.prefix_length, bool):
            raise TypeError("prefix_length must be an integer")
        for field_name in (
            "is_up",
            "is_default",
            "is_point_to_point",
            "is_vpn",
            "is_bridge",
            "is_virtual",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a boolean")


@dataclass(frozen=True, slots=True)
class RejectedInterface:
    candidate: InterfaceCandidate
    reason: SelectionReason


@dataclass(frozen=True, slots=True)
class InterfaceEvaluation:
    approved: tuple[InterfaceCandidate, ...]
    rejected: tuple[RejectedInterface, ...]


@dataclass(frozen=True, slots=True)
class SelectedInterface:
    """An exact owner-approved listener scope."""

    name: str
    address: str
    network: str
    prefix_length: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError("selected interface name must be a string")
        if not self.name or len(self.name) > 64 or any(ord(char) < 33 for char in self.name):
            raise InterfacePolicyError("selected interface name is invalid")
        if _is_vpn_name(self.name) or _is_bridge_name(self.name):
            raise InterfacePolicyError("selected interface name is not eligible for LAN binding")
        if not isinstance(self.address, str) or not isinstance(self.network, str):
            raise TypeError("selected interface address and network must be strings")
        try:
            address = ipaddress.ip_address(self.address)
            network = ipaddress.ip_network(self.network, strict=True)
        except ValueError as exc:
            raise InterfacePolicyError("selected interface address or network is invalid") from exc
        if address.version != 4 or network.version != 4:
            raise InterfacePolicyError("selected interface must use IPv4")
        if str(address) != self.address or str(network) != self.network:
            raise InterfacePolicyError("selected interface address and network must be canonical")
        if (
            not isinstance(self.prefix_length, int)
            or isinstance(self.prefix_length, bool)
            or not 8 <= self.prefix_length <= 30
        ):
            raise InterfacePolicyError("selected interface prefix is invalid")
        derived = ipaddress.ip_interface(f"{address}/{self.prefix_length}").network
        if network != derived:
            raise InterfacePolicyError("selected network must exactly match address and prefix")
        if not _is_rfc1918_network(network):
            raise InterfacePolicyError("selected network must be inside RFC1918 space")
        if address in (network.network_address, network.broadcast_address):
            raise InterfacePolicyError("selected address is not a usable host")

    @property
    def bind_host(self) -> str:
        return self.address


@dataclass(frozen=True, slots=True)
class LanScopePolicy:
    """Immutable allowlist for one temporary LAN responder session."""

    interface: SelectedInterface
    allowed_profiles: tuple[str, ...]
    fixed_targets: tuple[str, ...]
    active_discovery_approved: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.interface, SelectedInterface):
            raise TypeError("interface must be a SelectedInterface")
        if type(self.allowed_profiles) is not tuple:
            raise TypeError("allowed_profiles must be an immutable tuple")
        if type(self.fixed_targets) is not tuple:
            raise TypeError("fixed_targets must be an immutable tuple")
        if not isinstance(self.active_discovery_approved, bool):
            raise TypeError("active_discovery_approved must be a boolean")
        network = ipaddress.ip_network(self.interface.network, strict=True)
        if network.version != 4 or not _is_rfc1918_network(network):
            raise InterfacePolicyError("LAN scope must be an exact RFC1918 IPv4 network")
        address = ipaddress.ip_address(self.interface.address)
        derived = ipaddress.ip_interface(
            f"{self.interface.address}/{self.interface.prefix_length}"
        ).network
        if network != derived:
            raise InterfacePolicyError("LAN scope network does not match selected address/prefix")
        if address not in network or address in (
            network.network_address,
            network.broadcast_address,
        ):
            raise InterfacePolicyError("selected address is not a usable host in its network")
        if not self.allowed_profiles:
            raise ValueError("at least one fixed diagnostic profile is required")
        if any(not isinstance(profile, str) for profile in self.allowed_profiles):
            raise TypeError("diagnostic profile identifiers must be strings")
        if len(set(self.allowed_profiles)) != len(self.allowed_profiles):
            raise ValueError("diagnostic profiles must be unique")
        for profile in self.allowed_profiles:
            if profile not in PROFILE_ACTIVITY:
                raise ValueError(f"unknown diagnostic profile: {profile}")
            if (
                PROFILE_ACTIVITY[profile] == ProfileActivity.ACTIVE
                and not self.active_discovery_approved
            ):
                raise ValueError("active profile requires explicit host approval")
        if len(self.fixed_targets) > MAX_FIXED_TARGETS:
            raise ValueError("fixed target limit exceeded")
        if any(not isinstance(target, str) for target in self.fixed_targets):
            raise TypeError("fixed targets must be canonical IP address strings")
        if len(set(self.fixed_targets)) != len(self.fixed_targets):
            raise ValueError("fixed targets must be unique")
        for raw_target in self.fixed_targets:
            try:
                target = ipaddress.ip_address(raw_target)
            except ValueError as exc:
                raise ValueError("fixed target must be a valid IP address") from exc
            if str(target) != raw_target:
                raise ValueError("fixed target must use canonical notation")
            if target.version != 4 or target not in network:
                raise ValueError("fixed target must be inside the selected network")
            if target in (network.network_address, network.broadcast_address, address):
                raise ValueError("fixed target must identify another usable host")

    def require_profile(self, profile_id: str) -> str:
        """Return an allowlisted profile without accepting targets or parameters."""
        if profile_id not in self.allowed_profiles:
            raise PermissionError("diagnostic profile was not approved by the host")
        return profile_id

    def targets_for(self, profile_id: str) -> tuple[str, ...]:
        """Return server-derived targets; callers cannot substitute request input."""
        self.require_profile(profile_id)
        if PROFILE_ACTIVITY[profile_id] == ProfileActivity.PASSIVE:
            return ()
        return self.fixed_targets


class ProfileActivity(str, Enum):
    PASSIVE = "passive"
    LOW_IMPACT = "low_impact"
    ACTIVE = "active"


PROFILE_ACTIVITY: Final[dict[str, ProfileActivity]] = {
    "network.passive": ProfileActivity.PASSIVE,
    "network.path": ProfileActivity.LOW_IMPACT,
    "network.scoped-discovery": ProfileActivity.ACTIVE,
}
MAX_FIXED_TARGETS: Final[int] = 64

_RFC1918_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_UNSAFE_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:"
    r"utun|tun|tap|ppp|ipsec|gif|stf|wg|tailscale|zt|ham|vpn|"
    r"bridge|br(?:-|\d)|docker|veth|virbr|vmnet|vboxnet|cni|podman|"
    r"awdl|llw"
    r")",
    re.IGNORECASE,
)


def evaluate_interfaces(candidates: tuple[InterfaceCandidate, ...]) -> InterfaceEvaluation:
    """Classify every candidate without guessing among multiple safe addresses."""
    _validate_candidate_tuple(candidates)
    approved: list[InterfaceCandidate] = []
    rejected: list[RejectedInterface] = []
    for candidate in candidates:
        reason = rejection_reason(candidate)
        if reason is None:
            approved.append(candidate)
        else:
            rejected.append(RejectedInterface(candidate, reason))
    return InterfaceEvaluation(tuple(approved), tuple(rejected))


def rejection_reason(candidate: InterfaceCandidate) -> SelectionReason | None:
    """Return a stable rejection reason, or ``None`` for an exact safe candidate."""
    address = ipaddress.ip_address(candidate.address)
    if not candidate.is_up:
        return SelectionReason.NOT_ACTIVE
    if address.is_unspecified:
        return SelectionReason.WILDCARD
    if address.is_loopback:
        return SelectionReason.LOOPBACK
    if address.is_link_local:
        return SelectionReason.LINK_LOCAL
    if address.version != 4:
        return SelectionReason.IPV6_UNSUPPORTED
    if candidate.prefix_length < 8 or candidate.prefix_length > 30:
        return SelectionReason.INVALID_PREFIX
    if candidate.is_point_to_point:
        return SelectionReason.POINT_TO_POINT
    if candidate.is_vpn or _is_vpn_name(candidate.name):
        return SelectionReason.VPN_OR_TUNNEL
    if candidate.is_bridge or candidate.is_virtual or _is_bridge_name(candidate.name):
        return SelectionReason.BRIDGE_OR_VIRTUAL
    interface = ipaddress.ip_interface(f"{candidate.address}/{candidate.prefix_length}")
    if not _is_rfc1918_address(address) or not _is_rfc1918_network(interface.network):
        return SelectionReason.PUBLIC
    if address in (interface.network.network_address, interface.network.broadcast_address):
        return SelectionReason.INVALID_PREFIX
    return None


def select_interface(
    candidates: tuple[InterfaceCandidate, ...],
    *,
    owner_selected_name: str | None = None,
    owner_selected_address: str | None = None,
) -> SelectedInterface:
    """Select one exact scope, requiring a local choice whenever there is ambiguity.

    Automatic selection is allowed only when exactly one safe address exists and it
    is the observed default interface.  Any other case requires the owner to choose
    both interface name and canonical address locally.
    """
    _validate_candidate_tuple(candidates)
    evaluation = evaluate_interfaces(candidates)
    approved = evaluation.approved
    if owner_selected_name is None and owner_selected_address is None:
        if len(approved) != 1:
            raise InterfacePolicyError(SelectionReason.AMBIGUOUS.value)
        if not approved[0].is_default:
            raise InterfacePolicyError(SelectionReason.OWNER_APPROVAL_REQUIRED.value)
        chosen = approved[0]
    else:
        if not owner_selected_name or not owner_selected_address:
            raise InterfacePolicyError("owner selection requires exact name and address")
        matches = tuple(
            candidate
            for candidate in approved
            if candidate.name == owner_selected_name and candidate.address == owner_selected_address
        )
        if len(matches) != 1:
            raise InterfacePolicyError(SelectionReason.NOT_FOUND.value)
        chosen = matches[0]
    interface = ipaddress.ip_interface(f"{chosen.address}/{chosen.prefix_length}")
    return SelectedInterface(
        name=chosen.name,
        address=chosen.address,
        network=str(interface.network),
        prefix_length=chosen.prefix_length,
    )


def _is_rfc1918_address(address: ipaddress._BaseAddress) -> bool:
    return address.version == 4 and any(address in network for network in _RFC1918_NETWORKS)


def _is_rfc1918_network(network: ipaddress._BaseNetwork) -> bool:
    return network.version == 4 and any(network.subnet_of(parent) for parent in _RFC1918_NETWORKS)


def _is_vpn_name(name: str) -> bool:
    return _UNSAFE_NAME_RE.match(name) is not None and not _is_bridge_name(name)


def _is_bridge_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(
        ("bridge", "br-", "docker", "veth", "virbr", "vmnet", "vboxnet", "cni", "podman")
    )


def _validate_candidate_tuple(candidates: object) -> None:
    if type(candidates) is not tuple:
        raise TypeError("interface candidates must be an immutable tuple")
    if any(not isinstance(candidate, InterfaceCandidate) for candidate in candidates):
        raise TypeError("interface candidates must contain InterfaceCandidate values")
