from __future__ import annotations

import ipaddress
from dataclasses import FrozenInstanceError

import pytest

from netdiag.lan.policy import (
    InterfaceCandidate,
    InterfacePolicyError,
    LanScopePolicy,
    SelectedInterface,
    SelectionReason,
    evaluate_interfaces,
    rejection_reason,
    select_interface,
)


def candidate(address: str = "192.168.50.10", **overrides: object) -> InterfaceCandidate:
    values: dict[str, object] = {
        "name": "en0",
        "address": address,
        "prefix_length": 24,
        "is_up": True,
        "is_default": True,
    }
    values.update(overrides)
    return InterfaceCandidate(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        (candidate("0.0.0.0"), SelectionReason.WILDCARD),
        (candidate("127.0.0.1"), SelectionReason.LOOPBACK),
        (candidate("169.254.4.2"), SelectionReason.LINK_LOCAL),
        (candidate("8.8.8.8"), SelectionReason.PUBLIC),
        (candidate("100.64.1.2"), SelectionReason.PUBLIC),
        (candidate("fd00::2", prefix_length=64), SelectionReason.IPV6_UNSUPPORTED),
        (candidate(is_up=False), SelectionReason.NOT_ACTIVE),
        (candidate(prefix_length=31), SelectionReason.INVALID_PREFIX),
        (candidate(is_point_to_point=True), SelectionReason.POINT_TO_POINT),
        (candidate(name="utun7"), SelectionReason.VPN_OR_TUNNEL),
        (candidate(name="wg0"), SelectionReason.VPN_OR_TUNNEL),
        (candidate(name="tailscale0"), SelectionReason.VPN_OR_TUNNEL),
        (candidate(name="bridge0"), SelectionReason.BRIDGE_OR_VIRTUAL),
        (candidate(name="docker0"), SelectionReason.BRIDGE_OR_VIRTUAL),
        (candidate(is_vpn=True), SelectionReason.VPN_OR_TUNNEL),
        (candidate(is_bridge=True), SelectionReason.BRIDGE_OR_VIRTUAL),
        (candidate(is_virtual=True), SelectionReason.BRIDGE_OR_VIRTUAL),
    ],
)
def test_interface_policy_refuses_unintended_bindings(
    item: InterfaceCandidate,
    reason: SelectionReason,
) -> None:
    assert rejection_reason(item) is reason


def test_interface_policy_accepts_only_exact_rfc1918_hosts() -> None:
    for address in ("10.1.2.3", "172.16.1.2", "172.31.255.2", "192.168.1.2"):
        assert rejection_reason(candidate(address)) is None


def test_evaluation_keeps_rejection_provenance() -> None:
    result = evaluate_interfaces((candidate(), candidate("8.8.8.8", name="en1")))
    assert result.approved == (candidate(),)
    assert result.rejected[0].reason is SelectionReason.PUBLIC


def test_automatic_selection_requires_one_safe_default() -> None:
    selected = select_interface((candidate(), candidate("8.8.8.8", name="en1")))
    assert selected.address == "192.168.50.10"
    assert selected.network == "192.168.50.0/24"
    assert selected.bind_host == "192.168.50.10"

    with pytest.raises(InterfacePolicyError, match="ambiguous"):
        select_interface((candidate(), candidate("192.168.60.10", name="en1")))
    with pytest.raises(InterfacePolicyError, match="owner_approval_required"):
        select_interface((candidate(is_default=False),))


def test_owner_must_choose_exact_name_and_address() -> None:
    choices = (candidate(), candidate("192.168.60.10", name="en1"))
    selected = select_interface(
        choices,
        owner_selected_name="en1",
        owner_selected_address="192.168.60.10",
    )
    assert selected.name == "en1"
    with pytest.raises(InterfacePolicyError, match="not_found"):
        select_interface(
            choices,
            owner_selected_name="en1",
            owner_selected_address="192.168.50.10",
        )
    with pytest.raises(InterfacePolicyError, match="exact name and address"):
        select_interface(choices, owner_selected_name="en1")


def test_scope_has_fixed_profiles_and_server_derived_targets() -> None:
    selected = select_interface((candidate(),))
    policy = LanScopePolicy(
        selected,
        ("network.passive", "network.path"),
        ("192.168.50.1",),
    )
    assert policy.targets_for("network.passive") == ()
    assert policy.targets_for("network.path") == ("192.168.50.1",)
    with pytest.raises(PermissionError):
        policy.targets_for("network.scoped-discovery")


def test_active_profile_requires_separate_host_approval() -> None:
    selected = select_interface((candidate(),))
    with pytest.raises(ValueError, match="explicit host approval"):
        LanScopePolicy(
            selected,
            ("network.scoped-discovery",),
            ("192.168.50.1",),
        )
    approved = LanScopePolicy(
        selected,
        ("network.scoped-discovery",),
        ("192.168.50.1",),
        active_discovery_approved=True,
    )
    assert approved.targets_for("network.scoped-discovery") == ("192.168.50.1",)


@pytest.mark.parametrize(
    "target", ["192.168.51.1", "192.168.50.0", "192.168.50.255", "192.168.50.10"]
)
def test_scope_refuses_arbitrary_or_non_host_targets(target: str) -> None:
    with pytest.raises(ValueError):
        LanScopePolicy(
            select_interface((candidate(),)),
            ("network.path",),
            (target,),
        )


def test_candidate_requires_canonical_address_and_visible_name() -> None:
    with pytest.raises(ValueError):
        candidate("192.168.050.010")
    with pytest.raises(ValueError):
        candidate(name="en 0")


def test_direct_selected_interface_cannot_widen_network_scope() -> None:
    with pytest.raises(InterfacePolicyError, match="exactly match"):
        SelectedInterface("en0", "192.168.50.10", "192.168.0.0/16", 24)
    with pytest.raises(InterfacePolicyError, match="not eligible"):
        SelectedInterface("utun4", "192.168.50.10", "192.168.50.0/24", 24)


@pytest.mark.parametrize(
    "flag",
    ("is_up", "is_default", "is_point_to_point", "is_vpn", "is_bridge", "is_virtual"),
)
def test_interface_candidate_flags_require_actual_booleans(flag: str) -> None:
    with pytest.raises(TypeError, match=rf"{flag} must be a boolean"):
        candidate(**{flag: "false"})


def test_interface_candidate_rejects_bool_prefix_and_typed_address_impostors() -> None:
    with pytest.raises(TypeError, match="prefix_length must be an integer"):
        candidate(prefix_length=True)
    with pytest.raises(TypeError, match="address must be a string"):
        candidate(address=ipaddress.ip_address("192.168.50.10"))  # type: ignore[arg-type]


def test_scope_requires_immutable_tuples_and_an_actual_approval_boolean() -> None:
    selected = select_interface((candidate(),))
    with pytest.raises(TypeError, match="allowed_profiles must be an immutable tuple"):
        LanScopePolicy(selected, ["network.passive"], ())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="fixed_targets must be an immutable tuple"):
        LanScopePolicy(selected, ("network.path",), ["192.168.50.1"])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a boolean"):
        LanScopePolicy(
            selected,
            ("network.scoped-discovery",),
            ("192.168.50.1",),
            active_discovery_approved="false",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "target",
    (ipaddress.ip_address("192.168.50.1"), 3232248321, b"192.168.50.1"),
)
def test_scope_targets_require_canonical_ip_strings(target: object) -> None:
    with pytest.raises(TypeError, match="canonical IP address strings"):
        LanScopePolicy(
            select_interface((candidate(),)),
            ("network.path",),
            (target,),  # type: ignore[arg-type]
        )


def test_scope_and_candidate_collections_cannot_be_mutated_or_substituted() -> None:
    selected = select_interface((candidate(),))
    policy = LanScopePolicy(selected, ("network.path",), ("192.168.50.1",))
    with pytest.raises(FrozenInstanceError):
        policy.fixed_targets = ("192.168.50.2",)  # type: ignore[misc]
    with pytest.raises(TypeError, match="immutable tuple"):
        evaluate_interfaces([candidate()])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="InterfaceCandidate"):
        select_interface((object(),))  # type: ignore[arg-type]
