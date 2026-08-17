from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from netdiag.assessment import (
    AssessmentScope,
    AssessmentWindow,
    Authorization,
    EngagementEnvelope,
    FoundationStatus,
    ScopeRealm,
    Technique,
    TechniqueBudget,
    TechniqueState,
)

from .conftest import utc


def test_envelope_is_immutable_canonical_and_round_trips(valid_envelope) -> None:
    encoded = valid_envelope.to_canonical_json()

    assert encoded == valid_envelope.to_canonical_json()
    assert EngagementEnvelope.from_canonical_json(encoded) == valid_envelope
    assert len(valid_envelope.local_digest) == 64
    assert valid_envelope.status is FoundationStatus.DISABLED
    with pytest.raises(FrozenInstanceError):
        valid_envelope.organization_ref = "org.changed"
    with pytest.raises(AttributeError):
        valid_envelope.scope.included_networks.append("10.0.0.0/24")


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.7/24",  # host-bit widening
        "8.8.8.0/24",  # public
        "100.64.0.0/24",  # shared/VPN-like carrier space
        "127.0.0.0/24",  # loopback
        "169.254.10.0/24",  # link-local
        "224.0.0.0/24",  # multicast
        "2001:db8::/64",  # IPv6/documentation
        "10.0.0.0/8",  # too broad for the bounded foundation
    ],
)
def test_scope_rejects_noncanonical_unsafe_or_overbroad_networks(target: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        AssessmentScope(
            target_realm=ScopeRealm.PRIVATE_LAN,
            included_networks=(target,),
            included_hosts=(),
            included_asset_refs=(),
            site_refs=("site.main",),
            excluded_networks=(),
            excluded_hosts=(),
            excluded_asset_refs=(),
            excluded_site_refs=(),
            fragile_asset_refs=(),
            third_party_asset_refs=(),
            exclusions_reviewed=True,
        )


@pytest.mark.parametrize(
    "target", ["8.8.8.8", "100.64.0.1", "127.0.0.1", "169.254.1.2", "::1", "192.168.001.1"]
)
def test_scope_rejects_public_vpn_special_and_noncanonical_hosts(target: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        AssessmentScope(
            target_realm=ScopeRealm.PRIVATE_LAN,
            included_networks=(),
            included_hosts=(target,),
            included_asset_refs=(),
            site_refs=("site.main",),
            excluded_networks=(),
            excluded_hosts=(),
            excluded_asset_refs=(),
            excluded_site_refs=(),
            fragile_asset_refs=(),
            third_party_asset_refs=(),
            exclusions_reviewed=True,
        )


def test_scope_rejects_overlap_implicit_expansion_and_unreviewed_exclusions(valid_scope) -> None:
    with pytest.raises(ValueError, match="overlap"):
        replace(
            valid_scope,
            included_networks=("192.168.50.0/24", "192.168.50.0/25"),
        )
    with pytest.raises(ValueError, match="inside"):
        replace(valid_scope, excluded_networks=("10.99.0.0/24",))
    with pytest.raises(ValueError, match="exclusions reviewed"):
        replace(valid_scope, exclusions_reviewed=False)
    with pytest.raises(ValueError, match="duplicate"):
        replace(valid_scope, included_hosts=("192.168.50.11",))


def test_scope_rejects_vpn_or_public_realm_type_confusion(valid_scope) -> None:
    with pytest.raises(TypeError, match="ScopeRealm"):
        replace(valid_scope, target_realm="vpn")
    with pytest.raises(TypeError, match="ScopeRealm"):
        replace(valid_scope, target_realm="public")


@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_ref", "org.passwordhunter2"),
        ("organization_ref", "org.secretvalue"),
        ("organization_ref", "Customer Name"),
        ("organization_ref", "org.\N{SNOWMAN}"),
        ("organization_ref", "org.customer\nadmin"),
        ("organization_ref", "admin@example.test"),
    ],
)
def test_opaque_references_reject_secret_freeform_unicode_and_controls(
    valid_envelope, field: str, value: str
) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(valid_envelope, **{field: value})


def test_strict_programmatic_types_reject_lists_strings_and_bool_as_int(
    valid_envelope, valid_scope
) -> None:
    with pytest.raises(TypeError, match="tuple"):
        replace(valid_scope, included_networks=["192.168.50.0/24"])
    with pytest.raises(TypeError, match="Technique"):
        replace(valid_envelope, approved_techniques=("low_impact_path_check_design",))
    with pytest.raises(TypeError, match="integer"):
        replace(valid_envelope.technique_budgets[0], max_targets=True)
    with pytest.raises(TypeError, match="boolean"):
        replace(valid_scope, exclusions_reviewed=1)


def test_exact_design_technique_allowlist_and_scope_budget(valid_envelope) -> None:
    with pytest.raises(TypeError, match="Technique"):
        TechniqueBudget("shell", TechniqueState.DESIGN_ONLY, 1, 0, 1, 1000, 10)
    with pytest.raises(ValueError, match="effective scope"):
        replace(
            valid_envelope,
            technique_budgets=(
                replace(valid_envelope.technique_budgets[0], max_targets=4096),
                valid_envelope.technique_budgets[1],
            ),
        )


def test_discovery_design_requires_explicit_private_network(valid_envelope, valid_scope) -> None:
    asset_only_scope = replace(
        valid_scope,
        included_networks=(),
        included_hosts=(),
        excluded_networks=(),
        excluded_hosts=(),
    )
    budget = TechniqueBudget(
        Technique.PRIVATE_SEGMENT_DISCOVERY_DESIGN,
        TechniqueState.DESIGN_ONLY,
        1,
        1,
        1,
        1000,
        30,
    )
    with pytest.raises(ValueError, match="included private network"):
        replace(
            valid_envelope,
            scope=asset_only_scope,
            technique_budgets=(budget,),
            approved_techniques=(Technique.PRIVATE_SEGMENT_DISCOVERY_DESIGN,),
        )


def test_time_window_authorization_expiry_and_hard_stop_are_strict(valid_envelope) -> None:
    with pytest.raises(ValueError, match="after"):
        AssessmentWindow(
            valid_envelope.window.starts_at,
            valid_envelope.window.starts_at,
        )
    with pytest.raises(ValueError, match="24 hours"):
        AssessmentWindow(
            valid_envelope.window.starts_at,
            valid_envelope.window.starts_at + timedelta(hours=25),
        )
    with pytest.raises(ValueError, match="hard stop"):
        replace(
            valid_envelope,
            authorization=replace(
                valid_envelope.authorization,
                expires_at=valid_envelope.window.hard_stop_at - timedelta(seconds=1),
            ),
        )
    with pytest.raises(ValueError, match="UTC"):
        AssessmentWindow(
            valid_envelope.window.starts_at.replace(tzinfo=None),
            valid_envelope.window.hard_stop_at,
        )


def test_local_json_rejects_unknown_duplicate_nonfinite_noncanonical_and_deep_values(
    valid_envelope,
) -> None:
    payload = valid_envelope.to_local_dict()
    payload["password"] = "do-not-accept"
    with pytest.raises(ValueError, match="unknown"):
        EngagementEnvelope.from_local_dict(payload)

    canonical = valid_envelope.to_canonical_json()
    duplicate = canonical.replace(
        '"schema_version":"lantern.assessment-envelope.v1"',
        '"schema_version":"lantern.assessment-envelope.v1","schema_version":"bad"',
    )
    with pytest.raises(ValueError, match="duplicate"):
        EngagementEnvelope.from_canonical_json(duplicate)
    with pytest.raises(ValueError, match="non-finite"):
        EngagementEnvelope.from_canonical_json(
            canonical.replace('"retention_days":30', '"retention_days":NaN')
        )
    with pytest.raises(ValueError, match="canonical encoding"):
        EngagementEnvelope.from_canonical_json(json.dumps(valid_envelope.to_local_dict()))
    with pytest.raises(ValueError, match="ASCII"):
        EngagementEnvelope.from_canonical_json(canonical + "\ud800")
    with pytest.raises(ValueError, match="nesting"):
        EngagementEnvelope.from_canonical_json("[" * 2000 + "]" * 2000)


def test_local_dict_rejects_nested_unknown_secret_fields(valid_envelope) -> None:
    payload = valid_envelope.to_local_dict()
    payload["authorization"]["api_token"] = "hidden"
    with pytest.raises(ValueError, match="unknown"):
        EngagementEnvelope.from_local_dict(payload)


def test_authorization_requires_fixed_true_booleans(valid_envelope) -> None:
    authorization: Authorization = valid_envelope.authorization
    with pytest.raises(ValueError, match="explicit approval"):
        replace(authorization, explicit_approval=False)
    with pytest.raises(TypeError, match="boolean"):
        replace(authorization, emergency_stop_required=1)


def test_constructor_rejects_noncanonical_tuple_order(valid_scope) -> None:
    with pytest.raises(ValueError, match="sorted order"):
        replace(
            valid_scope,
            included_asset_refs=("asset.fragile-01", "asset.collector-01"),
        )


def test_canonical_parser_rejects_oversized_input(valid_envelope) -> None:
    with pytest.raises(ValueError, match="64 KiB"):
        EngagementEnvelope.from_canonical_json(valid_envelope.to_canonical_json() + (" " * 70000))


def test_authorization_reference_type_is_not_coerced(valid_envelope) -> None:
    with pytest.raises(TypeError, match="string"):
        replace(valid_envelope.authorization, authorization_ref=123)


def test_coverage_status_cannot_be_enabled_by_string(valid_envelope) -> None:
    with pytest.raises(TypeError, match="FoundationStatus"):
        replace(valid_envelope, status="enabled")


def test_whole_second_precision_required(valid_envelope) -> None:
    with pytest.raises(ValueError, match="whole-second"):
        replace(
            valid_envelope.window,
            starts_at=utc("2026-08-17T10:00:00").replace(microsecond=1),
        )
