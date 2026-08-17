from __future__ import annotations

import ipaddress
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone

import pytest

from netdiag.consent import ConsentExpired, DiagnosticGoal, issue_consent
from netdiag.core import ActivityLevel

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def test_basic_check_consent_is_low_impact_without_active_scope() -> None:
    record = issue_consent(
        consent_id="consent.basic",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.PROBLEM,
        basic_network_checks=True,
        now=NOW,
    )
    policy = record.to_scan_policy(now=NOW)
    assert policy.maximum_activity == ActivityLevel.LOW_IMPACT_NETWORK
    assert not policy.has_explicit_scope


def test_passive_check_has_no_network_authority() -> None:
    record = issue_consent(
        consent_id="consent.passive",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.RESCUE,
        basic_network_checks=False,
        now=NOW,
    )
    assert record.to_scan_policy(now=NOW).maximum_activity == ActivityLevel.PASSIVE


def test_active_consent_requires_exact_private_scope_and_host_budget() -> None:
    record = issue_consent(
        consent_id="consent.active",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.NETWORK,
        basic_network_checks=True,
        active_interface="en0",
        active_network="192.168.7.0/24",
        max_hosts=254,
        now=NOW,
    )
    policy = record.to_scan_policy(now=NOW)
    assert policy.maximum_activity == ActivityLevel.ACTIVE_DISCOVERY
    assert policy.allowed_interfaces == ("en0",)
    assert policy.allowed_networks == ("192.168.7.0/24",)

    with pytest.raises(ValueError, match="host limit"):
        issue_consent(
            consent_id="consent.too_large",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.NETWORK,
            basic_network_checks=True,
            active_interface="en0",
            active_network="10.0.0.0/16",
            max_hosts=256,
            now=NOW,
        )


def test_consent_rejects_host_bit_cidr_instead_of_widening_scope() -> None:
    with pytest.raises(ValueError, match="exact canonical network"):
        issue_consent(
            consent_id="consent.host_bits",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.NETWORK,
            basic_network_checks=True,
            active_interface="en0",
            active_network="192.168.1.42/24",
            now=NOW,
        )


@pytest.mark.parametrize("truthy_impostor", ["false", "true", 0, 1, None])
def test_basic_network_choice_requires_an_actual_boolean(truthy_impostor: object) -> None:
    with pytest.raises(TypeError, match="must be a boolean"):
        issue_consent(
            consent_id="consent.boolean",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.NETWORK,
            basic_network_checks=truthy_impostor,  # type: ignore[arg-type]
            now=NOW,
        )


def test_consent_scope_types_and_frozen_state_are_exact() -> None:
    with pytest.raises(TypeError, match="network must be a string"):
        issue_consent(
            consent_id="consent.typed_network",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.NETWORK,
            basic_network_checks=True,
            active_interface="en0",
            active_network=ipaddress.ip_network("192.168.1.0/24"),  # type: ignore[arg-type]
            now=NOW,
        )

    record = issue_consent(
        consent_id="consent.immutable",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.NETWORK,
        basic_network_checks=True,
        active_interface="en0",
        active_network="192.168.1.0/24",
        now=NOW,
    )
    policy = record.to_scan_policy(now=NOW)
    assert type(policy.allowed_interfaces) is tuple
    assert type(policy.allowed_networks) is tuple
    with pytest.raises(FrozenInstanceError):
        record.network = "192.168.0.0/16"  # type: ignore[misc]


def test_consent_time_arguments_reject_falsy_type_confusion() -> None:
    with pytest.raises(TypeError, match="issuance time"):
        issue_consent(
            consent_id="consent.bad_time",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.PROBLEM,
            basic_network_checks=False,
            now="",  # type: ignore[arg-type]
        )

    record = issue_consent(
        consent_id="consent.good_time",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.PROBLEM,
        basic_network_checks=False,
        now=NOW,
    )
    with pytest.raises(TypeError, match="validation time"):
        record.is_valid(now="")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "network",
    ("0.0.0.0/0", "127.0.0.0/8", "169.254.0.0/16", "8.8.8.0/24", "fd00::/64"),
)
def test_active_consent_rejects_non_lan_scope(network: str) -> None:
    with pytest.raises(ValueError):
        issue_consent(
            consent_id="consent.invalid",
            scan_id="scan.fixture",
            goal=DiagnosticGoal.NETWORK,
            basic_network_checks=True,
            active_interface="en0",
            active_network=network,
            now=NOW,
        )


def test_expired_consent_cannot_become_policy() -> None:
    record = issue_consent(
        consent_id="consent.short",
        scan_id="scan.fixture",
        goal=DiagnosticGoal.PROBLEM,
        basic_network_checks=True,
        ttl_seconds=1,
        now=NOW,
    )
    with pytest.raises(ConsentExpired):
        record.to_scan_policy(now=NOW + timedelta(seconds=1))


def test_consent_model_has_no_secret_bearing_field() -> None:
    field_names = {
        item.name
        for item in fields(
            issue_consent(
                consent_id="consent.fields",
                scan_id="scan.fixture",
                goal=DiagnosticGoal.PROBLEM,
                basic_network_checks=False,
                now=NOW,
            )
        )
    }
    forbidden = {"password", "credential", "token", "secret", "recovery_key"}
    assert field_names.isdisjoint(forbidden)
