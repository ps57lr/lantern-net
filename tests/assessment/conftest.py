from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netdiag.assessment import (
    AssessmentPurpose,
    AssessmentScope,
    AssessmentWindow,
    AuthorityStatement,
    Authorization,
    DataPolicy,
    DataSensitivity,
    EngagementEnvelope,
    EnvironmentKind,
    ExportPolicy,
    ScopeRealm,
    Technique,
    TechniqueBudget,
    TechniqueState,
    VantagePoint,
    VantageRole,
)


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


@pytest.fixture
def valid_scope() -> AssessmentScope:
    return AssessmentScope(
        target_realm=ScopeRealm.PRIVATE_LAN,
        included_networks=("192.168.50.0/24",),
        included_hosts=("10.20.30.40",),
        included_asset_refs=("asset.collector-01", "asset.fragile-01"),
        site_refs=("site.main",),
        excluded_networks=("192.168.50.128/26",),
        excluded_hosts=("192.168.50.10",),
        excluded_asset_refs=("asset.fragile-01",),
        excluded_site_refs=("site.vendor",),
        fragile_asset_refs=("asset.fragile-01",),
        third_party_asset_refs=(),
        exclusions_reviewed=True,
    )


@pytest.fixture
def valid_envelope(valid_scope: AssessmentScope) -> EngagementEnvelope:
    budgets = (
        TechniqueBudget(
            technique=Technique.LOW_IMPACT_PATH_CHECK_DESIGN,
            state=TechniqueState.DESIGN_ONLY,
            max_targets=2,
            max_packets_per_target=4,
            max_concurrency=1,
            timeout_ms=1500,
            max_duration_seconds=120,
        ),
        TechniqueBudget(
            technique=Technique.PASSIVE_ENDPOINT_OBSERVATION_DESIGN,
            state=TechniqueState.DESIGN_ONLY,
            max_targets=1,
            max_packets_per_target=0,
            max_concurrency=1,
            timeout_ms=1000,
            max_duration_seconds=60,
        ),
    )
    return EngagementEnvelope(
        engagement_id="engagement.demo-01",
        organization_ref="org.customer-01",
        scope_owner_ref="principal.scope-owner",
        assessor_ref="principal.assessor-01",
        environment_kind=EnvironmentKind.MUNICIPAL,
        purpose=AssessmentPurpose.NETWORK_HARDENING_PREPARATION,
        sensitivity=DataSensitivity.RESTRICTED,
        window=AssessmentWindow(
            starts_at=utc("2026-08-17T10:00:00"),
            hard_stop_at=utc("2026-08-17T12:00:00"),
        ),
        authorization=Authorization(
            authorization_ref="auth.written-01",
            authorizer_ref="principal.authorizer-01",
            authority_statement=AuthorityStatement.WRITTEN_DELEGATION_CONFIRMED,
            issued_at=utc("2026-08-16T10:00:00"),
            expires_at=utc("2026-08-18T10:00:00"),
            emergency_contact_ref="contact.emergency-01",
            incident_procedure_ref="procedure.incident-01",
            explicit_approval=True,
            emergency_stop_required=True,
        ),
        scope=valid_scope,
        technique_budgets=budgets,
        approved_techniques=tuple(item.technique for item in budgets),
        vantage_points=(
            VantagePoint(
                vantage_id="vantage.local-01",
                site_ref="site.main",
                asset_ref="asset.collector-01",
                role=VantageRole.ENDPOINT,
                approved=True,
            ),
        ),
        data_policy=DataPolicy(
            retention_days=30,
            export_policy=ExportPolicy.STRUCTURAL_SHARE_SAFE_ONLY,
            deletion_procedure_ref="procedure.delete-01",
            local_only=True,
            encryption_required=True,
        ),
    )
