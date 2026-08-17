"""Structural, share-safe export for disabled assessment designs."""

from __future__ import annotations

import json
from typing import Any

from .models import FOUNDATION_NOTICE, CoveragePlan, EngagementEnvelope

SHARE_SAFE_SCHEMA_VERSION = "lantern.assessment-share-safe.v1"


def build_share_safe_export(*, envelope: EngagementEnvelope, plan: CoveragePlan) -> dict[str, Any]:
    """Return counts, classifications, and budgets without scope identifiers.

    Organization, principal, contact, site, asset, authorization, engagement,
    vantage, IP, and CIDR values are deliberately omitted. This is structural
    redaction, not key-name filtering of a raw record.
    """

    if type(envelope) is not EngagementEnvelope:
        raise TypeError("envelope must be an EngagementEnvelope")
    if type(plan) is not CoveragePlan:
        raise TypeError("plan must be a CoveragePlan")
    plan.assert_matches(envelope)

    scope = envelope.scope
    export: dict[str, Any] = {
        "schema_version": SHARE_SAFE_SCHEMA_VERSION,
        "status": "disabled",
        "notice": FOUNDATION_NOTICE,
        "classification": {
            "environment_kind": envelope.environment_kind.value,
            "purpose": envelope.purpose.value,
            "sensitivity": envelope.sensitivity.value,
        },
        "authorization": {
            "authority_statement": envelope.authorization.authority_statement.value,
            "explicit_approval_recorded": True,
            "emergency_stop_required": True,
            "emergency_contact_reference_recorded": True,
            "incident_procedure_reference_recorded": True,
        },
        "window": {
            "duration_seconds": int(
                (envelope.window.hard_stop_at - envelope.window.starts_at).total_seconds()
            ),
            "has_hard_stop": True,
            "authorization_covers_hard_stop": True,
        },
        "scope_structure": {
            "target_realm": scope.target_realm.value,
            "included_network_entries": len(scope.included_networks),
            "included_host_entries": len(scope.included_hosts),
            "included_asset_entries": len(scope.included_asset_refs),
            "included_site_entries": len(scope.site_refs),
            "excluded_network_entries": len(scope.excluded_networks),
            "excluded_host_entries": len(scope.excluded_hosts),
            "excluded_asset_entries": len(scope.excluded_asset_refs),
            "excluded_site_entries": len(scope.excluded_site_refs),
            "fragile_asset_entries": len(scope.fragile_asset_refs),
            "third_party_asset_entries": len(scope.third_party_asset_refs),
            "effective_target_count": scope.effective_target_count,
            "exclusions_reviewed": True,
        },
        "vantage_structure": {
            "count": len(envelope.vantage_points),
            "roles": sorted({item.role.value for item in envelope.vantage_points}),
        },
        "technique_designs": [
            {
                "technique": item.technique.value,
                "state": item.state.value,
                "max_targets": item.max_targets,
                "max_packets_per_target": item.max_packets_per_target,
                "max_concurrency": item.max_concurrency,
                "timeout_ms": item.timeout_ms,
                "max_duration_seconds": item.max_duration_seconds,
            }
            for item in envelope.technique_budgets
        ],
        "coverage_plan": {
            "integrity_checked": True,
            "item_count": len(plan.items),
            "states": sorted({item.coverage_state.value for item in plan.items}),
            "observation_count": 0,
            "evidence_count": 0,
            "finding_count": 0,
            "conclusion_count": 0,
        },
        "data_policy": {
            "retention_days": envelope.data_policy.retention_days,
            "export_policy": envelope.data_policy.export_policy.value,
            "local_only": True,
            "encryption_required": True,
            "deletion_procedure_reference_recorded": True,
        },
        "limitations": [
            "No assessment traffic was sent.",
            "No evidence was collected and no security, compliance, or certification conclusion was made.",
            "This record is a disabled offline coverage design only.",
        ],
    }
    # Prove that this value is strict JSON now, rather than failing at a later handoff.
    json.dumps(export, ensure_ascii=True, allow_nan=False, sort_keys=True)
    return export


def share_safe_json(*, envelope: EngagementEnvelope, plan: CoveragePlan) -> str:
    """Return deterministic compact JSON for the structurally safe view."""

    return json.dumps(
        build_share_safe_export(envelope=envelope, plan=plan),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
