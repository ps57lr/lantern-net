"""Immutable, offline-only authorization and scope design models.

These values describe a possible future authorized assessment. They do not
grant runtime capability and cannot start collectors, open sockets, or run
commands. The only supported foundation state is ``disabled``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from ._validation import (
    expect_exact_dict,
    format_utc_second,
    json_array_as_tuple,
    parse_enum,
    parse_utc_second,
    require_bounded_int,
    require_enum,
    require_exact_bool,
    require_private_host,
    require_private_network,
    require_reference,
    require_sorted_unique,
    require_tuple,
    require_utc_second,
)

ENVELOPE_SCHEMA_VERSION = "lantern.assessment-envelope.v1"
PLAN_SCHEMA_VERSION = "lantern.assessment-coverage-plan.v1"
FOUNDATION_NOTICE = (
    "DESIGN ONLY — assessment collection and execution are disabled in this release."
)


class FoundationStatus(str, Enum):
    DISABLED = "disabled"


class EnvironmentKind(str, Enum):
    BUSINESS = "business"
    MUNICIPAL = "municipal"
    NONPROFIT = "nonprofit"
    OTHER_AUTHORIZED = "other_authorized"


class AssessmentPurpose(str, Enum):
    NETWORK_RELIABILITY_PREPARATION = "network_reliability_preparation"
    NETWORK_HARDENING_PREPARATION = "network_hardening_preparation"
    AUTHORIZED_RISK_REVIEW_PREPARATION = "authorized_risk_review_preparation"


class DataSensitivity(str, Enum):
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AuthorityStatement(str, Enum):
    OWNER_CONFIRMED = "owner_confirmed"
    WRITTEN_DELEGATION_CONFIRMED = "written_delegation_confirmed"


class Technique(str, Enum):
    """The exact, non-executable design allowlist."""

    PASSIVE_ENDPOINT_OBSERVATION_DESIGN = "passive_endpoint_observation_design"
    LOW_IMPACT_PATH_CHECK_DESIGN = "low_impact_path_check_design"
    PRIVATE_SEGMENT_DISCOVERY_DESIGN = "private_segment_discovery_design"
    SERVICE_IDENTIFICATION_DESIGN = "service_identification_design"
    READ_ONLY_CONFIGURATION_REVIEW_DESIGN = "read_only_configuration_review_design"


class TechniqueState(str, Enum):
    DESIGN_ONLY = "design_only"


class VantageRole(str, Enum):
    ENDPOINT = "endpoint"
    SITE_COLLECTOR_DESIGN = "site_collector_design"
    ANALYST_REVIEW_DESIGN = "analyst_review_design"


class ExportPolicy(str, Enum):
    STRUCTURAL_SHARE_SAFE_ONLY = "structural_share_safe_only"


class ScopeRealm(str, Enum):
    PRIVATE_LAN = "private_lan"


class CoverageState(str, Enum):
    NOT_ASSESSED_DESIGN_ONLY = "not_assessed_design_only"


@dataclass(frozen=True, slots=True)
class AssessmentWindow:
    starts_at: datetime
    hard_stop_at: datetime

    def __post_init__(self) -> None:
        require_utc_second(self.starts_at, label="assessment start")
        require_utc_second(self.hard_stop_at, label="assessment hard stop")
        if self.hard_stop_at <= self.starts_at:
            raise ValueError("assessment hard stop must be after its start")
        if self.hard_stop_at - self.starts_at > timedelta(hours=24):
            raise ValueError("an assessment window cannot exceed 24 hours")

    def _local_dict(self) -> dict[str, object]:
        return {
            "starts_at": format_utc_second(self.starts_at),
            "hard_stop_at": format_utc_second(self.hard_stop_at),
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> AssessmentWindow:
        item = expect_exact_dict(
            value,
            label="assessment window",
            keys=frozenset({"starts_at", "hard_stop_at"}),
        )
        return cls(
            starts_at=parse_utc_second(item["starts_at"], label="assessment start"),
            hard_stop_at=parse_utc_second(item["hard_stop_at"], label="assessment hard stop"),
        )


@dataclass(frozen=True, slots=True)
class Authorization:
    authorization_ref: str
    authorizer_ref: str
    authority_statement: AuthorityStatement
    issued_at: datetime
    expires_at: datetime
    emergency_contact_ref: str
    incident_procedure_ref: str
    explicit_approval: bool
    emergency_stop_required: bool

    def __post_init__(self) -> None:
        require_reference(self.authorization_ref, label="authorization reference", prefix="auth")
        require_reference(self.authorizer_ref, label="authorizer reference", prefix="principal")
        require_enum(self.authority_statement, AuthorityStatement, label="authority statement")
        require_utc_second(self.issued_at, label="authorization issuance")
        require_utc_second(self.expires_at, label="authorization expiry")
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must be after issuance")
        if self.expires_at - self.issued_at > timedelta(days=30):
            raise ValueError("authorization cannot remain valid for more than 30 days")
        require_reference(
            self.emergency_contact_ref,
            label="emergency contact reference",
            prefix="contact",
        )
        require_reference(
            self.incident_procedure_ref,
            label="incident procedure reference",
            prefix="procedure",
        )
        require_exact_bool(self.explicit_approval, label="explicit approval", required=True)
        require_exact_bool(
            self.emergency_stop_required,
            label="emergency stop requirement",
            required=True,
        )

    def is_current(self, *, now: datetime) -> bool:
        require_utc_second(now, label="authorization evaluation time")
        return self.issued_at <= now < self.expires_at

    def _local_dict(self) -> dict[str, object]:
        return {
            "authorization_ref": self.authorization_ref,
            "authorizer_ref": self.authorizer_ref,
            "authority_statement": self.authority_statement.value,
            "issued_at": format_utc_second(self.issued_at),
            "expires_at": format_utc_second(self.expires_at),
            "emergency_contact_ref": self.emergency_contact_ref,
            "incident_procedure_ref": self.incident_procedure_ref,
            "explicit_approval": self.explicit_approval,
            "emergency_stop_required": self.emergency_stop_required,
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> Authorization:
        keys = frozenset(
            {
                "authorization_ref",
                "authorizer_ref",
                "authority_statement",
                "issued_at",
                "expires_at",
                "emergency_contact_ref",
                "incident_procedure_ref",
                "explicit_approval",
                "emergency_stop_required",
            }
        )
        item = expect_exact_dict(value, label="authorization", keys=keys)
        return cls(
            authorization_ref=item["authorization_ref"],
            authorizer_ref=item["authorizer_ref"],
            authority_statement=parse_enum(
                item["authority_statement"], AuthorityStatement, label="authority statement"
            ),
            issued_at=parse_utc_second(item["issued_at"], label="authorization issuance"),
            expires_at=parse_utc_second(item["expires_at"], label="authorization expiry"),
            emergency_contact_ref=item["emergency_contact_ref"],
            incident_procedure_ref=item["incident_procedure_ref"],
            explicit_approval=item["explicit_approval"],
            emergency_stop_required=item["emergency_stop_required"],
        )


@dataclass(frozen=True, slots=True)
class AssessmentScope:
    target_realm: ScopeRealm
    included_networks: tuple[str, ...]
    included_hosts: tuple[str, ...]
    included_asset_refs: tuple[str, ...]
    site_refs: tuple[str, ...]
    excluded_networks: tuple[str, ...]
    excluded_hosts: tuple[str, ...]
    excluded_asset_refs: tuple[str, ...]
    excluded_site_refs: tuple[str, ...]
    fragile_asset_refs: tuple[str, ...]
    third_party_asset_refs: tuple[str, ...]
    exclusions_reviewed: bool

    def __post_init__(self) -> None:
        require_enum(self.target_realm, ScopeRealm, label="scope target realm")
        tuple_limits = {
            "included_networks": 64,
            "included_hosts": 256,
            "included_asset_refs": 256,
            "site_refs": 64,
            "excluded_networks": 128,
            "excluded_hosts": 512,
            "excluded_asset_refs": 256,
            "excluded_site_refs": 64,
            "fragile_asset_refs": 256,
            "third_party_asset_refs": 256,
        }
        for name, maximum in tuple_limits.items():
            values = getattr(self, name)
            require_tuple(values, label=name.replace("_", " "), maximum=maximum)
            require_sorted_unique(values, label=name.replace("_", " "))

        for value in self.included_networks:
            require_private_network(value, label="included network")
        for value in self.excluded_networks:
            require_private_network(value, label="excluded network")
        for value in self.included_hosts:
            require_private_host(value, label="included host")
        for value in self.excluded_hosts:
            require_private_host(value, label="excluded host")

        reference_fields = {
            "included_asset_refs": "asset",
            "site_refs": "site",
            "excluded_asset_refs": "asset",
            "excluded_site_refs": "site",
            "fragile_asset_refs": "asset",
            "third_party_asset_refs": "asset",
        }
        for name, prefix in reference_fields.items():
            for value in getattr(self, name):
                require_reference(value, label=name.replace("_", " "), prefix=prefix)

        require_exact_bool(self.exclusions_reviewed, label="exclusions reviewed", required=True)
        if not (self.included_networks or self.included_hosts or self.included_asset_refs):
            raise ValueError("scope must contain at least one explicit included target")
        self._validate_overlap_and_exclusion_rules()
        if self.effective_target_count <= 0:
            raise ValueError("scope exclusions remove every included target")
        if self.effective_target_count > 4096:
            raise ValueError("effective scope cannot exceed 4096 targets")

    def _validate_overlap_and_exclusion_rules(self) -> None:
        included_networks = tuple(ipaddress.ip_network(value) for value in self.included_networks)
        excluded_networks = tuple(ipaddress.ip_network(value) for value in self.excluded_networks)
        for index, network in enumerate(included_networks):
            if any(network.overlaps(other) for other in included_networks[index + 1 :]):
                raise ValueError("included networks must not overlap or implicitly widen scope")
        for index, network in enumerate(excluded_networks):
            if any(network.overlaps(other) for other in excluded_networks[index + 1 :]):
                raise ValueError("excluded networks must not overlap")
            if not any(network.subnet_of(parent) for parent in included_networks):
                raise ValueError("every excluded network must be inside one included network")

        included_hosts = tuple(ipaddress.ip_address(value) for value in self.included_hosts)
        excluded_hosts = tuple(ipaddress.ip_address(value) for value in self.excluded_hosts)
        if any(any(host in network for network in included_networks) for host in included_hosts):
            raise ValueError(
                "included hosts must not duplicate addresses already covered by a network"
            )
        for host in excluded_hosts:
            if any(host in network for network in excluded_networks):
                raise ValueError("excluded hosts must not duplicate an excluded network")
            if host not in included_hosts and not any(
                host in network for network in included_networks
            ):
                raise ValueError("every excluded host must be inside the included scope")

        included_assets = set(self.included_asset_refs)
        excluded_assets = set(self.excluded_asset_refs)
        if not excluded_assets.issubset(included_assets):
            raise ValueError("excluded assets must be selected from explicitly included assets")
        if not set(self.fragile_asset_refs).issubset(excluded_assets):
            raise ValueError("fragile assets must be explicitly excluded")
        if not set(self.third_party_asset_refs).issubset(excluded_assets):
            raise ValueError("third-party assets must be explicitly excluded")
        if set(self.site_refs) & set(self.excluded_site_refs):
            raise ValueError("included and excluded site references must be disjoint")

    @property
    def effective_target_count(self) -> int:
        count = sum(ipaddress.ip_network(value).num_addresses for value in self.included_networks)
        count += len(self.included_hosts) + len(self.included_asset_refs)
        count -= sum(ipaddress.ip_network(value).num_addresses for value in self.excluded_networks)
        count -= len(self.excluded_hosts) + len(self.excluded_asset_refs)
        return count

    def _local_dict(self) -> dict[str, object]:
        return {
            name: list(getattr(self, name))
            for name in (
                "included_networks",
                "included_hosts",
                "included_asset_refs",
                "site_refs",
                "excluded_networks",
                "excluded_hosts",
                "excluded_asset_refs",
                "excluded_site_refs",
                "fragile_asset_refs",
                "third_party_asset_refs",
            )
        } | {
            "target_realm": self.target_realm.value,
            "exclusions_reviewed": self.exclusions_reviewed,
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> AssessmentScope:
        tuple_fields = {
            "included_networks": 64,
            "included_hosts": 256,
            "included_asset_refs": 256,
            "site_refs": 64,
            "excluded_networks": 128,
            "excluded_hosts": 512,
            "excluded_asset_refs": 256,
            "excluded_site_refs": 64,
            "fragile_asset_refs": 256,
            "third_party_asset_refs": 256,
        }
        item = expect_exact_dict(
            value,
            label="assessment scope",
            keys=frozenset((*tuple_fields, "target_realm", "exclusions_reviewed")),
        )
        values = {
            name: json_array_as_tuple(item[name], label=name.replace("_", " "), maximum=maximum)
            for name, maximum in tuple_fields.items()
        }
        return cls(
            target_realm=parse_enum(item["target_realm"], ScopeRealm, label="scope target realm"),
            **values,
            exclusions_reviewed=item["exclusions_reviewed"],
        )


@dataclass(frozen=True, slots=True)
class TechniqueBudget:
    technique: Technique
    state: TechniqueState
    max_targets: int
    max_packets_per_target: int
    max_concurrency: int
    timeout_ms: int
    max_duration_seconds: int

    def __post_init__(self) -> None:
        require_enum(self.technique, Technique, label="technique")
        require_enum(self.state, TechniqueState, label="technique state")
        require_bounded_int(self.max_targets, label="maximum targets", minimum=1, maximum=4096)
        require_bounded_int(
            self.max_packets_per_target,
            label="maximum packets per target",
            minimum=0,
            maximum=100,
        )
        require_bounded_int(
            self.max_concurrency, label="maximum concurrency", minimum=1, maximum=16
        )
        require_bounded_int(
            self.timeout_ms, label="timeout milliseconds", minimum=100, maximum=10000
        )
        require_bounded_int(
            self.max_duration_seconds,
            label="maximum duration seconds",
            minimum=1,
            maximum=3600,
        )
        if (
            self.technique is Technique.PASSIVE_ENDPOINT_OBSERVATION_DESIGN
            and self.max_packets_per_target != 0
        ):
            raise ValueError("passive observation design must have a zero packet budget")

    def _local_dict(self) -> dict[str, object]:
        return {
            "technique": self.technique.value,
            "state": self.state.value,
            "max_targets": self.max_targets,
            "max_packets_per_target": self.max_packets_per_target,
            "max_concurrency": self.max_concurrency,
            "timeout_ms": self.timeout_ms,
            "max_duration_seconds": self.max_duration_seconds,
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> TechniqueBudget:
        keys = frozenset(
            {
                "technique",
                "state",
                "max_targets",
                "max_packets_per_target",
                "max_concurrency",
                "timeout_ms",
                "max_duration_seconds",
            }
        )
        item = expect_exact_dict(value, label="technique budget", keys=keys)
        return cls(
            technique=parse_enum(item["technique"], Technique, label="technique"),
            state=parse_enum(item["state"], TechniqueState, label="technique state"),
            max_targets=item["max_targets"],
            max_packets_per_target=item["max_packets_per_target"],
            max_concurrency=item["max_concurrency"],
            timeout_ms=item["timeout_ms"],
            max_duration_seconds=item["max_duration_seconds"],
        )


@dataclass(frozen=True, slots=True)
class VantagePoint:
    vantage_id: str
    site_ref: str
    asset_ref: str
    role: VantageRole
    approved: bool

    def __post_init__(self) -> None:
        require_reference(self.vantage_id, label="vantage ID", prefix="vantage")
        require_reference(self.site_ref, label="vantage site reference", prefix="site")
        require_reference(self.asset_ref, label="vantage asset reference", prefix="asset")
        require_enum(self.role, VantageRole, label="vantage role")
        require_exact_bool(self.approved, label="vantage approval", required=True)

    def _local_dict(self) -> dict[str, object]:
        return {
            "vantage_id": self.vantage_id,
            "site_ref": self.site_ref,
            "asset_ref": self.asset_ref,
            "role": self.role.value,
            "approved": self.approved,
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> VantagePoint:
        keys = frozenset({"vantage_id", "site_ref", "asset_ref", "role", "approved"})
        item = expect_exact_dict(value, label="vantage point", keys=keys)
        return cls(
            vantage_id=item["vantage_id"],
            site_ref=item["site_ref"],
            asset_ref=item["asset_ref"],
            role=parse_enum(item["role"], VantageRole, label="vantage role"),
            approved=item["approved"],
        )


@dataclass(frozen=True, slots=True)
class DataPolicy:
    retention_days: int
    export_policy: ExportPolicy
    deletion_procedure_ref: str
    local_only: bool
    encryption_required: bool

    def __post_init__(self) -> None:
        require_bounded_int(self.retention_days, label="retention days", minimum=0, maximum=90)
        require_enum(self.export_policy, ExportPolicy, label="export policy")
        require_reference(
            self.deletion_procedure_ref,
            label="deletion procedure reference",
            prefix="procedure",
        )
        require_exact_bool(self.local_only, label="local-only policy", required=True)
        require_exact_bool(
            self.encryption_required,
            label="encryption requirement",
            required=True,
        )

    def _local_dict(self) -> dict[str, object]:
        return {
            "retention_days": self.retention_days,
            "export_policy": self.export_policy.value,
            "deletion_procedure_ref": self.deletion_procedure_ref,
            "local_only": self.local_only,
            "encryption_required": self.encryption_required,
        }

    @classmethod
    def _from_local_dict(cls, value: object) -> DataPolicy:
        keys = frozenset(
            {
                "retention_days",
                "export_policy",
                "deletion_procedure_ref",
                "local_only",
                "encryption_required",
            }
        )
        item = expect_exact_dict(value, label="data policy", keys=keys)
        return cls(
            retention_days=item["retention_days"],
            export_policy=parse_enum(item["export_policy"], ExportPolicy, label="export policy"),
            deletion_procedure_ref=item["deletion_procedure_ref"],
            local_only=item["local_only"],
            encryption_required=item["encryption_required"],
        )


@dataclass(frozen=True, slots=True)
class EngagementEnvelope:
    engagement_id: str
    organization_ref: str
    scope_owner_ref: str
    assessor_ref: str
    environment_kind: EnvironmentKind
    purpose: AssessmentPurpose
    sensitivity: DataSensitivity
    window: AssessmentWindow
    authorization: Authorization
    scope: AssessmentScope
    technique_budgets: tuple[TechniqueBudget, ...]
    approved_techniques: tuple[Technique, ...]
    vantage_points: tuple[VantagePoint, ...]
    data_policy: DataPolicy
    status: FoundationStatus = FoundationStatus.DISABLED
    schema_version: str = ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_reference(self.engagement_id, label="engagement ID", prefix="engagement")
        require_reference(self.organization_ref, label="organization reference", prefix="org")
        require_reference(self.scope_owner_ref, label="scope owner reference", prefix="principal")
        require_reference(self.assessor_ref, label="assessor reference", prefix="principal")
        require_enum(self.environment_kind, EnvironmentKind, label="environment kind")
        require_enum(self.purpose, AssessmentPurpose, label="assessment purpose")
        require_enum(self.sensitivity, DataSensitivity, label="data sensitivity")
        if type(self.window) is not AssessmentWindow:
            raise TypeError("window must be an AssessmentWindow")
        if type(self.authorization) is not Authorization:
            raise TypeError("authorization must be an Authorization")
        if type(self.scope) is not AssessmentScope:
            raise TypeError("scope must be an AssessmentScope")
        if type(self.data_policy) is not DataPolicy:
            raise TypeError("data_policy must be a DataPolicy")
        require_enum(self.status, FoundationStatus, label="foundation status")
        if self.schema_version != ENVELOPE_SCHEMA_VERSION:
            raise ValueError("unsupported assessment envelope schema version")

        require_tuple(
            self.technique_budgets,
            label="technique budgets",
            maximum=len(Technique),
            allow_empty=False,
        )
        if any(type(item) is not TechniqueBudget for item in self.technique_budgets):
            raise TypeError("technique budgets must contain TechniqueBudget values")
        require_sorted_unique(
            self.technique_budgets,
            label="technique budgets",
            key=lambda item: item.technique.value,
        )
        techniques = tuple(item.technique for item in self.technique_budgets)
        if len(set(techniques)) != len(techniques):
            raise ValueError("each technique may have only one budget")

        require_tuple(
            self.approved_techniques,
            label="approved techniques",
            maximum=len(Technique),
            allow_empty=False,
        )
        if any(type(item) is not Technique for item in self.approved_techniques):
            raise TypeError("approved techniques must contain Technique values")
        require_sorted_unique(
            self.approved_techniques,
            label="approved techniques",
            key=lambda item: item.value,
        )
        if self.approved_techniques != techniques:
            raise ValueError("approved techniques must exactly match the budgeted techniques")
        for budget in self.technique_budgets:
            if budget.max_targets > self.scope.effective_target_count:
                raise ValueError("a technique target budget exceeds the explicit effective scope")
            if (
                budget.technique
                in {
                    Technique.PRIVATE_SEGMENT_DISCOVERY_DESIGN,
                    Technique.SERVICE_IDENTIFICATION_DESIGN,
                }
                and not self.scope.included_networks
            ):
                raise ValueError(
                    "private discovery and service designs require an included private network"
                )

        require_tuple(
            self.vantage_points,
            label="vantage points",
            maximum=64,
            allow_empty=False,
        )
        if any(type(item) is not VantagePoint for item in self.vantage_points):
            raise TypeError("vantage points must contain VantagePoint values")
        require_sorted_unique(
            self.vantage_points,
            label="vantage points",
            key=lambda item: item.vantage_id,
        )
        if len({item.vantage_id for item in self.vantage_points}) != len(self.vantage_points):
            raise ValueError("vantage IDs must be unique")

        if self.authorization.issued_at > self.window.starts_at:
            raise ValueError("authorization must be issued before the assessment starts")
        if self.authorization.expires_at < self.window.hard_stop_at:
            raise ValueError("authorization must remain valid through the hard stop")
        for vantage in self.vantage_points:
            if vantage.site_ref not in self.scope.site_refs:
                raise ValueError("each vantage point must bind to an included site")
            if vantage.asset_ref not in self.scope.included_asset_refs:
                raise ValueError("each vantage point must bind to an included asset")
            if vantage.asset_ref in self.scope.excluded_asset_refs:
                raise ValueError("an excluded asset cannot be an assessment vantage point")

    def to_local_dict(self) -> dict[str, object]:
        """Return the exact local record; it is sensitive and never share-safe."""

        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "engagement_id": self.engagement_id,
            "organization_ref": self.organization_ref,
            "scope_owner_ref": self.scope_owner_ref,
            "assessor_ref": self.assessor_ref,
            "environment_kind": self.environment_kind.value,
            "purpose": self.purpose.value,
            "sensitivity": self.sensitivity.value,
            "window": self.window._local_dict(),
            "authorization": self.authorization._local_dict(),
            "scope": self.scope._local_dict(),
            "technique_budgets": [item._local_dict() for item in self.technique_budgets],
            "approved_techniques": [item.value for item in self.approved_techniques],
            "vantage_points": [item._local_dict() for item in self.vantage_points],
            "data_policy": self.data_policy._local_dict(),
        }

    def to_canonical_json(self) -> str:
        """Serialize the sensitive local record deterministically."""

        return json.dumps(
            self.to_local_dict(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def local_digest(self) -> str:
        """Tamper-evident correlation digest; not a confidentiality mechanism."""

        return hashlib.sha256(self.to_canonical_json().encode("ascii")).hexdigest()

    @classmethod
    def from_local_dict(cls, value: object) -> EngagementEnvelope:
        keys = frozenset(
            {
                "schema_version",
                "status",
                "engagement_id",
                "organization_ref",
                "scope_owner_ref",
                "assessor_ref",
                "environment_kind",
                "purpose",
                "sensitivity",
                "window",
                "authorization",
                "scope",
                "technique_budgets",
                "approved_techniques",
                "vantage_points",
                "data_policy",
            }
        )
        item = expect_exact_dict(value, label="engagement envelope", keys=keys)
        budget_values = json_array_as_tuple(
            item["technique_budgets"], label="technique budgets", maximum=len(Technique)
        )
        approved_values = json_array_as_tuple(
            item["approved_techniques"], label="approved techniques", maximum=len(Technique)
        )
        vantage_values = json_array_as_tuple(
            item["vantage_points"], label="vantage points", maximum=64
        )
        return cls(
            schema_version=item["schema_version"],
            status=parse_enum(item["status"], FoundationStatus, label="foundation status"),
            engagement_id=item["engagement_id"],
            organization_ref=item["organization_ref"],
            scope_owner_ref=item["scope_owner_ref"],
            assessor_ref=item["assessor_ref"],
            environment_kind=parse_enum(
                item["environment_kind"], EnvironmentKind, label="environment kind"
            ),
            purpose=parse_enum(item["purpose"], AssessmentPurpose, label="assessment purpose"),
            sensitivity=parse_enum(item["sensitivity"], DataSensitivity, label="data sensitivity"),
            window=AssessmentWindow._from_local_dict(item["window"]),
            authorization=Authorization._from_local_dict(item["authorization"]),
            scope=AssessmentScope._from_local_dict(item["scope"]),
            technique_budgets=tuple(
                TechniqueBudget._from_local_dict(value) for value in budget_values
            ),
            approved_techniques=tuple(
                parse_enum(value, Technique, label="approved technique")
                for value in approved_values
            ),
            vantage_points=tuple(VantagePoint._from_local_dict(value) for value in vantage_values),
            data_policy=DataPolicy._from_local_dict(item["data_policy"]),
        )

    @classmethod
    def from_canonical_json(cls, value: object) -> EngagementEnvelope:
        if type(value) is not str:
            raise TypeError("assessment envelope JSON must be a string")
        if not value.isascii():
            raise ValueError("assessment envelope JSON must use canonical ASCII encoding")
        if len(value.encode("ascii")) > 65536:
            raise ValueError("assessment envelope JSON exceeds 64 KiB")

        def reject_constant(constant: str) -> None:
            raise ValueError(f"non-finite JSON value {constant} is not permitted")

        def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key {key!r} is not permitted")
                result[key] = item
            return result

        try:
            parsed = json.loads(
                value,
                parse_constant=reject_constant,
                object_pairs_hook=exact_object,
            )
        except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
            raise ValueError("assessment envelope is not valid JSON") from exc
        stack: list[tuple[object, int]] = [(parsed, 0)]
        visited = 0
        while stack:
            current, depth = stack.pop()
            visited += 1
            if depth > 32:
                raise ValueError("assessment envelope JSON nesting exceeds 32 levels")
            if visited > 10000:
                raise ValueError("assessment envelope JSON contains too many values")
            if type(current) is dict:
                stack.extend((item, depth + 1) for item in current.values())
            elif type(current) is list:
                stack.extend((item, depth + 1) for item in current)
        envelope = cls.from_local_dict(parsed)
        if envelope.to_canonical_json() != value:
            raise ValueError("assessment envelope JSON must use canonical encoding")
        return envelope


@dataclass(frozen=True, slots=True)
class CoveragePlanItem:
    step_id: str
    technique: Technique
    technique_state: TechniqueState
    coverage_state: CoverageState
    vantage_ids: tuple[str, ...]
    authorized_target_cap: int
    packet_cap: int
    concurrency_cap: int
    timeout_ms: int
    duration_cap_seconds: int

    def __post_init__(self) -> None:
        require_reference(self.step_id, label="coverage step ID", prefix="step")
        require_enum(self.technique, Technique, label="coverage technique")
        require_enum(self.technique_state, TechniqueState, label="coverage technique state")
        require_enum(self.coverage_state, CoverageState, label="coverage state")
        require_tuple(self.vantage_ids, label="coverage vantage IDs", maximum=64, allow_empty=False)
        require_sorted_unique(self.vantage_ids, label="coverage vantage IDs")
        for value in self.vantage_ids:
            require_reference(value, label="coverage vantage ID", prefix="vantage")
        require_bounded_int(
            self.authorized_target_cap,
            label="authorized target cap",
            minimum=1,
            maximum=4096,
        )
        require_bounded_int(self.packet_cap, label="packet cap", minimum=0, maximum=409600)
        require_bounded_int(self.concurrency_cap, label="concurrency cap", minimum=1, maximum=16)
        require_bounded_int(self.timeout_ms, label="coverage timeout", minimum=100, maximum=10000)
        require_bounded_int(
            self.duration_cap_seconds,
            label="coverage duration cap",
            minimum=1,
            maximum=3600,
        )

    def _digest_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "technique": self.technique.value,
            "technique_state": self.technique_state.value,
            "coverage_state": self.coverage_state.value,
            "vantage_ids": list(self.vantage_ids),
            "authorized_target_cap": self.authorized_target_cap,
            "packet_cap": self.packet_cap,
            "concurrency_cap": self.concurrency_cap,
            "timeout_ms": self.timeout_ms,
            "duration_cap_seconds": self.duration_cap_seconds,
        }


@dataclass(frozen=True, slots=True)
class CoveragePlan:
    engagement_id: str
    engagement_digest: str
    generated_at: datetime
    items: tuple[CoveragePlanItem, ...]
    status: FoundationStatus = FoundationStatus.DISABLED
    schema_version: str = PLAN_SCHEMA_VERSION
    plan_digest: str = field(init=False)

    def __post_init__(self) -> None:
        require_reference(self.engagement_id, label="plan engagement ID", prefix="engagement")
        if (
            type(self.engagement_digest) is not str
            or len(self.engagement_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.engagement_digest)
        ):
            raise ValueError("engagement digest must be a lowercase SHA-256 digest")
        require_utc_second(self.generated_at, label="plan generation time")
        require_tuple(
            self.items, label="coverage plan items", maximum=len(Technique), allow_empty=False
        )
        if any(type(item) is not CoveragePlanItem for item in self.items):
            raise TypeError("coverage plan items must contain CoveragePlanItem values")
        require_sorted_unique(
            self.items, label="coverage plan items", key=lambda item: item.step_id
        )
        require_enum(self.status, FoundationStatus, label="plan status")
        if self.schema_version != PLAN_SCHEMA_VERSION:
            raise ValueError("unsupported coverage plan schema version")
        object.__setattr__(self, "plan_digest", self._calculate_digest())

    def _calculate_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "engagement_id": self.engagement_id,
            "engagement_digest": self.engagement_digest,
            "generated_at": format_utc_second(self.generated_at),
            "items": [item._digest_dict() for item in self.items],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    def assert_integrity(self) -> None:
        if self.plan_digest != self._calculate_digest():
            raise ValueError("coverage plan digest does not match its immutable plan")

    def assert_matches(self, envelope: EngagementEnvelope) -> None:
        """Fail closed unless every plan field derives from this exact envelope."""

        if type(envelope) is not EngagementEnvelope:
            raise TypeError("envelope must be an EngagementEnvelope")
        self.assert_integrity()
        if self.engagement_id != envelope.engagement_id:
            raise ValueError("coverage plan belongs to a different engagement")
        if self.engagement_digest != envelope.local_digest:
            raise ValueError("coverage plan no longer matches the engagement envelope")
        if not envelope.authorization.is_current(now=self.generated_at):
            raise ValueError("coverage plan was not generated under current authorization")
        if self.generated_at >= envelope.window.hard_stop_at:
            raise ValueError("coverage plan was generated at or after the hard stop")
        if len(self.items) != len(envelope.technique_budgets):
            raise ValueError("coverage plan does not cover every approved technique exactly once")

        expected_vantages = tuple(item.vantage_id for item in envelope.vantage_points)
        for index, (item, budget) in enumerate(
            zip(self.items, envelope.technique_budgets, strict=True), start=1
        ):
            expected_step_id = f"step.{index:02d}.{budget.technique.value.replace('_', '-')}"
            if item.step_id != expected_step_id or item.technique is not budget.technique:
                raise ValueError("coverage plan technique or ordering does not match authorization")
            if item.technique_state is not TechniqueState.DESIGN_ONLY:
                raise ValueError("coverage plan technique state must remain design-only")
            if item.coverage_state is not CoverageState.NOT_ASSESSED_DESIGN_ONLY:
                raise ValueError("coverage plan must not claim observed coverage")
            if item.vantage_ids != expected_vantages:
                raise ValueError("coverage plan contains an unknown or omitted vantage point")
            if item.authorized_target_cap != budget.max_targets:
                raise ValueError("coverage plan target cap does not match the technique budget")
            if item.authorized_target_cap > envelope.scope.effective_target_count:
                raise ValueError("coverage plan target cap exceeds the effective scope")
            if item.packet_cap != budget.max_targets * budget.max_packets_per_target:
                raise ValueError("coverage plan packet cap does not match the technique budget")
            if (
                item.concurrency_cap != budget.max_concurrency
                or item.timeout_ms != budget.timeout_ms
                or item.duration_cap_seconds != budget.max_duration_seconds
            ):
                raise ValueError("coverage plan runtime caps do not match the technique budget")
