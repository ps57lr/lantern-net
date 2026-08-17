from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone

import pytest

from netdiag.core.access import (
    AccessPrerequisite,
    AccessState,
    PermissionRequirement,
    PermissionState,
)
from netdiag.core.evidence import Evidence
from netdiag.core.execution import CheckSpec
from netdiag.core.registry import (
    CheckRegistry,
    DefinitionState,
    DuplicateRegistrationError,
    EvidenceKindDefinition,
    EvidenceKindRegistry,
    ExplicitRegistry,
    FindingDefinition,
    FindingRegistry,
    FrozenRegistryError,
    RegistryValidationError,
)
from netdiag.core.status import ActivityLevel, OutcomeStatus, Sensitivity


def test_access_contracts_have_no_secret_value_fields():
    forbidden = {"password", "token", "credential", "secret", "recovery_key", "value"}
    for model in (PermissionRequirement, AccessPrerequisite):
        assert forbidden.isdisjoint(item.name for item in fields(model))

    permission = PermissionRequirement(
        "netdiag.permission.local_admin",
        "netdiag.permission_kind.local_admin",
        "Darwin",
        "local machine",
        PermissionState.UNKNOWN,
        "A separately approved action needs operating-system authorization.",
        "Use the native authorization prompt when asked.",
    )
    prerequisite = AccessPrerequisite(
        "netdiag.access.router_admin",
        "netdiag.access_kind.router_admin",
        "Router administrator",
        "default gateway",
        AccessState.REQUIRED,
        "A remaining guided step changes router configuration.",
        ("netdiag.action.router.guided_change",),
    )
    assert permission.to_dict()["state"] == "unknown"
    assert prerequisite.to_dict()["state"] == "required"
    assert "password" not in str(prerequisite.to_dict()).lower()


def test_access_export_withholds_arbitrary_prose_canaries() -> None:
    canary = "recovery-key-111111-222222"
    permission = PermissionRequirement(
        "netdiag.permission.fixture",
        "netdiag.permission_kind.fixture",
        "Darwin",
        f"scope {canary}",
        PermissionState.UNKNOWN,
        f"reason password=hunter2 {canary}",
        f"hint {canary}",
    )
    prerequisite = AccessPrerequisite(
        "netdiag.access.fixture",
        "netdiag.access_kind.fixture",
        f"label {canary}",
        f"scope {canary}",
        AccessState.REQUIRED,
        f"reason password=hunter2 {canary}",
        ("netdiag.action.fixture",),
    )
    for payload in (permission.to_dict(), prerequisite.to_dict()):
        assert canary not in str(payload)
        assert "hunter2" not in str(payload)
        assert "<redacted>" in str(payload)


@pytest.mark.parametrize(
    "unsafe_ref",
    ("password=hunter2", "recovery-key=abc", "bad ref"),
)
def test_access_references_require_identifier_syntax(unsafe_ref: str) -> None:
    with pytest.raises(ValueError, match="lower-case dotted identifier"):
        AccessPrerequisite(
            "netdiag.access.fixture",
            "netdiag.access_kind.fixture",
            "Fixture access",
            "local",
            AccessState.REQUIRED,
            "Fixture reason",
            (unsafe_ref,),
        )


def test_access_export_redacts_prefix_smuggled_identifier_prose() -> None:
    prerequisite = AccessPrerequisite(
        "netdiag.access.family-mac.local",
        "netdiag.access_kind.password-hunter2",
        "Fixture access",
        "local",
        AccessState.REQUIRED,
        "Fixture reason",
        ("evidence.recovery-key-abc",),
    )
    payload = str(prerequisite.to_dict())
    for canary in ("family-mac.local", "password-hunter2", "recovery-key-abc"):
        assert canary not in payload


def test_permission_platform_is_exact_and_revalidated_for_export() -> None:
    with pytest.raises(ValueError, match="canonical platform"):
        PermissionRequirement(
            "netdiag.permission.fixture",
            "netdiag.permission_kind.fixture",
            "password=hunter2",
            "local",
            PermissionState.UNKNOWN,
            "Fixture reason",
        )

    permission = PermissionRequirement(
        "netdiag.permission.fixture",
        "netdiag.permission_kind.fixture",
        "Darwin",
        "local",
        PermissionState.UNKNOWN,
        "Fixture reason",
    )
    object.__setattr__(permission, "platform", "password=hunter2")
    with pytest.raises(ValueError, match="canonical platform"):
        permission.to_dict()


def test_access_state_fields_are_revalidated_for_export() -> None:
    permission = PermissionRequirement(
        "netdiag.permission.fixture",
        "netdiag.permission_kind.fixture",
        "Darwin",
        "local",
        PermissionState.UNKNOWN,
        "Fixture reason",
    )
    object.__setattr__(permission, "state", "password=hunter2")
    with pytest.raises(TypeError, match="PermissionState"):
        permission.to_dict()

    prerequisite = AccessPrerequisite(
        "netdiag.access.fixture",
        "netdiag.access_kind.fixture",
        "Fixture access",
        "local",
        AccessState.REQUIRED,
        "Fixture reason",
    )
    object.__setattr__(prerequisite, "state", "family-mac.local")
    with pytest.raises(TypeError, match="AccessState"):
        prerequisite.to_dict()


def test_explicit_registry_rejects_duplicate_batch_atomically_and_freezes():
    registry: ExplicitRegistry[str] = ExplicitRegistry(lambda value: value)
    registry.register("one")
    with pytest.raises(DuplicateRegistrationError):
        registry.register_many(("two", "two"))
    assert registry.identifiers() == ("one",)
    registry.freeze()
    with pytest.raises(FrozenRegistryError):
        registry.register("three")


def _collector(_context):
    raise AssertionError("registry tests do not execute collectors")


def _check(check_id: str, dependencies: tuple[str, ...] = ()) -> CheckSpec:
    return CheckSpec(
        check_id,
        _collector,
        ActivityLevel.PASSIVE,
        ("Darwin", "Linux"),
        dependencies,
    )


def test_check_registry_returns_deterministic_topological_order():
    registry = CheckRegistry()
    registry.register_many(
        (
            _check("netdiag.check.lan", ("netdiag.check.route",)),
            _check("netdiag.check.dns", ("netdiag.check.route",)),
            _check("netdiag.check.route"),
        )
    )
    assert tuple(item.check_id for item in registry.ordered()) == (
        "netdiag.check.route",
        "netdiag.check.dns",
        "netdiag.check.lan",
    )


def test_check_registry_rejects_unknown_dependencies_and_cycles():
    unknown = CheckRegistry()
    unknown.register(_check("netdiag.check.lan", ("netdiag.check.route",)))
    with pytest.raises(RegistryValidationError, match="unknown"):
        unknown.freeze()

    cyclic = CheckRegistry()
    cyclic.register_many(
        (
            _check("netdiag.check.a", ("netdiag.check.b",)),
            _check("netdiag.check.b", ("netdiag.check.a",)),
        )
    )
    with pytest.raises(RegistryValidationError, match="cycle"):
        cyclic.freeze()


def test_finding_registry_validates_supersession_graph():
    successor = FindingDefinition(
        "NDG.ROUTE.DEFAULT_ROUTE_MISSING",
        "route",
        "No default route",
        "No usable default route was observed.",
    )
    predecessor = FindingDefinition(
        "NDG.ROUTE.NO_GATEWAY_LEGACY",
        "route",
        "No gateway",
        "Legacy meaning.",
        state=DefinitionState.DEPRECATED,
        superseded_by=successor.code,
    )
    registry = FindingRegistry()
    registry.register_many((predecessor, successor))
    assert registry.freeze().require(predecessor.code) is predecessor

    broken = FindingRegistry()
    broken.register(predecessor)
    with pytest.raises(RegistryValidationError, match="unknown successor"):
        broken.freeze()


def test_finding_registry_detects_post_freeze_definition_mutation_without_resealing():
    definition = FindingDefinition(
        "NDG.FIXTURE.MUTATION",
        "fixture",
        "Reviewed fixture title",
        "Reviewed fixture detail.",
    )
    registry = FindingRegistry()
    registry.register(definition)
    registry.freeze()

    original = definition.title_template
    object.__setattr__(definition, "title_template", "Changed but still structurally valid")
    try:
        for operation in (
            lambda: registry.get(definition.code),
            lambda: registry.require(definition.code),
            registry.snapshot,
            registry.identifiers,
            registry.freeze,
            lambda: tuple(registry),
        ):
            with pytest.raises(RegistryValidationError, match="integrity"):
                operation()
    finally:
        object.__setattr__(definition, "title_template", original)

    assert registry.require(definition.code) is definition


def test_product_finding_registry_rejects_mutated_reviewed_template() -> None:
    from netdiag.catalog import FINDING_REGISTRY

    definition = FINDING_REGISTRY.require("NDG.WIFI.CONNECTED")
    original = definition.detail_template
    object.__setattr__(definition, "detail_template", "Password={summary}")
    try:
        # The replacement is syntactically valid, so this specifically proves
        # the independent frozen-content snapshot is enforced.
        definition.__post_init__()
        with pytest.raises(RegistryValidationError, match="integrity"):
            FINDING_REGISTRY.require(definition.code)
        with pytest.raises(RegistryValidationError, match="integrity"):
            FINDING_REGISTRY.snapshot()
    finally:
        object.__setattr__(definition, "detail_template", original)

    assert FINDING_REGISTRY.require(definition.code) is definition


def test_evidence_kind_registry_enforces_registered_payload_type():
    registry = EvidenceKindRegistry()
    registry.register(
        EvidenceKindDefinition(
            "netdiag.evidence.route.default",
            dict,
            description="Default route snapshot",
        )
    )
    item = Evidence(
        "evidence-1",
        "netdiag.evidence.route.default",
        "netdiag.check.route",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.fixture",
        datetime(2026, 8, 16, tzinfo=timezone.utc),
        1,
        ["wrong payload type"],
    )
    with pytest.raises(RegistryValidationError, match="expects dict"):
        registry.validate_evidence(item)


def test_evidence_kind_registry_prevents_sensitivity_downgrade():
    registry = EvidenceKindRegistry()
    registry.register(
        EvidenceKindDefinition(
            "netdiag.evidence.device.identity",
            dict,
            default_sensitivity=Sensitivity.DEVICE_IDENTIFIER,
        )
    )
    item = Evidence(
        "evidence-1",
        "netdiag.evidence.device.identity",
        "netdiag.check.device",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.fixture",
        datetime(2026, 8, 16, tzinfo=timezone.utc),
        1,
        {"hostname": "family-mac"},
        sensitivity=Sensitivity.PUBLIC,
    )
    with pytest.raises(RegistryValidationError, match="does not match"):
        registry.validate_evidence(item)
