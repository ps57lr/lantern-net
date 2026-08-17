from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from netdiag.core.diagnostics import Confidence
from netdiag.core.evidence import (
    DuplicateEvidenceError,
    ErrorDetail,
    Evidence,
    EvidenceStore,
)
from netdiag.core.execution import (
    CancellationToken,
    CancelledError,
    CheckResult,
    CheckSpec,
    ScanPolicy,
)
from netdiag.core.redaction import RedactionPolicy, StructuralSensitivityMap
from netdiag.core.status import (
    ActivityLevel,
    ConfidenceLevel,
    ExecutionStatus,
    OutcomeStatus,
    Sensitivity,
)

NOW = datetime(2026, 8, 16, tzinfo=timezone.utc)


def evidence(
    evidence_id: str = "evidence-1",
    *,
    kind: str = "netdiag.evidence.route.default",
    check_id: str = "netdiag.check.route",
    payload: object = None,
    status: OutcomeStatus = OutcomeStatus.INFORMATIONAL,
) -> Evidence[object]:
    return Evidence(
        evidence_id=evidence_id,
        kind=kind,
        check_id=check_id,
        status=status,
        source="netdiag.source.fixture",
        observed_at=NOW,
        duration_ms=4,
        payload={} if payload is None else payload,
    )


def test_error_detail_does_not_copy_unknown_exception_text():
    detail = ErrorDetail.unexpected("netdiag.route.collect", RuntimeError("password=hunter2"))
    assert detail.code == "netdiag.route.collect.unexpected"
    assert "hunter2" not in detail.message
    assert detail.message == "Unexpected collector error"


@pytest.mark.parametrize(
    "unsafe_ref",
    ("password=hunter2", "recovery-key=abc", "bad ref"),
)
def test_confidence_references_require_identifier_syntax(unsafe_ref: str) -> None:
    with pytest.raises(ValueError, match="lower-case dotted identifier"):
        Confidence(ConfidenceLevel.LOW, "Fixture rationale", (unsafe_ref,))


def test_standalone_evidence_and_confidence_redact_unregistered_identifiers() -> None:
    item = Evidence(
        "evidence.family-mac.local",
        "netdiag.evidence.password-hunter2",
        "netdiag.check.recovery-key-abc",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.family-router.local",
        NOW,
        1,
        {},
    )
    confidence = Confidence(
        ConfidenceLevel.LOW,
        "Fixture rationale",
        ("evidence.family-mac.local",),
    )
    payload = str(item.to_dict()) + str(confidence.to_dict())
    for canary in (
        "family-mac.local",
        "password-hunter2",
        "recovery-key-abc",
        "family-router.local",
    ):
        assert canary not in payload


def test_evidence_validates_time_duration_health_and_error_invariants():
    with pytest.raises(ValueError, match="timezone"):
        Evidence(
            "evidence-1",
            "netdiag.evidence.test",
            "netdiag.check.test",
            OutcomeStatus.INFORMATIONAL,
            "netdiag.source.fixture",
            datetime(2026, 1, 1),  # noqa: DTZ001 - deliberately exercises rejection.
            0,
            {},
        )
    with pytest.raises(ValueError, match="healthy evidence must include"):
        Evidence(
            "evidence-1",
            "netdiag.evidence.test",
            "netdiag.check.test",
            OutcomeStatus.HEALTHY,
            "netdiag.source.fixture",
            NOW,
            0,
            None,
        )


def test_evidence_envelope_sensitivity_masks_whole_payload():
    item = Evidence(
        "evidence-1",
        "netdiag.evidence.device.snapshot",
        "netdiag.check.device",
        OutcomeStatus.INFORMATIONAL,
        "netdiag.source.fixture",
        NOW,
        1,
        {"hostname": "family-mac", "nested": [1, 2]},
        sensitivity=Sensitivity.DEVICE_IDENTIFIER,
    )
    raw = item.to_dict(policy=RedactionPolicy.raw())
    shared = item.to_dict(policy=RedactionPolicy.share_safe())
    assert raw["payload"] == {"hostname": "family-mac", "nested": [1, 2]}
    assert shared["payload"] == "<device-1>"


def test_share_safe_evidence_fails_closed_for_unclassified_nested_leaves():
    item = evidence(
        payload={
            "hostname": "family-mac.local",
            "nested": {"password": "hunter2"},
        }
    )
    shared = item.to_dict(policy=RedactionPolicy.share_safe())
    assert shared["payload"] == {
        "<field-1>": "<redacted>",
        "<field-2>": {"<field-3>": "<redacted>"},
    }
    assert "family-mac" not in str(shared)
    assert "hunter2" not in str(shared)


def test_default_evidence_export_never_emits_unclassified_public_payload() -> None:
    item = evidence(payload={"password": "hunter2", "hostname": "family-mac.local"})
    payload = item.to_dict()
    assert payload["payload"] == {
        "<field-1>": "<redacted>",
        "<field-2>": "<redacted>",
    }
    assert "hunter2" not in str(payload)
    assert "family-mac" not in str(payload)


def test_share_safe_evidence_requires_explicit_public_allowlist():
    item = evidence(
        payload={
            "latency_ms": 12,
            "hostname": "family-mac.local",
            "password": "hunter2",
        }
    )
    classification = StructuralSensitivityMap.from_json_pointers(
        {
            "/latency_ms": Sensitivity.PUBLIC,
            "/hostname": Sensitivity.DEVICE_IDENTIFIER,
            "/password": Sensitivity.POTENTIAL_SECRET,
        },
        default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
    )
    shared = item.to_dict(
        policy=RedactionPolicy.share_safe(),
        sensitivity_map=classification,
    )
    assert shared["payload"] == {
        "latency_ms": 12,
        "hostname": "<device-1>",
        "password": "<redacted>",
    }


def test_error_detail_prose_is_not_exported() -> None:
    item = Evidence(
        "evidence-1",
        "netdiag.evidence.fixture",
        "netdiag.check.fixture",
        OutcomeStatus.FAILED,
        "netdiag.source.fixture",
        NOW,
        1,
        {},
        error=ErrorDetail("netdiag.fixture.failed", "password=hunter2"),
    )
    shared = item.to_dict(policy=RedactionPolicy.share_safe())
    assert shared["error"]["code"] == "<redacted>"
    assert shared["error"]["message"] == "<redacted>"
    assert "hunter2" not in str(shared)


def test_evidence_and_confidence_revalidate_mutated_public_fields() -> None:
    detail = ErrorDetail("netdiag.fixture.failed", "Expected fixture error")
    item = Evidence(
        "evidence-1",
        "netdiag.evidence.fixture",
        "netdiag.check.fixture",
        OutcomeStatus.FAILED,
        "netdiag.source.fixture",
        NOW,
        1,
        {},
        error=detail,
    )
    object.__setattr__(detail, "retryable", "family-mac.local")
    with pytest.raises(TypeError, match="retryable"):
        item.to_dict()

    confidence = Confidence(ConfidenceLevel.LOW, "Fixture rationale")
    object.__setattr__(confidence, "level", "password=hunter2")
    with pytest.raises(TypeError, match="ConfidenceLevel"):
        confidence.to_dict()


def test_evidence_store_preserves_order_and_rejects_batch_atomically():
    first = evidence("evidence-1")
    second = evidence("evidence-2")
    store = EvidenceStore((first,))
    with pytest.raises(DuplicateEvidenceError):
        store.extend((second, first))
    assert store.snapshot() == (first,)
    store.add(second)
    assert tuple(item.evidence_id for item in store) == ("evidence-1", "evidence-2")
    assert store.by_kind(first.kind) == (first, second)


@dataclass
class FakeClock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value


def test_cancellation_token_supports_manual_and_deadline_cancellation():
    manual = CancellationToken()
    assert manual.cancel("user stopped") is True
    assert manual.cancel("later") is False
    assert manual.reason == "user stopped"
    with pytest.raises(CancelledError, match="user stopped"):
        manual.raise_if_cancelled()

    clock = FakeClock()
    deadline = CancellationToken.with_timeout(5, clock=clock)
    assert deadline.remaining_seconds() == 5
    clock.value += 5
    assert deadline.is_cancelled
    assert deadline.reason == "deadline exceeded"


def _collector(_context):
    raise AssertionError("metadata-only test must not run a collector")


def test_scan_policy_enforces_activity_and_explicit_scope():
    active = CheckSpec(
        "netdiag.check.lan.active",
        _collector,
        ActivityLevel.ACTIVE_DISCOVERY,
        ("Darwin", "Linux"),
        requires_explicit_scope=True,
    )
    passive = ScanPolicy()
    assert not passive.evaluate(active).allowed

    no_scope = ScanPolicy(maximum_activity=ActivityLevel.ACTIVE_DISCOVERY)
    assert not no_scope.evaluate(active).allowed

    scoped = ScanPolicy(
        maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
        allowed_networks=("192.168.1.0/24",),
    )
    assert scoped.allowed_networks == ("192.168.1.0/24",)
    assert scoped.evaluate(active).allowed

    with pytest.raises(ValueError, match="exact canonical CIDR"):
        ScanPolicy(
            maximum_activity=ActivityLevel.ACTIVE_DISCOVERY,
            allowed_networks=("192.168.1.42/24",),
        )


def test_scan_policy_scope_collections_are_exact_typed_immutable_tuples():
    with pytest.raises(TypeError, match="immutable tuple"):
        ScanPolicy(allowed_networks=["192.168.1.0/24"])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="canonical CIDR strings"):
        ScanPolicy(
            allowed_networks=(ipaddress.ip_network("192.168.1.0/24"),)  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="must be unique"):
        ScanPolicy(allowed_targets=("192.168.1.1", "192.168.1.1"))


def test_active_check_metadata_cannot_omit_scope_requirement():
    with pytest.raises(ValueError, match="must require explicit scope"):
        CheckSpec(
            "netdiag.check.unsafe",
            _collector,
            ActivityLevel.ACTIVE_DISCOVERY,
            ("Linux",),
        )


def test_check_result_rejects_foreign_evidence_and_failed_without_error():
    foreign = evidence(check_id="netdiag.check.other")
    with pytest.raises(ValueError, match="belong"):
        CheckResult(
            "netdiag.check.route",
            ExecutionStatus.COMPLETED,
            (foreign,),
            NOW,
            1,
        )
    with pytest.raises(ValueError, match="must include an error"):
        CheckResult(
            "netdiag.check.route",
            ExecutionStatus.FAILED,
            (),
            NOW,
            1,
        )
