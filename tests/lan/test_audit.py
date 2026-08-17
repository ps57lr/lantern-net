from __future__ import annotations

import json

import pytest

from netdiag.lan.audit import (
    AuditAction,
    AuditEvent,
    AuditEventKind,
    AuditLog,
    AuditOutcome,
    AuditReason,
)
from tests.lan.helpers import CounterRandom, aware_now


def audit_log(*, maximum_events: int = 32) -> AuditLog:
    return AuditLog(
        maximum_events=maximum_events,
        wall_clock=aware_now,
        random_bytes=CounterRandom(),
    )


def test_audit_event_is_typed_complete_and_contains_no_source_address() -> None:
    log = audit_log()
    event = log.record(
        AuditEventKind.PAIRING_SUCCEEDED,
        AuditOutcome.ALLOWED,
        source_address="192.168.50.20",
        session_id="a" * 24,
        action=AuditAction.PAIR,
        reason=AuditReason.HOST_APPROVED,
    )
    payload = event.as_dict()
    assert payload["event_id"] == "event-00000001"
    assert payload["occurred_at"].endswith("+00:00")
    assert payload["kind"] == "pairing_succeeded"
    assert payload["session_ref"] == "a" * 24
    assert payload["source_ref"].startswith("source-")
    assert "192.168.50.20" not in json.dumps(payload)


def test_source_pseudonyms_are_stable_only_within_one_run() -> None:
    first = audit_log()
    same_a = first.source_reference("192.168.50.20")
    same_b = first.source_reference("192.168.50.20")
    different = first.source_reference("192.168.50.21")
    second = AuditLog(wall_clock=aware_now, random_bytes=CounterRandom(start=90))
    assert same_a == same_b
    assert same_a != different
    assert same_a != second.source_reference("192.168.50.20")


def test_bounded_ring_discards_oldest_events() -> None:
    log = audit_log(maximum_events=16)
    assert log.maximum_events == 16
    for _index in range(25):
        log.record(AuditEventKind.CONNECTION_OBSERVED, AuditOutcome.ALLOWED)
    events = log.snapshot()
    assert len(events) == 16
    assert events[0].sequence == 10
    assert events[-1].sequence == 25
    assert log.snapshot(limit=2) == events[-2:]
    assert log.snapshot(limit=0) == ()


def test_audit_api_has_no_free_form_secret_or_report_field() -> None:
    log = audit_log()
    with pytest.raises(TypeError):
        log.record(  # type: ignore[arg-type]
            AuditEventKind.SCAN_REQUESTED,
            AuditOutcome.ALLOWED,
            action="password=hunter2",
        )
    with pytest.raises(TypeError):
        log.record(  # type: ignore[arg-type]
            AuditEventKind.SCAN_REQUESTED,
            AuditOutcome.ALLOWED,
            reason="SSID Family WiFi AA:BB:CC:DD:EE:FF",
        )
    with pytest.raises(TypeError):
        log.record(  # type: ignore[call-arg]
            AuditEventKind.SCAN_REQUESTED,
            AuditOutcome.ALLOWED,
            detail={"report": "secret"},
        )


def test_invalid_session_reference_and_clock_fail_closed() -> None:
    log = audit_log()
    with pytest.raises(ValueError, match="safe audit reference"):
        log.record(
            AuditEventKind.SESSION_REVOKED,
            AuditOutcome.REVOKED,
            session_id="pair-code-or-token",
        )
    naive = AuditLog(wall_clock=lambda: aware_now().replace(tzinfo=None))
    with pytest.raises(ValueError, match="timezone-aware"):
        naive.record(AuditEventKind.CONNECTION_OBSERVED, AuditOutcome.ALLOWED)


def test_close_erases_retained_events_and_rejects_further_use() -> None:
    log = audit_log()
    log.record(AuditEventKind.SERVICE_STARTED, AuditOutcome.COMPLETED)
    log.close()
    assert log.snapshot() == ()
    with pytest.raises(RuntimeError, match="closed"):
        log.record(AuditEventKind.SERVICE_STOPPED, AuditOutcome.COMPLETED)


def test_canary_secrets_never_appear_in_serialized_events() -> None:
    log = audit_log()
    log.record(
        AuditEventKind.REPORT_EXPORTED,
        AuditOutcome.COMPLETED,
        source_address="192.168.50.20",
        session_id="b" * 24,
        action=AuditAction.EXPORT_REDACTED_REPORT,
    )
    serialized = json.dumps([event.as_dict() for event in log.snapshot()])
    for canary in (
        "PAIRCODE",
        "bearer-token",
        "router-password",
        "Family WiFi",
        "AA:BB:CC:DD:EE:FF",
        "192.168.50.20",
        "full_report",
    ):
        assert canary not in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "event-password=hunter2"),
        ("occurred_at", "family-mac.local"),
        ("kind", "password=hunter2"),
        ("outcome", "family-mac.local"),
        ("source_ref", "source-recovery-key"),
        ("session_ref", "router-password=hunter2"),
        ("action", "password=hunter2"),
        ("reason", "family-mac.local"),
    ],
)
def test_direct_or_mutated_audit_events_cannot_export_unregistered_text(
    field: str,
    value: object,
) -> None:
    values = {
        "sequence": 1,
        "event_id": "event-00000001",
        "occurred_at": aware_now().isoformat(),
        "kind": AuditEventKind.SCAN_REQUESTED.value,
        "outcome": AuditOutcome.ALLOWED.value,
        "source_ref": "source-0123456789abcdef",
        "session_ref": "a" * 24,
        "action": AuditAction.RUN_PASSIVE.value,
        "reason": AuditReason.HOST_APPROVED.value,
    }
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        AuditEvent(**values).as_dict()

    valid = audit_log().record(
        AuditEventKind.SCAN_REQUESTED,
        AuditOutcome.ALLOWED,
        source_address="192.0.2.1",
        session_id="a" * 24,
        action=AuditAction.RUN_PASSIVE,
        reason=AuditReason.HOST_APPROVED,
    )
    object.__setattr__(valid, field, value)
    with pytest.raises((TypeError, ValueError)):
        valid.as_dict()


def test_valid_shaped_direct_event_is_not_accepted_without_audit_log_issuance() -> None:
    with pytest.raises(ValueError, match="not issued by AuditLog"):
        AuditEvent(
            sequence=1,
            event_id="event-00000001",
            occurred_at=aware_now().isoformat(),
            kind=AuditEventKind.SCAN_REQUESTED.value,
            outcome=AuditOutcome.ALLOWED.value,
            source_ref="source-deadbeefdeadbeef",
            session_ref="d" * 24,
            action=AuditAction.RUN_PASSIVE.value,
            reason=AuditReason.HOST_APPROVED.value,
        )


@pytest.mark.parametrize(
    ("field", "valid_shaped_secret"),
    [
        ("source_ref", "source-deadbeefdeadbeef"),
        ("session_ref", "d" * 24),
    ],
)
def test_valid_shaped_secret_mutation_cannot_be_resealed_or_exported(
    field: str,
    valid_shaped_secret: str,
) -> None:
    event = audit_log().record(
        AuditEventKind.SCAN_REQUESTED,
        AuditOutcome.ALLOWED,
        source_address="192.0.2.1",
        session_id="a" * 24,
        action=AuditAction.RUN_PASSIVE,
        reason=AuditReason.HOST_APPROVED,
    )
    object.__setattr__(event, field, valid_shaped_secret)

    with pytest.raises(ValueError, match="modified"):
        event.__post_init__()
    with pytest.raises(ValueError, match="modified"):
        event.as_dict()


def test_issuance_seal_mutation_cannot_be_resealed_or_exported() -> None:
    event = audit_log().record(
        AuditEventKind.SCAN_REQUESTED,
        AuditOutcome.ALLOWED,
    )
    object.__setattr__(event, "_issuance_seal", b"\x00" * 32)

    with pytest.raises(ValueError, match="modified"):
        event.__post_init__()
    with pytest.raises(ValueError, match="modified"):
        event.as_dict()
