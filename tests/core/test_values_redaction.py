from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from netdiag.core.redaction import (
    RedactionPolicy,
    StructuralSensitivityMap,
    StructuralSerializationError,
    serialize_structured,
)
from netdiag.core.status import OutcomeStatus, Sensitivity
from netdiag.core.values import DiagnosticValue, JsonValidationError, validate_json_value


def test_json_validation_accepts_shared_acyclic_objects_without_coercion():
    shared = {"ok": True}
    value = {"left": shared, "right": shared, "items": [None, 1, 2.5, "x"]}
    assert validate_json_value(value) is value


@pytest.mark.parametrize("value", [b"bytes", {"set"}, ("tuple",), math.nan, math.inf])
def test_json_validation_rejects_non_json_values(value):
    with pytest.raises(JsonValidationError):
        validate_json_value(value)


def test_json_validation_rejects_cycles_and_non_string_keys():
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(JsonValidationError, match="cyclic"):
        validate_json_value(cyclic)
    with pytest.raises(JsonValidationError, match="keys must be strings"):
        validate_json_value({1: "no"})


def test_json_validation_enforces_depth_limit():
    value = {"a": {"b": {"c": 1}}}
    with pytest.raises(JsonValidationError, match="maximum depth"):
        validate_json_value(value, max_depth=2)


@dataclass(frozen=True)
class DeviceRecord:
    hostname: str = field(metadata={"sensitivity": Sensitivity.DEVICE_IDENTIFIER})
    address: DiagnosticValue[str] = field(
        default_factory=lambda: DiagnosticValue(
            "192.168.1.20",
            Sensitivity.NETWORK_ADDRESS,
        )
    )
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: OutcomeStatus = OutcomeStatus.HEALTHY


def test_dataclass_and_typed_value_serialization_is_structural():
    record = DeviceRecord("pi")
    raw = serialize_structured(record, policy=RedactionPolicy.raw())
    shared = serialize_structured(record, policy=RedactionPolicy.share_safe())
    strict = serialize_structured(record, policy=RedactionPolicy.strict())

    assert raw["hostname"] == "pi"
    assert raw["address"] == "192.168.1.20"
    assert raw["status"] == "healthy"
    assert shared["hostname"] == "<device-1>"
    assert shared["address"] == "192.168.1.20"
    assert strict["address"] == "<network-1>"
    assert shared["observed_at"].endswith("+00:00")


def test_potential_secret_is_never_emitted_even_by_raw_policy():
    value = DiagnosticValue("do-not-print", Sensitivity.POTENTIAL_SECRET)
    assert serialize_structured(value, policy=RedactionPolicy.raw()) == "<redacted>"


def test_json_pointer_rules_do_not_replace_unrelated_substrings():
    value = {
        "wifi": {"ssid": "pi", "message": "ping path works"},
        "neighbors": [
            {"mac": "aa:bb:cc:dd:ee:ff"},
            {"mac": "aa:bb:cc:dd:ee:ff"},
        ],
    }
    sensitivity_map = StructuralSensitivityMap.from_json_pointers(
        {
            "/wifi/ssid": Sensitivity.DEVICE_IDENTIFIER,
            "/neighbors/*/mac": Sensitivity.DEVICE_IDENTIFIER,
        }
    )
    output = serialize_structured(
        value,
        policy=RedactionPolicy.share_safe(),
        sensitivity_map=sensitivity_map,
    )
    assert output["wifi"] == {"ssid": "<device-1>", "message": "ping path works"}
    assert output["neighbors"][0]["mac"] == "<device-2>"
    assert output["neighbors"][1]["mac"] == "<device-2>"


def test_exact_path_rule_beats_wildcard_rule():
    sensitivity_map = StructuralSensitivityMap.from_json_pointers(
        {
            "/devices/*/name": Sensitivity.DEVICE_IDENTIFIER,
            "/devices/0/name": Sensitivity.PUBLIC,
        }
    )
    output = serialize_structured(
        {"devices": [{"name": "keep"}, {"name": "hide"}]},
        policy=RedactionPolicy.share_safe(),
        sensitivity_map=sensitivity_map,
    )
    assert output == {"devices": [{"name": "keep"}, {"name": "<device-1>"}]}


def test_json_pointer_parser_rejects_invalid_escape():
    with pytest.raises(ValueError, match="invalid '~' escape"):
        StructuralSensitivityMap.from_json_pointers({"/wifi/~2ssid": Sensitivity.DEVICE_IDENTIFIER})


def test_unknown_legacy_leaf_can_fail_closed():
    sensitivity_map = StructuralSensitivityMap(
        default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET
    )
    output = serialize_structured(
        {"unknown": "value", "nested": {"also": 3}},
        sensitivity_map=sensitivity_map,
    )
    assert output == {
        "<field-1>": "<redacted>",
        "<field-2>": {"<field-3>": "<redacted>"},
    }


def test_sensitive_dictionary_keys_are_structurally_tokenized_without_collision():
    sensitivity_map = StructuralSensitivityMap.from_json_pointers(
        {"/known/value": Sensitivity.PUBLIC},
        default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
    )
    value = {
        "known": {"value": 1, "family-mac.local": 2},
        "password=hunter2": True,
        "<field-1>": "reserved collision canary",
    }
    for policy in (RedactionPolicy.raw(), RedactionPolicy.share_safe()):
        output = serialize_structured(
            value,
            policy=policy,
            sensitivity_map=sensitivity_map,
        )
        rendered = str(output)
        assert "family-mac.local" not in rendered
        assert "password=hunter2" not in rendered
        assert "reserved collision canary" not in rendered
        assert output["known"]["value"] == 1
        assert len(output) == 3
        assert len(set(output)) == 3


def test_wildcard_rule_does_not_authorize_dynamic_dictionary_key() -> None:
    sensitivity_map = StructuralSensitivityMap.from_json_pointers(
        {"/dynamic/*/value": Sensitivity.PUBLIC},
        default_leaf_sensitivity=Sensitivity.POTENTIAL_SECRET,
    )
    output = serialize_structured(
        {"dynamic": {"family-mac.local": {"value": 1}}},
        sensitivity_map=sensitivity_map,
    )
    assert output == {"dynamic": {"<field-1>": {"value": 1}}}


def test_serializer_rejects_naive_time_and_cycles():
    with pytest.raises(StructuralSerializationError, match="timezone"):
        serialize_structured(datetime(2026, 1, 1))  # noqa: DTZ001 - deliberate invalid input.
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(StructuralSerializationError, match="cyclic"):
        serialize_structured(cyclic)
