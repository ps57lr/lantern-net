from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path

import macos_notarize
import pytest
from package_support import PackageVerificationError

SUBMISSION_ID = "3295d9ec-89a3-4358-a2d4-bc6a8583c16e"


def _binding() -> dict[str, str]:
    return {
        "schema": macos_notarize.STATE_BINDING_SCHEMA,
        "artifact_name": "lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED-NOTARIZED",
        "artifact_snapshot_sha256": "a" * 64,
        "app_snapshot_sha256": "b" * 64,
        "embedded_provenance_sha256": "c" * 64,
        "release_tool_commit": "d" * 40,
    }


def _log(archive_hash: str, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "jobId": SUBMISSION_ID,
        "status": "Accepted",
        "statusCode": 0,
        "issues": None,
        "sha256": archive_hash,
    }
    payload.update(changes)
    return payload


def _submit_receipt(
    archive: Path,
    receipt: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(macos_notarize, "notarytool_path", lambda: Path("/notarytool"))
    monkeypatch.setattr(macos_notarize, "preflight_notary_credentials", lambda: {"history": []})

    def run(
        command: list[str], *, timeout: int, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del check
        assert timeout == 10 * 60
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"id": SUBMISSION_ID}),
            stderr="",
        )

    monkeypatch.setattr(macos_notarize, "_run", run)
    macos_notarize.submit_no_wait(archive, receipt, binding=_binding())
    return calls


def test_notary_preflight_is_read_only_history_with_fixed_keychain_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv("NOTARYTOOL_PROFILE", "attacker-profile")
    monkeypatch.setattr(macos_notarize, "notarytool_path", lambda: Path("/notarytool"))

    def run(
        command: list[str], *, timeout: int, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        assert timeout == 60
        assert check is True
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"history":[]}', stderr="")

    monkeypatch.setattr(macos_notarize, "_run", run)

    assert macos_notarize.notary_profile() == "lantern-notary"
    assert macos_notarize.preflight_notary_credentials() == {"history": []}
    assert calls == [
        [
            "/notarytool",
            "history",
            "--output-format",
            "json",
            "--keychain-profile",
            "lantern-notary",
        ]
    ]
    assert "store-credentials" not in calls[0]


def test_submit_no_wait_durably_records_one_canonical_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "Lantern.zip"
    archive.write_bytes(b"signed app")
    receipt = tmp_path / macos_notarize.RECEIPT_NAME

    calls = _submit_receipt(archive, receipt, monkeypatch)
    recorded = macos_notarize.load_submission_receipt(
        receipt,
        archive,
        expected_binding=_binding(),
    )

    assert recorded["submission_id"] == SUBMISSION_ID
    assert recorded["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o400
    assert calls == [
        [
            "/notarytool",
            "submit",
            str(archive),
            "--no-wait",
            "--output-format",
            "json",
            "--keychain-profile",
            "lantern-notary",
        ]
    ]
    assert "--wait" not in calls[0]


@pytest.mark.parametrize("kind", ("receipt", "log"))
def test_exceptional_evidence_write_never_unlinks_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    path = tmp_path / f"{kind}.json"
    moved = tmp_path / f"{kind}.created"

    def fail_after_replacement(_descriptor: int) -> None:
        path.rename(moved)
        path.write_bytes(b"unrelated replacement")
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(macos_notarize.os, "fsync", fail_after_replacement)

    with pytest.raises(OSError, match="synthetic fsync failure"):
        if kind == "receipt":
            macos_notarize._write_receipt_exclusive(
                path,
                {
                    "schema": macos_notarize.RECEIPT_SCHEMA,
                    "submission_id": SUBMISSION_ID,
                },
            )
        else:
            macos_notarize._write_log_exclusive(path, b"accepted log")

    assert path.read_bytes() == b"unrelated replacement"
    assert moved.is_file()


def test_interrupted_wait_resumes_without_resubmission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "Lantern.zip"
    archive.write_bytes(b"signed app")
    receipt = tmp_path / macos_notarize.RECEIPT_NAME
    _submit_receipt(archive, receipt, monkeypatch)
    log_destination = tmp_path / "APPLE-NOTARIZATION-LOG.json"
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    calls: list[list[str]] = []
    wait_attempts = 0
    monkeypatch.setattr(macos_notarize, "preflight_notary_credentials", lambda: {"history": []})

    def run(
        command: list[str], *, timeout: int, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del timeout, check
        nonlocal wait_attempts
        calls.append(command)
        if command[1] == "wait":
            wait_attempts += 1
            if wait_attempts == 1:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="timed out")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"id": SUBMISSION_ID, "status": "Accepted"}),
                stderr="",
            )
        if command[1] == "info":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"id": SUBMISSION_ID, "status": "In Progress"}),
                stderr="",
            )
        assert command[1] == "log"
        Path(command[3]).write_text(json.dumps(_log(archive_hash)), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(macos_notarize, "_run", run)
    evidence = macos_notarize.wait_for_receipt(
        archive,
        receipt,
        log_destination,
        expected_binding=_binding(),
    )

    assert evidence["status"] == "Accepted"
    assert evidence["submission_id"] == SUBMISSION_ID
    assert not any(command[1] == "submit" for command in calls)
    assert [command[1] for command in calls] == ["wait", "info", "wait", "log"]


def test_existing_valid_log_resumes_offline_without_apple_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "Lantern.zip"
    archive.write_bytes(b"signed app")
    receipt = tmp_path / macos_notarize.RECEIPT_NAME
    _submit_receipt(archive, receipt, monkeypatch)
    log_destination = tmp_path / "APPLE-NOTARIZATION-LOG.json"
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    log_destination.write_text(json.dumps(_log(archive_hash)), encoding="utf-8")
    monkeypatch.setattr(
        macos_notarize,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("existing valid evidence must not call Apple"),
    )

    evidence = macos_notarize.wait_for_receipt(
        archive,
        receipt,
        log_destination,
        expected_binding=_binding(),
    )

    assert evidence["log_sha256"] == hashlib.sha256(log_destination.read_bytes()).hexdigest()


@pytest.mark.parametrize("tamper", ["archive", "binding", "writable-receipt"])
def test_resume_rejects_tampered_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    archive = tmp_path / "Lantern.zip"
    archive.write_bytes(b"signed app")
    receipt = tmp_path / macos_notarize.RECEIPT_NAME
    _submit_receipt(archive, receipt, monkeypatch)
    binding = _binding()
    if tamper == "archive":
        archive.write_bytes(b"changed signed app")
    elif tamper == "binding":
        binding["app_snapshot_sha256"] = "f" * 64
    else:
        receipt.chmod(0o600)

    with pytest.raises(PackageVerificationError):
        macos_notarize.load_submission_receipt(
            receipt,
            archive,
            expected_binding=binding,
        )


@pytest.mark.parametrize(
    "change,error",
    [
        ({"jobId": "c75019c4-9198-4323-ac39-e1f90752c20a"}, "UUID does not match"),
        ({"status": "Invalid"}, "Accepted status"),
        ({"statusCode": 1}, "success status code"),
        ({"statusCode": True}, "success status code"),
        ({"issues": [{"severity": "warning"}]}, "unresolved issues"),
        ({"sha256": "0" * 64}, "archive hash does not match"),
        ({"sha256": None}, "archive hash does not match"),
        ({"sha256": "A" * 64}, "archive hash does not match"),
    ],
)
def test_notarization_log_requires_exact_clean_acceptance(
    change: dict[str, object], error: str
) -> None:
    archive_hash = "a" * 64
    payload = _log(archive_hash, **change)

    with pytest.raises(PackageVerificationError, match=error):
        macos_notarize._validate_log(
            json.dumps(payload).encode(),
            submission_id=SUBMISSION_ID,
            archive_sha256=archive_hash,
        )


def test_rejected_wait_status_fails_without_retrying_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "Lantern.zip"
    archive.write_bytes(b"signed app")
    receipt = tmp_path / macos_notarize.RECEIPT_NAME
    _submit_receipt(archive, receipt, monkeypatch)
    monkeypatch.setattr(macos_notarize, "preflight_notary_credentials", lambda: {"history": []})
    calls: list[list[str]] = []

    def run(
        command: list[str], *, timeout: int, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del timeout, check
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"id": SUBMISSION_ID, "status": "Invalid"}),
            stderr="",
        )

    monkeypatch.setattr(macos_notarize, "_run", run)
    with pytest.raises(PackageVerificationError, match="status was Invalid"):
        macos_notarize.wait_for_receipt(
            archive,
            receipt,
            tmp_path / "log.json",
            expected_binding=_binding(),
        )
    assert [command[1] for command in calls] == ["wait"]


def test_submission_uuid_must_be_canonical_lowercase() -> None:
    with pytest.raises(PackageVerificationError, match="non-canonical"):
        macos_notarize._submission_id(SUBMISSION_ID.upper())


def test_notary_timeout_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["notarytool"], 1)

    monkeypatch.setattr(macos_notarize.subprocess, "run", timeout)
    with pytest.raises(PackageVerificationError, match="timed out"):
        macos_notarize._run(["notarytool", "history"], timeout=1)
