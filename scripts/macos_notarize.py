"""Keychain-only Apple notarization with retained, hashed acceptance evidence."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path

from macos_codesign import resolve_xcrun_tool, tool_record
from package_support import PackageVerificationError, sha256_file

_DEFAULT_PROFILE = "lantern-notary"
_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_MAX_JSON_BYTES = 8 * 1024 * 1024
RECEIPT_NAME = "notarization-submission-receipt.json"
RECEIPT_SCHEMA = "lantern.apple-notarization-receipt.v1"
STATE_BINDING_SCHEMA = "lantern.macos-notarization-state.v1"
_WAIT_ATTEMPTS = 6
_WAIT_SERVICE_TIMEOUT = "10m"
_WAIT_PROCESS_TIMEOUT = 11 * 60
_PENDING_STATUSES = frozenset({"In Progress", "Uploaded"})
_REJECTED_STATUSES = frozenset({"Invalid", "Rejected"})
_BINDING_KEYS = {
    "schema",
    "artifact_name",
    "artifact_snapshot_sha256",
    "app_snapshot_sha256",
    "embedded_provenance_sha256",
    "release_tool_commit",
}
_ARTIFACT_NAME = re.compile(
    r"lantern-family-beta-[0-9]+\.[0-9]+\.[0-9]+(?:\.(?:dev|post)[0-9]+)?-"
    r"macos-arm64-SIGNED-NOTARIZED\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def notary_profile() -> str:
    """Return the sole reviewed Keychain profile; ambient overrides are unsupported."""

    return _DEFAULT_PROFILE


def notarytool_path() -> Path:
    return resolve_xcrun_tool("notarytool")


def notary_tool_records() -> dict[str, dict[str, str]]:
    return {
        "notarytool": tool_record(notarytool_path()),
        "spctl": tool_record(Path("/usr/sbin/spctl")),
        "stapler": tool_record(Path("/usr/bin/stapler")),
    }


def _load_json(payload: str | bytes, *, label: str) -> object:
    if isinstance(payload, str):
        try:
            encoded = payload.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise PackageVerificationError(f"{label} is not strict UTF-8") from exc
    elif isinstance(payload, bytes):
        encoded = payload
    else:
        raise PackageVerificationError(f"{label} is not JSON")
    if not encoded or len(encoded) > _MAX_JSON_BYTES:
        raise PackageVerificationError(f"{label} is empty or oversized")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PackageVerificationError(f"{label} contains duplicate members")
            result[key] = value
        return result

    try:
        return json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                PackageVerificationError(f"{label} contains a non-finite number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise PackageVerificationError(f"{label} is not valid JSON") from exc


def _run(
    command: list[str],
    *,
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_SAFE_ENV,
        )
    except subprocess.TimeoutExpired as exc:
        raise PackageVerificationError("Apple notarization command timed out") from exc
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise PackageVerificationError(f"Apple notarization command failed: {detail}")
    return completed


def _profile_arguments() -> list[str]:
    return ["--keychain-profile", notary_profile()]


def preflight_notary_credentials() -> dict[str, object]:
    """Validate the Keychain profile using only notarytool's read-only history call."""

    completed = _run(
        [
            str(notarytool_path()),
            "history",
            "--output-format",
            "json",
            *_profile_arguments(),
        ],
        timeout=60,
    )
    payload = _load_json(completed.stdout, label="notarytool history response")
    if type(payload) is not dict:
        raise PackageVerificationError("notarytool history response has an invalid shape")
    history = payload.get("history")
    if type(history) is not list or len(history) > 10_000:
        raise PackageVerificationError("notarytool history response has an invalid shape")
    return payload


def notary_credentials_available() -> bool:
    try:
        preflight_notary_credentials()
    except (OSError, subprocess.SubprocessError, PackageVerificationError):
        return False
    return True


def _submission_id(value: object) -> str:
    if type(value) is not str:
        raise PackageVerificationError("notarization response has no submission UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise PackageVerificationError(
            "notarization response has an invalid submission UUID"
        ) from exc
    if str(parsed) != value:
        raise PackageVerificationError("notarization response has a non-canonical submission UUID")
    return str(parsed)


def _state_binding(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != _BINDING_KEYS:
        raise PackageVerificationError("notarization state binding has an invalid shape")
    if value.get("schema") != STATE_BINDING_SCHEMA:
        raise PackageVerificationError("notarization state binding schema is invalid")
    artifact_name = value.get("artifact_name")
    if type(artifact_name) is not str or _ARTIFACT_NAME.fullmatch(artifact_name) is None:
        raise PackageVerificationError("notarization state artifact name is invalid")
    for key in (
        "artifact_snapshot_sha256",
        "app_snapshot_sha256",
        "embedded_provenance_sha256",
    ):
        digest = value.get(key)
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise PackageVerificationError("notarization state binding digest is invalid")
    commit = value.get("release_tool_commit")
    if type(commit) is not str or _COMMIT.fullmatch(commit) is None:
        raise PackageVerificationError("notarization state release commit is invalid")
    return dict(value)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_receipt_exclusive(path: Path, receipt: Mapping[str, object]) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PackageVerificationError("notarization state directory is unavailable")
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > 64 * 1024:
        raise PackageVerificationError("notarization receipt is oversized")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        _fsync_directory(parent)
    except FileExistsError as exc:
        raise PackageVerificationError("notarization receipt already exists") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        # Never unlink an exceptional write by pathname. A same-user rename
        # and replacement between an identity check and unlink could delete an
        # unrelated file. The private state is retained for explicit review.
        raise


def load_submission_receipt(
    receipt_path: Path,
    archive: Path,
    *,
    expected_binding: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Load one immutable receipt and rebind it to the exact submitted archive/state."""

    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise PackageVerificationError("notarization receipt is unavailable")
    details = receipt_path.stat()
    if details.st_size > 64 * 1024 or details.st_uid != os.geteuid() or details.st_mode & 0o222:
        raise PackageVerificationError("notarization receipt is not immutable or owner-controlled")
    receipt = _load_json(receipt_path.read_bytes(), label="notarization receipt")
    expected_keys = {"schema", "profile", "submission_id", "archive_sha256", "binding"}
    if type(receipt) is not dict or set(receipt) != expected_keys:
        raise PackageVerificationError("notarization receipt has an invalid shape")
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("profile") != notary_profile():
        raise PackageVerificationError("notarization receipt does not match the reviewed profile")
    submission_id = _submission_id(receipt.get("submission_id"))
    archive_sha256 = receipt.get("archive_sha256")
    if type(archive_sha256) is not str or _SHA256.fullmatch(archive_sha256) is None:
        raise PackageVerificationError("notarization receipt archive digest is invalid")
    binding = _state_binding(receipt.get("binding"))
    if expected_binding is not None and binding != _state_binding(dict(expected_binding)):
        raise PackageVerificationError("notarization receipt state binding does not match")
    if archive.is_symlink() or not archive.is_file() or sha256_file(archive) != archive_sha256:
        raise PackageVerificationError("notarization receipt does not match the submitted archive")
    return {
        "schema": RECEIPT_SCHEMA,
        "profile": notary_profile(),
        "submission_id": submission_id,
        "archive_sha256": archive_sha256,
        "binding": binding,
    }


def submit_no_wait(
    archive: Path,
    receipt_destination: Path,
    *,
    binding: Mapping[str, object],
) -> dict[str, object]:
    """Upload once, then durably retain the UUID/hash/state receipt before polling."""

    if archive.is_symlink() or not archive.is_file():
        raise PackageVerificationError("notarization archive is unavailable")
    if receipt_destination.exists() or receipt_destination.is_symlink():
        raise PackageVerificationError("notarization receipt already exists")
    archive = archive.resolve(strict=True)
    archive_sha256 = sha256_file(archive)
    state_binding = _state_binding(dict(binding))
    preflight_notary_credentials()
    completed = _run(
        [
            str(notarytool_path()),
            "submit",
            str(archive),
            "--no-wait",
            "--output-format",
            "json",
            *_profile_arguments(),
        ],
        timeout=10 * 60,
    )
    response = _load_json(completed.stdout, label="notarization submission response")
    if type(response) is not dict:
        raise PackageVerificationError("notarization submission response has an invalid shape")
    submission_id = _submission_id(response.get("id"))
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "profile": notary_profile(),
        "submission_id": submission_id,
        "archive_sha256": archive_sha256,
        "binding": state_binding,
    }
    _write_receipt_exclusive(receipt_destination, receipt)
    if sha256_file(archive) != archive_sha256:
        raise PackageVerificationError(
            "submitted archive changed after upload; receipt was retained for investigation"
        )
    return load_submission_receipt(
        receipt_destination,
        archive,
        expected_binding=state_binding,
    )


def _validate_log(
    payload: bytes,
    *,
    submission_id: str,
    archive_sha256: str,
) -> dict[str, object]:
    log = _load_json(payload, label="notarization log")
    if type(log) is not dict:
        raise PackageVerificationError("notarization log has an invalid shape")
    if _submission_id(log.get("jobId")) != submission_id:
        raise PackageVerificationError("notarization log submission UUID does not match")
    if log.get("status") != "Accepted":
        raise PackageVerificationError("notarization log does not record Accepted status")
    if type(log.get("statusCode")) is not int or log["statusCode"] != 0:
        raise PackageVerificationError("notarization log does not record success status code")
    issues = log.get("issues")
    if issues not in (None, []):
        raise PackageVerificationError("notarization log contains unresolved issues")
    recorded_archive_hash = log.get("sha256")
    if (
        type(recorded_archive_hash) is not str
        or re.fullmatch(r"[0-9a-f]{64}", recorded_archive_hash) is None
        or recorded_archive_hash != archive_sha256
    ):
        raise PackageVerificationError("notarization log archive hash does not match")
    return log


def _status_response(payload: str, *, label: str, submission_id: str) -> str:
    response = _load_json(payload, label=label)
    if type(response) is not dict:
        raise PackageVerificationError(f"{label} has an invalid shape")
    if _submission_id(response.get("id")) != submission_id:
        raise PackageVerificationError(f"{label} submission UUID does not match")
    status = response.get("status")
    if status not in {"Accepted", *_PENDING_STATUSES, *_REJECTED_STATUSES}:
        raise PackageVerificationError(f"{label} status is unsupported")
    return str(status)


def _poll_until_accepted(tool: Path, submission_id: str) -> None:
    """Wait with bounded attempts, consulting info after every interrupted wait."""

    for _attempt in range(_WAIT_ATTEMPTS):
        wait_result: subprocess.CompletedProcess[str] | None
        try:
            wait_result = _run(
                [
                    str(tool),
                    "wait",
                    submission_id,
                    "--timeout",
                    _WAIT_SERVICE_TIMEOUT,
                    "--output-format",
                    "json",
                    *_profile_arguments(),
                ],
                timeout=_WAIT_PROCESS_TIMEOUT,
                check=False,
            )
        except PackageVerificationError:
            wait_result = None
        if wait_result is not None and wait_result.returncode == 0:
            status = _status_response(
                wait_result.stdout,
                label="notarization wait response",
                submission_id=submission_id,
            )
            if status == "Accepted":
                return
            if status in _REJECTED_STATUSES:
                raise PackageVerificationError(f"Apple notarization status was {status}")

        try:
            info_result = _run(
                [
                    str(tool),
                    "info",
                    submission_id,
                    "--output-format",
                    "json",
                    *_profile_arguments(),
                ],
                timeout=60,
                check=False,
            )
        except PackageVerificationError:
            continue
        if info_result.returncode != 0:
            continue
        status = _status_response(
            info_result.stdout,
            label="notarization info response",
            submission_id=submission_id,
        )
        if status == "Accepted":
            return
        if status in _REJECTED_STATUSES:
            raise PackageVerificationError(f"Apple notarization status was {status}")

    raise PackageVerificationError(
        "Apple notarization remains pending; resume from the retained notarization state"
    )


def _write_log_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise PackageVerificationError("notarization log destination already exists") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        # As with receipts, retain uncertain bytes rather than unlinking a
        # pathname that a same-user racer could have replaced.
        raise


def wait_for_receipt(
    archive: Path,
    receipt_path: Path,
    log_destination: Path,
    *,
    expected_binding: Mapping[str, object] | None = None,
) -> dict[str, str]:
    """Resume one known submission; never upload, resubmit, or replace evidence."""

    receipt = load_submission_receipt(
        receipt_path,
        archive,
        expected_binding=expected_binding,
    )
    submission_id = str(receipt["submission_id"])
    archive_sha256 = str(receipt["archive_sha256"])
    if log_destination.is_symlink():
        raise PackageVerificationError("notarization log destination is unsafe")
    if log_destination.exists():
        if not log_destination.is_file() or log_destination.stat().st_size > _MAX_JSON_BYTES:
            raise PackageVerificationError("notarization log destination is unsafe")
        _validate_log(
            log_destination.read_bytes(),
            submission_id=submission_id,
            archive_sha256=archive_sha256,
        )
        return {
            "status": "Accepted",
            "submission_id": submission_id,
            "archive_sha256": archive_sha256,
            "log_sha256": sha256_file(log_destination),
        }
    preflight_notary_credentials()
    tool = notarytool_path()
    _poll_until_accepted(tool, submission_id)

    with tempfile.TemporaryDirectory(prefix="lantern-notary-log-") as temporary:
        temporary_log = Path(temporary) / "notarization-log.json"
        _run(
            [
                str(tool),
                "log",
                submission_id,
                str(temporary_log),
                *_profile_arguments(),
            ],
            timeout=2 * 60,
        )
        if (
            temporary_log.is_symlink()
            or not temporary_log.is_file()
            or temporary_log.stat().st_size > _MAX_JSON_BYTES
        ):
            raise PackageVerificationError("notarization log was not retrieved")
        log_bytes = temporary_log.read_bytes()
        _validate_log(
            log_bytes,
            submission_id=submission_id,
            archive_sha256=archive_sha256,
        )
        _write_log_exclusive(log_destination, log_bytes)

    return {
        "status": "Accepted",
        "submission_id": submission_id,
        "archive_sha256": archive_sha256,
        "log_sha256": sha256_file(log_destination),
    }


def setup_instructions() -> str:
    profile = notary_profile()
    return f"""Store one App Store Connect Team API key in the macOS Keychain profile first:

  xcrun notarytool store-credentials {profile} \\
    --key /absolute/path/to/AuthKey_KEY_ID.p8 \\
    --key-id YOUR_KEY_ID \\
    --issuer YOUR_ISSUER_UUID

The release pipeline accepts only --keychain-profile authentication. It never reads Apple
credentials, private keys, or app-specific passwords from environment variables.
"""
