"""Verify an unpacked Lantern family-beta artifact using only the stdlib."""

from __future__ import annotations

import argparse
import json
import platform
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from macos_codesign import (
    EMBEDDED_PROVENANCE,
    EXPECTED_CERTIFICATE_SHA256,
    EXPECTED_IDENTITY,
    EXPECTED_IDENTITY_SHA1,
    EXPECTED_TEAM_ID,
    SigningCertificate,
    assess_gatekeeper,
    verify_application_signatures,
)
from package_support import (
    CHECKSUM_NAME,
    MANIFEST_NAME,
    MANIFEST_SCHEMA,
    MAX_MANIFEST_BYTES,
    PackageVerificationError,
    canonical_records_sha256,
    collect_file_records,
    sha256_file,
    validate_relative_path,
)

_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.(?:dev|post)[0-9]+)?\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BASE_MANIFEST_KEYS = {
    "schema",
    "product",
    "release",
    "target",
    "contracts",
    "provenance",
    "files",
    "tree_sha256",
}
_SIGNED_MANIFEST_KEYS = _BASE_MANIFEST_KEYS | {"signing"}
_ENTITLEMENTS_SHA256 = "97704a8960b4facceef54397a08fb5d0a456247c3627359215aa2a27df22656c"
_BUILD_LOCK_SHA256 = "9ef83fb5980dc61a78b75d116955d5cc485f020d556f596e9b6213068073a23e"
_RUNTIME_LOCK_SHA256 = "523fde449f9e3587b2e662ad053b8bb5c99cb26139591fa1fd8113a22aa1e2b9"
_RUNTIME_ARCHIVE_SHA256 = "7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802"
_RUNTIME_EXECUTABLE_SHA256 = "95c331c5e61804b2dcea00dd105fbf7c9e417aaabff23fa5da6758d84033029d"
_RUNTIME_LIBRARY_SHA256 = "39669f88807bff419376e0ba17ae68d194f065f7959fb61cd4777af65da09e51"
_RUNTIME_TREE_SHA256 = "89f2b0d5e85dc62c5ec225dc850e097f863c7406d23a2835a4e983f050ee093d"
_BUILD_SITE_PACKAGES_SHA256 = "c6f4d93a0091bc6d86b118dbb05b85af5209b30c5d4b4048fbf17fe052bcb33d"
_RELEASE_SOURCE_NAMES = {
    "bootstrap_macos_release.py",
    "family-beta.entitlements.plist",
    "lantern-family-beta.spec",
    "macos_codesign.py",
    "macos_notarize.py",
    "package_family_beta.py",
    "package_support.py",
    "requirements-build.lock",
    "release_family_beta_macos.py",
    "runtime.lock.json",
    "verify_family_beta.py",
}


def _exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PackageVerificationError(f"{label} does not match its fixed contract")
    return value


def _bounded_text(value: object, *, label: str, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise PackageVerificationError(f"{label} must be bounded text")
    return value


def _load_manifest(root: Path) -> dict[str, object]:
    path = root / MANIFEST_NAME
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise PackageVerificationError("package manifest is missing, linked, or oversized")
    try:
        payload = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PackageVerificationError("package manifest is not valid JSON") from exc
    if type(payload) is not dict:
        raise PackageVerificationError("package manifest does not match its fixed contract")
    release = payload.get("release")
    channel = release.get("channel") if type(release) is dict else None
    expected = _SIGNED_MANIFEST_KEYS if channel == "family-beta-signed" else _BASE_MANIFEST_KEYS
    return _exact_keys(payload, expected, "package manifest")


def _strict_json_loads(payload: bytes | str) -> object:
    """Load strict JSON, rejecting duplicate members and non-finite numbers."""

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PackageVerificationError("JSON contains a duplicate object member")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise PackageVerificationError("JSON contains a non-finite number")

    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PackageVerificationError("JSON is not strict UTF-8") from exc
    if not isinstance(payload, str):
        raise PackageVerificationError("JSON payload must be text or bytes")
    try:
        result = json.loads(payload, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    except PackageVerificationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise PackageVerificationError("JSON is malformed or exceeds structural bounds") from exc

    pending = [(result, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 100_000:
            raise PackageVerificationError("JSON exceeds the structural node bound")
        if depth > 256:
            raise PackageVerificationError("JSON exceeds structural bounds")
        if isinstance(value, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
                raise PackageVerificationError("JSON contains an unpaired Unicode surrogate")
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is dict:
            pending.extend((item, depth + 1) for item in value)
            pending.extend((item, depth + 1) for item in value.values())
    return result


def _verify_checksum_file(root: Path) -> None:
    path = root / CHECKSUM_NAME
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256:
        raise PackageVerificationError("manifest checksum file is missing, linked, or oversized")
    expected = f"{sha256_file(root / MANIFEST_NAME)}  {MANIFEST_NAME}\n"
    try:
        actual = path.read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise PackageVerificationError("manifest checksum is not strict ASCII") from exc
    if actual != expected:
        raise PackageVerificationError("manifest checksum does not match")


def _verify_release(value: object) -> dict[str, object]:
    release = _exact_keys(
        value,
        {
            "version",
            "channel",
            "label",
            "unsigned_development",
            "developer_id_signing",
            "notarization",
            "auto_update",
            "installer",
            "elevation",
            "autorun",
            "persistence",
            "usb_autorun",
            "packaging_network_additions",
        },
        "release metadata",
    )
    version = _bounded_text(release["version"], label="release version", maximum=64)
    if _VERSION.fullmatch(version) is None:
        raise PackageVerificationError("release version is invalid")
    channel = release.get("channel")
    if channel == "family-beta-development":
        return _verify_release_unsigned(release, version=version)
    if channel == "family-beta-signed":
        return _verify_release_signed(release, version=version)
    raise PackageVerificationError("unsupported release channel")


def _verify_shared_release_flags(release: dict[str, object]) -> None:
    fixed = {
        "auto_update": False,
        "installer": False,
        "elevation": False,
        "autorun": False,
        "persistence": False,
        "usb_autorun": False,
        "packaging_network_additions": "none",
    }
    for key, expected in fixed.items():
        if release.get(key) != expected:
            raise PackageVerificationError(f"unsafe or misleading release setting: {key}")


def _verify_release_unsigned(release: dict[str, object], *, version: str) -> dict[str, object]:
    fixed = {
        "channel": "family-beta-development",
        "label": "UNSIGNED DEVELOPMENT BUILD",
        "unsigned_development": True,
        "developer_id_signing": "not-configured",
        "notarization": "not-performed",
    }
    for key, expected in fixed.items():
        if release.get(key) != expected:
            raise PackageVerificationError(f"unsafe or misleading release setting: {key}")
    _verify_shared_release_flags(release)
    release["version"] = version
    return release


def _verify_release_signed(release: dict[str, object], *, version: str) -> dict[str, object]:
    if release.get("unsigned_development") is not False:
        raise PackageVerificationError("signed release must not claim unsigned development")
    signing = release.get("developer_id_signing")
    if signing != f"team-id:{EXPECTED_TEAM_ID}":
        raise PackageVerificationError("signed release team identity is invalid")
    notarization = release.get("notarization")
    if notarization not in {"not-performed", "stapled"}:
        raise PackageVerificationError("signed release notarization label is invalid")
    label = release.get("label")
    if notarization == "stapled":
        if label != "SIGNED AND NOTARIZED FAMILY BETA":
            raise PackageVerificationError("signed release label does not match notarization")
    elif label != "SIGNED FAMILY BETA":
        raise PackageVerificationError("signed release label does not match notarization")
    _verify_shared_release_flags(release)
    release["version"] = version
    return release


def _verify_target(root: Path, value: object, release: dict[str, object]) -> dict[str, object]:
    target = _exact_keys(
        value,
        {"os", "architecture", "payload", "launcher", "self_test", "macos_signature"},
        "target metadata",
    )
    if target["os"] not in {"macos", "linux"}:
        raise PackageVerificationError("unsupported artifact operating system")
    if target["architecture"] not in {"arm64", "x86_64"}:
        raise PackageVerificationError("unsupported artifact architecture")
    if release["channel"] == "family-beta-development":
        expected_signature = "ad-hoc-only" if target["os"] == "macos" else "not-applicable"
    elif release["channel"] == "family-beta-signed":
        expected_target = {
            "os": "macos",
            "architecture": "arm64",
            "payload": "Start Lantern.app",
            "launcher": "Start Lantern.app/Contents/MacOS/Start Lantern",
            "self_test": "Start Lantern.app/Contents/MacOS/verify-lantern-package",
            "macos_signature": "developer-id-application",
        }
        if target != expected_target:
            raise PackageVerificationError(
                "signed release target does not match its fixed contract"
            )
        expected_signature = "developer-id-application"
    else:
        raise PackageVerificationError("unsupported release channel")
    if target["macos_signature"] != expected_signature:
        raise PackageVerificationError("macOS signature label is inconsistent")

    for key in ("payload", "launcher", "self_test"):
        relative = validate_relative_path(target[key])
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PackageVerificationError(f"target path is unavailable: {key}") from exc
        if not resolved.is_relative_to(root):
            raise PackageVerificationError(f"target path escapes the artifact: {key}")
    payload = root / str(target["payload"])
    if not payload.is_dir() or payload.is_symlink():
        raise PackageVerificationError("declared payload is not a real directory")
    for key in ("launcher", "self_test"):
        candidate = root / str(target[key])
        if candidate.is_symlink() or not candidate.is_file():
            raise PackageVerificationError(f"declared {key} is not a regular file")
        if not candidate.stat().st_mode & stat.S_IXUSR:
            raise PackageVerificationError(f"declared {key} is not executable")
    return target


def _verify_contracts(value: object) -> dict[str, object]:
    contracts = _exact_keys(
        value,
        {"report_schema", "report_schema_sha256", "ui_schema", "ui_assets"},
        "contract metadata",
    )
    if contracts["report_schema"] != "1.1" or contracts["ui_schema"] != "lantern.ui.v2":
        raise PackageVerificationError("packaged schema contract is unsupported")
    if (
        type(contracts["report_schema_sha256"]) is not str
        or _SHA256.fullmatch(contracts["report_schema_sha256"]) is None
    ):
        raise PackageVerificationError("report schema digest is invalid")
    assets = contracts["ui_assets"]
    if type(assets) is not list or len(assets) != 4:
        raise PackageVerificationError("UI asset contract must contain exactly four files")
    names: set[str] = set()
    for asset in assets:
        item = _exact_keys(asset, {"filename", "size", "sha256"}, "UI asset")
        filename = _bounded_text(item["filename"], label="UI asset filename", maximum=64)
        if "/" in filename or "\\" in filename or filename in names:
            raise PackageVerificationError("UI asset filename is unsafe or duplicated")
        if type(item["size"]) is not int or not 0 < item["size"] <= 2 * 1024 * 1024:
            raise PackageVerificationError("UI asset size is invalid")
        if type(item["sha256"]) is not str or _SHA256.fullmatch(item["sha256"]) is None:
            raise PackageVerificationError("UI asset digest is invalid")
        names.add(filename)
    if names != {"index.html", "styles.css", "app.js", "icons.svg"}:
        raise PackageVerificationError("UI asset set is incomplete")
    return contracts


def _verify_provenance(
    value: object,
    *,
    target: dict[str, object],
    require_clean_source: bool,
) -> dict[str, object]:
    provenance = _exact_keys(
        value,
        {
            "source_commit",
            "source_dirty",
            "source_epoch",
            "builder_python",
            "pyinstaller",
            "build_inputs",
            "build_lock_sha256",
            "builder_runtime",
        },
        "provenance metadata",
    )
    if (
        type(provenance["source_commit"]) is not str
        or _COMMIT.fullmatch(provenance["source_commit"]) is None
    ):
        raise PackageVerificationError("source commit is invalid")
    if type(provenance["source_dirty"]) is not bool:
        raise PackageVerificationError("source dirty flag is invalid")
    if require_clean_source and provenance["source_dirty"]:
        raise PackageVerificationError("artifact was built from a dirty source tree")
    if type(provenance["source_epoch"]) is not int or not 0 < provenance["source_epoch"]:
        raise PackageVerificationError("source epoch is invalid")
    for key in ("builder_python", "pyinstaller"):
        _bounded_text(provenance[key], label=key, maximum=64)
    if provenance["pyinstaller"] != "6.22.1":
        raise PackageVerificationError("artifact used an unreviewed PyInstaller version")
    if provenance["build_inputs"] != "locked-python-wheels-and-reviewed-spec":
        raise PackageVerificationError("artifact build-input declaration is unsupported")
    if provenance["build_lock_sha256"] != _BUILD_LOCK_SHA256:
        raise PackageVerificationError("build lock digest does not match the reviewed lock")
    runtime = provenance["builder_runtime"]
    if target["os"] == "macos":
        runtime = _exact_keys(
            runtime,
            {
                "schema",
                "provider",
                "version",
                "architecture",
                "minimum_macos",
                "runtime_lock_sha256",
                "runtime_archive_sha256",
                "runtime_tree_sha256",
                "build_site_packages_sha256",
                "python_executable_sha256",
                "libpython_sha256",
            },
            "macOS builder runtime",
        )
        expected = {
            "schema": "lantern.macos-builder-runtime.v1",
            "provider": "Astral python-build-standalone",
            "version": "3.11.15",
            "architecture": "arm64",
            "minimum_macos": "11.0",
            "runtime_lock_sha256": _RUNTIME_LOCK_SHA256,
            "runtime_archive_sha256": _RUNTIME_ARCHIVE_SHA256,
            "runtime_tree_sha256": _RUNTIME_TREE_SHA256,
            "build_site_packages_sha256": _BUILD_SITE_PACKAGES_SHA256,
            "python_executable_sha256": _RUNTIME_EXECUTABLE_SHA256,
            "libpython_sha256": _RUNTIME_LIBRARY_SHA256,
        }
        if runtime != expected or provenance["builder_python"] != "3.11.15":
            raise PackageVerificationError("macOS build runtime does not match the reviewed lock")
    elif runtime is not None:
        raise PackageVerificationError("non-macOS artifact carries unsupported runtime provenance")
    return provenance


def _verify_hash(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PackageVerificationError(f"{label} digest is invalid")
    return value


def _verify_tool_record(value: object, *, label: str) -> dict[str, object]:
    record = _exact_keys(value, {"path", "sha256"}, f"{label} tool record")
    path = _bounded_text(record["path"], label=f"{label} tool path", maximum=1024)
    if not path.startswith("/") or "\x00" in path:
        raise PackageVerificationError(f"{label} tool path is invalid")
    _verify_hash(record["sha256"], label=f"{label} tool")
    return record


def _verify_payload_provenance(
    value: object,
    *,
    notarized: bool,
) -> dict[str, object]:
    payload = _exact_keys(
        value,
        {
            "schema",
            "release_tool_commit",
            "release_tool_clean",
            "release_sources_sha256",
            "input_snapshot_sha256",
            "input_manifest_sha256",
            "input_tree_sha256",
            "input_archive_sha256",
            "input_manifest_binding",
            "entitlements_sha256",
            "runtime_lock_sha256",
            "runtime_archive_sha256",
            "runtime_version",
            "runtime_python_executable_sha256",
            "runtime_libpython_sha256",
            "runtime_tree_sha256",
            "build_site_packages_sha256",
            "certificate_common_name",
            "certificate_sha1",
            "certificate_sha256",
            "team_id",
            "tools",
        },
        "signed payload provenance",
    )
    if payload["schema"] != "lantern.macos-signing.v1":
        raise PackageVerificationError("signed payload provenance schema is unsupported")
    if (
        type(payload["release_tool_commit"]) is not str
        or _COMMIT.fullmatch(payload["release_tool_commit"]) is None
        or payload["release_tool_clean"] is not True
    ):
        raise PackageVerificationError("release-tool clean commit provenance is invalid")
    source_hashes = payload["release_sources_sha256"]
    if type(source_hashes) is not dict or set(source_hashes) != _RELEASE_SOURCE_NAMES:
        raise PackageVerificationError("release-tool source hashes are incomplete")
    for name, digest in source_hashes.items():
        _verify_hash(digest, label=f"release source {name}")
    for key in (
        "input_snapshot_sha256",
        "input_manifest_sha256",
        "input_tree_sha256",
        "input_archive_sha256",
    ):
        _verify_hash(payload[key], label=key)
    binding = _exact_keys(
        payload["input_manifest_binding"],
        {
            "release_version",
            "target",
            "contracts",
            "build_provenance",
            "tree_sha256",
        },
        "signed unsigned-manifest binding",
    )
    _bounded_text(binding["release_version"], label="bound release version", maximum=64)
    _exact_keys(
        binding["target"],
        {"os", "architecture", "payload", "launcher", "self_test", "macos_signature"},
        "bound unsigned target",
    )
    _verify_hash(binding["tree_sha256"], label="bound input tree")
    if payload["entitlements_sha256"] != _ENTITLEMENTS_SHA256:
        raise PackageVerificationError("signed entitlements input does not match the reviewed file")
    if (
        payload["runtime_lock_sha256"] != _RUNTIME_LOCK_SHA256
        or payload["runtime_archive_sha256"] != _RUNTIME_ARCHIVE_SHA256
        or payload["runtime_version"] != "3.11.15"
        or payload["runtime_python_executable_sha256"] != _RUNTIME_EXECUTABLE_SHA256
        or payload["runtime_libpython_sha256"] != _RUNTIME_LIBRARY_SHA256
        or payload["runtime_tree_sha256"] != _RUNTIME_TREE_SHA256
        or payload["build_site_packages_sha256"] != _BUILD_SITE_PACKAGES_SHA256
    ):
        raise PackageVerificationError("signed runtime provenance does not match the reviewed lock")
    if (
        payload["certificate_common_name"] != EXPECTED_IDENTITY
        or payload["certificate_sha1"] != EXPECTED_IDENTITY_SHA1
        or payload["certificate_sha256"] != EXPECTED_CERTIFICATE_SHA256
        or payload["team_id"] != EXPECTED_TEAM_ID
    ):
        raise PackageVerificationError("signed certificate identity does not match the release pin")
    _verify_hash(payload["certificate_sha256"], label="Developer ID certificate")

    tools = payload["tools"]
    expected_tools = {"codesign", "ditto", "git", "lipo", "python", "security", "vtool"}
    if notarized:
        expected_tools |= {"notarytool", "spctl", "stapler"}
    if type(tools) is not dict or set(tools) != expected_tools:
        raise PackageVerificationError("release tool hashes are incomplete")
    for name, record in tools.items():
        _verify_tool_record(record, label=name)
    return payload


def _canonical_uuid(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise PackageVerificationError(f"{label} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise PackageVerificationError(f"{label} is invalid") from exc
    if str(parsed) != value:
        raise PackageVerificationError(f"{label} is invalid")
    return value


def _verify_notarization_evidence(
    root: Path,
    value: object,
    *,
    notarized: bool,
) -> dict[str, object]:
    evidence = _exact_keys(
        value,
        {"status", "submission_id", "archive_sha256", "log_sha256"},
        "notarization evidence",
    )
    log_path = root / "APPLE-NOTARIZATION-LOG.json"
    if not notarized:
        if evidence != {
            "status": "not-performed",
            "submission_id": None,
            "archive_sha256": None,
            "log_sha256": None,
        }:
            raise PackageVerificationError(
                "unexpected notarization evidence on signed-only release"
            )
        if log_path.exists() or log_path.is_symlink():
            raise PackageVerificationError(
                "signed-only release unexpectedly includes a notarization log"
            )
        return evidence

    if evidence["status"] != "Accepted":
        raise PackageVerificationError("notarized release does not record Accepted status")
    submission_id = _canonical_uuid(evidence["submission_id"], label="notarization submission UUID")
    archive_sha256 = _verify_hash(evidence["archive_sha256"], label="notarization input archive")
    log_sha256 = _verify_hash(evidence["log_sha256"], label="notarization log")
    if log_path.is_symlink() or not log_path.is_file() or log_path.stat().st_size > 8 * 1024 * 1024:
        raise PackageVerificationError("notarization log is missing or unsafe")
    if sha256_file(log_path) != log_sha256:
        raise PackageVerificationError("notarization log digest does not match")
    log = _strict_json_loads(log_path.read_bytes())
    if (
        type(log) is not dict
        or _canonical_uuid(log.get("jobId"), label="notarization log UUID") != submission_id
        or log.get("status") != "Accepted"
        or type(log.get("statusCode")) is not int
        or log.get("statusCode") != 0
        or log.get("issues") not in (None, [])
    ):
        raise PackageVerificationError("notarization log does not match accepted submission")
    recorded_archive_hash = log.get("sha256")
    if (
        type(recorded_archive_hash) is not str
        or _SHA256.fullmatch(recorded_archive_hash) is None
        or recorded_archive_hash != archive_sha256
    ):
        raise PackageVerificationError("notarization log archive hash does not match")
    return evidence


def _verify_signing_provenance(
    root: Path,
    value: object,
    *,
    release: dict[str, object],
    target: dict[str, object],
    contracts: dict[str, object],
    build_provenance: dict[str, object],
) -> dict[str, object]:
    signing = _exact_keys(
        value,
        {"payload_provenance", "signature_evidence", "notarization"},
        "signing provenance",
    )
    notarized = release["notarization"] == "stapled"
    payload = _verify_payload_provenance(signing["payload_provenance"], notarized=notarized)
    binding = payload["input_manifest_binding"]
    if type(binding) is not dict:
        raise PackageVerificationError("signed unsigned-manifest binding is invalid")
    bound_target = binding.get("target")
    if (
        payload["release_tool_commit"] != build_provenance["source_commit"]
        or binding.get("release_version") != release["version"]
        or bound_target
        != {
            "os": "macos",
            "architecture": target["architecture"],
            "payload": "Start Lantern (Unsigned Dev).app",
            "launcher": (
                "Start Lantern (Unsigned Dev).app/Contents/MacOS/Start Lantern (Unsigned Dev)"
            ),
            "self_test": ("Start Lantern (Unsigned Dev).app/Contents/MacOS/verify-lantern-package"),
            "macos_signature": "ad-hoc-only",
        }
        or binding.get("contracts") != contracts
        or binding.get("build_provenance") != build_provenance
        or binding.get("tree_sha256") != payload["input_tree_sha256"]
    ):
        raise PackageVerificationError(
            "outer package metadata does not match the signed unsigned-manifest binding"
        )
    if (
        build_provenance["source_dirty"] is not False
        or build_provenance["builder_python"] != "3.11.15"
        or build_provenance["builder_runtime"]
        != {
            "schema": "lantern.macos-builder-runtime.v1",
            "provider": "Astral python-build-standalone",
            "version": "3.11.15",
            "architecture": "arm64",
            "minimum_macos": "11.0",
            "runtime_lock_sha256": _RUNTIME_LOCK_SHA256,
            "runtime_archive_sha256": _RUNTIME_ARCHIVE_SHA256,
            "runtime_tree_sha256": _RUNTIME_TREE_SHA256,
            "build_site_packages_sha256": _BUILD_SITE_PACKAGES_SHA256,
            "python_executable_sha256": _RUNTIME_EXECUTABLE_SHA256,
            "libpython_sha256": _RUNTIME_LIBRARY_SHA256,
        }
    ):
        raise PackageVerificationError("signed release input was not a clean locked runtime build")
    embedded = root / str(target["payload"]) / EMBEDDED_PROVENANCE
    if embedded.is_symlink() or not embedded.is_file() or embedded.stat().st_size > 1024 * 1024:
        raise PackageVerificationError("signed payload provenance is missing or unsafe")
    if _strict_json_loads(embedded.read_bytes()) != payload:
        raise PackageVerificationError("manifest provenance does not match the signed payload")
    _verify_notarization_evidence(
        root,
        signing["notarization"],
        notarized=notarized,
    )
    return signing


def _verify_records(root: Path, value: object, tree_sha256: object) -> None:
    if type(value) is not list or not value or len(value) > 20_000:
        raise PackageVerificationError("file manifest is empty or oversized")
    if type(tree_sha256) is not str or _SHA256.fullmatch(tree_sha256) is None:
        raise PackageVerificationError("tree digest is invalid")
    actual = collect_file_records(root)
    if value != actual:
        raise PackageVerificationError("artifact tree does not match its file manifest")
    if canonical_records_sha256(actual) != tree_sha256:
        raise PackageVerificationError("artifact tree digest does not match")


def _verify_macos_plist(root: Path, target: dict[str, object], release: dict[str, object]) -> None:
    if target["os"] != "macos":
        return
    payload = root / str(target["payload"])
    info_path = payload / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file() or info_path.stat().st_size > 1024 * 1024:
        raise PackageVerificationError("macOS application Info.plist is missing or unsafe")
    try:
        with info_path.open("rb") as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PackageVerificationError("macOS application Info.plist is invalid") from exc
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)(?:\.dev([0-9]+))?", str(release["version"]))
    if match is None:
        raise PackageVerificationError("release version cannot be represented in a macOS bundle")
    build_number = int(match.group(2) or "1")
    if build_number < 1:
        raise PackageVerificationError("macOS bundle build number must be positive")
    if release["channel"] == "family-beta-development":
        expected = {
            "CFBundleIdentifier": "net.lantern.family-beta-development",
            "CFBundleDisplayName": "Start Lantern (Unsigned Dev)",
            "CFBundleShortVersionString": match.group(1),
            "CFBundleVersion": str(build_number),
            "LanternReleaseChannel": "family-beta-development",
            "LanternUnsignedDevelopment": True,
        }
    else:
        expected = {
            "CFBundleIdentifier": "net.lantern.family-beta",
            "CFBundleDisplayName": "Start Lantern",
            "CFBundleExecutable": "Start Lantern",
            "CFBundleShortVersionString": match.group(1),
            "CFBundleVersion": str(build_number),
            "LanternReleaseChannel": "family-beta-signed",
            "LanternUnsignedDevelopment": False,
        }
    for key, value in expected.items():
        if info.get(key) != value:
            raise PackageVerificationError(f"macOS bundle metadata does not match: {key}")
    if info.get("LSMinimumSystemVersion") != "11.0":
        raise PackageVerificationError(
            "macOS bundle metadata does not match: LSMinimumSystemVersion"
        )


def _verify_macos_ad_hoc(root: Path, target: dict[str, object]) -> None:
    _verify_macos_signature(
        root,
        target,
        {"channel": "family-beta-development"},
        signing=None,
    )


def _verify_macos_signature(
    root: Path,
    target: dict[str, object],
    release: dict[str, object],
    *,
    signing: dict[str, object] | None,
) -> None:
    if target["os"] != "macos":
        return
    payload = root / str(target["payload"])
    if release["channel"] == "family-beta-signed":
        if platform.system() != "Darwin":
            raise PackageVerificationError("signed macOS artifacts must be verified on macOS")
        if signing is None:
            raise PackageVerificationError("signed release provenance is unavailable")
        provenance = signing["payload_provenance"]
        if type(provenance) is not dict:
            raise PackageVerificationError("signed payload provenance is unavailable")
        certificate = SigningCertificate(
            common_name=EXPECTED_IDENTITY,
            sha1=EXPECTED_IDENTITY_SHA1,
            sha256=EXPECTED_CERTIFICATE_SHA256,
            team_id=EXPECTED_TEAM_ID,
        )
        actual_signature_evidence = verify_application_signatures(
            payload,
            certificate=certificate,
            allowed_entitlements={},
        )
        if actual_signature_evidence != signing["signature_evidence"]:
            raise PackageVerificationError(
                "signed-object evidence does not match the application signatures"
            )
        if release.get("notarization") == "stapled":
            completed = subprocess.run(
                ["/usr/bin/stapler", "validate", "-v", str(payload)],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            if completed.returncode != 0:
                raise PackageVerificationError("macOS payload is not stapled as declared")
            assess_gatekeeper(payload)
        return

    if platform.system() != "Darwin":
        return
    verification = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", str(payload)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if verification.returncode != 0:
        raise PackageVerificationError(
            "macOS application or nested runtime failed strict signing checks"
        )

    for candidate in (
        payload,
        root / str(target["launcher"]),
        root / str(target["self_test"]),
    ):
        completed = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(candidate)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        details = f"{completed.stdout}\n{completed.stderr}"
        if completed.returncode != 0:
            raise PackageVerificationError("macOS payload signature details are unavailable")
        if "Signature=adhoc" not in details:
            raise PackageVerificationError("macOS payload is not ad-hoc signed as declared")
        if "Authority=" in details or not re.search(
            r"TeamIdentifier=(?:not set|none)", details, re.IGNORECASE
        ):
            raise PackageVerificationError("macOS payload unexpectedly carries a signing identity")


def _run_offline_self_test(
    root: Path,
    target: dict[str, object],
    release: dict[str, object],
    contracts: dict[str, object],
) -> None:
    executable = root / str(target["self_test"])
    with tempfile.TemporaryDirectory(prefix="lantern-package-verify-") as temporary:
        profile_root = Path(temporary)
        home = profile_root / "home"
        scratch = profile_root / "tmp"
        work = profile_root / "work"
        for directory in (home, scratch, work):
            directory.mkdir(mode=0o700)
        environment = {
            "HOME": str(home),
            "TMPDIR": str(scratch),
            "TMP": str(scratch),
            "TEMP": str(scratch),
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
        }
        completed = subprocess.run(
            [str(executable)],
            cwd=work,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 128 * 1024:
            raise PackageVerificationError("offline package self-test did not complete cleanly")
        try:
            payload = _strict_json_loads(completed.stdout)
        except (json.JSONDecodeError, PackageVerificationError, RecursionError) as exc:
            raise PackageVerificationError(
                "offline package self-test returned invalid JSON"
            ) from exc
        expected_keys = {
            "schema",
            "product",
            "release_channel",
            "unsigned_development",
            "frozen",
            "version",
            "contracts",
            "checks",
        }
        payload = _exact_keys(payload, expected_keys, "offline self-test response")
        if (
            payload["schema"] != "lantern.package-self-test.v1"
            or payload["product"] != "Lantern"
            or payload["release_channel"] != release["channel"]
            or payload["unsigned_development"] is not release["unsigned_development"]
            or payload["frozen"] is not True
            or payload["version"] != release["version"]
            or payload["contracts"] != contracts
            or payload["checks"]
            != {
                "network_audit_guard": True,
                "report_schema": True,
                "ui_asset_manifest": True,
            }
        ):
            raise PackageVerificationError("offline package self-test contract does not match")
        created = [
            path
            for directory in (home, scratch, work)
            for path in directory.rglob("*")
            if path.is_file() or path.is_symlink()
        ]
        if created:
            raise PackageVerificationError("package self-test wrote into the clean user profile")


def verify_package(root: Path, *, require_clean_source: bool = False) -> dict[str, object]:
    """Verify integrity, provenance labels, contracts, and the offline frozen runtime."""

    if root.is_symlink():
        raise PackageVerificationError("artifact root must not be a symbolic link")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PackageVerificationError("artifact root must be a directory")
    manifest = _load_manifest(root)
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["product"] != "Lantern":
        raise PackageVerificationError("artifact is not a supported Lantern package")
    _verify_checksum_file(root)
    release = _verify_release(manifest["release"])
    target = _verify_target(root, manifest["target"], release)
    contracts = _verify_contracts(manifest["contracts"])
    provenance = _verify_provenance(
        manifest["provenance"],
        target=target,
        require_clean_source=require_clean_source,
    )
    _verify_records(root, manifest["files"], manifest["tree_sha256"])
    _verify_macos_plist(root, target, release)
    signing = None
    if release["channel"] == "family-beta-signed":
        signing = _verify_signing_provenance(
            root,
            manifest.get("signing"),
            release=release,
            target=target,
            contracts=contracts,
            build_provenance=provenance,
        )
    _verify_macos_signature(root, target, release, signing=signing)
    _run_offline_self_test(root, target, release, contracts)
    trust = {
        "family-beta-development": "UNSIGNED DEVELOPMENT BUILD",
        "family-beta-signed": (
            "SIGNED AND NOTARIZED FAMILY BETA"
            if release.get("notarization") == "stapled"
            else "SIGNED FAMILY BETA"
        ),
    }[str(release["channel"])]
    return {
        "schema": "lantern.package-verification.v1",
        "verified": True,
        "version": release["version"],
        "target": {"os": target["os"], "architecture": target["architecture"]},
        "source_commit": provenance["source_commit"],
        "source_dirty": provenance["source_dirty"],
        "offline_self_test": True,
        "clean_profile": True,
        "file_count": len(manifest["files"]),
        "tree_sha256": manifest["tree_sha256"],
        "trust": trust,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify one unpacked Lantern family-beta artifact."
    )
    parser.add_argument("artifact", type=Path, help="unpacked artifact directory")
    parser.add_argument(
        "--require-clean-source",
        action="store_true",
        help="reject artifacts whose manifest records uncommitted source changes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_package(args.artifact, require_clean_source=args.require_clean_source)
    except (OSError, subprocess.SubprocessError, PackageVerificationError) as exc:
        print(f"Lantern package verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
