"""Verify, sign, optionally notarize, and safely publish a macOS family beta."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from macos_codesign import (
    EMBEDDED_PROVENANCE,
    EXPECTED_CERTIFICATE_SHA256,
    EXPECTED_IDENTITY,
    EXPECTED_IDENTITY_SHA1,
    EXPECTED_TEAM_ID,
    SIGNED_APP_NAME,
    SIGNED_RELEASE_CHANNEL,
    SigningCertificate,
    entitlements_path,
    load_entitlement_allowlist,
    rename_and_label_app,
    resolve_signing_certificate,
    sign_application,
    signing_tool_records,
    staple,
    tool_record,
    validate_staple,
    verify_application_signatures,
)
from macos_notarize import (
    RECEIPT_NAME,
    STATE_BINDING_SCHEMA,
    load_submission_receipt,
    notary_tool_records,
    preflight_notary_credentials,
    setup_instructions,
    submit_no_wait,
    wait_for_receipt,
)
from package_family_beta import BUILD_LOCK, build_family_beta
from package_support import (
    PackageVerificationError,
    assert_zip_matches_tree,
    canonical_records_sha256,
    collect_file_records,
    publish_outputs_exclusive,
    sha256_file,
    snapshot_tree_sha256,
    write_manifest,
    write_manifest_checksum,
)
from verify_family_beta import _strict_json_loads, _verify_payload_provenance, verify_package

ROOT = Path(__file__).resolve().parents[1]
UNSIGNED_APP_NAME = "Start Lantern (Unsigned Dev).app"
UNSIGNED_NOTICE = "UNSIGNED-DEVELOPMENT-BUILD.txt"
NOTARY_LOG_NAME = "APPLE-NOTARIZATION-LOG.json"
NOTARY_ARCHIVE_NAME = "notarization-input.zip"
RUNTIME_LOCK = ROOT / "packaging" / "macos" / "runtime.lock.json"
SYSTEM_GIT = Path("/usr/bin/git")
SYSTEM_DITTO = Path("/usr/bin/ditto")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RELEASE_SOURCES = {
    "bootstrap_macos_release.py": ROOT / "scripts" / "bootstrap_macos_release.py",
    "family-beta.entitlements.plist": ROOT
    / "packaging"
    / "macos"
    / "family-beta.entitlements.plist",
    "lantern-family-beta.spec": ROOT / "packaging" / "lantern-family-beta.spec",
    "macos_codesign.py": ROOT / "scripts" / "macos_codesign.py",
    "macos_notarize.py": ROOT / "scripts" / "macos_notarize.py",
    "package_family_beta.py": ROOT / "scripts" / "package_family_beta.py",
    "package_support.py": ROOT / "scripts" / "package_support.py",
    "requirements-build.lock": BUILD_LOCK,
    "release_family_beta_macos.py": ROOT / "scripts" / "release_family_beta_macos.py",
    "runtime.lock.json": RUNTIME_LOCK,
    "verify_family_beta.py": ROOT / "scripts" / "verify_family_beta.py",
}
_SAFE_GIT_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


def _run_git(*arguments: str) -> str:
    if SYSTEM_GIT.is_symlink() or not SYSTEM_GIT.is_file() or not os.access(SYSTEM_GIT, os.X_OK):
        raise PackageVerificationError("reviewed system Git is unavailable")
    completed = subprocess.run(
        [str(SYSTEM_GIT), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=_SAFE_GIT_ENV,
    )
    if completed.returncode != 0:
        raise PackageVerificationError("release-tool Git provenance is unavailable")
    return completed.stdout.strip()


def _release_source_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, path in _RELEASE_SOURCES.items():
        if path.is_symlink() or not path.is_file():
            raise PackageVerificationError(f"release-tool source is unavailable: {name}")
        hashes[name] = sha256_file(path)
    return hashes


def _release_tool_identity() -> dict[str, object]:
    commit = _run_git("rev-parse", "HEAD")
    if _COMMIT.fullmatch(commit) is None:
        raise PackageVerificationError("release-tool commit is invalid")
    if _run_git("status", "--porcelain=v1", "--untracked-files=all"):
        raise PackageVerificationError(
            "release tools must come from a clean reviewed commit before signing"
        )
    source_hashes = _release_source_hashes()
    if _run_git("rev-parse", "HEAD") != commit or _run_git(
        "status", "--porcelain=v1", "--untracked-files=all"
    ):
        raise PackageVerificationError("release tools changed while provenance was captured")
    return {
        "release_tool_commit": commit,
        "release_tool_clean": True,
        "release_sources_sha256": source_hashes,
    }


def _assert_release_tool_unchanged(expected: dict[str, object]) -> None:
    if _run_git("rev-parse", "HEAD") != expected["release_tool_commit"]:
        raise PackageVerificationError("release-tool commit changed during release")
    if _run_git("status", "--porcelain=v1", "--untracked-files=all"):
        raise PackageVerificationError("release tools became dirty during release")
    if _release_source_hashes() != expected["release_sources_sha256"]:
        raise PackageVerificationError("release-tool bytes changed during release")


def _runtime_lock() -> dict[str, object]:
    if (
        RUNTIME_LOCK.is_symlink()
        or not RUNTIME_LOCK.is_file()
        or RUNTIME_LOCK.stat().st_size > 64 * 1024
    ):
        raise PackageVerificationError("macOS runtime lock is unavailable")
    try:
        value = json.loads(RUNTIME_LOCK.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageVerificationError("macOS runtime lock is invalid") from exc
    expected = {
        "architecture": "arm64",
        "archive": "cpython-3.11.15+20260728-aarch64-apple-darwin-install_only.tar.gz",
        "archive_sha256": "7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802",
        "build_site_packages_sha256": (
            "d027604b53d335f21c22687cfa4e69d83c7a1468664ebbbe502f5377388bb5fd"
        ),
        "libpython": "python/lib/libpython3.11.dylib",
        "libpython_sha256": ("39669f88807bff419376e0ba17ae68d194f065f7959fb61cd4777af65da09e51"),
        "minimum_macos": "11.0",
        "provider": "Astral python-build-standalone",
        "python_executable": "python/bin/python3.11",
        "python_executable_sha256": (
            "95c331c5e61804b2dcea00dd105fbf7c9e417aaabff23fa5da6758d84033029d"
        ),
        "release": "20260728",
        "runtime_tree_sha256": ("89f2b0d5e85dc62c5ec225dc850e097f863c7406d23a2835a4e983f050ee093d"),
        "schema": "lantern.macos-runtime.v1",
        "url": (
            "https://github.com/astral-sh/python-build-standalone/releases/download/20260728/"
            "cpython-3.11.15%2B20260728-aarch64-apple-darwin-install_only.tar.gz"
        ),
        "version": "3.11.15",
        "wheels": {
            "altgraph-0.17.5-py2.py3-none-any.whl": (
                "f3a22400bce1b0c701683820ac4f3b159cd301acab067c51c653e06961600597"
            ),
            "macholib-1.16.4-py2.py3-none-any.whl": (
                "da1a3fa8266e30f0ce7e97c6a54eefaae8edd1e5f86f3eb8b95457cae90265ea"
            ),
            "packaging-26.3-py3-none-any.whl": (
                "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
            ),
            "pyinstaller-6.22.1-py3-none-macosx_10_13_universal2.whl": (
                "d519a5549bf560407a9cffa8547f278e79c1093dc1cade6d9658c67b650d66c4"
            ),
            "pyinstaller_hooks_contrib-2026.6-py3-none-any.whl": (
                "fd13b8ac126b35361175edacd41a0d97080b75dd5f4b594ecefefff969509dd3"
            ),
            "setuptools-84.0.0-py3-none-any.whl": (
                "51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670"
            ),
        },
    }
    if value != expected:
        raise PackageVerificationError("macOS runtime lock does not match the reviewed runtime")
    return {
        "runtime_lock_sha256": sha256_file(RUNTIME_LOCK),
        "runtime_archive_sha256": expected["archive_sha256"],
        "runtime_version": expected["version"],
        "runtime_python_executable_sha256": expected["python_executable_sha256"],
        "runtime_libpython_sha256": expected["libpython_sha256"],
        "runtime_tree_sha256": expected["runtime_tree_sha256"],
        "build_site_packages_sha256": expected["build_site_packages_sha256"],
    }


def _run_ditto(arguments: list[str], *, timeout: int = 5 * 60) -> None:
    try:
        completed = subprocess.run(
            [str(SYSTEM_DITTO), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise PackageVerificationError("Apple archive command timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise PackageVerificationError(f"Apple archive command failed: {detail}")


def _validate_apple_zip_names(archive: Path, *, root_name: str) -> None:
    try:
        with zipfile.ZipFile(archive) as stream:
            infos = stream.infolist()
            names = [item.filename for item in infos]
            if not infos or len(infos) > 40_001 or len(names) != len(set(names)):
                raise PackageVerificationError("Apple archive member set is invalid")
            total = 0
            for info in infos:
                name = info.filename.rstrip("/")
                if not name or "\x00" in name or "\\" in name:
                    raise PackageVerificationError("Apple archive member path is invalid")
                path = PurePosixPath(name)
                if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                    raise PackageVerificationError("Apple archive member path is invalid")
                if path.parts[0] == "__MACOSX":
                    if len(path.parts) < 2 or path.parts[1] != root_name:
                        raise PackageVerificationError("Apple archive metadata path is invalid")
                elif path.parts[0] != root_name:
                    raise PackageVerificationError("Apple archive root does not match")
                if info.file_size > 512 * 1024 * 1024:
                    raise PackageVerificationError("Apple archive member is oversized")
                total += info.file_size
                if total > 2 * 1024 * 1024 * 1024:
                    raise PackageVerificationError("Apple archive is oversized")
    except zipfile.BadZipFile as exc:
        raise PackageVerificationError("Apple archive is not a valid ZIP") from exc


def _create_apple_zip(source: Path, archive: Path) -> None:
    """Use Apple's ZIP writer so signatures, resource forks, and staple data survive."""

    if source.is_symlink() or not source.is_dir():
        raise PackageVerificationError("Apple archive source is unavailable")
    if archive.exists() or archive.is_symlink():
        raise PackageVerificationError("Apple archive destination already exists")
    _run_ditto(["-c", "-k", "--keepParent", str(source), str(archive)])
    if archive.is_symlink() or not archive.is_file():
        raise PackageVerificationError("Apple archive was not created")
    _validate_apple_zip_names(archive, root_name=source.name)


def _verify_apple_zip(source: Path, archive: Path, *, stapled_app: str | None) -> None:
    """Round-trip Apple's ZIP and verify bytes plus an optional stapled app ticket."""

    _validate_apple_zip_names(archive, root_name=source.name)
    with tempfile.TemporaryDirectory(prefix="lantern-apple-archive-verify-") as temporary:
        extraction = Path(temporary) / "extracted"
        extraction.mkdir(mode=0o700)
        _run_ditto(["-x", "-k", str(archive), str(extraction)])
        extracted = extraction / source.name
        if extracted.is_symlink() or not extracted.is_dir():
            raise PackageVerificationError("Apple archive did not preserve its root")
        if snapshot_tree_sha256(extracted) != snapshot_tree_sha256(source):
            raise PackageVerificationError("Apple archive changed signed artifact bytes")
        if stapled_app is not None:
            validate_staple(extracted / stapled_app)


def _artifact_name(version: str, architecture: str, *, notarized: bool) -> str:
    suffix = "SIGNED-NOTARIZED" if notarized else "SIGNED"
    return f"lantern-family-beta-{version}-macos-{architecture}-{suffix}"


def _signed_notices(*, version: str, commit: str, notarized: bool) -> tuple[str, str]:
    trust = (
        "Developer ID signed, Apple-notarized, and stapled"
        if notarized
        else "Developer ID signed; Apple notarization was not requested for this artifact"
    )
    start_here = f"""START HERE — LANTERN LOCAL FAMILY BETA

This is Lantern {version}, built from clean source commit {commit}. It is {trust}.

macOS: open “{SIGNED_APP_NAME}”. Opening Lantern starts only a short-lived interface on
this computer. A diagnostic does not start until the person at the computer chooses a
goal, reviews the stated scope, and presses Start check.

Packaging adds no automatic software download/update mechanism, installer, persistence,
elevation, autorun, USB behavior, telemetry, or remote service. Before sharing any
exported report, review it. This family beta is not a security audit or certification.

Compare the ZIP SHA-256 through a separately trusted channel. A checksum detects changed
bytes; Apple's Developer ID signature establishes the application publisher.
"""
    signed_notice = f"""SIGNED FAMILY BETA — NOT A PRODUCTION CERTIFICATION

Lantern {version} is signed with the pinned Developer ID Application certificate for team
{EXPECTED_TEAM_ID}. {trust.capitalize()}.

This artifact is intended only for a small, supervised family beta. It is not an
installer, managed endpoint agent, enterprise scanner, compliance tool, or rescue disk.
It adds no updater, persistence, elevation, autorun, USB behavior, telemetry, or remotely
reachable service.
"""
    return start_here, signed_notice


def _write_exclusive(path: Path, content: str | bytes) -> None:
    mode = "xb" if isinstance(content, bytes) else "x"
    kwargs = {} if isinstance(content, bytes) else {"encoding": "utf-8", "newline": "\n"}
    try:
        with path.open(mode, **kwargs) as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise PackageVerificationError(f"refusing to replace staged file: {path.name}") from exc


def _load_existing_manifest(artifact: Path) -> dict[str, object]:
    manifest_path = artifact / "package-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise PackageVerificationError("unsigned artifact manifest is unavailable")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageVerificationError("unsigned artifact manifest is invalid") from exc
    if type(payload) is not dict:
        raise PackageVerificationError("unsigned artifact manifest is invalid")
    return payload


def _verified_unsigned_input(
    unsigned_artifact: Path,
    unsigned_archive: Path,
    *,
    expected_source_commit: str,
    expected_snapshot_sha256: str,
    expected_manifest_sha256: str,
    expected_tree_sha256: str,
    expected_archive_sha256: str,
) -> tuple[dict[str, object], str]:
    """Snapshot around full verification so no unverified bytes become signing input."""

    before = snapshot_tree_sha256(unsigned_artifact)
    if before != expected_snapshot_sha256:
        raise PackageVerificationError("unsigned input does not match the fresh build snapshot")
    if (
        unsigned_archive.is_symlink()
        or not unsigned_archive.is_file()
        or sha256_file(unsigned_archive) != expected_archive_sha256
    ):
        raise PackageVerificationError("unsigned archive does not match the fresh build receipt")
    assert_zip_matches_tree(unsigned_artifact, unsigned_archive)
    result = verify_package(unsigned_artifact, require_clean_source=True)
    after = snapshot_tree_sha256(unsigned_artifact)
    if before != after:
        raise PackageVerificationError("unsigned input changed during verification")
    if result.get("trust") != "UNSIGNED DEVELOPMENT BUILD":
        raise PackageVerificationError("source artifact is not the unsigned development channel")
    manifest = _load_existing_manifest(unsigned_artifact)
    if snapshot_tree_sha256(unsigned_artifact) != before:
        raise PackageVerificationError("unsigned input changed after verification")
    release = manifest.get("release")
    target = manifest.get("target")
    provenance = manifest.get("provenance")
    runtime = _runtime_lock()
    expected_builder_runtime = {
        "schema": "lantern.macos-builder-runtime.v1",
        "provider": "Astral python-build-standalone",
        "version": runtime["runtime_version"],
        "architecture": "arm64",
        "minimum_macos": "11.0",
        "runtime_lock_sha256": runtime["runtime_lock_sha256"],
        "runtime_archive_sha256": runtime["runtime_archive_sha256"],
        "runtime_tree_sha256": runtime["runtime_tree_sha256"],
        "build_site_packages_sha256": runtime["build_site_packages_sha256"],
        "python_executable_sha256": runtime["runtime_python_executable_sha256"],
        "libpython_sha256": runtime["runtime_libpython_sha256"],
    }
    if (
        type(release) is not dict
        or release.get("channel") != "family-beta-development"
        or release.get("unsigned_development") is not True
        or type(target) is not dict
        or target.get("os") != "macos"
        or target.get("architecture") != "arm64"
        or type(provenance) is not dict
        or provenance.get("source_dirty") is not False
        or provenance.get("source_commit") != expected_source_commit
        or provenance.get("builder_python") != "3.11.15"
        or provenance.get("build_lock_sha256") != sha256_file(BUILD_LOCK)
        or provenance.get("builder_runtime") != expected_builder_runtime
        or manifest.get("tree_sha256") != expected_tree_sha256
        or sha256_file(unsigned_artifact / "package-manifest.json") != expected_manifest_sha256
    ):
        raise PackageVerificationError(
            "unsigned input does not match the locked macOS release target"
        )
    return manifest, before


def _payload_provenance(
    *,
    unsigned_artifact: Path,
    unsigned_manifest: dict[str, object],
    input_snapshot_sha256: str,
    input_archive_sha256: str,
    release_tool: dict[str, object],
    certificate: SigningCertificate,
    tools: dict[str, dict[str, str]],
) -> dict[str, object]:
    runtime = _runtime_lock()
    manifest_tree = unsigned_manifest.get("tree_sha256")
    if type(manifest_tree) is not str or _SHA256.fullmatch(manifest_tree) is None:
        raise PackageVerificationError("unsigned input tree digest is invalid")
    return {
        "schema": "lantern.macos-signing.v1",
        **release_tool,
        "input_snapshot_sha256": input_snapshot_sha256,
        "input_manifest_sha256": sha256_file(unsigned_artifact / "package-manifest.json"),
        "input_tree_sha256": manifest_tree,
        "input_archive_sha256": input_archive_sha256,
        "input_manifest_binding": {
            "release_version": unsigned_manifest["release"]["version"],
            "target": unsigned_manifest["target"],
            "contracts": unsigned_manifest["contracts"],
            "build_provenance": unsigned_manifest["provenance"],
            "tree_sha256": manifest_tree,
        },
        "entitlements_sha256": sha256_file(entitlements_path()),
        **runtime,
        "certificate_common_name": certificate.common_name,
        "certificate_sha1": certificate.sha1,
        "certificate_sha256": certificate.sha256,
        "team_id": certificate.team_id,
        "tools": tools,
    }


def _write_embedded_provenance(app_path: Path, payload: dict[str, object]) -> None:
    destination = app_path / EMBEDDED_PROVENANCE
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_exclusive(destination, encoded)


def _prepare_signed_tree(
    source: Path,
    destination: Path,
    *,
    expected_snapshot_sha256: str,
) -> Path:
    if destination.exists() or destination.is_symlink():
        raise PackageVerificationError("signed artifact staging destination already exists")
    shutil.copytree(source, destination, symlinks=True)
    if snapshot_tree_sha256(destination) != expected_snapshot_sha256:
        raise PackageVerificationError("copied unsigned input does not match verified bytes")
    for name in ("package-manifest.json", "SHA256SUMS.txt", "START-HERE.txt", UNSIGNED_NOTICE):
        path = destination / name
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            raise PackageVerificationError(f"unsigned package metadata is missing: {name}")
    unsigned_app = destination / UNSIGNED_APP_NAME
    if not unsigned_app.is_dir() or unsigned_app.is_symlink():
        raise PackageVerificationError("unsigned application bundle is unavailable")
    return rename_and_label_app(unsigned_app)


def _build_signed_manifest(
    artifact: Path,
    *,
    unsigned_manifest: dict[str, object],
    payload_provenance: dict[str, object],
    signature_evidence: dict[str, object],
    notarization: dict[str, object],
) -> dict[str, object]:
    release = unsigned_manifest["release"]
    target = unsigned_manifest["target"]
    if type(release) is not dict or type(target) is not dict:
        raise PackageVerificationError("unsigned artifact manifest is incomplete")
    notarized = notarization["status"] == "Accepted"
    records = collect_file_records(artifact)
    return {
        "schema": "lantern.package.v1",
        "product": "Lantern",
        "release": {
            "version": release["version"],
            "channel": SIGNED_RELEASE_CHANNEL,
            "label": "SIGNED AND NOTARIZED FAMILY BETA" if notarized else "SIGNED FAMILY BETA",
            "unsigned_development": False,
            "developer_id_signing": f"team-id:{EXPECTED_TEAM_ID}",
            "notarization": "stapled" if notarized else "not-performed",
            "auto_update": False,
            "installer": False,
            "elevation": False,
            "autorun": False,
            "persistence": False,
            "usb_autorun": False,
            "packaging_network_additions": "none",
        },
        "target": {
            "os": "macos",
            "architecture": target["architecture"],
            "payload": SIGNED_APP_NAME,
            "launcher": f"{SIGNED_APP_NAME}/Contents/MacOS/Start Lantern",
            "self_test": f"{SIGNED_APP_NAME}/Contents/MacOS/verify-lantern-package",
            "macos_signature": "developer-id-application",
        },
        "contracts": unsigned_manifest["contracts"],
        "provenance": unsigned_manifest["provenance"],
        "signing": {
            "payload_provenance": payload_provenance,
            "signature_evidence": signature_evidence,
            "notarization": notarization,
        },
        "files": records,
        "tree_sha256": canonical_records_sha256(records),
    }


def _notarization_default() -> dict[str, object]:
    return {
        "status": "not-performed",
        "submission_id": None,
        "archive_sha256": None,
        "log_sha256": None,
    }


def _validate_output_directory(output_dir: Path) -> Path:
    if output_dir.exists() and output_dir.is_symlink():
        raise PackageVerificationError("output directory must not be a symbolic link")
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = output_dir.resolve(strict=True)
    if resolved in {Path("/"), Path.home().resolve()}:
        raise PackageVerificationError("output directory is too broad")
    return resolved


def _output_paths(output_dir: Path, final_name: str) -> tuple[Path, Path, Path]:
    return (
        output_dir / final_name,
        output_dir / f"{final_name}.zip",
        output_dir / f"{final_name}.zip.sha256",
    )


def _assert_outputs_available(paths: tuple[Path, Path, Path]) -> None:
    for destination in paths:
        if destination.exists() or destination.is_symlink():
            raise PackageVerificationError(
                f"refusing to replace existing output: {destination.name}"
            )


def _complete_and_publish(
    artifact: Path,
    output_dir: Path,
    *,
    final_name: str,
    unsigned_manifest: dict[str, object],
    payload_provenance: dict[str, object],
    signature_evidence: dict[str, object],
    notarization: dict[str, object],
    release_tool: dict[str, object],
) -> dict[str, object]:
    """Create final metadata/archive and exclusively publish a fully verified artifact."""

    artifact_destination, archive_destination, archive_checksum_destination = _output_paths(
        output_dir, final_name
    )
    _assert_outputs_available(
        (artifact_destination, archive_destination, archive_checksum_destination)
    )
    release = unsigned_manifest["release"]
    target = unsigned_manifest["target"]
    provenance = unsigned_manifest["provenance"]
    if type(release) is not dict or type(target) is not dict or type(provenance) is not dict:
        raise PackageVerificationError("unsigned artifact manifest is incomplete")
    notarized = notarization.get("status") == "Accepted"
    source_commit = str(provenance["source_commit"])
    start_here, signed_notice = _signed_notices(
        version=str(release["version"]),
        commit=source_commit,
        notarized=notarized,
    )
    _write_exclusive(artifact / "START-HERE.txt", start_here)
    _write_exclusive(artifact / "SIGNED-FAMILY-BETA.txt", signed_notice)
    manifest = _build_signed_manifest(
        artifact,
        unsigned_manifest=unsigned_manifest,
        payload_provenance=payload_provenance,
        signature_evidence=signature_evidence,
        notarization=notarization,
    )
    write_manifest(artifact, manifest)
    write_manifest_checksum(artifact)
    verify_package(artifact, require_clean_source=True)

    with tempfile.TemporaryDirectory(prefix="lantern-final-archive-") as temporary:
        staging = Path(temporary)
        archive = staging / archive_destination.name
        _create_apple_zip(artifact, archive)
        _verify_apple_zip(
            artifact,
            archive,
            stapled_app=SIGNED_APP_NAME if notarized else None,
        )
        archive_checksum = staging / archive_checksum_destination.name
        _write_exclusive(archive_checksum, f"{sha256_file(archive)}  {archive.name}\n")
        _assert_release_tool_unchanged(release_tool)

        def verify_published() -> None:
            _assert_release_tool_unchanged(release_tool)
            verify_package(artifact_destination, require_clean_source=True)
            _verify_apple_zip(
                artifact_destination,
                archive_destination,
                stapled_app=SIGNED_APP_NAME if notarized else None,
            )
            expected = f"{sha256_file(archive_destination)}  {archive_destination.name}\n"
            if archive_checksum_destination.read_text(encoding="ascii") != expected:
                raise PackageVerificationError("published archive checksum does not match")

        publish_outputs_exclusive(
            (
                (artifact, artifact_destination),
                (archive, archive_destination),
                (archive_checksum, archive_checksum_destination),
            ),
            verify=verify_published,
        )

    return {
        "schema": "lantern.package-release.v1",
        "artifact": str(artifact_destination),
        "archive": str(archive_destination),
        "archive_sha256": sha256_file(archive_destination),
        "manifest_sha256": sha256_file(artifact_destination / "package-manifest.json"),
        "version": release["version"],
        "target": {"os": "macos", "architecture": target["architecture"]},
        "source_commit": provenance["source_commit"],
        "source_dirty": False,
        "release_tool_commit": release_tool["release_tool_commit"],
        "signature_inventory_sha256": signature_evidence["inventory_sha256"],
        "outer_cdhash": signature_evidence["outer_cdhash"],
        "notarization": "stapled" if notarized else "not-performed",
        "submission_id": notarization["submission_id"],
        "trust": ("SIGNED AND NOTARIZED FAMILY BETA" if notarized else "SIGNED FAMILY BETA"),
    }


def _notarization_binding(
    artifact: Path,
    app_path: Path,
    *,
    final_name: str,
    release_tool: dict[str, object],
) -> dict[str, str]:
    embedded = app_path / EMBEDDED_PROVENANCE
    if embedded.is_symlink() or not embedded.is_file():
        raise PackageVerificationError("signed payload provenance is unavailable")
    return {
        "schema": STATE_BINDING_SCHEMA,
        "artifact_name": final_name,
        "artifact_snapshot_sha256": snapshot_tree_sha256(artifact),
        "app_snapshot_sha256": snapshot_tree_sha256(app_path),
        "embedded_provenance_sha256": sha256_file(embedded),
        "release_tool_commit": str(release_tool["release_tool_commit"]),
    }


def _load_resume_payload(
    app_path: Path,
    *,
    binding: dict[str, object],
    release_tool: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    embedded = app_path / EMBEDDED_PROVENANCE
    if (
        embedded.is_symlink()
        or not embedded.is_file()
        or embedded.stat().st_size > 1024 * 1024
        or sha256_file(embedded) != binding["embedded_provenance_sha256"]
    ):
        raise PackageVerificationError("retained signed provenance does not match its receipt")
    payload = _strict_json_loads(embedded.read_bytes())
    payload = _verify_payload_provenance(payload, notarized=True)
    if (
        payload.get("release_tool_commit") != release_tool["release_tool_commit"]
        or payload.get("release_sources_sha256") != release_tool["release_sources_sha256"]
        or binding.get("release_tool_commit") != release_tool["release_tool_commit"]
    ):
        raise PackageVerificationError("retained notarization state is from another release")
    manifest_binding = payload.get("input_manifest_binding")
    if type(manifest_binding) is not dict:
        raise PackageVerificationError("retained unsigned-manifest binding is invalid")
    unsigned_manifest = {
        "release": {"version": manifest_binding["release_version"]},
        "target": manifest_binding["target"],
        "contracts": manifest_binding["contracts"],
        "provenance": manifest_binding["build_provenance"],
        "tree_sha256": manifest_binding["tree_sha256"],
    }
    return payload, unsigned_manifest


def _validate_notarization_work_directory(work_dir: Path, output_dir: Path) -> Path:
    if work_dir.is_symlink() or not work_dir.is_dir():
        raise PackageVerificationError("notarization state directory is unavailable")
    resolved = work_dir.resolve(strict=True)
    details = resolved.stat()
    if (
        resolved.parent != output_dir
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise PackageVerificationError("notarization state directory is not owner-private")
    return resolved


def _notarization_state_is_unchanged(
    work_dir: Path,
    expected_identity: tuple[int, int],
) -> bool:
    """Check a retained state root without ever deleting through its pathname."""

    try:
        current = work_dir.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and not work_dir.is_symlink()
        and (current.st_dev, current.st_ino) == expected_identity
    )


def resume_notarized_family_beta(
    work_dir: Path,
    output_dir: Path,
) -> dict[str, object]:
    """Resume the one recorded Apple submission without rebuilding or resubmitting."""

    if platform.system() != "Darwin":
        raise PackageVerificationError("macOS notarization must run on a supported Mac host")
    if os.environ.get("LANTERN_RELEASE_BOOTSTRAP") != "lantern.macos-bootstrap.v1":
        raise PackageVerificationError(
            "notarization resume must be launched by the reviewed sealed macOS bootstrap"
        )
    output_dir = _validate_output_directory(output_dir)
    work_dir = _validate_notarization_work_directory(work_dir, output_dir)
    work_identity = (work_dir.stat().st_dev, work_dir.stat().st_ino)
    archive = work_dir / NOTARY_ARCHIVE_NAME
    receipt_path = work_dir / RECEIPT_NAME
    receipt = load_submission_receipt(receipt_path, archive)
    binding = receipt["binding"]
    if type(binding) is not dict:
        raise PackageVerificationError("notarization receipt binding is invalid")
    final_name = str(binding["artifact_name"])
    artifact = work_dir / final_name
    app_path = artifact / SIGNED_APP_NAME
    allowed_entries = {final_name, NOTARY_ARCHIVE_NAME, RECEIPT_NAME, NOTARY_LOG_NAME}
    actual_entries = {path.name for path in work_dir.iterdir()}
    if not actual_entries.issubset(allowed_entries) or not {
        final_name,
        NOTARY_ARCHIVE_NAME,
        RECEIPT_NAME,
    }.issubset(actual_entries):
        raise PackageVerificationError("notarization state directory contains unexpected entries")
    if (
        artifact.is_symlink()
        or not artifact.is_dir()
        or app_path.is_symlink()
        or not app_path.is_dir()
        or snapshot_tree_sha256(artifact) != binding["artifact_snapshot_sha256"]
        or snapshot_tree_sha256(app_path) != binding["app_snapshot_sha256"]
    ):
        raise PackageVerificationError("retained signed artifact does not match its receipt")
    release_tool = _release_tool_identity()
    payload, unsigned_manifest = _load_resume_payload(
        app_path,
        binding=binding,
        release_tool=release_tool,
    )
    release = unsigned_manifest["release"]
    target = unsigned_manifest["target"]
    if type(release) is not dict or type(target) is not dict:
        raise PackageVerificationError("retained release binding is invalid")
    expected_name = _artifact_name(
        str(release["version"]),
        str(target["architecture"]),
        notarized=True,
    )
    if final_name != expected_name:
        raise PackageVerificationError("notarization state artifact name does not match")
    _assert_outputs_available(_output_paths(output_dir, final_name))
    certificate = resolve_signing_certificate()
    if (
        certificate.common_name != EXPECTED_IDENTITY
        or certificate.sha1 != EXPECTED_IDENTITY_SHA1
        or certificate.sha256 != EXPECTED_CERTIFICATE_SHA256
        or certificate.team_id != EXPECTED_TEAM_ID
    ):
        raise PackageVerificationError("Developer ID certificate does not match the release pin")
    verify_application_signatures(
        app_path,
        certificate=certificate,
        allowed_entitlements=load_entitlement_allowlist(),
    )
    _verify_apple_zip(app_path, archive, stapled_app=None)
    notarization = wait_for_receipt(
        archive,
        receipt_path,
        work_dir / NOTARY_LOG_NAME,
        expected_binding=binding,
    )

    with tempfile.TemporaryDirectory(prefix="lantern-notarization-finalize-") as temporary:
        final_artifact = Path(temporary) / final_name
        shutil.copytree(artifact, final_artifact, symlinks=True)
        if snapshot_tree_sha256(final_artifact) != binding["artifact_snapshot_sha256"]:
            raise PackageVerificationError("retained artifact changed during finalization copy")
        final_app = final_artifact / SIGNED_APP_NAME
        log_bytes = (work_dir / NOTARY_LOG_NAME).read_bytes()
        _write_exclusive(final_artifact / NOTARY_LOG_NAME, log_bytes)
        staple(final_app)
        validate_staple(final_app)
        signature_evidence = verify_application_signatures(
            final_app,
            certificate=certificate,
            allowed_entitlements=load_entitlement_allowlist(),
        )
        result = _complete_and_publish(
            final_artifact,
            output_dir,
            final_name=final_name,
            unsigned_manifest=unsigned_manifest,
            payload_provenance=payload,
            signature_evidence=signature_evidence,
            notarization=dict(notarization),
            release_tool=release_tool,
        )

    if not _notarization_state_is_unchanged(work_dir, work_identity):
        raise PackageVerificationError(
            "notarization state identity changed; published output is valid but state was retained"
        )
    # Deliberately retain the private state. Path-based recursive deletion after an
    # identity check has an unavoidable rename/replacement race. The operator can
    # move this bounded evidence directory to Trash after independently verifying
    # the published artifact.
    result["retained_notarization_state"] = str(work_dir)
    return result


def _release_verified_family_beta(
    unsigned_artifact: Path,
    unsigned_archive: Path,
    output_dir: Path,
    *,
    notarize: bool,
    release_tool: dict[str, object],
    build_receipt: dict[str, object],
) -> dict[str, object]:
    """Sign only the fresh unsigned precursor produced by this release invocation."""

    if platform.system() != "Darwin":
        raise PackageVerificationError("macOS signing must run on a supported Mac build host")
    if unsigned_artifact.is_symlink() or not unsigned_artifact.is_dir():
        raise PackageVerificationError("unsigned artifact directory is unavailable")
    unsigned_artifact = unsigned_artifact.resolve(strict=True)

    _assert_release_tool_unchanged(release_tool)
    if build_receipt.get("source_commit") != release_tool["release_tool_commit"]:
        raise PackageVerificationError(
            "fresh unsigned build does not match the release-tool commit"
        )
    unsigned_manifest, input_snapshot = _verified_unsigned_input(
        unsigned_artifact,
        unsigned_archive,
        expected_source_commit=str(release_tool["release_tool_commit"]),
        expected_snapshot_sha256=str(build_receipt.get("artifact_snapshot_sha256", "")),
        expected_manifest_sha256=str(build_receipt.get("manifest_sha256", "")),
        expected_tree_sha256=str(build_receipt.get("tree_sha256", "")),
        expected_archive_sha256=str(build_receipt.get("archive_sha256", "")),
    )
    release = unsigned_manifest["release"]
    target = unsigned_manifest["target"]
    provenance = unsigned_manifest["provenance"]
    if type(release) is not dict or type(target) is not dict or type(provenance) is not dict:
        raise PackageVerificationError("unsigned artifact manifest is incomplete")
    version = str(release.get("version", ""))
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.(?:dev|post)[0-9]+)?", version) is None:
        raise PackageVerificationError("artifact version is invalid")
    architecture = str(target["architecture"])
    source_epoch = provenance.get("source_epoch")
    if type(source_epoch) is not int or source_epoch <= 0:
        raise PackageVerificationError("artifact source epoch is invalid")

    certificate = resolve_signing_certificate()
    if (
        certificate.common_name != EXPECTED_IDENTITY
        or certificate.sha1 != EXPECTED_IDENTITY_SHA1
        or certificate.sha256 != EXPECTED_CERTIFICATE_SHA256
        or certificate.team_id != EXPECTED_TEAM_ID
    ):
        raise PackageVerificationError("Developer ID certificate does not match the release pin")
    load_entitlement_allowlist()
    tools = signing_tool_records()
    tools["ditto"] = tool_record(SYSTEM_DITTO)
    tools["git"] = tool_record(SYSTEM_GIT)
    tools["python"] = tool_record(Path(sys.executable))
    if notarize:
        try:
            preflight_notary_credentials()
        except PackageVerificationError as exc:
            raise PackageVerificationError(
                "notarization keychain profile is unavailable\n\n" + setup_instructions()
            ) from exc
        tools.update(notary_tool_records())

    payload_provenance = _payload_provenance(
        unsigned_artifact=unsigned_artifact,
        unsigned_manifest=unsigned_manifest,
        input_snapshot_sha256=input_snapshot,
        input_archive_sha256=str(build_receipt["archive_sha256"]),
        release_tool=release_tool,
        certificate=certificate,
        tools=tools,
    )
    output_dir = _validate_output_directory(output_dir)
    final_name = _artifact_name(version, architecture, notarized=notarize)
    _assert_outputs_available(_output_paths(output_dir, final_name))

    if notarize:
        work_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{final_name}.notarization-",
                dir=output_dir,
            )
        )
        work_dir.chmod(0o700)
        work_identity = (work_dir.stat().st_dev, work_dir.stat().st_ino)
        receipt_path = work_dir / RECEIPT_NAME
        try:
            artifact = work_dir / final_name
            app_path = _prepare_signed_tree(
                unsigned_artifact,
                artifact,
                expected_snapshot_sha256=input_snapshot,
            )
            if snapshot_tree_sha256(unsigned_artifact) != input_snapshot:
                raise PackageVerificationError("unsigned input changed while it was copied")
            _write_embedded_provenance(app_path, payload_provenance)
            sign_application(app_path, certificate=certificate)
            submission_archive = work_dir / NOTARY_ARCHIVE_NAME
            _create_apple_zip(app_path, submission_archive)
            _verify_apple_zip(app_path, submission_archive, stapled_app=None)
            binding = _notarization_binding(
                artifact,
                app_path,
                final_name=final_name,
                release_tool=release_tool,
            )
            submit_no_wait(
                submission_archive,
                receipt_path,
                binding=binding,
            )
            if snapshot_tree_sha256(unsigned_artifact) != input_snapshot:
                raise PackageVerificationError("unsigned input changed after notarization upload")
            return resume_notarized_family_beta(work_dir, output_dir)
        except Exception as exc:
            if receipt_path.is_file() and not receipt_path.is_symlink():
                raise PackageVerificationError(
                    "notarization did not finish; resume the retained state with "
                    f"--resume-notarization {work_dir}"
                ) from exc
            if _notarization_state_is_unchanged(work_dir, work_identity):
                raise PackageVerificationError(
                    "notarization preparation failed before a submission receipt was recorded; "
                    f"private state was retained for review at {work_dir}"
                ) from exc
            raise PackageVerificationError(
                "notarization preparation failed before a submission receipt was recorded; "
                "the state path identity changed and no cleanup was attempted"
            ) from exc

    with tempfile.TemporaryDirectory(prefix="lantern-signed-build-") as temporary:
        artifact = Path(temporary) / final_name
        app_path = _prepare_signed_tree(
            unsigned_artifact,
            artifact,
            expected_snapshot_sha256=input_snapshot,
        )
        if snapshot_tree_sha256(unsigned_artifact) != input_snapshot:
            raise PackageVerificationError("unsigned input changed while it was copied")
        _write_embedded_provenance(app_path, payload_provenance)
        signature_evidence = sign_application(app_path, certificate=certificate)
        if snapshot_tree_sha256(unsigned_artifact) != input_snapshot:
            raise PackageVerificationError("unsigned input changed before publication")
        return _complete_and_publish(
            artifact,
            output_dir,
            final_name=final_name,
            unsigned_manifest=unsigned_manifest,
            payload_provenance=payload_provenance,
            signature_evidence=signature_evidence,
            notarization=_notarization_default(),
            release_tool=release_tool,
        )


def release_signed_family_beta(
    output_dir: Path,
    *,
    notarize: bool,
) -> dict[str, object]:
    """Build, sign, optionally notarize, and publish one clean commit atomically."""

    if platform.system() != "Darwin":
        raise PackageVerificationError("macOS signing must run on a supported Mac build host")
    if os.environ.get("LANTERN_RELEASE_BOOTSTRAP") != "lantern.macos-bootstrap.v1":
        raise PackageVerificationError(
            "release must be launched by the reviewed sealed macOS bootstrap"
        )
    release_tool = _release_tool_identity()
    with tempfile.TemporaryDirectory(prefix="lantern-fresh-unsigned-") as temporary:
        build_receipt = build_family_beta(Path(temporary) / "build", allow_dirty=False)
        _assert_release_tool_unchanged(release_tool)
        unsigned_artifact = Path(str(build_receipt["artifact"])).resolve(strict=True)
        unsigned_archive = Path(str(build_receipt["archive"])).resolve(strict=True)
        return _release_verified_family_beta(
            unsigned_artifact,
            unsigned_archive,
            output_dir,
            notarize=notarize,
            release_tool=release_tool,
            build_receipt=build_receipt,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a fresh clean Lantern macOS family beta, sign it, and optionally notarize it."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "dist" / "family-beta",
        help="signed artifacts are created here without replacing existing files",
    )
    parser.add_argument(
        "--notarize",
        action="store_true",
        help="submit with the Keychain profile, require Accepted, retrieve its log, and staple",
    )
    parser.add_argument(
        "--resume-notarization",
        type=Path,
        help="resume one retained notarization state without rebuilding or resubmitting",
    )
    parser.add_argument(
        "--require-clean-source",
        action="store_true",
        help="compatibility flag; clean unsigned source and release tools are always required",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.resume_notarization is not None:
            if args.notarize:
                raise PackageVerificationError(
                    "--resume-notarization cannot be combined with --notarize"
                )
            result = resume_notarized_family_beta(
                args.resume_notarization,
                args.output_dir,
            )
        else:
            result = release_signed_family_beta(
                args.output_dir,
                notarize=args.notarize,
            )
    except (OSError, subprocess.SubprocessError, PackageVerificationError) as exc:
        print(f"Lantern macOS family-beta release failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
