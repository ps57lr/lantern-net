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
from pathlib import Path

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
_EXACT_MANIFEST_KEYS = {
    "schema",
    "product",
    "release",
    "target",
    "contracts",
    "provenance",
    "files",
    "tree_sha256",
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
    return _exact_keys(payload, _EXACT_MANIFEST_KEYS, "package manifest")


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
    fixed = {
        "channel": "family-beta-development",
        "label": "UNSIGNED DEVELOPMENT BUILD",
        "unsigned_development": True,
        "developer_id_signing": "not-configured",
        "notarization": "not-performed",
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
    return release


def _verify_target(root: Path, value: object) -> dict[str, object]:
    target = _exact_keys(
        value,
        {"os", "architecture", "payload", "launcher", "self_test", "macos_signature"},
        "target metadata",
    )
    if target["os"] not in {"macos", "linux"}:
        raise PackageVerificationError("unsupported artifact operating system")
    if target["architecture"] not in {"arm64", "x86_64"}:
        raise PackageVerificationError("unsupported artifact architecture")
    expected_signature = "ad-hoc-only" if target["os"] == "macos" else "not-applicable"
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


def _verify_provenance(value: object, *, require_clean_source: bool) -> dict[str, object]:
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
    if (
        type(provenance["build_lock_sha256"]) is not str
        or _SHA256.fullmatch(provenance["build_lock_sha256"]) is None
    ):
        raise PackageVerificationError("build lock digest is invalid")
    return provenance


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


def _verify_macos_ad_hoc(root: Path, target: dict[str, object]) -> None:
    if target["os"] != "macos" or platform.system() != "Darwin":
        return
    payload = root / str(target["payload"])
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
        if completed.returncode != 0 or "Signature=adhoc" not in details:
            raise PackageVerificationError("macOS payload is not ad-hoc signed as declared")
        if "Authority=" in details or not re.search(
            r"TeamIdentifier=(?:not set|none)", details, re.IGNORECASE
        ):
            raise PackageVerificationError("macOS payload unexpectedly carries a signing identity")


def _verify_macos_plist(root: Path, target: dict[str, object], version: str) -> None:
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
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)(?:\.dev([0-9]+))?", version)
    if match is None:
        raise PackageVerificationError("release version cannot be represented in a macOS bundle")
    build_number = int(match.group(2) or "1")
    if build_number < 1:
        raise PackageVerificationError("macOS bundle build number must be positive")
    expected = {
        "CFBundleIdentifier": "net.lantern.family-beta-development",
        "CFBundleDisplayName": "Start Lantern (Unsigned Dev)",
        "CFBundleShortVersionString": match.group(1),
        "CFBundleVersion": str(build_number),
    }
    for key, value in expected.items():
        if info.get(key) != value:
            raise PackageVerificationError(f"macOS bundle metadata does not match: {key}")


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
            or payload["unsigned_development"] is not True
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
    target = _verify_target(root, manifest["target"])
    contracts = _verify_contracts(manifest["contracts"])
    provenance = _verify_provenance(
        manifest["provenance"], require_clean_source=require_clean_source
    )
    _verify_records(root, manifest["files"], manifest["tree_sha256"])
    _verify_macos_plist(root, target, str(release["version"]))
    _verify_macos_ad_hoc(root, target)
    _run_offline_self_test(root, target, release, contracts)
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
        "trust": "UNSIGNED DEVELOPMENT BUILD",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify one unpacked Lantern unsigned family-beta development artifact."
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
