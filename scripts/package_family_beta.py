"""Build a labeled, one-folder Lantern family-beta development artifact."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

from package_support import (
    PackageVerificationError,
    assert_zip_matches_tree,
    canonical_records_sha256,
    collect_file_records,
    create_reproducible_zip,
    publish_outputs_exclusive,
    sha256_file,
    snapshot_tree_sha256,
    write_manifest,
    write_manifest_checksum,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "lantern-family-beta.spec"
BUILD_LOCK = ROOT / "packaging" / "requirements-build.lock"
MACOS_RUNTIME_LOCK = ROOT / "packaging" / "macos" / "runtime.lock.json"
PYINSTALLER_VERSION = "6.22.1"
SYSTEM_GIT = Path("/usr/bin/git")
BUILD_PACKAGES = {
    "PyInstaller": PYINSTALLER_VERSION,
    "altgraph": "0.17.5",
    "packaging": "26.3",
    "pyinstaller-hooks-contrib": "2026.6",
    "setuptools": "84.0.0",
}
DARWIN_BUILD_PACKAGES = {"macholib": "1.16.4"}
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.(?:dev|post)[0-9]+)?\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MACOS_WHEELS = {
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
}
_MACOS_RUNTIME = {
    "architecture": "arm64",
    "archive": "cpython-3.11.15+20260728-aarch64-apple-darwin-install_only.tar.gz",
    "archive_sha256": "7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802",
    "build_site_packages_sha256": "c6f4d93a0091bc6d86b118dbb05b85af5209b30c5d4b4048fbf17fe052bcb33d",
    "libpython": "python/lib/libpython3.11.dylib",
    "libpython_sha256": "39669f88807bff419376e0ba17ae68d194f065f7959fb61cd4777af65da09e51",
    "minimum_macos": "11.0",
    "provider": "Astral python-build-standalone",
    "python_executable": "python/bin/python3.11",
    "python_executable_sha256": "95c331c5e61804b2dcea00dd105fbf7c9e417aaabff23fa5da6758d84033029d",
    "release": "20260728",
    "runtime_tree_sha256": "89f2b0d5e85dc62c5ec225dc850e097f863c7406d23a2835a4e983f050ee093d",
    "schema": "lantern.macos-runtime.v1",
    "url": (
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260728/"
        "cpython-3.11.15%2B20260728-aarch64-apple-darwin-install_only.tar.gz"
    ),
    "version": "3.11.15",
    "wheels": _MACOS_WHEELS,
}


def _run_git(*arguments: str) -> str:
    if SYSTEM_GIT.is_symlink() or not SYSTEM_GIT.is_file() or not os.access(SYSTEM_GIT, os.X_OK):
        raise PackageVerificationError("reviewed system Git is unavailable at /usr/bin/git")
    completed = subprocess.run(
        [str(SYSTEM_GIT), *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    return completed.stdout.strip()


def _source_identity(*, allow_dirty: bool) -> tuple[str, bool, int]:
    commit = _run_git("rev-parse", "HEAD")
    if _COMMIT.fullmatch(commit) is None:
        raise PackageVerificationError("source commit is unavailable")
    status = _run_git("status", "--porcelain=v1", "--untracked-files=all")
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise PackageVerificationError(
            "source tree is not clean; commit reviewed changes or pass --allow-dirty for a labeled test build"
        )
    source_epoch_text = _run_git("show", "-s", "--format=%ct", commit)
    try:
        source_epoch = int(source_epoch_text)
    except ValueError as exc:
        raise PackageVerificationError("source commit timestamp is invalid") from exc
    if source_epoch <= 0:
        raise PackageVerificationError("source commit timestamp is invalid")
    return commit, dirty, source_epoch


def _assert_source_unchanged(*, commit: str, dirty: bool) -> None:
    """Recheck the source identity after build work, before any publication."""

    if _run_git("rev-parse", "HEAD") != commit:
        raise PackageVerificationError("source commit changed during the package build")
    current_dirty = bool(_run_git("status", "--porcelain=v1", "--untracked-files=all"))
    if current_dirty is not dirty:
        raise PackageVerificationError("source clean state changed during the package build")


def _load_macos_runtime_lock() -> dict[str, object]:
    if (
        MACOS_RUNTIME_LOCK.is_symlink()
        or not MACOS_RUNTIME_LOCK.is_file()
        or MACOS_RUNTIME_LOCK.stat().st_size > 64 * 1024
    ):
        raise PackageVerificationError("reviewed macOS runtime lock is unavailable")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise PackageVerificationError("macOS runtime lock contains duplicate keys")
            value[key] = item
        return value

    try:
        value = json.loads(
            MACOS_RUNTIME_LOCK.read_text(encoding="utf-8"),
            object_pairs_hook=object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PackageVerificationError("reviewed macOS runtime lock is invalid") from exc
    if value != _MACOS_RUNTIME:
        raise PackageVerificationError("macOS runtime lock does not match the reviewed runtime")
    return value


def _validated_builder_runtime(
    *,
    os_name: str,
    architecture: str,
) -> dict[str, object] | None:
    """Bind a macOS artifact to the exact reviewed interpreter and shared library."""

    if os_name != "macos":
        return None
    lock = _load_macos_runtime_lock()
    if (
        architecture != lock["architecture"]
        or platform.system() != "Darwin"
        or platform.machine().lower() != lock["architecture"]
        or platform.python_version() != lock["version"]
        or sys.implementation.name != "cpython"
        or sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET") != lock["minimum_macos"]
    ):
        raise PackageVerificationError("builder Python does not match the reviewed macOS runtime")

    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    environment_prefix = Path(sys.prefix).resolve(strict=True)
    base_executable = Path(sys._base_executable).resolve(strict=True)
    invoked_executable = Path(sys.executable).resolve(strict=True)
    expected_executable = base_prefix / "bin" / "python3.11"
    libpython = base_prefix / "lib" / "libpython3.11.dylib"
    if (
        expected_executable.is_symlink()
        or not expected_executable.is_file()
        or expected_executable.resolve(strict=True) != base_executable
        or invoked_executable != base_executable
        or base_executable.is_symlink()
        or not base_executable.is_file()
        or libpython.is_symlink()
        or not libpython.is_file()
    ):
        raise PackageVerificationError("reviewed macOS runtime files are unavailable")
    if (
        sha256_file(base_executable) != lock["python_executable_sha256"]
        or sha256_file(libpython) != lock["libpython_sha256"]
    ):
        raise PackageVerificationError("builder Python bytes do not match the reviewed runtime")

    site_packages = environment_prefix / "lib" / "python3.11" / "site-packages"
    if (
        environment_prefix == base_prefix
        or site_packages.is_symlink()
        or not site_packages.is_dir()
        or snapshot_tree_sha256(base_prefix) != lock["runtime_tree_sha256"]
        or snapshot_tree_sha256(site_packages) != lock["build_site_packages_sha256"]
    ):
        raise PackageVerificationError("macOS build environment does not match the reviewed lock")

    return {
        "schema": "lantern.macos-builder-runtime.v1",
        "provider": lock["provider"],
        "version": lock["version"],
        "architecture": lock["architecture"],
        "minimum_macos": lock["minimum_macos"],
        "runtime_lock_sha256": sha256_file(MACOS_RUNTIME_LOCK),
        "runtime_archive_sha256": lock["archive_sha256"],
        "runtime_tree_sha256": lock["runtime_tree_sha256"],
        "build_site_packages_sha256": lock["build_site_packages_sha256"],
        "python_executable_sha256": lock["python_executable_sha256"],
        "libpython_sha256": lock["libpython_sha256"],
    }


def _validate_build_environment() -> None:
    for distribution, expected in BUILD_PACKAGES.items():
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise PackageVerificationError(
                "locked packaging tools are not installed; follow docs/PACKAGING.md"
            ) from exc
        if actual != expected:
            raise PackageVerificationError(
                f"{distribution} must be exactly {expected}; found {actual}"
            )
    if platform.system() == "Darwin":
        for distribution, expected in DARWIN_BUILD_PACKAGES.items():
            try:
                actual = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError as exc:
                raise PackageVerificationError(
                    "the locked macOS packaging tools are incomplete"
                ) from exc
            if actual != expected:
                raise PackageVerificationError(
                    f"{distribution} must be exactly {expected}; found {actual}"
                )


def _target_identity() -> tuple[str, str]:
    system = platform.system()
    machine = platform.machine().lower()
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64"}.get(machine)
    if system == "Darwin" and architecture == "arm64":
        return "macos", "arm64"
    if system == "Linux" and architecture in {"arm64", "x86_64"}:
        return "linux", architecture
    if architecture is None:
        raise PackageVerificationError(
            "family-beta packaging does not support this processor architecture"
        )
    raise PackageVerificationError(
        "family-beta packaging currently supports macOS arm64 and glibc Linux arm64/x86_64"
    )


def _project_contracts() -> tuple[str, dict[str, object]]:
    sys.path.insert(0, str(ROOT))
    try:
        from importlib.resources import files

        from netdiag import __version__
        from netdiag.presentation import SCHEMA_VERSION
        from netdiag.ui.assets import verify_asset_manifest
        from netdiag.ui.viewmodel import UI_SCHEMA
    finally:
        try:
            sys.path.remove(str(ROOT))
        except ValueError:
            pass

    if _VERSION.fullmatch(__version__) is None:
        raise PackageVerificationError("project version is invalid")
    declared = re.search(
        r"(?m)^version\s*=\s*\"([^\"]+)\"\s*$",
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    )
    if declared is None or declared.group(1) != __version__:
        raise PackageVerificationError("pyproject and runtime versions do not match")

    schema_bytes = files("netdiag.schemas").joinpath("report-1.1.schema.json").read_bytes()
    schema_payload = json.loads(schema_bytes)
    if (
        schema_payload.get("properties", {}).get("schema_version", {}).get("const")
        != SCHEMA_VERSION
    ):
        raise PackageVerificationError("report schema file and runtime contract do not match")
    assets = verify_asset_manifest()
    contracts: dict[str, object] = {
        "report_schema": SCHEMA_VERSION,
        "report_schema_sha256": __import__("hashlib").sha256(schema_bytes).hexdigest(),
        "ui_schema": UI_SCHEMA,
        "ui_assets": [
            {
                "filename": asset.spec.filename,
                "size": len(asset.body),
                "sha256": __import__("hashlib").sha256(asset.body).hexdigest(),
            }
            for asset in assets
        ],
    }
    return __version__, contracts


def _bundle_versions(version: str) -> tuple[str, str]:
    """Map the PEP 440 development version into valid macOS bundle versions."""

    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)(?:\.dev([0-9]+))?", version)
    if match is None:
        raise PackageVerificationError("project version cannot be represented in a macOS bundle")
    build_number = int(match.group(2) or "1")
    if build_number < 1:
        raise PackageVerificationError("macOS bundle build number must be positive")
    return match.group(1), str(build_number)


def _notices(*, version: str, commit: str, dirty: bool) -> tuple[str, str]:
    state = "DIRTY TEST BUILD (contains uncommitted source changes)" if dirty else "clean commit"
    start_here = f"""START HERE — LANTERN LOCAL FAMILY BETA DEVELOPMENT BUILD

This is Lantern {version}, an unsigned local developer artifact built from {commit} ({state}).

macOS: open “Start Lantern (Unsigned Dev).app”. If macOS blocks it, use Control-click →
Open only when you received this exact artifact directly from someone you trust. Do not
disable Gatekeeper. Linux: open the executable inside the “Start Lantern (Unsigned Dev)”
folder. The package never asks for an administrator password.

Opening Lantern starts only a short-lived interface on this computer. A diagnostic does
not start until the person at the computer chooses a goal, reviews the stated scope, and
presses Start check. Packaging adds no automatic software download/update mechanism,
installer, persistence, elevation, autorun, USB behavior, telemetry, or remote service.
Lantern can still download a redacted JSON report when the person explicitly requests it.

Before sharing any exported report, review it. Lantern's share export is redacted by
design, but this remains a development build and is not a security audit or certification.

For integrity verification, use package-manifest.json and SHA256SUMS.txt from a separately
trusted copy of the expected hash. Checksums detect changed bytes; they do not establish
who created the software.
"""
    warning = f"""UNSIGNED DEVELOPMENT BUILD — NOT FOR PRODUCTION

Lantern {version} has not been Developer ID signed, notarized, or independently audited.
On Apple Silicon, macOS may apply an ad-hoc signature required for executable integrity;
that is not a publisher identity and does not create trust.

This artifact is intended only for a small, supervised family beta. It is not an
installer, managed endpoint agent, enterprise scanner, compliance tool, or rescue disk.
It adds no automatic software download/update mechanism, persistence, elevation, autorun,
USB behavior, telemetry, or remotely reachable service. Lantern's explicit redacted JSON
report download remains available for the person at the computer.

The included hashes provide transfer-integrity evidence only. An attacker who can replace
the artifact can also replace its hashes. Compare the ZIP hash over a separate trusted
channel and do not open the application if its origin is uncertain.
"""
    return start_here, warning


def _write_exclusive(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def _pyinstaller_payload(dist: Path, *, os_name: str) -> Path:
    name = (
        "Start Lantern (Unsigned Dev).app" if os_name == "macos" else "Start Lantern (Unsigned Dev)"
    )
    payload = dist / name
    if payload.is_symlink() or not payload.is_dir():
        raise PackageVerificationError(
            "PyInstaller did not produce the expected one-folder payload"
        )
    return payload


def _build_manifest(
    artifact: Path,
    *,
    version: str,
    contracts: dict[str, object],
    os_name: str,
    architecture: str,
    commit: str,
    dirty: bool,
    source_epoch: int,
    builder_runtime: dict[str, object] | None,
) -> dict[str, object]:
    payload = (
        "Start Lantern (Unsigned Dev).app" if os_name == "macos" else "Start Lantern (Unsigned Dev)"
    )
    executable_root = f"{payload}/Contents/MacOS" if os_name == "macos" else payload
    records = collect_file_records(artifact)
    return {
        "schema": "lantern.package.v1",
        "product": "Lantern",
        "release": {
            "version": version,
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
        },
        "target": {
            "os": os_name,
            "architecture": architecture,
            "payload": payload,
            "launcher": f"{executable_root}/Start Lantern (Unsigned Dev)",
            "self_test": f"{executable_root}/verify-lantern-package",
            "macos_signature": "ad-hoc-only" if os_name == "macos" else "not-applicable",
        },
        "contracts": contracts,
        "provenance": {
            "source_commit": commit,
            "source_dirty": dirty,
            "source_epoch": source_epoch,
            "builder_python": platform.python_version(),
            "pyinstaller": PYINSTALLER_VERSION,
            "build_inputs": "locked-python-wheels-and-reviewed-spec",
            "build_lock_sha256": sha256_file(BUILD_LOCK),
            "builder_runtime": builder_runtime,
        },
        "files": records,
        "tree_sha256": canonical_records_sha256(records),
    }


def _run_pyinstaller(
    staging: Path,
    *,
    version: str,
    source_epoch: int,
    os_name: str,
    architecture: str,
    builder_runtime: dict[str, object] | None,
) -> Path:
    dist = staging / "pyinstaller-dist"
    work = staging / "pyinstaller-work"
    bundle_short_version, bundle_build_version = _bundle_versions(version)
    build_home = staging / "build-home"
    pyinstaller_config = staging / "pyinstaller-config"
    build_tmp = staging / "build-tmp"
    build_home.mkdir(mode=0o700)
    pyinstaller_config.mkdir(mode=0o700)
    build_tmp.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(build_home),
        "TMPDIR": str(build_tmp),
        "TMP": str(build_tmp),
        "TEMP": str(build_tmp),
        "PYINSTALLER_CONFIG_DIR": str(pyinstaller_config),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": str(source_epoch),
        "LANG": "C",
        "LC_ALL": "C",
        "LANTERN_BUILD_VERSION": version,
        "LANTERN_BUNDLE_SHORT_VERSION": bundle_short_version,
        "LANTERN_BUNDLE_BUILD_VERSION": bundle_build_version,
    }
    python_executable = Path(sys.executable).resolve(strict=True)
    if os_name == "macos":
        if (
            _validated_builder_runtime(os_name=os_name, architecture=architecture)
            != builder_runtime
        ):
            raise PackageVerificationError("macOS build environment changed before PyInstaller")
        target_arch = platform.machine()
        if target_arch != "arm64":
            raise PackageVerificationError("unsupported macOS build architecture")
        environment.update(
            {
                "LANTERN_TARGET_ARCH": target_arch,
                "MACOSX_DEPLOYMENT_TARGET": "11.0",
                "PYTHON_JIT": "0",
            }
        )
    subprocess.run(
        [
            str(python_executable),
            "-I",
            "-B",
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--distpath",
            str(dist),
            "--workpath",
            str(work),
            str(SPEC),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        timeout=10 * 60,
    )
    return dist


def _publish_outputs(
    artifact: Path,
    archive: Path,
    archive_checksum: Path,
    artifact_destination: Path,
    archive_destination: Path,
    archive_checksum_destination: Path,
) -> None:
    """Publish through the shared no-replace, fail-safe retention boundary."""

    publish_outputs_exclusive(
        (
            (artifact, artifact_destination),
            (archive, archive_destination),
            (archive_checksum, archive_checksum_destination),
        )
    )


def _verify_published_outputs(
    artifact_destination: Path,
    archive_destination: Path,
    *,
    dirty: bool,
) -> None:
    published_verify_command = [
        sys.executable,
        str(ROOT / "scripts" / "verify_family_beta.py"),
        str(artifact_destination),
    ]
    if not dirty:
        published_verify_command.append("--require-clean-source")
    subprocess.run(
        published_verify_command,
        cwd=ROOT,
        check=True,
        timeout=2 * 60,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
    )
    assert_zip_matches_tree(artifact_destination, archive_destination)


def _publish_verified_outputs(
    artifact: Path,
    archive: Path,
    archive_checksum: Path,
    artifact_destination: Path,
    archive_destination: Path,
    archive_checksum_destination: Path,
    *,
    dirty: bool,
) -> None:
    """Publish and reverify, retaining any failed paths for manual review."""

    def verify() -> None:
        _verify_published_outputs(
            artifact_destination,
            archive_destination,
            dirty=dirty,
        )

    publish_outputs_exclusive(
        (
            (artifact, artifact_destination),
            (archive, archive_destination),
            (archive_checksum, archive_checksum_destination),
        ),
        verify=verify,
    )


def build_family_beta(output_base: Path, *, allow_dirty: bool = False) -> dict[str, object]:
    """Build, self-test, verify, archive, and publish a new local artifact."""

    _validate_build_environment()
    os_name, architecture = _target_identity()
    builder_runtime = _validated_builder_runtime(os_name=os_name, architecture=architecture)
    commit, dirty, source_epoch = _source_identity(allow_dirty=allow_dirty)
    version, contracts = _project_contracts()

    if output_base.exists() and output_base.is_symlink():
        raise PackageVerificationError("output directory must not be a symbolic link")
    output_base.mkdir(parents=True, exist_ok=True)
    output_base = output_base.resolve(strict=True)
    if output_base == Path("/") or output_base == Path.home().resolve():
        raise PackageVerificationError("output directory is too broad")

    artifact_name = f"lantern-family-beta-{version}-{os_name}-{architecture}-UNSIGNED-DEV"
    artifact_destination = output_base / artifact_name
    archive_destination = output_base / f"{artifact_name}.zip"
    archive_checksum_destination = output_base / f"{artifact_name}.zip.sha256"
    for destination in (
        artifact_destination,
        archive_destination,
        archive_checksum_destination,
    ):
        if destination.exists() or destination.is_symlink():
            raise PackageVerificationError(
                f"refusing to replace existing output: {destination.name}"
            )

    with tempfile.TemporaryDirectory(prefix=".lantern-family-build-", dir=output_base) as temporary:
        staging = Path(temporary)
        dist = _run_pyinstaller(
            staging,
            version=version,
            source_epoch=source_epoch,
            os_name=os_name,
            architecture=architecture,
            builder_runtime=builder_runtime,
        )
        if (
            _validated_builder_runtime(os_name=os_name, architecture=architecture)
            != builder_runtime
        ):
            raise PackageVerificationError("build environment changed during PyInstaller")
        _assert_source_unchanged(commit=commit, dirty=dirty)
        pyinstaller_payload = _pyinstaller_payload(dist, os_name=os_name)
        artifact = staging / artifact_name
        artifact.mkdir(mode=0o755)
        payload = artifact / pyinstaller_payload.name
        os.replace(pyinstaller_payload, payload)

        start_here, warning = _notices(
            version=version,
            commit=commit,
            dirty=dirty,
        )
        _write_exclusive(artifact / "START-HERE.txt", start_here)
        _write_exclusive(artifact / "UNSIGNED-DEVELOPMENT-BUILD.txt", warning)
        manifest = _build_manifest(
            artifact,
            version=version,
            contracts=contracts,
            os_name=os_name,
            architecture=architecture,
            commit=commit,
            dirty=dirty,
            source_epoch=source_epoch,
            builder_runtime=builder_runtime,
        )
        write_manifest(artifact, manifest)
        write_manifest_checksum(artifact)

        verifier = ROOT / "scripts" / "verify_family_beta.py"
        verify_command = [sys.executable, str(verifier), str(artifact)]
        if not dirty:
            verify_command.append("--require-clean-source")
        subprocess.run(
            verify_command,
            cwd=ROOT,
            check=True,
            timeout=2 * 60,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        )

        archive = staging / archive_destination.name
        create_reproducible_zip(artifact, archive, source_epoch=source_epoch)
        assert_zip_matches_tree(artifact, archive)
        archive_checksum = staging / archive_checksum_destination.name
        _write_exclusive(archive_checksum, f"{sha256_file(archive)}  {archive.name}\n")

        _assert_source_unchanged(commit=commit, dirty=dirty)

        _publish_verified_outputs(
            artifact,
            archive,
            archive_checksum,
            artifact_destination,
            archive_destination,
            archive_checksum_destination,
            dirty=dirty,
        )

    return {
        "schema": "lantern.package-build.v1",
        "artifact": str(artifact_destination),
        "archive": str(archive_destination),
        "archive_sha256": sha256_file(archive_destination),
        "manifest_sha256": sha256_file(artifact_destination / "package-manifest.json"),
        "artifact_snapshot_sha256": snapshot_tree_sha256(artifact_destination),
        "tree_sha256": manifest["tree_sha256"],
        "build_lock_sha256": sha256_file(BUILD_LOCK),
        "builder_runtime": builder_runtime,
        "version": version,
        "target": {"os": os_name, "architecture": architecture},
        "source_commit": commit,
        "source_dirty": dirty,
        "trust": "UNSIGNED DEVELOPMENT BUILD",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build Lantern's unsigned, one-folder family-beta development artifact."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "dist" / "family-beta",
        help="new artifacts are created here without replacing existing files",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a test-only build and record source_dirty=true in its manifest",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = build_family_beta(args.output_dir, allow_dirty=args.allow_dirty)
    except (OSError, subprocess.SubprocessError, PackageVerificationError) as exc:
        print(f"Lantern family-beta build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
