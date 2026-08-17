"""Build a labeled, one-folder Lantern family-beta development artifact."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from package_support import (
    PackageVerificationError,
    assert_zip_matches_tree,
    canonical_records_sha256,
    collect_file_records,
    create_reproducible_zip,
    sha256_file,
    write_manifest,
    write_manifest_checksum,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "lantern-family-beta.spec"
BUILD_LOCK = ROOT / "packaging" / "requirements-build.lock"
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
    os_name = {"Darwin": "macos", "Linux": "linux"}.get(system)
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64"}.get(machine)
    if os_name is None or architecture is None:
        raise PackageVerificationError(
            "family-beta packaging currently supports macOS/Linux on arm64 or x86_64"
        )
    return os_name, architecture


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
        },
        "files": records,
        "tree_sha256": canonical_records_sha256(records),
    }


def _run_pyinstaller(
    staging: Path,
    *,
    version: str,
    source_epoch: int,
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
        "SOURCE_DATE_EPOCH": str(source_epoch),
        "LANG": "C",
        "LC_ALL": "C",
        "LANTERN_BUILD_VERSION": version,
        "LANTERN_BUNDLE_SHORT_VERSION": bundle_short_version,
        "LANTERN_BUNDLE_BUILD_VERSION": bundle_build_version,
    }
    subprocess.run(
        [
            sys.executable,
            "-I",
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


def _copy_file_exclusive(source: Path, destination: Path) -> None:
    """Copy one file through an exclusive destination create; never replace."""

    created = False
    try:
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            created = True
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
        shutil.copymode(source, destination, follow_symlinks=False)
    except Exception:
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise


def _copy_entry_exclusive(source: Path, destination: Path) -> None:
    """Copy one tree entry using only no-replace destination operations."""

    if source.is_symlink():
        os.symlink(os.readlink(source), destination)
        try:
            shutil.copystat(source, destination, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        return
    if source.is_dir():
        destination.mkdir(mode=source.stat().st_mode & 0o777)
        try:
            for child in sorted(source.iterdir(), key=lambda item: item.name):
                _copy_entry_exclusive(child, destination / child.name)
            shutil.copystat(source, destination, follow_symlinks=False)
        except Exception:
            shutil.rmtree(destination)
            raise
        return
    if source.is_file():
        _copy_file_exclusive(source, destination)
        shutil.copystat(source, destination, follow_symlinks=False)
        return
    raise PackageVerificationError("staged artifact contains an unsupported entry")


def _publish_outputs(
    artifact: Path,
    archive: Path,
    archive_checksum: Path,
    artifact_destination: Path,
    archive_destination: Path,
    archive_checksum_destination: Path,
) -> None:
    """Publish through exclusive creates and remove only outputs created by this call."""

    created: list[Path] = []
    try:
        artifact_destination.mkdir(mode=artifact.stat().st_mode & 0o777)
        created.append(artifact_destination)
        for child in sorted(artifact.iterdir(), key=lambda item: item.name):
            _copy_entry_exclusive(child, artifact_destination / child.name)
        shutil.copystat(artifact, artifact_destination, follow_symlinks=False)
        _copy_file_exclusive(archive, archive_destination)
        created.append(archive_destination)
        _copy_file_exclusive(archive_checksum, archive_checksum_destination)
        created.append(archive_checksum_destination)
    except Exception as publish_error:
        try:
            _remove_reserved_outputs(tuple(created))
        except PackageVerificationError as cleanup_error:
            raise cleanup_error from publish_error
        raise


def _remove_reserved_outputs(paths: tuple[Path, ...]) -> None:
    """Remove only outputs exclusively created by the current publication attempt."""

    failures: list[str] = []
    for path in reversed(paths):
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        except OSError:
            failures.append(path.name)
    if failures:
        raise PackageVerificationError(
            "failed publication could not be fully removed: " + ", ".join(sorted(failures))
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
    """Publish, reverify the copied bytes, and remove the reserved set on failure."""

    destinations = (
        artifact_destination,
        archive_destination,
        archive_checksum_destination,
    )
    _publish_outputs(
        artifact,
        archive,
        archive_checksum,
        *destinations,
    )
    try:
        _verify_published_outputs(
            artifact_destination,
            archive_destination,
            dirty=dirty,
        )
    except Exception:
        _remove_reserved_outputs(destinations)
        raise


def build_family_beta(output_base: Path, *, allow_dirty: bool = False) -> dict[str, object]:
    """Build, self-test, verify, archive, and publish a new local artifact."""

    _validate_build_environment()
    os_name, architecture = _target_identity()
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
        dist = _run_pyinstaller(staging, version=version, source_epoch=source_epoch)
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
