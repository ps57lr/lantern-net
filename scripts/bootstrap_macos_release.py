"""Trusted-system-Python bootstrap for Lantern's sealed macOS release build."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import posixpath
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_LOCK = ROOT / "packaging" / "macos" / "runtime.lock.json"
BUILD_LOCK = ROOT / "packaging" / "requirements-build.lock"
RELEASE_SCRIPT = ROOT / "scripts" / "release_family_beta_macos.py"
RELEASE_LOADER = (
    "import runpy,sys;"
    "from pathlib import Path;"
    "root=Path(sys.argv[1]).resolve(strict=True);"
    "script=(root/'scripts'/'release_family_beta_macos.py').resolve(strict=True);"
    "sys.path.insert(0,str(script.parent));"
    "sys.argv=[str(script),*sys.argv[2:]];"
    "runpy.run_path(str(script),run_name='__main__')"
)
SYSTEM_GIT = Path("/usr/bin/git")
SYSTEM_PYTHON = Path("/usr/bin/python3")
SYSTEM_PYTHON_RUNTIME = Path(
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
    "Python3.framework/Versions/3.9/bin/python3.9"
)
SYSTEM_PYTHON_RUNTIME_SHA256 = "271143990bc83af0fb2404a255038f5faafb96df1584ed7f085e5018c0f33ffb"
RUNTIME_LOCK_SHA256 = "523fde449f9e3587b2e662ad053b8bb5c99cb26139591fa1fd8113a22aa1e2b9"
BUILD_LOCK_SHA256 = "9ef83fb5980dc61a78b75d116955d5cc485f020d556f596e9b6213068073a23e"
RUNTIME_ARCHIVE_SHA256 = "7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802"
RUNTIME_TREE_SHA256 = "89f2b0d5e85dc62c5ec225dc850e097f863c7406d23a2835a4e983f050ee093d"
BUILD_SITE_PACKAGES_SHA256 = "c6f4d93a0091bc6d86b118dbb05b85af5209b30c5d4b4048fbf17fe052bcb33d"
PYTHON_EXECUTABLE_SHA256 = "95c331c5e61804b2dcea00dd105fbf7c9e417aaabff23fa5da6758d84033029d"
LIBPYTHON_SHA256 = "39669f88807bff419376e0ba17ae68d194f065f7959fb61cd4777af65da09e51"
WHEELS = {
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
MAX_MEMBERS = 20_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_PYVENV_BYTES = 4096
_RETAINED_BUILD_BIN = frozenset({"python", "python3", "python3.11"})


class BootstrapError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise BootstrapError("expected a regular release input file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        [str(SYSTEM_GIT), *arguments],
        cwd=str(ROOT),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
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
    if completed.returncode != 0:
        raise BootstrapError("clean source provenance is unavailable")
    return completed.stdout.strip()


def require_clean_source() -> str:
    if SYSTEM_GIT.is_symlink() or not SYSTEM_GIT.is_file():
        raise BootstrapError("reviewed system Git is unavailable")
    commit = _git("rev-parse", "HEAD")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise BootstrapError("source commit is invalid")
    if _git("status", "--porcelain=v1", "--untracked-files=all"):
        raise BootstrapError("release source must be a clean committed tree")
    return commit


def _canonical_tree_sha256(root: Path) -> str:
    records = []
    total = 0
    for current, directories, filenames in os.walk(str(root), topdown=True, followlinks=False):
        current_path = Path(current)
        retained = []
        for name in sorted(directories):
            candidate = current_path / name
            if candidate.is_symlink():
                filenames.append(name)
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(filenames):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            mode = stat.S_IMODE(candidate.lstat().st_mode)
            if candidate.is_symlink():
                target = os.readlink(str(candidate))
                resolved = candidate.resolve(strict=True)
                try:
                    resolved.relative_to(root.resolve(strict=True))
                except ValueError as exc:
                    raise BootstrapError("runtime symbolic link escapes its root") from exc
                records.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": f"{mode:04o}",
                        "target": target,
                        "sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
                    }
                )
                continue
            if not candidate.is_file():
                raise BootstrapError("runtime tree contains an unsupported entry")
            size = candidate.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise BootstrapError("runtime tree exceeds its resource bound")
            records.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": f"{mode:04o}",
                    "size": size,
                    "sha256": sha256_file(candidate),
                }
            )
            if len(records) > MAX_MEMBERS:
                raise BootstrapError("runtime tree contains too many entries")
    records.sort(key=lambda record: str(record["path"]))
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise BootstrapError("runtime archive contains an unsafe path")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or not path.parts or path.parts[0] != "python":
        raise BootstrapError("runtime archive root is invalid")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise BootstrapError("runtime archive contains an unsafe path")
    return path


def extract_runtime(archive: Path, destination: Path) -> Path:
    if sha256_file(archive) != RUNTIME_ARCHIVE_SHA256:
        raise BootstrapError("runtime archive digest does not match the release pin")
    try:
        with tarfile.open(str(archive), mode="r:gz") as stream:
            members = stream.getmembers()
            if not members or len(members) > MAX_MEMBERS:
                raise BootstrapError("runtime archive member count is invalid")
            names = [_safe_member_name(member.name).as_posix() for member in members]
            if len(names) != len(set(names)):
                raise BootstrapError("runtime archive contains duplicate paths")
            symlink_names = {
                _safe_member_name(member.name).as_posix() for member in members if member.issym()
            }
            total = 0
            for member, name in zip(members, names):
                parts = PurePosixPath(name).parts
                if any("/".join(parts[:index]) in symlink_names for index in range(1, len(parts))):
                    raise BootstrapError("runtime archive traverses a symbolic link")
                if not (member.isdir() or member.isreg() or member.issym()):
                    raise BootstrapError("runtime archive contains an unsupported entry")
                if member.size > MAX_FILE_BYTES:
                    raise BootstrapError("runtime archive member is oversized")
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise BootstrapError("runtime archive is oversized")

            for member, name in zip(members, names):
                target = destination / Path(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    raise BootstrapError("runtime extraction destination collision")
                if member.isdir():
                    target.mkdir(mode=stat.S_IMODE(member.mode) or 0o755)
                elif member.isreg():
                    source = stream.extractfile(member)
                    if source is None:
                        raise BootstrapError("runtime archive member cannot be read")
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    target.chmod(stat.S_IMODE(member.mode) & 0o755)
                else:
                    if PurePosixPath(member.linkname).is_absolute():
                        raise BootstrapError("runtime symbolic link is absolute")
                    resolved_name = posixpath.normpath(
                        posixpath.join(posixpath.dirname(name), member.linkname)
                    )
                    if not (resolved_name == "python" or resolved_name.startswith("python/")):
                        raise BootstrapError("runtime symbolic link escapes its root")
                    os.symlink(member.linkname, str(target))
    except (OSError, tarfile.TarError) as exc:
        raise BootstrapError("runtime archive could not be safely extracted") from exc
    return destination / "python"


def remove_bytecode(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_file() and path.suffix in {".pyc", ".pyo"}:
            path.unlink()
        elif path.is_dir() and path.name == "__pycache__":
            shutil.rmtree(path)


def _replace_record(record: Path, rows: list[list[str]]) -> None:
    """Atomically replace one validated RECORD through its real parent directory."""

    buffer = io.StringIO(newline="")
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    encoded = buffer.getvalue().encode("utf-8")
    if len(encoded) > MAX_RECORD_BYTES:
        raise BootstrapError("normalized installed-package record is too large")

    original = record.lstat()
    original_parent = record.parent.lstat()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    temporary_name = ".RECORD.lantern-normalized"
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(str(record.parent), directory_flags)
        try:
            opened_parent = os.fstat(directory_descriptor)
            if (opened_parent.st_dev, opened_parent.st_ino, opened_parent.st_mode) != (
                original_parent.st_dev,
                original_parent.st_ino,
                original_parent.st_mode,
            ):
                raise BootstrapError("installed-package metadata changed before normalization")
            current = os.stat(record.name, dir_fd=directory_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_mode) != (
                original.st_dev,
                original.st_ino,
                original.st_mode,
            ):
                raise BootstrapError("installed-package record changed before normalization")
            descriptor = os.open(
                temporary_name,
                file_flags,
                stat.S_IMODE(original.st_mode),
                dir_fd=directory_descriptor,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode))
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                descriptor = -1
                raise
            os.replace(
                temporary_name,
                record.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BootstrapError:
        raise
    except OSError as exc:
        raise BootstrapError("installed-package record could not be normalized") from exc


def canonicalize_build_environment(build_environment: Path, *, runtime: Path) -> Path:
    """Validate the venv binding and remove unused path-bound launchers."""

    binary_directory = build_environment / "bin"
    library_directory = build_environment / "lib"
    version_directory = library_directory / "python3.11"
    site_packages = build_environment / "lib" / "python3.11" / "site-packages"
    configuration = build_environment / "pyvenv.cfg"
    if (
        build_environment.is_symlink()
        or not build_environment.is_dir()
        or binary_directory.is_symlink()
        or not binary_directory.is_dir()
        or library_directory.is_symlink()
        or not library_directory.is_dir()
        or version_directory.is_symlink()
        or not version_directory.is_dir()
        or site_packages.is_symlink()
        or not site_packages.is_dir()
        or configuration.is_symlink()
        or not configuration.is_file()
        or configuration.stat().st_size > MAX_PYVENV_BYTES
    ):
        raise BootstrapError("sealed build environment has an invalid layout")
    resolved_environment = build_environment.resolve(strict=True)
    for directory in (binary_directory, library_directory, version_directory, site_packages):
        try:
            directory.resolve(strict=True).relative_to(resolved_environment)
        except ValueError as exc:
            raise BootstrapError("sealed build environment escapes its root") from exc

    expected_executable = (runtime / "bin" / "python3.11").resolve(strict=True)
    if expected_executable.is_symlink() or not expected_executable.is_file():
        raise BootstrapError("sealed runtime executable is invalid")

    expected_links = {
        "python": "python3.11",
        "python3": "python3.11",
    }
    for name, target in expected_links.items():
        launcher = binary_directory / name
        if not launcher.is_symlink() or os.readlink(str(launcher)) != target:
            raise BootstrapError("sealed Python launcher is invalid")
    versioned_launcher = binary_directory / "python3.11"
    if (
        not versioned_launcher.is_symlink()
        or versioned_launcher.resolve(strict=True) != expected_executable
    ):
        raise BootstrapError("sealed Python launcher is invalid")

    try:
        configuration_lines = configuration.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise BootstrapError("sealed Python configuration could not be read") from exc
    configuration_values: dict[str, str] = {}
    for line in configuration_lines:
        key, separator, value = line.partition(" = ")
        if not separator or not key or key in configuration_values or not value:
            raise BootstrapError("sealed Python configuration is invalid")
        configuration_values[key] = value
    if set(configuration_values) != {
        "home",
        "include-system-site-packages",
        "version",
        "executable",
        "command",
    }:
        raise BootstrapError("sealed Python configuration is invalid")
    try:
        command = shlex.split(configuration_values["command"], posix=True)
        home = Path(configuration_values["home"]).resolve(strict=True)
        configured_executable = Path(configuration_values["executable"]).resolve(strict=True)
        command_executable = Path(command[0]).resolve(strict=True)
        command_environment = Path(command[3]).resolve(strict=True)
    except (IndexError, OSError, ValueError) as exc:
        raise BootstrapError("sealed Python configuration is invalid") from exc
    if (
        configuration_values["include-system-site-packages"] != "false"
        or configuration_values["version"] != "3.11.15"
        or home != expected_executable.parent
        or configured_executable != expected_executable
        or len(command) != 4
        or command[1:3] != ["-m", "venv"]
        or command_executable != expected_executable
        or command_environment != build_environment.resolve(strict=True)
    ):
        raise BootstrapError("sealed Python configuration is invalid")

    removed_entries: set[str] = set()
    for entry in sorted(binary_directory.iterdir(), key=lambda item: item.name):
        if entry.name in _RETAINED_BUILD_BIN:
            continue
        if entry.is_symlink() or entry.is_file():
            removed_entries.add(entry.name)
            continue
        raise BootstrapError("sealed build environment contains an unexpected executable entry")

    dist_info_directories = sorted(site_packages.glob("*.dist-info"))
    if not dist_info_directories:
        raise BootstrapError("sealed build environment has no installed-package records")
    records: list[Path] = []
    resolved_site_packages = site_packages.resolve(strict=True)
    for dist_info in dist_info_directories:
        if dist_info.is_symlink() or not dist_info.is_dir():
            raise BootstrapError("installed-package metadata directory is invalid")
        try:
            if dist_info.resolve(strict=True).parent != resolved_site_packages:
                raise BootstrapError("installed-package metadata directory is invalid")
        except OSError as exc:
            raise BootstrapError("installed-package metadata directory is invalid") from exc
        records.append(dist_info / "RECORD")

    normalized_records: list[tuple[Path, list[list[str]]]] = []
    for record in records:
        if record.is_symlink() or not record.is_file() or record.stat().st_size > MAX_RECORD_BYTES:
            raise BootstrapError("installed-package record is invalid")
        try:
            with record.open("r", encoding="utf-8", newline="") as stream:
                rows = list(csv.reader(stream))
        except (OSError, UnicodeError, csv.Error) as exc:
            raise BootstrapError("installed-package record could not be read") from exc
        retained: list[list[str]] = []
        for row in rows:
            if len(row) != 3 or not row[0] or "\\" in row[0] or "\x00" in row[0]:
                raise BootstrapError("installed-package record row is invalid")
            if row[1]:
                encoded_digest = row[1].removeprefix("sha256=")
                if (
                    not row[1].startswith("sha256=")
                    or len(encoded_digest) != 43
                    or any(
                        character
                        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                        for character in encoded_digest
                    )
                ):
                    raise BootstrapError("installed-package record digest is invalid")
            if row[2] and not row[2].isdigit():
                raise BootstrapError("installed-package record size is invalid")
            if row[0].startswith("../../../bin/"):
                launcher_name = row[0].removeprefix("../../../bin/")
                if (
                    not launcher_name
                    or "/" in launcher_name
                    or launcher_name in _RETAINED_BUILD_BIN
                    or launcher_name not in removed_entries
                ):
                    raise BootstrapError("installed-package record launcher path is invalid")
                continue
            record_path = PurePosixPath(row[0])
            if record_path.is_absolute() or ".." in record_path.parts:
                raise BootstrapError("installed-package record path is invalid")
            retained.append(row)
        if not retained:
            raise BootstrapError("installed-package record became empty")
        normalized_records.append((record, retained))

    for entry in sorted(binary_directory.iterdir(), key=lambda item: item.name):
        if entry.name in removed_entries:
            entry.unlink()
    for record, retained in normalized_records:
        _replace_record(record, retained)
    return site_packages


def verify_wheelhouse(wheelhouse: Path) -> None:
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise BootstrapError("locked wheelhouse is unavailable")
    entries = list(wheelhouse.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise BootstrapError("wheelhouse does not contain the exact reviewed wheel set")
    files = {path.name: path for path in entries}
    if set(files) != set(WHEELS):
        raise BootstrapError("wheelhouse does not contain the exact reviewed wheel set")
    for name, expected in WHEELS.items():
        if files[name].is_symlink() or sha256_file(files[name]) != expected:
            raise BootstrapError(f"wheelhouse digest does not match: {name}")


def _copy_verified_file(source: Path, destination: Path, *, expected_sha256: str) -> None:
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    if sha256_file(destination) != expected_sha256:
        destination.unlink()
        raise BootstrapError("release input changed while it was sealed")


def _run(command: list[str], *, timeout: int, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        check=False,
        timeout=timeout,
        env=environment,
    )
    if completed.returncode != 0:
        raise BootstrapError("sealed release subprocess failed")


def _release_command(
    builder: Path,
    output_dir: Path,
    *,
    notarize: bool,
    resume_notarization: Optional[Path] = None,  # noqa: UP045 - bootstrap runs on Python 3.9
) -> list[str]:
    if notarize and resume_notarization is not None:
        raise BootstrapError("notarization resume cannot create another submission")
    command = [
        str(builder),
        "-I",
        "-B",
        "-c",
        RELEASE_LOADER,
        str(ROOT),
        "--output-dir",
        str(output_dir.resolve()),
    ]
    if notarize:
        command.append("--notarize")
    if resume_notarization is not None:
        command.extend(["--resume-notarization", str(resume_notarization.resolve(strict=True))])
    return command


def run_release(
    runtime_archive: Path,
    wheelhouse: Path,
    output_dir: Path,
    *,
    notarize: bool,
    resume_notarization: Optional[Path] = None,  # noqa: UP045 - bootstrap runs on Python 3.9
) -> None:
    if (
        Path(sys.executable).resolve(strict=True) != SYSTEM_PYTHON_RUNTIME
        or sha256_file(SYSTEM_PYTHON_RUNTIME) != SYSTEM_PYTHON_RUNTIME_SHA256
    ):
        raise BootstrapError("bootstrap must run with /usr/bin/python3")
    require_clean_source()
    if sha256_file(RUNTIME_LOCK) != RUNTIME_LOCK_SHA256:
        raise BootstrapError("runtime lock does not match this reviewed bootstrap")
    if sha256_file(BUILD_LOCK) != BUILD_LOCK_SHA256:
        raise BootstrapError("build lock does not match this reviewed bootstrap")
    verify_wheelhouse(wheelhouse)
    with tempfile.TemporaryDirectory(prefix="lantern-sealed-release-") as temporary:
        staging = Path(temporary)
        sealed_archive = staging / "runtime.tar.gz"
        _copy_verified_file(
            runtime_archive,
            sealed_archive,
            expected_sha256=RUNTIME_ARCHIVE_SHA256,
        )
        sealed_build_lock = staging / "requirements-build.lock"
        _copy_verified_file(BUILD_LOCK, sealed_build_lock, expected_sha256=BUILD_LOCK_SHA256)
        sealed_wheelhouse = staging / "wheelhouse"
        sealed_wheelhouse.mkdir(mode=0o700)
        for name, expected in WHEELS.items():
            _copy_verified_file(
                wheelhouse / name,
                sealed_wheelhouse / name,
                expected_sha256=expected,
            )
        runtime = extract_runtime(sealed_archive, staging / "runtime")
        remove_bytecode(runtime)
        if (
            _canonical_tree_sha256(runtime) != RUNTIME_TREE_SHA256
            or sha256_file(runtime / "bin" / "python3.11") != PYTHON_EXECUTABLE_SHA256
            or sha256_file(runtime / "lib" / "libpython3.11.dylib") != LIBPYTHON_SHA256
        ):
            raise BootstrapError("transformed runtime tree does not match the release pin")

        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
        }
        build_environment = staging / "build-environment"
        _run(
            [str(runtime / "bin" / "python3.11"), "-I", "-B", "-m", "venv", str(build_environment)],
            timeout=120,
            environment=environment,
        )
        builder = build_environment / "bin" / "python"
        _run(
            [
                str(builder),
                "-I",
                "-B",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--only-binary=:all:",
                "--require-hashes",
                "--no-compile",
                "--find-links",
                str(sealed_wheelhouse),
                "-r",
                str(sealed_build_lock),
            ],
            timeout=300,
            environment=environment,
        )
        remove_bytecode(runtime)
        remove_bytecode(build_environment)
        site_packages = canonicalize_build_environment(build_environment, runtime=runtime)
        if (
            _canonical_tree_sha256(runtime) != RUNTIME_TREE_SHA256
            or _canonical_tree_sha256(site_packages) != BUILD_SITE_PACKAGES_SHA256
        ):
            raise BootstrapError("sealed build environment does not match the release pin")

        require_clean_source()
        command = _release_command(
            builder,
            output_dir,
            notarize=notarize,
            resume_notarization=resume_notarization,
        )
        release_environment = dict(environment)
        release_environment["LANTERN_RELEASE_BOOTSTRAP"] = "lantern.macos-bootstrap.v1"
        _run(command, timeout=2 * 60 * 60, environment=release_environment)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a sealed Lantern macOS release build.")
    parser.add_argument("--runtime-archive", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--notarize", action="store_true")
    parser.add_argument("--resume-notarization", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        run_release(
            arguments.runtime_archive,
            arguments.wheelhouse,
            arguments.output_dir,
            notarize=arguments.notarize,
            resume_notarization=arguments.resume_notarization,
        )
    except (BootstrapError, OSError, subprocess.SubprocessError) as exc:
        print(f"Lantern sealed macOS release failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
