"""Small stdlib-only helpers shared by Lantern packaging and verification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MANIFEST_NAME = "package-manifest.json"
CHECKSUM_NAME = "SHA256SUMS.txt"
MANIFEST_SCHEMA = "lantern.package.v1"
SELF_TEST_SCHEMA = "lantern.package-self-test.v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILES = 20_000
MAX_ARCHIVE_MEMBERS = MAX_FILES * 2 + 1
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
EXCLUDED_MANIFEST_PATHS = frozenset({MANIFEST_NAME, CHECKSUM_NAME})


class PackageVerificationError(RuntimeError):
    """Raised when an artifact does not match its declared package contract."""


@dataclass(frozen=True)
class _PublishedIdentity:
    path: Path
    device: int
    inode: int
    mode: int


def _published_identity(path: Path) -> _PublishedIdentity:
    details = path.lstat()
    return _PublishedIdentity(path, details.st_dev, details.st_ino, details.st_mode)


def _identity_matches(identity: _PublishedIdentity) -> bool:
    try:
        current = identity.path.lstat()
    except FileNotFoundError:
        return False
    return (
        current.st_dev == identity.device
        and current.st_ino == identity.inode
        and stat.S_IFMT(current.st_mode) == stat.S_IFMT(identity.mode)
    )


def sha256_file(path: Path) -> str:
    """Hash one regular file without following a last-component symlink."""

    if path.is_symlink() or not path.is_file():
        raise PackageVerificationError(f"expected a regular file: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def validate_relative_path(value: object) -> str:
    """Return one canonical, bounded POSIX artifact path."""

    if type(value) is not str or not value or len(value) > 1024:
        raise PackageVerificationError("manifest path must be bounded text")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise PackageVerificationError("manifest path is not a safe relative POSIX path")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageVerificationError("manifest path is not canonical")
    return value


def validate_symlink_target(root: Path, link: Path, target: object) -> str:
    """Validate a relative symlink target and prove it remains inside the artifact."""

    if type(target) is not str or not target or len(target) > 1024:
        raise PackageVerificationError("symbolic-link target must be bounded text")
    if "\x00" in target or "\\" in target or PurePosixPath(target).is_absolute():
        raise PackageVerificationError("symbolic-link target must be a relative POSIX path")
    try:
        resolved_target = link.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageVerificationError("symbolic-link target is missing or cyclic") from exc
    if not resolved_target.is_relative_to(root.resolve(strict=True)):
        raise PackageVerificationError("symbolic link escapes artifact")
    return target


def _walk_archive_tree(root: Path) -> Iterable[tuple[str, str, Path]]:
    """Yield every directory, file, and symlink without following links."""

    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                yield "symlink", relative, candidate
            else:
                yield "directory", relative, candidate
                retained.append(name)
        directories[:] = retained
        for name in sorted(filenames):
            candidate = current_path / name
            kind = "symlink" if candidate.is_symlink() else "file"
            yield kind, candidate.relative_to(root).as_posix(), candidate


def _walk_entries(root: Path) -> Iterable[tuple[str, Path]]:
    """Yield files and symlinks without traversing directory symlinks."""

    for kind, relative, candidate in _walk_archive_tree(root):
        if kind != "directory":
            yield relative, candidate


def collect_file_records(
    root: Path,
    *,
    exclude: frozenset[str] = EXCLUDED_MANIFEST_PATHS,
) -> list[dict[str, object]]:
    """Describe every regular file and symlink in deterministic order."""

    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise PackageVerificationError("artifact root must be a directory")

    records: list[dict[str, object]] = []
    total_bytes = 0
    for relative, candidate in sorted(_walk_entries(resolved_root)):
        relative = validate_relative_path(relative)
        if relative in exclude:
            continue
        if len(records) >= MAX_FILES:
            raise PackageVerificationError("artifact contains too many files")

        mode = stat.S_IMODE(candidate.lstat().st_mode)
        if candidate.is_symlink():
            target = validate_symlink_target(resolved_root, candidate, os.readlink(candidate))
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
            raise PackageVerificationError(f"unsupported artifact entry: {relative}")
        size = candidate.stat().st_size
        if size > MAX_FILE_BYTES:
            raise PackageVerificationError(f"artifact file is too large: {relative}")
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise PackageVerificationError("artifact exceeds the total-size safety bound")
        records.append(
            {
                "path": relative,
                "type": "file",
                "mode": f"{mode:04o}",
                "size": size,
                "sha256": sha256_file(candidate),
            }
        )
    return records


def canonical_records_sha256(records: list[dict[str, object]]) -> str:
    """Hash the canonical file-record list used by the manifest."""

    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_manifest(root: Path, manifest: Mapping[str, object]) -> Path:
    """Write one canonical manifest, refusing to replace an existing one."""

    target = root / MANIFEST_NAME
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise PackageVerificationError("package manifest is too large")
    try:
        with target.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise PackageVerificationError("package manifest already exists") from exc
    return target


def write_manifest_checksum(root: Path) -> Path:
    """Write the transfer-integrity checksum for the manifest."""

    manifest = root / MANIFEST_NAME
    checksum = sha256_file(manifest)
    target = root / CHECKSUM_NAME
    try:
        with target.open("x", encoding="ascii", errors="strict", newline="\n") as stream:
            stream.write(f"{checksum}  {MANIFEST_NAME}\n")
    except FileExistsError as exc:
        raise PackageVerificationError("manifest checksum already exists") from exc
    return target


def replace_manifest(root: Path, manifest: Mapping[str, object]) -> Path:
    """Replace one manifest after signing or notarization changes the artifact tree."""

    target = root / MANIFEST_NAME
    if target.exists() or target.is_symlink():
        target.unlink()
    return write_manifest(root, manifest)


def replace_manifest_checksum(root: Path) -> Path:
    """Replace the manifest checksum after the manifest is regenerated."""

    target = root / CHECKSUM_NAME
    if target.exists() or target.is_symlink():
        target.unlink()
    return write_manifest_checksum(root)


def snapshot_tree_sha256(root: Path) -> str:
    """Hash every file and symlink in a tree, including package metadata."""

    records = collect_file_records(root, exclude=frozenset())
    return canonical_records_sha256(records)


def _copy_file_exclusive(source: Path, destination: Path) -> _PublishedIdentity:
    """Copy one regular file without ever replacing the destination."""

    identity: _PublishedIdentity | None = None
    try:
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            details = os.fstat(output_stream.fileno())
            identity = _PublishedIdentity(
                destination,
                details.st_dev,
                details.st_ino,
                details.st_mode,
            )
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
        shutil.copystat(source, destination, follow_symlinks=False)
        if identity is None or not _identity_matches(identity):
            raise PackageVerificationError("published file identity changed during copy")
        return identity
    except Exception as exc:
        if identity is not None:
            raise PackageVerificationError(
                "exclusive publication copy failed; the partial output was retained for "
                f"manual review: {destination.name}"
            ) from exc
        raise


def _copy_entry_exclusive(source: Path, destination: Path) -> _PublishedIdentity:
    """Copy a tree entry using only exclusive destination operations."""

    if source.is_symlink():
        os.symlink(os.readlink(source), destination)
        identity = _published_identity(destination)
        try:
            shutil.copystat(source, destination, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        if not _identity_matches(identity):
            raise PackageVerificationError("published symbolic-link identity changed during copy")
        return identity
    if source.is_dir():
        destination.mkdir(mode=stat.S_IMODE(source.stat().st_mode))
        identity = _published_identity(destination)
        try:
            for child in sorted(source.iterdir(), key=lambda item: item.name):
                _copy_entry_exclusive(child, destination / child.name)
            shutil.copystat(source, destination, follow_symlinks=False)
        except Exception as exc:
            raise PackageVerificationError(
                "exclusive publication copy failed; the partial output was retained for "
                f"manual review: {destination.name}"
            ) from exc
        if not _identity_matches(identity):
            raise PackageVerificationError("published directory identity changed during copy")
        return identity
    if source.is_file():
        return _copy_file_exclusive(source, destination)
    raise PackageVerificationError("staged output contains an unsupported entry")


def _retained_publication_error(outputs: Sequence[_PublishedIdentity]) -> PackageVerificationError:
    """Describe fail-safe retention without deleting through raced pathnames."""

    names = sorted({identity.path.name for identity in outputs})
    return PackageVerificationError(
        "publication failed; paths created by this attempt were retained for safe manual "
        "review and no automatic deletion was attempted: " + ", ".join(names)
    )


def publish_outputs_exclusive(
    outputs: Sequence[tuple[Path, Path]],
    *,
    verify: Callable[[], None] | None = None,
) -> None:
    """Publish a set without replacement and retain failed paths for safe review."""

    if not outputs:
        raise PackageVerificationError("publication output set is empty")
    destinations = [destination for _source, destination in outputs]
    if len(destinations) != len(set(destinations)):
        raise PackageVerificationError("publication destinations are duplicated")
    for source, destination in outputs:
        if source.is_symlink() or not (source.is_file() or source.is_dir()):
            raise PackageVerificationError("staged publication source is unavailable")
        if destination.exists() or destination.is_symlink():
            raise PackageVerificationError(
                f"refusing to replace existing output: {destination.name}"
            )

    created: list[_PublishedIdentity] = []
    try:
        for source, destination in outputs:
            try:
                identity = _copy_entry_exclusive(source, destination)
            except FileExistsError as exc:
                raise PackageVerificationError(
                    f"refusing to replace existing output: {destination.name}"
                ) from exc
            created.append(identity)
        if verify is not None:
            verify()
    except Exception as publish_error:
        if created:
            raise _retained_publication_error(created) from publish_error
        raise


def zip_epoch_tuple(source_epoch: int) -> tuple[int, int, int, int, int, int]:
    """Return a ZIP-safe UTC timestamp, clamped to the format's lower bound."""

    import time

    epoch = max(source_epoch, 315_532_800)  # 1980-01-01 UTC
    values = time.gmtime(epoch)
    return (values.tm_year, values.tm_mon, values.tm_mday, values.tm_hour, values.tm_min, 0)


def create_reproducible_zip(source: Path, destination: Path, *, source_epoch: int) -> None:
    """Archive a package tree with stable order, timestamps, modes, and symlinks."""

    if destination.exists():
        raise PackageVerificationError("archive destination already exists")
    source = source.resolve(strict=True)
    timestamp = zip_epoch_tuple(source_epoch)
    root_name = validate_relative_path(source.name)

    with zipfile.ZipFile(
        destination,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        root_info = zipfile.ZipInfo(f"{root_name}/", date_time=timestamp)
        root_info.create_system = 3
        root_mode = stat.S_IMODE(source.lstat().st_mode)
        root_info.external_attr = (stat.S_IFDIR | root_mode) << 16
        root_info.compress_type = zipfile.ZIP_STORED
        archive.writestr(root_info, b"")

        entries = sorted(_walk_archive_tree(source), key=lambda item: item[1])
        if len(entries) + 1 > MAX_ARCHIVE_MEMBERS:
            raise PackageVerificationError("artifact contains too many archive members")
        for kind, relative, candidate in entries:
            relative = validate_relative_path(relative)
            mode = stat.S_IMODE(candidate.lstat().st_mode)
            if kind == "directory":
                info = zipfile.ZipInfo(f"{root_name}/{relative}/", date_time=timestamp)
                info.create_system = 3
                info.external_attr = (stat.S_IFDIR | mode) << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, b"")
                continue

            archive_name = f"{root_name}/{relative}"
            info = zipfile.ZipInfo(archive_name, date_time=timestamp)
            info.create_system = 3
            if kind == "symlink":
                target = validate_symlink_target(source, candidate, os.readlink(candidate))
                info.external_attr = (stat.S_IFLNK | mode) << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, target.encode("utf-8"))
            elif candidate.is_file():
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with candidate.open("rb") as stream, archive.open(info, "w") as output:
                    while block := stream.read(1024 * 1024):
                        output.write(block)
            else:
                raise PackageVerificationError(f"unsupported archive entry: {relative}")


def assert_zip_matches_tree(source: Path, archive_path: Path) -> None:
    """Verify archive names, file bytes, modes, and symlink targets against a tree."""

    source = source.resolve(strict=True)
    expected: dict[str, tuple[str, int, str]] = {}
    root_name = source.name
    expected[f"{root_name}/"] = (
        "directory",
        stat.S_IMODE(source.lstat().st_mode),
        "",
    )
    for kind, relative, candidate in _walk_archive_tree(source):
        relative = validate_relative_path(relative)
        mode = stat.S_IMODE(candidate.lstat().st_mode)
        if kind == "directory":
            expected[f"{root_name}/{relative}/"] = ("directory", mode, "")
        elif kind == "symlink":
            name = f"{root_name}/{relative}"
            expected[name] = (
                "symlink",
                mode,
                validate_symlink_target(source, candidate, os.readlink(candidate)),
            )
        elif kind == "file":
            name = f"{root_name}/{relative}"
            expected[name] = ("file", mode, sha256_file(candidate))

    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise PackageVerificationError("archive contains too many members")
        if len(infos) != len({item.filename for item in infos}):
            raise PackageVerificationError("archive contains duplicate paths")
        for info in infos:
            _validate_archive_member_name(info.filename, root_name=root_name)
        if {item.filename for item in infos} != set(expected):
            raise PackageVerificationError("archive contents do not match the artifact tree")
        total = 0
        for info in infos:
            if info.file_size > MAX_FILE_BYTES:
                raise PackageVerificationError("archive member exceeds the size safety bound")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise PackageVerificationError("archive exceeds the total-size safety bound")
            kind, mode, expected_value = expected[info.filename]
            archived_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_IMODE(archived_mode) != mode:
                raise PackageVerificationError("archive mode does not match the artifact tree")
            if kind == "directory":
                if not info.is_dir() or not stat.S_ISDIR(archived_mode) or info.file_size != 0:
                    raise PackageVerificationError("archive changed a directory entry type")
                continue
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            if kind == "symlink":
                if not stat.S_ISLNK(archived_mode):
                    raise PackageVerificationError("archive lost a symbolic link")
                if archive.read(info).decode("utf-8") != expected_value:
                    raise PackageVerificationError("archive symbolic-link target changed")
            else:
                if not stat.S_ISREG(archived_mode):
                    raise PackageVerificationError("archive changed a regular-file entry type")
                if digest.hexdigest() != expected_value:
                    raise PackageVerificationError("archive file content changed")


def _validate_archive_member_name(value: object, *, root_name: str) -> str:
    """Validate one canonical ZIP member rooted beneath the artifact directory."""

    if type(value) is not str or not value or len(value) > 2048:
        raise PackageVerificationError("archive member name must be bounded text")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise PackageVerificationError("archive member is not a safe relative POSIX path")
    is_directory = value.endswith("/")
    canonical = value[:-1] if is_directory else value
    if not canonical:
        raise PackageVerificationError("archive member path is empty")
    path = PurePosixPath(canonical)
    if str(path) != canonical or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageVerificationError("archive member path is not canonical")
    if not path.parts or path.parts[0] != root_name:
        raise PackageVerificationError("archive member is outside the canonical artifact root")
    if len(path.parts) == 1 and value != f"{root_name}/":
        raise PackageVerificationError("archive root member is not a directory")
    return value
