from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import package_support
import pytest
from package_support import (
    CHECKSUM_NAME,
    MANIFEST_NAME,
    PackageVerificationError,
    assert_zip_matches_tree,
    canonical_records_sha256,
    collect_file_records,
    create_reproducible_zip,
    write_manifest,
    write_manifest_checksum,
)


def test_records_and_zip_are_deterministic_and_preserve_safe_symlinks(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    payload = artifact / "payload"
    payload.mkdir(parents=True)
    executable = payload / "start"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    (payload / "start-link").symlink_to("start")
    records = collect_file_records(artifact)

    assert [record["path"] for record in records] == ["payload/start", "payload/start-link"]
    assert records[0]["mode"] == "0755"
    assert records[1]["type"] == "symlink"
    assert len(canonical_records_sha256(records)) == 64

    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    create_reproducible_zip(artifact, first, source_epoch=1_700_000_000)
    create_reproducible_zip(artifact, second, source_epoch=1_700_000_000)
    assert first.read_bytes() == second.read_bytes()
    assert_zip_matches_tree(artifact, first)
    with zipfile.ZipFile(first) as archive:
        link = archive.getinfo("artifact/payload/start-link")
        assert (link.external_attr >> 16) & 0o170000 == 0o120000


def test_absolute_symlink_is_rejected_even_when_it_points_inside_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    target = artifact / "target"
    target.write_text("data", encoding="utf-8")
    (artifact / "absolute-link").symlink_to(target.resolve())

    with pytest.raises(PackageVerificationError, match="relative POSIX"):
        collect_file_records(artifact)


def test_escaping_and_broken_symlinks_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("data", encoding="utf-8")
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "escape").symlink_to("../outside")
    with pytest.raises(PackageVerificationError, match="escapes"):
        collect_file_records(artifact)

    (artifact / "escape").unlink()
    (artifact / "broken").symlink_to("missing")
    with pytest.raises(PackageVerificationError, match="missing or cyclic"):
        collect_file_records(artifact)


def test_manifest_and_checksum_refuse_overwrite(tmp_path: Path) -> None:
    manifest = {"schema": "example"}
    write_manifest(tmp_path, manifest)
    write_manifest_checksum(tmp_path)
    assert json.loads((tmp_path / MANIFEST_NAME).read_text(encoding="utf-8")) == manifest
    assert (tmp_path / CHECKSUM_NAME).read_text(encoding="ascii").endswith(f"  {MANIFEST_NAME}\n")

    with pytest.raises(PackageVerificationError, match="already exists"):
        write_manifest(tmp_path, manifest)
    with pytest.raises(PackageVerificationError, match="already exists"):
        write_manifest_checksum(tmp_path)


def test_zip_refuses_existing_destination_and_absolute_symlink(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    file = artifact / "file"
    file.write_bytes(b"data")
    destination = tmp_path / "artifact.zip"
    destination.write_bytes(b"occupied")
    with pytest.raises(PackageVerificationError, match="already exists"):
        create_reproducible_zip(artifact, destination, source_epoch=1_700_000_000)

    destination.unlink()
    (artifact / "absolute-link").symlink_to(file.resolve())
    with pytest.raises(PackageVerificationError, match="relative POSIX"):
        create_reproducible_zip(artifact, destination, source_epoch=1_700_000_000)


def test_manifest_paths_are_posix_and_environment_independent(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    nested = artifact / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "file").write_text("value", encoding="utf-8")
    record = collect_file_records(artifact)[0]
    assert record["path"] == "one/two/file"
    assert os.fspath(tmp_path) not in json.dumps(record)


def _append_directory_member(archive_path: Path, name: str) -> None:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (0o040000 | 0o755) << 16
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(archive_path, mode="a") as archive:
        archive.writestr(info, b"")


@pytest.mark.parametrize(
    ("member", "error"),
    [
        ("../../escape/", "not canonical"),
        ("/absolute/", "safe relative"),
        ("artifact/unexpected/", "do not match"),
    ],
)
def test_zip_rejects_every_extra_or_unsafe_directory_member(
    tmp_path: Path, member: str, error: str
) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "file").write_bytes(b"payload")
    archive = tmp_path / "artifact.zip"
    create_reproducible_zip(artifact, archive, source_epoch=1_700_000_000)
    _append_directory_member(archive, member)

    with pytest.raises(PackageVerificationError, match=error):
        assert_zip_matches_tree(artifact, archive)


def test_zip_rejects_duplicate_directory_member(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "file").write_bytes(b"payload")
    archive = tmp_path / "artifact.zip"
    create_reproducible_zip(artifact, archive, source_epoch=1_700_000_000)
    with pytest.warns(UserWarning, match="Duplicate name"):
        _append_directory_member(archive, "artifact/")

    with pytest.raises(PackageVerificationError, match="duplicate"):
        assert_zip_matches_tree(artifact, archive)


def test_zip_enforces_total_member_count_including_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact"
    nested = artifact / "nested"
    nested.mkdir(parents=True)
    (nested / "file").write_bytes(b"payload")
    archive = tmp_path / "artifact.zip"
    create_reproducible_zip(artifact, archive, source_epoch=1_700_000_000)
    monkeypatch.setattr(package_support, "MAX_ARCHIVE_MEMBERS", 2)

    with pytest.raises(PackageVerificationError, match="too many members"):
        assert_zip_matches_tree(artifact, archive)
