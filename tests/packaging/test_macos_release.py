from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest
import release_family_beta_macos as release
from package_support import (
    PackageVerificationError,
    create_reproducible_zip,
    sha256_file,
    snapshot_tree_sha256,
)


def test_unsigned_input_tamper_during_verification_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "unsigned"
    artifact.mkdir()
    payload = artifact / "payload"
    payload.write_bytes(b"verified bytes")
    (artifact / "package-manifest.json").write_text("{}", encoding="utf-8")
    archive = tmp_path / "unsigned.zip"
    create_reproducible_zip(artifact, archive, source_epoch=1_700_000_000)
    snapshot = snapshot_tree_sha256(artifact)

    def tamper(_artifact: Path, *, require_clean_source: bool) -> dict[str, object]:
        assert require_clean_source is True
        payload.write_bytes(b"changed after trust decision")
        return {"trust": "UNSIGNED DEVELOPMENT BUILD"}

    monkeypatch.setattr(release, "verify_package", tamper)
    with pytest.raises(PackageVerificationError, match="changed during verification"):
        release._verified_unsigned_input(
            artifact,
            archive,
            expected_source_commit="a" * 40,
            expected_snapshot_sha256=snapshot,
            expected_manifest_sha256=sha256_file(artifact / "package-manifest.json"),
            expected_tree_sha256="b" * 64,
            expected_archive_sha256=sha256_file(archive),
        )


def test_release_tool_identity_requires_clean_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    commit = "a" * 40

    def git(*arguments: str) -> str:
        if arguments[0] == "rev-parse":
            return commit
        if arguments[0] == "status":
            return " M scripts/macos_codesign.py"
        raise AssertionError(arguments)

    monkeypatch.setattr(release, "_run_git", git)
    with pytest.raises(PackageVerificationError, match="clean reviewed commit"):
        release._release_tool_identity()


def test_release_refuses_direct_unsealed_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release.platform, "system", lambda: "Darwin")
    monkeypatch.delenv("LANTERN_RELEASE_BOOTSTRAP", raising=False)
    with pytest.raises(PackageVerificationError, match="reviewed sealed macOS bootstrap"):
        release.release_signed_family_beta(tmp_path, notarize=False)


def test_runtime_lock_is_exact_and_immutable() -> None:
    metadata = release._runtime_lock()
    assert metadata == {
        "runtime_lock_sha256": "ab6582b81a411e0afeac0f5e9d8f06515f67915b2cdb6e58d7517c0f27df7c2a",
        "runtime_archive_sha256": (
            "7dc10e31eede05a6ab1ec9e0b961f521078b0959f838ed1d7452597d529ff802"
        ),
        "runtime_version": "3.11.15",
        "runtime_python_executable_sha256": (
            "95c331c5e61804b2dcea00dd105fbf7c9e417aaabff23fa5da6758d84033029d"
        ),
        "runtime_libpython_sha256": (
            "39669f88807bff419376e0ba17ae68d194f065f7959fb61cd4777af65da09e51"
        ),
        "runtime_tree_sha256": ("89f2b0d5e85dc62c5ec225dc850e097f863c7406d23a2835a4e983f050ee093d"),
        "build_site_packages_sha256": (
            "d027604b53d335f21c22687cfa4e69d83c7a1468664ebbbe502f5377388bb5fd"
        ),
    }


def test_embedded_provenance_writer_refuses_collision(tmp_path: Path) -> None:
    app = tmp_path / "Start Lantern.app"
    destination = app / release.EMBEDDED_PROVENANCE
    destination.parent.mkdir(parents=True)
    destination.write_text("attacker-controlled", encoding="utf-8")

    with pytest.raises(PackageVerificationError, match="refusing to replace"):
        release._write_embedded_provenance(app, {"schema": "example"})
    assert destination.read_text(encoding="utf-8") == "attacker-controlled"


def test_notarization_default_cannot_claim_acceptance() -> None:
    assert release._notarization_default() == {
        "status": "not-performed",
        "submission_id": None,
        "archive_sha256": None,
        "log_sha256": None,
    }


def test_load_existing_manifest_rejects_non_object(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "package-manifest.json").write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(PackageVerificationError, match="manifest is invalid"):
        release._load_existing_manifest(artifact)


@pytest.mark.skipif(
    release.platform.system() != "Darwin",
    reason="Apple ditto round-trip is available only on macOS",
)
def test_apple_zip_round_trip_preserves_tree_bytes(tmp_path: Path) -> None:
    artifact = tmp_path / "Lantern"
    artifact.mkdir()
    (artifact / "file").write_bytes(b"signed bytes")
    archive = tmp_path / "Lantern.zip"

    release._create_apple_zip(artifact, archive)
    release._verify_apple_zip(artifact, archive, stapled_app=None)


def test_apple_zip_validation_rejects_escape_member(tmp_path: Path) -> None:
    archive = tmp_path / "Lantern.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("Lantern/file", b"safe")
        stream.writestr("../escape", b"unsafe")

    with pytest.raises(PackageVerificationError, match="path is invalid"):
        release._validate_apple_zip_names(archive, root_name="Lantern")


def test_signed_manifest_binds_full_signature_inventory_and_outer_cdhash(tmp_path: Path) -> None:
    artifact = tmp_path / "signed"
    artifact.mkdir()
    (artifact / "signed-byte").write_bytes(b"signed application bytes")
    evidence = {
        "schema": "lantern.macos-signature-inventory.v1",
        "objects": [
            {
                "path": "Start Lantern.app",
                "type": "application-bundle",
                "architectures": [],
                "minimum_macos": [],
                "cdhash": "a" * 40,
                "designated_requirement": (
                    'identifier "net.lantern.family-beta" and anchor apple generic'
                ),
                "runtime": True,
                "secure_timestamp": "Aug 17, 2026 at 10:00:00 AM",
                "certificate_sha1": "b" * 40,
                "certificate_sha256": "c" * 64,
                "team_id": "HY2MDL9DND",
                "entitlements_sha256": "d" * 64,
            }
        ],
        "object_count": 1,
        "macho_count": 0,
        "inventory_sha256": "e" * 64,
        "outer_cdhash": "a" * 40,
        "team_id": "HY2MDL9DND",
        "certificate_sha1": "b" * 40,
        "certificate_sha256": "c" * 64,
    }
    unsigned_manifest = {
        "release": {"version": "0.3.0.dev4"},
        "target": {"architecture": "arm64"},
        "contracts": {},
        "provenance": {},
    }

    manifest = release._build_signed_manifest(
        artifact,
        unsigned_manifest=unsigned_manifest,
        payload_provenance={"schema": "lantern.macos-signing.v1"},
        signature_evidence=evidence,
        notarization=release._notarization_default(),
    )

    assert manifest["signing"]["signature_evidence"] == evidence
    assert manifest["signing"]["signature_evidence"]["inventory_sha256"] == "e" * 64
    assert manifest["signing"]["signature_evidence"]["outer_cdhash"] == "a" * 40


def _resume_state(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    output = tmp_path / "output"
    output.mkdir()
    work = output / ".lantern-notarization-state"
    work.mkdir(mode=0o700)
    final_name = "lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED-NOTARIZED"
    artifact = work / final_name
    app = artifact / release.SIGNED_APP_NAME
    embedded = app / release.EMBEDDED_PROVENANCE
    embedded.parent.mkdir(parents=True)
    embedded.write_text('{"schema":"signed"}', encoding="utf-8")
    (work / release.NOTARY_ARCHIVE_NAME).write_bytes(b"submitted zip")
    (work / release.RECEIPT_NAME).write_text("receipt", encoding="utf-8")
    binding = {
        "schema": release.STATE_BINDING_SCHEMA,
        "artifact_name": final_name,
        "artifact_snapshot_sha256": snapshot_tree_sha256(artifact),
        "app_snapshot_sha256": snapshot_tree_sha256(app),
        "embedded_provenance_sha256": sha256_file(embedded),
        "release_tool_commit": "a" * 40,
    }
    return output, work, binding


def _resume_mocks(
    monkeypatch: pytest.MonkeyPatch,
    binding: dict[str, str],
    events: list[str],
) -> None:
    release_tool = {
        "release_tool_commit": "a" * 40,
        "release_tool_clean": True,
        "release_sources_sha256": {"source": "b" * 64},
    }
    unsigned_manifest = {
        "release": {"version": "0.3.0.dev4"},
        "target": {"architecture": "arm64"},
        "contracts": {},
        "provenance": {"source_commit": "a" * 40},
    }
    certificate = release.SigningCertificate(
        common_name=release.EXPECTED_IDENTITY,
        sha1=release.EXPECTED_IDENTITY_SHA1,
        sha256=release.EXPECTED_CERTIFICATE_SHA256,
        team_id=release.EXPECTED_TEAM_ID,
    )
    signature_evidence = {
        "inventory_sha256": "c" * 64,
        "outer_cdhash": "d" * 40,
    }
    monkeypatch.setattr(release.platform, "system", lambda: "Darwin")
    monkeypatch.setenv("LANTERN_RELEASE_BOOTSTRAP", "lantern.macos-bootstrap.v1")
    monkeypatch.setattr(release, "_release_tool_identity", lambda: release_tool)
    monkeypatch.setattr(
        release,
        "load_submission_receipt",
        lambda *_args, **_kwargs: {"binding": binding},
    )
    monkeypatch.setattr(
        release,
        "_load_resume_payload",
        lambda *_args, **_kwargs: ({"schema": "signed"}, unsigned_manifest),
    )
    monkeypatch.setattr(release, "resolve_signing_certificate", lambda: certificate)
    monkeypatch.setattr(release, "load_entitlement_allowlist", dict)

    def verify_signatures(*_args: object, **_kwargs: object) -> dict[str, object]:
        events.append("verify-signatures")
        return signature_evidence

    monkeypatch.setattr(release, "verify_application_signatures", verify_signatures)
    monkeypatch.setattr(
        release,
        "_verify_apple_zip",
        lambda *_args, **_kwargs: events.append("verify-submission-zip"),
    )

    def wait(
        _archive: Path,
        _receipt: Path,
        log: Path,
        **_kwargs: object,
    ) -> dict[str, str]:
        events.append("wait-for-existing-submission")
        log.write_text("accepted log", encoding="utf-8")
        return {
            "status": "Accepted",
            "submission_id": "3295d9ec-89a3-4358-a2d4-bc6a8583c16e",
            "archive_sha256": "e" * 64,
            "log_sha256": "f" * 64,
        }

    monkeypatch.setattr(release, "wait_for_receipt", wait)
    monkeypatch.setattr(release, "staple", lambda _path: events.append("staple"))
    monkeypatch.setattr(release, "validate_staple", lambda _path: events.append("validate-staple"))

    def complete(*_args: object, **_kwargs: object) -> dict[str, object]:
        events.append("publish-verified-final")
        return {"trust": "SIGNED AND NOTARIZED FAMILY BETA"}

    monkeypatch.setattr(release, "_complete_and_publish", complete)


def test_resume_revalidates_then_staples_and_publishes_without_resubmitting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, work, binding = _resume_state(tmp_path)
    events: list[str] = []
    _resume_mocks(monkeypatch, binding, events)

    result = release.resume_notarized_family_beta(work, output)

    assert result == {
        "trust": "SIGNED AND NOTARIZED FAMILY BETA",
        "retained_notarization_state": str(work),
    }
    assert events == [
        "verify-signatures",
        "verify-submission-zip",
        "wait-for-existing-submission",
        "staple",
        "validate-staple",
        "verify-signatures",
        "publish-verified-final",
    ]
    assert work.is_dir()


def test_notarization_state_identity_check_never_deletes_replacement(
    tmp_path: Path,
) -> None:
    work = tmp_path / "state"
    work.mkdir()
    original = work.stat()
    moved = tmp_path / "original-state"
    work.rename(moved)
    work.mkdir()
    marker = work / "unrelated-owner-data"
    marker.write_text("keep", encoding="utf-8")

    assert not release._notarization_state_is_unchanged(
        work,
        (original.st_dev, original.st_ino),
    )
    assert marker.read_text(encoding="utf-8") == "keep"


def test_pre_receipt_failure_retains_private_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned = tmp_path / "unsigned"
    unsigned.mkdir()
    unsigned_archive = tmp_path / "unsigned.zip"
    unsigned_archive.write_bytes(b"unsigned")
    output = tmp_path / "output"
    commit = "a" * 40
    release_tool = {
        "release_tool_commit": commit,
        "release_tool_clean": True,
        "release_sources_sha256": {"source": "b" * 64},
    }
    build_receipt = {
        "source_commit": commit,
        "artifact_snapshot_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "tree_sha256": "e" * 64,
        "archive_sha256": "f" * 64,
    }
    manifest = {
        "release": {"version": "0.3.0.dev4"},
        "target": {"architecture": "arm64"},
        "contracts": {},
        "provenance": {"source_commit": commit, "source_epoch": 1_700_000_000},
    }
    certificate = release.SigningCertificate(
        common_name=release.EXPECTED_IDENTITY,
        sha1=release.EXPECTED_IDENTITY_SHA1,
        sha256=release.EXPECTED_CERTIFICATE_SHA256,
        team_id=release.EXPECTED_TEAM_ID,
    )
    monkeypatch.setattr(release.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(release, "_assert_release_tool_unchanged", lambda _value: None)
    monkeypatch.setattr(
        release,
        "_verified_unsigned_input",
        lambda *_args, **_kwargs: (manifest, "c" * 64),
    )
    monkeypatch.setattr(release, "resolve_signing_certificate", lambda: certificate)
    monkeypatch.setattr(release, "load_entitlement_allowlist", dict)
    monkeypatch.setattr(release, "signing_tool_records", dict)
    monkeypatch.setattr(
        release,
        "tool_record",
        lambda _path: {"path": "/tool", "sha256": "1" * 64},
    )
    monkeypatch.setattr(release, "preflight_notary_credentials", dict)
    monkeypatch.setattr(release, "notary_tool_records", dict)
    monkeypatch.setattr(release, "_payload_provenance", lambda **_kwargs: {})

    def fail_after_creating_state(_source: Path, destination: Path, **_kwargs: object) -> Path:
        destination.mkdir(parents=True)
        (destination / "review-marker").write_text("retained", encoding="utf-8")
        raise PackageVerificationError("preparation failed")

    monkeypatch.setattr(release, "_prepare_signed_tree", fail_after_creating_state)

    with pytest.raises(PackageVerificationError, match="private state was retained for review"):
        release._release_verified_family_beta(
            unsigned,
            unsigned_archive,
            output,
            notarize=True,
            release_tool=release_tool,
            build_receipt=build_receipt,
        )

    states = list(output.glob(".*.notarization-*"))
    assert len(states) == 1
    assert (next(states[0].rglob("review-marker"))).read_text(encoding="utf-8") == "retained"


def test_resume_staple_failure_preserves_state_and_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, work, binding = _resume_state(tmp_path)
    events: list[str] = []
    _resume_mocks(monkeypatch, binding, events)
    monkeypatch.setattr(
        release,
        "staple",
        lambda _path: (_ for _ in ()).throw(PackageVerificationError("staple failed")),
    )

    with pytest.raises(PackageVerificationError, match="staple failed"):
        release.resume_notarized_family_beta(work, output)

    assert work.is_dir()
    assert not any(path.name.endswith(".zip.sha256") for path in output.iterdir())
    assert "publish-verified-final" not in events


def test_resume_rejects_tampered_signed_artifact_before_apple_or_staple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, work, binding = _resume_state(tmp_path)
    events: list[str] = []
    _resume_mocks(monkeypatch, binding, events)
    app = work / binding["artifact_name"] / release.SIGNED_APP_NAME
    (app / "tamper").write_text("changed", encoding="utf-8")

    with pytest.raises(PackageVerificationError, match="does not match its receipt"):
        release.resume_notarized_family_beta(work, output)

    assert events == []
    assert work.is_dir()


def test_fresh_notarized_release_submits_once_then_enters_resume_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unsigned = tmp_path / "unsigned"
    unsigned.mkdir()
    unsigned_archive = tmp_path / "unsigned.zip"
    unsigned_archive.write_bytes(b"unsigned archive")
    output = tmp_path / "output"
    release_tool = {
        "release_tool_commit": "a" * 40,
        "release_tool_clean": True,
        "release_sources_sha256": {"source": "b" * 64},
    }
    manifest = {
        "release": {"version": "0.3.0.dev4"},
        "target": {"architecture": "arm64"},
        "contracts": {},
        "provenance": {"source_commit": "a" * 40, "source_epoch": 1_700_000_000},
    }
    receipt = {
        "source_commit": "a" * 40,
        "artifact_snapshot_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "tree_sha256": "e" * 64,
        "archive_sha256": "f" * 64,
    }
    binding = {
        "schema": release.STATE_BINDING_SCHEMA,
        "artifact_name": "lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED-NOTARIZED",
        "artifact_snapshot_sha256": "1" * 64,
        "app_snapshot_sha256": "2" * 64,
        "embedded_provenance_sha256": "3" * 64,
        "release_tool_commit": "a" * 40,
    }
    certificate = release.SigningCertificate(
        common_name=release.EXPECTED_IDENTITY,
        sha1=release.EXPECTED_IDENTITY_SHA1,
        sha256=release.EXPECTED_CERTIFICATE_SHA256,
        team_id=release.EXPECTED_TEAM_ID,
    )
    events: list[str] = []
    monkeypatch.setattr(release.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(release, "_assert_release_tool_unchanged", lambda _value: None)
    monkeypatch.setattr(
        release,
        "_verified_unsigned_input",
        lambda *_args, **_kwargs: (manifest, "c" * 64),
    )
    monkeypatch.setattr(release, "snapshot_tree_sha256", lambda _path: "c" * 64)
    monkeypatch.setattr(release, "resolve_signing_certificate", lambda: certificate)
    monkeypatch.setattr(release, "load_entitlement_allowlist", dict)
    monkeypatch.setattr(release, "signing_tool_records", dict)
    monkeypatch.setattr(release, "tool_record", lambda _path: {"path": "/tool", "sha256": "4" * 64})
    monkeypatch.setattr(release, "preflight_notary_credentials", dict)
    monkeypatch.setattr(release, "notary_tool_records", dict)
    monkeypatch.setattr(release, "_payload_provenance", lambda **_kwargs: {"signed": True})

    def prepare(_source: Path, destination: Path, **_kwargs: object) -> Path:
        events.append("prepare")
        app = destination / release.SIGNED_APP_NAME
        embedded = app / release.EMBEDDED_PROVENANCE
        embedded.parent.mkdir(parents=True)
        return app

    monkeypatch.setattr(release, "_prepare_signed_tree", prepare)
    monkeypatch.setattr(
        release,
        "sign_application",
        lambda *_args, **_kwargs: events.append("sign") or {},
    )

    def create_zip(_source: Path, archive: Path) -> None:
        events.append("create-submission-zip")
        archive.write_bytes(b"submitted")

    monkeypatch.setattr(release, "_create_apple_zip", create_zip)
    monkeypatch.setattr(
        release,
        "_verify_apple_zip",
        lambda *_args, **_kwargs: events.append("verify-submission-zip"),
    )
    monkeypatch.setattr(release, "_notarization_binding", lambda *_args, **_kwargs: binding)

    def submit(_archive: Path, receipt_path: Path, **_kwargs: object) -> dict[str, object]:
        events.append("submit-no-wait")
        receipt_path.write_text("receipt", encoding="utf-8")
        return {"submission_id": "3295d9ec-89a3-4358-a2d4-bc6a8583c16e"}

    monkeypatch.setattr(release, "submit_no_wait", submit)

    def resume(work: Path, resume_output: Path) -> dict[str, object]:
        events.append("resume-existing-submission")
        assert work.parent == resume_output
        return {"trust": "SIGNED AND NOTARIZED FAMILY BETA"}

    monkeypatch.setattr(release, "resume_notarized_family_beta", resume)

    result = release._release_verified_family_beta(
        unsigned,
        unsigned_archive,
        output,
        notarize=True,
        release_tool=release_tool,
        build_receipt=receipt,
    )

    assert result == {"trust": "SIGNED AND NOTARIZED FAMILY BETA"}
    assert events == [
        "prepare",
        "sign",
        "create-submission-zip",
        "verify-submission-zip",
        "submit-no-wait",
        "resume-existing-submission",
    ]


def test_finalization_verifies_staged_and_published_notarized_bytes_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final_name = "lantern-family-beta-0.3.0.dev4-macos-arm64-SIGNED-NOTARIZED"
    artifact = tmp_path / "staged" / final_name
    (artifact / release.SIGNED_APP_NAME).mkdir(parents=True)
    output = tmp_path / "output"
    output.mkdir()
    events: list[str] = []
    unsigned_manifest = {
        "release": {"version": "0.3.0.dev4"},
        "target": {"architecture": "arm64"},
        "contracts": {},
        "provenance": {"source_commit": "a" * 40},
    }
    signature_evidence = {
        "inventory_sha256": "b" * 64,
        "outer_cdhash": "c" * 40,
    }
    notarization = {
        "status": "Accepted",
        "submission_id": "3295d9ec-89a3-4358-a2d4-bc6a8583c16e",
        "archive_sha256": "d" * 64,
        "log_sha256": "e" * 64,
    }
    release_tool = {"release_tool_commit": "a" * 40}
    monkeypatch.setattr(
        release,
        "_build_signed_manifest",
        lambda *_args, **_kwargs: {"schema": "lantern.package.v1"},
    )

    def write_manifest(root: Path, _manifest: object) -> Path:
        events.append("write-manifest")
        path = root / "package-manifest.json"
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(release, "write_manifest", write_manifest)
    monkeypatch.setattr(
        release,
        "write_manifest_checksum",
        lambda root: (root / "SHA256SUMS.txt").write_text("checksum", encoding="ascii"),
    )
    monkeypatch.setattr(
        release,
        "verify_package",
        lambda *_args, **_kwargs: events.append("verify-package") or {},
    )

    def create_zip(_source: Path, archive: Path) -> None:
        events.append("create-final-zip")
        archive.write_bytes(b"final zip")

    monkeypatch.setattr(release, "_create_apple_zip", create_zip)
    monkeypatch.setattr(
        release,
        "_verify_apple_zip",
        lambda *_args, **kwargs: events.append(f"verify-final-zip:{kwargs['stapled_app']}"),
    )
    monkeypatch.setattr(
        release,
        "_assert_release_tool_unchanged",
        lambda _tool: events.append("verify-release-source"),
    )

    def publish(outputs: object, *, verify: object) -> None:
        events.append("publish-exclusive")
        for source, destination in outputs:
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        verify()

    monkeypatch.setattr(release, "publish_outputs_exclusive", publish)

    result = release._complete_and_publish(
        artifact,
        output,
        final_name=final_name,
        unsigned_manifest=unsigned_manifest,
        payload_provenance={"schema": "signed"},
        signature_evidence=signature_evidence,
        notarization=notarization,
        release_tool=release_tool,
    )

    assert result["trust"] == "SIGNED AND NOTARIZED FAMILY BETA"
    assert events == [
        "write-manifest",
        "verify-package",
        "create-final-zip",
        f"verify-final-zip:{release.SIGNED_APP_NAME}",
        "verify-release-source",
        "publish-exclusive",
        "verify-release-source",
        "verify-package",
        f"verify-final-zip:{release.SIGNED_APP_NAME}",
    ]
