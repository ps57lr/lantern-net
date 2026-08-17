from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path

import pytest
from package_support import PackageVerificationError
from verify_family_beta import (
    _strict_json_loads,
    _verify_macos_ad_hoc,
    _verify_macos_plist,
    _verify_macos_signature,
    _verify_payload_provenance,
    _verify_release,
    _verify_target,
)


def test_strict_json_rejects_duplicate_keys_and_nonfinite_values() -> None:
    with pytest.raises(PackageVerificationError, match="duplicate"):
        _strict_json_loads('{"schema":"one","schema":"two"}')
    for value in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(PackageVerificationError, match="non-finite"):
            _strict_json_loads(f'{{"number":{value}}}')


def test_strict_json_normalizes_deep_nesting_and_rejects_lone_surrogates() -> None:
    with pytest.raises(PackageVerificationError, match="structural bounds"):
        _strict_json_loads("[" * 2_000 + "0" + "]" * 2_000)
    with pytest.raises(PackageVerificationError, match="Unicode surrogate"):
        _strict_json_loads('{"value":"\\ud800"}')


def test_release_contract_rejects_any_unsafe_packaging_feature() -> None:
    release = {
        "version": "0.3.0.dev3",
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
    assert _verify_release(release)["unsigned_development"] is True
    for field in ("auto_update", "installer", "elevation", "autorun", "persistence"):
        changed = dict(release)
        changed[field] = True
        with pytest.raises(PackageVerificationError, match="unsafe or misleading"):
            _verify_release(changed)


def test_target_rejects_symlinked_executable(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    real = payload / "real"
    real.write_bytes(b"binary")
    real.chmod(0o755)
    (payload / "launcher").symlink_to("real")
    target = {
        "os": "linux",
        "architecture": "x86_64",
        "payload": "payload",
        "launcher": "payload/launcher",
        "self_test": "payload/real",
        "macos_signature": "not-applicable",
    }
    release = {"channel": "family-beta-development"}
    with pytest.raises(PackageVerificationError, match="launcher.*regular"):
        _verify_target(tmp_path.resolve(), target, release)


def test_signed_target_cannot_downgrade_to_linux_or_escape_signed_app(tmp_path: Path) -> None:
    release = {"channel": "family-beta-signed"}
    linux = {
        "os": "linux",
        "architecture": "x86_64",
        "payload": "payload",
        "launcher": "payload/launcher",
        "self_test": "payload/verifier",
        "macos_signature": "not-applicable",
    }
    with pytest.raises(PackageVerificationError, match="fixed contract"):
        _verify_target(tmp_path.resolve(), linux, release)

    outside_self_test = {
        "os": "macos",
        "architecture": "arm64",
        "payload": "Start Lantern.app",
        "launcher": "Start Lantern.app/Contents/MacOS/Start Lantern",
        "self_test": "attacker-self-test",
        "macos_signature": "developer-id-application",
    }
    with pytest.raises(PackageVerificationError, match="fixed contract"):
        _verify_target(tmp_path.resolve(), outside_self_test, release)


def test_macos_plist_uses_numeric_marketing_and_build_versions(tmp_path: Path) -> None:
    app = tmp_path / "Start Lantern (Unsigned Dev).app"
    contents = app / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(
            {
                "CFBundleIdentifier": "net.lantern.family-beta-development",
                "CFBundleDisplayName": "Start Lantern (Unsigned Dev)",
                "CFBundleShortVersionString": "0.3.0",
                "CFBundleVersion": "3",
                "LanternReleaseChannel": "family-beta-development",
                "LanternUnsignedDevelopment": True,
                "LSMinimumSystemVersion": "11.0",
            },
            stream,
        )
    target = {"os": "macos", "payload": app.name}
    release = {"channel": "family-beta-development", "version": "0.3.0.dev3"}
    _verify_macos_plist(tmp_path, target, release)

    info = plistlib.loads((contents / "Info.plist").read_bytes())
    info["CFBundleShortVersionString"] = "0.3.0.dev3"
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    with pytest.raises(PackageVerificationError, match="CFBundleShortVersionString"):
        _verify_macos_plist(tmp_path, target, release)

    info["CFBundleShortVersionString"] = "0.3.0"
    info["LSMinimumSystemVersion"] = "12.0"
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    with pytest.raises(PackageVerificationError, match="LSMinimumSystemVersion"):
        _verify_macos_plist(tmp_path, target, release)


def test_signed_release_contract_requires_team_id_and_matching_label() -> None:
    release = {
        "version": "0.3.0.dev3",
        "channel": "family-beta-signed",
        "label": "SIGNED FAMILY BETA",
        "unsigned_development": False,
        "developer_id_signing": "team-id:HY2MDL9DND",
        "notarization": "not-performed",
        "auto_update": False,
        "installer": False,
        "elevation": False,
        "autorun": False,
        "persistence": False,
        "usb_autorun": False,
        "packaging_network_additions": "none",
    }
    assert _verify_release(release)["notarization"] == "not-performed"
    stapled = dict(release)
    stapled["label"] = "SIGNED AND NOTARIZED FAMILY BETA"
    stapled["notarization"] = "stapled"
    assert _verify_release(stapled)["notarization"] == "stapled"

    wrong_team = dict(release)
    wrong_team["developer_id_signing"] = "team-id:WRONGTEAM1"
    with pytest.raises(PackageVerificationError, match="team identity"):
        _verify_release(wrong_team)


def test_signed_payload_provenance_requires_exact_pins_and_tool_hashes() -> None:
    digest = "a" * 64
    payload = {
        "schema": "lantern.macos-signing.v1",
        "release_tool_commit": "b" * 40,
        "release_tool_clean": True,
        "release_sources_sha256": {
            name: digest
            for name in (
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
            )
        },
        "input_snapshot_sha256": digest,
        "input_manifest_sha256": digest,
        "input_tree_sha256": digest,
        "input_archive_sha256": digest,
        "input_manifest_binding": {
            "release_version": "0.3.0.dev4",
            "target": {
                "os": "macos",
                "architecture": "arm64",
                "payload": "Start Lantern (Unsigned Dev).app",
                "launcher": (
                    "Start Lantern (Unsigned Dev).app/Contents/MacOS/Start Lantern (Unsigned Dev)"
                ),
                "self_test": (
                    "Start Lantern (Unsigned Dev).app/Contents/MacOS/verify-lantern-package"
                ),
                "macos_signature": "ad-hoc-only",
            },
            "contracts": {},
            "build_provenance": {},
            "tree_sha256": digest,
        },
        "entitlements_sha256": ("97704a8960b4facceef54397a08fb5d0a456247c3627359215aa2a27df22656c"),
        "runtime_lock_sha256": ("523fde449f9e3587b2e662ad053b8bb5c99cb26139591fa1fd8113a22aa1e2b9"),
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
            "c6f4d93a0091bc6d86b118dbb05b85af5209b30c5d4b4048fbf17fe052bcb33d"
        ),
        "certificate_common_name": "Developer ID Application: Matthew Buttrick (HY2MDL9DND)",
        "certificate_sha1": "DFE4DF368133715BAAE725CC68CC7BA8A7246BEB",
        "certificate_sha256": ("3ebaefae5bd5bdc0b0b00015d7fecea0ff0f60baae8279f4e7125d9ebdd598ed"),
        "team_id": "HY2MDL9DND",
        "tools": {
            name: {"path": f"/tools/{name}", "sha256": digest}
            for name in ("codesign", "ditto", "git", "lipo", "python", "security", "vtool")
        },
    }
    assert _verify_payload_provenance(payload, notarized=False)["team_id"] == "HY2MDL9DND"

    wrong_identity = dict(payload)
    wrong_identity["certificate_sha1"] = "0" * 40
    with pytest.raises(PackageVerificationError, match="release pin"):
        _verify_payload_provenance(wrong_identity, notarized=False)

    missing_tool = dict(payload)
    missing_tool["tools"] = dict(payload["tools"])
    del missing_tool["tools"]["lipo"]
    with pytest.raises(PackageVerificationError, match="tool hashes"):
        _verify_payload_provenance(missing_tool, notarized=False)


def test_macos_verification_covers_whole_app_and_nested_entrypoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "Start Lantern (Unsigned Dev).app"
    executable_root = app / "Contents" / "MacOS"
    executable_root.mkdir(parents=True)
    launcher = executable_root / "Start Lantern (Unsigned Dev)"
    verifier = executable_root / "verify-lantern-package"
    launcher.write_bytes(b"launcher")
    verifier.write_bytes(b"verifier")
    target = {
        "os": "macos",
        "payload": app.name,
        "launcher": launcher.relative_to(tmp_path).as_posix(),
        "self_test": verifier.relative_to(tmp_path).as_posix(),
    }
    calls: list[list[str]] = []

    def codesign(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "--verify" in command:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="Signature=adhoc\nTeamIdentifier=not set\n",
        )

    monkeypatch.setattr("verify_family_beta.platform.system", lambda: "Darwin")
    monkeypatch.setattr("verify_family_beta.subprocess.run", codesign)
    _verify_macos_ad_hoc(tmp_path, target)

    assert calls[0][1:5] == ["--verify", "--deep", "--strict", "--verbose=4"]
    assert calls[0][-1] == str(app)
    assert [call[-1] for call in calls[1:]] == [str(app), str(launcher), str(verifier)]


def test_macos_verification_rejects_nested_publisher_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    launcher = app / "launcher"
    verifier = app / "verifier"
    launcher.write_bytes(b"launcher")
    verifier.write_bytes(b"verifier")
    target = {
        "os": "macos",
        "payload": "app",
        "launcher": "app/launcher",
        "self_test": "app/verifier",
    }
    display_count = 0

    def codesign(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal display_count
        if "--verify" in command:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        display_count += 1
        details = (
            "Signature=adhoc\nTeamIdentifier=not set\n"
            if display_count < 3
            else "Signature=adhoc\nAuthority=Unexpected Developer\nTeamIdentifier=TEAM123\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr=details)

    monkeypatch.setattr("verify_family_beta.platform.system", lambda: "Darwin")
    monkeypatch.setattr("verify_family_beta.subprocess.run", codesign)
    with pytest.raises(PackageVerificationError, match="signing identity"):
        _verify_macos_ad_hoc(tmp_path, target)


def test_signed_verifier_recomputes_exact_signature_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "Start Lantern.app"
    app.mkdir()
    target = {"os": "macos", "payload": app.name}
    release = {"channel": "family-beta-signed", "notarization": "not-performed"}
    evidence = {
        "schema": "lantern.macos-signature-inventory.v1",
        "objects": [],
        "object_count": 0,
        "macho_count": 0,
        "inventory_sha256": "a" * 64,
        "outer_cdhash": "b" * 40,
        "team_id": "HY2MDL9DND",
        "certificate_sha1": "DFE4DF368133715BAAE725CC68CC7BA8A7246BEB",
        "certificate_sha256": ("3ebaefae5bd5bdc0b0b00015d7fecea0ff0f60baae8279f4e7125d9ebdd598ed"),
    }
    signing = {
        "payload_provenance": {},
        "signature_evidence": evidence,
        "notarization": {
            "status": "not-performed",
            "submission_id": None,
            "archive_sha256": None,
            "log_sha256": None,
        },
    }
    monkeypatch.setattr("verify_family_beta.platform.system", lambda: "Darwin")
    monkeypatch.setattr(
        "verify_family_beta.verify_application_signatures",
        lambda *_args, **_kwargs: evidence,
    )

    _verify_macos_signature(tmp_path, target, release, signing=signing)

    changed = dict(evidence)
    changed["outer_cdhash"] = "c" * 40
    signing["signature_evidence"] = changed
    with pytest.raises(PackageVerificationError, match="signed-object evidence"):
        _verify_macos_signature(tmp_path, target, release, signing=signing)
