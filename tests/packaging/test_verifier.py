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
    with pytest.raises(PackageVerificationError, match="launcher.*regular"):
        _verify_target(tmp_path.resolve(), target)


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
            },
            stream,
        )
    target = {"os": "macos", "payload": app.name}
    _verify_macos_plist(tmp_path, target, "0.3.0.dev3")

    info = plistlib.loads((contents / "Info.plist").read_bytes())
    info["CFBundleShortVersionString"] = "0.3.0.dev3"
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    with pytest.raises(PackageVerificationError, match="CFBundleShortVersionString"):
        _verify_macos_plist(tmp_path, target, "0.3.0.dev3")


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
