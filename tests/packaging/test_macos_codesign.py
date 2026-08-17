from __future__ import annotations

import hashlib
import plistlib
import subprocess
from pathlib import Path

import macos_codesign
import pytest
from macos_codesign import (
    EXPECTED_CERTIFICATE_SHA256,
    EXPECTED_IDENTITY,
    EXPECTED_IDENTITY_SHA1,
    EXPECTED_TEAM_ID,
    SigningCertificate,
)
from package_support import PackageVerificationError


def _certificate() -> SigningCertificate:
    return SigningCertificate(
        common_name=EXPECTED_IDENTITY,
        sha1=EXPECTED_IDENTITY_SHA1,
        sha256=EXPECTED_CERTIFICATE_SHA256,
        team_id=EXPECTED_TEAM_ID,
    )


def _app(tmp_path: Path) -> Path:
    app = tmp_path / "Start Lantern.app"
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump({"LSMinimumSystemVersion": "11.0"}, stream)
    return app


def _macho(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xcf\xfa\xed\xfe" + b"binary")
    path.chmod(0o755)


def test_reviewed_entitlements_start_empty_and_forbid_get_task_allow() -> None:
    assert macos_codesign.load_entitlement_allowlist() == {}


def test_certificate_extraction_uses_codesign_output_prefix_syntax(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "Lantern"
    _macho(binary)
    leaf = b"reviewed leaf certificate"

    def extract(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        options = [item for item in command if item.startswith("--extract-certificates=")]
        assert len(options) == 1
        prefix = Path(options[0].split("=", 1)[1])
        Path(f"{prefix}0").write_bytes(leaf)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(macos_codesign, "_run_text", extract)

    assert macos_codesign._extract_certificate_hashes(binary) == (
        hashlib.sha1(leaf).hexdigest().upper(),
        hashlib.sha256(leaf).hexdigest(),
    )


def test_signing_never_applies_executable_entitlements_to_libraries_or_frameworks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    executable = app / "Contents" / "MacOS" / "Lantern"
    dylib = app / "Contents" / "Frameworks" / "libpython.dylib"
    framework = app / "Contents" / "Frameworks" / "Example.framework"
    framework_binary = framework / "Versions" / "A" / "Example"
    for path in (executable, dylib, framework_binary):
        _macho(path)

    calls: list[tuple[Path, Path | None]] = []

    def sign_one(path: Path, *, certificate: SigningCertificate, entitlements: Path | None) -> None:
        assert certificate == _certificate()
        calls.append((path, entitlements))

    monkeypatch.setattr(macos_codesign, "_sign_one", sign_one)
    monkeypatch.setattr(macos_codesign, "verify_macho_deployment_targets", lambda _path: None)
    monkeypatch.setattr(
        macos_codesign,
        "verify_application_signatures",
        lambda *_args, **_kwargs: {"macho_count": 3},
    )

    macos_codesign.sign_application(app, certificate=_certificate())

    by_path = dict(calls)
    assert by_path[executable] == macos_codesign.entitlements_path()
    assert by_path[dylib] is None
    assert by_path[framework_binary] is None
    assert by_path[framework] is None
    assert by_path[app] == macos_codesign.entitlements_path()


def test_signing_rejects_any_unpinned_identity(tmp_path: Path) -> None:
    app = _app(tmp_path)
    _macho(app / "Contents" / "MacOS" / "Lantern")
    wrong = SigningCertificate(
        common_name=EXPECTED_IDENTITY,
        sha1="0" * 40,
        sha256="a" * 64,
        team_id="WRONGTEAM1",
    )
    with pytest.raises(PackageVerificationError, match="does not match the release pin"):
        macos_codesign.sign_application(app, certificate=wrong)


def test_identity_resolution_rejects_same_fingerprint_under_wrong_team(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = f'  1) {EXPECTED_IDENTITY_SHA1} "Developer ID Application: Other (WRONGTEAM1)"\n'

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(macos_codesign, "_run_text", run)
    with pytest.raises(PackageVerificationError, match="pinned Developer ID"):
        macos_codesign.resolve_signing_certificate()


def test_deployment_target_rejects_any_nested_macho_above_plist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    binary = app / "Contents" / "MacOS" / "Lantern"
    _macho(binary)
    monkeypatch.setattr(macos_codesign, "resolve_xcrun_tool", lambda _name: Path("/vtool"))
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            stdout=("arm64\n" if "-archs" in command else "platform MACOS\n    minos 12.0\n"),
            stderr="",
        ),
    )

    with pytest.raises(PackageVerificationError, match="minimum OS exceeds"):
        macos_codesign.verify_macho_deployment_targets(app)


def test_bundle_deployment_target_must_be_exactly_macos_11(tmp_path: Path) -> None:
    app = _app(tmp_path)
    info_path = app / "Contents" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["LSMinimumSystemVersion"] = "12.0"
    info_path.write_bytes(plistlib.dumps(info))

    with pytest.raises(PackageVerificationError, match="exactly 11.0"):
        macos_codesign.verify_macho_deployment_targets(app)


def test_release_scan_rejects_missing_arm64_and_static_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    binary = app / "Contents" / "MacOS" / "Lantern"
    _macho(binary)
    monkeypatch.setattr(macos_codesign, "resolve_xcrun_tool", lambda _name: Path("/vtool"))
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            0,
            stdout=("x86_64\n" if "-archs" in command else "minos 11.0\n"),
            stderr="",
        ),
    )
    with pytest.raises(PackageVerificationError, match="not exactly arm64"):
        macos_codesign.verify_macho_deployment_targets(app)

    (app / "Contents" / "Resources").mkdir()
    (app / "Contents" / "Resources" / "unreviewed.a").write_bytes(b"archive")
    with pytest.raises(PackageVerificationError, match="object-code material"):
        macos_codesign.verify_macho_deployment_targets(app)


def test_release_scan_rejects_universal_or_non_macos_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    binary = app / "Contents" / "MacOS" / "Lantern"
    _macho(binary)
    monkeypatch.setattr(macos_codesign, "resolve_xcrun_tool", lambda _name: Path("/vtool"))

    def universal(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        stdout = "arm64 x86_64\n" if "-archs" in command else "platform MACOS\nminos 11.0\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(macos_codesign, "_run_text", universal)
    with pytest.raises(PackageVerificationError, match="not exactly arm64"):
        macos_codesign.verify_macho_deployment_targets(app)

    def ios(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        stdout = "arm64\n" if "-archs" in command else "platform IOS\nminos 11.0\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(macos_codesign, "_run_text", ios)
    with pytest.raises(PackageVerificationError, match="platform is not macOS"):
        macos_codesign.verify_macho_deployment_targets(app)


def test_signature_verification_rejects_get_task_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "Lantern"
    _macho(binary)
    details = (
        f"Authority={EXPECTED_IDENTITY}\nTeamIdentifier={EXPECTED_TEAM_ID}\n"
        "flags=0x10000(runtime)\nTimestamp=Aug 17, 2026\n"
        f"CDHash={'1' * 40}\n"
        'designated => identifier "net.lantern.family-beta" and anchor apple generic\n'
    )
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        macos_codesign,
        "inspect_signature",
        lambda _path: {
            "authority": EXPECTED_IDENTITY,
            "team_identifier": EXPECTED_TEAM_ID,
            "details": details,
        },
    )
    monkeypatch.setattr(
        macos_codesign,
        "_extract_certificate_hashes",
        lambda _path: (EXPECTED_IDENTITY_SHA1, EXPECTED_CERTIFICATE_SHA256),
    )
    monkeypatch.setattr(
        macos_codesign,
        "_signed_entitlements",
        lambda _path: {"com.apple.security.get-task-allow": True},
    )

    with pytest.raises(PackageVerificationError, match="get-task-allow"):
        macos_codesign._verify_one_signature(
            binary,
            certificate=_certificate(),
            allowed_entitlements={},
            library_code=False,
        )


def test_signature_inventory_is_sorted_complete_and_hash_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    launcher = app / "Contents" / "MacOS" / "Lantern"
    framework = app / "Contents" / "Frameworks" / "Example.framework"
    framework_binary = framework / "Versions" / "A" / "Example"
    for path in (launcher, framework_binary):
        _macho(path)

    # Exercise sorting independently from the order returned by the scanners.
    monkeypatch.setattr(macos_codesign, "macho_paths", lambda _app: [launcher, framework_binary])
    monkeypatch.setattr(macos_codesign, "_nested_bundles", lambda _app: [framework])
    monkeypatch.setattr(
        macos_codesign,
        "verify_macho_deployment_targets",
        lambda _app: {
            launcher: {"architectures": ["arm64"], "minimum_macos": ["11.0"]},
            framework_binary: {"architectures": ["arm64"], "minimum_macos": ["10.13"]},
        },
    )
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    def evidence(path: Path, **_kwargs: object) -> dict[str, object]:
        index = {
            app: "a",
            launcher: "b",
            framework: "c",
            framework_binary: "d",
        }[path]
        return {
            "cdhash": index * 40,
            "designated_requirement": f'identifier "{path.name}" and anchor apple generic',
            "runtime": True,
            "secure_timestamp": "Aug 17, 2026 at 10:00:00 AM",
            "certificate_sha1": EXPECTED_IDENTITY_SHA1,
            "certificate_sha256": EXPECTED_CERTIFICATE_SHA256,
            "team_id": EXPECTED_TEAM_ID,
            "entitlements_sha256": "e" * 64,
        }

    monkeypatch.setattr(macos_codesign, "_verify_one_signature", evidence)

    inventory = macos_codesign.verify_application_signatures(
        app,
        certificate=_certificate(),
        allowed_entitlements={},
    )

    objects = inventory["objects"]
    assert isinstance(objects, list)
    assert [item["path"] for item in objects] == sorted(item["path"] for item in objects)
    assert [item["type"] for item in objects] == [
        "application-bundle",
        "framework-bundle",
        "mach-o",
        "mach-o",
    ]
    assert inventory["object_count"] == 4
    assert inventory["macho_count"] == 2
    assert inventory["outer_cdhash"] == "a" * 40
    assert inventory["inventory_sha256"] == macos_codesign.signature_inventory_sha256(objects)
    assert objects[0]["architectures"] == []
    assert objects[-1]["architectures"] == ["arm64"]
    required = {
        "path",
        "type",
        "architectures",
        "minimum_macos",
        "cdhash",
        "designated_requirement",
        "runtime",
        "secure_timestamp",
        "certificate_sha1",
        "certificate_sha256",
        "team_id",
        "entitlements_sha256",
    }
    assert all(set(item) == required for item in objects)


def test_signature_evidence_requires_cdhash_and_designated_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "Lantern"
    _macho(binary)
    base = (
        f"Authority={EXPECTED_IDENTITY}\nTeamIdentifier={EXPECTED_TEAM_ID}\n"
        "flags=0x10000(runtime)\nTimestamp=Aug 17, 2026\n"
    )
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        macos_codesign,
        "_extract_certificate_hashes",
        lambda _path: (EXPECTED_IDENTITY_SHA1, EXPECTED_CERTIFICATE_SHA256),
    )
    monkeypatch.setattr(macos_codesign, "_signed_entitlements", lambda _path: {})

    def inspect(details: str) -> None:
        monkeypatch.setattr(
            macos_codesign,
            "inspect_signature",
            lambda _path: {
                "authority": EXPECTED_IDENTITY,
                "team_identifier": EXPECTED_TEAM_ID,
                "details": details,
            },
        )

    inspect(base + 'designated => identifier "Lantern" and anchor apple generic\n')
    with pytest.raises(PackageVerificationError, match="code-directory hash"):
        macos_codesign._verify_one_signature(
            binary,
            certificate=_certificate(),
            allowed_entitlements={},
            library_code=False,
        )

    inspect(base + f"CDHash={'1' * 40}\n")
    with pytest.raises(PackageVerificationError, match="designated requirement"):
        macos_codesign._verify_one_signature(
            binary,
            certificate=_certificate(),
            allowed_entitlements={},
            library_code=False,
        )


def test_signature_verification_returns_normalized_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "Lantern"
    _macho(binary)
    details = (
        f"Authority={EXPECTED_IDENTITY}\nTeamIdentifier={EXPECTED_TEAM_ID}\n"
        "CodeDirectory v=20500 size=5251 flags=0x10000(runtime) hashes=153+7 "
        "location=embedded\nTimestamp=Aug 17, 2026 at 10:00:00 AM\n"
        f"CDHash={'A' * 40}\n"
        'designated => identifier "net.lantern.family-beta" and anchor apple generic\n'
    )
    monkeypatch.setattr(
        macos_codesign,
        "_run_text",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        macos_codesign,
        "inspect_signature",
        lambda _path: {
            "authority": EXPECTED_IDENTITY,
            "team_identifier": EXPECTED_TEAM_ID,
            "details": details,
        },
    )
    monkeypatch.setattr(
        macos_codesign,
        "_extract_certificate_hashes",
        lambda _path: (EXPECTED_IDENTITY_SHA1, EXPECTED_CERTIFICATE_SHA256),
    )
    monkeypatch.setattr(macos_codesign, "_signed_entitlements", lambda _path: {})

    result = macos_codesign._verify_one_signature(
        binary,
        certificate=_certificate(),
        allowed_entitlements={},
        library_code=False,
    )

    assert result == {
        "cdhash": "a" * 40,
        "designated_requirement": ('identifier "net.lantern.family-beta" and anchor apple generic'),
        "runtime": True,
        "secure_timestamp": "Aug 17, 2026 at 10:00:00 AM",
        "certificate_sha1": EXPECTED_IDENTITY_SHA1,
        "certificate_sha256": EXPECTED_CERTIFICATE_SHA256,
        "team_id": EXPECTED_TEAM_ID,
        "entitlements_sha256": macos_codesign._entitlements_sha256({}),
    }


def test_staple_validation_failure_is_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    calls: list[list[str]] = []

    def fail(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        raise PackageVerificationError("stapler rejected ticket")

    monkeypatch.setattr(macos_codesign, "_run_text", fail)
    with pytest.raises(PackageVerificationError, match="stapler rejected"):
        macos_codesign.validate_staple(app)
    assert calls == [["/usr/bin/stapler", "validate", "-v", str(app)]]


def test_gatekeeper_accepts_real_notarized_output_without_optional_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)

    def accepted(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            str(app),
        ]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="accepted\nsource=Notarized Developer ID\n",
        )

    monkeypatch.setattr(macos_codesign, "_run_text", accepted)
    macos_codesign.assess_gatekeeper(app)

    def wrong_source(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="accepted\nsource=Developer ID\n",
            stderr=f"origin={EXPECTED_IDENTITY}\n",
        )

    monkeypatch.setattr(macos_codesign, "_run_text", wrong_source)
    with pytest.raises(PackageVerificationError, match="Gatekeeper did not accept"):
        macos_codesign.assess_gatekeeper(app)

    def deceptive_source(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="accepted\nsource=Notarized Developer ID extra\n",
            stderr="",
        )

    monkeypatch.setattr(macos_codesign, "_run_text", deceptive_source)
    with pytest.raises(PackageVerificationError, match="Gatekeeper did not accept"):
        macos_codesign.assess_gatekeeper(app)
