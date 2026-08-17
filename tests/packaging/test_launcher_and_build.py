from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import package_family_beta
import pytest
from package_family_beta import (
    BUILD_PACKAGES,
    DARWIN_BUILD_PACKAGES,
    ROOT,
    SYSTEM_GIT,
    _bundle_versions,
    _notices,
    _publish_outputs,
    _publish_verified_outputs,
    _run_git,
    _run_pyinstaller,
    _target_identity,
    _validate_build_environment,
)
from package_support import PackageVerificationError

import netdiag.cli


def _load_launcher():
    path = ROOT / "packaging" / "lantern_family_beta.py"
    spec = importlib.util.spec_from_file_location("lantern_packaged_launcher_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bundle_versions_map_pep440_development_version_to_numeric_values() -> None:
    assert _bundle_versions("0.3.0.dev4") == ("0.3.0", "4")


def test_macos_packaging_is_arm64_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_family_beta.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(package_family_beta.platform, "machine", lambda: "x86_64")

    with pytest.raises(PackageVerificationError, match="macOS arm64"):
        _target_identity()


def test_isolated_spec_uses_only_explicit_reviewed_package_data() -> None:
    spec = (ROOT / "packaging" / "lantern-family-beta.spec").read_text(encoding="utf-8")
    assert "collect_data_files" not in spec
    assert 'if target_arch != "arm64":' in spec
    for filename in (
        "report-1.1.schema.json",
        "index.html",
        "styles.css",
        "app.js",
        "icons.svg",
    ):
        assert spec.count(f'"{filename}"') == 1


def test_launcher_calls_only_existing_ui_command(monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = _load_launcher()
    calls: list[list[str]] = []
    monkeypatch.setattr(netdiag.cli, "main", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(launcher, "_show_start_failure", lambda: pytest.fail("unexpected dialog"))

    assert launcher.main([]) == 0
    assert calls == [["ui"]]


def test_launcher_normalizes_start_failure_and_shows_fixed_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = _load_launcher()
    shown: list[bool] = []

    def fail(_argv: list[str]) -> int:
        raise RuntimeError("private local failure detail")

    monkeypatch.setattr(netdiag.cli, "main", fail)
    monkeypatch.setattr(launcher, "_show_start_failure", lambda: shown.append(True))
    assert launcher.main([]) == 1
    assert shown == [True]


def test_macos_failure_dialog_is_fixed_and_does_not_use_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = _load_launcher()
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher.os.path, "isfile", lambda path: path == "/usr/bin/osascript")
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)),
    )

    launcher._show_start_failure()
    assert calls[0][0][0] == "/usr/bin/osascript"
    assert calls[0][1]["timeout"] == 30
    assert "shell" not in calls[0][1]
    assert "No diagnostic was started" in calls[0][0][2]


def test_source_self_test_is_offline_bounded_and_writes_no_profile_files(tmp_path: Path) -> None:
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    launcher = ROOT / "packaging" / "lantern_family_beta.py"
    environment = {
        "HOME": str(home),
        "TMPDIR": str(tmp_path),
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(ROOT),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C",
        "LC_ALL": "C",
    }
    completed = subprocess.run(
        [sys.executable, str(launcher), "--package-self-test"],
        cwd=work,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    assert payload["checks"] == {
        "network_audit_guard": True,
        "report_schema": True,
        "ui_asset_manifest": True,
    }
    assert payload["frozen"] is False
    assert payload["unsigned_development"] is True
    assert not list(home.rglob("*"))
    assert not list(work.rglob("*"))


def test_build_help_works_from_unrelated_directory(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "package_family_beta.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert "unsigned" in completed.stdout.lower()


def test_notices_do_not_overstate_unsigned_artifact_trust() -> None:
    start, warning = _notices(version="0.3.0.dev3", commit="a" * 40, dirty=False)
    combined = f"{start}\n{warning}"
    assert "local" in combined.lower()
    assert "UNSIGNED DEVELOPMENT BUILD" in combined
    assert "not been Developer ID signed, notarized" in combined
    assert "Checksums detect changed bytes; they do not establish" in combined
    assert "disable Gatekeeper" in combined
    assert "automatic software download/update mechanism" in combined
    assert "explicit redacted JSON" in combined
    assert "no updater, installer" not in combined


def test_publication_never_replaces_existing_output_or_creates_another_destination(
    tmp_path: Path,
) -> None:
    staged = tmp_path / "staged"
    artifact = staged / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "file").write_text("new artifact", encoding="utf-8")
    archive = staged / "artifact.zip"
    archive.write_bytes(b"new archive")
    checksum = staged / "artifact.zip.sha256"
    checksum.write_text("new checksum", encoding="ascii")

    output = tmp_path / "output"
    output.mkdir()
    destination = output / "artifact"
    archive_destination = output / "artifact.zip"
    checksum_destination = output / "artifact.zip.sha256"
    archive_destination.write_bytes(b"existing archive")

    with pytest.raises(PackageVerificationError, match="refusing to replace"):
        _publish_outputs(
            artifact,
            archive,
            checksum,
            destination,
            archive_destination,
            checksum_destination,
        )
    assert not destination.exists()
    assert archive_destination.read_bytes() == b"existing archive"
    assert not checksum_destination.exists()


def test_publication_preserves_symlinks_and_refuses_existing_artifact(tmp_path: Path) -> None:
    staged = tmp_path / "staged"
    artifact = staged / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "file").write_text("payload", encoding="utf-8")
    (artifact / "link").symlink_to("file")
    archive = staged / "artifact.zip"
    archive.write_bytes(b"archive")
    checksum = staged / "artifact.zip.sha256"
    checksum.write_text("checksum", encoding="ascii")
    output = tmp_path / "output"
    output.mkdir()
    destination = output / "artifact"
    archive_destination = output / "artifact.zip"
    checksum_destination = output / "artifact.zip.sha256"

    _publish_outputs(
        artifact,
        archive,
        checksum,
        destination,
        archive_destination,
        checksum_destination,
    )
    assert (destination / "link").is_symlink()
    assert (destination / "link").read_text(encoding="utf-8") == "payload"

    with pytest.raises(PackageVerificationError, match="refusing to replace"):
        _publish_outputs(
            artifact,
            archive,
            checksum,
            destination,
            archive_destination,
            checksum_destination,
        )
    assert (destination / "file").read_text(encoding="utf-8") == "payload"


def test_failed_postpublication_verification_retains_only_reserved_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = tmp_path / "staged"
    artifact = staged / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "file").write_text("payload", encoding="utf-8")
    archive = staged / "artifact.zip"
    archive.write_bytes(b"archive")
    checksum = staged / "artifact.zip.sha256"
    checksum.write_text("checksum", encoding="ascii")
    output = tmp_path / "output"
    output.mkdir()
    unrelated = output / "keep-me"
    unrelated.write_text("unrelated", encoding="utf-8")
    destinations = (
        output / "artifact",
        output / "artifact.zip",
        output / "artifact.zip.sha256",
    )

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic postpublication failure")

    monkeypatch.setattr(package_family_beta, "_verify_published_outputs", fail_verification)
    with pytest.raises(PackageVerificationError, match="retained for safe manual review"):
        _publish_verified_outputs(
            artifact,
            archive,
            checksum,
            *destinations,
            dirty=True,
        )
    assert (destinations[0] / "file").read_text(encoding="utf-8") == "payload"
    assert destinations[1].read_bytes() == b"archive"
    assert destinations[2].read_text(encoding="ascii") == "checksum"
    assert unrelated.read_text(encoding="utf-8") == "unrelated"


def test_isolated_python_ignores_fake_pyinstaller_on_pythonpath(tmp_path: Path) -> None:
    fake_root = tmp_path / "fake-pythonpath"
    fake_package = fake_root / "PyInstaller"
    fake_package.mkdir(parents=True)
    (fake_package / "__init__.py").write_text("ORIGIN = 'untrusted-pythonpath'\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(fake_root)
    probe = "import importlib.util; s=importlib.util.find_spec('PyInstaller'); print(s.origin if s else '')"

    ambient = subprocess.run(
        [sys.executable, "-c", probe],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    isolated = subprocess.run(
        [sys.executable, "-I", "-c", probe],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert str(fake_package) in ambient.stdout
    assert str(fake_package) not in isolated.stdout


def test_pyinstaller_launch_is_isolated_and_strips_python_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    for variable in (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "CC",
        "CFLAGS",
    ):
        monkeypatch.setenv(variable, f"untrusted-{variable.lower()}")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(package_family_beta.subprocess, "run", fake_run)
    dist = _run_pyinstaller(
        tmp_path,
        version="0.3.0.dev4",
        source_epoch=1_700_000_000,
        os_name="linux",
        architecture="x86_64",
        builder_runtime=None,
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[:5] == [sys.executable, "-I", "-B", "-m", "PyInstaller"]
    assert command[-1] == str(ROOT / "packaging" / "lantern-family-beta.spec")
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert not {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "CC",
        "CFLAGS",
    }.intersection(environment)
    expected_environment = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "PYINSTALLER_CONFIG_DIR",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "SOURCE_DATE_EPOCH",
        "LANG",
        "LC_ALL",
        "LANTERN_BUILD_VERSION",
        "LANTERN_BUNDLE_SHORT_VERSION",
        "LANTERN_BUNDLE_BUILD_VERSION",
    }
    assert set(environment) == expected_environment
    assert environment["PATH"] == "/usr/bin:/bin"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["SOURCE_DATE_EPOCH"] == "1700000000"
    assert environment["LANTERN_BUILD_VERSION"] == "0.3.0.dev4"
    assert environment["LANTERN_BUNDLE_SHORT_VERSION"] == "0.3.0"
    assert environment["LANTERN_BUNDLE_BUILD_VERSION"] == "4"
    assert captured["cwd"] == ROOT
    assert captured["check"] is True
    assert dist == tmp_path / "pyinstaller-dist"


def test_git_path_shim_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shim = tmp_path / "git"
    shim.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert _run_git("--version").startswith("git version")


def test_git_launch_uses_reviewed_binary_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="result\n", stderr="")

    monkeypatch.setattr(package_family_beta.subprocess, "run", fake_run)
    assert _run_git("rev-parse", "HEAD") == "result"
    assert captured["command"] == [str(SYSTEM_GIT), "rev-parse", "HEAD"]
    assert captured["env"] == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert captured["cwd"] == ROOT
    assert captured["check"] is True


def _locked_version(distribution: str) -> str:
    if distribution in BUILD_PACKAGES:
        return BUILD_PACKAGES[distribution]
    return DARWIN_BUILD_PACKAGES[distribution]


def test_darwin_build_requires_macholib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_macholib(distribution: str) -> str:
        if distribution == "macholib":
            raise package_family_beta.importlib.metadata.PackageNotFoundError(distribution)
        return _locked_version(distribution)

    monkeypatch.setattr(package_family_beta.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(package_family_beta.importlib.metadata, "version", missing_macholib)
    with pytest.raises(PackageVerificationError, match="macOS packaging tools are incomplete"):
        _validate_build_environment()


def test_darwin_build_rejects_wrong_macholib_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wrong_macholib(distribution: str) -> str:
        return "0.0.0" if distribution == "macholib" else _locked_version(distribution)

    monkeypatch.setattr(package_family_beta.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(package_family_beta.importlib.metadata, "version", wrong_macholib)
    with pytest.raises(PackageVerificationError, match="macholib must be exactly 1.16.4"):
        _validate_build_environment()


def test_darwin_build_accepts_exact_macholib_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[str] = []

    def exact_versions(distribution: str) -> str:
        requested.append(distribution)
        return _locked_version(distribution)

    monkeypatch.setattr(package_family_beta.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(package_family_beta.importlib.metadata, "version", exact_versions)
    _validate_build_environment()
    assert requested.count("macholib") == 1


def test_linux_build_does_not_require_darwin_only_macholib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[str] = []

    def linux_versions(distribution: str) -> str:
        requested.append(distribution)
        if distribution == "macholib":
            raise AssertionError("Linux validation must not request macholib")
        return _locked_version(distribution)

    monkeypatch.setattr(package_family_beta.platform, "system", lambda: "Linux")
    monkeypatch.setattr(package_family_beta.importlib.metadata, "version", linux_versions)
    _validate_build_environment()
    assert "macholib" not in requested
