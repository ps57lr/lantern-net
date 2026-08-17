from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import bootstrap_macos_release as bootstrap
import pytest


def _archive(tmp_path: Path, names: list[str]) -> Path:
    archive = tmp_path / "runtime.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        for name in names:
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            content = b"runtime"
            info.size = len(content)
            stream.addfile(info, io.BytesIO(content))
    return archive


def test_runtime_archive_rejects_traversal_before_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _archive(tmp_path, ["python/../../escape"])
    monkeypatch.setattr(bootstrap, "RUNTIME_ARCHIVE_SHA256", bootstrap.sha256_file(archive))

    with pytest.raises(bootstrap.BootstrapError, match="unsafe path"):
        bootstrap.extract_runtime(archive, tmp_path / "output")
    assert not (tmp_path / "escape").exists()


def test_runtime_archive_rejects_duplicate_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _archive(tmp_path, ["python/file", "python/file"])
    monkeypatch.setattr(bootstrap, "RUNTIME_ARCHIVE_SHA256", bootstrap.sha256_file(archive))

    with pytest.raises(bootstrap.BootstrapError, match="duplicate"):
        bootstrap.extract_runtime(archive, tmp_path / "output")


def test_runtime_archive_digest_is_checked_before_parsing(tmp_path: Path) -> None:
    archive = _archive(tmp_path, ["python/file"])
    with pytest.raises(bootstrap.BootstrapError, match="digest"):
        bootstrap.extract_runtime(archive, tmp_path / "output")


def test_wheelhouse_requires_exact_reviewed_set_and_hashes(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    for name in bootstrap.WHEELS:
        (wheelhouse / name).write_bytes(b"wrong wheel")

    with pytest.raises(bootstrap.BootstrapError, match="digest"):
        bootstrap.verify_wheelhouse(wheelhouse)

    (wheelhouse / "unexpected.whl").write_bytes(b"extra")
    with pytest.raises(bootstrap.BootstrapError, match="exact reviewed wheel set"):
        bootstrap.verify_wheelhouse(wheelhouse)


def test_bytecode_removal_includes_sourceless_startup_cache(tmp_path: Path) -> None:
    cache = tmp_path / "site-packages" / "__pycache__"
    cache.mkdir(parents=True)
    sourceless = cache / "sitecustomize.cpython-311.pyc"
    sourceless.write_bytes(b"executable attacker bytecode")
    ordinary = tmp_path / "site-packages" / "module.py"
    ordinary.write_text("SAFE = True\n", encoding="utf-8")

    bootstrap.remove_bytecode(tmp_path)

    assert not sourceless.exists()
    assert not cache.exists()
    assert ordinary.is_file()


def _build_environment_fixture(root: Path) -> tuple[Path, Path]:
    runtime = root / "runtime" / "python"
    executable = runtime / "bin" / "python3.11"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"reviewed python")
    environment = root / "build-environment"
    binary_directory = environment / "bin"
    binary_directory.mkdir(parents=True)
    (environment / "lib" / "python3.11" / "site-packages").mkdir(parents=True)
    (binary_directory / "python").symlink_to("python3.11")
    (binary_directory / "python3").symlink_to("python3.11")
    (binary_directory / "python3.11").symlink_to(executable)
    (environment / "pyvenv.cfg").write_text(
        f"home = {executable.parent}\n"
        "include-system-site-packages = false\n"
        "version = 3.11.15\n"
        f"executable = {executable}\n"
        f"command = {executable} -m venv {environment}\n",
        encoding="utf-8",
    )
    return environment, runtime


def test_build_environment_canonicalization_removes_path_bound_launchers(
    tmp_path: Path,
) -> None:
    digests: list[str] = []
    for name in ("first-long-staging-name", "second"):
        environment, runtime = _build_environment_fixture(tmp_path / name)
        binary_directory = environment / "bin"
        site_packages = environment / "lib" / "python3.11" / "site-packages"
        dist_info = site_packages / "example-1.0.dist-info"
        package = site_packages / "example"
        dist_info.mkdir(parents=True)
        package.mkdir()
        (binary_directory / "example-tool").write_text(
            f"#!{environment}/bin/python\n",
            encoding="utf-8",
        )
        (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
        (dist_info / "RECORD").write_text(
            "../../../bin/example-tool,sha256=" + "a" * 43 + ",123\n"
            "example/__init__.py,,\n"
            "example-1.0.dist-info/RECORD,,\n",
            encoding="utf-8",
        )

        normalized = bootstrap.canonicalize_build_environment(environment, runtime=runtime)
        digests.append(bootstrap._canonical_tree_sha256(normalized))

        assert {entry.name for entry in binary_directory.iterdir()} == {
            "python",
            "python3",
            "python3.11",
        }
        assert (dist_info / "RECORD").read_text(encoding="utf-8") == (
            "example/__init__.py,,\nexample-1.0.dist-info/RECORD,,\n"
        )

    assert digests[0] == digests[1]


def test_build_environment_canonicalization_rejects_malformed_record(
    tmp_path: Path,
) -> None:
    environment, runtime = _build_environment_fixture(tmp_path)
    record = environment / "lib/python3.11/site-packages/example-1.0.dist-info/RECORD"
    record.parent.mkdir(parents=True)
    record.write_text("../outside,,\n", encoding="utf-8")

    with pytest.raises(bootstrap.BootstrapError, match="record path"):
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)


@pytest.mark.parametrize(
    "unsafe_path",
    ("../../../bin/../../outside", "../../../bin/python"),
)
def test_build_environment_rejects_unsafe_external_record_path(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    environment, runtime = _build_environment_fixture(tmp_path)
    launcher = environment / "bin" / "tool"
    launcher.write_text("tool\n", encoding="utf-8")
    record = environment / "lib/python3.11/site-packages/example-1.0.dist-info/RECORD"
    record.parent.mkdir(parents=True)
    record.write_text(f"{unsafe_path},,\nexample-1.0.dist-info/RECORD,,\n", encoding="utf-8")

    with pytest.raises(bootstrap.BootstrapError, match="launcher path"):
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)


def test_build_environment_rejects_launcher_or_configuration_substitution(
    tmp_path: Path,
) -> None:
    environment, runtime = _build_environment_fixture(tmp_path / "launcher")
    (environment / "bin" / "python3.11").unlink()
    (environment / "bin" / "python3.11").symlink_to("/usr/bin/python3")

    with pytest.raises(bootstrap.BootstrapError, match="Python launcher"):
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)

    environment, runtime = _build_environment_fixture(tmp_path / "configuration")
    configuration = environment / "pyvenv.cfg"
    configuration.write_text(
        configuration.read_text(encoding="utf-8").replace(
            "include-system-site-packages = false",
            "include-system-site-packages = true",
        ),
        encoding="utf-8",
    )

    with pytest.raises(bootstrap.BootstrapError, match="Python configuration"):
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)


def test_build_environment_rejects_linked_metadata_without_mutation(tmp_path: Path) -> None:
    environment, runtime = _build_environment_fixture(tmp_path / "sealed")
    launcher = environment / "bin" / "tool"
    launcher.write_text("tool\n", encoding="utf-8")
    outside = tmp_path / "outside" / "example-1.0.dist-info"
    outside.mkdir(parents=True)
    record = outside / "RECORD"
    original = "../../../bin/tool,,\nexample-1.0.dist-info/RECORD,,\n"
    record.write_text(original, encoding="utf-8")
    site_packages = environment / "lib/python3.11/site-packages"
    (site_packages / "example-1.0.dist-info").symlink_to(outside, target_is_directory=True)

    with pytest.raises(bootstrap.BootstrapError, match="metadata directory"):
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)

    assert launcher.read_text(encoding="utf-8") == "tool\n"
    assert record.read_text(encoding="utf-8") == original


def test_build_environment_replaces_record_without_mutating_external_hardlink(
    tmp_path: Path,
) -> None:
    environment, runtime = _build_environment_fixture(tmp_path / "sealed")
    launcher = environment / "bin" / "tool"
    launcher.write_text("tool\n", encoding="utf-8")
    outside = tmp_path / "outside-record"
    original = "../../../bin/tool,,\nexample-1.0.dist-info/RECORD,,\n"
    outside.write_text(original, encoding="utf-8")
    dist_info = environment / "lib/python3.11/site-packages/example-1.0.dist-info"
    dist_info.mkdir()
    record = dist_info / "RECORD"
    os.link(outside, record)
    original_mode = record.stat().st_mode

    previous_umask = os.umask(0o077)
    try:
        bootstrap.canonicalize_build_environment(environment, runtime=runtime)
    finally:
        os.umask(previous_umask)

    assert outside.read_text(encoding="utf-8") == original
    assert record.read_text(encoding="utf-8") == "example-1.0.dist-info/RECORD,,\n"
    assert record.stat().st_mode == original_mode


def test_isolated_release_loader_can_import_sibling_modules() -> None:
    command = bootstrap._release_command(Path(sys.executable), Path("/tmp/output"), notarize=False)
    command[-2:] = ["--help"]

    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )

    assert completed.returncode == 0, completed.stderr
    assert "Build a fresh clean Lantern macOS family beta" in completed.stdout


def test_release_command_preserves_isolation_and_notary_choice(tmp_path: Path) -> None:
    builder = tmp_path / "python"
    output = tmp_path / "output"

    assert bootstrap._release_command(builder, output, notarize=True) == [
        str(builder),
        "-I",
        "-B",
        "-c",
        bootstrap.RELEASE_LOADER,
        str(bootstrap.ROOT),
        "--output-dir",
        str(output.resolve()),
        "--notarize",
    ]


def test_run_release_seals_inputs_rechecks_source_and_uses_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_archive = tmp_path / "runtime.tar.gz"
    runtime_archive.write_bytes(b"reviewed runtime")
    runtime_lock = tmp_path / "runtime.lock.json"
    runtime_lock.write_bytes(b"reviewed runtime lock")
    build_lock = tmp_path / "requirements-build.lock"
    build_lock.write_bytes(b"reviewed build lock")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "tool.whl"
    wheel.write_bytes(b"reviewed wheel")
    output = tmp_path / "output"
    output.mkdir()
    current_python = Path(sys.executable).resolve()

    monkeypatch.setattr(bootstrap, "RUNTIME_LOCK", runtime_lock)
    monkeypatch.setattr(bootstrap, "BUILD_LOCK", build_lock)
    monkeypatch.setattr(bootstrap, "SYSTEM_PYTHON_RUNTIME", current_python)
    monkeypatch.setattr(bootstrap.sys, "executable", str(current_python))
    monkeypatch.setattr(
        bootstrap, "SYSTEM_PYTHON_RUNTIME_SHA256", bootstrap.sha256_file(current_python)
    )
    monkeypatch.setattr(bootstrap, "RUNTIME_LOCK_SHA256", bootstrap.sha256_file(runtime_lock))
    monkeypatch.setattr(bootstrap, "BUILD_LOCK_SHA256", bootstrap.sha256_file(build_lock))
    monkeypatch.setattr(bootstrap, "RUNTIME_ARCHIVE_SHA256", bootstrap.sha256_file(runtime_archive))
    monkeypatch.setattr(bootstrap, "WHEELS", {wheel.name: bootstrap.sha256_file(wheel)})
    monkeypatch.setattr(bootstrap, "RUNTIME_TREE_SHA256", "a" * 64)
    monkeypatch.setattr(bootstrap, "BUILD_SITE_PACKAGES_SHA256", "b" * 64)

    source_checks: list[bool] = []
    monkeypatch.setattr(
        bootstrap,
        "require_clean_source",
        lambda: source_checks.append(True) or "c" * 40,
    )

    def extract(_archive: Path, destination: Path) -> Path:
        runtime = destination / "python"
        (runtime / "bin").mkdir(parents=True)
        (runtime / "lib").mkdir()
        (runtime / "bin" / "python3.11").write_bytes(b"python")
        (runtime / "lib" / "libpython3.11.dylib").write_bytes(b"library")
        return runtime

    monkeypatch.setattr(bootstrap, "extract_runtime", extract)
    monkeypatch.setattr(
        bootstrap, "PYTHON_EXECUTABLE_SHA256", hashlib.sha256(b"python").hexdigest()
    )
    monkeypatch.setattr(bootstrap, "LIBPYTHON_SHA256", hashlib.sha256(b"library").hexdigest())
    monkeypatch.setattr(
        bootstrap,
        "_canonical_tree_sha256",
        lambda path: "b" * 64 if path.name == "site-packages" else "a" * 64,
    )

    calls: list[tuple[list[str], dict[str, str]]] = []

    def run(command: list[str], *, timeout: int, environment: dict[str, str]) -> None:
        del timeout
        calls.append((command, environment))
        if "venv" in command:
            build_environment = Path(command[-1])
            binary_directory = build_environment / "bin"
            binary_directory.mkdir(parents=True)
            executable = Path(command[0]).resolve()
            (binary_directory / "python").symlink_to("python3.11")
            (binary_directory / "python3").symlink_to("python3.11")
            (binary_directory / "python3.11").symlink_to(executable)
            (build_environment / "pyvenv.cfg").write_text(
                f"home = {executable.parent}\n"
                "include-system-site-packages = false\n"
                "version = 3.11.15\n"
                f"executable = {executable}\n"
                f"command = {executable} -m venv {build_environment}\n",
                encoding="utf-8",
            )
        elif "pip" in command:
            site_packages = Path(command[0]).parents[1] / "lib" / "python3.11" / "site-packages"
            site_packages.mkdir(parents=True)
            package = site_packages / "tool"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            dist_info = site_packages / "tool-1.0.dist-info"
            dist_info.mkdir()
            (dist_info / "RECORD").write_text(
                "tool/__init__.py,,\ntool-1.0.dist-info/RECORD,,\n",
                encoding="utf-8",
            )

    monkeypatch.setattr(bootstrap, "_run", run)

    bootstrap.run_release(runtime_archive, wheelhouse, output, notarize=True)

    assert len(source_checks) == 2
    assert len(calls) == 3
    release_command, release_environment = calls[-1]
    assert release_command == bootstrap._release_command(
        Path(release_command[0]), output, notarize=True
    )
    assert release_environment == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "LANTERN_RELEASE_BOOTSTRAP": "lantern.macos-bootstrap.v1",
    }


def test_sealed_subprocess_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bootstrap.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["builder"], 1),
    )

    with pytest.raises(bootstrap.BootstrapError, match="subprocess failed"):
        bootstrap._run(["builder"], timeout=1, environment={})
