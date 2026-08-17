import subprocess
import sys
from pathlib import Path

from netdiag import platform


def test_run_forces_stable_locale(monkeypatch):
    captured = {}

    def fake_run(*_args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(["probe"], 0, "ok", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    platform.run(["probe"])
    assert captured["env"]["LC_ALL"] == "C"
    assert captured["env"]["LANG"] == "C"


def test_run_ok_marks_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        platform,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["probe"], 7, "", "permission denied"
        ),
    )
    result = platform.run_ok(["probe"])
    assert result == "(command failed: exit 7: permission denied)"


def _prepare_macos_reexec(monkeypatch):
    monkeypatch.delenv("NETDIAG_MACOS_REEXEC", raising=False)
    monkeypatch.setenv("PYTHONHOME", "/tmp/untrusted-python-home")
    monkeypatch.setenv("PYTHONPATH", "/tmp/untrusted-python-path")
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "executable", "/opt/lantern/python")
    monkeypatch.setattr(platform.os.path, "isfile", lambda path: path == "/usr/bin/python3")


def test_macos_reexec_skips_incompatible_system_python(monkeypatch):
    _prepare_macos_reexec(monkeypatch)
    probes = []

    def fake_run(command, **kwargs):
        probes.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, "", "unsupported Python")

    monkeypatch.setattr(platform.subprocess, "run", fake_run)
    monkeypatch.setattr(
        platform.os,
        "execve",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not exec")),
    )

    platform.maybe_reexec_macos_system_python(["run"])

    assert len(probes) == 1
    assert probes[0][0][1:3] == ["-I", "-c"]
    assert "sys.version_info >= (3, 10)" in probes[0][0][3]
    assert "PYTHONHOME" not in probes[0][1]["env"]
    assert "PYTHONPATH" not in probes[0][1]["env"]


def test_macos_reexec_executes_compatible_importable_system_python(monkeypatch):
    _prepare_macos_reexec(monkeypatch)
    probes = []
    executed = {}

    def fake_run(command, **kwargs):
        probes.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_execve(executable, args, env):
        executed.update(executable=executable, args=args, env=env)

    monkeypatch.setattr(platform.subprocess, "run", fake_run)
    monkeypatch.setattr(platform.os, "execve", fake_execve)

    platform.maybe_reexec_macos_system_python(["run", "--json"])

    assert len(probes) == 2
    assert all(command[1:3] == ["-I", "-c"] for command, _kwargs in probes)
    assert probes[1][0][3] == platform._MACOS_IMPORT_PROBE
    assert Path(probes[1][0][4]).samefile(Path(platform.__file__).parent.parent)
    assert executed["executable"] == "/usr/bin/python3"
    assert executed["args"][:4] == [
        "/usr/bin/python3",
        "-I",
        "-c",
        platform._MACOS_LAUNCH_BOOTSTRAP,
    ]
    assert Path(executed["args"][4]).samefile(Path(platform.__file__).parent.parent)
    assert executed["args"][5:] == ["run", "--json"]
    assert executed["env"]["NETDIAG_MACOS_REEXEC"] == "1"
    assert "PYTHONHOME" not in executed["env"]
    assert "PYTHONPATH" not in executed["env"]


def test_macos_reexec_skips_when_package_is_unavailable(monkeypatch):
    _prepare_macos_reexec(monkeypatch)
    probes = []

    def fake_run(command, **kwargs):
        probes.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0 if len(probes) == 1 else 1, "", "")

    monkeypatch.setattr(platform.subprocess, "run", fake_run)
    monkeypatch.setattr(
        platform.os,
        "execve",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not exec")),
    )

    platform.maybe_reexec_macos_system_python(["lan"])

    assert len(probes) == 2
    assert probes[1][0][3] == platform._MACOS_IMPORT_PROBE


def test_isolated_import_probe_ignores_cwd_and_ambient_pythonpath(tmp_path):
    shadow_root = tmp_path / "shadow"
    shadow_package = shadow_root / "netdiag"
    shadow_package.mkdir(parents=True)
    (shadow_package / "__init__.py").write_text(
        "raise RuntimeError('cwd or PYTHONPATH shadow was imported')\n",
        encoding="utf-8",
    )
    package_root = str(Path(platform.__file__).resolve().parent.parent)
    env = platform.os.environ.copy()
    env["PYTHONPATH"] = str(shadow_root)

    completed = subprocess.run(
        [sys.executable, "-I", "-c", platform._MACOS_IMPORT_PROBE, package_root],
        cwd=shadow_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_isolated_launch_bootstrap_preserves_cli_arguments():
    package_root = str(Path(platform.__file__).resolve().parent.parent)

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            platform._MACOS_LAUNCH_BOOTSTRAP,
            package_root,
            "--version",
        ],
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("netdiag ")


def test_macos_reexec_recursion_guard_avoids_probe_and_exec(monkeypatch):
    monkeypatch.setenv("NETDIAG_MACOS_REEXEC", "1")
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        platform.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    monkeypatch.setattr(
        platform.os,
        "execve",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not exec")),
    )

    platform.maybe_reexec_macos_system_python(["run"])
