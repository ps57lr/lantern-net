import subprocess

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
