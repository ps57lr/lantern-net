"""Platform detection and command execution helpers."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from netdiag.core.values import validate_platform_identity

_MACOS_VERSION_PROBE = "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
_MACOS_IMPORT_PROBE = (
    "import importlib, os, sys; "
    "root = os.path.realpath(sys.argv[1]); "
    "sys.path.insert(0, root); "
    "importlib.import_module('netdiag.cli'); "
    "package = importlib.import_module('netdiag'); "
    "actual = os.path.realpath(os.path.dirname(package.__file__)); "
    "expected = os.path.realpath(os.path.join(root, 'netdiag')); "
    "raise SystemExit(0 if actual == expected else 1)"
)
_MACOS_LAUNCH_BOOTSTRAP = (
    "import importlib, os, runpy, sys; "
    "root = os.path.realpath(sys.argv.pop(1)); "
    "sys.path.insert(0, root); "
    "package = importlib.import_module('netdiag'); "
    "actual = os.path.realpath(os.path.dirname(package.__file__)); "
    "expected = os.path.realpath(os.path.join(root, 'netdiag')); "
    "(actual == expected) or sys.exit(1); "
    "runpy.run_module('netdiag.__main__', run_name='__main__', alter_sys=True)"
)


@dataclass(frozen=True)
class OSInfo:
    system: str  # Darwin | Linux
    release: str
    machine: str

    def __post_init__(self) -> None:
        validate_platform_identity(self.system, self.release, self.machine)

    @property
    def is_mac(self) -> bool:
        return self.system == "Darwin"

    @property
    def is_linux(self) -> bool:
        return self.system == "Linux"


def detect_os() -> OSInfo:
    u = platform.uname()
    return OSInfo(system=u.system, release=u.release, machine=u.machine)


def maybe_reexec_macos_system_python(argv: list[str] | None = None) -> None:
    """Re-exec through a compatible system Python for macOS PF_ROUTE access.

    The system interpreter is an optional capability boost, not a requirement for
    running the CLI.  In particular, recent macOS releases can still ship an Apple
    Python older than this package supports.  Probe both interpreter compatibility
    and the actual ``netdiag`` import before replacing the working process so a
    failed ARP enhancement cannot make the whole diagnostic unavailable.
    """
    import os
    import sys

    if sys.platform != "darwin" or os.environ.get("NETDIAG_MACOS_REEXEC") == "1":
        return

    system_python = "/usr/bin/python3"
    if not os.path.isfile(system_python):
        return
    if os.path.realpath(sys.executable) == os.path.realpath(system_python):
        return

    env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONHOME", "PYTHONPATH"}
    }
    env["NETDIAG_MACOS_REEXEC"] = "1"
    pkg_root = os.path.realpath(os.path.join(os.path.dirname(__file__), os.pardir))

    probes = (
        [system_python, "-I", "-c", _MACOS_VERSION_PROBE],
        [system_python, "-I", "-c", _MACOS_IMPORT_PROBE, pkg_root],
    )
    try:
        for command in probes:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                env=env,
            )
            if completed.returncode != 0:
                return
    except (subprocess.TimeoutExpired, OSError):
        return

    args = [
        system_python,
        "-I",
        "-c",
        _MACOS_LAUNCH_BOOTSTRAP,
        pkg_root,
        *(argv if argv is not None else sys.argv[1:]),
    ]
    os.execve(system_python, args, env)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    cmd: Sequence[str],
    *,
    timeout: float = 15.0,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    command_env["LC_ALL"] = "C"
    command_env["LANG"] = "C"
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=check,
        env=command_env,
    )


def run_ok(cmd: Sequence[str], *, timeout: float = 15.0) -> str:
    try:
        cp = run(cmd, timeout=timeout)
        if cp.returncode != 0:
            detail = (cp.stderr or cp.stdout or "no diagnostic output").strip()
            return f"(command failed: exit {cp.returncode}: {detail})"
        return (cp.stdout or "") + (cp.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return f"(command failed: {exc})"


def first_match(pattern: str, text: str, group: int = 1) -> str | None:
    m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return m.group(group).strip() if m else None
