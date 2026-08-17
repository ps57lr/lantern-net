"""Platform detection and command execution helpers."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class OSInfo:
    system: str  # Darwin | Linux
    release: str
    machine: str

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
    """Re-exec via /usr/bin/python3 so PF_ROUTE sysctl returns neighbor MACs on macOS."""
    import os
    import sys

    if sys.platform != "darwin" or os.environ.get("NETDIAG_MACOS_REEXEC") == "1":
        return

    system_python = "/usr/bin/python3"
    if not os.path.isfile(system_python):
        return
    if os.path.realpath(sys.executable) == os.path.realpath(system_python):
        return

    env = os.environ.copy()
    env["NETDIAG_MACOS_REEXEC"] = "1"
    pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = pkg_root if not existing else f"{pkg_root}{os.pathsep}{existing}"
    args = [system_python, "-m", "netdiag", *(argv if argv is not None else sys.argv[1:])]
    os.execve(system_python, args, env)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    cmd: Sequence[str],
    *,
    timeout: float = 15.0,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def run_ok(cmd: Sequence[str], *, timeout: float = 15.0) -> str:
    try:
        cp = run(cmd, timeout=timeout)
        return (cp.stdout or "") + (cp.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return f"(command failed: {exc})"


def first_match(pattern: str, text: str, group: int = 1) -> str | None:
    m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return m.group(group).strip() if m else None
