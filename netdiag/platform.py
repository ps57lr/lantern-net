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
