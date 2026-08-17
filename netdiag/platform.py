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
