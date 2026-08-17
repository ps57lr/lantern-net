"""Frozen entry point for the unsigned Lantern family-beta development build.

The normal entry point launches only Lantern's existing local UI.  The second
entry point produced by the PyInstaller specification runs a deliberately
offline package self-test.  Packaging adds no updater, installer, persistence,
elevation, autorun, USB behavior, or remote service.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import socket
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

SELF_TEST_SCHEMA = "lantern.package-self-test.v1"
VERIFY_EXECUTABLE_NAME = "verify-lantern-package"


class OfflineSelfTestViolation(RuntimeError):
    """Raised when package verification attempts to use a network primitive."""


def _install_offline_audit_guard() -> None:
    """Deny socket activity before importing the application for self-test.

    The guard supplements process isolation in the verifier.  It is intentionally
    installed only for package verification; user-authorized diagnostic checks
    retain their existing behavior when Lantern is launched normally.
    """

    def audit(event: str, _arguments: tuple[object, ...]) -> None:
        if event == "socket.getaddrinfo" or event.startswith("socket."):
            raise OfflineSelfTestViolation("network access is disabled during package self-test")

    sys.addaudithook(audit)


def _release_metadata() -> tuple[str, bool]:
    """Return the packaged release channel and unsigned flag from bundle metadata."""

    if sys.platform == "darwin" and getattr(sys, "frozen", False):
        info_path = Path(sys.executable).resolve().parent.parent / "Info.plist"
        if info_path.is_file() and not info_path.is_symlink():
            try:
                with info_path.open("rb") as stream:
                    info = plistlib.load(stream)
            except (OSError, plistlib.InvalidFileException):
                info = {}
            channel = info.get("LanternReleaseChannel")
            unsigned = info.get("LanternUnsignedDevelopment")
            if channel in {"family-beta-development", "family-beta-signed"} and isinstance(
                unsigned, bool
            ):
                return channel, unsigned
    return "family-beta-development", True


def _prove_offline_guard() -> bool:
    """Prove that even creating a socket is denied during the self-test."""

    try:
        socket.socket()
    except OfflineSelfTestViolation:
        return True
    raise OfflineSelfTestViolation("the package self-test network guard was not enforced")


def _self_test_payload() -> dict[str, object]:
    """Return a bounded, identifier-free description of packaged contracts."""

    from importlib.resources import files

    from netdiag import __version__
    from netdiag.presentation import SCHEMA_VERSION
    from netdiag.ui.assets import verify_asset_manifest
    from netdiag.ui.viewmodel import UI_SCHEMA

    assets = verify_asset_manifest()
    schema_bytes = files("netdiag.schemas").joinpath("report-1.1.schema.json").read_bytes()
    schema = json.loads(schema_bytes)
    if schema.get("properties", {}).get("schema_version", {}).get("const") != SCHEMA_VERSION:
        raise RuntimeError("the packaged report schema does not match the runtime contract")

    release_channel, unsigned_development = _release_metadata()
    return {
        "schema": SELF_TEST_SCHEMA,
        "product": "Lantern",
        "release_channel": release_channel,
        "unsigned_development": unsigned_development,
        "frozen": bool(getattr(sys, "frozen", False)),
        "version": __version__,
        "contracts": {
            "report_schema": SCHEMA_VERSION,
            "report_schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
            "ui_schema": UI_SCHEMA,
            "ui_assets": [
                {
                    "filename": asset.spec.filename,
                    "size": len(asset.body),
                    "sha256": hashlib.sha256(asset.body).hexdigest(),
                }
                for asset in assets
            ],
        },
        "checks": {
            "network_audit_guard": _prove_offline_guard(),
            "report_schema": True,
            "ui_asset_manifest": True,
        },
    }


def package_self_test() -> int:
    """Run the package-only offline verification command."""

    _install_offline_audit_guard()
    try:
        payload = _self_test_payload()
    except Exception:  # noqa: BLE001 - package verifier emits no local error details.
        print("Lantern package self-test failed.", file=sys.stderr)
        return 1
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _is_verifier_executable() -> bool:
    executable = os.path.basename(sys.executable).lower()
    return executable == VERIFY_EXECUTABLE_NAME or executable == f"{VERIFY_EXECUTABLE_NAME}.exe"


def _show_start_failure() -> None:
    """Show one fixed local error when a windowed launch cannot reach the UI."""

    message = (
        "Lantern could not start its private local window. "
        "No diagnostic was started. Close Lantern and ask the person who gave you this build for help."
    )
    if sys.platform == "darwin" and os.path.isfile("/usr/bin/osascript"):
        command = [
            "/usr/bin/osascript",
            "-e",
            (
                'display dialog "Lantern could not start its private local window. '
                "No diagnostic was started. Close Lantern and ask the person who gave you "
                'this build for help." with title "Lantern did not start" '
                'buttons {"OK"} default button "OK" with icon caution'
            ),
        ]
    elif sys.platform.startswith("linux") and os.path.isfile("/usr/bin/zenity"):
        command = [
            "/usr/bin/zenity",
            "--error",
            "--title=Lantern did not start",
            f"--text={message}",
        ]
    elif sys.platform.startswith("linux") and os.path.isfile("/usr/bin/kdialog"):
        command = ["/usr/bin/kdialog", "--title", "Lantern did not start", "--error", message]
    else:
        print(message, file=sys.stderr)
        return
    try:
        subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except Exception:  # noqa: BLE001 - failure path must never expose local details.
        print(message, file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the frozen family launcher or its offline verification peer."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if _is_verifier_executable() or arguments == ["--package-self-test"]:
        return package_self_test()
    if arguments:
        print(
            "Lantern's family-beta launcher does not accept command-line options.", file=sys.stderr
        )
        return 64

    try:
        from netdiag.cli import main as netdiag_main

        result = netdiag_main(["ui"])
    except Exception:  # noqa: BLE001 - normalize all startup failures for a family user.
        result = 1
    if result != 0:
        _show_start_failure()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
