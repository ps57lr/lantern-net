# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder specification for unsigned family-beta artifacts."""

import os
import re
import sys

version = os.environ.get("LANTERN_BUILD_VERSION", "")
if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.(?:dev|post)[0-9]+)?", version) is None:
    raise SystemExit("LANTERN_BUILD_VERSION is missing or invalid")
bundle_short_version = os.environ.get("LANTERN_BUNDLE_SHORT_VERSION", "")
bundle_build_version = os.environ.get("LANTERN_BUNDLE_BUILD_VERSION", "")
if re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", bundle_short_version) is None:
    raise SystemExit("LANTERN_BUNDLE_SHORT_VERSION is missing or invalid")
if re.fullmatch(r"[1-9][0-9]*", bundle_build_version) is None:
    raise SystemExit("LANTERN_BUNDLE_BUILD_VERSION is missing or invalid")
target_arch = None
if sys.platform == "darwin":
    target_arch = os.environ.get("LANTERN_TARGET_ARCH", "")
    if target_arch != "arm64":
        raise SystemExit("LANTERN_TARGET_ARCH is missing or invalid")

block_cipher = None
project_root = os.path.dirname(os.path.abspath(SPECPATH))
entrypoint = os.path.join(project_root, "packaging", "lantern_family_beta.py")
data_files = [
    (
        os.path.join(project_root, "netdiag", "schemas", "report-1.1.schema.json"),
        "netdiag/schemas",
    ),
    (os.path.join(project_root, "netdiag", "ui", "static", "index.html"), "netdiag/ui/static"),
    (os.path.join(project_root, "netdiag", "ui", "static", "styles.css"), "netdiag/ui/static"),
    (os.path.join(project_root, "netdiag", "ui", "static", "app.js"), "netdiag/ui/static"),
    (os.path.join(project_root, "netdiag", "ui", "static", "icons.svg"), "netdiag/ui/static"),
]
for source, _destination in data_files:
    if os.path.islink(source) or not os.path.isfile(source):
        raise SystemExit("a required reviewed package-data file is unavailable")

analysis = Analysis(
    [entrypoint],
    pathex=[project_root],
    binaries=[],
    datas=data_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)

launcher = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="Start Lantern (Unsigned Dev)",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=target_arch,
    codesign_identity=None,
    entitlements_file=None,
)

verifier = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="verify-lantern-package",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=target_arch,
    codesign_identity=None,
    entitlements_file=None,
)

payload = COLLECT(
    launcher,
    verifier,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Start Lantern (Unsigned Dev)",
)

if sys.platform == "darwin":
    app = BUNDLE(
        payload,
        name="Start Lantern (Unsigned Dev).app",
        icon=None,
        bundle_identifier="net.lantern.family-beta-development",
        version=bundle_build_version,
        info_plist={
            "CFBundleDisplayName": "Start Lantern (Unsigned Dev)",
            "CFBundleName": "Lantern Family Beta Development",
            "CFBundleShortVersionString": bundle_short_version,
            "CFBundleVersion": bundle_build_version,
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
            "LanternReleaseChannel": "family-beta-development",
            "LanternUnsignedDevelopment": True,
        },
    )
