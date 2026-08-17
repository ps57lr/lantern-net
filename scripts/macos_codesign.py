"""Fail-closed Developer ID signing helpers for Lantern macOS releases."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from package_support import PackageVerificationError, sha256_file

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENTITLEMENTS = ROOT / "packaging" / "macos" / "family-beta.entitlements.plist"
EXPECTED_IDENTITY = "Developer ID Application: Matthew Buttrick (HY2MDL9DND)"
EXPECTED_IDENTITY_SHA1 = "DFE4DF368133715BAAE725CC68CC7BA8A7246BEB"
EXPECTED_CERTIFICATE_SHA256 = "3ebaefae5bd5bdc0b0b00015d7fecea0ff0f60baae8279f4e7125d9ebdd598ed"
EXPECTED_TEAM_ID = "HY2MDL9DND"
SIGNED_APP_NAME = "Start Lantern.app"
SIGNED_BUNDLE_ID = "net.lantern.family-beta"
SIGNED_DISPLAY_NAME = "Start Lantern"
SIGNED_RELEASE_CHANNEL = "family-beta-signed"
EMBEDDED_PROVENANCE = "Contents/Resources/lantern-signing-provenance.json"

_CODESIGN = Path("/usr/bin/codesign")
_LIPO = Path("/usr/bin/lipo")
_SECURITY = Path("/usr/bin/security")
_SPCTL = Path("/usr/sbin/spctl")
_STAPLER = Path("/usr/bin/stapler")
_XCRUN = Path("/usr/bin/xcrun")
_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
_BUNDLE_SUFFIXES = {".app", ".appex", ".framework", ".xpc"}
_NO_ENTITLEMENT_SUFFIXES = {".dylib", ".so"}
_GET_TASK_ALLOW = "com.apple.security.get-task-allow"


@dataclass(frozen=True)
class SigningCertificate:
    common_name: str
    sha1: str
    sha256: str
    team_id: str


def signing_identity() -> str:
    """Return the pinned certificate fingerprint used by codesign."""

    return EXPECTED_IDENTITY_SHA1


def signing_team_id() -> str:
    return EXPECTED_TEAM_ID


def entitlements_path() -> Path:
    """Return the repository-owned, non-overridable entitlements input."""

    path = DEFAULT_ENTITLEMENTS
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise PackageVerificationError("reviewed entitlements file is unavailable")
    return path.resolve(strict=True)


def load_entitlement_allowlist(path: Path | None = None) -> dict[str, object]:
    """Load the exact entitlement values permitted on executable code."""

    source = entitlements_path() if path is None else path
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 64 * 1024:
        raise PackageVerificationError("reviewed entitlements file is unavailable")
    try:
        with source.open("rb") as stream:
            payload = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PackageVerificationError("reviewed entitlements file is invalid") from exc
    if type(payload) is not dict:
        raise PackageVerificationError("reviewed entitlements must be a dictionary")
    if _GET_TASK_ALLOW in payload:
        raise PackageVerificationError("get-task-allow is forbidden in a release")
    for key in payload:
        if type(key) is not str or not key.startswith("com.apple."):
            raise PackageVerificationError("reviewed entitlement name is invalid")
    return payload


def _run_text(
    command: list[str],
    *,
    timeout: int = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_SAFE_ENV,
        )
    except subprocess.TimeoutExpired as exc:
        raise PackageVerificationError("macOS signing command timed out") from exc
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise PackageVerificationError(f"macOS signing command failed: {detail}")
    return completed


def resolve_xcrun_tool(name: str) -> Path:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
        raise PackageVerificationError("Xcode tool name is invalid")
    completed = _run_text([str(_XCRUN), "--find", name], timeout=15)
    value = completed.stdout.strip()
    if not value or "\n" in value:
        raise PackageVerificationError(f"Xcode tool is unavailable: {name}")
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PackageVerificationError(f"Xcode tool is unavailable: {name}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PackageVerificationError(f"Xcode tool is unavailable: {name}")
    return resolved


def tool_record(path: Path) -> dict[str, str]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PackageVerificationError("release tool is unavailable")
    return {"path": str(resolved), "sha256": sha256_file(resolved)}


def signing_tool_records() -> dict[str, dict[str, str]]:
    return {
        "codesign": tool_record(_CODESIGN),
        "lipo": tool_record(_LIPO),
        "security": tool_record(_SECURITY),
        "vtool": tool_record(resolve_xcrun_tool("vtool")),
    }


def resolve_signing_certificate() -> SigningCertificate:
    """Resolve exactly the pinned private-key identity and hash its certificate."""

    completed = _run_text([str(_SECURITY), "find-identity", "-v", "-p", "codesigning"], timeout=30)
    matches = re.findall(
        r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$',
        completed.stdout,
        re.MULTILINE,
    )
    pinned = [item for item in matches if item[0] == EXPECTED_IDENTITY_SHA1]
    if pinned != [(EXPECTED_IDENTITY_SHA1, EXPECTED_IDENTITY)]:
        raise PackageVerificationError(
            "the pinned Developer ID private-key identity is unavailable"
        )
    if any(
        name == EXPECTED_IDENTITY and fingerprint != EXPECTED_IDENTITY_SHA1
        for fingerprint, name in matches
    ):
        raise PackageVerificationError(
            "Developer ID common name resolves to an unexpected certificate"
        )

    certificate = _run_text(
        [str(_SECURITY), "find-certificate", "-c", EXPECTED_IDENTITY, "-p"], timeout=30
    ).stdout
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        certificate,
        re.DOTALL,
    )
    if len(blocks) != 1:
        raise PackageVerificationError("the pinned Developer ID certificate is ambiguous")
    try:
        der = ssl.PEM_cert_to_DER_cert(blocks[0])
    except ValueError as exc:
        raise PackageVerificationError("the pinned Developer ID certificate is invalid") from exc
    der_bytes = der if isinstance(der, bytes) else bytes(der, "latin1")
    sha1 = hashlib.sha1(der_bytes).hexdigest().upper()
    sha256 = hashlib.sha256(der_bytes).hexdigest()
    if sha1 != EXPECTED_IDENTITY_SHA1:
        raise PackageVerificationError(
            "Developer ID certificate fingerprint does not match the pin"
        )
    if sha256 != EXPECTED_CERTIFICATE_SHA256:
        raise PackageVerificationError("Developer ID certificate SHA-256 does not match the pin")
    return SigningCertificate(
        common_name=EXPECTED_IDENTITY,
        sha1=sha1,
        sha256=sha256,
        team_id=EXPECTED_TEAM_ID,
    )


def is_macho(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open("rb") as stream:
            return stream.read(4) in _MACHO_MAGICS
    except OSError:
        return False


def macho_paths(app_path: Path) -> list[Path]:
    paths = [path for path in app_path.rglob("*") if is_macho(path)]
    return sorted(paths, key=lambda item: item.relative_to(app_path).as_posix())


def _nested_bundles(app_path: Path) -> list[Path]:
    bundles = [
        path
        for path in app_path.rglob("*")
        if path.is_dir() and not path.is_symlink() and path.suffix in _BUNDLE_SUFFIXES
    ]
    return sorted(bundles, key=lambda item: len(item.parts), reverse=True)


def _is_library_code(path: Path) -> bool:
    return path.suffix in _NO_ENTITLEMENT_SUFFIXES or any(
        part.endswith(".framework") for part in path.parts
    )


def _sign_one(path: Path, *, certificate: SigningCertificate, entitlements: Path | None) -> None:
    command = [
        str(_CODESIGN),
        "--force",
        "--sign",
        certificate.sha1,
        "--options",
        "runtime",
        "--timestamp",
    ]
    if entitlements is not None:
        command.extend(["--entitlements", str(entitlements)])
    command.append(str(path))
    _run_text(command)


def _deployment_version(value: object, *, label: str) -> tuple[int, ...]:
    if type(value) is not str or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", value) is None:
        raise PackageVerificationError(f"{label} is invalid")
    return tuple(int(part) for part in value.split("."))


def _app_deployment_target(app_path: Path) -> tuple[int, ...]:
    info_path = app_path / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file() or info_path.stat().st_size > 1024 * 1024:
        raise PackageVerificationError("macOS Info.plist is unavailable")
    try:
        with info_path.open("rb") as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise PackageVerificationError("macOS Info.plist is invalid") from exc
    if type(info) is not dict:
        raise PackageVerificationError("macOS Info.plist is invalid")
    target = _deployment_version(info.get("LSMinimumSystemVersion"), label="deployment target")
    if target != (11, 0):
        raise PackageVerificationError("macOS deployment target must be exactly 11.0")
    return target


def _macho_minimum_versions(path: Path, *, vtool: Path) -> list[tuple[int, ...]]:
    completed = _run_text([str(vtool), "-show-build", str(path)], timeout=30)
    platforms = re.findall(r"(?im)^\s*platform\s+(\S+)\s*$", completed.stdout)
    if not platforms or any(platform != "MACOS" for platform in platforms):
        raise PackageVerificationError(f"Mach-O platform is not macOS: {path.name}")
    versions = re.findall(r"(?im)^\s*minos\s+([0-9]+(?:\.[0-9]+){1,2})\s*$", completed.stdout)
    if not versions:
        versions = re.findall(r"(?im)^\s*version\s+([0-9]+(?:\.[0-9]+){1,2})\s*$", completed.stdout)
    if not versions:
        raise PackageVerificationError(f"Mach-O deployment target is unavailable: {path.name}")
    return [_deployment_version(value, label="Mach-O deployment target") for value in versions]


def _version_text(value: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in value)


def verify_macho_deployment_targets(
    app_path: Path,
) -> dict[Path, dict[str, list[str]]]:
    """Verify and return canonical architecture/minimum-OS evidence for every Mach-O."""

    target = _app_deployment_target(app_path)
    vtool = resolve_xcrun_tool("vtool")
    forbidden_material = [
        path
        for path in app_path.rglob("*")
        if not path.is_symlink() and path.is_file() and path.suffix in {".a", ".o"}
    ]
    if forbidden_material:
        relative = forbidden_material[0].relative_to(app_path).as_posix()
        raise PackageVerificationError(f"static or object-code material is forbidden: {relative}")
    machos = macho_paths(app_path)
    if not machos:
        raise PackageVerificationError("macOS application contains no Mach-O code")
    evidence: dict[Path, dict[str, list[str]]] = {}
    for path in machos:
        architectures = _run_text([str(_LIPO), "-archs", str(path)], timeout=30).stdout.split()
        if architectures != ["arm64"]:
            relative = path.relative_to(app_path).as_posix()
            raise PackageVerificationError(f"Mach-O is not exactly arm64: {relative}")
        minimum_versions = _macho_minimum_versions(path, vtool=vtool)
        for minimum in minimum_versions:
            width = max(len(minimum), len(target))
            minimum_padded = minimum + (0,) * (width - len(minimum))
            target_padded = target + (0,) * (width - len(target))
            if minimum_padded > target_padded:
                relative = path.relative_to(app_path).as_posix()
                raise PackageVerificationError(
                    f"Mach-O minimum OS exceeds Info.plist deployment target: {relative}"
                )
        evidence[path] = {
            "architectures": architectures,
            "minimum_macos": [_version_text(value) for value in minimum_versions],
        }
    return evidence


def rename_and_label_app(app_path: Path) -> Path:
    """Rename the unsigned app bundle and stamp signed release metadata."""

    if not app_path.is_dir() or app_path.is_symlink():
        raise PackageVerificationError("macOS application bundle is unavailable")
    destination = app_path.with_name(SIGNED_APP_NAME)
    if destination.exists() or destination.is_symlink():
        raise PackageVerificationError("signed application destination already exists")
    app_path.rename(destination)

    info_path = destination / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        raise PackageVerificationError("macOS Info.plist is unavailable")
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)
    if type(info) is not dict:
        raise PackageVerificationError("macOS Info.plist is invalid")
    info["CFBundleIdentifier"] = SIGNED_BUNDLE_ID
    info["CFBundleDisplayName"] = SIGNED_DISPLAY_NAME
    info["CFBundleName"] = "Lantern Family Beta"
    info["LanternReleaseChannel"] = SIGNED_RELEASE_CHANNEL
    info["LanternUnsignedDevelopment"] = False
    launcher = destination / "Contents" / "MacOS" / "Start Lantern (Unsigned Dev)"
    renamed_launcher = destination / "Contents" / "MacOS" / "Start Lantern"
    if not launcher.is_file() or launcher.is_symlink():
        raise PackageVerificationError("macOS launcher executable is unavailable")
    if renamed_launcher.exists() or renamed_launcher.is_symlink():
        raise PackageVerificationError("signed launcher destination already exists")
    launcher.rename(renamed_launcher)
    info["CFBundleExecutable"] = "Start Lantern"
    with info_path.open("wb") as stream:
        plistlib.dump(info, stream, sort_keys=True)
    return destination


def sign_application(
    app_path: Path,
    *,
    certificate: SigningCertificate | None = None,
) -> dict[str, object]:
    """Sign each Mach-O inside-out, never applying executable entitlements to libraries."""

    if app_path.is_symlink() or not app_path.is_dir() or app_path.suffix != ".app":
        raise PackageVerificationError("expected a macOS .app bundle")
    certificate = certificate or resolve_signing_certificate()
    if (
        certificate.sha1 != EXPECTED_IDENTITY_SHA1
        or certificate.sha256 != EXPECTED_CERTIFICATE_SHA256
        or certificate.team_id != EXPECTED_TEAM_ID
    ):
        raise PackageVerificationError("Developer ID identity does not match the release pin")
    entitlements = entitlements_path()
    load_entitlement_allowlist(entitlements)
    verify_macho_deployment_targets(app_path)

    machos = macho_paths(app_path)
    if not machos:
        raise PackageVerificationError("macOS application contains no Mach-O code")
    for candidate in sorted(machos, key=lambda item: len(item.parts), reverse=True):
        candidate_entitlements = None if _is_library_code(candidate) else entitlements
        _sign_one(candidate, certificate=certificate, entitlements=candidate_entitlements)
    for bundle in _nested_bundles(app_path):
        bundle_entitlements = None if bundle.suffix == ".framework" else entitlements
        _sign_one(bundle, certificate=certificate, entitlements=bundle_entitlements)
    _sign_one(app_path, certificate=certificate, entitlements=entitlements)
    return verify_application_signatures(
        app_path,
        certificate=certificate,
        allowed_entitlements=load_entitlement_allowlist(entitlements),
    )


def inspect_signature(path: Path) -> dict[str, str]:
    completed = _run_text([str(_CODESIGN), "-d", "-r-", "--verbose=4", str(path)])
    details = f"{completed.stdout}\n{completed.stderr}"
    authority_match = re.search(r"(?m)^Authority=(.+)$", details)
    team_match = re.search(r"(?m)^TeamIdentifier=([A-Z0-9]{10})$", details)
    return {
        "authority": authority_match.group(1).strip() if authority_match else "",
        "team_identifier": team_match.group(1) if team_match else "",
        "details": details,
    }


def _signed_entitlements(path: Path) -> dict[str, object]:
    completed = _run_text([str(_CODESIGN), "-d", "--entitlements", ":-", str(path)], check=False)
    output = f"{completed.stdout}\n{completed.stderr}"
    start = output.find("<?xml")
    end_marker = "</plist>"
    end = output.find(end_marker, start)
    if start < 0 or end < 0:
        lowered = output.lower()
        if completed.returncode == 0 or "no entitlements" in lowered:
            return {}
        raise PackageVerificationError(f"signed entitlements are unavailable: {path.name}")
    try:
        payload = plistlib.loads(output[start : end + len(end_marker)].encode("utf-8"))
    except plistlib.InvalidFileException as exc:
        raise PackageVerificationError("signed entitlements are invalid") from exc
    if type(payload) is not dict:
        raise PackageVerificationError("signed entitlements are invalid")
    return payload


def _extract_certificate_hashes(path: Path) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="lantern-codesign-cert-") as temporary:
        prefix = Path(temporary) / "certificate"
        _run_text(
            [str(_CODESIGN), "-d", f"--extract-certificates={prefix}", str(path)],
            timeout=30,
        )
        leaf = Path(f"{prefix}0")
        if leaf.is_symlink() or not leaf.is_file() or leaf.stat().st_size > 1024 * 1024:
            raise PackageVerificationError("signed leaf certificate is unavailable")
        content = leaf.read_bytes()
        return (
            hashlib.sha1(content).hexdigest().upper(),
            hashlib.sha256(content).hexdigest(),
        )


def _entitlements_sha256(value: dict[str, object]) -> str:
    encoded = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)
    return hashlib.sha256(encoded).hexdigest()


def _verify_one_signature(
    path: Path,
    *,
    certificate: SigningCertificate,
    allowed_entitlements: dict[str, object],
    library_code: bool,
) -> dict[str, object]:
    _run_text([str(_CODESIGN), "--verify", "--strict", "--verbose=4", str(path)])
    signature = inspect_signature(path)
    if signature["authority"] != certificate.common_name:
        raise PackageVerificationError(f"Developer ID authority does not match: {path.name}")
    if signature["team_identifier"] != certificate.team_id:
        raise PackageVerificationError(f"Developer ID team does not match: {path.name}")
    details = signature["details"]
    runtime = (
        re.search(
            r"(?m)^(?:CodeDirectory[^\r\n]*\s)?flags=0x[0-9A-Fa-f]+"
            r"\([^\r\n)]*\bruntime\b[^\r\n)]*\)",
            details,
        )
        is not None
    )
    if not runtime:
        raise PackageVerificationError(f"Hardened Runtime is missing: {path.name}")
    timestamp = re.search(r"(?m)^Timestamp=(.+)$", details)
    if timestamp is None or timestamp.group(1).strip().lower() in {"", "none"}:
        raise PackageVerificationError(f"secure signing timestamp is missing: {path.name}")
    timestamp_text = timestamp.group(1).strip()
    if len(timestamp_text) > 256 or "\x00" in timestamp_text:
        raise PackageVerificationError(f"secure signing timestamp is invalid: {path.name}")
    cdhash = re.search(r"(?m)^CDHash=([0-9A-Fa-f]{40})$", details)
    if cdhash is None:
        raise PackageVerificationError(f"code-directory hash is missing: {path.name}")
    designated = re.search(r"(?m)^designated => (.+)$", details)
    if designated is None:
        raise PackageVerificationError(f"designated requirement is missing: {path.name}")
    designated_requirement = designated.group(1).strip()
    if (
        not designated_requirement
        or len(designated_requirement) > 16 * 1024
        or "\x00" in designated_requirement
    ):
        raise PackageVerificationError(f"designated requirement is invalid: {path.name}")
    leaf_sha1, leaf_sha256 = _extract_certificate_hashes(path)
    if leaf_sha1 != certificate.sha1 or leaf_sha256 != certificate.sha256:
        raise PackageVerificationError(f"signing certificate does not match the pin: {path.name}")
    entitlements = _signed_entitlements(path)
    if _GET_TASK_ALLOW in entitlements:
        raise PackageVerificationError("get-task-allow is forbidden in a release")
    if library_code and entitlements:
        raise PackageVerificationError(f"library code carries executable entitlements: {path.name}")
    for key, value in entitlements.items():
        if key not in allowed_entitlements or allowed_entitlements[key] != value:
            raise PackageVerificationError(f"signed entitlement is not allowlisted: {key}")
    return {
        "cdhash": cdhash.group(1).lower(),
        "designated_requirement": designated_requirement,
        "runtime": runtime,
        "secure_timestamp": timestamp_text,
        "certificate_sha1": leaf_sha1,
        "certificate_sha256": leaf_sha256,
        "team_id": signature["team_identifier"],
        "entitlements_sha256": _entitlements_sha256(entitlements),
    }


def _bundle_type(path: Path, *, outer: bool) -> str:
    if outer or path.suffix == ".app":
        return "application-bundle"
    return {
        ".appex": "extension-bundle",
        ".framework": "framework-bundle",
        ".xpc": "xpc-bundle",
    }[path.suffix]


def _evidence_path(app_path: Path, path: Path) -> str:
    if path == app_path:
        return app_path.name
    return f"{app_path.name}/{path.relative_to(app_path).as_posix()}"


def signature_inventory_sha256(objects: list[dict[str, object]]) -> str:
    """Hash the canonical sorted signed-object evidence list."""

    encoded = json.dumps(objects, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_application_signatures(
    app_path: Path,
    *,
    certificate: SigningCertificate,
    allowed_entitlements: dict[str, object],
) -> dict[str, object]:
    """Verify the outer bundle and every nested Mach-O against the release pin."""

    if (
        certificate.sha1 != EXPECTED_IDENTITY_SHA1
        or certificate.sha256 != EXPECTED_CERTIFICATE_SHA256
        or certificate.team_id != EXPECTED_TEAM_ID
    ):
        raise PackageVerificationError("Developer ID verification pin is invalid")
    _run_text([str(_CODESIGN), "--verify", "--deep", "--strict", "--verbose=4", str(app_path)])
    machos = macho_paths(app_path)
    if not machos:
        raise PackageVerificationError("macOS application contains no Mach-O code")
    macho_evidence = verify_macho_deployment_targets(app_path)
    objects: list[dict[str, object]] = []
    for path in machos:
        signature = _verify_one_signature(
            path,
            certificate=certificate,
            allowed_entitlements=allowed_entitlements,
            library_code=_is_library_code(path),
        )
        objects.append(
            {
                "path": _evidence_path(app_path, path),
                "type": "mach-o",
                **macho_evidence[path],
                **signature,
            }
        )
    bundles = [*_nested_bundles(app_path), app_path]
    for bundle in bundles:
        signature = _verify_one_signature(
            bundle,
            certificate=certificate,
            allowed_entitlements=allowed_entitlements,
            library_code=bundle.suffix == ".framework",
        )
        objects.append(
            {
                "path": _evidence_path(app_path, bundle),
                "type": _bundle_type(bundle, outer=bundle == app_path),
                "architectures": [],
                "minimum_macos": [],
                **signature,
            }
        )
    objects.sort(key=lambda item: str(item["path"]))
    outer = next(
        (item for item in objects if item["path"] == app_path.name),
        None,
    )
    if outer is None:
        raise PackageVerificationError("outer application signature evidence is missing")
    return {
        "schema": "lantern.macos-signature-inventory.v1",
        "objects": objects,
        "object_count": len(objects),
        "macho_count": len(machos),
        "inventory_sha256": signature_inventory_sha256(objects),
        "outer_cdhash": outer["cdhash"],
        "team_id": certificate.team_id,
        "certificate_sha1": certificate.sha1,
        "certificate_sha256": certificate.sha256,
    }


def staple(path: Path) -> None:
    _run_text([str(_STAPLER), "staple", "-v", str(path)], timeout=180)


def validate_staple(path: Path) -> None:
    _run_text([str(_STAPLER), "validate", "-v", str(path)], timeout=60)


def assess_gatekeeper(path: Path) -> None:
    """Require Gatekeeper to recognize the stapled app as Notarized Developer ID."""

    completed = _run_text(
        [str(_SPCTL), "--assess", "--type", "execute", "--verbose=4", str(path)],
        timeout=60,
    )
    details = f"{completed.stdout}\n{completed.stderr}"
    if "source=Notarized Developer ID" not in details or EXPECTED_IDENTITY not in details:
        raise PackageVerificationError("Gatekeeper did not accept the notarized Developer ID app")
