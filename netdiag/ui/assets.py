"""Strict loader for Lantern's offline, packaged interface assets.

The HTTP layer is intentionally not implemented here.  A future loopback-only
server can use this module without accepting filesystem paths from a request.
Only exact routes in :data:`ASSET_MANIFEST` can be loaded, and every file is
verified against its expected length and SHA-256 digest before it is returned.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final


class AssetNotFound(LookupError):
    """Raised when a request does not match the fixed application manifest."""


class AssetIntegrityError(RuntimeError):
    """Raised when a packaged asset is missing, redirected, or modified."""


@dataclass(frozen=True, slots=True)
class AssetSpec:
    """Immutable metadata for one exact application route."""

    route: str
    filename: str
    content_type: str
    size: int
    sha256: str

    @property
    def etag(self) -> str:
        """Return a strong, quoted ETag derived from the packaged bytes."""
        return f'"sha256-{self.sha256}"'


@dataclass(frozen=True, slots=True)
class LoadedAsset:
    """Verified bytes and response metadata for an allowlisted asset."""

    spec: AssetSpec
    body: bytes

    @property
    def content_type(self) -> str:
        return self.spec.content_type

    @property
    def etag(self) -> str:
        return self.spec.etag


_STATIC_ROOT: Final[Path] = Path(__file__).with_name("static")

_INDEX = AssetSpec(
    route="/app/",
    filename="index.html",
    content_type="text/html; charset=utf-8",
    size=8_943,
    sha256="ad343cc5ef3146f89cf48132be60acaba483f7f1fd21612758e5f936bf905eff",
)

_SPECS: Final[tuple[AssetSpec, ...]] = (
    _INDEX,
    AssetSpec(
        route="/app/index.html",
        filename=_INDEX.filename,
        content_type=_INDEX.content_type,
        size=_INDEX.size,
        sha256=_INDEX.sha256,
    ),
    AssetSpec(
        route="/app/styles.css",
        filename="styles.css",
        content_type="text/css; charset=utf-8",
        size=24_370,
        sha256="d1c150fdc6a84287e0eda7724f33e78d505f40988944a0378472e28b58583abb",
    ),
    AssetSpec(
        route="/app/app.js",
        filename="app.js",
        content_type="text/javascript; charset=utf-8",
        size=53_427,
        sha256="6c96b29b3be29dfd9d12c766d32c1b8105b6b9b4ed0b5f0d0bc1a5ab01a78e89",
    ),
    AssetSpec(
        route="/app/icons.svg",
        filename="icons.svg",
        content_type="image/svg+xml",
        size=10_121,
        sha256="2c2b992b18bcfa5d3923c17ac05730e7f3a42850d0e632dd9057aad046b47e8d",
    ),
)

ASSET_MANIFEST: Final[Mapping[str, AssetSpec]] = MappingProxyType(
    {spec.route: spec for spec in _SPECS}
)

# These headers are safe defaults for both the loopback application and the
# future same-origin LAN presentation.  No remote fonts, images, scripts,
# styles, frames, workers, or network destinations are permitted.
STATIC_SECURITY_HEADERS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "connect-src 'self'; "
            "font-src 'none'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "worker-src 'none'"
        ),
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }
)


def asset_routes() -> tuple[str, ...]:
    """Return the fixed routes in deterministic order."""
    return tuple(ASSET_MANIFEST)


def load_asset(request_path: str) -> LoadedAsset:
    """Load and verify one exact request path from the fixed manifest.

    The caller must pass the parsed URL path, without a query or fragment.  No
    normalization, percent-decoding, directory index lookup, or extension
    guessing occurs here.  This prevents aliases from becoming filesystem
    traversal or content-sniffing paths later.
    """
    spec = _lookup_spec(request_path)
    root = _resolved_static_root()
    candidate = root / spec.filename

    try:
        if candidate.is_symlink():
            raise AssetIntegrityError(f"packaged asset is a symbolic link: {spec.route}")
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise AssetIntegrityError(f"packaged asset is unavailable: {spec.route}") from exc

    if resolved.parent != root or not resolved.is_file():
        raise AssetIntegrityError(f"packaged asset escaped its manifest root: {spec.route}")

    try:
        body = resolved.read_bytes()
    except OSError as exc:
        raise AssetIntegrityError(f"packaged asset could not be read: {spec.route}") from exc

    if len(body) != spec.size:
        raise AssetIntegrityError(f"packaged asset length mismatch: {spec.route}")

    digest = hashlib.sha256(body).hexdigest()
    if digest != spec.sha256:
        raise AssetIntegrityError(f"packaged asset digest mismatch: {spec.route}")

    return LoadedAsset(spec=spec, body=body)


def verify_asset_manifest() -> tuple[LoadedAsset, ...]:
    """Verify every unique packaged file and return deterministic results."""
    loaded: list[LoadedAsset] = []
    seen: set[str] = set()
    for route, spec in ASSET_MANIFEST.items():
        if spec.filename in seen:
            continue
        loaded.append(load_asset(route))
        seen.add(spec.filename)
    return tuple(loaded)


def _lookup_spec(request_path: str) -> AssetSpec:
    if not isinstance(request_path, str):
        raise AssetNotFound("asset route must be text")
    if not request_path or len(request_path) > 128:
        raise AssetNotFound("asset route is not allowlisted")
    if "\x00" in request_path or "\\" in request_path:
        raise AssetNotFound("asset route is not allowlisted")
    if "?" in request_path or "#" in request_path:
        raise AssetNotFound("asset route must not contain a query or fragment")
    if any(part in {".", ".."} for part in request_path.split("/")):
        raise AssetNotFound("asset route is not allowlisted")
    try:
        return ASSET_MANIFEST[request_path]
    except KeyError as exc:
        raise AssetNotFound("asset route is not allowlisted") from exc


def _resolved_static_root() -> Path:
    try:
        root = _STATIC_ROOT.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise AssetIntegrityError("packaged static-asset root is unavailable") from exc
    if not root.is_dir():
        raise AssetIntegrityError("packaged static-asset root is not a directory")
    return root
