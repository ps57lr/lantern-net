"""Strict HTTPS request and route allowlist for the gated LAN responder."""

from __future__ import annotations

import hmac
import ipaddress
import json
from dataclasses import dataclass, field
from enum import Enum
from http.cookies import CookieError, SimpleCookie
from typing import Final

from netdiag.lan.pairing import (
    PAIRING_CODE_LENGTH,
    UNAMBIGUOUS_ALPHABET,
    validate_client_label,
)
from netdiag.lan.sessions import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    SessionAuthority,
    SessionView,
)

MAX_HEADER_COUNT: Final[int] = 32
MAX_HEADER_BYTES: Final[int] = 8192
MAX_REQUEST_BODY: Final[int] = 16 * 1024
MAX_RESPONSE_BODY: Final[int] = 1024 * 1024
MAX_JSON_DEPTH: Final[int] = 8
MAX_JSON_NODES: Final[int] = 128

SECURITY_RESPONSE_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("Cache-Control", "no-store"),
    (
        "Content-Security-Policy",
        (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'"
        ),
    ),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
)


class LanRoute(str, Enum):
    PAIR = "pair"
    SESSION = "session"
    NETWORK_SUMMARY = "network_summary"
    RUN_START = "run_start"
    RUN_STATUS = "run_status"
    REPORT_EXPORT = "report_export"
    SESSION_END = "session_end"


@dataclass(frozen=True, slots=True)
class RouteSpec:
    route: LanRoute
    method: str
    path: str
    capability: str | None
    mutation: bool
    session_required: bool
    response_limit: int


ROUTES: Final[tuple[RouteSpec, ...]] = (
    RouteSpec(LanRoute.PAIR, "POST", "/api/v1/pair", None, True, False, 4096),
    RouteSpec(LanRoute.SESSION, "GET", "/api/v1/session", "network.read", False, True, 8192),
    RouteSpec(
        LanRoute.NETWORK_SUMMARY,
        "GET",
        "/api/v1/network/summary",
        "network.read",
        False,
        True,
        MAX_RESPONSE_BODY,
    ),
    RouteSpec(
        LanRoute.RUN_START,
        "POST",
        "/api/v1/run",
        None,
        True,
        True,
        8192,
    ),
    RouteSpec(LanRoute.RUN_STATUS, "GET", "/api/v1/run", "network.read", False, True, 65536),
    RouteSpec(
        LanRoute.REPORT_EXPORT,
        "POST",
        "/api/v1/report/export",
        "report.export.redacted",
        True,
        True,
        MAX_RESPONSE_BODY,
    ),
    RouteSpec(
        LanRoute.SESSION_END,
        "POST",
        "/api/v1/session/end",
        "session.end",
        True,
        True,
        4096,
    ),
)

_ROUTE_LOOKUP: Final[dict[tuple[str, str], RouteSpec]] = {
    (spec.method, spec.path): spec for spec in ROUTES
}


class RequestRejected(PermissionError):
    """Stable, low-detail request rejection safe for an HTTPS response."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class RequestEnvelope:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    source_address: str
    is_tls: bool


@dataclass(frozen=True, slots=True)
class AuthorizedRequest:
    route: LanRoute
    payload: dict[str, object] = field(repr=False)
    session: SessionView | None = None
    response_limit: int = 0


class LanApiGuard:
    """Validate transport metadata, session proof, CSRF, and bounded JSON."""

    def __init__(
        self,
        *,
        interface_address: str,
        port: int,
        sessions: SessionAuthority,
        allowed_profiles: tuple[str, ...],
    ) -> None:
        address = ipaddress.ip_address(interface_address)
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if address.version != 4 or not any(address in network for network in private_networks):
            raise ValueError("API guard requires an exact RFC1918 IPv4 address")
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("API guard requires a non-privileged TCP port")
        if not allowed_profiles or any(
            profile not in {"network.passive", "network.path", "network.scoped-discovery"}
            for profile in allowed_profiles
        ):
            raise ValueError("API guard profiles must use the fixed network allowlist")
        self._host = f"{address}:{port}"
        self._origin = f"https://{self._host}"
        self._sessions = sessions
        self._allowed_profiles = frozenset(allowed_profiles)

    @property
    def exact_host(self) -> str:
        return self._host

    @property
    def exact_origin(self) -> str:
        return self._origin

    def authorize(self, request: RequestEnvelope) -> AuthorizedRequest:
        """Return typed route data or reject before application code runs."""
        if not request.is_tls:
            raise RequestRejected(426, "tls_required")
        if request.method.upper() != request.method or request.method not in {"GET", "POST"}:
            raise RequestRejected(405, "route_not_allowed")
        if "?" in request.path or "#" in request.path or not request.path.startswith("/"):
            raise RequestRejected(404, "route_not_found")
        headers = _validated_headers(request.headers)
        if not hmac.compare_digest(headers.get("host", ""), self._host):
            raise RequestRejected(421, "request_context_rejected")
        if not hmac.compare_digest(headers.get("origin", ""), self._origin):
            raise RequestRejected(403, "request_context_rejected")
        if "transfer-encoding" in headers:
            raise RequestRejected(400, "request_framing_rejected")
        spec = _ROUTE_LOOKUP.get((request.method, request.path))
        if spec is None:
            raise RequestRejected(404, "route_not_found")
        _validate_body_framing(headers, request.body, mutation=spec.mutation)
        payload = _parse_payload(request.body, route=spec.route)

        session: SessionView | None = None
        if spec.session_required:
            token = _session_cookie(headers.get("cookie"))
            try:
                if spec.mutation:
                    csrf = headers.get(CSRF_HEADER_NAME.lower(), "")
                    session = self._sessions.verify_csrf(
                        token,
                        csrf,
                        source_address=request.source_address,
                    )
                else:
                    session = self._sessions.authenticate(
                        token,
                        source_address=request.source_address,
                    )
            except (ValueError, PermissionError):
                session = None
            if session is None:
                raise RequestRejected(401, "authentication_required")
            capability = _required_capability(spec, payload)
            if capability is not None and capability not in session.capabilities:
                raise RequestRejected(403, "capability_denied")
        elif "cookie" in headers:
            # Pairing must not inherit or fixate an existing session cookie.
            raise RequestRejected(400, "request_context_rejected")

        if spec.route is LanRoute.RUN_START:
            profile = payload["profile_id"]
            if profile not in self._allowed_profiles:
                raise RequestRejected(403, "capability_denied")
        return AuthorizedRequest(spec.route, payload, session, spec.response_limit)

    @staticmethod
    def response_headers() -> tuple[tuple[str, str], ...]:
        """Security headers intentionally contain no CORS allowance."""
        return SECURITY_RESPONSE_HEADERS


def _validated_headers(raw_headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if len(raw_headers) > MAX_HEADER_COUNT:
        raise RequestRejected(431, "request_headers_rejected")
    result: dict[str, str] = {}
    total = 0
    for raw_name, value in raw_headers:
        if not isinstance(raw_name, str) or not isinstance(value, str):
            raise RequestRejected(400, "request_headers_rejected")
        name = raw_name.lower()
        if not name or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in name
        ):
            raise RequestRejected(400, "request_headers_rejected")
        if name in result:
            raise RequestRejected(400, "request_headers_rejected")
        if "\r" in value or "\n" in value or "\x00" in value:
            raise RequestRejected(400, "request_headers_rejected")
        total += len(name.encode("ascii")) + len(value.encode("utf-8")) + 4
        if total > MAX_HEADER_BYTES:
            raise RequestRejected(431, "request_headers_rejected")
        result[name] = value
    return result


def _validate_body_framing(headers: dict[str, str], body: bytes, *, mutation: bool) -> None:
    if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BODY:
        raise RequestRejected(413, "request_body_rejected")
    content_length = headers.get("content-length")
    if mutation:
        if headers.get("content-type", "").lower() != "application/json":
            raise RequestRejected(415, "json_required")
        if content_length is None:
            raise RequestRejected(411, "content_length_required")
    elif body:
        raise RequestRejected(400, "request_body_rejected")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdigit():
            raise RequestRejected(400, "request_framing_rejected")
        if int(content_length) != len(body):
            raise RequestRejected(400, "request_framing_rejected")


def _parse_payload(body: bytes, *, route: LanRoute) -> dict[str, object]:
    if not body:
        if route in {LanRoute.SESSION, LanRoute.NETWORK_SUMMARY, LanRoute.RUN_STATUS}:
            return {}
        raise RequestRejected(400, "json_body_required")
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: _raise_invalid_json(),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise RequestRejected(400, "invalid_json") from None
    if not isinstance(value, dict):
        raise RequestRejected(400, "invalid_json_shape")
    _validate_json_bounds(value)
    expected_keys = {
        LanRoute.PAIR: {"code", "client_label"},
        LanRoute.RUN_START: {"profile_id"},
        LanRoute.REPORT_EXPORT: set(),
        LanRoute.SESSION_END: set(),
    }.get(route, set())
    if set(value) != expected_keys:
        raise RequestRejected(400, "invalid_json_shape")
    if route is LanRoute.PAIR:
        code = value["code"]
        label = value["client_label"]
        if (
            not isinstance(code, str)
            or len(code) != PAIRING_CODE_LENGTH
            or any(character not in UNAMBIGUOUS_ALPHABET for character in code)
        ):
            raise RequestRejected(400, "invalid_json_shape")
        try:
            value["client_label"] = validate_client_label(label)
        except (TypeError, ValueError):
            raise RequestRejected(400, "invalid_json_shape")
    if route is LanRoute.RUN_START and not isinstance(value["profile_id"], str):
        raise RequestRejected(400, "invalid_json_shape")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _raise_invalid_json() -> None:
    raise ValueError("non-finite JSON number")


def _validate_json_bounds(value: object) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise RequestRejected(400, "invalid_json_shape")
        if isinstance(item, dict):
            for key, child in item.items():
                if len(key) > 64:
                    raise RequestRejected(400, "invalid_json_shape")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and len(item) > 256:
            raise RequestRejected(400, "invalid_json_shape")

    visit(value, 0)


def _session_cookie(raw_cookie: str | None) -> str:
    if raw_cookie is None or len(raw_cookie) > 4096:
        return ""
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except CookieError:
        return ""
    if set(cookie) != {SESSION_COOKIE_NAME}:
        return ""
    return cookie[SESSION_COOKIE_NAME].value


def _required_capability(spec: RouteSpec, payload: dict[str, object]) -> str | None:
    if spec.route is LanRoute.RUN_START:
        return {
            "network.passive": "network.run.passive",
            "network.path": "network.run.path",
            "network.scoped-discovery": "network.run.scoped-discovery",
        }.get(payload.get("profile_id"))
    return spec.capability
