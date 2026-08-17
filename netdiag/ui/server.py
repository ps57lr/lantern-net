"""Hardened loopback-only HTTP transport for Lantern's local interface.

The transport intentionally exposes only packaged static assets, health,
session bootstrap/revocation, and a read-only status provider.  It has no host
parameter, no LAN mode, no credential input, and no remediation route.

This backend is intentionally not wired to the CLI until the static client
implements and tests fragment exchange plus immediate browser-history cleanup.
"""

from __future__ import annotations

import hashlib
import json
import math
import socket
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final
from urllib.parse import urlsplit

from .assets import (
    STATIC_SECURITY_HEADERS,
    AssetIntegrityError,
    AssetNotFound,
    load_asset,
    verify_asset_manifest,
)
from .controller import JsonValue, ReadyStatusProvider, StatusProvider
from .security import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    LocalSessionSecurity,
)

_LOOPBACK_HOST: Final[str] = "127.0.0.1"
_MAX_REQUEST_BODY: Final[int] = 4096
_MAX_RESPONSE_BODY: Final[int] = 512 * 1024
_READ_TIMEOUT_SECONDS: Final[float] = 2.0
_SHUTDOWN_TIMEOUT_SECONDS: Final[float] = 3.0

_COMMON_HEADERS: Final[Mapping[str, str]] = {
    **STATIC_SECURITY_HEADERS,
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes
    content_type: str
    headers: tuple[tuple[str, str], ...] = ()


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _json_response(
    status: int,
    value: object,
    *,
    headers: tuple[tuple[str, str], ...] = (),
) -> _Response:
    return _Response(
        status=status,
        body=_json_bytes(value),
        content_type="application/json; charset=utf-8",
        headers=headers,
    )


def _error_response(
    status: int,
    code: str,
    message: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
) -> _Response:
    return _json_response(
        status,
        {"error": {"code": code, "message": message}},
        headers=headers,
    )


class LocalApplication:
    """Pure request policy shared by every local HTTP handler thread."""

    def __init__(
        self,
        *,
        expected_host: str,
        expected_origin: str,
        security: LocalSessionSecurity,
        status_provider: StatusProvider,
        on_launch_consumed: Callable[[], None] | None = None,
        max_request_body: int = _MAX_REQUEST_BODY,
        max_response_body: int = _MAX_RESPONSE_BODY,
    ) -> None:
        if not expected_host or not expected_origin:
            raise ValueError("local application origin is required")
        if max_request_body <= 0 or max_response_body <= 0:
            raise ValueError("body limits must be positive")
        self.expected_host = expected_host
        self.expected_origin = expected_origin
        self.security = security
        self.status_provider = status_provider
        self.on_launch_consumed = on_launch_consumed
        self.max_request_body = max_request_body
        self.max_response_body = max_response_body

    def dispatch(self, request: _LocalRequestHandler, *, head_only: bool = False) -> None:
        """Validate, route, and write exactly one normalized response."""
        try:
            response = self._dispatch(request)
        except (TimeoutError, BrokenPipeError, ConnectionResetError):
            request.close_connection = True
            return
        except Exception:  # noqa: BLE001 - trust boundary must normalize provider failures
            # The HTTP boundary never serializes exception text or tracebacks.
            response = _error_response(
                500,
                "internal_error",
                "The local application could not complete the request.",
            )
        request.write_response(response, head_only=head_only)

    def _dispatch(self, request: _LocalRequestHandler) -> _Response:
        boundary_error = self._validate_boundary(request)
        if boundary_error is not None:
            return boundary_error

        path = self._exact_path(request.path)
        if path is None:
            return _error_response(404, "route_not_found", "That local route does not exist.")

        method = request.command
        if method in {"GET", "HEAD"}:
            return self._get(request, path)
        if method == "POST":
            return self._post(request, path)
        return _error_response(
            405,
            "method_not_allowed",
            "That method is not available on the local application.",
            headers=(("Allow", "GET, HEAD, POST"),),
        )

    def _validate_boundary(self, request: _LocalRequestHandler) -> _Response | None:
        host_values = request.headers.get_all("Host", failobj=[])
        if len(host_values) != 1 or host_values[0] != self.expected_host:
            return _error_response(403, "invalid_host", "The request host is not permitted.")

        origin_values = request.headers.get_all("Origin", failobj=[])
        if len(origin_values) > 1:
            return _error_response(403, "invalid_origin", "The request origin is not permitted.")
        if origin_values and origin_values[0] != self.expected_origin:
            return _error_response(403, "invalid_origin", "The request origin is not permitted.")
        if request.command == "POST" and origin_values != [self.expected_origin]:
            return _error_response(403, "invalid_origin", "The request origin is not permitted.")
        return None

    @staticmethod
    def _exact_path(target: str) -> str | None:
        if not target or len(target) > 256 or "\x00" in target or "\\" in target:
            return None
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            return None
        if parsed.path != target:
            return None
        return parsed.path

    def _get(self, request: _LocalRequestHandler, path: str) -> _Response:
        if path.startswith("/app/"):
            try:
                asset = load_asset(path)
            except AssetNotFound:
                return _error_response(
                    404, "asset_not_found", "That application asset does not exist."
                )
            except AssetIntegrityError:
                return _error_response(
                    500,
                    "asset_integrity_error",
                    "A packaged application asset failed verification.",
                )
            return _Response(
                status=200,
                body=asset.body,
                content_type=asset.content_type,
                headers=(("ETag", asset.etag),),
            )

        if path == "/api/health":
            return _json_response(
                200,
                {"service": "lantern-local", "status": "ok", "transport": "loopback"},
            )

        if path == "/api/session":
            if request.command == "HEAD":
                return _error_response(
                    405,
                    "method_not_allowed",
                    "That method is not available for the session route.",
                    headers=(("Allow", "GET"),),
                )
            session_id = self._session_cookie(request)
            view = self.security.authenticate(session_id)
            if view is None:
                return self._unauthorized(clear_cookie=True)
            csrf = self.security.session_csrf(session_id)
            if csrf is None:
                return self._unauthorized(clear_cookie=True)
            return _json_response(
                200,
                {"csrf_token": csrf, "expires_in": view.expires_in},
            )

        if path == "/api/status":
            if self.security.authenticate(self._session_cookie(request)) is None:
                return self._unauthorized(clear_cookie=True)
            return self._status_response()

        return _error_response(404, "route_not_found", "That local route does not exist.")

    def _post(self, request: _LocalRequestHandler, path: str) -> _Response:
        if path == "/api/session/exchange":
            return self._exchange(request)
        if path == "/api/session/revoke":
            return self._revoke(request)
        return _error_response(
            405,
            "method_not_allowed",
            "That method is not available on the local application.",
            headers=(("Allow", "GET, HEAD"),),
        )

    def _exchange(self, request: _LocalRequestHandler) -> _Response:
        client_key = request.client_address[0]
        retry_after = self.security.retry_after(client_key)
        if retry_after:
            return _error_response(
                429,
                "exchange_rate_limited",
                "Too many launch attempts. Try again shortly.",
                headers=(("Retry-After", str(retry_after)),),
            )

        body, body_error = self._read_json_object(request)
        if body_error is not None:
            return body_error
        if set(body) != {"launch_token"}:
            return _error_response(400, "invalid_request", "The launch request is invalid.")

        result = self.security.exchange(body["launch_token"], client_key=client_key)
        if result is None:
            retry_after = self.security.retry_after(client_key)
            if retry_after:
                return _error_response(
                    429,
                    "exchange_rate_limited",
                    "Too many launch attempts. Try again shortly.",
                    headers=(("Retry-After", str(retry_after)),),
                )
            return _error_response(
                401,
                "launch_denied",
                "The launch link is invalid, expired, or already used.",
            )

        if self.on_launch_consumed is not None:
            self.on_launch_consumed()

        return _json_response(
            201,
            {"csrf_token": result.csrf_token, "expires_in": result.expires_in},
            headers=(("Set-Cookie", self._session_cookie_header(result.session_id)),),
        )

    def _revoke(self, request: _LocalRequestHandler) -> _Response:
        body, body_error = self._read_json_object(request)
        if body_error is not None:
            return body_error
        if body:
            return _error_response(400, "invalid_request", "The revoke request is invalid.")

        session_id = self._session_cookie(request)
        if self.security.authenticate(session_id) is None:
            return self._unauthorized(clear_cookie=True)

        csrf_values = request.headers.get_all(CSRF_HEADER_NAME, failobj=[])
        if len(csrf_values) != 1 or not self.security.verify_csrf(session_id, csrf_values[0]):
            return _error_response(403, "csrf_denied", "The request could not be verified.")

        self.security.revoke(session_id)
        return _json_response(
            200,
            {"revoked": True},
            headers=(("Set-Cookie", self._clear_cookie_header()),),
        )

    def _read_json_object(
        self, request: _LocalRequestHandler
    ) -> tuple[dict[str, object], _Response | None]:
        if request.headers.get_all("Transfer-Encoding", failobj=[]):
            return {}, _error_response(
                400,
                "unsupported_transfer_encoding",
                "Transfer encoding is not supported.",
            )

        lengths = request.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            return {}, _error_response(411, "length_required", "A request length is required.")
        try:
            length = int(lengths[0], 10)
        except (TypeError, ValueError):
            return {}, _error_response(400, "invalid_length", "The request length is invalid.")
        if length <= 0:
            return {}, _error_response(400, "invalid_body", "A JSON object is required.")
        if length > self.max_request_body:
            return {}, _error_response(413, "body_too_large", "The request body is too large.")

        content_types = request.headers.get_all("Content-Type", failobj=[])
        if len(content_types) != 1:
            return {}, _error_response(415, "json_required", "JSON content is required.")
        media_type = content_types[0].split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return {}, _error_response(415, "json_required", "JSON content is required.")

        try:
            raw = request.rfile.read(length)
        except (TimeoutError, OSError):
            return {}, _error_response(400, "invalid_body", "The request body is invalid.")
        if len(raw) != length:
            return {}, _error_response(400, "invalid_body", "The request body is invalid.")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}, _error_response(400, "invalid_json", "The request JSON is invalid.")
        if not isinstance(value, dict):
            return {}, _error_response(400, "invalid_request", "A JSON object is required.")
        return value, None

    def _status_response(self) -> _Response:
        try:
            snapshot: Mapping[str, JsonValue] = self.status_provider.snapshot()
            if not isinstance(snapshot, Mapping):
                raise TypeError("status snapshot must be a mapping")
            body = _json_bytes(snapshot)
            if len(body) > self.max_response_body:
                raise ValueError("status snapshot is too large")
            # json.dumps accepts NaN when nested custom float subclasses can
            # evade casual validation; explicitly reject all non-finite values.
            self._reject_non_finite(snapshot)
        except (TypeError, ValueError, OverflowError):
            return _error_response(
                503,
                "status_unavailable",
                "A safe status snapshot is not available.",
            )
        return _Response(200, body, "application/json; charset=utf-8")

    @classmethod
    def _reject_non_finite(cls, value: object) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        if isinstance(value, Mapping):
            if not all(isinstance(key, str) for key in value):
                raise TypeError("JSON object keys must be strings")
            for nested in value.values():
                cls._reject_non_finite(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                cls._reject_non_finite(nested)

    @staticmethod
    def _session_cookie(request: _LocalRequestHandler) -> str | None:
        cookie_headers = request.headers.get_all("Cookie", failobj=[])
        if len(cookie_headers) != 1:
            return None
        matches: list[str] = []
        for item in cookie_headers[0].split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == SESSION_COOKIE_NAME:
                matches.append(value)
        if len(matches) != 1:
            return None
        return matches[0]

    def _session_cookie_header(self, session_id: str) -> str:
        return (
            f"{SESSION_COOKIE_NAME}={session_id}; Path=/api/; "
            f"Max-Age={self.security.session_ttl}; HttpOnly; SameSite=Strict"
        )

    @staticmethod
    def _clear_cookie_header() -> str:
        return f"{SESSION_COOKIE_NAME}=; Path=/api/; Max-Age=0; HttpOnly; SameSite=Strict"

    def _unauthorized(self, *, clear_cookie: bool) -> _Response:
        headers: tuple[tuple[str, str], ...] = ()
        if clear_cookie:
            headers = (("Set-Cookie", self._clear_cookie_header()),)
        return _error_response(
            401,
            "session_required",
            "A valid local application session is required.",
            headers=headers,
        )


class _LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(
        self,
        server_address: tuple[str, int],
        application: LocalApplication | None,
        request_timeout: float,
    ) -> None:
        self.application = application
        self.request_timeout = request_timeout
        super().__init__(server_address, _LocalRequestHandler, bind_and_activate=True)

    def verify_request(self, request: socket.socket, client_address: tuple[str, int]) -> bool:
        return client_address[0] == _LOOPBACK_HOST


class _LocalRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LanternLocal"
    sys_version = ""

    @property
    def local_server(self) -> _LoopbackHTTPServer:
        server = self.server
        if not isinstance(server, _LoopbackHTTPServer):
            raise TypeError("unexpected server type")
        return server

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.local_server.request_timeout)

    def do_GET(self) -> None:
        self._dispatch(head_only=False)

    def do_HEAD(self) -> None:
        self._dispatch(head_only=True)

    def do_POST(self) -> None:
        self._dispatch(head_only=False)

    def do_PUT(self) -> None:
        self._dispatch(head_only=False)

    def do_PATCH(self) -> None:
        self._dispatch(head_only=False)

    def do_DELETE(self) -> None:
        self._dispatch(head_only=False)

    def do_OPTIONS(self) -> None:
        self._dispatch(head_only=False)

    def do_TRACE(self) -> None:
        self._dispatch(head_only=False)

    def do_CONNECT(self) -> None:
        self._dispatch(head_only=False)

    def handle_expect_100(self) -> bool:
        self.close_connection = True
        application = self.local_server.application
        if application is not None:
            boundary_error = application._validate_boundary(self)
            if boundary_error is not None:
                self.write_response(boundary_error, head_only=False)
                return False
        self.write_response(
            _error_response(417, "expectation_failed", "Request expectations are unsupported."),
            head_only=False,
        )
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Replace inherited HTML/parser errors with the hardened JSON envelope."""
        del message, explain
        self.close_connection = True
        application = self.local_server.application
        if application is not None and hasattr(self, "headers"):
            boundary_error = application._validate_boundary(self)
            if boundary_error is not None:
                self.write_response(boundary_error, head_only=self.command == "HEAD")
                return

        if code == 501:
            response = _error_response(
                405,
                "method_not_allowed",
                "That method is not available on the local application.",
                headers=(("Allow", "GET, HEAD, POST"),),
            )
        else:
            status = code if 400 <= code <= 599 else 400
            response = _error_response(
                status,
                "invalid_http_request",
                "The HTTP request is invalid.",
            )
        self.write_response(response, head_only=self.command == "HEAD")

    def _dispatch(self, *, head_only: bool) -> None:
        self.close_connection = True
        application = self.local_server.application
        if application is None:
            self.write_response(
                _error_response(503, "starting", "The local application is starting."),
                head_only=head_only,
            )
            return
        application.dispatch(self, head_only=head_only)

    def write_response(self, response: _Response, *, head_only: bool) -> None:
        try:
            self.send_response_only(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.send_header("Connection", "close")
            for name, value in _COMMON_HEADERS.items():
                self.send_header(name, value)
            for name, value in response.headers:
                self.send_header(name, value)
            self.end_headers()
            if not head_only:
                self.wfile.write(response.body)
                self.wfile.flush()
        except (TimeoutError, BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        # Request targets can contain the one-use launch token if a caller
        # violates the fragment contract.  Never place any request data in logs.
        return


class LanternLocalServer:
    """Context-managed local server with no configurable network exposure."""

    def __init__(
        self,
        *,
        status_provider: StatusProvider | None = None,
        security: LocalSessionSecurity | None = None,
        request_timeout: float = _READ_TIMEOUT_SECONDS,
    ) -> None:
        if request_timeout <= 0 or request_timeout > 10:
            raise ValueError("request timeout must be between zero and ten seconds")
        self._status_provider = status_provider or ReadyStatusProvider()
        self._security = security or LocalSessionSecurity()
        self._request_timeout = request_timeout
        self._server: _LoopbackHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._origin: str | None = None
        self._launch_url: str | None = None
        self._state_lock = threading.RLock()

    @property
    def origin(self) -> str:
        if self._origin is None:
            raise RuntimeError("local server has not started")
        return self._origin

    @property
    def launch_url(self) -> str:
        if self._launch_url is None:
            raise RuntimeError("local server has not started")
        return self._launch_url

    @property
    def port(self) -> int:
        server = self._server
        if server is None:
            raise RuntimeError("local server has not started")
        return int(server.server_address[1])

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> LanternLocalServer:
        with self._state_lock:
            if self._server is not None:
                raise RuntimeError("local server is already running")

            # Fail closed before opening a socket if any packaged UI byte has
            # changed from the reviewed manifest.
            verify_asset_manifest()
            server = _LoopbackHTTPServer(
                (_LOOPBACK_HOST, 0),
                application=None,
                request_timeout=self._request_timeout,
            )
            try:
                bound_host, bound_port = server.server_address[:2]
                if bound_host != _LOOPBACK_HOST:
                    raise RuntimeError("local server did not bind to literal loopback")

                launch_token = self._security.issue_launch_token()
                origin_label = hashlib.sha256(launch_token.encode()).hexdigest()[:32]
                application_host = f"lantern-{origin_label}.localhost"
                self._verify_application_host(application_host, bound_port)
                origin = f"http://{application_host}:{bound_port}"
                application = LocalApplication(
                    expected_host=f"{application_host}:{bound_port}",
                    expected_origin=origin,
                    security=self._security,
                    status_provider=self._status_provider,
                    on_launch_consumed=self._mark_launch_consumed,
                )
                server.application = application
                launch_url = f"{origin}/app/#launch={launch_token}"

                thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.05},
                    name=f"lantern-loopback-{bound_port}",
                    daemon=True,
                )
                thread.start()
            except BaseException:
                self._security.revoke_all()
                server.server_close()
                raise

            self._server = server
            self._thread = thread
            self._origin = origin
            self._launch_url = launch_url
            return self

    @staticmethod
    def _verify_application_host(hostname: str, port: int) -> None:
        """Fail closed unless the per-launch hostname resolves only to loopback."""
        try:
            answers = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise RuntimeError("per-launch localhost name is unavailable") from exc
        addresses = {answer[4][0] for answer in answers}
        if _LOOPBACK_HOST not in addresses or not addresses <= {_LOOPBACK_HOST, "::1"}:
            raise RuntimeError("per-launch localhost name did not resolve only to loopback")

    def _mark_launch_consumed(self) -> None:
        """Drop the raw launch token from retained server state after exchange."""
        with self._state_lock:
            if self._origin is not None:
                self._launch_url = f"{self._origin}/app/"

    def close(self) -> None:
        with self._state_lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
            self._origin = None
            self._launch_url = None

        self._security.revoke_all()
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
            if thread.is_alive():
                raise RuntimeError("local server did not shut down cleanly")

    def __enter__(self) -> LanternLocalServer:  # noqa: PYI034 - Python 3.10 has no Self
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
