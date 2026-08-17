"""End-to-end security checks for Lantern's loopback-only HTTP boundary."""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from netdiag.ui import server as server_module
from netdiag.ui.controller import JsonValue
from netdiag.ui.security import LocalSessionSecurity
from netdiag.ui.server import LanternLocalServer


@dataclass(slots=True)
class FakeClock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


class FixtureStatusProvider:
    def snapshot(self) -> dict[str, JsonValue]:
        return {
            "state": "complete",
            "severity": "ok",
            "finding_codes": ["route.default.available"],
        }


def request(
    server: LanternLocalServer,
    method: str,
    path: str,
    *,
    body: bytes | str | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    request_headers = dict(headers or {})
    request_headers.setdefault("Host", urlsplit(server.origin).netloc)
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = HttpResult(
            status=response.status,
            headers={name.lower(): value for name, value in response.getheaders()},
            body=response.read(),
        )
    finally:
        connection.close()
    return result


def launch_token(server: LanternLocalServer) -> str:
    parsed = urlsplit(server.launch_url)
    assert parsed.scheme == "http"
    assert parsed.hostname is not None
    assert parsed.hostname.startswith("lantern-")
    assert parsed.hostname.endswith(".localhost")
    assert parsed.port == server.port
    assert parsed.path == "/app/"
    assert parsed.query == ""
    values = parse_qs(parsed.fragment, strict_parsing=True)
    assert set(values) == {"launch"}
    return values["launch"][0]


def exchange(
    server: LanternLocalServer,
    token: str | None = None,
) -> tuple[HttpResult, str, str]:
    raw_token = token or launch_token(server)
    payload = json.dumps({"launch_token": raw_token})
    result = request(
        server,
        "POST",
        "/api/session/exchange",
        body=payload,
        headers={"Content-Type": "application/json", "Origin": server.origin},
    )
    assert result.status == 201
    cookie = result.headers["set-cookie"].split(";", 1)[0]
    csrf = result.json()["csrf_token"]
    return result, cookie, csrf


def error_code(result: HttpResult) -> str:
    payload = result.json()
    assert set(payload) == {"error"}
    assert set(payload["error"]) == {"code", "message"}
    return payload["error"]["code"]


@pytest.fixture
def local_server() -> LanternLocalServer:
    with LanternLocalServer(status_provider=FixtureStatusProvider()) as server:
        yield server


def test_server_binds_literal_loopback_with_os_selected_port_and_fragment_secret(
    local_server: LanternLocalServer,
) -> None:
    parsed = urlsplit(local_server.launch_url)
    assert local_server.origin == f"http://{parsed.hostname}:{local_server.port}"
    assert parsed.netloc == f"{parsed.hostname}:{local_server.port}"
    assert local_server.port > 0
    assert local_server.is_running
    assert "launch=" not in parsed.path
    assert "launch=" not in parsed.query
    assert len(launch_token(local_server)) >= 32

    answers = socket.getaddrinfo(
        parsed.hostname,
        local_server.port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    addresses = {answer[4][0] for answer in answers}
    assert "127.0.0.1" in addresses
    assert addresses <= {"127.0.0.1", "::1"}

    # This assertion guards the actual socket address, not just the public URL.
    assert local_server._server is not None
    assert local_server._server.server_address[0] == "127.0.0.1"


def test_startup_fails_closed_and_closes_socket_for_unsafe_localhost_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed_ports: list[int] = []
    original_close = server_module._LoopbackHTTPServer.server_close

    def tracked_close(http_server: server_module._LoopbackHTTPServer) -> None:
        closed_ports.append(int(http_server.server_address[1]))
        original_close(http_server)

    monkeypatch.setattr(server_module._LoopbackHTTPServer, "server_close", tracked_close)
    monkeypatch.setattr(
        server_module.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("203.0.113.10", int(args[1])),
            )
        ],
    )

    server = LanternLocalServer()
    with pytest.raises(RuntimeError, match="resolve only to loopback"):
        server.start()
    assert closed_ports
    assert not server.is_running
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", closed_ports[-1]), timeout=0.2)


def test_exchange_is_one_use_and_wrong_replay_responses_are_indistinguishable(
    local_server: LanternLocalServer,
) -> None:
    token = launch_token(local_server)
    wrong = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body=json.dumps({"launch_token": "x" * 43}),
        headers={"Content-Type": "application/json", "Origin": local_server.origin},
    )
    assert wrong.status == 401
    assert error_code(wrong) == "launch_denied"
    assert "set-cookie" not in wrong.headers

    success, _cookie, _csrf = exchange(local_server, token)
    assert success.status == 201
    assert token.encode() not in success.body
    assert token not in local_server.launch_url
    assert urlsplit(local_server.launch_url).fragment == ""

    replay = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body=json.dumps({"launch_token": token}),
        headers={"Content-Type": "application/json", "Origin": local_server.origin},
    )
    assert replay.status == wrong.status
    assert replay.body == wrong.body
    assert "set-cookie" not in replay.headers


def test_exchange_rate_limit_blocks_brute_force_then_recovers() -> None:
    clock = FakeClock()
    security = LocalSessionSecurity(
        clock=clock,
        launch_ttl=120,
        failure_limit=3,
        failure_window=60,
        lockout_seconds=10,
    )
    with LanternLocalServer(security=security) as server:
        token = launch_token(server)
        statuses: list[int] = []
        for suffix in ("a", "b", "c"):
            result = request(
                server,
                "POST",
                "/api/session/exchange",
                body=json.dumps({"launch_token": suffix * 43}),
                headers={"Content-Type": "application/json", "Origin": server.origin},
            )
            statuses.append(result.status)
        assert statuses == [401, 401, 429]

        blocked = request(
            server,
            "POST",
            "/api/session/exchange",
            body=json.dumps({"launch_token": token}),
            headers={"Content-Type": "application/json", "Origin": server.origin},
        )
        assert blocked.status == 429
        assert blocked.headers["retry-after"] == "10"
        assert error_code(blocked) == "exchange_rate_limited"

        clock.advance(11)
        success, _cookie, _csrf = exchange(server, token)
        assert success.status == 201


@pytest.mark.parametrize(
    ("method", "path", "headers", "expected_code"),
    [
        ("GET", "/api/health", {"Host": "localhost"}, "invalid_host"),
        (
            "GET",
            "/api/health",
            {"Origin": "https://attacker.invalid"},
            "invalid_origin",
        ),
        (
            "POST",
            "/api/session/exchange",
            {"Content-Type": "application/json"},
            "invalid_origin",
        ),
        (
            "POST",
            "/api/session/exchange",
            {"Content-Type": "application/json", "Origin": "null"},
            "invalid_origin",
        ),
    ],
)
def test_host_and_origin_are_strictly_same_origin(
    local_server: LanternLocalServer,
    method: str,
    path: str,
    headers: dict[str, str],
    expected_code: str,
) -> None:
    body = json.dumps({"launch_token": launch_token(local_server)}) if method == "POST" else None
    result = request(local_server, method, path, body=body, headers=headers)
    assert result.status == 403
    assert error_code(result) == expected_code


def test_cookie_flags_authenticated_status_and_csrf_enforced_revoke(
    local_server: LanternLocalServer,
) -> None:
    exchanged, cookie, csrf = exchange(local_server)
    set_cookie = exchanged.headers["set-cookie"]
    assert set_cookie.startswith("lantern_session=")
    assert "; Path=/api/" in set_cookie
    assert "; Max-Age=900" in set_cookie
    assert "; HttpOnly" in set_cookie
    assert "; SameSite=Strict" in set_cookie
    assert "Domain=" not in set_cookie
    assert "Secure" not in set_cookie  # Loopback transport is deliberately HTTP-only.
    assert exchanged.json()["expires_in"] == 900

    status = request(local_server, "GET", "/api/status", headers={"Cookie": cookie})
    assert status.status == 200
    assert status.json()["finding_codes"] == ["route.default.available"]

    missing = request(
        local_server,
        "POST",
        "/api/session/revoke",
        body="{}",
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Cookie": cookie,
        },
    )
    assert missing.status == 403
    assert error_code(missing) == "csrf_denied"

    wrong = request(
        local_server,
        "POST",
        "/api/session/revoke",
        body="{}",
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Cookie": cookie,
            "X-Lantern-CSRF": "z" * 43,
        },
    )
    assert wrong.status == 403
    assert error_code(wrong) == "csrf_denied"

    revoked = request(
        local_server,
        "POST",
        "/api/session/revoke",
        body="{}",
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Cookie": cookie,
            "X-Lantern-CSRF": csrf,
        },
    )
    assert revoked.status == 200
    assert revoked.json() == {"revoked": True}
    assert "Max-Age=0" in revoked.headers["set-cookie"]

    rejected = request(local_server, "GET", "/api/status", headers={"Cookie": cookie})
    assert rejected.status == 401
    assert error_code(rejected) == "session_required"


def test_each_server_uses_a_distinct_host_only_cookie_origin() -> None:
    with LanternLocalServer() as first, LanternLocalServer() as second:
        first_host = urlsplit(first.origin).hostname
        second_host = urlsplit(second.origin).hostname
        assert first_host != second_host
        assert first_host is not None and first_host.endswith(".localhost")
        assert second_host is not None and second_host.endswith(".localhost")

        exchanged, _cookie, _csrf = exchange(first)
        assert "Domain=" not in exchanged.headers["set-cookie"]


def test_session_refresh_is_read_only_and_rejects_duplicate_cookie(
    local_server: LanternLocalServer,
) -> None:
    _result, cookie, first_csrf = exchange(local_server)
    refreshed = request(local_server, "GET", "/api/session", headers={"Cookie": cookie})
    assert refreshed.status == 200
    second_csrf = refreshed.json()["csrf_token"]
    assert second_csrf == first_csrf

    duplicate = request(
        local_server,
        "GET",
        "/api/status",
        headers={"Cookie": f"{cookie}; {cookie}"},
    )
    assert duplicate.status == 401

    current = request(
        local_server,
        "POST",
        "/api/session/revoke",
        body="{}",
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Cookie": cookie,
            "X-Lantern-CSRF": first_csrf,
        },
    )
    assert current.status == 200


def test_head_session_does_not_rotate_csrf_authority(local_server: LanternLocalServer) -> None:
    _result, cookie, csrf = exchange(local_server)
    head = request(local_server, "HEAD", "/api/session", headers={"Cookie": cookie})
    assert head.status == 405
    assert head.body == b""
    assert head.headers["allow"] == "GET"

    revoked = request(
        local_server,
        "POST",
        "/api/session/revoke",
        body="{}",
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Cookie": cookie,
            "X-Lantern-CSRF": csrf,
        },
    )
    assert revoked.status == 200


def test_session_expires_absolutely_and_clears_browser_cookie() -> None:
    clock = FakeClock()
    security = LocalSessionSecurity(clock=clock, launch_ttl=20, session_ttl=5)
    with LanternLocalServer(security=security) as server:
        _result, cookie, _csrf = exchange(server)
        assert request(server, "GET", "/api/status", headers={"Cookie": cookie}).status == 200
        clock.advance(6)
        expired = request(server, "GET", "/api/status", headers={"Cookie": cookie})
        assert expired.status == 401
        assert error_code(expired) == "session_required"
        assert "Max-Age=0" in expired.headers["set-cookie"]


@pytest.mark.parametrize(
    "method", ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "BREW"]
)
def test_unsupported_methods_are_normalized_and_never_enable_cors(
    local_server: LanternLocalServer, method: str
) -> None:
    result = request(local_server, method, "/api/health")
    assert result.status == 405
    assert error_code(result) == "method_not_allowed"
    assert result.headers["allow"] == "GET, HEAD, POST"
    assert not any(name.startswith("access-control-") for name in result.headers)


def test_malformed_http_parser_errors_use_json_and_security_headers(
    local_server: LanternLocalServer,
) -> None:
    host = urlsplit(local_server.origin).netloc
    raw = (
        f"GET /api/health HTTP/1.1\r\nHost: {host}\r\nX-Oversized: {'x' * 70_000}\r\n\r\n"
    ).encode()
    client = socket.create_connection(("127.0.0.1", local_server.port), timeout=2)
    try:
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        client.close()
    response = b"".join(chunks)
    headers, body = response.split(b"\r\n\r\n", 1)
    assert headers.startswith(b"HTTP/1.1 431")
    assert b"Content-Security-Policy: default-src 'none'" in headers
    assert b"Server:" not in headers
    assert json.loads(body)["error"]["code"] == "invalid_http_request"


def test_expectation_rejection_is_bounded_and_closes(local_server: LanternLocalServer) -> None:
    result = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body=json.dumps({"launch_token": launch_token(local_server)}),
        headers={
            "Content-Type": "application/json",
            "Origin": local_server.origin,
            "Expect": "100-continue",
        },
    )
    assert result.status == 417
    assert result.headers["connection"] == "close"
    assert error_code(result) == "expectation_failed"


def test_request_bodies_are_bounded_and_content_type_is_exact(
    local_server: LanternLocalServer,
) -> None:
    oversized = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body=b"x" * 4097,
        headers={"Content-Type": "application/json", "Origin": local_server.origin},
    )
    assert oversized.status == 413
    assert error_code(oversized) == "body_too_large"

    wrong_type = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body="{}",
        headers={"Content-Type": "text/plain", "Origin": local_server.origin},
    )
    assert wrong_type.status == 415
    assert error_code(wrong_type) == "json_required"

    malformed = request(
        local_server,
        "POST",
        "/api/session/exchange",
        body="{",
        headers={"Content-Type": "application/json", "Origin": local_server.origin},
    )
    assert malformed.status == 400
    assert error_code(malformed) == "invalid_json"


def test_assets_are_integrity_checked_exact_and_hardened(local_server: LanternLocalServer) -> None:
    index = request(local_server, "GET", "/app/")
    assert index.status == 200
    assert index.headers["content-type"] == "text/html; charset=utf-8"
    assert index.headers["etag"].startswith('"sha256-')
    assert len(index.body) == int(index.headers["content-length"])
    assert "default-src 'none'" in index.headers["content-security-policy"]
    assert index.headers["x-content-type-options"] == "nosniff"
    assert index.headers["x-frame-options"] == "DENY"
    assert index.headers["cross-origin-opener-policy"] == "same-origin"
    assert index.headers["cache-control"] == "no-store"

    head = request(local_server, "HEAD", "/app/app.js")
    assert head.status == 200
    assert head.body == b""
    assert int(head.headers["content-length"]) > 0

    for alias in (
        "/app",
        "/",
        "/app/../assets.py",
        "/app/%2e%2e/assets.py",
        "/app/app.js?debug=true",
        "/credentials",
        "/api/remediation/apply",
        "/api/fix",
    ):
        result = request(local_server, "GET", alias)
        assert result.status == 404
        assert error_code(result) in {"asset_not_found", "route_not_found"}


def test_health_is_minimal_and_all_responses_carry_security_headers(
    local_server: LanternLocalServer,
) -> None:
    health = request(local_server, "GET", "/api/health")
    assert health.status == 200
    assert health.json() == {
        "service": "lantern-local",
        "status": "ok",
        "transport": "loopback",
    }
    assert "hostname" not in health.body.decode().lower()

    missing = request(local_server, "GET", "/not-found")
    assert missing.status == 404
    for response in (health, missing):
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["permissions-policy"].startswith("camera=()")
        assert response.headers["cross-origin-resource-policy"] == "same-origin"
        assert not any(name.startswith("access-control-") for name in response.headers)


def test_bad_status_provider_is_fail_closed_without_exception_details() -> None:
    class BadProvider:
        def snapshot(self) -> dict[str, JsonValue]:
            return {"bad": float("nan")}

    with LanternLocalServer(status_provider=BadProvider()) as server:
        _result, cookie, _csrf = exchange(server)
        unavailable = request(server, "GET", "/api/status", headers={"Cookie": cookie})
        assert unavailable.status == 503
        assert error_code(unavailable) == "status_unavailable"
        assert b"nan" not in unavailable.body.lower()


def test_shutdown_revokes_capabilities_stops_thread_and_is_idempotent() -> None:
    security = LocalSessionSecurity()
    server = LanternLocalServer(security=security, request_timeout=0.2).start()
    port = server.port
    thread_name = f"lantern-loopback-{port}"
    _result, cookie, _csrf = exchange(server)
    session_id = cookie.split("=", 1)[1]
    assert security.authenticate(session_id) is not None
    assert any(thread.name == thread_name for thread in threading.enumerate())

    server.close()
    server.close()

    assert not server.is_running
    assert security.authenticate(session_id) is None
    assert not any(thread.name == thread_name for thread in threading.enumerate())
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.2)


def test_shutdown_does_not_wait_indefinitely_for_partial_request() -> None:
    server = LanternLocalServer(request_timeout=0.1).start()
    client = socket.create_connection(("127.0.0.1", server.port), timeout=1)
    try:
        client.sendall(
            (
                "POST /api/session/exchange HTTP/1.1\r\n"
                f"Host: {urlsplit(server.origin).netloc}\r\n"
                f"Origin: {server.origin}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 100\r\n\r\n{}"
            ).encode()
        )
        started = time.monotonic()
        server.close()
        elapsed = time.monotonic() - started
        assert elapsed < 1.0
    finally:
        client.close()
