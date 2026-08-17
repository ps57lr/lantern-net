from __future__ import annotations

import json

import pytest

from netdiag.lan.routes import (
    MAX_REQUEST_BODY,
    LanApiGuard,
    LanRoute,
    RequestEnvelope,
    RequestRejected,
)
from netdiag.lan.sessions import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from tests.lan.helpers import FakeClock, issue_session, paired_session_authority

ADDRESS = "192.168.50.10"
PORT = 38443
SOURCE = "192.168.50.20"
HOST = f"{ADDRESS}:{PORT}"
ORIGIN = f"https://{HOST}"


def setup_guard(*, capabilities: tuple[str, ...] | None = None):
    sessions = paired_session_authority(clock=FakeClock())
    credentials = issue_session(
        sessions,
        capabilities=capabilities
        or (
            "network.read",
            "network.run.passive",
            "network.run.path",
            "report.export.redacted",
            "session.end",
        ),
    )
    guard = LanApiGuard(
        interface_address=ADDRESS,
        port=PORT,
        sessions=sessions,
        allowed_profiles=("network.passive", "network.path"),
    )
    return guard, credentials


def request(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    credentials=None,
    headers: tuple[tuple[str, str], ...] = (),
    source: str = SOURCE,
    is_tls: bool = True,
) -> RequestEnvelope:
    default_headers = [("Host", HOST), ("Origin", ORIGIN)]
    if method == "POST":
        default_headers.extend(
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ]
        )
    if credentials is not None:
        default_headers.append(("Cookie", f"{SESSION_COOKIE_NAME}={credentials.token}"))
        if method == "POST":
            default_headers.append((CSRF_HEADER_NAME, credentials.csrf_token))
    default_headers.extend(headers)
    return RequestEnvelope(method, path, tuple(default_headers), body, source, is_tls)


def json_body(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_pairing_route_is_tls_origin_host_and_json_bound() -> None:
    guard, _credentials = setup_guard()
    body = json_body({"code": "23456789", "client_label": "Technician phone"})
    authorized = guard.authorize(request("POST", "/api/v1/pair", body=body))
    assert authorized.route is LanRoute.PAIR
    assert authorized.payload == {"code": "23456789", "client_label": "Technician phone"}
    assert authorized.session is None


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"is_tls": False}, 426),
        ({"headers": (("Host", "evil.example"),)}, 400),
        ({"headers": (("Origin", "https://evil.example"),)}, 400),
    ],
)
def test_transport_context_failures_are_rejected(change: dict[str, object], status: int) -> None:
    guard, credentials = setup_guard()
    envelope = request("GET", "/api/v1/session", credentials=credentials, **change)  # type: ignore[arg-type]
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(envelope)
    assert caught.value.status == status


def test_dns_rebinding_and_missing_origin_are_rejected() -> None:
    guard, credentials = setup_guard()
    for raw_headers in (
        (("Host", "attacker.invalid"), ("Origin", ORIGIN)),
        (("Host", HOST),),
        (("Host", HOST), ("Origin", "null")),
    ):
        envelope = RequestEnvelope(
            "GET",
            "/api/v1/session",
            raw_headers + (("Cookie", f"{SESSION_COOKIE_NAME}={credentials.token}"),),
            b"",
            SOURCE,
            True,
        )
        with pytest.raises(RequestRejected, match="request_context_rejected"):
            guard.authorize(envelope)


def test_authenticated_reads_require_exact_cookie_and_capability() -> None:
    guard, credentials = setup_guard()
    authorized = guard.authorize(request("GET", "/api/v1/session", credentials=credentials))
    assert authorized.route is LanRoute.SESSION
    assert authorized.session is not None
    assert authorized.session.source_address == SOURCE

    no_cookie = request("GET", "/api/v1/session")
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(no_cookie)
    assert caught.value.status == 401

    extra_cookie = request(
        "GET",
        "/api/v1/session",
        headers=(("Cookie", f"{SESSION_COOKIE_NAME}={credentials.token}; other=value"),),
    )
    with pytest.raises(RequestRejected):
        guard.authorize(extra_cookie)


def test_mutation_requires_csrf_and_source_binding() -> None:
    guard, credentials = setup_guard()
    body = json_body({"profile_id": "network.passive"})
    authorized = guard.authorize(request("POST", "/api/v1/run", body=body, credentials=credentials))
    assert authorized.route is LanRoute.RUN_START

    raw = request("POST", "/api/v1/run", body=body, credentials=credentials)
    without_csrf = RequestEnvelope(
        raw.method,
        raw.path,
        tuple((name, value) for name, value in raw.headers if name != CSRF_HEADER_NAME),
        raw.body,
        raw.source_address,
        raw.is_tls,
    )
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(without_csrf)
    assert caught.value.status == 401

    with pytest.raises(RequestRejected) as caught:
        guard.authorize(
            request(
                "POST",
                "/api/v1/run",
                body=body,
                credentials=credentials,
                source="192.168.50.21",
            )
        )
    assert caught.value.status == 401


def test_run_profiles_are_fixed_and_request_cannot_supply_target() -> None:
    guard, credentials = setup_guard()
    for body in (
        json_body({"profile_id": "network.passive", "target": "192.168.50.99"}),
        json_body({"profile_id": "shell.execute"}),
        json_body({"profile_id": "network.scoped-discovery"}),
    ):
        with pytest.raises(RequestRejected):
            guard.authorize(request("POST", "/api/v1/run", body=body, credentials=credentials))


@pytest.mark.parametrize(
    "path",
    [
        "/shell",
        "/api/v1/shell",
        "/api/v1/command",
        "/api/v1/files",
        "/api/v1/upload",
        "/api/v1/remediation",
        "/api/v1/proxy",
        "/api/v1/ports/192.168.50.1",
        "/api/v1/run?target=192.168.50.1",
        "/../etc/passwd",
    ],
)
def test_dangerous_and_dynamic_routes_do_not_exist(path: str) -> None:
    guard, credentials = setup_guard()
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(request("GET", path, credentials=credentials))
    assert caught.value.status == 404


def test_cors_and_preflight_are_not_supported() -> None:
    guard, credentials = setup_guard()
    header_names = {name.lower() for name, _value in guard.response_headers()}
    assert "access-control-allow-origin" not in header_names
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(request("OPTIONS", "/api/v1/session", credentials=credentials))
    assert caught.value.status == 405


def test_security_headers_include_csp_no_store_and_frame_denial() -> None:
    guard, _credentials = setup_guard()
    headers = dict(guard.response_headers())
    assert headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_request_framing_content_type_and_size_are_bounded() -> None:
    guard, credentials = setup_guard()
    body = json_body({"profile_id": "network.passive"})
    base = request("POST", "/api/v1/run", body=body, credentials=credentials)
    bad_framing = RequestEnvelope(
        base.method,
        base.path,
        tuple((name, "999" if name == "Content-Length" else value) for name, value in base.headers),
        body,
        SOURCE,
        True,
    )
    with pytest.raises(RequestRejected, match="request_framing_rejected"):
        guard.authorize(bad_framing)

    transfer = request(
        "POST",
        "/api/v1/run",
        body=body,
        credentials=credentials,
        headers=(("Transfer-Encoding", "chunked"),),
    )
    with pytest.raises(RequestRejected, match="request_framing_rejected"):
        guard.authorize(transfer)

    oversized = b"{" + b"x" * MAX_REQUEST_BODY + b"}"
    with pytest.raises(RequestRejected) as caught:
        guard.authorize(request("POST", "/api/v1/run", body=oversized, credentials=credentials))
    assert caught.value.status == 413


def test_hostile_json_is_rejected_before_application_dispatch() -> None:
    guard, credentials = setup_guard()
    bodies = (
        b'{"profile_id":"network.passive","profile_id":"network.path"}',
        b'{"profile_id":NaN}',
        b'{"profile_id":' + b"[" * 10 + b"0" + b"]" * 10 + b"}",
        b'{"profile_id":"' + b"x" * 300 + b'"}',
        b"[]",
        b"\xff",
    )
    for body in bodies:
        with pytest.raises(RequestRejected):
            guard.authorize(request("POST", "/api/v1/run", body=body, credentials=credentials))


def test_export_and_end_routes_are_fixed_redacted_session_actions() -> None:
    guard, credentials = setup_guard()
    for path, route in (
        ("/api/v1/report/export", LanRoute.REPORT_EXPORT),
        ("/api/v1/session/end", LanRoute.SESSION_END),
    ):
        authorized = guard.authorize(request("POST", path, body=b"{}", credentials=credentials))
        assert authorized.route is route
        assert authorized.response_limit <= 1024 * 1024


def test_pairing_rejects_cookie_fixation() -> None:
    guard, credentials = setup_guard()
    body = json_body({"code": "23456789", "client_label": "Phone"})
    with pytest.raises(RequestRejected, match="request_context_rejected"):
        guard.authorize(request("POST", "/api/v1/pair", body=body, credentials=credentials))


@pytest.mark.parametrize(
    "label", ["helper\u202eexe", "helper\u2066admin", "helper\u0085line", "helper\ud800"]
)
def test_pairing_route_rejects_unicode_visual_spoof_controls(label: str) -> None:
    guard, _credentials = setup_guard()
    body = json_body({"code": "23456789", "client_label": label})
    with pytest.raises(RequestRejected, match="invalid_json_shape"):
        guard.authorize(request("POST", "/api/v1/pair", body=body))
