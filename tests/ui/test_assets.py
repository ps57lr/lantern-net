"""Integrity, offline-security, accessibility, and product-boundary tests for the UI."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

import pytest

from netdiag.ui import assets

EXPECTED_ROUTES = {
    "/app/",
    "/app/index.html",
    "/app/styles.css",
    "/app/app.js",
    "/app/icons.svg",
}

EXPECTED_VIEWS = {
    "overview",
    "device",
    "network",
    "route",
    "wifi",
    "dns",
    "lan",
    "mdns",
    "ports",
    "fixes",
    "rescue",
    "session",
    "share",
}


class DocumentInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.inline_script_bodies: list[str] = []
        self._inside_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "script" and not attributes.get("src"):
            self._inside_inline_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._inside_inline_script = False

    def handle_data(self, data: str) -> None:
        if self._inside_inline_script and data.strip():
            self.inline_script_bodies.append(data)

    def attributes_for(self, tag_name: str) -> list[dict[str, str | None]]:
        return [attributes for tag, attributes in self.tags if tag == tag_name]


@pytest.fixture(scope="module")
def source_text() -> dict[str, str]:
    return {
        loaded.spec.filename: loaded.body.decode("utf-8")
        for loaded in assets.verify_asset_manifest()
    }


def test_manifest_is_exact_immutable_and_integrity_checked() -> None:
    assert set(assets.asset_routes()) == EXPECTED_ROUTES
    assert set(assets.ASSET_MANIFEST) == EXPECTED_ROUTES

    loaded = assets.verify_asset_manifest()
    assert {item.spec.filename for item in loaded} == {
        "index.html",
        "styles.css",
        "app.js",
        "icons.svg",
    }
    for item in loaded:
        assert len(item.body) == item.spec.size
        assert item.etag == f'"sha256-{item.spec.sha256}"'
        assert len(item.spec.sha256) == 64

    with pytest.raises(TypeError):
        assets.ASSET_MANIFEST["/app/extra"] = assets.ASSET_MANIFEST[  # type: ignore[index]
            "/app/"
        ]


def test_index_alias_and_content_types_are_exact() -> None:
    root_index = assets.load_asset("/app/")
    named_index = assets.load_asset("/app/index.html")
    assert root_index.body == named_index.body
    assert root_index.content_type == "text/html; charset=utf-8"
    assert assets.load_asset("/app/styles.css").content_type == "text/css; charset=utf-8"
    assert assets.load_asset("/app/app.js").content_type == "text/javascript; charset=utf-8"
    assert assets.load_asset("/app/icons.svg").content_type == "image/svg+xml"


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/app",
        "/",
        "/app/unknown.js",
        "/app/../assets.py",
        "/app/./app.js",
        "/app/%2e%2e/assets.py",
        "/app/app.js?debug=1",
        "/app/app.js#source",
        "\\app\\app.js",
        "/app/app.js\x00.css",
        "https://example.invalid/app.js",
    ],
)
def test_loader_rejects_every_non_manifest_path(path: str) -> None:
    with pytest.raises(assets.AssetNotFound):
        assets.load_asset(path)


def test_loader_rejects_non_text_paths() -> None:
    with pytest.raises(assets.AssetNotFound):
        assets.load_asset(None)  # type: ignore[arg-type]


def test_loader_detects_changed_packaged_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "index.html").write_text("modified", encoding="utf-8")
    monkeypatch.setattr(assets, "_STATIC_ROOT", tmp_path)
    with pytest.raises(assets.AssetIntegrityError, match="length mismatch"):
        assets.load_asset("/app/")


def test_security_headers_keep_the_application_same_origin_and_script_safe() -> None:
    headers = assets.STATIC_SECURITY_HEADERS
    policy = headers["Content-Security-Policy"]

    assert headers["Cache-Control"] == "no-store"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    for directive in (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "worker-src 'none'",
    ):
        assert directive in policy
    for forbidden in ("unsafe-inline", "unsafe-eval", "https:", "http:", "data:"):
        assert forbidden not in policy
    assert "camera=()" in headers["Permissions-Policy"]
    assert "microphone=()" in headers["Permissions-Policy"]


def test_html_references_only_verified_packaged_assets(source_text: dict[str, str]) -> None:
    inspector = DocumentInspector()
    inspector.feed(source_text["index.html"])

    references: set[str] = set()
    for attributes in inspector.attributes_for("script"):
        if attributes.get("src"):
            references.add(str(attributes["src"]))
    for attributes in inspector.attributes_for("link"):
        if attributes.get("href"):
            references.add(str(attributes["href"]))
    for attributes in inspector.attributes_for("use"):
        if attributes.get("href"):
            references.add(str(attributes["href"]).split("#", 1)[0])

    assert references == {"app.js", "styles.css", "icons.svg"}
    for reference in references:
        assert "/app/" + reference in assets.ASSET_MANIFEST

    combined = "\n".join(source_text.values())
    network_urls = set(re.findall(r'https?://[^\s"\')>]+', combined))
    assert network_urls <= {"http://www.w3.org/2000/svg"}
    assert "@import" not in source_text["styles.css"]
    assert "url(" not in source_text["styles.css"]


def test_html_has_semantic_landmarks_and_accessible_live_controls(
    source_text: dict[str, str],
) -> None:
    html = source_text["index.html"]
    inspector = DocumentInspector()
    inspector.feed(html)

    assert inspector.attributes_for("html")[0].get("lang") == "en"
    assert inspector.attributes_for("header")
    assert len(inspector.attributes_for("nav")) >= 2
    assert inspector.attributes_for("aside")
    sidebar = next(
        attrs for attrs in inspector.attributes_for("aside") if attrs.get("id") == "primary-sidebar"
    )
    assert sidebar.get("aria-hidden") == "true"
    assert "inert" in sidebar
    assert any(attrs.get("id") == "main-content" for attrs in inspector.attributes_for("main"))
    assert any(attrs.get("id") == "page-title" for attrs in inspector.attributes_for("h1"))
    assert any(attrs.get("name") == "viewport" for attrs in inspector.attributes_for("meta"))
    assert any(attrs.get("href") == "#main-content" for attrs in inspector.attributes_for("a"))
    assert any(attrs.get("role") == "progressbar" for _, attrs in inspector.tags)
    assert len([attrs for _, attrs in inspector.tags if attrs.get("aria-live") == "polite"]) >= 2
    assert any(attrs.get("id") == "cancel-button" for attrs in inspector.attributes_for("button"))
    buttons = {
        attrs.get("id"): attrs for attrs in inspector.attributes_for("button") if attrs.get("id")
    }
    assert "end-session-button" in buttons
    assert "mobile-end-session-button" in buttons
    assert "disabled" in buttons["mobile-end-session-button"]
    assert 'id="mobile-end-session-button"' in html
    assert html.index('id="mobile-end-session-button"') < html.index("</aside>")
    assert ">\n          End local session\n        </button>" in html

    identifiers = [
        str(attrs["id"]) for _tag, attrs in inspector.tags if attrs.get("id") is not None
    ]
    assert all(count == 1 for count in Counter(identifiers).values())

    scripts = inspector.attributes_for("script")
    assert scripts == [{"src": "app.js", "defer": None}]
    assert not inspector.inline_script_bodies
    assert "<style" not in html.lower()
    for _tag, attributes in inspector.tags:
        assert "style" not in attributes
        assert not any(name.lower().startswith("on") for name in attributes)


def test_all_live_and_explicitly_unavailable_views_are_navigable(
    source_text: dict[str, str],
) -> None:
    html_targets = set(re.findall(r'data-view-target="([a-z]+)"', source_text["index.html"]))
    assert html_targets == EXPECTED_VIEWS
    combined = source_text["index.html"] + source_text["app.js"]
    for phrase in (
        "Module coverage",
        "Include basic network checks",
        "Cancel check",
        "Fixes are unavailable",
        "LAN sessions are unavailable",
        "Rescue is guidance only",
        "Sharing is disabled",
    ):
        assert phrase in combined


def test_css_covers_keyboard_mobile_motion_contrast_and_partial_states(
    source_text: dict[str, str],
) -> None:
    css = source_text["styles.css"]
    for token in (
        ":focus-visible",
        "@media (max-width: 860px)",
        "@media (max-width: 599px)",
        "@media (prefers-color-scheme: dark)",
        "@media (prefers-reduced-motion: reduce)",
        "@media (forced-colors: active)",
        "env(safe-area-inset-bottom)",
        "min-height: 44px",
        ".status-ok",
        ".status-attention",
        ".status-limited",
        ".status-unavailable",
        ".loading-shell",
        ".unsupported-state",
        ".sidebar-session-button",
        ".assessment-facts",
        ".issue-grid",
        ".lantern-path",
        "grid-template-columns: repeat(5, minmax(0, 1fr))",
        ".technical-disclosure",
        ".path-mark",
    ):
        assert token in css
    assert "outline: none" not in css
    assert "outline: 0" not in css
    assert ".path-node:not(:last-child)::after" not in css
    base_sidebar_action = css.split("@media (max-width: 860px)", 1)[0].split(
        ".sidebar-session-button", 1
    )[1]
    narrow = css.split("@media (max-width: 860px)", 1)[1].split("@media (max-width: 599px)", 1)[0]
    assert "display: none" in base_sidebar_action.split("}", 1)[0]
    assert ".sidebar-session-button" in narrow
    assert "display: inline-flex" in narrow.split(".sidebar-session-button", 1)[1].split("}", 1)[0]
    tablet = css.split("@media (max-width: 1040px)", 1)[1].split("@media (max-width: 860px)", 1)[0]
    tablet_path = tablet.split(".lantern-path", 1)[1].split("}", 1)[0]
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in tablet_path
    assert "overflow" not in tablet_path
    assert "scroll-snap" not in tablet
    phone = css.split("@media (max-width: 599px)", 1)[1].split(
        "@media (prefers-color-scheme: dark)", 1
    )[0]
    assert ".lantern-path" in phone
    assert "grid-template-columns: 1fr" in phone.split(".lantern-path", 1)[1].split("}", 1)[0]


def test_light_palette_status_pairs_meet_wcag_aa(source_text: dict[str, str]) -> None:
    css = source_text["styles.css"]
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    variables = dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})", root))
    for name in ("healthy", "attention", "critical", "info", "unknown", "blocked"):
        assert contrast_ratio(variables[name], variables[name + "-bg"]) >= 4.5
    assert contrast_ratio("#ffffff", variables["navy"]) >= 4.5


def test_svg_sprite_is_local_scriptless_and_complete(source_text: dict[str, str]) -> None:
    svg = source_text["icons.svg"]
    root = ET.fromstring(svg)
    symbol_ids = {
        element.attrib["id"]
        for element in root
        if element.tag.endswith("symbol") and "id" in element.attrib
    }
    required = {
        "lantern",
        "overview",
        "device",
        "network",
        "wifi",
        "gateway",
        "dns",
        "lan",
        "mdns",
        "ports",
        "wrench",
        "share",
        "session",
        "rescue",
        "lock",
        "shield",
        "alert",
        "check",
        "info",
        "unknown",
    }
    assert required <= symbol_ids
    assert "<script" not in svg.lower()
    assert "foreignObject" not in svg
    assert not re.search(r"\bon[a-z]+\s*=", svg, re.IGNORECASE)
    assert "href=" not in svg


def contrast_ratio(first: str, second: str) -> float:
    lighter = max(relative_luminance(first), relative_luminance(second))
    darker = min(relative_luminance(first), relative_luminance(second))
    return (lighter + 0.05) / (darker + 0.05)


def relative_luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]

    def linear(channel: float) -> float:
        if channel <= 0.04045:
            return channel / 12.92
        return ((channel + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue
