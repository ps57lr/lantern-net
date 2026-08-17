"""Static contract tests for the dependency-free, CSP-safe Lantern browser client."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC_ROOT = Path(__file__).parents[2] / "netdiag" / "ui" / "static"
EXPECTED_API_ROUTES = {
    "/api/session/exchange",
    "/api/session",
    "/api/status",
    "/api/status/events",
    "/api/report/export",
    "/api/diagnostics/start",
    "/api/diagnostics/cancel",
    "/api/session/revoke",
}


@pytest.fixture(scope="module")
def client() -> str:
    return (STATIC_ROOT / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def interface() -> str:
    return (STATIC_ROOT / "index.html").read_text(encoding="utf-8")


def test_client_is_valid_javascript(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    result = subprocess.run(
        [node, "--check", str(STATIC_ROOT / "app.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_launch_fragment_is_exact_and_scrubbed_before_any_request(client: str) -> None:
    assert "window.location.hash.match(/^#launch=([A-Za-z0-9_-]{32,256})$/)" in client
    history_index = client.index('window.history.replaceState(null, "", window.location.pathname)')
    fetch_index = client.index("window.fetch(")
    establish_index = client.index("void establishSession()")
    assert history_index < fetch_index < establish_index

    exchange_block = client.split("async function establishSession()", 1)[1].split(
        "async function refreshCsrfAfterForbidden()", 1
    )[0]
    assert exchange_block.index(
        "const exchangeBody = { launch_token: launchToken }"
    ) < exchange_block.index("launchToken = null")
    assert exchange_block.index("launchToken = null") < exchange_block.index(
        'apiFetch("/api/session/exchange"'
    )
    assert "location.hash =" not in client


def test_api_routes_and_methods_are_an_exact_same_origin_allowlist(client: str) -> None:
    discovered = set(re.findall(r'"(/api/[a-z/]+)"', client))
    assert discovered == EXPECTED_API_ROUTES
    allowlist = client.split("const API_METHODS = Object.freeze({", 1)[1].split("});", 1)[0]
    for route in EXPECTED_API_ROUTES:
        assert f'"{route}"' in allowlist
    assert '"/api/status": Object.freeze(["GET"])' in allowlist
    assert '"/api/session": Object.freeze(["GET"])' in allowlist
    assert '"/api/status/events": Object.freeze(["GET"])' in allowlist
    assert '"/api/report/export": Object.freeze(["GET"])' in allowlist
    for route in EXPECTED_API_ROUTES - {
        "/api/status",
        "/api/session",
        "/api/status/events",
        "/api/report/export",
    }:
        assert f'"{route}": Object.freeze(["POST"])' in allowlist
    assert "resolved.origin !== window.location.origin" in client
    assert "resolved.pathname !== route" in client
    assert 'credentials: "same-origin"' in client
    assert 'cache: "no-store"' in client
    assert 'redirect: "error"' in client


def test_every_fetch_is_bounded_and_body_read_is_inside_the_abort_window(client: str) -> None:
    assert client.count("window.fetch(") == 1
    api_block = client.split("async function apiFetch", 1)[1].split("async function readJson", 1)[0]
    assert "const controller = new AbortController()" in api_block
    assert "REQUEST_TIMEOUT_MS = 8000" in client
    assert "controller.abort()" in api_block
    assert "signal: controller.signal" in api_block
    assert "await response.arrayBuffer()" in api_block
    assert "responseBody.byteLength > MAX_JSON_BYTES" in api_block
    assert api_block.index("await response.arrayBuffer()") < api_block.index(
        "window.clearTimeout(timeout)"
    )
    assert "finally" in api_block


def test_session_authority_stays_in_memory_and_401_stops_polling(client: str) -> None:
    assert "let csrfToken = null" in client
    assert 'const CSRF_HEADER = "X-Lantern-CSRF"' in client
    assert 'apiFetch("/api/session", { method: "GET" })' in client
    assert "function clearSession" in client
    clear_block = client.split("function clearSession", 1)[1].split(
        "async function establishSession", 1
    )[0]
    assert "authenticated = false" in clear_block
    assert "csrfToken = null" in clear_block
    assert "stopPolling()" in clear_block
    assert "stopStatusStream()" in clear_block
    assert "stopSessionExpiryTimer()" in clear_block
    assert "document.cookie" not in client

    for forbidden in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "serviceWorker",
        "WebSocket",
        "sendBeacon",
        "navigator.clipboard",
        "pagehide",
        "beforeunload",
    ):
        assert forbidden not in client
    assert "new EventSource(" in client
    assert 'streamUrl.pathname !== "/api/status/events"' in client


def test_clearing_a_session_removes_stale_run_announcements(client: str) -> None:
    clear = (
        "function clearSession"
        + client.split("function clearSession", 1)[1].split(
            "function setSessionActionsDisabled", 1
        )[0]
    )
    assert 'runAnnouncement.textContent = ""' in clear
    assert clear.index('runAnnouncement.textContent = ""') < clear.index("renderCurrentView()")
    assert clear.index("sessionCleared = true") < clear.index("renderCurrentView()")
    expiry = client.split("function armSessionExpiry", 1)[1].split("function clearSession", 1)[0]
    revoke = client.split("async function revokeSession", 1)[1].split(
        "document.addEventListener", 1
    )[0]
    assert 'clearSession("The private local session expired.' in expiry
    assert 'clearSession("The private local session ended.' in revoke

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    harness = r"""
let sessionGeneration = 50;
let startInFlight = true;
let cancelInFlight = true;
let revokeInFlight = true;
let pollInFlight = true;
let authenticated = true;
let csrfToken = "token";
let sessionCleared = false;
let statusSnapshot = {state: "completed"};
let rendered = 0;
let noticeMessage = "";
let noticeTone = "";
const mobileDrawerQuery = {matches: false};
const primarySidebar = {classList: {contains() { return false; }}};
const newCheckButton = {disabled: false};
const endSessionButton = {disabled: false};
const mobileEndSessionButton = {disabled: false};
const cancelButton = {disabled: false};
const connectionState = {textContent: "Private local session"};
const runAnnouncement = {textContent: ""};
function stopSessionExpiryTimer() {}
function stopPolling() {}
function stopStatusStream() {}
function setSessionActionsDisabled(disabled) {
  endSessionButton.disabled = disabled;
  mobileEndSessionButton.disabled = disabled;
}
function showNotice(message, tone) {
  noticeMessage = message;
  noticeTone = tone;
}
function closeSidebar() { throw new Error("desktop close unexpectedly moved focus"); }
function renderCurrentView() { rendered += 1; }
function reset(announcement) {
  startInFlight = true;
  cancelInFlight = true;
  revokeInFlight = true;
  pollInFlight = true;
  authenticated = true;
  csrfToken = "token";
  sessionCleared = false;
  statusSnapshot = {state: "completed"};
  newCheckButton.disabled = false;
  endSessionButton.disabled = false;
  mobileEndSessionButton.disabled = false;
  cancelButton.disabled = false;
  connectionState.textContent = "Private local session";
  runAnnouncement.textContent = announcement;
  noticeMessage = "";
  noticeTone = "";
  rendered = 0;
}
function assertClosed(expectedMessage, expectedTone) {
  if (runAnnouncement.textContent !== "" || authenticated || csrfToken !== null ||
      !sessionCleared || statusSnapshot !== null ||
      connectionState.textContent !== "Local session closed" ||
      !newCheckButton.disabled || !endSessionButton.disabled ||
      !mobileEndSessionButton.disabled || !cancelButton.disabled ||
      startInFlight || cancelInFlight || revokeInFlight || pollInFlight || rendered !== 1 ||
      noticeMessage !== expectedMessage || noticeTone !== expectedTone) {
    throw new Error("closed session retained live readiness state");
  }
}
"""
    checks = r"""
const announcements = [
  "Lantern is ready for a consent-based check.",
  "The diagnostic check started.",
  "The diagnostic check completed.",
];
for (const announcement of announcements) {
  reset(announcement);
  const ended = "The private local session ended. Launch Lantern again to reconnect.";
  clearSession(ended, "info");
  assertClosed(ended, "info");

  reset(announcement);
  const expired = "The private local session expired. Launch Lantern again to continue.";
  clearSession(expired);
  assertClosed(expired, "attention");
}
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + clear + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_cleared_expired_and_auth_lost_views_create_no_new_requests(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")

    create_element = (
        "function createElement"
        + client.split("function createElement", 1)[1].split("function createIcon", 1)[0]
    )
    unavailable = (
        "function renderStatusUnavailable"
        + client.split("function renderStatusUnavailable", 1)[1].split(
            "function assessmentPanel", 1
        )[0]
    )
    renderer = (
        "function renderCurrentView"
        + client.split("function renderCurrentView", 1)[1].split("function setView", 1)[0]
    )
    clear = (
        "function clearSession"
        + client.split("function clearSession", 1)[1].split(
            "function setSessionActionsDisabled", 1
        )[0]
    )
    assert renderer.index("if (unavailable)") < renderer.index('currentView === "overview"')
    assert "createIcon" not in unavailable

    harness = r"""
class TestNode {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.className = "";
    this.dataset = {};
    this._text = "";
  }
  append(...items) { this.children.push(...items.filter((item) => item != null)); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((item) => item.textContent).join(""); }
  focus() {}
}
let resourceRequests = 0;
let apiRequests = 0;
const window = {fetch() { apiRequests += 1; throw new Error("fetch after clear"); }};
const document = {
  activeElement: new TestNode("body"),
  createElement(tag) { return new TestNode(tag); },
  createElementNS() { resourceRequests += 1; throw new Error("asset reference after clear"); },
  getElementById() { return null; },
};
const PAGE_META = {overview: {eyebrow: "Diagnosis", title: "Overview", description: "Overview."},
                   wifi: {eyebrow: "Network module", title: "Wi-Fi", description: "Wi-Fi."}};
const MODULE_IDS = ["route", "wifi", "dns", "lan", "mdns", "ports"];
let currentView = "wifi";
let sessionGeneration = 9;
let startInFlight = true;
let cancelInFlight = true;
let revokeInFlight = true;
let pollInFlight = true;
let authenticated = true;
let csrfToken = "token";
let sessionCleared = false;
let statusSnapshot = {state: "completed"};
const pageEyebrow = {textContent: ""};
const pageTitle = {textContent: ""};
const pageDescription = {textContent: ""};
const pageContent = {
  last: null,
  contains() { return false; },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  replaceChildren(value) { this.last = value; },
};
const mobileDrawerQuery = {matches: false};
const primarySidebar = {classList: {contains() { return false; }}};
const newCheckButton = {disabled: false};
const endSessionButton = {disabled: false};
const mobileEndSessionButton = {disabled: false};
const cancelButton = {disabled: false};
const connectionState = {textContent: "Private local session"};
const runAnnouncement = {textContent: "old run copy"};
function stopSessionExpiryTimer() {}
function stopPolling() {}
function stopStatusStream() {}
function setSessionActionsDisabled(disabled) {
  endSessionButton.disabled = disabled;
  mobileEndSessionButton.disabled = disabled;
}
function showNotice() {}
function closeSidebar() { throw new Error("desktop clear moved drawer focus"); }
function renderProgress() {}
function unexpectedRenderer() { throw new Error("authenticated renderer ran after clear"); }
const renderOverview = unexpectedRenderer;
const renderDevice = unexpectedRenderer;
const renderNetwork = unexpectedRenderer;
const renderModule = unexpectedRenderer;
const renderFixes = unexpectedRenderer;
const renderRescue = unexpectedRenderer;
const renderSession = unexpectedRenderer;
const renderShare = unexpectedRenderer;

function reset() {
  authenticated = true;
  csrfToken = "token";
  sessionCleared = false;
  statusSnapshot = {state: "completed"};
  runAnnouncement.textContent = "old run copy";
  pageContent.last = null;
}
function assertRequestFreeClosedView() {
  if (resourceRequests !== 0 || apiRequests !== 0 || !sessionCleared || authenticated ||
      statusSnapshot !== null || runAnnouncement.textContent !== "" ||
      pageTitle.textContent !== "Local session closed" || !pageContent.last ||
      !pageContent.last.textContent.includes("Lantern is disconnected") ||
      !pageContent.last.textContent.includes("Launch Lantern again")) {
    throw new Error("closed view was not request-free and self-contained");
  }
}
"""
    checks = r"""
for (const message of [
  "The private local session ended. Launch Lantern again to reconnect.",
  "The private local session expired. Launch Lantern again to continue.",
  "The private local session expired. Launch Lantern again to continue.",
]) {
  reset();
  clearSession(message, message.includes("ended") ? "info" : "attention");
  assertRequestFreeClosedView();
}
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input=(
            '"use strict";\n' + harness + create_element + unavailable + renderer + clear + checks
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_session_expiry_timer_is_absolute_replaced_and_fail_closed(client: str) -> None:
    stop_timer = (
        "function stopSessionExpiryTimer"
        + client.split("function stopSessionExpiryTimer", 1)[1].split(
            "function armSessionExpiry", 1
        )[0]
    )
    arm_timer = (
        "function armSessionExpiry"
        + client.split("function armSessionExpiry", 1)[1].split("function clearSession", 1)[0]
    )
    establish = client.split("async function establishSession", 1)[1].split(
        "async function refreshCsrfAfterForbidden", 1
    )[0]
    refresh = client.split("async function refreshCsrfAfterForbidden", 1)[1].split(
        "async function postMutation", 1
    )[0]
    assert "armSessionExpiry(session.expires_in, activeGeneration)" in establish
    assert "armSessionExpiry(session.expires_in, generation)" in refresh
    assert "performance.now() + lifetimeMs" in arm_timer
    assert "Date.now()" not in arm_timer

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    harness = r"""
let sessionExpiryTimer = null;
let sessionExpiresAt = 0;
let authenticated = true;
let sessionGeneration = 1;
let monotonicNow = 1000;
let nextTimer = 1;
const scheduled = new Map();
const clearedTimers = [];
const messages = [];
Object.defineProperty(globalThis, "performance", {
  value: {now: () => monotonicNow},
  configurable: true,
});
const window = {
  setTimeout(callback, delay) {
    const id = nextTimer++;
    scheduled.set(id, {callback: callback, delay: delay});
    return id;
  },
  clearTimeout(id) {
    clearedTimers.push(id);
    scheduled.delete(id);
  },
};
function clearSession(message) { messages.push(message); stopSessionExpiryTimer(); }
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
"""
    checks = r"""
armSessionExpiry(10, 1);
const first = sessionExpiryTimer;
if (scheduled.get(first).delay !== 9000) throw new Error("wrong first deadline");
armSessionExpiry(20, 1);
const second = sessionExpiryTimer;
if (!clearedTimers.includes(first) || second === first) throw new Error("timer not replaced");
const deadline = sessionExpiresAt;
monotonicNow = deadline - 1;
scheduled.get(second).callback();
if (messages.length !== 0) throw new Error("session expired early");
const finalTimer = sessionExpiryTimer;
monotonicNow = deadline;
scheduled.get(finalTimer).callback();
if (messages.length !== 1 || !messages[0].includes("expired")) throw new Error("no expiry");
if (sessionExpiryTimer !== null || sessionExpiresAt !== 0) throw new Error("timer retained");
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + stop_timer + arm_timer + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_async_session_generation_is_checked_at_every_client_boundary(client: str) -> None:
    assert "let sessionGeneration = 0" in client
    assert "function isCurrentSession(generation)" in client
    assert "function requireCurrentSession(generation)" in client
    clear = client.split("function clearSession", 1)[1].split(
        "function setSessionActionsDisabled", 1
    )[0]
    assert clear.index("sessionGeneration += 1") < clear.index("authenticated = false")
    assert "startInFlight = false" in clear
    assert "cancelInFlight = false" in clear
    assert "revokeInFlight = false" in clear

    establish = client.split("async function establishSession", 1)[1].split(
        "async function refreshCsrfAfterForbidden", 1
    )[0]
    assert establish.count("expectedGeneration !== sessionGeneration") >= 4
    assert "await pollStatus(false, activeGeneration)" in establish

    refresh = client.split("async function refreshCsrfAfterForbidden", 1)[1].split(
        "async function postMutation", 1
    )[0]
    assert refresh.count("requireCurrentSession(generation)") >= 4

    mutation = client.split("async function postMutation", 1)[1].split("function stopPolling", 1)[0]
    assert mutation.count("requireCurrentSession(generation)") >= 4

    polling = client.split("async function pollStatus", 1)[1].split("function showNotice", 1)[0]
    assert polling.count("isCurrentSession(generation)") >= 5

    for name, following in (
        ("startCheck", "cancelCheck"),
        ("cancelCheck", "revokeSession"),
        ("revokeSession", "document.addEventListener"),
    ):
        block = client.split(f"async function {name}", 1)[1].split(
            f"async function {following}"
            if following != "document.addEventListener"
            else following,
            1,
        )[0]
        assert "const generation = sessionGeneration" in block
        assert "requireCurrentSession(generation)" in block
        assert "isCurrentSession(generation)" in block


def test_delayed_session_establishment_cannot_restore_cleared_authority(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    establish = (
        "async function establishSession"
        + client.split("async function establishSession", 1)[1].split(
            "async function refreshCsrfAfterForbidden", 1
        )[0]
    )
    harness = r"""
let launchToken;
let authenticated;
let sessionGeneration;
let csrfToken;
let fetchMode;
let fetchGate;
let bodyGate;
let readCalls;
let validateCalls;
let armCalls;
let pollCalls;
let noticeMutations;
let closedCopy;
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise: promise, resolve: resolve};
}
async function apiFetch() {
  if (fetchMode === "pending") return await fetchGate.promise;
  return {status: 200, ok: true};
}
async function readJson() {
  readCalls += 1;
  return await bodyGate.promise;
}
async function failureMessage() { return "connection failed"; }
function validateSession(value) {
  validateCalls += 1;
  return value;
}
function armSessionExpiry() { armCalls += 1; }
async function pollStatus() { pollCalls += 1; }
function setSessionActionsDisabled() { noticeMutations += 1; }
function hideNotice() { noticeMutations += 1; }
const connectionState = {textContent: "Local session closed"};
const newCheckButton = {disabled: true};
function clearSession(message) {
  sessionGeneration += 1;
  authenticated = false;
  csrfToken = null;
  closedCopy = message;
  connectionState.textContent = "Local session closed";
  newCheckButton.disabled = true;
}
function reset(mode) {
  launchToken = null;
  authenticated = false;
  sessionGeneration = 0;
  csrfToken = null;
  fetchMode = mode;
  fetchGate = deferred();
  bodyGate = deferred();
  readCalls = 0;
  validateCalls = 0;
  armCalls = 0;
  pollCalls = 0;
  noticeMutations = 0;
  closedCopy = "";
  connectionState.textContent = "Local session closed";
  newCheckButton.disabled = true;
}
function assertClosed(label) {
  if (authenticated || sessionGeneration !== 1 || csrfToken !== null ||
      connectionState.textContent !== "Local session closed" || !newCheckButton.disabled ||
      validateCalls !== 0 || armCalls !== 0 || pollCalls !== 0 || noticeMutations !== 0 ||
      closedCopy !== label) {
    throw new Error("stale establishment restored authority after " + label);
  }
}
"""
    checks = r"""
async function staleFetch() {
  reset("pending");
  const pending = establishSession();
  await Promise.resolve();
  clearSession("expired during session fetch");
  fetchGate.resolve({status: 200, ok: true});
  await pending;
  if (readCalls !== 0) throw new Error("stale establishment read a response body");
  assertClosed("expired during session fetch");
}
async function staleBody() {
  reset("ready");
  const pending = establishSession();
  for (let turn = 0; turn < 5 && readCalls === 0; turn += 1) {
    await Promise.resolve();
  }
  if (readCalls !== 1) throw new Error("establishment did not reach deferred body");
  clearSession("revoked during session body");
  bodyGate.resolve({csrf_token: "new-session-token", expires_in: 900});
  await pending;
  assertClosed("revoked during session body");
}
(async () => {
  await staleFetch();
  await staleBody();
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + establish + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_delayed_status_cannot_resurrect_expired_or_revoked_session(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    polling = (
        "async function pollStatus"
        + client.split("async function pollStatus", 1)[1].split("function showNotice", 1)[0]
    )
    stop_timer = (
        "function stopSessionExpiryTimer"
        + client.split("function stopSessionExpiryTimer", 1)[1].split(
            "function armSessionExpiry", 1
        )[0]
    )
    arm_timer = (
        "function armSessionExpiry"
        + client.split("function armSessionExpiry", 1)[1].split("function clearSession", 1)[0]
    )
    harness = r"""
const POLL_IDLE_MS = 2500;
const POLL_RUNNING_MS = 700;
let authenticated;
let sessionGeneration;
let pollInFlight;
let pollTimer;
let statusSnapshot;
let sessionExpiryTimer;
let sessionExpiresAt;
let monotonicNow = 1000;
let activeRequest;
let statusBody;
let bodyPending;
let readCalls;
let viewMutations;
let closedCopy;
let nextTimer = 1;
const scheduled = new Map();
Object.defineProperty(globalThis, "performance", {
  value: {now: () => monotonicNow}, configurable: true,
});
const window = {
  setTimeout(callback, delay) {
    const id = nextTimer++;
    scheduled.set(id, {callback: callback, delay: delay});
    return id;
  },
  clearTimeout(id) { scheduled.delete(id); },
};
const connectionState = {textContent: ""};
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise: promise, resolve: resolve};
}
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
function stopPolling() {
  if (pollTimer !== null) window.clearTimeout(pollTimer);
  pollTimer = null;
}
function clearSession(message) {
  sessionGeneration += 1;
  authenticated = false;
  stopSessionExpiryTimer();
  stopPolling();
  pollInFlight = false;
  statusSnapshot = null;
  closedCopy = message;
  connectionState.textContent = "Local session closed";
}
async function apiFetch() { return await activeRequest.promise; }
async function readJson() {
  readCalls += 1;
  if (bodyPending) return await statusBody.promise;
  return {state: "ready", assessment: {sentence: "stale diagnosis"},
          path: [{id: "device", detail: "stale path"}]};
}
async function failureMessage() { return "stale failure"; }
function validateStatus(value) { return value; }
function showNotice() { viewMutations += 1; }
function hideNotice() { viewMutations += 1; }
function announceState() { viewMutations += 1; }
function renderCurrentView() { viewMutations += 1; }
function schedulePoll() { viewMutations += 1; }
function reset(pendingBody) {
  authenticated = true;
  sessionGeneration = 10;
  pollInFlight = false;
  pollTimer = null;
  statusSnapshot = {state: "running", marker: "old"};
  sessionExpiryTimer = null;
  sessionExpiresAt = 0;
  activeRequest = deferred();
  statusBody = deferred();
  bodyPending = Boolean(pendingBody);
  readCalls = 0;
  viewMutations = 0;
  closedCopy = "";
}
"""
    checks = r"""
async function directInvalidation(label) {
  reset();
  const generation = sessionGeneration;
  const pending = pollStatus(false, generation);
  await Promise.resolve();
  clearSession(label);
  activeRequest.resolve({status: 200, ok: true});
  await pending;
  if (authenticated || statusSnapshot !== null || readCalls !== 0 || viewMutations !== 0 ||
      connectionState.textContent !== "Local session closed" || closedCopy !== label) {
    throw new Error("stale status resurrected " + label);
  }
}
async function bodyInvalidation(label) {
  reset(true);
  const generation = sessionGeneration;
  const pending = pollStatus(false, generation);
  activeRequest.resolve({status: 200, ok: true});
  for (let turn = 0; turn < 5 && readCalls === 0; turn += 1) await Promise.resolve();
  if (readCalls !== 1) throw new Error("status did not reach deferred body");
  clearSession(label);
  statusBody.resolve({state: "ready", assessment: {sentence: "stale diagnosis"},
                      path: [{id: "device", detail: "stale path"}]});
  await pending;
  if (authenticated || statusSnapshot !== null || readCalls !== 1 || viewMutations !== 0 ||
      connectionState.textContent !== "Local session closed" || closedCopy !== label) {
    throw new Error("stale status body resurrected " + label);
  }
}
async function ttlOneExpiry() {
  reset();
  const generation = sessionGeneration;
  armSessionExpiry(1, generation);
  const expiryTimer = sessionExpiryTimer;
  const pending = pollStatus(false, generation);
  await Promise.resolve();
  monotonicNow = sessionExpiresAt;
  scheduled.get(expiryTimer).callback();
  activeRequest.resolve({status: 200, ok: true});
  await pending;
  if (authenticated || statusSnapshot !== null || readCalls !== 0 || viewMutations !== 0 ||
      !closedCopy.includes("expired")) {
    throw new Error("TTL=1 stale status resurrection");
  }
}
(async () => {
  await directInvalidation("expired");
  await directInvalidation("revoked");
  await bodyInvalidation("expired during status body");
  await bodyInvalidation("revoked during status body");
  await ttlOneExpiry();
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + stop_timer + arm_timer + polling + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_stale_csrf_refresh_cannot_replace_token_or_rearm_expiry(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    refresh = (
        "async function refreshCsrfAfterForbidden"
        + client.split("async function refreshCsrfAfterForbidden", 1)[1].split(
            "async function postMutation", 1
        )[0]
    )
    harness = r"""
const STALE_SESSION = Object.freeze({reason: "stale"});
let authenticated;
let sessionGeneration;
let csrfToken;
let fetchMode;
let fetchGate;
let bodyGate;
let readCalls;
let validateCalls;
let armCalls;
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise: promise, resolve: resolve};
}
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
function requireCurrentSession(generation) {
  if (!isCurrentSession(generation)) throw STALE_SESSION;
}
async function apiFetch() {
  if (fetchMode === "pending") return await fetchGate.promise;
  return {status: 200, ok: true};
}
async function readJson() {
  readCalls += 1;
  return await bodyGate.promise;
}
function validateSession(value) {
  validateCalls += 1;
  return value;
}
function armSessionExpiry() { armCalls += 1; }
function clearSession() {
  sessionGeneration += 1;
  authenticated = false;
  csrfToken = null;
}
function reset(mode) {
  authenticated = true;
  sessionGeneration = 20;
  csrfToken = "old-token";
  fetchMode = mode;
  fetchGate = deferred();
  bodyGate = deferred();
  readCalls = 0;
  validateCalls = 0;
  armCalls = 0;
}
"""
    checks = r"""
async function staleFetch() {
  reset("pending");
  const pending = refreshCsrfAfterForbidden(20).catch((error) => error);
  await Promise.resolve();
  clearSession();
  fetchGate.resolve({status: 200, ok: true});
  const result = await pending;
  if (result !== STALE_SESSION || readCalls !== 0 || validateCalls !== 0 || armCalls !== 0 ||
      csrfToken !== null || authenticated) {
    throw new Error("stale refresh fetch replaced authority");
  }
}
async function staleBody() {
  reset("ready");
  const pending = refreshCsrfAfterForbidden(20).catch((error) => error);
  await Promise.resolve();
  await Promise.resolve();
  if (readCalls !== 1) throw new Error("refresh did not reach deferred body");
  clearSession();
  bodyGate.resolve({csrf_token: "new-token", expires_in: 900});
  const result = await pending;
  if (result !== STALE_SESSION || validateCalls !== 0 || armCalls !== 0 ||
      csrfToken !== null || authenticated) {
    throw new Error("stale refresh body replaced authority");
  }
}
(async () => {
  await staleFetch();
  await staleBody();
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + refresh + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_stale_csrf_retry_cannot_send_again_or_return_a_response(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    refresh_and_mutation = (
        "async function refreshCsrfAfterForbidden"
        + client.split("async function refreshCsrfAfterForbidden", 1)[1].split(
            "function stopPolling", 1
        )[0]
    )
    harness = r"""
const STALE_SESSION = Object.freeze({reason: "stale"});
let authenticated;
let sessionGeneration;
let csrfToken;
let scenario;
let fetchCalls;
let refreshGate;
let retryGate;
let readCalls;
let armCalls;
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise: promise, resolve: resolve};
}
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
function requireCurrentSession(generation) {
  if (!isCurrentSession(generation)) throw STALE_SESSION;
}
async function apiFetch() {
  fetchCalls += 1;
  if (fetchCalls === 1) return {status: 403, ok: false};
  if (fetchCalls === 2 && scenario === "pending-refresh") return await refreshGate.promise;
  if (fetchCalls === 2) return {status: 200, ok: true};
  if (fetchCalls === 3) return await retryGate.promise;
  throw new Error("unexpected extra mutation request");
}
async function readJson() {
  readCalls += 1;
  return {csrf_token: "refreshed-token", expires_in: 900};
}
function validateSession(value) { return value; }
function armSessionExpiry() { armCalls += 1; }
function clearSession() {
  sessionGeneration += 1;
  authenticated = false;
  csrfToken = null;
}
function reset(nextScenario) {
  authenticated = true;
  sessionGeneration = 40;
  csrfToken = "old-token";
  scenario = nextScenario;
  fetchCalls = 0;
  refreshGate = deferred();
  retryGate = deferred();
  readCalls = 0;
  armCalls = 0;
}
"""
    checks = r"""
async function staleRefreshFetch() {
  reset("pending-refresh");
  const pending = postMutation("/api/diagnostics/cancel", {}, true, 40)
    .catch((error) => error);
  for (let turn = 0; turn < 5 && fetchCalls < 2; turn += 1) await Promise.resolve();
  if (fetchCalls !== 2) throw new Error("mutation did not reach CSRF refresh");
  clearSession();
  refreshGate.resolve({status: 200, ok: true});
  const result = await pending;
  if (result !== STALE_SESSION || fetchCalls !== 2 || readCalls !== 0 || armCalls !== 0 ||
      authenticated || csrfToken !== null) {
    throw new Error("stale refresh retried a mutation");
  }
}
async function staleRetryFetch() {
  reset("pending-retry");
  const pending = postMutation("/api/diagnostics/cancel", {}, true, 40)
    .catch((error) => error);
  for (let turn = 0; turn < 10 && fetchCalls < 3; turn += 1) await Promise.resolve();
  if (fetchCalls !== 3 || readCalls !== 1 || armCalls !== 1 ||
      csrfToken !== "refreshed-token") {
    throw new Error("mutation did not reach its single authorized retry");
  }
  clearSession();
  retryGate.resolve({status: 200, ok: true});
  const result = await pending;
  if (result !== STALE_SESSION || fetchCalls !== 3 || authenticated || csrfToken !== null) {
    throw new Error("stale mutation retry returned into a closed session");
  }
}
(async () => {
  await staleRefreshFetch();
  await staleRetryFetch();
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + refresh_and_mutation + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_stale_start_cancel_and_revoke_responses_are_silently_discarded(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    start = (
        "async function startCheck"
        + client.split("async function startCheck", 1)[1].split("async function cancelCheck", 1)[0]
    )
    cancel = (
        "async function cancelCheck"
        + client.split("async function cancelCheck", 1)[1].split("async function revokeSession", 1)[
            0
        ]
    )
    revoke = (
        "async function revokeSession"
        + client.split("async function revokeSession", 1)[1].split("document.addEventListener", 1)[
            0
        ]
    )
    harness = r"""
const STALE_SESSION = Object.freeze({reason: "stale"});
let authenticated;
let sessionGeneration;
let statusSnapshot;
let startInFlight;
let cancelInFlight;
let revokeInFlight;
let draftGoal;
let draftBasic;
let draftMdns;
let activeRequest;
let activeBody;
let readCalls;
let notices;
let polls;
let renders;
let progressRenders;
let closedCopy;
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise: promise, resolve: resolve};
}
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
function requireCurrentSession(generation) {
  if (!isCurrentSession(generation)) throw STALE_SESSION;
}
async function postMutation() { return await activeRequest.promise; }
async function readJson() { readCalls += 1; return await activeBody.promise; }
async function failureMessage() { return "stale failure"; }
function exactKeys() { return true; }
function boundedText(value) { return value; }
function showNotice() { notices += 1; }
async function pollStatus() { polls += 1; }
function renderCurrentView() { renders += 1; }
function renderProgress() { progressRenders += 1; }
const endSessionButton = {disabled: false};
const mobileEndSessionButton = {disabled: false};
function setSessionActionsDisabled(disabled) {
  endSessionButton.disabled = disabled;
  mobileEndSessionButton.disabled = disabled;
}
const mobileDrawerQuery = {matches: true};
const sessionNotice = {focus() { throw new Error("stale response moved focus"); }};
function closeSidebar() { throw new Error("stale response closed drawer again"); }
function reset(state) {
  authenticated = true;
  sessionGeneration = 30;
  statusSnapshot = {state: state};
  startInFlight = false;
  cancelInFlight = false;
  revokeInFlight = false;
  draftGoal = "network";
  draftBasic = true;
  draftMdns = true;
  activeRequest = deferred();
  activeBody = deferred();
  readCalls = 0;
  notices = 0;
  polls = 0;
  renders = 0;
  progressRenders = 0;
  closedCopy = "";
  setSessionActionsDisabled(false);
}
function invalidate(label) {
  sessionGeneration += 1;
  authenticated = false;
  statusSnapshot = null;
  startInFlight = false;
  cancelInFlight = false;
  revokeInFlight = false;
  closedCopy = label;
  setSessionActionsDisabled(true);
}
"""
    checks = r"""
async function race(action, label) {
  reset(action === "cancel" ? "running" : "completed");
  const pending = action === "start" ? startCheck() :
                  action === "cancel" ? cancelCheck() : revokeSession();
  await Promise.resolve();
  const rendersAtClear = renders;
  const progressAtClear = progressRenders;
  invalidate(label);
  activeRequest.resolve({status: 202, ok: true});
  await pending;
  if (authenticated || statusSnapshot !== null || closedCopy !== label || readCalls !== 0 ||
      notices !== 0 || polls !== 0 || renders !== rendersAtClear ||
      progressRenders !== progressAtClear || startInFlight || cancelInFlight || revokeInFlight) {
    throw new Error("stale " + action + " response mutated expired UI");
  }
  if (draftBasic !== true || draftMdns !== true) {
    throw new Error("stale accepted start reset future consent");
  }
  if (!endSessionButton.disabled || !mobileEndSessionButton.disabled) {
    throw new Error("stale response re-enabled revoke controls");
  }
}
async function raceBody(action, label) {
  reset(action === "cancel" ? "running" : "completed");
  const pending = action === "start" ? startCheck() :
                  action === "cancel" ? cancelCheck() : revokeSession();
  activeRequest.resolve({status: action === "start" ? 202 : 200, ok: true});
  for (let turn = 0; turn < 5 && readCalls === 0; turn += 1) await Promise.resolve();
  if (readCalls !== 1) throw new Error(action + " did not reach deferred body");
  const rendersAtClear = renders;
  const progressAtClear = progressRenders;
  invalidate(label);
  activeBody.resolve(action === "start" ? {accepted: true} :
                     action === "cancel" ? {cancel_requested: true} : {revoked: true});
  await pending;
  if (authenticated || statusSnapshot !== null || closedCopy !== label || readCalls !== 1 ||
      notices !== 0 || polls !== 0 || renders !== rendersAtClear ||
      progressRenders !== progressAtClear || startInFlight || cancelInFlight || revokeInFlight) {
    throw new Error("stale " + action + " body mutated expired UI");
  }
  if (draftBasic !== true || draftMdns !== true) {
    throw new Error("stale accepted start body reset future consent");
  }
  if (!endSessionButton.disabled || !mobileEndSessionButton.disabled) {
    throw new Error("stale response body re-enabled revoke controls");
  }
}
(async () => {
  for (const label of ["expired", "revoked"]) {
    await race("start", label);
    await race("cancel", label);
    await race("revoke", label);
    await raceBody("start", label + " during body");
    await raceBody("cancel", label + " during body");
    await raceBody("revoke", label + " during body");
  }
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + start + cancel + revoke + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_csrf_refresh_is_triggered_only_by_explicit_403_and_start_is_not_retried(
    client: str,
) -> None:
    mutation = client.split("async function postMutation", 1)[1].split("function stopPolling", 1)[0]
    assert mutation.count("refreshCsrfAfterForbidden(generation)") == 1
    assert mutation.index("response.status === 403") < mutation.index(
        "refreshCsrfAfterForbidden(generation)"
    )
    assert "if (!retryAfterRefresh)" in mutation
    assert 'postMutation("/api/diagnostics/start", requestBody, false, generation)' in client
    assert 'postMutation("/api/diagnostics/cancel", {}, true, generation)' in client
    assert 'postMutation("/api/session/revoke", {}, true, generation)' in client
    assert "setTimeout(startCheck" not in client


def test_desktop_and_mobile_revoke_share_one_double_submit_safe_flow(
    client: str, interface: str
) -> None:
    assert interface.count('id="end-session-button"') == 1
    assert interface.count('id="mobile-end-session-button"') == 1
    assert "End local session" in interface
    assert 'tabindex="-1" aria-live="polite"' in interface
    assert "let revokeInFlight = false" in client
    assert "if (!authenticated || revokeInFlight)" in client
    assert "setSessionActionsDisabled(true)" in client
    assert "endSessionButton.disabled = disabled" in client
    assert "mobileEndSessionButton.disabled = disabled" in client
    assert 'postMutation("/api/session/revoke", {}, true, generation)' in client
    assert "sessionNotice.focus()" in client  # Desktop feedback target.
    assert "closeSidebar(true)" in client  # Mobile restores the menu control.
    assert client.count("void revokeSession()") == 2


def test_revoke_runtime_canary_prevents_double_submit_and_announces_success(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    revoke = (
        "async function revokeSession"
        + client.split("async function revokeSession", 1)[1].split("document.addEventListener", 1)[
            0
        ]
    )
    harness = r"""
let authenticated = true;
let sessionGeneration = 7;
let revokeInFlight = false;
let postCalls = 0;
let resolvePost;
let cleared = 0;
let closed = 0;
let menuFocused = 0;
const endSessionButton = {disabled: false, focus() {}};
const mobileEndSessionButton = {disabled: false, focus() {}};
const sessionNotice = {focus() { throw new Error("mobile focus escaped to main"); }};
const mobileDrawerQuery = {matches: true};
const menuToggle = {focus() { menuFocused += 1; }};
function setSessionActionsDisabled(disabled) {
  endSessionButton.disabled = disabled;
  mobileEndSessionButton.disabled = disabled;
}
function isCurrentSession(generation) {
  return authenticated && generation === sessionGeneration;
}
function requireCurrentSession(generation) {
  if (!isCurrentSession(generation)) throw new Error("stale");
}
async function postMutation(route, body, retry, generation) {
  if (route !== "/api/session/revoke" || Object.keys(body).length || retry !== true ||
      generation !== sessionGeneration) {
    throw new Error("wrong revoke authority");
  }
  postCalls += 1;
  return await new Promise((resolve) => { resolvePost = resolve; });
}
async function readJson() { return {revoked: true}; }
function exactKeys(value) { return Object.keys(value).length === 1 && value.revoked === true; }
async function failureMessage() { return "failure"; }
function clearSession(message, tone) {
  if (!message.includes("ended")) throw new Error("dishonest success message");
  if (tone !== "info") throw new Error("successful revoke was presented as a failure");
  cleared += 1;
  sessionGeneration += 1;
  authenticated = false;
  revokeInFlight = false;
  setSessionActionsDisabled(true);
  if (mobileDrawerQuery.matches) closeSidebar(true);
}
function closeSidebar(restoreFocus) {
  if (!restoreFocus) throw new Error("mobile close did not request focus restore");
  closed += 1;
  menuToggle.focus();
}
function boundedText(value) { return value; }
function showNotice() {}
"""
    checks = r"""
(async () => {
  const first = revokeSession();
  const duplicate = revokeSession();
  await Promise.resolve();
  if (postCalls !== 1 || !revokeInFlight) throw new Error("double submit was not blocked");
  if (!endSessionButton.disabled || !mobileEndSessionButton.disabled) {
    throw new Error("revoke controls remained enabled");
  }
  resolvePost({ok: true});
  await Promise.all([first, duplicate]);
  if (postCalls !== 1 || cleared !== 1 || closed !== 1 || menuFocused !== 1) {
    throw new Error("revoke success path was incomplete");
  }
  if (authenticated || revokeInFlight || sessionGeneration !== 8 || !endSessionButton.disabled ||
      !mobileEndSessionButton.disabled) {
    throw new Error("revoke authority remained live");
  }
  process.stdout.write("ok");
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + revoke + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_mobile_drawer_runtime_canary_contains_focus_and_resets_on_resize(client: str) -> None:
    for token in (
        'window.matchMedia("(max-width: 860px)")',
        "primarySidebar.inert = true",
        'primarySidebar.setAttribute("aria-hidden", "true")',
        "primarySidebar.inert = false",
        'primarySidebar.removeAttribute("aria-hidden")',
        "firstControl.focus()",
        "containDrawerFocus(event)",
        'event.key === "Escape"',
        'sidebarScrim.addEventListener("click"',
        'mobileDrawerQuery.addEventListener("change", synchronizeSidebarMode)',
    ):
        assert token in client
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    drawer = (
        "function openSidebar"
        + client.split("function openSidebar", 1)[1].split("async function startCheck", 1)[0]
    )
    set_view = (
        "function setView"
        + client.split("function setView", 1)[1].split("function openSidebar", 1)[0]
    )
    harness = r"""
function classList() {
  const values = new Set();
  return {
    add(value) { values.add(value); },
    remove(value) { values.delete(value); },
    contains(value) { return values.has(value); },
  };
}
const document = {activeElement: null, querySelectorAll() { return []; }};
function control(name) {
  return {name: name, focus() { document.activeElement = this; }};
}
const first = control("first");
const last = control("last");
const controls = [first, last];
const attributes = new Map([["aria-hidden", "true"]]);
const primarySidebar = {
  classList: classList(),
  inert: true,
  setAttribute(name, value) { attributes.set(name, value); },
  removeAttribute(name) { attributes.delete(name); },
  contains(value) { return controls.includes(value); },
  querySelector() { return first; },
  querySelectorAll() { return controls; },
};
const sidebarScrim = {classList: classList()};
const menuToggle = control("menu");
menuToggle.setAttribute = () => {};
const pageTitle = control("title");
const mobileDrawerQuery = {matches: true};
const PAGE_META = {overview: {}};
let currentView = "overview";
let rendered = 0;
function renderCurrentView() { rendered += 1; }
"""
    checks = r"""
document.activeElement = first;
synchronizeSidebarMode();
if (!primarySidebar.inert || attributes.get("aria-hidden") !== "true" ||
    document.activeElement !== menuToggle) {
  throw new Error("closed mobile drawer remained exposed");
}
openSidebar();
if (primarySidebar.inert || attributes.has("aria-hidden") ||
    document.activeElement !== first || !primarySidebar.classList.contains("is-open")) {
  throw new Error("mobile drawer did not open accessibly");
}
setView("overview", true);
if (!primarySidebar.inert || attributes.get("aria-hidden") !== "true" ||
    document.activeElement !== pageTitle || rendered !== 1) {
  throw new Error("drawer navigation did not focus its destination");
}
openSidebar();
document.activeElement = last;
const forward = {key: "Tab", shiftKey: false, prevented: false,
                 preventDefault() { this.prevented = true; }};
containDrawerFocus(forward);
if (!forward.prevented || document.activeElement !== first) {
  throw new Error("forward focus escaped the drawer");
}
document.activeElement = first;
const reverse = {key: "Tab", shiftKey: true, prevented: false,
                 preventDefault() { this.prevented = true; }};
containDrawerFocus(reverse);
if (!reverse.prevented || document.activeElement !== last) {
  throw new Error("reverse focus escaped the drawer");
}
closeSidebar(true);
if (!primarySidebar.inert || attributes.get("aria-hidden") !== "true" ||
    document.activeElement !== menuToggle) {
  throw new Error("mobile drawer did not close accessibly");
}
mobileDrawerQuery.matches = false;
synchronizeSidebarMode();
if (primarySidebar.inert || attributes.has("aria-hidden") ||
    document.activeElement !== pageTitle) {
  throw new Error("desktop resize retained mobile drawer semantics");
}
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + set_view + drawer + checks,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_start_body_is_exact_passive_by_default_and_basic_is_bounded(client: str) -> None:
    assert 'let draftGoal = "problem"' in client
    assert "let draftBasic = false" in client
    assert "let draftMdns = false" in client
    assert 'const profile = draftBasic ? "low_impact_network" : "passive"' in client
    assert "const includeMdns = draftBasic && draftMdns" in client
    assert (
        "const requestBody = { goal: draftGoal, profile: profile, include_mdns: includeMdns }"
        in client
    )
    assert "active_discovery" in client  # Rejected capability, never a start profile.
    assert 'profile = "active_discovery"' not in client
    assert "target:" not in client
    assert "!authenticated || !statusSnapshot || startInFlight" in client


def test_packet_generating_choices_reset_after_each_accepted_run(client: str) -> None:
    start = client.split("async function startCheck", 1)[1].split("async function cancelCheck", 1)[
        0
    ]
    request_index = start.index(
        "const requestBody = { goal: draftGoal, profile: profile, include_mdns: includeMdns }"
    )
    accepted_index = start.index("result.accepted !== true")
    reset_basic_index = start.index("draftBasic = false", accepted_index)
    reset_mdns_index = start.index("draftMdns = false", accepted_index)
    poll_index = start.index("await pollStatus(true, generation)")
    assert request_index < accepted_index < reset_basic_index < poll_index
    assert accepted_index < reset_mdns_index < poll_index
    assert start.count("draftBasic = false") == 1
    assert start.count("draftMdns = false") == 1

    change = client.split('target.id === "basic-network-checks"', 1)[1].split(
        '} else if (target.id === "include-mdns")', 1
    )[0]
    assert "draftBasic = target.checked" in change
    assert "if (!draftBasic)" in change
    assert "draftMdns = false" in change
    assert "mdns.disabled = !draftBasic" in change
    assert "mdns.checked = draftMdns" in change


def test_consent_copy_names_real_packets_and_mdns_is_separate_opt_in(client: str) -> None:
    for phrase in (
        "It sends no diagnostic packets.",
        "small public reachability probes (ping/ICMP and TCP), DNS queries, and gateway service-port probes",
        "It does not sweep the LAN or change settings.",
        "Off by default.",
        "sends and receives local multicast service-discovery traffic",
    ):
        assert phrase in client
    assert "mdnsInput.disabled = !draftBasic" in client


def test_status_contract_is_exact_bounded_ordered_and_fail_closed(client: str) -> None:
    assert 'value.schema !== "lantern.ui.v2"' in client
    assert 'value.transport !== "loopback"' in client
    assert 'Object.freeze(["route", "wifi", "dns", "lan", "mdns", "ports"])' in client
    for path_id in ("device", "gateway", "internet", "dns", "services"):
        assert f'id: "{path_id}"' in client
    assert 'id: "device", label: "Device route"' in client
    for status in (
        "not_started",
        "queued",
        "running",
        "ok",
        "attention",
        "limited",
        "unavailable",
        "not_run",
        "cancelled",
    ):
        assert f'"{status}"' in client
    assert 'ok: "Completed"' in client
    assert 'ok: "Healthy"' not in client
    assert "value.length !== MODULE_IDS.length" in client
    assert "module.id !== expectedOrder[index]" in client
    assert 'validateModules(value.modules, run ? run.goal : "problem")' in client
    assert 'requiredSafeText(module.detail, 500, "module detail")' in client
    assert 'requiredSafeText(module.finding, 180, "module finding")' in client
    assert "module.technical.length > 4" in client
    assert "value.length > 3" in client
    assert "codes.has(issue.code)" in client
    assert "value.length !== PATH_SPECS.length" in client
    assert "node.id !== spec.id" in client
    assert "node.label !== spec.label" in client
    assert "node.module !== spec.module" in client
    assert 'requiredSafeText(node.detail, 200, "path detail")' in client
    assert 'requiredSafeText(value.sentence, 240, "assessment sentence")' in client
    assert 'requiredSafeText(value.disclaimer, 300, "assessment disclaimer")' in client
    assert "assessment.tone !== summary.tone" in client
    assert 'value.state === "completed" && assessment.tone === "neutral"' in client
    assert '(value.coverage === "none") !== (value.confidence === "none")' in client
    assert 'value.coverage === "partial" && value.confidence !== "low"' in client
    assert 'state === "ready" || state === "running" || state === "failed"' in client
    assert "disclaimer !== NETWORK_DISCLAIMER" in client
    assert "not a whole-network assessment, security audit, or compliance certification" in client
    assert "boundedInteger(value.percent, 0, 100)" in client
    assert 'value.profile === "passive" && value.include_mdns' in client
    assert '(value.state === "ready") !== (run === null)' in client
    assert 'value.state === "cancelled" && run.cancel_requested !== true' in client
    assert "Math.round(value.processed * 100 / value.planned)" in client
    assert "value.percent !== expectedPercent" in client


def test_status_validator_runtime_canaries_fail_closed(client: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")

    declarations = (
        "const MODULE_IDS" + client.split("const MODULE_IDS", 1)[1].split("let csrfToken", 1)[0]
    )
    validators = (
        "function boundedText"
        + client.split("function boundedText", 1)[1].split("async function apiFetch", 1)[0]
    )
    harness = r"""
const networkBoundary = "This is an informational evaluation from one endpoint, not a whole-network assessment, security audit, or compliance certification for a home, business, financial system, or municipality.";
const base = {
  schema: "lantern.ui.v2",
  product: "Lantern",
  transport: "loopback",
  state: "completed",
  summary: {tone: "attention", headline: "Complete", detail: "Bounded result."},
  assessment: {sentence: "Lantern completed a bounded network assessment.", tone: "attention",
               confidence: "medium", coverage: "complete", disclaimer: networkBoundary},
  issues: [],
  path: PATH_SPECS.map((item) => ({id: item.id, label: item.label, status: "ok",
                                  detail: "This path stage completed.", module: item.module})),
  run: {goal: "network", profile: "passive", include_mdns: false,
        cancel_requested: false, duration_ms: 1},
  progress: {processed: 2, planned: 2, percent: 100},
  modules: GOAL_MODULE_ORDER.network.map((id) => ({id: id, label: PAGE_META[id].title,
                                    status: "ok", detail: "Complete.",
                                    finding: "No issue was reported by this module.",
                                    why_it_matters: "This module helps explain one bounded layer of the network path.",
                                    technical: ["The bounded module reached a terminal state."]})),
  capabilities: {passive_scan: true, low_impact_network: true,
                 active_discovery: false, remediation: false, credentials: false,
                 lan_remote: false, rescue_boot: false, share_export: true},
};
function copy() { return JSON.parse(JSON.stringify(base)); }
function mustReject(change) {
  const candidate = copy();
  change(candidate);
  let rejected = false;
  try { validateStatus(candidate); } catch (_error) { rejected = true; }
  if (!rejected) { throw new Error("validator accepted a contract canary"); }
}
validateStatus(copy());
mustReject((value) => { value.summary.tone = "neutral"; value.assessment.tone = "neutral"; });
mustReject((value) => { value.run.include_mdns = true; });
mustReject((value) => { value.state = "ready"; });
mustReject((value) => { value.state = "cancelled"; });
mustReject((value) => { value.state = "failed"; });
mustReject((value) => { value.run = null; });
mustReject((value) => { value.progress.percent = 99; });
mustReject((value) => { value.progress.processed = true; });
mustReject((value) => { value.capabilities.remediation = true; });
mustReject((value) => { value.modules.reverse(); });
mustReject((value) => { value.extra = true; });
mustReject((value) => { value.assessment.tone = "positive"; });
mustReject((value) => { value.assessment.coverage = "partial"; });
mustReject((value) => { value.assessment.coverage = "none"; });
mustReject((value) => { value.assessment.confidence = "none"; });
mustReject((value) => { value.assessment.sentence = "x".repeat(241); });
mustReject((value) => { value.assessment.disclaimer = "Informational only."; });
mustReject((value) => { value.summary.tone = "positive"; value.assessment.tone = "positive";
  value.modules[0].status = "limited"; });
mustReject((value) => { value.summary.tone = "neutral"; value.assessment.tone = "neutral";
  value.path[0].status = "attention"; });
mustReject((value) => { value.summary.tone = "neutral"; value.assessment.tone = "neutral";
  value.modules[0].status = "attention"; });
mustReject((value) => { value.path.reverse(); });
mustReject((value) => { value.path[1].id = "device"; });
mustReject((value) => { value.path[0].module = "wifi"; });
mustReject((value) => { value.path[0].status = "healthy"; });
mustReject((value) => { value.path[0].detail = "x".repeat(201); });
mustReject((value) => { value.path[0].extra = "unsafe"; });
mustReject((value) => { value.modules[0].finding = "x".repeat(181); });
mustReject((value) => { value.modules[0].technical = ["a", "b", "c", "d", "e"]; });
mustReject((value) => { value.modules[0].technical = [true]; });
mustReject((value) => { value.modules[0].extra = "unsafe"; });
mustReject((value) => { value.state = "running"; value.summary.tone = "neutral";
  value.assessment.tone = "neutral"; value.modules.forEach((item) => { item.status = "queued"; });
  value.path.forEach((item) => { item.status = "not_run"; });
  value.progress = {processed: 0, planned: 0, percent: 0}; });
mustReject((value) => { value.state = "cancelled"; value.summary.tone = "attention";
  value.assessment.tone = "attention"; });
mustReject((value) => { value.issues = [0, 1, 2, 3].map((index) => ({
  code: "NDG.ROUTE.CHECK_" + String(index), title: "Review route", explanation: "Review.",
  next_step: "Recheck the route.", module: "route", severity: "attention"})); });
mustReject((value) => { value.issues = [
  {code: "NDG.ROUTE.CHECK_FAILED", title: "Review route", explanation: "Review.",
   next_step: "Recheck the route.", module: "route", severity: "attention"},
  {code: "NDG.ROUTE.CHECK_FAILED", title: "Review route again", explanation: "Review.",
   next_step: "Recheck the route.", module: "route", severity: "attention"},
]; });
mustReject((value) => { value.issues = [{code: "unknown", title: "Review route",
  explanation: "Review.", next_step: "Recheck the route.", module: "route",
  severity: "attention"}]; });
mustReject((value) => { value.issues = [{code: "NDG.ROUTE.NOT_REGISTERED", title: "Review route",
  explanation: "Review.", next_step: "Recheck the route.", module: "route",
  severity: "attention"}]; });
mustReject((value) => { value.issues = [{code: "NDG.LAN.ACTIVE_DISCOVERY_NO_SCOPE",
  title: "Review LAN", explanation: "Review.", next_step: "Recheck the LAN.", module: "lan",
  severity: "attention"}]; });
mustReject((value) => { value.issues = [{code: "NDG.DNS.RESOLUTION_FAILED", title: "Review DNS",
  explanation: "Review.", next_step: "Recheck name lookup.", module: "wifi",
  severity: "attention"}]; });
mustReject((value) => { value.issues = [{code: "NDG.ROUTE.OUTBOUND_HTTPS_FAILED",
  title: "Review route", explanation: "Review.", next_step: "Recheck the route.",
  module: "route", severity: "critical"}]; value.summary.tone = "attention";
  value.assessment.tone = "attention"; });
mustReject((value) => { value.issues = [{code: "NDG.DNS.RESOLUTION_FAILED",
  title: "Review DNS", explanation: "Review.", next_step: "Recheck name lookup.",
  module: "dns", severity: "critical"}]; value.summary.tone = "attention";
  value.assessment.tone = "attention"; });
mustReject((value) => { value.issues = [{code: "NDG.ROUTE.CHECK_FAILED", title: "Review route",
  explanation: "Review.", next_step: true, module: "route", severity: "attention"}]; });
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + declarations + validators + harness,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_synthetic_healthy_and_real_limited_offline_cancelled_failed_fixtures_validate(
    client: str,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    declarations = (
        "const MODULE_IDS" + client.split("const MODULE_IDS", 1)[1].split("let csrfToken", 1)[0]
    )
    validators = (
        "function boundedText"
        + client.split("function boundedText", 1)[1].split("async function apiFetch", 1)[0]
    )
    harness = r"""
const networkBoundary = "This is an informational evaluation from one endpoint, not a whole-network assessment, security audit, or compliance certification for a home, business, financial system, or municipality.";
function fixture() {
  return {
    schema: "lantern.ui.v2", product: "Lantern", transport: "loopback",
    state: "completed",
    summary: {tone: "attention", headline: "The bounded observations completed",
              detail: "No adverse observation was reported, but one planned check cannot run in this profile."},
    assessment: {sentence: "No adverse observation was reported, but planned coverage is incomplete.",
                 tone: "attention", confidence: "low", coverage: "partial",
                 disclaimer: networkBoundary},
    issues: [],
    path: PATH_SPECS.map((item) => ({id: item.id, label: item.label, status: "ok",
                                    detail: "No issue was reported for this layer.",
                                    module: item.module})),
    run: {goal: "network", profile: "low_impact_network", include_mdns: true,
          cancel_requested: false, duration_ms: 50},
    progress: {processed: 8, planned: 8, percent: 100},
    modules: GOAL_MODULE_ORDER.network.map((id) => ({id: id, label: PAGE_META[id].title,
      status: id === "lan" ? "limited" : "ok",
      detail: "The bounded module completed.",
      finding: id === "lan" ? "Passive LAN observations completed; active discovery did not run."
                            : "No issue was reported by this module.",
      why_it_matters: "This module helps explain one bounded layer of the network path.",
      technical: ["The module reached a terminal state within the authorized profile."]})),
    capabilities: {passive_scan: true, low_impact_network: true, active_discovery: false,
      remediation: false, credentials: false, lan_remote: false, rescue_boot: false,
      share_export: true},
  };
}
function issue(code, module, severity) {
  return {code: code, title: "A bounded check needs review",
          explanation: "Lantern could not confirm this diagnostic layer.",
          next_step: "Repeat the bounded check before changing settings.",
          module: module, severity: severity};
}
const fixtures = [];
// Phase 2.1's positive healthy branch is presentation-only synthetic coverage.
// Current live profiles cannot produce it because active LAN stays not_run.
const healthy = fixture();
healthy.summary.tone = "positive";
healthy.summary.headline = "Synthetic planned coverage completed";
healthy.summary.detail = "Synthetic presentation data reported no issue.";
healthy.assessment.tone = "positive";
healthy.assessment.coverage = "complete";
healthy.assessment.confidence = "high";
healthy.assessment.sentence = "Synthetic presentation data reported no issue across every layer.";
healthy.modules.find((item) => item.id === "lan").status = "ok";
healthy.modules.find((item) => item.id === "lan").finding = "Synthetic presentation data reported no LAN issue.";
if (healthy.assessment.tone !== "positive" || healthy.assessment.coverage !== "complete" ||
    healthy.modules.some((item) => item.status !== "ok")) {
  throw new Error("synthetic positive branch fixture is incomplete");
}
fixtures.push(["synthetic_healthy", healthy]);

// This is the ideal reachable live projection: no adverse observation, but
// necessarily partial/limited coverage and no whole-run health claim.
const noAdverseLive = fixture();
if (noAdverseLive.assessment.tone !== "attention" ||
    noAdverseLive.assessment.coverage !== "partial" ||
    noAdverseLive.modules.find((item) => item.id === "lan").status !== "limited") {
  throw new Error("live no-adverse fixture overstated real scanner coverage");
}
fixtures.push(["no_adverse_live", noAdverseLive]);

const limited = fixture();
limited.summary.tone = "attention";
limited.assessment.tone = "attention";
limited.assessment.sentence = "Part of the planned diagnostic coverage is limited.";
limited.assessment.confidence = "low";
limited.assessment.coverage = "partial";
limited.path[2].status = "limited";
limited.path[2].detail = "Internet-path evidence is incomplete.";
limited.modules[0].status = "limited";
limited.modules[0].finding = "Part of this module was not included.";
limited.issues = [issue("NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED", "route", "attention")];
fixtures.push(["limited", limited]);

const offline = fixture();
offline.summary.tone = "critical";
offline.assessment.tone = "critical";
offline.assessment.sentence = "The internet path could not be confirmed from this endpoint.";
offline.assessment.confidence = "low";
offline.path[1].status = "unavailable";
offline.path[2].status = "unavailable";
offline.path[1].detail = "The gateway layer is unavailable.";
offline.path[2].detail = "The internet layer is unavailable.";
offline.modules[0].status = "unavailable";
offline.modules[0].finding = "The connection path could not be confirmed.";
offline.issues = [issue("NDG.ROUTE.OUTBOUND_HTTPS_FAILED", "route", "attention")];
fixtures.push(["offline", offline]);

const cancelled = fixture();
cancelled.state = "cancelled";
cancelled.summary.tone = "attention";
cancelled.summary.headline = "The check was cancelled";
cancelled.assessment.tone = "attention";
cancelled.assessment.sentence = "The cancelled run does not support a complete assessment.";
cancelled.assessment.confidence = "low";
cancelled.assessment.coverage = "partial";
cancelled.run.cancel_requested = true;
cancelled.progress = {processed: 8, planned: 8, percent: 100};
cancelled.path.forEach((item) => { item.status = "not_run"; item.detail = "Not checked before cancellation."; });
cancelled.modules.forEach((item) => { item.status = "cancelled"; item.finding = "This module was cancelled."; });
cancelled.capabilities.share_export = true;
fixtures.push(["cancelled", cancelled]);

const failed = fixture();
failed.state = "failed";
failed.summary.tone = "attention";
failed.summary.headline = "The diagnostic could not complete";
failed.assessment.tone = "attention";
failed.assessment.sentence = "The failed run cannot support a network conclusion.";
failed.assessment.confidence = "none";
failed.assessment.coverage = "none";
failed.progress = {processed: 0, planned: 0, percent: 0};
failed.path.forEach((item) => { item.status = "unavailable"; item.detail = "No safe layer status is available."; });
failed.modules.forEach((item) => { item.status = "unavailable"; item.finding = "No safe finding is available."; });
failed.capabilities.share_export = true;
fixtures.push(["failed", failed]);

for (const [name, value] of fixtures) {
  try { validateStatus(value); } catch (error) {
    throw new Error(name + " fixture was rejected: " + String(error));
  }
}
process.stdout.write(fixtures.map((item) => item[0]).join(","));
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + declarations + validators + harness,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ("synthetic_healthy,no_adverse_live,limited,offline,cancelled,failed")


def test_python_v2_lifecycle_snapshots_match_the_javascript_validator(client: str) -> None:
    import importlib.util

    from netdiag.ui.viewmodel import build_ui_viewmodel, ready_ui_viewmodel

    viewmodel_tests = importlib.util.spec_from_file_location(
        "lantern_test_viewmodel",
        Path(__file__).with_name("test_viewmodel.py"),
    )
    assert viewmodel_tests and viewmodel_tests.loader
    module = importlib.util.module_from_spec(viewmodel_tests)
    viewmodel_tests.loader.exec_module(module)
    ideal_low_impact_snapshot = module.ideal_low_impact_snapshot

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    ideal_live = build_ui_viewmodel(ideal_low_impact_snapshot(goal="network"))
    assert ideal_live["assessment"]["tone"] == "attention"
    assert ideal_live["assessment"]["coverage"] == "partial"
    assert next(item for item in ideal_live["modules"] if item["id"] == "lan")["status"] == (
        "limited"
    )
    views = [ready_ui_viewmodel(), ideal_live]
    profiles = (
        ("passive", False),
        ("low_impact_network", False),
        ("low_impact_network", True),
    )
    for state in ("running", "failed"):
        for goal in ("problem", "network", "rescue"):
            for profile, include_mdns in profiles:
                views.append(
                    build_ui_viewmodel(
                        {
                            "state": state,
                            "duration_ms": 3,
                            "run": {
                                "goal": goal,
                                "profile": profile,
                                "include_mdns": include_mdns,
                                "cancel_requested": False,
                            },
                            "progress": {
                                "processed": 0,
                                "planned": 0,
                                "percent": 0,
                                "events": [],
                            },
                            "result": None,
                        }
                    )
                )
    declarations = (
        "const MODULE_IDS" + client.split("const MODULE_IDS", 1)[1].split("let csrfToken", 1)[0]
    )
    validators = (
        "function boundedText"
        + client.split("function boundedText", 1)[1].split("async function apiFetch", 1)[0]
    )
    harness = (
        "const snapshots = "
        + json.dumps(views, separators=(",", ":"))
        + ";\nfor (const snapshot of snapshots) validateStatus(snapshot);\n"
        + "process.stdout.write(String(snapshots.length));\n"
    )
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + declarations + validators + harness,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "20"


def test_phase21_renderers_use_accessible_landmarks_and_progressive_disclosure(
    client: str,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    declarations = (
        "const MODULE_IDS" + client.split("const MODULE_IDS", 1)[1].split("let csrfToken", 1)[0]
    )
    renderers = (
        "function createElement"
        + client.split("function createElement", 1)[1].split("function unavailablePanel", 1)[0]
    )
    harness = r"""
class TestNode {
  constructor(tag, text) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.dataset = {};
    this.className = "";
    this._text = text || "";
  }
  append(...nodes) { for (const node of nodes) if (node !== null && node !== undefined) this.children.push(node); }
  prepend(...nodes) { this.children.unshift(...nodes); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name); }
  get firstElementChild() { return this.children.find((node) => node.tagName !== "#TEXT") || null; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((node) => node.textContent).join(""); }
}
const document = {
  createElement(tag) { return new TestNode(tag); },
  createElementNS(_namespace, tag) { return new TestNode(tag); },
  createTextNode(text) { return new TestNode("#text", String(text)); },
  createDocumentFragment() { return new TestNode("#fragment"); },
};
function descendants(node, tag) {
  const wanted = tag.toUpperCase();
  const found = [];
  function visit(item) {
    if (item.tagName === wanted) found.push(item);
    item.children.forEach(visit);
  }
  visit(node);
  return found;
}
let authenticated = true;
let startInFlight = false;
let draftGoal = "problem";
let draftBasic = false;
let draftMdns = false;
const issueCodes = ["NDG.ROUTE.CHECK_FAILED", "NDG.DNS.RESOLVER_INCONSISTENT", "NDG.WIFI.SIGNAL_WEAK"];
const issueModules = ["route", "dns", "wifi"];
const statusSnapshot = {
  state: "completed",
  summary: {tone: "attention", headline: "Review", detail: "The bounded run found items to review."},
  assessment: {sentence: "Three priority items need review.", tone: "attention",
               confidence: "medium", coverage: "partial",
               disclaimer: "One endpoint cannot certify a wider network."},
  issues: issueCodes.map((code, index) => ({code: code, title: "Priority item " + String(index + 1),
    explanation: "This safe explanation contains no identifier.",
    next_step: "Repeat the bounded module before changing settings.",
    module: issueModules[index], severity: "attention"})),
  path: PATH_SPECS.map((spec, index) => ({id: spec.id, label: spec.label,
    status: index === 2 ? "limited" : "ok", detail: "Bounded layer summary.",
    module: spec.module})),
  modules: MODULE_IDS.map((id) => ({id: id, label: PAGE_META[id].title,
    status: id === "route" ? "attention" : "ok", detail: "Bounded module state.",
    finding: "Safe finding for " + PAGE_META[id].title + ".",
    why_it_matters: "This module helps explain one bounded layer of the network path.",
    technical: ["Identifier-free technical note one.", "Identifier-free technical note two."]})),
  capabilities: {passive_scan: true, low_impact_network: true, active_discovery: false,
    remediation: false, credentials: false, lan_remote: false, rescue_boot: false,
    share_export: true},
};
const assessment = assessmentPanel();
if (descendants(assessment, "dl").length !== 1 || descendants(assessment, "dt").length !== 2 ||
    descendants(assessment, "dd").length !== 2 || !assessment.textContent.includes("Confidence") ||
    !assessment.textContent.includes("Coverage")) {
  throw new Error("assessment metadata is not semantic");
}
const priority = renderPriorityIssues();
const articles = descendants(priority, "article");
if (articles.length !== 3 || articles.some((item) =>
    descendants(item, "strong").filter((part) => part.textContent === "Safe next step").length !== 1)) {
  throw new Error("priority issues do not have one safe next step each");
}
if (issueCodes.some((code) => priority.textContent.includes(code))) {
  throw new Error("renderer exposed internal finding codes");
}
const path = renderLanternPath();
const ordered = descendants(path, "ol");
if (ordered.length !== 1 || descendants(path, "li").length !== 5 ||
    ordered[0].getAttribute("aria-label") !== "Lantern Path diagnostic-layer map" ||
    !path.textContent.includes("not a network topology")) {
  throw new Error("Lantern Path is not an honest accessible ordered map");
}
const module = renderModule("route");
if (descendants(module, "details").length !== 1 || descendants(module, "summary").length !== 1 ||
    !module.textContent.includes("Safe finding summary") ||
    !module.textContent.includes("Identifier-free technical note one.")) {
  throw new Error("module detail is not progressively disclosed");
}
if (descendants(module, "details")[0].id !== "technical-disclosure-route" ||
    descendants(module, "summary")[0].id !== "technical-summary-route") {
  throw new Error("technical disclosure has no stable focus identity");
}
const consent = renderStartPanel();
if (!consent.textContent.includes(
    "Run network checks only on a network you own, manage, or are explicitly authorized to assess.")) {
  throw new Error("network assessment authorization boundary was not rendered");
}

// Synthetic presentation-only coverage for the positive rendering branch.
// Current live profiles cannot produce this all-ok state.
statusSnapshot.assessment.tone = "positive";
statusSnapshot.assessment.coverage = "complete";
statusSnapshot.assessment.sentence = "Synthetic presentation data reported no issue.";
statusSnapshot.issues.splice(0);
statusSnapshot.path.forEach((item) => { item.status = "ok"; });
statusSnapshot.modules.forEach((item) => { item.status = "ok"; });
const syntheticAssessment = assessmentPanel();
const syntheticPriority = renderPriorityIssues();
const syntheticIcons = descendants(syntheticAssessment, "use").map((item) => item.getAttribute("href"));
if (!syntheticAssessment.className.includes("tone-positive") ||
    !syntheticIcons.includes("icons.svg#shield-check") ||
    !syntheticPriority.textContent.includes("No priority issue was returned from the completed plan")) {
  throw new Error("synthetic positive presentation branch was not rendered");
}
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + declarations + renderers + harness,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_goal_changes_priority_emphasis_only_and_never_scan_scope(client: str) -> None:
    assert "Priority emphasis:" in client
    assert "Presentation order:" not in client
    assert (
        "priority emphasis, module presentation order, and priority-issue ordering only" in client
    )
    assert "It never changes the diagnostic profile, packet activity, or scan scope." in client
    assert "from one endpoint" in client
    assert "not a whole-network assessment, security audit, or compliance certification" in client
    assert "home, business, financial system, or municipality" in client
    assert (
        "Run network checks only on a network you own, manage, or are explicitly authorized to assess."
        in client
    )
    assert 'emphasisCopy.setAttribute("aria-live", "polite")' in client
    assert 'emphasis.setAttribute("aria-live", "polite")' not in client
    change = client.split('target.name === "goal"', 1)[1].split(
        '} else if (target.id === "basic-network-checks")', 1
    )[0]
    assert "draftGoal = target.value" in change
    assert "goalEmphasisText(draftGoal)" in change
    start = client.split("async function startCheck", 1)[1].split("async function cancelCheck", 1)[
        0
    ]
    assert start.count("draftGoal") == 1
    assert (
        "const requestBody = { goal: draftGoal, profile: profile, include_mdns: includeMdns }"
        in start
    )


def test_running_rerender_preserves_technical_disclosure_and_summary_focus(
    client: str,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    renderer = (
        "function renderCurrentView"
        + client.split("function renderCurrentView", 1)[1].split("function setView", 1)[0]
    )
    harness = r"""
const MODULE_IDS = ["route", "wifi", "dns", "lan", "mdns", "ports"];
const PAGE_META = {route: {eyebrow: "Network module", title: "Route", description: "Route."},
                   overview: {eyebrow: "Diagnosis", title: "Overview", description: "Overview."}};
let currentView = "route";
let statusSnapshot = {state: "running"};
let sessionCleared = false;
const pageEyebrow = {textContent: ""};
const pageTitle = {textContent: ""};
const pageDescription = {textContent: ""};
let focusCalls = 0;
const active = {id: "technical-summary-route", dataset: {}, name: "", focus() {}};
const replacementSummary = {focus() { focusCalls += 1; }};
const replacementDisclosure = {open: false};
const document = {
  activeElement: active,
  getElementById(id) {
    if (id === "technical-summary-route") return replacementSummary;
    if (id === "technical-disclosure-route") return replacementDisclosure;
    return null;
  },
};
let replaced = 0;
const pageContent = {
  contains(node) { return node === active; },
  querySelector(selector) {
    return selector === "details.technical-disclosure[open]"
      ? {id: "technical-disclosure-route"} : null;
  },
  querySelectorAll() { return []; },
  replaceChildren() { replaced += 1; },
};
function renderProgress() {}
function renderStatusUnavailable() { throw new Error("running view used closed renderer"); }
function renderOverview() { return {}; }
function renderDevice() { return {}; }
function renderNetwork() { return {}; }
function renderModule() { return {}; }
function renderFixes() { return {}; }
function renderRescue() { return {}; }
function renderSession() { return {}; }
function renderShare() { return {}; }
renderCurrentView();
if (replaced !== 1 || !replacementDisclosure.open || focusCalls !== 1) {
  throw new Error("running rerender dropped disclosure state or focus");
}
process.stdout.write("ok");
"""
    result = subprocess.run(
        [node, "-"],
        input='"use strict";\n' + harness + renderer,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok"


def test_dangerous_capabilities_are_rejected_even_if_server_marks_them_true(
    client: str,
) -> None:
    capability_block = client.split("function validateCapabilities", 1)[1].split(
        "function validateStatus", 1
    )[0]
    for capability in (
        "active_discovery",
        "remediation",
        "credentials",
        "lan_remote",
        "rescue_boot",
    ):
        assert f'"{capability}"' in capability_block
    assert '"share_export"' in capability_block
    assert "EXPORT_STATES" in capability_block
    assert "result[name] !== false" in capability_block
    assert "result.passive_scan !== true" in capability_block
    assert "result.low_impact_network !== true" in capability_block


def test_polling_runs_only_during_a_run_and_preserves_dynamic_focus(client: str) -> None:
    streaming = client.split("function openStatusStream", 1)[1].split("function schedulePoll", 1)[0]
    assert 'new EventSource(streamUrl.toString())' in streaming
    assert 'event: "status"' in streaming or 'addEventListener("status"' in streaming
    polling = client.split("async function pollStatus", 1)[1].split("function showNotice", 1)[0]
    assert "schedulePoll(POLL_RUNNING_MS, false, generation)" in polling
    assert "applyStatusSnapshot(nextSnapshot, generation)" in polling

    apply_block = client.split("function applyStatusSnapshot", 1)[1].split("function openStatusStream", 1)[0]
    assert 'statusSnapshot.state === "running"' in apply_block
    assert "openStatusStream(generation)" in apply_block
    assert "stopStatusStream()" in apply_block

    rendering = client.split("function renderCurrentView", 1)[1].split("function setView", 1)[0]
    assert "document.activeElement" in rendering
    assert "focusModule" in rendering
    assert "focusGoal" in rendering
    assert 'pageContent.querySelector("details.technical-disclosure[open]")' in rendering
    assert "replacementDisclosure.open = true" in rendering
    assert "replacement.focus()" in rendering


def test_terminal_transitions_are_announced_and_cancel_is_visible(
    client: str, interface: str
) -> None:
    assert 'id="run-announcement" aria-live="polite" aria-atomic="true"' in interface
    assert 'id="cancel-button"' in interface
    for phrase in (
        "The diagnostic check started.",
        "The diagnostic check completed.",
        "The diagnostic check was cancelled.",
        "The diagnostic check could not be completed.",
    ):
        assert phrase in client


def test_rescue_fixes_lan_session_share_and_credentials_are_honest(
    client: str, interface: str
) -> None:
    combined = interface + client
    for phrase in (
        "Fixes are unavailable",
        "No remediation handlers are connected.",
        "LAN sessions are unavailable",
        "No LAN listener",
        "Rescue is guidance only",
        "does not assess boot viability or operating-system integrity",
        "hardware, storage health, encryption, backup state, or data recoverability",
        "Sharing is disabled",
        "Do not enter passwords, recovery keys, or other secrets",
    ):
        assert phrase in combined
    assert "syncCapabilityNavigation" in client
    assert (
        "password"
        not in " ".join(
            re.findall(r'<input\b[^>]*name="([^"]+)"', interface, flags=re.IGNORECASE)
        ).lower()
    )


def test_renderer_uses_text_nodes_and_has_no_unsafe_dom_or_live_fixtures(client: str) -> None:
    assert "textContent" in client
    assert "document.createElement" in client
    assert "replaceChildren" in client
    for forbidden in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        '.setAttribute("style"',
    ):
        assert forbidden not in client

    combined = (STATIC_ROOT / "index.html").read_text(encoding="utf-8") + client
    for forbidden in ("DEMO_MODE", "DEMO_FIXTURE", "demo fixture", "simulated scan"):
        assert forbidden.lower() not in combined.lower()
    assert not re.search(
        r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", combined
    )
    assert not re.search(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", combined, re.IGNORECASE)
    assert not re.search(r"−?\d+\s*dBm\b", combined)
