"""Static contract tests for the dependency-free, CSP-safe Lantern browser client."""

from __future__ import annotations

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
    for route in EXPECTED_API_ROUTES - {"/api/status", "/api/session"}:
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
    assert "stopSessionExpiryTimer()" in clear_block
    assert "document.cookie" not in client

    for forbidden in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "serviceWorker",
        "WebSocket",
        "EventSource",
        "sendBeacon",
        "navigator.clipboard",
        "pagehide",
        "beforeunload",
    ):
        assert forbidden not in client


def test_clearing_a_session_removes_stale_run_announcements(client: str) -> None:
    clear = (
        "function clearSession"
        + client.split("function clearSession", 1)[1].split(
            "function setSessionActionsDisabled", 1
        )[0]
    )
    assert 'runAnnouncement.textContent = ""' in clear
    assert clear.index('runAnnouncement.textContent = ""') < clear.index("renderCurrentView()")
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
      statusSnapshot !== null || connectionState.textContent !== "Local session closed" ||
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
  return {state: "ready"};
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
  statusBody.resolve({state: "ready"});
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
    assert 'value.schema !== "lantern.ui.v1"' in client
    assert 'value.transport !== "loopback"' in client
    assert 'Object.freeze(["route", "wifi", "dns", "lan", "mdns", "ports"])' in client
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
    assert "module.id !== MODULE_IDS[index]" in client
    assert "boundedText(module.detail, 500" in client
    assert "boundedInteger(value.percent, 0, 100)" in client
    assert 'value.profile === "passive" && value.include_mdns' in client
    assert '(value.state === "ready") !== (run === null)' in client
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
const base = {
  schema: "lantern.ui.v1",
  product: "Lantern",
  transport: "loopback",
  state: "completed",
  summary: {tone: "neutral", headline: "Complete", detail: "Bounded result."},
  run: {goal: "network", profile: "passive", include_mdns: false,
        cancel_requested: false, duration_ms: 1},
  progress: {processed: 2, planned: 2, percent: 100},
  modules: MODULE_IDS.map((id) => ({id: id, label: PAGE_META[id].title,
                                    status: "ok", detail: "Complete."})),
  capabilities: {passive_scan: true, low_impact_network: true,
                 active_discovery: false, remediation: false, credentials: false,
                 lan_remote: false, rescue_boot: false, share_export: false},
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
mustReject((value) => { value.run.include_mdns = true; });
mustReject((value) => { value.state = "ready"; });
mustReject((value) => { value.run = null; });
mustReject((value) => { value.progress.percent = 99; });
mustReject((value) => { value.capabilities.remediation = true; });
mustReject((value) => { value.modules.reverse(); });
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
        "share_export",
    ):
        assert f'"{capability}"' in capability_block
    assert "result[name] !== false" in capability_block
    assert "result.passive_scan !== true" in capability_block
    assert "result.low_impact_network !== true" in capability_block


def test_polling_runs_only_during_a_run_and_preserves_dynamic_focus(client: str) -> None:
    polling = client.split("async function pollStatus", 1)[1].split("function showNotice", 1)[0]
    assert 'statusSnapshot.state === "running"' in polling
    assert "schedulePoll(POLL_RUNNING_MS, false, generation)" in polling
    assert "stopPolling()" in polling
    assert "JSON.stringify(nextSnapshot) !== JSON.stringify(statusSnapshot)" in polling
    assert "if (changed)" in polling

    rendering = client.split("function renderCurrentView", 1)[1].split("function setView", 1)[0]
    assert "document.activeElement" in rendering
    assert "focusModule" in rendering
    assert "focusGoal" in rendering
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
    assert re.search(r'data-view-target="share" disabled', interface)
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
