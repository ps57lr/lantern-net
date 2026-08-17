(function () {
  "use strict";

  const launchMatch = window.location.hash.match(/^#launch=([A-Za-z0-9_-]{32,256})$/);
  let launchToken = launchMatch ? launchMatch[1] : null;
  window.history.replaceState(null, "", window.location.pathname);

  const API_METHODS = Object.freeze({
    "/api/session/exchange": Object.freeze(["POST"]),
    "/api/session": Object.freeze(["GET"]),
    "/api/status": Object.freeze(["GET"]),
    "/api/diagnostics/start": Object.freeze(["POST"]),
    "/api/diagnostics/cancel": Object.freeze(["POST"]),
    "/api/session/revoke": Object.freeze(["POST"]),
  });
  const CSRF_HEADER = "X-Lantern-CSRF";
  const MAX_JSON_BYTES = 524288;
  const REQUEST_TIMEOUT_MS = 8000;
  const POLL_RUNNING_MS = 700;
  const POLL_IDLE_MS = 2500;

  const MODULE_IDS = Object.freeze(["route", "wifi", "dns", "lan", "mdns", "ports"]);
  const MODULE_ICONS = Object.freeze({
    route: "gateway",
    wifi: "wifi",
    dns: "dns",
    lan: "lan",
    mdns: "mdns",
    ports: "ports",
  });
  const STATES = new Set(["ready", "running", "completed", "cancelled", "failed"]);
  const GOALS = new Set(["problem", "network", "rescue"]);
  const PROFILES = new Set(["passive", "low_impact_network"]);
  const SUMMARY_TONES = new Set(["neutral", "positive", "attention", "critical"]);
  const MODULE_STATUSES = new Set([
    "not_started",
    "queued",
    "running",
    "ok",
    "attention",
    "limited",
    "unavailable",
    "not_run",
    "cancelled",
  ]);
  const STATUS_LABELS = Object.freeze({
    not_started: "Not started",
    queued: "Waiting",
    running: "Checking",
    ok: "Completed",
    attention: "Needs attention",
    limited: "Partially checked",
    unavailable: "Unavailable",
    not_run: "Not checked",
    cancelled: "Cancelled",
  });
  const STATUS_ICONS = Object.freeze({
    not_started: "clock",
    queued: "clock",
    running: "refresh",
    ok: "check",
    attention: "alert",
    limited: "info",
    unavailable: "unknown",
    not_run: "clock",
    cancelled: "clock",
  });

  const PAGE_META = Object.freeze({
    overview: Object.freeze({
      eyebrow: "Diagnosis",
      title: "Overview",
      description: "A local, evidence-bounded view of this device and its network path.",
    }),
    device: Object.freeze({
      eyebrow: "Diagnosis",
      title: "This device",
      description: "What the current network-oriented diagnostic can confirm about this computer.",
    }),
    network: Object.freeze({
      eyebrow: "Network",
      title: "Network path",
      description: "Six bounded modules, shown honestly even when a check is unavailable or incomplete.",
    }),
    route: Object.freeze({ eyebrow: "Network module", title: "Route", description: "Local routing and the path beyond this device." }),
    wifi: Object.freeze({ eyebrow: "Network module", title: "Wi-Fi", description: "Association and link information available to this platform." }),
    dns: Object.freeze({ eyebrow: "Network module", title: "DNS", description: "Name-resolution checks included in the authorized profile." }),
    lan: Object.freeze({ eyebrow: "Network module", title: "LAN", description: "Locally observed neighbor state; basic checks never sweep the LAN." }),
    mdns: Object.freeze({ eyebrow: "Network module", title: "mDNS", description: "A brief local service browse only when explicitly included." }),
    ports: Object.freeze({ eyebrow: "Network module", title: "Ports", description: "Bounded service-port checks against the detected gateway only." }),
    fixes: Object.freeze({ eyebrow: "Act safely", title: "Fixes", description: "Remediation is deliberately unavailable in this live slice." }),
    rescue: Object.freeze({ eyebrow: "Guidance only", title: "Rescue guidance", description: "Network viability context without boot or recovery claims." }),
    session: Object.freeze({ eyebrow: "Local only", title: "LAN session", description: "Remote LAN access is not enabled and no LAN listener is running." }),
    share: Object.freeze({ eyebrow: "Unavailable", title: "Share", description: "Report export and upload are disabled in this live slice." }),
  });

  let csrfToken = null;
  let authenticated = false;
  let sessionGeneration = 0;
  let statusSnapshot = null;
  let currentView = "overview";
  let pollTimer = null;
  let sessionExpiryTimer = null;
  let sessionExpiresAt = 0;
  let pollInFlight = false;
  let startInFlight = false;
  let cancelInFlight = false;
  let revokeInFlight = false;
  let draftGoal = "problem";
  let draftBasic = false;
  let draftMdns = false;
  const STALE_SESSION = Object.freeze({ reason: "stale_session" });

  const pageContent = document.getElementById("page-content");
  const pageTitle = document.getElementById("page-title");
  const pageEyebrow = document.getElementById("page-eyebrow");
  const pageDescription = document.getElementById("page-description");
  const connectionState = document.getElementById("connection-state");
  const sessionNotice = document.getElementById("session-notice");
  const sessionMessage = document.getElementById("session-message");
  const newCheckButton = document.getElementById("new-check-button");
  const endSessionButton = document.getElementById("end-session-button");
  const mobileEndSessionButton = document.getElementById("mobile-end-session-button");
  const cancelButton = document.getElementById("cancel-button");
  const runProgress = document.getElementById("run-progress");
  const runProgressDetail = document.getElementById("run-progress-detail");
  const runProgressValue = document.getElementById("run-progress-value");
  const runProgressBar = document.getElementById("run-progress-bar");
  const progressTrack = document.getElementById("progress-track");
  const runAnnouncement = document.getElementById("run-announcement");
  const menuToggle = document.getElementById("menu-toggle");
  const primarySidebar = document.getElementById("primary-sidebar");
  const sidebarScrim = document.getElementById("sidebar-scrim");
  const mobileDrawerQuery = window.matchMedia("(max-width: 860px)");

  function boundedText(value, maximum, fallback) {
    if (typeof value !== "string" || value.length > maximum) {
      return fallback;
    }
    for (const character of value) {
      const code = character.codePointAt(0);
      if (code < 32 && character !== "\n" && character !== "\t") {
        return fallback;
      }
    }
    return value;
  }

  function exactKeys(value, required, optional) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    const allowed = new Set(required.concat(optional));
    const keys = Object.keys(value);
    return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
  }

  function boundedInteger(value, minimum, maximum) {
    return Number.isInteger(value) && value >= minimum && value <= maximum;
  }

  function isCurrentSession(generation) {
    return authenticated && generation === sessionGeneration;
  }

  function requireCurrentSession(generation) {
    if (!isCurrentSession(generation)) {
      throw STALE_SESSION;
    }
  }

  function validateSession(value) {
    if (!exactKeys(value, ["csrf_token", "expires_in"], [])) {
      throw new Error("Lantern returned an invalid local session response.");
    }
    if (typeof value.csrf_token !== "string" || !/^[A-Za-z0-9_-]{32,256}$/.test(value.csrf_token)) {
      throw new Error("Lantern returned an invalid local session response.");
    }
    if (!boundedInteger(value.expires_in, 1, 3600)) {
      throw new Error("Lantern returned an invalid local session response.");
    }
    return value;
  }

  function validateSummary(value) {
    if (!exactKeys(value, ["tone", "headline", "detail"], [])) {
      throw new Error("Lantern returned an invalid status summary.");
    }
    if (!SUMMARY_TONES.has(value.tone)) {
      throw new Error("Lantern returned an invalid status summary.");
    }
    return Object.freeze({
      tone: value.tone,
      headline: boundedText(value.headline, 180, "Summary unavailable."),
      detail: boundedText(value.detail, 600, "Lantern could not safely display the summary detail."),
    });
  }

  function validateRun(value) {
    if (value === null) {
      return null;
    }
    if (!exactKeys(value, ["goal", "profile", "include_mdns", "cancel_requested", "duration_ms"], [])) {
      throw new Error("Lantern returned an invalid run status.");
    }
    if (!GOALS.has(value.goal) || !PROFILES.has(value.profile)) {
      throw new Error("Lantern returned an invalid run status.");
    }
    if (typeof value.include_mdns !== "boolean" || typeof value.cancel_requested !== "boolean") {
      throw new Error("Lantern returned an invalid run status.");
    }
    if (value.profile === "passive" && value.include_mdns) {
      throw new Error("Lantern returned an inconsistent run profile.");
    }
    if (!boundedInteger(value.duration_ms, 0, 2147483647)) {
      throw new Error("Lantern returned an invalid run status.");
    }
    return Object.freeze({
      goal: value.goal,
      profile: value.profile,
      include_mdns: value.include_mdns,
      cancel_requested: value.cancel_requested,
      duration_ms: value.duration_ms,
    });
  }

  function validateProgress(value) {
    if (!exactKeys(value, ["processed", "planned", "percent"], [])) {
      throw new Error("Lantern returned invalid diagnostic progress.");
    }
    if (
      !boundedInteger(value.processed, 0, 1024) ||
      !boundedInteger(value.planned, 0, 1024) ||
      value.processed > value.planned ||
      !boundedInteger(value.percent, 0, 100)
    ) {
      throw new Error("Lantern returned invalid diagnostic progress.");
    }
    const expectedPercent = value.planned === 0 ? 0 : Math.round(value.processed * 100 / value.planned);
    if (value.percent !== expectedPercent) {
      throw new Error("Lantern returned inconsistent diagnostic progress.");
    }
    return Object.freeze({ processed: value.processed, planned: value.planned, percent: value.percent });
  }

  function validateModules(value) {
    if (!Array.isArray(value) || value.length !== MODULE_IDS.length) {
      throw new Error("Lantern returned an invalid module list.");
    }
    return Object.freeze(value.map((module, index) => {
      if (!exactKeys(module, ["id", "label", "status", "detail"], [])) {
        throw new Error("Lantern returned an invalid module result.");
      }
      if (module.id !== MODULE_IDS[index] || !MODULE_STATUSES.has(module.status)) {
        throw new Error("Lantern returned an invalid module result.");
      }
      return Object.freeze({
        id: module.id,
        label: boundedText(module.label, 64, PAGE_META[module.id].title),
        status: module.status,
        detail: boundedText(module.detail, 500, "No safe detail is available for this module."),
      });
    }));
  }

  function validateCapabilities(value) {
    const names = [
      "passive_scan",
      "low_impact_network",
      "active_discovery",
      "remediation",
      "credentials",
      "lan_remote",
      "rescue_boot",
      "share_export",
    ];
    if (!exactKeys(value, names, [])) {
      throw new Error("Lantern returned an invalid capability description.");
    }
    const result = {};
    for (const name of names) {
      if (typeof value[name] !== "boolean") {
        throw new Error("Lantern returned an invalid capability description.");
      }
      result[name] = value[name];
    }
    if (result.passive_scan !== true || result.low_impact_network !== true) {
      throw new Error("Lantern returned an incompatible capability description.");
    }
    for (const name of ["active_discovery", "remediation", "credentials", "lan_remote", "rescue_boot", "share_export"]) {
      if (result[name] !== false) {
        throw new Error("Lantern refused an unsafe capability description.");
      }
    }
    return Object.freeze(result);
  }

  function validateStatus(value) {
    if (!exactKeys(value, ["schema", "product", "transport", "state", "summary", "run", "progress", "modules", "capabilities"], [])) {
      throw new Error("Lantern returned an invalid status snapshot.");
    }
    if (value.schema !== "lantern.ui.v1" || value.product !== "Lantern" || value.transport !== "loopback" || !STATES.has(value.state)) {
      throw new Error("Lantern returned an unsupported status snapshot.");
    }
    const run = validateRun(value.run);
    if ((value.state === "ready") !== (run === null)) {
      throw new Error("Lantern returned an inconsistent diagnostic state.");
    }
    return Object.freeze({
      schema: value.schema,
      product: value.product,
      transport: value.transport,
      state: value.state,
      summary: validateSummary(value.summary),
      run: run,
      progress: validateProgress(value.progress),
      modules: validateModules(value.modules),
      capabilities: validateCapabilities(value.capabilities),
    });
  }

  async function apiFetch(route, options) {
    const method = options && options.method ? options.method : "GET";
    if (!Object.prototype.hasOwnProperty.call(API_METHODS, route) || !API_METHODS[route].includes(method)) {
      throw new Error("Lantern blocked an unexpected local request.");
    }
    const resolved = new URL(route, window.location.origin);
    if (resolved.origin !== window.location.origin || resolved.pathname !== route || resolved.search || resolved.hash) {
      throw new Error("Lantern blocked an unexpected local request.");
    }

    const headers = { Accept: "application/json" };
    let body;
    if (options && Object.prototype.hasOwnProperty.call(options, "body")) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    if (options && options.csrf) {
      if (typeof csrfToken !== "string") {
        throw new Error("The local session is not ready for that action.");
      }
      headers[CSRF_HEADER] = csrfToken;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT_MS);
    try {
      const response = await window.fetch(route, {
        method: method,
        headers: headers,
        body: body,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      const responseBody = await response.arrayBuffer();
      if (responseBody.byteLength > MAX_JSON_BYTES) {
        throw new Error("Lantern returned an oversized local response.");
      }
      return new Response(responseBody, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } finally {
      window.clearTimeout(timeout);
    }
  }

  async function readJson(response) {
    const contentType = response.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      throw new Error("Lantern returned an unexpected local response.");
    }
    const text = await response.text();
    if (text.length === 0 || text.length > MAX_JSON_BYTES) {
      throw new Error("Lantern returned an invalid local response.");
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (_error) {
      throw new Error("Lantern returned an invalid local response.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Lantern returned an invalid local response.");
    }
    return parsed;
  }

  async function failureMessage(response, fallback) {
    try {
      const value = await readJson(response);
      if (exactKeys(value, ["error"], []) && exactKeys(value.error, ["code", "message"], [])) {
        return boundedText(value.error.message, 300, fallback);
      }
    } catch (_error) {
      return fallback;
    }
    return fallback;
  }

  function stopSessionExpiryTimer() {
    if (sessionExpiryTimer !== null) {
      window.clearTimeout(sessionExpiryTimer);
      sessionExpiryTimer = null;
    }
    sessionExpiresAt = 0;
  }

  function armSessionExpiry(expiresIn, generation) {
    if (!Number.isInteger(expiresIn) || expiresIn < 1 || expiresIn > 3600) {
      throw new Error("Lantern returned an invalid local session lifetime.");
    }
    if (!isCurrentSession(generation)) {
      return;
    }
    stopSessionExpiryTimer();
    const lifetimeMs = Math.max(1, expiresIn * 1000 - 1000);
    sessionExpiresAt = performance.now() + lifetimeMs;

    function expireWhenDue() {
      if (!isCurrentSession(generation)) {
        return;
      }
      const remaining = sessionExpiresAt - performance.now();
      if (remaining > 0) {
        sessionExpiryTimer = window.setTimeout(expireWhenDue, remaining);
        return;
      }
      sessionExpiryTimer = null;
      sessionExpiresAt = 0;
      clearSession("The private local session expired. Launch Lantern again to continue.");
    }

    sessionExpiryTimer = window.setTimeout(expireWhenDue, lifetimeMs);
  }

  function clearSession(message, tone) {
    sessionGeneration += 1;
    const closeOpenDrawer = mobileDrawerQuery.matches && primarySidebar.classList.contains("is-open");
    stopSessionExpiryTimer();
    startInFlight = false;
    cancelInFlight = false;
    revokeInFlight = false;
    pollInFlight = false;
    authenticated = false;
    csrfToken = null;
    stopPolling();
    newCheckButton.disabled = true;
    setSessionActionsDisabled(true);
    cancelButton.disabled = true;
    connectionState.textContent = "Local session closed";
    runAnnouncement.textContent = "";
    showNotice(message, tone === "info" ? "info" : "attention");
    statusSnapshot = null;
    if (closeOpenDrawer) {
      closeSidebar(true);
    }
    renderCurrentView();
  }

  function setSessionActionsDisabled(disabled) {
    endSessionButton.disabled = disabled;
    mobileEndSessionButton.disabled = disabled;
  }

  async function establishSession() {
    let expectedGeneration = sessionGeneration;
    try {
      let response;
      if (launchToken !== null) {
        const exchangeBody = { launch_token: launchToken };
        launchToken = null;
        response = await apiFetch("/api/session/exchange", { method: "POST", body: exchangeBody });
      } else {
        response = await apiFetch("/api/session", { method: "GET" });
      }
      if (expectedGeneration !== sessionGeneration) {
        return;
      }

      if (response.status === 401) {
        clearSession("This local launch link is invalid, expired, or already used. Open Lantern again from its command-line launcher.");
        return;
      }
      if (!response.ok) {
        const message = await failureMessage(response, "Lantern could not open a private local session.");
        if (expectedGeneration !== sessionGeneration) {
          return;
        }
        clearSession(message);
        return;
      }
      const sessionPayload = await readJson(response);
      if (expectedGeneration !== sessionGeneration) {
        return;
      }
      const session = validateSession(sessionPayload);
      sessionGeneration += 1;
      const activeGeneration = sessionGeneration;
      expectedGeneration = activeGeneration;
      csrfToken = session.csrf_token;
      authenticated = true;
      armSessionExpiry(session.expires_in, activeGeneration);
      connectionState.textContent = "Private local session";
      newCheckButton.disabled = false;
      setSessionActionsDisabled(false);
      hideNotice();
      await pollStatus(false, activeGeneration);
    } catch (_error) {
      if (expectedGeneration !== sessionGeneration) {
        return;
      }
      clearSession("Lantern could not connect to its local service. Close this tab and launch the interface again.");
    }
  }

  async function refreshCsrfAfterForbidden(generation) {
    requireCurrentSession(generation);
    const response = await apiFetch("/api/session", { method: "GET" });
    requireCurrentSession(generation);
    if (response.status === 401) {
      clearSession("The private local session expired. Launch Lantern again to continue.");
      return false;
    }
    if (!response.ok) {
      return false;
    }
    const sessionPayload = await readJson(response);
    requireCurrentSession(generation);
    const session = validateSession(sessionPayload);
    requireCurrentSession(generation);
    csrfToken = session.csrf_token;
    armSessionExpiry(session.expires_in, generation);
    return true;
  }

  async function postMutation(route, body, retryAfterRefresh, generation) {
    requireCurrentSession(generation);
    let response = await apiFetch(route, { method: "POST", body: body, csrf: true });
    requireCurrentSession(generation);
    if (response.status === 401) {
      clearSession("The private local session expired. Launch Lantern again to continue.");
      throw STALE_SESSION;
    }
    if (response.status === 403) {
      const refreshed = await refreshCsrfAfterForbidden(generation);
      requireCurrentSession(generation);
      if (!refreshed) {
        throw new Error("Lantern could not refresh local action verification.");
      }
      if (!retryAfterRefresh) {
        throw new Error("Local action verification was refreshed. Select Start check again.");
      }
      response = await apiFetch(route, { method: "POST", body: body, csrf: true });
      requireCurrentSession(generation);
      if (response.status === 401) {
        clearSession("The private local session expired. Launch Lantern again to continue.");
        throw STALE_SESSION;
      }
    }
    return response;
  }

  function stopPolling() {
    if (pollTimer !== null) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function schedulePoll(delay, continueOnError, generation) {
    stopPolling();
    if (isCurrentSession(generation)) {
      pollTimer = window.setTimeout(function () {
        void pollStatus(continueOnError, generation);
      }, delay);
    }
  }

  async function pollStatus(continueOnError, generation) {
    if (!isCurrentSession(generation) || pollInFlight) {
      return;
    }
    pollInFlight = true;
    try {
      const response = await apiFetch("/api/status", { method: "GET" });
      if (!isCurrentSession(generation)) {
        return;
      }
      if (response.status === 401) {
        clearSession("The private local session expired. Launch Lantern again to continue.");
        return;
      }
      if (!response.ok) {
        const message = await failureMessage(response, "Lantern status is temporarily unavailable.");
        if (!isCurrentSession(generation)) {
          return;
        }
        showNotice(message, "attention");
        if (continueOnError || (statusSnapshot && statusSnapshot.state === "running")) {
          schedulePoll(POLL_IDLE_MS, false, generation);
        }
        return;
      }
      const statusPayload = await readJson(response);
      if (!isCurrentSession(generation)) {
        return;
      }
      const nextSnapshot = validateStatus(statusPayload);
      if (!isCurrentSession(generation)) {
        return;
      }
      const previousState = statusSnapshot ? statusSnapshot.state : null;
      const changed = JSON.stringify(nextSnapshot) !== JSON.stringify(statusSnapshot);
      statusSnapshot = nextSnapshot;
      connectionState.textContent = statusSnapshot.state === "running" ? "Checking locally" : "Private local session";
      hideNotice();
      announceState(statusSnapshot.state, previousState);
      if (changed) {
        renderCurrentView();
      }
      if (statusSnapshot.state === "running") {
        schedulePoll(POLL_RUNNING_MS, false, generation);
      } else {
        stopPolling();
      }
    } catch (_error) {
      if (!isCurrentSession(generation)) {
        return;
      }
      showNotice("Lantern could not read a safe local status snapshot. It will try the status route again.", "attention");
      if (continueOnError || (statusSnapshot && statusSnapshot.state === "running")) {
        schedulePoll(POLL_IDLE_MS, false, generation);
      }
    } finally {
      if (isCurrentSession(generation)) {
        pollInFlight = false;
      }
    }
  }

  function showNotice(message, tone) {
    sessionNotice.className = "notice notice-" + tone;
    sessionMessage.textContent = message;
  }

  function hideNotice() {
    sessionNotice.className = "notice is-hidden";
    sessionMessage.textContent = "";
  }

  function announceState(state, previousState) {
    if (state === previousState) {
      return;
    }
    const messages = {
      ready: "Lantern is ready for a consent-based check.",
      running: "The diagnostic check started.",
      completed: "The diagnostic check completed.",
      cancelled: "The diagnostic check was cancelled.",
      failed: "The diagnostic check could not be completed.",
    };
    runAnnouncement.textContent = messages[state];
  }

  function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (typeof text === "string") {
      element.textContent = text;
    }
    return element;
  }

  function createIcon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "icons.svg#" + name);
    svg.append(use);
    return svg;
  }

  function statusBadge(status) {
    const badge = createElement("span", "status-badge status-" + status);
    badge.append(createIcon(STATUS_ICONS[status]), document.createTextNode(STATUS_LABELS[status]));
    return badge;
  }

  function moduleCard(module) {
    const button = createElement("button", "module-card status-card-" + module.status);
    button.type = "button";
    button.dataset.moduleTarget = module.id;
    button.setAttribute("aria-label", module.label + ": " + STATUS_LABELS[module.status]);
    const heading = createElement("div", "module-card-heading");
    const mark = createElement("span", "module-mark");
    mark.append(createIcon(MODULE_ICONS[module.id]));
    heading.append(mark, createElement("h3", "", module.label), statusBadge(module.status));
    button.append(heading, createElement("p", "module-detail", module.detail));
    const action = createElement("span", "module-action", "View module");
    action.append(createIcon("arrow-right"));
    button.append(action);
    return button;
  }

  function renderModules(title) {
    const section = createElement("section", "section-block");
    section.append(createElement("h2", "section-title", title));
    const grid = createElement("div", "module-grid");
    if (!statusSnapshot) {
      grid.append(emptyPanel("No live module status is available until the local session connects."));
    } else {
      for (const module of statusSnapshot.modules) {
        grid.append(moduleCard(module));
      }
    }
    section.append(grid);
    return section;
  }

  function emptyPanel(message) {
    const panel = createElement("section", "panel empty-state");
    panel.append(createIcon("unknown"), createElement("p", "", message));
    return panel;
  }

  function summaryPanel() {
    if (!statusSnapshot) {
      const panel = createElement("section", "panel connection-panel");
      panel.append(createIcon("lock"), createElement("h2", "", "No authenticated local status"));
      panel.append(createElement("p", "", "Launch Lantern again if this tab no longer has a private local session."));
      return panel;
    }
    const panel = createElement("section", "summary-panel tone-" + statusSnapshot.summary.tone);
    const copy = createElement("div", "summary-copy");
    copy.append(createElement("p", "eyebrow", statusSnapshot.state === "running" ? "Check in progress" : "Current assessment"));
    copy.append(createElement("h2", "", statusSnapshot.summary.headline));
    copy.append(createElement("p", "", statusSnapshot.summary.detail));
    panel.append(copy);
    const shield = createElement("span", "summary-mark");
    shield.append(createIcon(statusSnapshot.summary.tone === "positive" ? "shield-check" : "shield"));
    panel.append(shield);
    return panel;
  }

  function choiceRow(name, value, title, detail) {
    const label = createElement("label", "choice-card");
    const input = document.createElement("input");
    input.type = "radio";
    input.name = name;
    input.value = value;
    input.checked = draftGoal === value;
    const copy = createElement("span", "choice-copy");
    copy.append(createElement("strong", "", title), createElement("small", "", detail));
    label.append(input, copy);
    return label;
  }

  function renderStartPanel() {
    const panel = createElement("section", "panel start-panel");
    const intro = createElement("div", "panel-heading");
    intro.append(createElement("p", "eyebrow", "Consent for one run"));
    intro.append(createElement("h2", "", "Choose the smallest useful check"));
    intro.append(createElement("p", "", "Passive is the default. Nothing starts automatically, and this interface cannot change settings."));
    panel.append(intro);

    const form = document.createElement("form");
    form.id = "start-check-form";
    const goals = document.createElement("fieldset");
    goals.className = "choice-fieldset";
    goals.append(createElement("legend", "", "What needs help?"));
    goals.append(
      choiceRow("goal", "problem", "Something is not working", "Check the local network path and explain what is confirmed."),
      choiceRow("goal", "network", "Evaluate this network", "Focus the explanation on network viability."),
      choiceRow("goal", "rescue", "Gather network context for recovery", "Network viability only—not boot, hardware, storage, encryption, or recoverability."),
    );
    form.append(goals);

    const passive = createElement("div", "consent-fact");
    passive.append(createIcon("eye"));
    const passiveCopy = createElement("span", "");
    passiveCopy.append(createElement("strong", "", "Passive local state · default"));
    passiveCopy.append(createElement("small", "", "Reads local route, interface, Wi-Fi, and neighbor state. It sends no diagnostic packets."));
    passive.append(passiveCopy);
    form.append(passive);

    const basicLabel = createElement("label", "consent-row");
    const basicInput = document.createElement("input");
    basicInput.type = "checkbox";
    basicInput.id = "basic-network-checks";
    basicInput.checked = draftBasic;
    const basicCopy = createElement("span", "");
    basicCopy.append(createElement("strong", "", "Include basic network checks"));
    basicCopy.append(createElement("small", "", "Sends small public reachability probes (ping/ICMP and TCP), DNS queries, and gateway service-port probes. It does not sweep the LAN or change settings."));
    basicLabel.append(basicInput, basicCopy);
    form.append(basicLabel);

    const mdnsLabel = createElement("label", "consent-row consent-row-nested");
    const mdnsInput = document.createElement("input");
    mdnsInput.type = "checkbox";
    mdnsInput.id = "include-mdns";
    mdnsInput.checked = draftMdns;
    mdnsInput.disabled = !draftBasic;
    const mdnsCopy = createElement("span", "");
    mdnsCopy.append(createElement("strong", "", "Include a brief local mDNS browse"));
    mdnsCopy.append(createElement("small", "", "Off by default. When selected, it briefly sends and receives local multicast service-discovery traffic."));
    mdnsLabel.append(mdnsInput, mdnsCopy);
    form.append(mdnsLabel);

    const warning = createElement("div", "credential-warning");
    warning.append(createIcon("key"), createElement("p", "", "Lantern will not ask for credentials here. Do not enter passwords, recovery keys, or other secrets into this interface."));
    form.append(warning);

    const submit = createElement("button", "primary-button", startInFlight ? "Starting…" : "Start check");
    submit.type = "submit";
    submit.disabled = !authenticated || !statusSnapshot || startInFlight || statusSnapshot.state === "running";
    submit.prepend(createIcon("scan"));
    form.append(submit);
    panel.append(form);
    return panel;
  }

  function capabilityPanel() {
    const panel = createElement("section", "panel capability-panel");
    panel.append(createElement("p", "eyebrow", "Boundaries"), createElement("h2", "", "What this live slice can—and cannot—do"));
    const grid = createElement("div", "capability-grid");
    const items = [
      ["passive_scan", "Read passive state", "Local configuration and operating-system observations."],
      ["low_impact_network", "Run basic network checks", "Only after the checkbox is selected for that run."],
      ["active_discovery", "Sweep the LAN", "Active discovery is not exposed in this interface."],
      ["remediation", "Apply fixes", "No remediation API or fix handler is connected."],
      ["credentials", "Collect credentials", "There are no credential fields or credential transport."],
      ["lan_remote", "Open remote access", "No LAN listener or remote session is enabled."],
      ["share_export", "Export or share", "No report export or external sharing route is connected."],
    ];
    for (const item of items) {
      const available = Boolean(statusSnapshot && statusSnapshot.capabilities[item[0]]);
      const card = createElement("div", "capability-item");
      card.append(createIcon(available ? "check" : "lock"));
      const copy = createElement("span", "");
      copy.append(createElement("strong", "", item[1]), createElement("small", "", item[2]));
      card.append(copy);
      grid.append(card);
    }
    panel.append(grid);
    return panel;
  }

  function renderOverview() {
    const fragment = document.createDocumentFragment();
    fragment.append(summaryPanel());
    if (!statusSnapshot || statusSnapshot.state !== "running") {
      fragment.append(renderStartPanel());
    }
    fragment.append(renderModules("Module coverage"), capabilityPanel());
    return fragment;
  }

  function renderDevice() {
    const fragment = document.createDocumentFragment();
    fragment.append(summaryPanel());
    const panel = createElement("section", "panel explanation-panel");
    panel.append(createIcon("device"), createElement("h2", "", "Network-facing device context"));
    panel.append(createElement("p", "", "This diagnostic may observe local interface, routing, Wi-Fi, and neighbor-table state. It does not claim to evaluate processor, memory, battery, storage, operating-system integrity, or general hardware health."));
    fragment.append(panel);
    return fragment;
  }

  function renderNetwork() {
    const fragment = document.createDocumentFragment();
    fragment.append(summaryPanel(), renderModules("From local link to name resolution"));
    const note = createElement("section", "panel explanation-panel");
    note.append(createIcon("shield"), createElement("h2", "", "The profile is the boundary"));
    note.append(createElement("p", "", "Passive reads local state without diagnostic packets. Basic network checks add only the bounded traffic described before you start. Neither profile performs an active LAN sweep."));
    fragment.append(note);
    return fragment;
  }

  function renderModule(moduleId) {
    if (!statusSnapshot) {
      return emptyPanel("No authenticated module status is available.");
    }
    const module = statusSnapshot.modules.find((item) => item.id === moduleId);
    if (!module) {
      return emptyPanel("This module is unavailable in the current status contract.");
    }
    const fragment = document.createDocumentFragment();
    const panel = createElement("section", "panel module-focus status-card-" + module.status);
    const heading = createElement("div", "module-focus-heading");
    const mark = createElement("span", "module-mark module-mark-large");
    mark.append(createIcon(MODULE_ICONS[module.id]));
    heading.append(mark, createElement("h2", "", module.label), statusBadge(module.status));
    panel.append(heading, createElement("p", "module-focus-detail", module.detail));
    const truth = createElement("div", "truth-row");
    truth.append(createIcon("info"), createElement("p", "", "This is the bounded presentation returned by Lantern. Raw addresses, device identifiers, evidence payloads, and credentials are not sent to this page."));
    panel.append(truth);
    fragment.append(panel);
    if (module.status === "unavailable" || module.status === "limited" || module.status === "not_started" || module.status === "not_run" || module.status === "cancelled") {
      const state = createElement("section", "panel unsupported-state");
      state.append(createIcon(module.status === "unavailable" ? "lock" : "unknown"));
      state.append(createElement("h2", "", "No stronger conclusion is available"));
      state.append(createElement("p", "", "Lantern preserves unsupported, partial, blocked, and not-run states instead of presenting missing evidence as healthy."));
      fragment.append(state);
    }
    return fragment;
  }

  function unavailablePanel(iconName, title, detail, points) {
    const fragment = document.createDocumentFragment();
    const panel = createElement("section", "panel unavailable-panel");
    const mark = createElement("span", "unavailable-mark");
    mark.append(createIcon(iconName));
    panel.append(mark, createElement("p", "eyebrow", "Not connected"), createElement("h2", "", title), createElement("p", "", detail));
    const list = document.createElement("ul");
    for (const point of points) {
      list.append(createElement("li", "", point));
    }
    panel.append(list);
    fragment.append(panel);
    return fragment;
  }

  function renderFixes() {
    return unavailablePanel(
      "wrench",
      "Fixes are unavailable",
      "This interface can diagnose and explain, but it cannot preview, approve, apply, or roll back a change.",
      ["No remediation handlers are connected.", "No administrator credentials can be entered.", "A diagnostic result never applies a change automatically."],
    );
  }

  function renderRescue() {
    const fragment = unavailablePanel(
      "rescue",
      "Rescue is guidance only",
      "A network run can provide network viability context. It cannot determine whether this computer is bootable or recoverable.",
      [
        "This live slice does not assess boot viability or operating-system integrity.",
        "It does not assess hardware, storage health, encryption, backup state, or data recoverability.",
        "Never interpret a healthy network module as a healthy or recoverable computer.",
      ],
    );
    const safety = createElement("section", "panel safety-panel");
    safety.append(createIcon("shield"), createElement("h2", "", "Protect data before repair"));
    safety.append(createElement("p", "", "If a computer may have storage or hardware trouble, stop write-heavy experimentation and seek qualified recovery help. Lantern does not unlock disks, request recovery keys, or change boot state."));
    fragment.append(safety);
    return fragment;
  }

  function renderSession() {
    return unavailablePanel(
      "session",
      "LAN sessions are unavailable",
      "The page is served only from this computer's loopback address. No LAN listener, pairing route, or remote-control channel is running.",
      ["Only the browser session on this computer is authenticated.", "Closing or revoking this local session does not create remote access.", "Remote support remains a future, separately reviewed capability."],
    );
  }

  function renderShare() {
    return unavailablePanel(
      "share",
      "Sharing is disabled",
      "This live interface has no download, upload, email, clipboard, or external sharing action.",
      ["Status remains on this computer.", "No external destination is configured.", "The disabled navigation item is an explicit product boundary."],
    );
  }

  function renderProgress() {
    const running = Boolean(statusSnapshot && statusSnapshot.state === "running");
    runProgress.classList.toggle("is-hidden", !running);
    if (!running) {
      return;
    }
    const progress = statusSnapshot.progress;
    const percent = progress.percent;
    const bucket = Math.min(100, Math.max(0, Math.round(percent / 10) * 10));
    runProgressValue.textContent = String(percent) + "%";
    runProgressDetail.textContent = progress.planned > 0
      ? String(progress.processed) + " of " + String(progress.planned) + " bounded steps reached a terminal state."
      : "Preparing the authorized diagnostic steps…";
    progressTrack.setAttribute("aria-valuenow", String(percent));
    runProgressBar.className = "progress-fill progress-" + String(bucket);
    cancelButton.disabled = cancelInFlight || Boolean(statusSnapshot.run && statusSnapshot.run.cancel_requested);
    cancelButton.textContent = statusSnapshot.run && statusSnapshot.run.cancel_requested ? "Cancellation requested" : (cancelInFlight ? "Requesting…" : "Cancel check");
  }

  function renderCurrentView() {
    const meta = PAGE_META[currentView] || PAGE_META.overview;
    pageEyebrow.textContent = meta.eyebrow;
    pageTitle.textContent = meta.title;
    pageDescription.textContent = meta.description;
    renderProgress();

    let content;
    if (currentView === "overview") {
      content = renderOverview();
    } else if (currentView === "device") {
      content = renderDevice();
    } else if (currentView === "network") {
      content = renderNetwork();
    } else if (MODULE_IDS.includes(currentView)) {
      content = renderModule(currentView);
    } else if (currentView === "fixes") {
      content = renderFixes();
    } else if (currentView === "rescue") {
      content = renderRescue();
    } else if (currentView === "session") {
      content = renderSession();
    } else {
      content = renderShare();
    }
    const active = document.activeElement;
    const focusId = active && pageContent.contains(active) ? active.id : "";
    const focusModule = active && pageContent.contains(active) ? active.dataset.moduleTarget : "";
    const focusGoal = active && pageContent.contains(active) && active.name === "goal" ? active.value : "";
    pageContent.replaceChildren(content);
    let replacement = focusId ? document.getElementById(focusId) : null;
    if (!replacement && focusModule) {
      replacement = Array.from(pageContent.querySelectorAll("[data-module-target]")).find((item) => item.dataset.moduleTarget === focusModule);
    }
    if (!replacement && focusGoal) {
      replacement = Array.from(pageContent.querySelectorAll('input[name="goal"]')).find((item) => item.value === focusGoal);
    }
    if (replacement) {
      replacement.focus();
    }
  }

  function setView(view, focusHeading) {
    if (!Object.prototype.hasOwnProperty.call(PAGE_META, view)) {
      return;
    }
    currentView = view;
    for (const item of document.querySelectorAll("[data-view-target]")) {
      const isCurrent = item.dataset.viewTarget === view;
      item.classList.toggle("is-current", isCurrent);
      if (isCurrent) {
        item.setAttribute("aria-current", "page");
      } else {
        item.removeAttribute("aria-current");
      }
    }
    const cameFromDrawer = mobileDrawerQuery.matches && primarySidebar.contains(document.activeElement);
    const focusDestination = focusHeading || cameFromDrawer;
    closeSidebar(false);
    renderCurrentView();
    if (focusDestination) {
      pageTitle.focus();
    }
  }

  function openSidebar() {
    if (!mobileDrawerQuery.matches) {
      return;
    }
    primarySidebar.classList.add("is-open");
    primarySidebar.inert = false;
    primarySidebar.removeAttribute("aria-hidden");
    sidebarScrim.classList.add("is-visible");
    menuToggle.setAttribute("aria-expanded", "true");
    menuToggle.setAttribute("aria-label", "Close navigation");
    const firstControl = primarySidebar.querySelector(".nav-item:not(:disabled)");
    if (firstControl) {
      firstControl.focus();
    }
  }

  function closeSidebar(restoreFocus) {
    primarySidebar.classList.remove("is-open");
    sidebarScrim.classList.remove("is-visible");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation");
    if (mobileDrawerQuery.matches) {
      primarySidebar.inert = true;
      primarySidebar.setAttribute("aria-hidden", "true");
      if (restoreFocus) {
        menuToggle.focus();
      }
    } else {
      primarySidebar.inert = false;
      primarySidebar.removeAttribute("aria-hidden");
    }
  }

  function synchronizeSidebarMode() {
    const focusWasInside = primarySidebar.contains(document.activeElement);
    if (mobileDrawerQuery.matches) {
      if (!primarySidebar.classList.contains("is-open")) {
        if (focusWasInside) {
          menuToggle.focus();
        }
        primarySidebar.inert = true;
        primarySidebar.setAttribute("aria-hidden", "true");
      }
      return;
    }
    primarySidebar.classList.remove("is-open");
    sidebarScrim.classList.remove("is-visible");
    primarySidebar.inert = false;
    primarySidebar.removeAttribute("aria-hidden");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation");
    if (document.activeElement === menuToggle) {
      pageTitle.focus();
    }
  }

  function containDrawerFocus(event) {
    if (event.key !== "Tab" || !mobileDrawerQuery.matches || !primarySidebar.classList.contains("is-open")) {
      return;
    }
    const controls = Array.from(primarySidebar.querySelectorAll("button:not(:disabled), a[href]"));
    if (controls.length === 0) {
      event.preventDefault();
      menuToggle.focus();
      return;
    }
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && (document.activeElement === first || !primarySidebar.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !primarySidebar.contains(document.activeElement))) {
      event.preventDefault();
      first.focus();
    }
  }

  async function startCheck() {
    if (!authenticated || !statusSnapshot || startInFlight || statusSnapshot.state === "running") {
      return;
    }
    const generation = sessionGeneration;
    startInFlight = true;
    renderCurrentView();
    const profile = draftBasic ? "low_impact_network" : "passive";
    const includeMdns = draftBasic && draftMdns;
    const requestBody = { goal: draftGoal, profile: profile, include_mdns: includeMdns };
    try {
      const response = await postMutation("/api/diagnostics/start", requestBody, false, generation);
      requireCurrentSession(generation);
      if (!response.ok) {
        const message = await failureMessage(response, "Lantern did not accept the diagnostic request.");
        requireCurrentSession(generation);
        throw new Error(message);
      }
      const result = await readJson(response);
      requireCurrentSession(generation);
      if (!exactKeys(result, ["accepted"], []) || result.accepted !== true) {
        throw new Error("Lantern returned an invalid start response.");
      }
      draftBasic = false;
      draftMdns = false;
      showNotice("The authorized diagnostic started. You can cancel it at a module boundary.", "info");
      await pollStatus(true, generation);
    } catch (error) {
      if (!isCurrentSession(generation)) {
        return;
      }
      showNotice(error instanceof Error ? boundedText(error.message, 300, "Lantern could not start the check.") : "Lantern could not start the check.", "attention");
    } finally {
      if (isCurrentSession(generation)) {
        startInFlight = false;
        renderCurrentView();
      }
    }
  }

  async function cancelCheck() {
    if (!authenticated || cancelInFlight || !statusSnapshot || statusSnapshot.state !== "running") {
      return;
    }
    const generation = sessionGeneration;
    cancelInFlight = true;
    renderProgress();
    try {
      const response = await postMutation("/api/diagnostics/cancel", {}, true, generation);
      requireCurrentSession(generation);
      if (!response.ok) {
        const message = await failureMessage(response, "Lantern could not request cancellation.");
        requireCurrentSession(generation);
        throw new Error(message);
      }
      const result = await readJson(response);
      requireCurrentSession(generation);
      if (!exactKeys(result, ["cancel_requested"], []) || typeof result.cancel_requested !== "boolean") {
        throw new Error("Lantern returned an invalid cancellation response.");
      }
      showNotice(result.cancel_requested ? "Cancellation was requested. The current bounded module will stop at its cooperative boundary." : "The diagnostic had already reached a terminal state.", "info");
      await pollStatus(true, generation);
    } catch (error) {
      if (!isCurrentSession(generation)) {
        return;
      }
      showNotice(error instanceof Error ? boundedText(error.message, 300, "Lantern could not request cancellation.") : "Lantern could not request cancellation.", "attention");
    } finally {
      if (isCurrentSession(generation)) {
        cancelInFlight = false;
        renderProgress();
      }
    }
  }

  async function revokeSession() {
    if (!authenticated || revokeInFlight) {
      return;
    }
    const generation = sessionGeneration;
    revokeInFlight = true;
    setSessionActionsDisabled(true);
    try {
      const response = await postMutation("/api/session/revoke", {}, true, generation);
      requireCurrentSession(generation);
      if (!response.ok) {
        const message = await failureMessage(response, "Lantern could not end the local session.");
        requireCurrentSession(generation);
        throw new Error(message);
      }
      const result = await readJson(response);
      requireCurrentSession(generation);
      if (!exactKeys(result, ["revoked"], []) || result.revoked !== true) {
        throw new Error("Lantern returned an invalid revoke response.");
      }
      clearSession("The private local session ended. Launch Lantern again to reconnect.", "info");
      if (!mobileDrawerQuery.matches) {
        sessionNotice.focus();
      }
    } catch (error) {
      if (isCurrentSession(generation)) {
        revokeInFlight = false;
        setSessionActionsDisabled(false);
        showNotice(error instanceof Error ? boundedText(error.message, 300, "Lantern could not end the local session.") : "Lantern could not end the local session.", "attention");
        if (mobileDrawerQuery.matches) {
          closeSidebar(true);
        } else {
          sessionNotice.focus();
        }
      }
    }
  }

  document.addEventListener("click", function (event) {
    const viewButton = event.target.closest("[data-view-target]");
    if (viewButton && !viewButton.disabled) {
      setView(viewButton.dataset.viewTarget, true);
      return;
    }
    const moduleButton = event.target.closest("[data-module-target]");
    if (moduleButton) {
      setView(moduleButton.dataset.moduleTarget, true);
    }
  });

  pageContent.addEventListener("change", function (event) {
    const target = event.target;
    if (target.name === "goal" && GOALS.has(target.value)) {
      draftGoal = target.value;
    } else if (target.id === "basic-network-checks") {
      draftBasic = target.checked;
      if (!draftBasic) {
        draftMdns = false;
      }
      const mdns = document.getElementById("include-mdns");
      if (mdns) {
        mdns.disabled = !draftBasic;
        mdns.checked = draftMdns;
      }
    } else if (target.id === "include-mdns") {
      draftMdns = target.checked;
    }
  });

  pageContent.addEventListener("submit", function (event) {
    if (event.target.id === "start-check-form") {
      event.preventDefault();
      void startCheck();
    }
  });

  menuToggle.addEventListener("click", function () {
    if (primarySidebar.classList.contains("is-open")) {
      closeSidebar(true);
    } else {
      openSidebar();
    }
  });
  sidebarScrim.addEventListener("click", function () { closeSidebar(true); });
  cancelButton.addEventListener("click", function () { void cancelCheck(); });
  endSessionButton.addEventListener("click", function () { void revokeSession(); });
  mobileEndSessionButton.addEventListener("click", function () { void revokeSession(); });
  newCheckButton.addEventListener("click", function () {
    setView("overview", true);
    const form = document.getElementById("start-check-form");
    if (form) {
      form.querySelector("input").focus();
    }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && primarySidebar.classList.contains("is-open")) {
      event.preventDefault();
      closeSidebar(true);
      return;
    }
    containDrawerFocus(event);
  });
  mobileDrawerQuery.addEventListener("change", synchronizeSidebarMode);

  synchronizeSidebarMode();
  renderCurrentView();
  void establishSession();
}());
