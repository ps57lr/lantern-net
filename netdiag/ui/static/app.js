(function () {
  "use strict";

  const launchMatch = window.location.hash.match(/^#launch=([A-Za-z0-9_-]{32,256})$/);
  let launchToken = launchMatch ? launchMatch[1] : null;
  window.history.replaceState(null, "", window.location.pathname);

  const API_METHODS = Object.freeze({
    "/api/session/exchange": Object.freeze(["POST"]),
    "/api/session": Object.freeze(["GET"]),
    "/api/status": Object.freeze(["GET"]),
    "/api/status/events": Object.freeze(["GET"]),
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
  const PATH_SPECS = Object.freeze([
    Object.freeze({ id: "device", label: "Device route", icon: "device", module: "route" }),
    Object.freeze({ id: "gateway", label: "Gateway", icon: "gateway", module: "route" }),
    Object.freeze({ id: "internet", label: "Internet", icon: "globe", module: "route" }),
    Object.freeze({ id: "dns", label: "DNS", icon: "dns", module: "dns" }),
    Object.freeze({ id: "services", label: "Local services", icon: "mdns", module: "mdns" }),
  ]);
  const STATES = new Set(["ready", "running", "completed", "cancelled", "failed"]);
  const EXPORT_STATES = new Set(["completed", "cancelled", "failed"]);
  const GOALS = new Set(["problem", "network", "rescue"]);
  const PROFILES = new Set(["passive", "low_impact_network"]);
  const SUMMARY_TONES = new Set(["neutral", "positive", "attention", "critical"]);
  const CONFIDENCE_LEVELS = new Set(["high", "medium", "low", "none"]);
  const COVERAGE_LEVELS = new Set(["complete", "partial", "none"]);
  const PATH_STATUSES = new Set(["ok", "attention", "limited", "not_run", "unavailable"]);
  const ISSUE_SEVERITIES = new Set(["attention", "critical"]);
  const ISSUE_CODE_MODULE = Object.freeze({
    "NDG.ROUTE.DEFAULT_ROUTE_MISSING": "route",
    "NDG.ROUTE.OUTBOUND_HTTPS_FAILED": "route",
    "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED": "route",
    "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED": "route",
    "NDG.ROUTE.CHECK_FAILED": "route",
    "NDG.DNS.FILTERING_DETECTED": "dns",
    "NDG.DNS.RESOLVER_INCONSISTENT": "dns",
    "NDG.DNS.RESOLUTION_FAILED": "dns",
    "NDG.DNS.NO_RESOLVERS_CONFIGURED": "dns",
    "NDG.DNS.CHECK_FAILED": "dns",
    "NDG.WIFI.UNSUPPORTED": "wifi",
    "NDG.WIFI.SIGNAL_WEAK": "wifi",
    "NDG.WIFI.CHECK_FAILED": "wifi",
    "NDG.LAN.NEIGHBOR_CACHE_PARTIAL": "lan",
    "NDG.LAN.NEIGHBOR_CACHE_FAILED": "lan",
    "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED": "lan",
    "NDG.LAN.CHECK_FAILED": "lan",
    "NDG.MDNS.BROWSE_FAILED": "mdns",
    "NDG.MDNS.UNSUPPORTED": "mdns",
    "NDG.MDNS.CHECK_FAILED": "mdns",
    "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED": "ports",
    "NDG.PORTS.CHECK_FAILED": "ports",
  });
  const ISSUE_CODES = new Set(Object.keys(ISSUE_CODE_MODULE));
  const CRITICAL_ISSUE_CODES = new Set([
    "NDG.DNS.RESOLUTION_FAILED",
    "NDG.DNS.NO_RESOLVERS_CONFIGURED",
  ]);
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
  const PATH_STATUS_LABELS = Object.freeze({
    ok: "No issue reported",
    attention: "Needs attention",
    limited: "Partially checked",
    not_run: "Not checked",
    unavailable: "Unavailable",
  });
  const PATH_STATUS_ICONS = Object.freeze({
    ok: "check",
    attention: "alert",
    limited: "info",
    not_run: "clock",
    unavailable: "unknown",
  });
  const CONFIDENCE_LABELS = Object.freeze({
    high: "High confidence",
    medium: "Medium confidence",
    low: "Low confidence",
    none: "Confidence unavailable",
  });
  const COVERAGE_LABELS = Object.freeze({
    complete: "Complete planned coverage",
    partial: "Partial planned coverage",
    none: "No diagnostic coverage",
  });
  const NETWORK_DISCLAIMER = "This is an informational evaluation from one endpoint, not a whole-network assessment, security audit, or compliance certification for a home, business, financial system, or municipality.";
  const RESCUE_DISCLAIMER = "This is current-device and network guidance only; it does not determine bootability, storage or hardware health, OS integrity, encryption, backups, or data recoverability, and it does not perform recovery.";
  const GOAL_MODULE_ORDER = Object.freeze({
    problem: Object.freeze(["route", "wifi", "dns", "lan", "mdns", "ports"]),
    network: Object.freeze(["route", "dns", "ports", "lan", "wifi", "mdns"]),
    rescue: Object.freeze(["route", "wifi", "lan", "dns", "mdns", "ports"]),
  });
  const GOAL_EMPHASIS = Object.freeze({
    problem: Object.freeze({
      label: "Likely-cause emphasis",
      priority: "Connection path → Wi-Fi → Name lookup → Nearby devices → Local services → Gateway services",
    }),
    network: Object.freeze({
      label: "Network-path emphasis",
      priority: "Connection path → Name lookup → Gateway services → Nearby devices → Wi-Fi → Local services",
    }),
    rescue: Object.freeze({
      label: "Recovery-context emphasis",
      priority: "Connection path → Wi-Fi → Nearby devices → Name lookup → Local services → Gateway services",
    }),
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
    fixes: Object.freeze({ eyebrow: "Act safely", title: "Fixes", description: "Read-only next steps from completed checks. Lantern cannot apply changes from this page." }),
    rescue: Object.freeze({ eyebrow: "Guidance only", title: "Rescue guidance", description: "Network viability context without boot or recovery claims." }),
    session: Object.freeze({ eyebrow: "Local only", title: "LAN session", description: "Remote LAN access is not enabled and no LAN listener is running." }),
    share: Object.freeze({ eyebrow: "Local file", title: "Share", description: "Download a redacted JSON report to this computer. Nothing is uploaded." }),
  });

  let csrfToken = null;
  let authenticated = false;
  let sessionGeneration = 0;
  let statusSnapshot = null;
  let currentView = "overview";
  let pollTimer = null;
  let statusEventSource = null;
  let statusStreamGeneration = null;
  let sessionExpiryTimer = null;
  let sessionExpiresAt = 0;
  let pollInFlight = false;
  let startInFlight = false;
  let cancelInFlight = false;
  let revokeInFlight = false;
  let exportInFlight = false;
  let sessionCleared = false;
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

  function requiredSafeText(value, maximum, label) {
    if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
      throw new Error("Lantern returned invalid " + label + ".");
    }
    for (const character of value) {
      const code = character.codePointAt(0);
      if (code < 32 && character !== "\n" && character !== "\t") {
        throw new Error("Lantern returned invalid " + label + ".");
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
      headline: requiredSafeText(value.headline, 180, "status headline"),
      detail: requiredSafeText(value.detail, 600, "status detail"),
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

  function validateAssessment(value, run, state) {
    if (!exactKeys(value, ["sentence", "tone", "confidence", "coverage", "disclaimer"], [])) {
      throw new Error("Lantern returned an invalid assessment.");
    }
    if (
      !SUMMARY_TONES.has(value.tone) ||
      !CONFIDENCE_LEVELS.has(value.confidence) ||
      !COVERAGE_LEVELS.has(value.coverage)
    ) {
      throw new Error("Lantern returned an invalid assessment.");
    }
    const needsDisclaimer = Boolean(run && (run.goal === "network" || run.goal === "rescue"));
    let disclaimer = null;
    if (value.disclaimer !== null) {
      disclaimer = requiredSafeText(value.disclaimer, 300, "assessment disclaimer");
    }
    if (needsDisclaimer !== (disclaimer !== null)) {
      throw new Error("Lantern returned an inconsistent assessment boundary.");
    }
    if (run && run.goal === "network" && disclaimer !== NETWORK_DISCLAIMER) {
      throw new Error("Lantern returned an incomplete network assessment boundary.");
    }
    if (run && run.goal === "rescue" && disclaimer !== RESCUE_DISCLAIMER) {
      throw new Error("Lantern returned an incomplete rescue assessment boundary.");
    }
    if (
      (value.coverage === "none") !== (value.confidence === "none") ||
      (value.coverage === "partial" && value.confidence !== "low")
    ) {
      throw new Error("Lantern returned inconsistent assessment confidence.");
    }
    if (
      (state === "ready" || state === "running" || state === "failed") &&
      (value.confidence !== "none" || value.coverage !== "none")
    ) {
      throw new Error("Lantern returned an unsupported live assessment conclusion.");
    }
    return Object.freeze({
      sentence: requiredSafeText(value.sentence, 240, "assessment sentence"),
      tone: value.tone,
      confidence: value.confidence,
      coverage: value.coverage,
      disclaimer: disclaimer,
    });
  }

  function validateIssues(value) {
    if (!Array.isArray(value) || value.length > 3) {
      throw new Error("Lantern returned an invalid priority issue list.");
    }
    const codes = new Set();
    return Object.freeze(value.map((issue) => {
      if (!exactKeys(issue, ["code", "title", "explanation", "next_step", "module", "severity"], [])) {
        throw new Error("Lantern returned an invalid priority issue.");
      }
      if (
        typeof issue.code !== "string" ||
        issue.code.length > 96 ||
        !ISSUE_CODES.has(issue.code) ||
        codes.has(issue.code) ||
        ISSUE_CODE_MODULE[issue.code] !== issue.module ||
        !ISSUE_SEVERITIES.has(issue.severity) ||
        issue.severity !== (CRITICAL_ISSUE_CODES.has(issue.code) ? "critical" : "attention")
      ) {
        throw new Error("Lantern returned an invalid priority issue.");
      }
      codes.add(issue.code);
      return Object.freeze({
        code: issue.code,
        title: requiredSafeText(issue.title, 120, "priority issue title"),
        explanation: requiredSafeText(issue.explanation, 240, "priority issue explanation"),
        next_step: requiredSafeText(issue.next_step, 240, "priority issue next step"),
        module: issue.module,
        severity: issue.severity,
      });
    }));
  }

  function validatePath(value) {
    if (!Array.isArray(value) || value.length !== PATH_SPECS.length) {
      throw new Error("Lantern returned an invalid path.");
    }
    return Object.freeze(value.map((node, index) => {
      const spec = PATH_SPECS[index];
      if (!exactKeys(node, ["id", "label", "status", "detail", "module"], [])) {
        throw new Error("Lantern returned an invalid path node.");
      }
      if (
        node.id !== spec.id ||
        node.label !== spec.label ||
        !PATH_STATUSES.has(node.status) ||
        node.module !== spec.module
      ) {
        throw new Error("Lantern returned an invalid path node.");
      }
      return Object.freeze({
        id: node.id,
        label: node.label,
        status: node.status,
        detail: requiredSafeText(node.detail, 200, "path detail"),
        module: node.module,
      });
    }));
  }

  function validateModules(value, goal) {
    if (!Array.isArray(value) || value.length !== MODULE_IDS.length) {
      throw new Error("Lantern returned an invalid module list.");
    }
    const expectedOrder = GOAL_MODULE_ORDER[goal];
    return Object.freeze(value.map((module, index) => {
      if (!exactKeys(module, ["id", "label", "status", "detail", "finding", "why_it_matters", "technical"], [])) {
        throw new Error("Lantern returned an invalid module result.");
      }
      if (
        module.id !== expectedOrder[index] ||
        !MODULE_STATUSES.has(module.status) ||
        typeof module.why_it_matters !== "string" ||
        module.why_it_matters.length < 1 ||
        module.why_it_matters.length > 240 ||
        !Array.isArray(module.technical) ||
        module.technical.length > 4
      ) {
        throw new Error("Lantern returned an invalid module result.");
      }
      return Object.freeze({
        id: module.id,
        label: requiredSafeText(module.label, 64, "module label"),
        status: module.status,
        detail: requiredSafeText(module.detail, 500, "module detail"),
        finding: requiredSafeText(module.finding, 180, "module finding"),
        why_it_matters: requiredSafeText(module.why_it_matters, 240, "module context"),
        technical: Object.freeze(module.technical.map((item) => requiredSafeText(item, 180, "technical context"))),
      });
    }));
  }

  function validateCapabilities(value, state) {
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
    for (const name of ["active_discovery", "remediation", "credentials", "lan_remote", "rescue_boot"]) {
      if (result[name] !== false) {
        throw new Error("Lantern refused an unsafe capability description.");
      }
    }
    if (result.share_export !== false && !EXPORT_STATES.has(state)) {
      throw new Error("Lantern refused an unsafe capability description.");
    }
    if (result.share_export !== true && EXPORT_STATES.has(state)) {
      throw new Error("Lantern returned an inconsistent export capability.");
    }
    return Object.freeze(result);
  }

  function validateStatus(value) {
    if (!exactKeys(value, ["schema", "product", "transport", "state", "summary", "assessment", "issues", "path", "run", "progress", "modules", "capabilities"], [])) {
      throw new Error("Lantern returned an invalid status snapshot.");
    }
    if (value.schema !== "lantern.ui.v2" || value.product !== "Lantern" || value.transport !== "loopback" || !STATES.has(value.state)) {
      throw new Error("Lantern returned an unsupported status snapshot.");
    }
    const run = validateRun(value.run);
    if ((value.state === "ready") !== (run === null)) {
      throw new Error("Lantern returned an inconsistent diagnostic state.");
    }
    if (value.state === "cancelled" && run.cancel_requested !== true) {
      throw new Error("Lantern returned an unrequested cancellation.");
    }
    const summary = validateSummary(value.summary);
    const assessment = validateAssessment(value.assessment, run, value.state);
    if (assessment.tone !== summary.tone) {
      throw new Error("Lantern returned an inconsistent assessment tone.");
    }
    if (
      ((value.state === "ready" || value.state === "running") && assessment.tone !== "neutral") ||
      ((value.state === "cancelled" || value.state === "failed") && assessment.tone !== "attention" && assessment.tone !== "critical") ||
      (value.state === "completed" && assessment.tone === "neutral")
    ) {
      throw new Error("Lantern returned an inconsistent state assessment.");
    }
    const issues = validateIssues(value.issues);
    const path = validatePath(value.path);
    const modules = validateModules(value.modules, run ? run.goal : "problem");
    if (
      assessment.tone === "positive" &&
      (
        value.state !== "completed" ||
        assessment.coverage !== "complete" ||
        issues.length !== 0 ||
        path.some((node) => node.status !== "ok") ||
        modules.some((module) => module.status !== "ok")
      )
    ) {
      throw new Error("Lantern returned an unsupported positive assessment.");
    }
    if (issues.some((issue) => issue.severity === "critical") && assessment.tone !== "critical") {
      throw new Error("Lantern returned an understated critical assessment.");
    }
    const hasAttention = issues.length > 0 ||
      path.some((node) => node.status === "attention") ||
      modules.some((module) => module.status === "attention");
    if (hasAttention && assessment.tone !== "attention" && assessment.tone !== "critical") {
      throw new Error("Lantern returned an understated attention assessment.");
    }
    return Object.freeze({
      schema: value.schema,
      product: value.product,
      transport: value.transport,
      state: value.state,
      summary: summary,
      assessment: assessment,
      issues: issues,
      path: path,
      run: run,
      progress: validateProgress(value.progress),
      modules: modules,
      capabilities: validateCapabilities(value.capabilities, value.state),
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
    exportInFlight = false;
    pollInFlight = false;
    authenticated = false;
    csrfToken = null;
    sessionCleared = true;
    stopStatusStream();
    stopPolling();
    newCheckButton.disabled = true;
    setSessionActionsDisabled(true);
    cancelButton.disabled = true;
    connectionState.textContent = "Local session closed";
    runAnnouncement.textContent = "";
    showNotice(message, tone === "info" ? "info" : "attention");
    statusSnapshot = null;
    syncCapabilityNavigation();
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
      sessionCleared = false;
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

  function stopStatusStream() {
    statusStreamGeneration = null;
    if (statusEventSource !== null) {
      statusEventSource.close();
      statusEventSource = null;
    }
  }

  function syncCapabilityNavigation() {
    const shareEnabled = Boolean(statusSnapshot && statusSnapshot.capabilities.share_export);
    for (const item of document.querySelectorAll("[data-view-target=\"share\"]")) {
      item.disabled = !shareEnabled;
      const note = item.querySelector(".nav-note");
      if (note) {
        note.textContent = shareEnabled ? "Local file" : "After check";
      }
    }
  }

  function applyStatusSnapshot(nextSnapshot, generation) {
    if (!isCurrentSession(generation)) {
      return false;
    }
    const previousState = statusSnapshot ? statusSnapshot.state : null;
    const changed = JSON.stringify(nextSnapshot) !== JSON.stringify(statusSnapshot);
    statusSnapshot = nextSnapshot;
    connectionState.textContent = statusSnapshot.state === "running" ? "Checking locally" : "Private local session";
    hideNotice();
    announceState(statusSnapshot.state, previousState);
    syncCapabilityNavigation();
    if (changed) {
      renderCurrentView();
    }
    if (statusSnapshot.state === "running") {
      openStatusStream(generation);
    } else {
      stopStatusStream();
      stopPolling();
    }
    return true;
  }

  function openStatusStream(generation) {
    if (!isCurrentSession(generation) || statusStreamGeneration === generation) {
      return;
    }
    stopStatusStream();
    stopPolling();
    statusStreamGeneration = generation;
    const streamUrl = new URL("/api/status/events", window.location.origin);
    if (streamUrl.origin !== window.location.origin || streamUrl.pathname !== "/api/status/events") {
      schedulePoll(POLL_RUNNING_MS, false, generation);
      return;
    }
    const source = new EventSource(streamUrl.toString());
    statusEventSource = source;

    source.addEventListener("status", function (event) {
      if (!isCurrentSession(generation) || statusStreamGeneration !== generation) {
        return;
      }
      try {
        const payload = JSON.parse(String(event.data));
        applyStatusSnapshot(validateStatus(payload), generation);
      } catch (_error) {
        showNotice("Lantern received an invalid status stream update. It will fall back to periodic status checks.", "attention");
        stopStatusStream();
        schedulePoll(POLL_RUNNING_MS, false, generation);
      }
    });

    source.addEventListener("close", function () {
      if (!isCurrentSession(generation) || statusStreamGeneration !== generation) {
        return;
      }
      const stillRunning = Boolean(statusSnapshot && statusSnapshot.state === "running");
      stopStatusStream();
      if (stillRunning) {
        schedulePoll(POLL_RUNNING_MS, false, generation);
      }
    });

    source.addEventListener("error", function () {
      if (!isCurrentSession(generation) || statusStreamGeneration !== generation) {
        return;
      }
      stopStatusStream();
      if (statusSnapshot && statusSnapshot.state === "running") {
        schedulePoll(POLL_RUNNING_MS, false, generation);
      }
    });
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
      applyStatusSnapshot(nextSnapshot, generation);
      if (statusSnapshot && statusSnapshot.state === "running" && statusEventSource === null) {
        schedulePoll(POLL_RUNNING_MS, false, generation);
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
    button.append(heading, createElement("p", "module-detail", module.finding));
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

  function renderStatusUnavailable() {
    const panel = createElement("section", "panel connection-panel");
    const copy = createElement("div", "");
    if (sessionCleared) {
      copy.append(createElement("h2", "", "Lantern is disconnected"));
      copy.append(createElement("p", "", "This page no longer has a private local session. Launch Lantern again to continue."));
    } else {
      copy.append(createElement("h2", "", "Connecting to Lantern"));
      copy.append(createElement("p", "", "Waiting for a private local status. No diagnostic starts automatically."));
    }
    panel.append(copy);
    return panel;
  }

  function assessmentPanel() {
    if (!statusSnapshot) {
      const panel = createElement("section", "panel connection-panel");
      panel.append(createIcon("lock"), createElement("h2", "", "No authenticated local status"));
      panel.append(createElement("p", "", "Launch Lantern again if this tab no longer has a private local session."));
      return panel;
    }
    const assessment = statusSnapshot.assessment;
    const panel = createElement("section", "summary-panel assessment-panel tone-" + assessment.tone);
    const copy = createElement("div", "summary-copy assessment-copy");
    copy.append(createElement("p", "eyebrow", statusSnapshot.state === "running" ? "Assessment in progress" : "Lantern assessment"));
    copy.append(createElement("h2", "", assessment.sentence));
    copy.append(createElement("p", "assessment-detail", statusSnapshot.summary.detail));

    const facts = document.createElement("dl");
    facts.className = "assessment-facts";
    const confidence = createElement("div", "assessment-fact");
    confidence.append(createElement("dt", "", "Confidence"), createElement("dd", "", CONFIDENCE_LABELS[assessment.confidence]));
    const coverage = createElement("div", "assessment-fact");
    coverage.append(createElement("dt", "", "Coverage"), createElement("dd", "", COVERAGE_LABELS[assessment.coverage]));
    facts.append(confidence, coverage);
    copy.append(facts);

    if (assessment.disclaimer !== null) {
      const boundary = createElement("div", "assessment-boundary");
      boundary.append(createIcon("info"), createElement("p", "", assessment.disclaimer));
      copy.append(boundary);
    }
    panel.append(copy);
    const shield = createElement("span", "summary-mark");
    shield.append(createIcon(assessment.tone === "positive" ? "shield-check" : "shield"));
    panel.append(shield);
    return panel;
  }

  function renderPriorityIssues() {
    if (!statusSnapshot || statusSnapshot.state === "ready" || statusSnapshot.state === "running") {
      return null;
    }
    const section = createElement("section", "priority-section");
    const heading = createElement("div", "section-heading-row");
    heading.append(createElement("div", "", ""));
    const headingCopy = heading.firstElementChild;
    headingCopy.append(createElement("p", "eyebrow", "What deserves attention"));
    headingCopy.append(createElement("h2", "section-title", "Priority review"));
    heading.append(createElement("span", "issue-count", String(statusSnapshot.issues.length) + " of 3 maximum"));
    section.append(heading);

    if (statusSnapshot.issues.length === 0) {
      const empty = createElement("div", "panel priority-empty");
      const fullyPositive = statusSnapshot.assessment.tone === "positive" && statusSnapshot.assessment.coverage === "complete";
      empty.append(createIcon(fullyPositive ? "check" : "unknown"));
      const copy = createElement("div", "");
      const title = fullyPositive
        ? "No priority issue was returned from the completed plan"
        : "No priority issue is available from this run";
      copy.append(createElement("h3", "", title));
      copy.append(createElement("p", "", "Use the confidence, coverage, path, and module states above before drawing a broader conclusion."));
      empty.append(copy);
      section.append(empty);
      return section;
    }

    const grid = createElement("div", "issue-grid");
    statusSnapshot.issues.forEach(function (issue, index) {
      const card = createElement("article", "panel issue-card issue-" + issue.severity);
      const cardHeading = createElement("div", "issue-card-heading");
      cardHeading.append(createElement("span", "issue-rank", String(index + 1)));
      const title = createElement("div", "");
      title.append(createElement("p", "issue-module", PAGE_META[issue.module].title));
      title.append(createElement("h3", "", issue.title));
      cardHeading.append(title);
      card.append(cardHeading, createElement("p", "issue-explanation", issue.explanation));
      const next = createElement("div", "safe-next-step");
      next.append(createIcon("arrow-right"));
      const nextCopy = createElement("div", "");
      nextCopy.append(createElement("strong", "", "Safe next step"), createElement("p", "", issue.next_step));
      next.append(nextCopy);
      card.append(next);
      grid.append(card);
    });
    section.append(grid);
    return section;
  }

  function pathStatusBadge(status) {
    const badge = createElement("span", "path-status path-status-" + status);
    badge.append(createIcon(PATH_STATUS_ICONS[status]), document.createTextNode(PATH_STATUS_LABELS[status]));
    return badge;
  }

  function renderLanternPath() {
    if (!statusSnapshot) {
      return null;
    }
    const section = createElement("section", "path-section");
    const heading = createElement("div", "section-heading-row");
    const headingCopy = createElement("div", "");
    headingCopy.append(createElement("p", "eyebrow", "Five diagnostic layers"));
    headingCopy.append(createElement("h2", "section-title", "Lantern Path"));
    heading.append(headingCopy, createElement("p", "section-note", "A diagnostic-layer map—not a network topology. DNS and local services are independent views."));
    section.append(heading);
    const path = document.createElement("ol");
    path.className = "lantern-path";
    path.setAttribute("aria-label", "Lantern Path diagnostic-layer map");
    statusSnapshot.path.forEach(function (node, index) {
      const spec = PATH_SPECS[index];
      const item = createElement("li", "path-node path-node-" + node.status);
      const mark = createElement("span", "path-mark");
      mark.append(createIcon(spec.icon));
      const copy = createElement("div", "path-copy");
      copy.append(createElement("h3", "", node.label), pathStatusBadge(node.status));
      copy.append(createElement("p", "", node.detail));
      item.append(mark, copy);
      path.append(item);
    });
    section.append(path);
    return section;
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

  function goalEmphasisText(goal) {
    const emphasis = GOAL_EMPHASIS[goal];
    return emphasis.label + ". Priority emphasis: " + emphasis.priority + ".";
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
      choiceRow("goal", "network", "Evaluate this network", "Prioritize path viability for a household, business, or municipality."),
      choiceRow("goal", "rescue", "Gather network context for recovery", "Network viability only—not boot, hardware, storage, encryption, or recoverability."),
    );
    form.append(goals);

    const emphasis = createElement("div", "presentation-emphasis");
    emphasis.id = "goal-emphasis";
    const emphasisCopy = createElement("p", "");
    emphasisCopy.id = "goal-emphasis-copy";
    emphasisCopy.setAttribute("aria-live", "polite");
    emphasisCopy.textContent = goalEmphasisText(draftGoal);
    emphasis.append(createIcon("overview"), emphasisCopy);
    const scopeCopy = createElement("p", "goal-scope-copy", "Goal selection changes priority emphasis, module presentation order, and priority-issue ordering only. It never changes the diagnostic profile, packet activity, or scan scope. Run network checks only on a network you own, manage, or are explicitly authorized to assess. " + NETWORK_DISCLAIMER);
    emphasis.append(scopeCopy);
    form.append(emphasis);

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
      ["share_export", "Export or share", statusSnapshot && statusSnapshot.capabilities.share_export
        ? "Download a redacted JSON report to this computer only."
        : "Report export becomes available after a finished check."],
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
    fragment.append(assessmentPanel());
    if (!statusSnapshot || statusSnapshot.state === "ready") {
      fragment.append(renderStartPanel());
    }
    const priority = renderPriorityIssues();
    const path = renderLanternPath();
    if (priority) {
      fragment.append(priority);
    }
    if (path) {
      fragment.append(path);
    }
    fragment.append(renderModules("Module coverage"));
    if (statusSnapshot && statusSnapshot.state !== "ready" && statusSnapshot.state !== "running") {
      fragment.append(renderStartPanel());
    }
    fragment.append(capabilityPanel());
    return fragment;
  }

  function renderDevice() {
    const fragment = document.createDocumentFragment();
    fragment.append(assessmentPanel());
    const panel = createElement("section", "panel explanation-panel");
    panel.append(createIcon("device"), createElement("h2", "", "Network-facing device context"));
    panel.append(createElement("p", "", "This diagnostic may observe local interface, routing, Wi-Fi, and neighbor-table state. It does not claim to evaluate processor, memory, battery, storage, operating-system integrity, or general hardware health."));
    fragment.append(panel);
    return fragment;
  }

  function renderNetwork() {
    const fragment = document.createDocumentFragment();
    fragment.append(assessmentPanel());
    const path = renderLanternPath();
    if (path) {
      fragment.append(path);
    }
    fragment.append(renderModules("From local link to name resolution"));
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
    panel.append(heading);
    const finding = createElement("div", "module-finding");
    finding.append(createElement("p", "eyebrow", "Why this matters"));
    finding.append(createElement("p", "module-why", module.why_it_matters));
    finding.append(createElement("p", "eyebrow", "Safe finding summary"));
    finding.append(createElement("h3", "", module.finding));
    finding.append(createElement("p", "module-focus-detail", module.detail));
    panel.append(finding);

    const related = statusSnapshot.issues.filter((issue) => issue.module === module.id);
    if (related.length > 0) {
      const next = createElement("section", "module-next-step");
      next.append(createIcon("arrow-right"));
      const nextCopy = createElement("div", "");
      nextCopy.append(createElement("h3", "", "Safe next step"), createElement("p", "", related[0].next_step));
      next.append(nextCopy);
      panel.append(next);
    }

    const disclosure = document.createElement("details");
    disclosure.className = "technical-disclosure";
    disclosure.id = "technical-disclosure-" + module.id;
    const disclosureSummary = document.createElement("summary");
    disclosureSummary.id = "technical-summary-" + module.id;
    disclosureSummary.append(createElement("span", "", "Technical context"));
    disclosureSummary.append(createElement("small", "", "Safe, identifier-free detail"));
    disclosure.append(disclosureSummary);
    const disclosureBody = createElement("div", "technical-disclosure-body");
    if (module.technical.length === 0) {
      disclosureBody.append(createElement("p", "", "No additional technical context is available for this module state."));
    } else {
      const list = document.createElement("ul");
      for (const item of module.technical) {
        list.append(createElement("li", "", item));
      }
      disclosureBody.append(list);
    }
    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "secondary-button module-copy-button";
    copyButton.textContent = "Copy redacted module JSON";
    copyButton.onclick = function () {
      const payload = JSON.stringify({
        id: module.id,
        label: module.label,
        status: module.status,
        finding: module.finding,
        why_it_matters: module.why_it_matters,
        technical: module.technical,
      });
      const helper = document.createElement("textarea");
      helper.value = payload;
      helper.setAttribute("readonly", "readonly");
      helper.style.position = "fixed";
      helper.style.left = "-9999px";
      document.body.append(helper);
      helper.select();
      let copied = false;
      try {
        copied = document.execCommand("copy");
      } catch (_error) {
        copied = false;
      }
      helper.remove();
      showNotice(
        copied ? "Redacted module JSON was copied on this computer." : "Lantern could not copy the module JSON automatically.",
        copied ? "info" : "attention",
      );
    };
    disclosureBody.append(copyButton);
    disclosure.append(disclosureBody);
    panel.append(disclosure);
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
    if (!statusSnapshot) {
      return emptyPanel("No authenticated status is available.");
    }
    const fragment = document.createDocumentFragment();
    const banner = createElement("section", "panel explanation-panel");
    banner.append(createIcon("wrench"), createElement("h2", "", "Read-only next steps"));
    banner.append(createElement("p", "", "Lantern can diagnose and explain, but it cannot preview, approve, apply, or roll back a change. No remediation handlers are connected."));
    fragment.append(banner);

    if (statusSnapshot.issues.length === 0) {
      const empty = createElement("section", "panel unavailable-panel");
      empty.append(createIcon("info"), createElement("h2", "", "No priority recommendation yet"));
      empty.append(createElement("p", "", "Start and finish a check to receive up to three safe next steps from the completed result."));
      fragment.append(empty);
    } else {
      const list = createElement("section", "panel recommendation-list");
      list.append(createElement("h2", "", "Suggested next steps"));
      for (const issue of statusSnapshot.issues) {
        const card = createElement("article", "issue-card recommendation-card");
        card.append(createElement("p", "eyebrow", issue.module), createElement("h3", "", issue.title));
        card.append(createElement("p", "", issue.explanation));
        const step = createElement("div", "module-next-step");
        step.append(createIcon("arrow-right"));
        const stepCopy = createElement("div", "");
        stepCopy.append(createElement("h4", "", "Safe next step"), createElement("p", "", issue.next_step));
        step.append(stepCopy);
        card.append(step);
        list.append(card);
      }
      fragment.append(list);
    }

    const boundary = createElement("section", "panel safety-panel");
    boundary.append(createIcon("shield"), createElement("h2", "", "Fixes are unavailable"));
    boundary.append(createElement("p", "", "This interface does not apply changes automatically and cannot enter administrator credentials."));
    fragment.append(boundary);
    return fragment;
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

  function downloadReport(trigger) {
    if (exportInFlight) {
      return;
    }
    if (!statusSnapshot || !statusSnapshot.capabilities.share_export) {
      showNotice("Report export is available only after a finished check.", "attention");
      return;
    }
    exportInFlight = true;
    trigger.disabled = true;
    trigger.textContent = "Preparing local file…";
    try {
      const exported = validateStatus(JSON.parse(JSON.stringify(statusSnapshot)));
      const payload = JSON.stringify(exported, null, 2) + "\n";
      const blob = new Blob([payload], { type: "application/json" });
      if (blob.size > MAX_JSON_BYTES) {
        showNotice("The redacted report exceeded the local size limit.", "attention");
        return;
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "lantern-report-" + exported.state + ".json";
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showNotice("Redacted report downloaded to this computer. Nothing was uploaded.", "info");
    } catch (_error) {
      showNotice("Lantern could not create the local report.", "attention");
    } finally {
      exportInFlight = false;
      trigger.disabled = false;
      trigger.textContent = "Download reviewed JSON";
    }
  }

  function renderShare() {
    if (!statusSnapshot) {
      return emptyPanel("No authenticated status is available.");
    }
    const fragment = document.createDocumentFragment();
    const panel = createElement("section", "panel explanation-panel");
    panel.append(createIcon("share"), createElement("h2", "", "Download a redacted report"));
    if (statusSnapshot.capabilities.share_export) {
      panel.append(createElement("p", "", "Review the same identifier-free presentation Lantern shows in the browser before creating a local file. Lantern does not upload or transmit it; your browser, operating system, backup, or sync settings control what happens to downloaded files."));
      const included = createElement("section", "report-boundary");
      included.append(createElement("h3", "", "Included"));
      included.append(createElement("p", "", "The selected goal and profile, run timing, diagnostic condition, confidence, coverage, safe findings and next steps, path and module summaries, and capability states."));
      const excluded = createElement("section", "report-boundary");
      excluded.append(createElement("h3", "", "Excluded"));
      excluded.append(createElement("p", "", "Raw evidence, hostnames, Wi-Fi names, device identifiers, IP or MAC addresses, credentials, recovery keys, and native error text."));
      panel.append(included, excluded);
      panel.append(createElement("p", "report-warning", "This report may still reveal the selected goal, diagnostic condition, findings, and timing. Review it before sending it to anyone."));
      const preview = document.createElement("details");
      preview.className = "technical-disclosure report-preview";
      const previewSummary = document.createElement("summary");
      previewSummary.textContent = "Review redacted JSON";
      const previewBody = createElement("pre", "report-preview-json", JSON.stringify(statusSnapshot, null, 2));
      previewBody.tabIndex = 0;
      previewBody.setAttribute("aria-label", "Share-safe report JSON preview");
      preview.append(previewSummary, previewBody);
      panel.append(preview);
      const button = createElement("button", "primary-button", "Download reviewed JSON");
      button.type = "button";
      button.addEventListener("click", function () {
        downloadReport(button);
      });
      panel.append(button);
    } else {
      panel.append(createElement("p", "", "Sharing is disabled until a diagnostic check reaches a finished state."));
    }
    fragment.append(panel);

    const boundary = createElement("section", "panel safety-panel");
    boundary.append(createIcon("shield"), createElement("h2", "", "Local-only boundary"));
    boundary.append(createElement("p", "", "Lantern has no external destination and does not upload this report. Download storage, backup, and synchronization are controlled outside Lantern."));
    fragment.append(boundary);
    return fragment;
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
    const unavailable = statusSnapshot === null;
    const meta = PAGE_META[currentView] || PAGE_META.overview;
    pageEyebrow.textContent = unavailable ? "Local only" : meta.eyebrow;
    pageTitle.textContent = unavailable
      ? (sessionCleared ? "Local session closed" : "Connecting")
      : meta.title;
    pageDescription.textContent = unavailable
      ? (sessionCleared
        ? "Lantern has stopped using this private local session."
        : "Lantern is waiting for its private local service.")
      : meta.description;
    renderProgress();

    let content;
    if (unavailable) {
      content = renderStatusUnavailable();
    } else if (currentView === "overview") {
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
    const openDisclosure = pageContent.querySelector("details.technical-disclosure[open]");
    const openDisclosureId = openDisclosure ? openDisclosure.id : "";
    pageContent.replaceChildren(content);
    if (openDisclosureId) {
      const replacementDisclosure = document.getElementById(openDisclosureId);
      if (replacementDisclosure) {
        replacementDisclosure.open = true;
      }
    }
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
      const emphasis = document.getElementById("goal-emphasis-copy");
      if (emphasis) {
        emphasis.textContent = goalEmphasisText(draftGoal);
      }
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
