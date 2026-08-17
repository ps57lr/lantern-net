(function () {
  "use strict";

  const DEMO_MODE = true;

  const ICON_NAMES = new Set([
    "alert",
    "arrow-right",
    "check",
    "chevron-right",
    "clock",
    "copy",
    "device",
    "dns",
    "download",
    "gateway",
    "globe",
    "info",
    "key",
    "lan",
    "lantern",
    "lock",
    "mdns",
    "network",
    "ports",
    "refresh",
    "rescue",
    "scan",
    "session",
    "share",
    "shield",
    "shield-check",
    "unknown",
    "wifi",
    "wrench",
  ]);

  const STATUS = Object.freeze({
    healthy: Object.freeze({ label: "Healthy", icon: "check" }),
    attention: Object.freeze({ label: "Needs attention", icon: "alert" }),
    critical: Object.freeze({ label: "Critical", icon: "alert" }),
    info: Object.freeze({ label: "Information", icon: "info" }),
    unknown: Object.freeze({ label: "Not confirmed", icon: "unknown" }),
    blocked: Object.freeze({ label: "Access needed", icon: "lock" }),
  });

  const PAGE_META = Object.freeze({
    overview: Object.freeze({ eyebrow: "Diagnosis", title: "Overview", description: "The clearest picture of this device and its network path." }),
    device: Object.freeze({ eyebrow: "Diagnosis", title: "This device", description: "What Lantern can confirm about the computer in front of you." }),
    network: Object.freeze({ eyebrow: "Network", title: "Network health", description: "Read the connection from the local link outward, one layer at a time." }),
    route: Object.freeze({ eyebrow: "Network module", title: "Route & internet", description: "Default route, gateway reachability, and the outbound internet path." }),
    wifi: Object.freeze({ eyebrow: "Network module", title: "Wi-Fi", description: "Association, signal quality, channel, band, and link details." }),
    dns: Object.freeze({ eyebrow: "Network module", title: "DNS", description: "How configured and comparison resolvers answer the same question." }),
    lan: Object.freeze({ eyebrow: "Network module", title: "LAN neighbors", description: "Scoped devices observed on the default local network." }),
    mdns: Object.freeze({ eyebrow: "Network module", title: "mDNS services", description: "Nearby service advertisements observed during a bounded browse window." }),
    ports: Object.freeze({ eyebrow: "Network module", title: "Service ports", description: "Explicit, bounded TCP reachability checks for an authorized target." }),
    fixes: Object.freeze({ eyebrow: "Act safely", title: "Fixes", description: "Preview what can change, approve deliberately, verify, and roll back." }),
    share: Object.freeze({ eyebrow: "Private support", title: "Share a report", description: "Review exactly what remains before anything leaves this computer." }),
    session: Object.freeze({ eyebrow: "Temporary connection", title: "LAN session", description: "A short-lived, paired, read-only view for someone on this network." }),
    rescue: Object.freeze({ eyebrow: "Last resort", title: "Rescue viability", description: "Protect data first, then assess hardware, storage, operating system, and network." }),
  });

  // The fixture is intentionally isolated from transport and platform APIs. It is
  // synthetic, contains no user data, and powers only this interface demonstration.
  const DEMO_FIXTURE = deepFreeze({
    meta: {
      mode: "Read-only demonstration",
      platform: "macOS · demo fixture",
      started: "Today at 9:41 PM",
      duration: "18.4 seconds",
      schema: "Experience fixture 1.0",
      scope: "This device + passive network",
    },
    assessment: {
      status: "attention",
      title: "Your internet path works. One DNS answer deserves a closer look.",
      summary: "The device reaches its gateway and the public internet. The configured resolver returned a different result for one test, which may be intentional filtering rather than a connection failure.",
      confidence: "Moderate confidence",
      scope: "Likely DNS-specific",
    },
    path: [
      { id: "device", label: "Device", detail: "Interface active", icon: "device", status: "healthy", target: "device" },
      { id: "link", label: "Local link", detail: "Wi-Fi is fair", icon: "wifi", status: "attention", target: "wifi" },
      { id: "gateway", label: "Gateway", detail: "192.168.0.1", icon: "gateway", status: "healthy", target: "route" },
      { id: "internet", label: "Internet", detail: "TCP/443 works", icon: "globe", status: "healthy", target: "route" },
      { id: "dns", label: "DNS", detail: "Answers differ", icon: "dns", status: "attention", target: "dns" },
    ],
    issues: [
      {
        code: "DNS.ANSWER_VARIANCE",
        status: "attention",
        title: "One resolver returned a different answer",
        detail: "That can be normal for content delivery or intentional DNS filtering. Confirm the expected policy before changing anything.",
        target: "dns",
      },
      {
        code: "WIFI.SIGNAL_FAIR",
        status: "info",
        title: "Wi-Fi signal is usable, not excellent",
        detail: "A fair signal can explain intermittent calls or slower transfers without causing a total outage.",
        target: "wifi",
      },
    ],
    working: [
      { title: "Default gateway is reachable", detail: "The device has a valid local path through 192.168.0.1." },
      { title: "Outbound HTTPS works", detail: "A TCP connection reached a public endpoint." },
      { title: "LAN scope is deterministic", detail: "Passive neighbors are limited to en0 and 192.168.0.0/24." },
    ],
    access: [
      { title: "DNS administrator", reason: "Needed only if the different answer is not expected policy.", where: "Authorize in the DNS service itself; Lantern does not collect the password.", status: "Not needed yet" },
      { title: "Router administrator", reason: "Needed only for gateway or Wi-Fi configuration changes.", where: "Open the router's own interface when a reviewed step requires it.", status: "Keep available" },
    ],
    modules: {
      route: {
        title: "Route & internet",
        icon: "gateway",
        status: "healthy",
        state: "complete",
        summary: "The gateway and outbound HTTPS path are working.",
        why: "Routing connects this device to everything beyond its own local address. A broken default path can explain many downstream symptoms at once.",
        next: "No route change is recommended. Keep this evidence as a known-good layer.",
        metrics: [
          { label: "Interface", value: "en0" },
          { label: "Gateway", value: "192.168.0.1" },
          { label: "HTTPS path", value: "Working" },
          { label: "Check time", value: "4.2 s" },
        ],
        evidence: [
          { label: "Default route", value: "Gateway 192.168.0.1 through en0", source: "route adapter" },
          { label: "Gateway ping", value: "3 of 3 replies in the demo fixture", source: "ICMP probe" },
          { label: "Outbound TCP", value: "Connected to test endpoint on port 443", source: "socket probe" },
          { label: "Interpretation", value: "Local and internet routing are corroborated by independent probes.", source: "diagnosis rule" },
        ],
      },
      wifi: {
        title: "Wi-Fi",
        icon: "wifi",
        status: "attention",
        state: "partial",
        summary: "Connected with fair signal; brief degradation is plausible.",
        why: "Signal and link quality can cause slow or intermittent service even when the internet path is otherwise healthy.",
        next: "If the problem is intermittent, compare another location or access point before changing settings.",
        metrics: [
          { label: "Connection", value: "Connected" },
          { label: "Signal", value: "−69 dBm" },
          { label: "Band", value: "5 GHz" },
          { label: "Channel", value: "44" },
        ],
        evidence: [
          { label: "Signal assessment", value: "Fair—expected to work with less margin than a strong signal", source: "Wi-Fi adapter" },
          { label: "Network name", value: "Hidden in share-safe views", source: "structured redaction" },
          { label: "Link detail", value: "Security detail unavailable in this fixture", source: "not tested" },
        ],
      },
      dns: {
        title: "DNS",
        icon: "dns",
        status: "attention",
        state: "partial",
        summary: "Resolution works, but the configured and comparison answers differ.",
        why: "DNS turns service names into addresses. Filtering, stale answers, or a resolver failure can look like an internet outage for only some apps.",
        next: "Confirm whether the configured resolver is meant to filter this domain before applying any fix.",
        metrics: [
          { label: "System resolver", value: "192.168.0.53" },
          { label: "System latency", value: "18 ms" },
          { label: "Comparison", value: "1.1.1.1" },
          { label: "Result", value: "Answers differ" },
        ],
        evidence: [
          { label: "Configured answer", value: "0.0.0.0 (possible intentional block)", source: "DNS probe" },
          { label: "Comparison answer", value: "203.0.113.24 (documentation address)", source: "DNS probe" },
          { label: "Both responded", value: "Neither resolver timed out", source: "probe timing" },
          { label: "Interpretation", value: "Difference is real; intent is not known from network evidence alone.", source: "diagnosis rule" },
        ],
      },
      lan: {
        title: "LAN neighbors",
        icon: "lan",
        status: "healthy",
        state: "complete",
        summary: "Passive neighbor evidence is scoped to the default interface.",
        why: "A scoped local view can confirm the gateway and nearby devices without sweeping unrelated VPN, container, or virtual networks.",
        next: "No active scan is needed for the current question.",
        metrics: [
          { label: "Network", value: "192.168.0.0/24" },
          { label: "Interface", value: "en0" },
          { label: "Observed", value: "12 entries" },
          { label: "Discovery", value: "Passive" },
        ],
        evidence: [
          { label: "Source", value: "Route-socket neighbor table", source: "sysctl_rtm" },
          { label: "Scope", value: "Only addresses in 192.168.0.0/24 on en0", source: "scope policy" },
          { label: "Meaning", value: "Observed entries may be stale and do not prove current device identity.", source: "evidence note" },
        ],
      },
      mdns: {
        title: "mDNS services",
        icon: "mdns",
        status: "unknown",
        state: "error",
        summary: "The bounded browse ended early, so nearby services are unknown.",
        why: "mDNS reveals services that advertise themselves locally. A brief empty or failed browse is not proof that no services exist.",
        next: "Retry this module by itself. The rest of the report remains valid.",
        metrics: [
          { label: "Browse window", value: "5 seconds" },
          { label: "Unique", value: "Unknown" },
          { label: "Raw records", value: "Unknown" },
          { label: "State", value: "Could not complete" },
        ],
        evidence: [
          { label: "Failure class", value: "Fixture demonstrates an isolated native-tool error", source: "probe boundary" },
          { label: "Report impact", value: "Other network modules completed normally", source: "orchestrator" },
        ],
      },
      ports: {
        title: "Service ports",
        icon: "ports",
        status: "unknown",
        state: "unsupported",
        summary: "No explicit target was approved for a TCP service check.",
        why: "A port check sends traffic to a named host. Lantern must know the exact authorized target and bounded ports before it runs.",
        next: "Choose a known device and review the target when this capability is connected.",
        metrics: [],
        evidence: [],
      },
    },
    rescue: [
      { title: "Hardware", status: "unknown", detail: "Firmware diagnostics have not been run." },
      { title: "Storage", status: "unknown", detail: "No read-only storage evidence is connected." },
      { title: "Operating system", status: "healthy", detail: "The normal application is currently running." },
      { title: "Data access", status: "blocked", detail: "Encryption and backup readiness are not assessed." },
      { title: "Network", status: "attention", detail: "Usable path with one DNS question." },
    ],
  });

  const appState = {
    view: "overview",
    menuOpen: false,
    scan: {
      phase: "complete",
      progress: 100,
      detail: "Read-only check complete",
    },
    activeDiscovery: false,
    sharePreview: false,
    fixPhase: "preview",
  };

  let scanTimer = null;
  let fixTimer = null;

  const elements = {};

  function deepFreeze(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value)) {
      return value;
    }
    Object.freeze(value);
    Object.keys(value).forEach(function (key) {
      deepFreeze(value[key]);
    });
    return value;
  }

  function makeElement(tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) {
      element.className = className;
    }
    if (text !== undefined && text !== null) {
      element.textContent = String(text);
    }
    return element;
  }

  function makeIcon(name, className) {
    const safeName = ICON_NAMES.has(name) ? name : "unknown";
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    svg.setAttribute("class", className || "icon");
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "icons.svg#" + safeName);
    svg.append(use);
    return svg;
  }

  function append(parent) {
    const children = Array.prototype.slice.call(arguments, 1);
    children.flat().forEach(function (child) {
      if (child !== null && child !== undefined) {
        parent.append(child);
      }
    });
    return parent;
  }

  function makeButton(label, className, handler, iconName) {
    const button = makeElement("button", className);
    button.type = "button";
    if (iconName) {
      button.append(makeIcon(iconName));
    }
    button.append(makeElement("span", "", label));
    button.addEventListener("click", handler);
    return button;
  }

  function statusBadge(status, label) {
    const spec = STATUS[status] || STATUS.unknown;
    const badge = makeElement("span", "status-badge status-" + (STATUS[status] ? status : "unknown"));
    append(badge, makeIcon(spec.icon), makeElement("span", "", label || spec.label));
    return badge;
  }

  function tag(text, status) {
    return makeElement("span", "tag" + (status ? " status-" + status : ""), text);
  }

  function panelHeader(title, description, action) {
    const header = makeElement("header", "panel-header");
    const copy = makeElement("div");
    append(copy, makeElement("h2", "", title));
    if (description) {
      append(copy, makeElement("p", "", description));
    }
    append(header, copy);
    if (action) {
      append(header, action);
    }
    return header;
  }

  function sectionLink(label, target) {
    return makeButton(label, "section-link", function () {
      navigate(target, true);
    }, "chevron-right");
  }

  function setPageMeta(view) {
    const meta = PAGE_META[view] || PAGE_META.overview;
    elements.pageEyebrow.textContent = meta.eyebrow;
    elements.pageTitle.textContent = meta.title;
    elements.pageDescription.textContent = meta.description;
    document.title = meta.title + " · Lantern";
  }

  function setPageActions(view) {
    elements.pageActions.replaceChildren();

    const readOnly = statusBadge("healthy", "Read-only");
    readOnly.title = "No configuration-changing action is connected";

    if (["overview", "device", "network", "route", "wifi", "dns", "lan", "mdns", "ports"].includes(view)) {
      const retry = makeButton("Run again", "secondary-button", openOnboarding, "refresh");
      append(elements.pageActions, readOnly, retry);
      return;
    }

    if (view === "session") {
      append(elements.pageActions, statusBadge("unknown", "Session inactive"));
      return;
    }

    if (view === "rescue") {
      append(elements.pageActions, statusBadge("info", "Guided assessment"));
      return;
    }

    append(elements.pageActions, readOnly);
  }

  function renderOverview() {
    const fragment = document.createDocumentFragment();

    const hero = makeElement("section", "assessment-hero");
    hero.setAttribute("aria-labelledby", "assessment-title");
    const copy = makeElement("div", "assessment-copy");
    const heroBadge = statusBadge(DEMO_FIXTURE.assessment.status);
    const title = makeElement("h2", "", DEMO_FIXTURE.assessment.title);
    title.id = "assessment-title";
    const summary = makeElement("p", "", DEMO_FIXTURE.assessment.summary);
    const actions = makeElement("div", "assessment-actions");
    append(
      actions,
      makeButton("Review suggested fix", "primary-button", function () { navigate("fixes", true); }, "wrench"),
      makeButton("View DNS evidence", "secondary-button", function () { navigate("dns", true); }, "dns")
    );
    append(copy, heroBadge, title, summary, actions);

    const facts = makeElement("div", "assessment-facts");
    [
      { icon: "shield-check", label: DEMO_FIXTURE.assessment.confidence, value: "Three layers corroborate the path" },
      { icon: "network", label: DEMO_FIXTURE.assessment.scope, value: "Not a total network outage" },
      { icon: "clock", label: DEMO_FIXTURE.meta.duration, value: DEMO_FIXTURE.meta.started },
    ].forEach(function (fact) {
      const row = makeElement("div", "fact-row");
      const body = makeElement("div");
      append(body, makeElement("strong", "", fact.label), makeElement("span", "", fact.value));
      append(row, makeIcon(fact.icon), body);
      facts.append(row);
    });
    append(hero, copy, facts);
    fragment.append(hero);

    fragment.append(renderPathPanel());

    const grid = makeElement("div", "content-grid");
    const issuePanel = makeElement("section", "panel");
    issuePanel.setAttribute("aria-labelledby", "priority-title");
    const issueHeader = panelHeader("What deserves attention", "Prioritized by likely impact and supporting evidence.");
    issueHeader.querySelector("h2").id = "priority-title";
    const issueStack = makeElement("div", "card-stack");
    DEMO_FIXTURE.issues.forEach(function (issue) {
      issueStack.append(renderIssue(issue));
    });
    append(issuePanel, issueHeader, issueStack);

    const side = makeElement("div", "content-stack");
    const workingPanel = makeElement("section", "panel");
    workingPanel.setAttribute("aria-labelledby", "working-title");
    const workingHeader = panelHeader("What is working", "Evidence that narrows the search.");
    workingHeader.querySelector("h2").id = "working-title";
    const workingList = makeElement("ul", "working-list");
    DEMO_FIXTURE.working.forEach(function (item) {
      const row = makeElement("li");
      const text = makeElement("div");
      append(text, makeElement("strong", "", item.title), makeElement("span", "", item.detail));
      append(row, makeIcon("check"), text);
      workingList.append(row);
    });
    append(workingPanel, workingHeader, workingList);

    const accessPanel = makeElement("section", "panel");
    accessPanel.setAttribute("aria-labelledby", "access-summary-title");
    const accessHeader = panelHeader(
      "Access, if needed",
      "Lantern lists prerequisites without collecting secrets.",
      sectionLink("See fixes", "fixes")
    );
    accessHeader.querySelector("h2").id = "access-summary-title";
    const access = DEMO_FIXTURE.access[0];
    const accessCard = makeElement("div", "access-card");
    const accessMark = makeElement("span", "access-mark");
    accessMark.append(makeIcon("key"));
    const accessBody = makeElement("div");
    append(
      accessBody,
      makeElement("h3", "", access.title),
      makeElement("p", "", access.reason),
      makeElement("small", "", access.status + " · " + access.where)
    );
    append(accessCard, accessMark, accessBody);
    append(accessPanel, accessHeader, accessCard);
    append(side, workingPanel, accessPanel);
    append(grid, issuePanel, side);
    fragment.append(grid);

    return fragment;
  }

  function renderPathPanel() {
    const panel = makeElement("section", "panel path-panel");
    panel.setAttribute("aria-labelledby", "lantern-path-title");
    const header = panelHeader("The Lantern Path", "Select a layer to see the observation, interpretation, and source evidence.");
    header.querySelector("h2").id = "lantern-path-title";
    const list = makeElement("ol", "lantern-path");
    DEMO_FIXTURE.path.forEach(function (pathItem) {
      const row = makeElement("li", "path-node status-" + pathItem.status);
      const button = makeElement("button", "path-node-button");
      button.type = "button";
      button.setAttribute("aria-label", pathItem.label + ": " + pathItem.detail + ". Open details.");
      button.addEventListener("click", function () { navigate(pathItem.target, true); });
      const mark = makeElement("span", "path-icon");
      mark.append(makeIcon(pathItem.icon));
      append(button, mark, makeElement("strong", "", pathItem.label), makeElement("small", "", pathItem.detail));
      row.append(button);
      list.append(row);
    });
    append(panel, header, list);
    return panel;
  }

  function renderIssue(issue) {
    const card = makeElement("article", "issue-card status-" + issue.status);
    const mark = makeElement("span", "issue-mark");
    mark.append(makeIcon(STATUS[issue.status] ? STATUS[issue.status].icon : "unknown"));
    const copy = makeElement("div");
    append(copy, tag(issue.code, issue.status), makeElement("h3", "", issue.title), makeElement("p", "", issue.detail));
    append(card, mark, copy, sectionLink("Evidence", issue.target));
    return card;
  }

  function renderDevice() {
    const fragment = document.createDocumentFragment();
    const summaryPanel = makeElement("section", "panel");
    summaryPanel.setAttribute("aria-labelledby", "device-summary-title");
    const summary = makeElement("div", "device-summary");
    const orb = makeElement("span", "device-orb");
    orb.append(makeIcon("device"));
    const copy = makeElement("div");
    const title = makeElement("h2", "", "Demo device");
    title.id = "device-summary-title";
    append(
      copy,
      title,
      makeElement("p", "", "Lantern currently confirms platform context and network behavior. Hardware, storage, and service health remain explicit capability gaps."),
      tag(DEMO_FIXTURE.meta.platform, "info")
    );
    append(summary, orb, copy);

    const capabilities = makeElement("div", "capability-list");
    [
      { title: "Platform context", detail: "Operating system and architecture", status: "healthy", label: "Available" },
      { title: "Network adapters", detail: "Route, Wi-Fi, DNS, LAN, and services", status: "healthy", label: "Available" },
      { title: "Hardware health", detail: "Firmware diagnostics and memory", status: "unknown", label: "Not supported yet" },
      { title: "Storage health", detail: "Disk visibility, SMART, and filesystem", status: "unknown", label: "Not supported yet" },
      { title: "Operating-system services", detail: "Service and driver evidence", status: "unknown", label: "Designed" },
      { title: "Automatic remediation", detail: "Preview, verify, and rollback engine", status: "blocked", label: "Not connected" },
    ].forEach(function (capability) {
      const row = makeElement("div", "capability-row");
      const body = makeElement("span");
      append(body, makeElement("strong", "", capability.title), makeElement("small", "", capability.detail));
      append(row, body, makeElement("span", "capability-badge status-" + capability.status, capability.label));
      capabilities.append(row);
    });

    append(summaryPanel, summary, capabilities);
    fragment.append(summaryPanel);

    const callout = makeElement("section", "callout status-attention");
    callout.setAttribute("aria-labelledby", "device-boundary-title");
    const calloutCopy = makeElement("div");
    const calloutTitle = makeElement("h3", "", "An honest unknown is safer than a false pass");
    calloutTitle.id = "device-boundary-title";
    append(calloutCopy, calloutTitle, makeElement("p", "", "This preview does not call unimplemented collectors healthy. Each capability becomes available only after its platform adapter and real-device evidence pass review."));
    append(callout, makeIcon("info"), calloutCopy);
    fragment.append(callout);
    return fragment;
  }

  function renderNetwork() {
    const fragment = document.createDocumentFragment();
    fragment.append(renderPathPanel());

    const header = makeElement("div", "panel-header");
    const copy = makeElement("div");
    append(copy, makeElement("h2", "", "Network modules"), makeElement("p", "", "Every layer keeps its own evidence and failure state."));
    append(header, copy, tag("Passive scope", "healthy"));
    fragment.append(header);

    const grid = makeElement("section", "module-grid");
    grid.setAttribute("aria-label", "Network diagnostic modules");
    Object.keys(DEMO_FIXTURE.modules).forEach(function (moduleId) {
      grid.append(renderModuleCard(moduleId, DEMO_FIXTURE.modules[moduleId]));
    });
    fragment.append(grid);

    const callout = makeElement("section", "callout");
    callout.setAttribute("aria-labelledby", "network-scope-title");
    const body = makeElement("div");
    const title = makeElement("h3", "", "Active discovery remains off");
    title.id = "network-scope-title";
    append(body, title, makeElement("p", "", "This demonstration uses passive local evidence. A real active scan will show the exact interface, network, and host limit before it sends traffic."));
    append(callout, makeIcon("shield"), body);
    fragment.append(callout);
    return fragment;
  }

  function renderModuleCard(moduleId, moduleData) {
    const card = makeElement("button", "module-card status-" + moduleData.status);
    card.type = "button";
    card.setAttribute("aria-label", moduleData.title + ": " + moduleData.summary + ". Open evidence.");
    card.addEventListener("click", function () { navigate(moduleId, true); });
    const top = makeElement("div", "module-card-top");
    const mark = makeElement("span", "module-mark");
    mark.append(makeIcon(moduleData.icon));
    append(top, mark, statusBadge(moduleData.status));
    const foot = makeElement("div", "module-card-foot");
    append(foot, makeIcon("clock"), makeElement("span", "", moduleData.state === "complete" ? "Checked in this run" : stateLabel(moduleData.state)));
    append(card, top, makeElement("h3", "", moduleData.title), makeElement("p", "", moduleData.summary), foot);
    return card;
  }

  function stateLabel(state) {
    const labels = {
      partial: "Partial evidence",
      error: "Could not complete",
      unsupported: "Not tested",
      complete: "Complete",
    };
    return labels[state] || "Unknown";
  }

  function renderModule(moduleId) {
    const moduleData = DEMO_FIXTURE.modules[moduleId];
    if (!moduleData) {
      return renderUnknownView();
    }
    const fragment = document.createDocumentFragment();

    const hero = makeElement("section", "module-hero status-" + moduleData.status);
    const mark = makeElement("span", "module-mark");
    mark.append(makeIcon(moduleData.icon));
    const body = makeElement("div");
    append(body, makeElement("h2", "", moduleData.summary), makeElement("p", "", "Observed " + DEMO_FIXTURE.meta.started + " · " + stateLabel(moduleData.state)));
    append(hero, mark, body, statusBadge(moduleData.status));
    fragment.append(hero);

    if (moduleData.state === "unsupported") {
      fragment.append(renderStatePanel(
        "unsupported-state",
        "unknown",
        "This check did not run",
        moduleData.next,
        "Return to network",
        function () { navigate("network", true); }
      ));
      fragment.append(renderWhyPanel(moduleData));
      return fragment;
    }

    if (moduleData.state === "error") {
      fragment.append(renderStatePanel(
        "error-state",
        "critical",
        "This module could not complete",
        "The error is isolated. Route, Wi-Fi, DNS, and LAN evidence remain available.",
        "Simulate retry",
        function () { showToast("Retry is demonstrated only; no native tool was called.", "info"); }
      ));
    }

    if (moduleData.metrics.length) {
      const metrics = makeElement("dl", "metric-grid");
      moduleData.metrics.forEach(function (metric) {
        const tile = makeElement("div", "metric-tile");
        append(tile, makeElement("dt", "", metric.label), makeElement("dd", "", metric.value));
        metrics.append(tile);
      });
      fragment.append(metrics);
    }

    const evidencePanel = makeElement("section", "panel");
    evidencePanel.setAttribute("aria-labelledby", moduleId + "-evidence-title");
    const evidenceHeader = panelHeader("Evidence", "Observed values stay separate from interpretation.", tag("Synthetic fixture", "info"));
    evidenceHeader.querySelector("h2").id = moduleId + "-evidence-title";
    const evidenceList = makeElement("dl", "evidence-list");
    moduleData.evidence.forEach(function (evidence) {
      const row = makeElement("div", "evidence-row");
      append(
        row,
        makeElement("dt", "", evidence.label),
        makeElement("dd", "", evidence.value),
        makeElement("span", "evidence-source", evidence.source)
      );
      evidenceList.append(row);
    });

    const details = makeElement("details", "technical-details");
    append(
      details,
      makeElement("summary", "", "Technical evidence · share-safe fixture"),
      makeElement("pre", "code-block", JSON.stringify({ module: moduleId, status: moduleData.status, state: moduleData.state, evidence: moduleData.evidence }, null, 2))
    );
    append(evidencePanel, evidenceHeader, evidenceList, details);
    fragment.append(evidencePanel);
    fragment.append(renderWhyPanel(moduleData));
    return fragment;
  }

  function renderWhyPanel(moduleData) {
    const panel = makeElement("section", "panel");
    panel.setAttribute("aria-labelledby", "why-this-matters-title");
    const header = panelHeader("Why this matters", moduleData.why);
    header.querySelector("h2").id = "why-this-matters-title";
    const callout = makeElement("div", "callout" + (moduleData.status === "attention" ? " status-attention" : ""));
    const body = makeElement("div");
    append(body, makeElement("h3", "", "Safest next step"), makeElement("p", "", moduleData.next));
    append(callout, makeIcon("arrow-right"), body);
    append(panel, header, callout);
    return panel;
  }

  function renderStatePanel(className, status, titleText, detail, buttonText, handler) {
    const section = makeElement("section", className);
    const body = makeElement("div", "state-content");
    const mark = makeElement("span", "state-mark status-" + status);
    mark.append(makeIcon(STATUS[status] ? STATUS[status].icon : "unknown"));
    append(body, mark, makeElement("h2", "", titleText), makeElement("p", "", detail), makeButton(buttonText, "secondary-button", handler, "refresh"));
    section.append(body);
    return section;
  }

  function renderFixes() {
    const fragment = document.createDocumentFragment();
    const callout = makeElement("section", "callout");
    callout.setAttribute("aria-labelledby", "fix-safety-title");
    const calloutBody = makeElement("div");
    const calloutTitle = makeElement("h3", "", "Suggestions never run automatically");
    calloutTitle.id = "fix-safety-title";
    append(calloutBody, calloutTitle, makeElement("p", "", "A real fix must preview the exact change, request access only when needed, verify the result, and preserve rollback evidence. This shell simulates that lifecycle without calling the computer."));
    append(callout, makeIcon("shield-check"), calloutBody);
    fragment.append(callout);

    const section = makeElement("section", "panel");
    section.setAttribute("aria-labelledby", "available-fixes-title");
    const header = panelHeader("Available plans", "One low-risk demonstration and one guided prerequisite.");
    header.querySelector("h2").id = "available-fixes-title";
    const stack = makeElement("div", "card-stack");

    const fix = makeElement("article", "fix-card");
    const fixMark = makeElement("span", "issue-mark");
    fixMark.append(makeIcon("dns"));
    const fixBody = makeElement("div");
    const meta = makeElement("div", "fix-meta");
    append(meta, tag("Low risk and reversible", "healthy"), tag("May request admin", "blocked"), tag("Under 10 seconds", "info"));
    append(
      fixBody,
      makeElement("h3", "", "Refresh the local DNS cache"),
      makeElement("p", "", "May help only if the inconsistent answer is stale. It will not change the configured resolver."),
      meta
    );
    append(fix, fixMark, fixBody, makeButton("Preview", "primary-button", openFixPreview, "chevron-right"));

    const guided = makeElement("article", "fix-card");
    const guidedMark = makeElement("span", "access-mark");
    guidedMark.append(makeIcon("key"));
    const guidedBody = makeElement("div");
    const guidedMeta = makeElement("div", "fix-meta");
    append(guidedMeta, tag("Guided only", "blocked"), tag("DNS administrator", "blocked"));
    append(
      guidedBody,
      makeElement("h3", "", "Confirm the DNS filtering policy"),
      makeElement("p", "", "The different answer may be intentional. Review the DNS service before proposing a configuration change."),
      guidedMeta
    );
    const guidedButton = makeButton("View access", "secondary-button", function () {
      showToast("Access details are listed below. Lantern never asks for the password.", "info");
    }, "key");
    append(guided, guidedMark, guidedBody, guidedButton);
    append(stack, fix, guided);
    append(section, header, stack);
    fragment.append(section);

    const accessSection = makeElement("section", "panel");
    accessSection.setAttribute("aria-labelledby", "access-needed-title");
    const accessHeader = panelHeader("Access prerequisites", "What may be needed, why, and where authorization occurs.");
    accessHeader.querySelector("h2").id = "access-needed-title";
    const accessStack = makeElement("div", "card-stack");
    DEMO_FIXTURE.access.forEach(function (access) {
      const card = makeElement("article", "access-card");
      const mark = makeElement("span", "access-mark");
      mark.append(makeIcon("key"));
      const body = makeElement("div");
      append(body, makeElement("h3", "", access.title), makeElement("p", "", access.reason), makeElement("small", "", access.where), tag(access.status, "blocked"));
      append(card, mark, body);
      accessStack.append(card);
    });
    append(accessSection, accessHeader, accessStack);
    fragment.append(accessSection);
    return fragment;
  }

  function renderShare() {
    const fragment = document.createDocumentFragment();
    const privacyCallout = makeElement("section", "callout");
    privacyCallout.setAttribute("aria-labelledby", "share-privacy-title");
    const calloutBody = makeElement("div");
    const calloutTitle = makeElement("h3", "", "Share-safe by default");
    calloutTitle.id = "share-privacy-title";
    append(calloutBody, calloutTitle, makeElement("p", "", "Hostnames, Wi-Fi names, service instances, BSSIDs, and hardware addresses are removed structurally. Local network addresses remain because they are often essential to diagnosis."));
    append(privacyCallout, makeIcon("lock"), calloutBody);
    fragment.append(privacyCallout);

    const grid = makeElement("div", "share-grid");
    const human = makeElement("section", "share-option");
    human.setAttribute("aria-labelledby", "human-report-title");
    const humanHeader = makeElement("div", "share-option-header");
    const humanMark = makeElement("span", "module-mark");
    humanMark.append(makeIcon("share"));
    const humanCopy = makeElement("div");
    const humanTitle = makeElement("h2", "", "Plain-language summary");
    humanTitle.id = "human-report-title";
    append(humanCopy, humanTitle, makeElement("p", "", "Best for a message or support call."));
    append(humanHeader, humanMark, humanCopy);
    append(
      human,
      humanHeader,
      makeElement("p", "", "Includes the top assessment, supporting evidence, what could not be tested, and prioritized next steps."),
      makeButton("Preview redacted summary", "secondary-button", toggleSharePreview, "eye")
    );

    const machine = makeElement("section", "share-option");
    machine.setAttribute("aria-labelledby", "machine-report-title");
    const machineHeader = makeElement("div", "share-option-header");
    const machineMark = makeElement("span", "module-mark");
    machineMark.append(makeIcon("download"));
    const machineCopy = makeElement("div");
    const machineTitle = makeElement("h2", "", "Structured report");
    machineTitle.id = "machine-report-title";
    append(machineCopy, machineTitle, makeElement("p", "", "Versioned JSON for tools and deeper review."));
    append(machineHeader, machineMark, machineCopy);
    const disabledDownload = makeButton("Export when connected", "secondary-button", function () {
      showToast("Export is intentionally disconnected in this interface fixture.", "info");
    }, "download");
    append(
      machine,
      machineHeader,
      makeElement("p", "", "Carries finding codes, status, evidence, source, timestamps, and capability gaps without credentials."),
      disabledDownload
    );
    append(grid, human, machine);
    fragment.append(grid);

    const preview = makeElement("section", "panel" + (appState.sharePreview ? "" : " is-hidden"));
    preview.setAttribute("aria-labelledby", "redaction-preview-title");
    const previewHeader = panelHeader("Redaction preview", "Synthetic report preview—no computer data is present.", tag("Safe to demonstrate", "healthy"));
    previewHeader.querySelector("h2").id = "redaction-preview-title";
    const privacy = makeElement("dl", "privacy-preview");
    [
      { label: "Computer name", value: "Removed" },
      { label: "Wi-Fi name", value: "Removed" },
      { label: "MAC addresses", value: "Removed" },
      { label: "Local IP addresses", value: "Retained" },
    ].forEach(function (item) {
      const row = makeElement("div");
      append(row, makeElement("dt", "", item.label), makeElement("dd", "", item.value));
      privacy.append(row);
    });
    append(
      preview,
      previewHeader,
      privacy,
      makeElement("pre", "code-block", "Overall: NEEDS ATTENTION\nInternet path: Working\nDNS: Resolver answers differ\nDevice identifiers: <redacted>\nGateway: 192.168.0.1\nNext step: Confirm expected DNS filtering policy")
    );
    fragment.append(preview);
    return fragment;
  }

  function renderSession() {
    const fragment = document.createDocumentFragment();
    const callout = makeElement("section", "callout status-attention");
    callout.setAttribute("aria-labelledby", "session-boundary-title");
    const calloutBody = makeElement("div");
    const calloutTitle = makeElement("h3", "", "Read-only network view—not remote control");
    calloutTitle.id = "session-boundary-title";
    append(calloutBody, calloutTitle, makeElement("p", "", "A paired person can view scoped network evidence. They cannot browse files, run commands, collect credentials, inspect another endpoint, or apply a fix."));
    append(callout, makeIcon("shield"), calloutBody);
    fragment.append(callout);

    const grid = makeElement("div", "session-hero");
    const setup = makeElement("section", "panel");
    setup.setAttribute("aria-labelledby", "session-setup-title");
    const setupHeader = panelHeader("Start a temporary session", "Every session begins with visible approval on this device.", statusBadge("unknown", "Inactive"));
    setupHeader.querySelector("h2").id = "session-setup-title";

    const facts = makeElement("dl", "session-facts");
    [
      { label: "Interface", value: "Would bind only the confirmed private interface" },
      { label: "Scope", value: "Redacted network report · read-only" },
      { label: "Expiry", value: "15 minutes by default" },
      { label: "Transport", value: "HTTPS and verified development fingerprint required" },
      { label: "Active probes", value: "Off until separately approved" },
    ].forEach(function (item) {
      const row = makeElement("div");
      append(row, makeElement("dt", "", item.label), makeElement("dd", "", item.value));
      facts.append(row);
    });
    const startButton = makeButton("Start when secure service is connected", "primary-button", function () {
      showToast("The LAN server is not connected to this design fixture.", "info");
    }, "session");
    startButton.setAttribute("aria-describedby", "session-demo-note");
    append(setup, setupHeader, facts, startButton, makeElement("p", "demo-notice", "No listener, certificate, pairing secret, or network route exists in this static shell."));
    setup.lastElementChild.id = "session-demo-note";

    const identity = makeElement("section", "session-identity");
    identity.setAttribute("aria-labelledby", "pairing-title");
    append(
      identity,
      makeElement("p", "eyebrow", "Pairing preview"),
      makeElement("h2", "", "One-time host code")
    );
    identity.querySelector("h2").id = "pairing-title";
    const code = makeElement("div", "session-code", "•••• ••••");
    code.setAttribute("aria-label", "Pairing code unavailable because the session is inactive");
    code.setAttribute("aria-disabled", "true");
    const identityBody = makeElement("p", "session-note", "A real code is single-use, rate-limited, short-lived, and shown only after the host confirms the interface and expiry.");
    const verify = makeElement("p", "session-note session-note-last", "Both people verify the host identity and temporary certificate fingerprint before viewing a report.");
    append(identity, code, identityBody, verify);
    append(grid, setup, identity);
    fragment.append(grid);

    const lifecycle = makeElement("section", "panel");
    lifecycle.setAttribute("aria-labelledby", "session-lifecycle-title");
    const lifecycleHeader = panelHeader("Session lifecycle", "Nothing persists after expiry or host shutdown.");
    lifecycleHeader.querySelector("h2").id = "session-lifecycle-title";
    const steps = makeElement("ol", "timeline-list");
    [
      { title: "Confirm scope", detail: "Host reviews interface, network, passive/active policy, and duration." },
      { title: "Pair visibly", detail: "Single-use code and host identity establish the intended session." },
      { title: "Review together", detail: "Connected clients and time remaining stay visible on both screens." },
      { title: "Revoke or expire", detail: "The host can stop immediately; absolute expiry clears tokens and keys." },
    ].forEach(function (step, index) {
      const row = makeElement("li", "rescue-step");
      const body = makeElement("div");
      append(body, makeElement("h3", "", step.title), makeElement("p", "", step.detail));
      append(row, makeElement("span", "step-number", index + 1), body, makeIcon("chevron-right"));
      steps.append(row);
    });
    append(lifecycle, lifecycleHeader, steps);
    fragment.append(lifecycle);
    return fragment;
  }

  function renderRescue() {
    const fragment = document.createDocumentFragment();
    const stopCallout = makeElement("section", "callout status-critical");
    stopCallout.setAttribute("aria-labelledby", "rescue-stop-title");
    const body = makeElement("div");
    const title = makeElement("h3", "", "Protect important data before attempting repair");
    title.id = "rescue-stop-title";
    append(body, title, makeElement("p", "", "Storage health, encryption state, and backup readiness are unknown in this fixture. Lantern starts with read-only evidence and treats disk repair, write mounts, boot changes, resets, and encryption operations as guided-only actions."));
    append(stopCallout, makeIcon("alert"), body);
    fragment.append(stopCallout);

    const section = makeElement("section", "panel");
    section.setAttribute("aria-labelledby", "viability-title");
    const header = panelHeader("Five-part viability view", "A running computer does not prove that its storage, data, or recovery path is healthy.", tag("Synthetic fixture", "info"));
    header.querySelector("h2").id = "viability-title";
    const grid = makeElement("div", "viability-grid");
    DEMO_FIXTURE.rescue.forEach(function (axis) {
      const card = makeElement("article", "viability-card");
      append(card, statusBadge(axis.status), makeElement("h3", "", axis.title), makeElement("p", "", axis.detail));
      grid.append(card);
    });
    append(section, header, grid);
    fragment.append(section);

    const guides = makeElement("section", "panel");
    guides.setAttribute("aria-labelledby", "guided-checks-title");
    const guideHeader = panelHeader("Safest sequence", "Platform-specific steps replace a misleading universal boot workflow.");
    guideHeader.querySelector("h2").id = "guided-checks-title";
    const list = makeElement("ol", "timeline-list");
    [
      { title: "Choose the real platform and startup state", detail: "Apple silicon, Intel Mac, Windows Recovery, and Linux live environments follow different paths.", status: "info" },
      { title: "Record encryption and data priority", detail: "List FileVault or BitLocker access as a prerequisite without entering a key into Lantern.", status: "blocked" },
      { title: "Collect read-only evidence", detail: "Check hardware diagnostics, disk visibility, filesystem readability, OS boot stage, and network independently.", status: "unknown" },
      { title: "Choose the least destructive next step", detail: "Preserve or copy data before repair whenever storage health is uncertain.", status: "attention" },
    ].forEach(function (step, index) {
      const row = makeElement("li", "rescue-step");
      const stepBody = makeElement("div");
      append(stepBody, makeElement("h3", "", step.title), makeElement("p", "", step.detail));
      append(row, makeElement("span", "step-number", index + 1), stepBody, statusBadge(step.status));
      list.append(row);
    });
    append(guides, guideHeader, list);
    fragment.append(guides);
    return fragment;
  }

  function renderUnknownView() {
    return renderStatePanel(
      "empty-state",
      "unknown",
      "That view is not available",
      "Return to the overview and choose a supported module.",
      "Return to overview",
      function () { navigate("overview", true); }
    );
  }

  const VIEW_RENDERERS = {
    overview: renderOverview,
    device: renderDevice,
    network: renderNetwork,
    route: function () { return renderModule("route"); },
    wifi: function () { return renderModule("wifi"); },
    dns: function () { return renderModule("dns"); },
    lan: function () { return renderModule("lan"); },
    mdns: function () { return renderModule("mdns"); },
    ports: function () { return renderModule("ports"); },
    fixes: renderFixes,
    share: renderShare,
    session: renderSession,
    rescue: renderRescue,
  };

  function render() {
    setPageMeta(appState.view);
    setPageActions(appState.view);
    updateNavigation();
    updateScanProgress();

    const renderer = VIEW_RENDERERS[appState.view] || renderUnknownView;
    elements.pageContent.replaceChildren(renderer());
  }

  function navigate(view, moveFocus) {
    if (!Object.prototype.hasOwnProperty.call(VIEW_RENDERERS, view)) {
      return;
    }
    appState.view = view;
    closeMenu();
    render();
    elements.routeAnnouncer.textContent = PAGE_META[view].title + " view loaded";
    if (moveFocus) {
      elements.mainContent.focus({ preventScroll: true });
      window.scrollTo({ top: 0, behavior: "auto" });
    }
  }

  function updateNavigation() {
    document.querySelectorAll("[data-view-target]").forEach(function (button) {
      const isCurrent = button.getAttribute("data-view-target") === appState.view;
      button.classList.toggle("is-current", isCurrent);
      if (isCurrent) {
        button.setAttribute("aria-current", "page");
      } else {
        button.removeAttribute("aria-current");
      }
    });
  }

  function updateScanProgress() {
    const running = appState.scan.phase === "running";
    elements.scanProgress.classList.toggle("is-hidden", !running);
    elements.scanProgressDetail.textContent = appState.scan.detail;
    elements.scanProgressValue.textContent = appState.scan.progress + "%";
    elements.scanProgressBar.className = "progress-value-" + String(appState.scan.progress);
    const track = elements.scanProgress.querySelector("[role='progressbar']");
    track.setAttribute("aria-valuenow", String(appState.scan.progress));
  }

  function openOnboarding() {
    if (elements.onboardingDialog.open) {
      return;
    }
    elements.onboardingDialog.showModal();
  }

  function startDemoScan(goal, activeDiscovery) {
    if (scanTimer !== null) {
      window.clearInterval(scanTimer);
    }
    appState.activeDiscovery = activeDiscovery;
    appState.scan.phase = "running";
    appState.scan.progress = 4;
    appState.scan.detail = "Confirming platform and interfaces…";
    if (goal === "rescue") {
      appState.view = "rescue";
    } else if (goal === "network") {
      appState.view = "network";
    } else {
      appState.view = "overview";
    }
    render();

    const steps = [
      { progress: 18, detail: "Reading the default route…" },
      { progress: 34, detail: "Checking the local link…" },
      { progress: 52, detail: "Testing the outbound path…" },
      { progress: 70, detail: "Comparing DNS answers…" },
      { progress: 86, detail: activeDiscovery ? "Demonstrating approved LAN scope…" : "Reading passive LAN evidence…" },
      { progress: 100, detail: "Prioritizing evidence…" },
    ];
    let index = 0;
    scanTimer = window.setInterval(function () {
      const step = steps[index];
      appState.scan.progress = step.progress;
      appState.scan.detail = step.detail;
      updateScanProgress();
      index += 1;
      if (index >= steps.length) {
        window.clearInterval(scanTimer);
        scanTimer = null;
        window.setTimeout(function () {
          appState.scan.phase = "complete";
          render();
          showToast("Read-only demonstration complete. No system or network probe ran.", "healthy");
          elements.pageTitle.focus({ preventScroll: true });
        }, 320);
      }
    }, 430);
  }

  function toggleSharePreview() {
    appState.sharePreview = !appState.sharePreview;
    render();
    if (appState.sharePreview) {
      window.setTimeout(function () {
        const preview = document.getElementById("redaction-preview-title");
        if (preview) {
          preview.setAttribute("tabindex", "-1");
          preview.focus();
        }
      }, 0);
    }
  }

  function openFixPreview() {
    resetFixPreview();
    elements.fixDialog.showModal();
  }

  function resetFixPreview() {
    if (fixTimer !== null) {
      window.clearInterval(fixTimer);
      fixTimer = null;
    }
    appState.fixPhase = "preview";
    elements.fixPreviewBody.classList.remove("is-hidden");
    elements.fixResult.classList.add("is-hidden");
    elements.fixResultTitle.textContent = "Simulation verified";
    elements.fixResultDescription.textContent = "The demonstration completed without touching this computer. A real action will show before-and-after evidence here.";
    elements.simulateFixButton.disabled = false;
    elements.simulateFixButton.textContent = "Simulate fix lifecycle";
    document.querySelectorAll("[data-fix-step]").forEach(function (step) {
      step.classList.remove("is-active", "is-complete", "is-available");
      if (step.getAttribute("data-fix-step") === "preview") {
        step.classList.add("is-active");
      }
    });
  }

  function simulateFixLifecycle() {
    if (fixTimer !== null) {
      return;
    }
    if (appState.fixPhase === "verified") {
      simulateRollback();
      return;
    }

    const phases = ["apply", "verify"];
    let index = 0;
    elements.simulateFixButton.disabled = true;
    elements.simulateFixButton.textContent = "Simulating…";

    fixTimer = window.setInterval(function () {
      const phase = phases[index];
      appState.fixPhase = phase;
      document.querySelectorAll("[data-fix-step]").forEach(function (step) {
        const stepName = step.getAttribute("data-fix-step");
        const order = ["preview", "apply", "verify", "rollback"];
        const stepIndex = order.indexOf(stepName);
        const phaseIndex = order.indexOf(phase);
        step.classList.toggle("is-complete", stepIndex < phaseIndex);
        step.classList.toggle("is-active", stepIndex === phaseIndex);
        step.classList.remove("is-available");
      });
      index += 1;
      if (index >= phases.length) {
        window.clearInterval(fixTimer);
        fixTimer = window.setTimeout(function () {
          fixTimer = null;
          elements.fixPreviewBody.classList.add("is-hidden");
          elements.fixResult.classList.remove("is-hidden");
          appState.fixPhase = "verified";
          document.querySelectorAll("[data-fix-step]").forEach(function (step) {
            const stepName = step.getAttribute("data-fix-step");
            step.classList.remove("is-active");
            step.classList.toggle("is-complete", stepName !== "rollback");
            step.classList.toggle("is-available", stepName === "rollback");
          });
          elements.simulateFixButton.disabled = false;
          elements.simulateFixButton.textContent = "Simulate rollback";
          elements.fixResult.setAttribute("tabindex", "-1");
          elements.fixResult.focus();
        }, 380);
      }
    }, 620);
  }

  function simulateRollback() {
    appState.fixPhase = "rollback";
    elements.simulateFixButton.disabled = true;
    elements.simulateFixButton.textContent = "Rolling back simulation…";
    document.querySelectorAll("[data-fix-step]").forEach(function (step) {
      const stepName = step.getAttribute("data-fix-step");
      step.classList.remove("is-available");
      step.classList.toggle("is-complete", stepName !== "rollback");
      step.classList.toggle("is-active", stepName === "rollback");
    });
    fixTimer = window.setTimeout(function () {
      fixTimer = null;
      document.querySelectorAll("[data-fix-step]").forEach(function (step) {
        step.classList.remove("is-active", "is-available");
        step.classList.add("is-complete");
      });
      elements.fixResultTitle.textContent = "Simulation rolled back";
      elements.fixResultDescription.textContent = "The preview returned to its original synthetic state. No computer setting was touched.";
      elements.simulateFixButton.textContent = "Rollback simulated";
      elements.fixResult.focus();
    }, 700);
  }

  function showToast(message, status) {
    const toast = makeElement("div", "toast");
    toast.setAttribute("role", "status");
    append(toast, makeIcon(STATUS[status] ? STATUS[status].icon : "info"), makeElement("span", "", message));
    elements.toastRegion.replaceChildren(toast);
    window.setTimeout(function () {
      if (toast.isConnected) {
        toast.remove();
      }
    }, 4800);
  }

  function openMenu() {
    appState.menuOpen = true;
    elements.sidebar.classList.add("is-open");
    elements.menuToggle.setAttribute("aria-expanded", "true");
    elements.menuToggle.setAttribute("aria-label", "Close navigation");
    const first = elements.sidebar.querySelector("button[data-view-target]");
    if (first) {
      first.focus();
    }
  }

  function closeMenu() {
    appState.menuOpen = false;
    elements.sidebar.classList.remove("is-open");
    elements.menuToggle.setAttribute("aria-expanded", "false");
    elements.menuToggle.setAttribute("aria-label", "Open navigation");
  }

  function cacheElements() {
    elements.pageContent = document.getElementById("page-content");
    elements.pageEyebrow = document.getElementById("page-eyebrow");
    elements.pageTitle = document.getElementById("page-title");
    elements.pageDescription = document.getElementById("page-description");
    elements.pageActions = document.getElementById("page-actions");
    elements.mainContent = document.getElementById("main-content");
    elements.routeAnnouncer = document.getElementById("route-announcer");
    elements.scanProgress = document.getElementById("scan-progress");
    elements.scanProgressDetail = document.getElementById("scan-progress-detail");
    elements.scanProgressValue = document.getElementById("scan-progress-value");
    elements.scanProgressBar = document.getElementById("scan-progress-bar");
    elements.onboardingDialog = document.getElementById("onboarding-dialog");
    elements.onboardingForm = document.getElementById("onboarding-form");
    elements.fixDialog = document.getElementById("fix-dialog");
    elements.fixPreviewBody = document.getElementById("fix-preview-body");
    elements.fixResult = document.getElementById("fix-result");
    elements.fixResultTitle = document.getElementById("fix-result-title");
    elements.fixResultDescription = document.getElementById("fix-result-description");
    elements.simulateFixButton = document.getElementById("simulate-fix-button");
    elements.toastRegion = document.getElementById("toast-region");
    elements.menuToggle = document.getElementById("menu-toggle");
    elements.sidebar = document.getElementById("primary-sidebar");
    elements.sidebarScrim = document.getElementById("sidebar-scrim");
  }

  function bindEvents() {
    document.querySelectorAll("[data-view-target]").forEach(function (button) {
      button.addEventListener("click", function () {
        navigate(button.getAttribute("data-view-target"), true);
      });
    });

    document.getElementById("new-check-button").addEventListener("click", openOnboarding);
    elements.menuToggle.addEventListener("click", function () {
      if (appState.menuOpen) {
        closeMenu();
      } else {
        openMenu();
      }
    });
    elements.sidebarScrim.addEventListener("click", function () {
      closeMenu();
      elements.menuToggle.focus();
    });

    elements.onboardingForm.addEventListener("submit", function (event) {
      event.preventDefault();
      const selectedGoal = elements.onboardingForm.querySelector("input[name='goal']:checked");
      const activeDiscovery = document.getElementById("active-discovery").checked;
      elements.onboardingDialog.close();
      startDemoScan(selectedGoal ? selectedGoal.value : "problem", activeDiscovery);
    });

    elements.simulateFixButton.addEventListener("click", simulateFixLifecycle);
    elements.fixDialog.addEventListener("close", resetFixPreview);

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && appState.menuOpen) {
        closeMenu();
        elements.menuToggle.focus();
      }
    });
  }

  function init() {
    cacheElements();
    bindEvents();
    render();
    if (DEMO_MODE) {
      window.setTimeout(openOnboarding, 180);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
}());
