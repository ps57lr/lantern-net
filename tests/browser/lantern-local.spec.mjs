import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import path from "node:path";

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const REPOSITORY_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FIXTURE_SCRIPT = path.join(REPOSITORY_ROOT, "tests", "browser", "fixture_server.py");
const LOCAL_PYTHON = path.join(REPOSITORY_ROOT, ".venv", "bin", "python");
const FIXTURE_PREFIX = "LANTERN_FIXTURE_URL=";
const FIXTURE_SCENARIOS = new Set(["attention", "positive", "failed", "cancel"]);
const FIXTURE_BOOTSTRAP = [
  "import runpy, sys",
  "repository_root, script, *arguments = sys.argv[1:]",
  "sys.path.insert(0, repository_root)",
  "sys.argv = [script, *arguments]",
  "runpy.run_path(script, run_name='__main__')",
].join("; ");

function fixturePython() {
  if (process.env.LANTERN_PYTHON) {
    return process.env.LANTERN_PYTHON;
  }
  return existsSync(LOCAL_PYTHON) ? LOCAL_PYTHON : "python3";
}

function fixtureArguments(scenario) {
  const installedMode = process.env.LANTERN_INSTALLED_PACKAGE;
  if (installedMode !== undefined && installedMode !== "1") {
    throw new Error("LANTERN_INSTALLED_PACKAGE must be unset or exactly 1.");
  }
  if (installedMode === "1") {
    // The test script remains synthetic source, while every `netdiag` import,
    // HTTP asset, and presentation boundary comes from the isolated wheel.
    return ["-I", FIXTURE_SCRIPT, "--scenario", scenario];
  }
  return [
    "-I",
    "-c",
    FIXTURE_BOOTSTRAP,
    REPOSITORY_ROOT,
    FIXTURE_SCRIPT,
    "--scenario",
    scenario,
  ];
}

function boundedAppend(current, chunk) {
  return (current + String(chunk)).slice(-8192);
}

async function startFixture(scenario = "attention") {
  if (!FIXTURE_SCENARIOS.has(scenario)) {
    throw new Error("Synthetic Lantern fixture scenario is not allowlisted.");
  }
  const child = spawn(
    fixturePython(),
    fixtureArguments(scenario),
    {
    cwd: REPOSITORY_ROOT,
    env: {
      PATH: process.env.PATH || "",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PYTHONUNBUFFERED: "1",
    },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    },
  );

  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr = boundedAppend(stderr, chunk);
  });

  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  try {
    const launchUrl = await new Promise((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        finish(new Error(`Synthetic Lantern fixture did not start. ${stderr}`));
      }, 10_000);

      function finish(error, value) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        lines.removeAllListeners();
        lines.close();
        child.removeListener("error", onError);
        child.removeListener("exit", onExit);
        if (error) {
          reject(error);
        } else {
          resolve(value);
        }
      }

      function onError(error) {
        finish(error);
      }

      function onExit(code, signal) {
        finish(new Error(`Synthetic Lantern fixture exited early (${code ?? signal}). ${stderr}`));
      }

      child.once("error", onError);
      child.once("exit", onExit);
      lines.on("line", (line) => {
        if (line.startsWith(FIXTURE_PREFIX)) {
          finish(null, line.slice(FIXTURE_PREFIX.length));
        }
      });
    });

    const parsed = new URL(launchUrl);
    const safeOrigin = /^http:\/\/lantern-[a-f0-9]{32}\.localhost:\d+$/.test(parsed.origin);
    const safeLaunch =
      safeOrigin &&
      parsed.pathname === "/app/" &&
      parsed.search === "" &&
      /^#launch=[A-Za-z0-9_-]{32,256}$/.test(parsed.hash);
    if (!safeLaunch) {
      throw new Error("Synthetic Lantern fixture returned an unsafe launch URL.");
    }
    return { child, launchUrl, origin: parsed.origin, stderr: () => stderr };
  } catch (error) {
    await terminateAndReap(child);
    throw error;
  }
}

async function observeExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { exited: true, code: child.exitCode };
  }
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      finish(null, { exited: false, code: null });
    }, timeoutMs);

    function finish(error, value) {
      clearTimeout(timeout);
      child.removeListener("exit", onExit);
      child.removeListener("error", onError);
      if (error) {
        reject(error);
      } else {
        resolve(value);
      }
    }

    function onExit(code) {
      finish(null, { exited: true, code });
    }

    function onError(error) {
      finish(error);
    }

    child.once("exit", onExit);
    child.once("error", onError);
  });
}

async function terminateAndReap(child) {
  // Node emits `error` without `spawn`/`exit` when the executable never
  // existed. There is no operating-system child to signal or reap.
  if (child.pid === undefined) {
    return null;
  }
  if (child.exitCode !== null || child.signalCode !== null) {
    return child.exitCode;
  }
  child.kill("SIGTERM");
  let result = await observeExit(child, 3_000);
  if (!result.exited) {
    child.kill("SIGKILL");
    result = await observeExit(child, 3_000);
  }
  if (!result.exited) {
    throw new Error("Synthetic Lantern fixture could not be reaped.");
  }
  return result.code;
}

async function waitForCleanExit(child, timeoutMs = 5_000) {
  const result = await observeExit(child, timeoutMs);
  if (result.exited) {
    return result.code;
  }
  await terminateAndReap(child);
  throw new Error("Synthetic Lantern fixture did not exit after session revocation.");
}

async function stopFixture(fixture) {
  if (fixture) {
    await terminateAndReap(fixture.child);
  }
}

async function expectNoAxeViolations(page) {
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
}

async function monitorLocalScenario(page, fixture) {
  const observations = {
    consoleProblems: [],
    pageErrors: [],
    offOriginRequests: [],
    allRequests: [],
    startRequests: [],
    cancelRequests: [],
    revokeRequests: [],
  };
  page.on("console", (message) => {
    if (message.type() === "warning" || message.type() === "error") {
      observations.consoleProblems.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => observations.pageErrors.push(error.message));
  await page.context().route("**/*", async (route) => {
    let requestOrigin = "";
    try {
      requestOrigin = new URL(route.request().url()).origin;
    } catch (_error) {
      observations.offOriginRequests.push(route.request().url());
      await route.abort("blockedbyclient");
      return;
    }
    if (requestOrigin !== fixture.origin) {
      observations.offOriginRequests.push(route.request().url());
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
  page.on("request", (request) => {
    observations.allRequests.push(request.url());
    const requestPath = new URL(request.url()).pathname;
    if (requestPath === "/api/diagnostics/start") {
      observations.startRequests.push(request);
    } else if (requestPath === "/api/diagnostics/cancel") {
      observations.cancelRequests.push(request);
    } else if (requestPath === "/api/session/revoke") {
      observations.revokeRequests.push(request);
    }
  });
  return observations;
}

async function expectExactMutation(request, fixture, expectedPath, expectedBody) {
  expect(new URL(request.url()).pathname).toBe(expectedPath);
  expect(request.method()).toBe("POST");
  expect(request.postDataJSON()).toEqual(expectedBody);
  expect(request.headers()["origin"]).toBe(fixture.origin);
  expect(request.headers()["x-lantern-csrf"]).toMatch(/^[A-Za-z0-9_-]{20,}$/);
}

test("fixture startup failure is bounded and preserves the spawn error", async ({}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium");
  const original = process.env.LANTERN_PYTHON;
  process.env.LANTERN_PYTHON = path.join(REPOSITORY_ROOT, "does-not-exist-python");
  try {
    await expect(startFixture()).rejects.toThrow(/ENOENT|spawn/i);
  } finally {
    if (original === undefined) {
      delete process.env.LANTERN_PYTHON;
    } else {
      process.env.LANTERN_PYTHON = original;
    }
  }
});

test("synthetic passive first-run diagnosis stays local, honest, and accessible", async ({ page }, testInfo) => {
  const fixture = await startFixture();
  const consoleProblems = [];
  const pageErrors = [];
  const offOriginRequests = [];
  const startRequests = [];
  const revokeRequests = [];

  page.on("console", (message) => {
    if (message.type() === "warning" || message.type() === "error") {
      consoleProblems.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.context().route("**/*", async (route) => {
    let requestOrigin = "";
    try {
      requestOrigin = new URL(route.request().url()).origin;
    } catch (_error) {
      offOriginRequests.push(route.request().url());
      await route.abort("blockedbyclient");
      return;
    }
    if (requestOrigin !== fixture.origin) {
      offOriginRequests.push(route.request().url());
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
  page.on("request", (request) => {
    const requestUrl = new URL(request.url());
    if (requestUrl.pathname === "/api/diagnostics/start") {
      startRequests.push(request);
    }
    if (requestUrl.pathname === "/api/session/revoke") {
      revokeRequests.push(request);
    }
  });

  try {
    await page.goto(fixture.launchUrl, { waitUntil: "domcontentloaded" });
    await expect(page.locator("#connection-state")).toHaveText("Private local session");
    await expect(page).toHaveURL((url) => url.hash === "" && url.origin === fixture.origin);
    await expect(
      page.getByRole("heading", { name: "Lantern has not run a diagnostic check yet." }),
    ).toBeVisible();
    await expect(page.locator("#basic-network-checks")).not.toBeChecked();
    await expect(page.locator("#include-mdns")).toBeDisabled();
    await expect(page.locator("#run-announcement")).toHaveText(
      "Lantern is ready for a consent-based check.",
    );
    await expectNoAxeViolations(page);

    // A reload proves the one-use launch fragment was scrubbed while the
    // host-only HttpOnly session remains usable on the unique local origin.
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("#connection-state")).toHaveText("Private local session");
    await expect(page).toHaveURL((url) => url.hash === "" && url.origin === fixture.origin);

    await page.getByRole("radio", { name: /Evaluate this network/ }).check();
    await expect(page.getByText(/network you own, manage, or are explicitly authorized to assess/i)).toBeVisible();
    await page.getByRole("button", { name: "Start check" }).click();

    await expect(page.getByRole("heading", { name: "Observed Wi-Fi signal was weak" })).toBeVisible();
    await expect(page.getByText("1 of 3 maximum")).toBeVisible();
    await expect(
      page.getByText("Lantern found a reported problem in the selected network evaluation checks."),
    ).toBeVisible();
    await expect(page.getByText("Low confidence", { exact: true })).toBeVisible();
    await expect(page.getByText("Partial planned coverage", { exact: true })).toBeVisible();
    await expect(page.locator(".assessment-boundary")).toContainText(
      "one endpoint, not a whole-network assessment",
    );
    await expect(page.getByRole("list", { name: "Lantern Path diagnostic-layer map" }).getByRole("listitem")).toHaveCount(5);
    await expect(page.getByRole("heading", { name: "Device route" })).toBeVisible();
    await expect(page.locator(".module-card")).toHaveCount(6);
    await expectNoAxeViolations(page);
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth))
      .toBe(true);

    expect(startRequests).toHaveLength(1);
    expect(startRequests[0].postDataJSON()).toEqual({
      goal: "network",
      profile: "passive",
      include_mdns: false,
    });

    await page.getByRole("button", { name: /^Wi-Fi:/ }).click();
    await expect(page.locator("#page-title")).toHaveText("Wi-Fi");
    await expect(page.getByText("Safe finding summary", { exact: true })).toBeVisible();
    await page.getByText("Technical context", { exact: true }).click();
    await expect(page.getByText("Safe, identifier-free detail", { exact: true })).toBeVisible();

    await expectNoAxeViolations(page);

    if (testInfo.project.name === "mobile-chromium") {
      const menu = page.locator("#menu-toggle");
      const drawer = page.locator("#primary-sidebar");
      await expect(drawer).toHaveAttribute("aria-hidden", "true");
      await menu.click();
      await expect(menu).toHaveAttribute("aria-expanded", "true");
      await expect(drawer).not.toHaveAttribute("aria-hidden", "true");
      await expect(page.locator("#primary-sidebar .nav-item").first()).toBeFocused();
      await expectNoAxeViolations(page);

      await page.locator("#mobile-end-session-button").focus();
      await page.keyboard.press("Escape");
      await expect(menu).toBeFocused();
      await expect(drawer).toHaveAttribute("aria-hidden", "true");

      await menu.click();
      await page.locator("#mobile-end-session-button").click();
    } else {
      await page.locator("#end-session-button").click();
    }

    await expect(page.locator("#connection-state")).toHaveText("Local session closed");
    await expect(page.locator("#session-message")).toHaveText(
      "The private local session ended. Launch Lantern again to reconnect.",
    );
    await expect(page.locator("#run-announcement")).toBeEmpty();
    await expect(page.locator("#new-check-button")).toBeDisabled();
    await expect(page.locator("#end-session-button")).toBeDisabled();
    expect(revokeRequests).toHaveLength(1);
    expect(revokeRequests[0].method()).toBe("POST");
    expect(revokeRequests[0].headers()["origin"]).toBe(fixture.origin);
    expect(revokeRequests[0].headers()["x-lantern-csrf"]).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(await waitForCleanExit(fixture.child)).toBe(0);

    expect(offOriginRequests).toEqual([]);
    expect(consoleProblems).toEqual([]);
    expect(pageErrors).toEqual([]);
  } finally {
    await stopFixture(fixture);
  }
});

const DESKTOP_SCENARIOS = [
  {
    id: "attention",
    name: "attention",
    state: "completed",
    tone: "attention",
    coverage: "partial",
    confidence: "low",
    sentence: "Lantern found a reported problem in the selected checks.",
  },
  {
    id: "positive",
    name: "positive presentation-only fixture (unreachable live)",
    state: "completed",
    tone: "positive",
    coverage: "complete",
    confidence: "high",
    sentence: "Synthetic presentation-only data reported no issue across every diagnostic layer.",
  },
  {
    id: "failed",
    name: "deterministic honest failure",
    state: "failed",
    tone: "attention",
    coverage: "none",
    confidence: "none",
    sentence: "Lantern could not complete the diagnostic check, so no health conclusion is available.",
  },
  {
    id: "cancel",
    name: "explicit cancellation",
    state: "cancelled",
    tone: "attention",
    coverage: "none",
    confidence: "none",
    sentence: "The diagnostic check stopped; completed results remain valid, but no complete conclusion is available.",
  },
];

for (const scenario of DESKTOP_SCENARIOS) {
  test(`desktop scenario: ${scenario.name}`, async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== "desktop-chromium");
    const fixture = await startFixture(scenario.id);
    const observed = await monitorLocalScenario(page, fixture);

    try {
      await page.goto(fixture.launchUrl, { waitUntil: "domcontentloaded" });
      await expect(page.locator("#connection-state")).toHaveText("Private local session");
      await expect(page).toHaveURL((url) => url.hash === "" && url.origin === fixture.origin);
      await expect(
        page.getByRole("heading", { name: "Lantern has not run a diagnostic check yet." }),
      ).toBeVisible();
      await expect(page.locator("#basic-network-checks")).not.toBeChecked();
      await expect(page.locator("#include-mdns")).toBeDisabled();

      await page.getByRole("button", { name: "Start check" }).click();
      if (scenario.id === "cancel") {
        await expect(page.locator("#connection-state")).toHaveText("Checking locally");
        await expect(page.locator("#run-announcement")).toHaveText(
          "The diagnostic check started.",
        );
        await expect(page.locator("#cancel-button")).toBeVisible();
        await page.locator("#cancel-button").click();
      }

      await expect(page.getByRole("heading", { name: scenario.sentence })).toBeVisible();
      await expect(page.locator(".assessment-panel")).toHaveClass(
        new RegExp(`(?:^|\\s)tone-${scenario.tone}(?:\\s|$)`),
      );
      const expectedConfidence = {
        high: "High confidence",
        low: "Low confidence",
        none: "Confidence unavailable",
      }[scenario.confidence];
      const expectedCoverage = {
        complete: "Complete planned coverage",
        partial: "Partial planned coverage",
        none: "No diagnostic coverage",
      }[scenario.coverage];
      await expect(page.getByText(expectedConfidence, { exact: true })).toBeVisible();
      await expect(page.getByText(expectedCoverage, { exact: true })).toBeVisible();

      if (scenario.id === "positive") {
        await expect(
          page.getByRole("heading", {
            name: "Synthetic presentation-only data reported no issue across every diagnostic layer.",
          }),
        ).toBeVisible();
        await expect(page.locator(".issue-card")).toHaveCount(0);
        await expect(
          page.getByRole("heading", {
            name: "No priority issue was returned from the completed plan",
          }),
        ).toBeVisible();
      } else if (scenario.id === "attention") {
        await expect(
          page.getByRole("heading", { name: "Observed Wi-Fi signal was weak" }),
        ).toBeVisible();
      } else if (scenario.id === "failed") {
        await expect(
          page.getByRole("heading", { name: "No priority issue is available from this run" }),
        ).toBeVisible();
      } else {
        await expect(page.locator("#run-announcement")).toHaveText(
          "The diagnostic check was cancelled.",
        );
        await expect(page.getByRole("button", { name: /Connection path: Cancelled/ }))
          .toBeVisible();
      }

      const status = await page.evaluate(async () => {
        const response = await window.fetch("/api/status", {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
        });
        return await response.json();
      });
      expect(status.schema).toBe("lantern.ui.v2");
      expect(status.state).toBe(scenario.state);
      expect(status.assessment).toMatchObject({
        tone: scenario.tone,
        coverage: scenario.coverage,
        confidence: scenario.confidence,
      });
      expect(status.issues.length).toBeLessThanOrEqual(3);
      expect(status.capabilities).toMatchObject({
        active_discovery: false,
        remediation: false,
        credentials: false,
        lan_remote: false,
        rescue_boot: false,
        share_export: true,
      });
      if (scenario.id === "cancel") {
        expect(status.run.cancel_requested).toBe(true);
        expect(status.assessment.tone).not.toBe("positive");
        expect(status.assessment.coverage).not.toBe("complete");
      }

      const visibleText = await page.locator("body").innerText();
      expect(visibleText).not.toContain("NDG.");
      expect(visibleText).not.toContain("synthetic source prose withheld");
      expect(visibleText).not.toMatch(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      expect(visibleText).not.toMatch(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i);
      await expect(page.locator(".issue-card")).toHaveCount(status.issues.length);
      await expectNoAxeViolations(page);

      expect(observed.startRequests).toHaveLength(1);
      await expectExactMutation(
        observed.startRequests[0],
        fixture,
        "/api/diagnostics/start",
        { goal: "problem", profile: "passive", include_mdns: false },
      );
      if (scenario.id === "cancel") {
        expect(observed.cancelRequests).toHaveLength(1);
        await expectExactMutation(
          observed.cancelRequests[0],
          fixture,
          "/api/diagnostics/cancel",
          {},
        );
      } else {
        expect(observed.cancelRequests).toHaveLength(0);
      }

      await page.locator("#end-session-button").click();
      await expect(page.locator("#connection-state")).toHaveText("Local session closed");
      await expect(page.locator("#run-announcement")).toBeEmpty();
      await expect(page.getByRole("heading", { name: "Local session closed" })).toBeVisible();
      const requestsAtClear = observed.allRequests.length;
      expect(observed.revokeRequests).toHaveLength(1);
      await expectExactMutation(
        observed.revokeRequests[0],
        fixture,
        "/api/session/revoke",
        {},
      );
      expect(await waitForCleanExit(fixture.child)).toBe(0);
      await page.waitForTimeout(150);
      expect(observed.allRequests).toHaveLength(requestsAtClear);

      expect(observed.offOriginRequests).toEqual([]);
      expect(observed.consoleProblems).toEqual([]);
      expect(observed.pageErrors).toEqual([]);
    } finally {
      await stopFixture(fixture);
    }
  });
}
