# Lantern experience and delivery architecture

Status: implemented local development foundation plus explicitly future designs

Current local checkpoint: `netdiag` `0.3.0.dev5`; original baseline: v0.2.1 (`0871248`)

Applies to: local UI, portable builds, LAN responder, and rescue workflows

## Decision summary

Lantern should remain one diagnostic core with multiple deliberately separate
surfaces:

1. **Lantern Local** is a visible, user-launched application. It serves a static
   interface on literal `127.0.0.1` with an operating-system-selected port and a
   unique per-launch `*.localhost` hostname, then opens the system browser. It runs
   passive and low-impact diagnostics after consent, shows progress and evidence,
   and later brokers tightly allowlisted remediations.
2. **Lantern Portable** packages that same application and the Python runtime as
   per-platform, one-folder artifacts. A USB has one obvious launcher for each
   supported platform, but never uses removable-media autorun.
3. **Lantern LAN** is a separate, temporary, read-only server profile. It binds one
   selected private interface, advertises only while running, uses authenticated
   short-lived sessions, and exposes a narrow report API. It is not a remote shell
   and cannot inspect another endpoint unless Lantern is running there.
4. **Lantern Rescue** is initially a guided viability workflow plus portable,
   read-only collectors for supported recovery environments. Windows, Linux, and
   macOS retain separate, honest paths; there is no claim of a universal boot USB.

The local browser interface is the pragmatic development choice. It permits a
modern and accessible experience with standard HTML, CSS, and JavaScript, reuses
the same presentation layer on a phone for LAN sessions, works offline, and avoids
shipping Electron. The local server is not made remotely reachable by changing a
flag: local and LAN profiles have different security policies and route tables.

The existing checks already return `(findings, data)` without printing. That is
the correct seam. The UI must consume a versioned application model above that
seam; it must not parse console output or infer health independently.

### Baseline constraints that shape the build

- `run_full_scan()` is synchronous and reports only after a whole module returns.
  A responsive UI therefore needs an application orchestrator with module-boundary
  progress, cancellation, immutable snapshots, and bounded event history; putting
  the existing function in a background thread is only a throwaway prototype.
- The report currently has human findings and raw section dictionaries, not the
  finding codes, confidence, test-status, dependency, permission, or action models
  the UI needs. Add those models below the UI rather than creating a second diagnosis
  engine in JavaScript.
- The earlier macOS neighbor collector re-executed the whole CLI with
  `/usr/bin/python3`. That path has been removed: it is incompatible with a frozen
  application and can move the entire product across an unintended interpreter
  boundary. A narrow system-Python subprocess was also disproved on a modern Mac
  because it inherited the parent process's restricted PF_ROUTE visibility. The
  current collector therefore reports partial neighbor coverage when link-layer
  data is unavailable; portable builds must not imply complete LAN visibility.
- The current package has no Windows adapters. A Windows launcher can be prototyped,
  but the UI must show unsupported collectors and cannot imply Windows diagnostic or
  rescue parity until fixtures and real-platform tests exist.
- The current app has no durable store, daemon, updater, credential broker, or
  privileged helper. Preserve that small trust surface until a feature demonstrably
  needs one.

## Product truth and boundaries

The experience must say what Lantern actually knows:

- USB insertion does not launch code. The user opens **Start Lantern** and sees
  the collection scope before a scan begins.
- A baseline scan is read-only and does not require administrator access. Active
  LAN discovery, elevation, remediation, reboot, and recovery actions each need
  separate, just-in-time approval.
- Lantern tries the available network path during every normal diagnostic run.
  In rescue mode it also tries the network, but a network failure does not block
  hardware or storage viability checks.
- A Lantern LAN node reports the network from that node's vantage point. It cannot
  inspect another computer's logs, storage, drivers, or boot state without an
  authorized endpoint agent or supported remote-management channel.
- Findings distinguish `healthy`, `degraded`, `failed`, `blocked`, `not_tested`,
  `unsupported`, and `permission_denied`. "No evidence" is not "healthy."
- A report separates observations, interpretations, confidence, and proposed next
  actions. It never asks the UI to turn arbitrary probe strings into conclusions.
- Credentials and recovery keys are prerequisites, not report fields. Lantern
  never asks the user to paste a secret into an exportable form.
- Rescue describes five independent axes: hardware viability, storage and
  filesystem viability, operating-system viability, data recoverability, and
  network viability. It does not collapse these into one reassuring boolean.

## Experience principles

1. **Outcome before instrumentation.** Lead with "what is likely wrong" and "what
   to do next"; keep command output and raw evidence behind an explicit disclosure.
2. **Show the path.** The primary visualization is the Lantern Path: Device → Local
   link → Gateway → Internet → DNS/services. Each node has text, icon, status,
   tested time, and downstream impact.
3. **Evidence, not theatre.** Never use an animated success state before a probe
   completes. Show skipped, timed out, permission-denied, and unsupported checks.
4. **Progressive permission.** Begin read-only. Ask for active probes or elevation
   only when a concrete next step needs them.
5. **Reversibility is visible.** A fix is not just a button. Preview, expected
   interruption, permission, verification, and rollback state travel together.
6. **Share safely.** The default support export is structurally redacted, previewed
   before download, and labeled with exactly what remains, including LAN addresses.
7. **Calm under failure.** One failed module never destroys the whole run or hides
   successful evidence. Errors include a useful retry or alternative.
8. **No pretend platform parity.** Unsupported platform features remain visible as
   unavailable with an explanation; they are not stubbed as successful.

## User journeys

### First local run

1. The user opens **Start Lantern**. The browser opens a local-only page titled
   "Let's find what is getting in the way."
2. Lantern explains that it will inspect the computer and network, will not upload
   a report, and will not change settings during the baseline scan.
3. The user chooses a goal: **Something is not working**, **Check this network**, or
   **Prepare for recovery**. The choice changes emphasis, not the evidence contract.
4. A scope card lists baseline modules. **Active device discovery** is a separate,
   off-by-default switch with target network and host limit.
5. The user selects **Start read-only check**. No elevation prompt appears.
6. The scan view shows the Lantern Path, current module, elapsed time, completed
   modules, and **Cancel after current safe step**.
7. The overview leads with a plain-language assessment, confidence, affected scope
   (this device or network-wide), and the best next action.
8. If a supported fix exists, it appears in **Fixes** but never executes because a
   diagnosis was detected. Otherwise **Access needed** and guided steps explain the
   remaining work.
9. **Share report** opens a redacted preview and downloads locally only after the
   user confirms.

After the first run, the onboarding explanation may collapse to a one-screen scope
confirmation. Consent is never remembered for active discovery, elevation, or a
configuration-changing action.

### Technician using Lantern LAN

1. On the Lantern node, the owner selects **Start temporary LAN session**.
2. The host screen shows the exact interface, IP, subnet, default read-only scope,
   expiry, certificate status, and whether active tests are allowed. It refuses a
   public, loopback, VPN, or ambiguous interface until the owner makes a safe choice.
3. The host displays an eight-character, single-use pairing code and QR/address.
4. The technician opens the HTTPS address, verifies the displayed host identity and
   development certificate fingerprint, and enters the code.
5. Both screens show the connected client and remaining session time. The host can
   revoke or stop immediately.
6. The technician sees network-only evidence and recommendations. No endpoint
   filesystem, arbitrary command, or remote remediation route exists.
7. The session expires at its absolute limit even if active. All bearer tokens and
   ephemeral keys disappear when the process exits.

Self-signed TLS is a development limitation, not a production security claim. A
browser cannot silently pin an ad-hoc local certificate. Until Lantern has a
trusted-certificate or audited companion-client strategy, the UI must require
explicit fingerprint verification and display **Development secure session**. Do
not fall back to plaintext HTTP for reports or imply that a pairing code repairs an
unauthenticated transport.

### Rescue assessment

1. A working companion device or supported recovery environment opens **Rescue**.
2. The user selects platform, architecture/model when relevant, whether the system
   reaches login/recovery, and whether important data takes priority over repair.
3. Lantern shows a branched workflow with a **Stop—protect data first** gate when
   storage health or encryption state is unknown.
4. Automated collectors, when available, are read-only first. Manual steps have
   platform-specific instructions and an evidence field that records a status, not
   a credential.
5. The viability dashboard reports every axis separately, with unknowns and access
   blockers prominent.
6. Any disk repair, write mount, bootloader change, reinstall, reset, or encryption
   operation is a red-tier guided action and is outside automatic rescue.

## Information architecture

### Local and portable navigation

- **Overview** — overall assessment, Lantern Path, priority issues, what is working,
  what could not be tested, and the single best next step.
- **This device** — system, hardware, storage, services, and permissions as those
  collectors become available. In the current baseline, it honestly shows platform
  context and unavailable modules rather than fabricated device health.
- **Network** — route, interface, Wi-Fi, gateway, WAN, DNS, LAN neighbors, mDNS, and
  service-port evidence grouped by path segment.
- **Fixes** — available remediation plans, prior attempts, verification, and
  rollback availability.
- **Share** — human summary, structured report, redaction preview, and local export.

**Access needed** is a persistent panel and a filter within Fixes, not a hidden
settings page. Settings contains only presentation, privacy defaults, and diagnostics
about Lantern itself.

### LAN navigation

- **Overview** — network assessment and device-versus-network isolation.
- **Network path** — node, gateway, WAN, DNS, latency/loss, and scoped discovery.
- **Observed devices** — passive records first; active-scan results are labeled with
  scope and time. Presence is not identity.
- **Recommendations** — read-only proposed next actions and access prerequisites.
- **Session** — host identity, client identity, expiry, audit events, and disconnect.

### Rescue navigation

- **Viability** — the five-axis matrix and most conservative next action.
- **Guided checks** — platform-specific sequence with stop conditions.
- **Evidence** — sources, timestamps, uncertainty, and import/manual observations.
- **Recovery options** — safe supported routes, prerequisites, and consequences.
- **Export** — share-safe rescue summary without keys or credentials.

## Overview and triage dashboard

The dashboard should fit the essential answer into the first laptop viewport and
the first two phone screens:

1. **Assessment banner:** "Internet path works; local DNS is blocking the tested
   service" rather than "WARN." Include confidence and scope.
2. **Lantern Path:** five compact nodes; selecting one moves to that module.
3. **Priority issue cards:** impact, observation, interpretation, confidence, and
   next action. Never show more than three before **View all**.
4. **What is working:** explicit corroborating evidence prevents tunnel vision.
5. **Could not test:** unsupported, blocked, permission-denied, or timed-out modules.
6. **Access needed:** count and next relevant prerequisite, with no secret entry.
7. **Run facts:** scan profile, timestamp, duration, app/schema version, passive or
   active scope, and whether the report is redacted.

The overall health word is always accompanied by a sentence. Status order is
`critical`, `attention`, `unknown`, `healthy`, but unknown does not lower a known
critical result and informational findings do not make a healthy run look degraded.

## Per-module evidence views

All modules use the same anatomy:

- Header with status, one-sentence summary, time, duration, source, and supported
  platform.
- **Why this matters** in plain language.
- Key measurements with units and reference bands where evidence supports them.
- Findings split into **Observed** and **What it may mean**.
- Confidence and corroborating/contradicting evidence.
- Downstream relationships; for example, a missing route can explain WAN and DNS
  failures without duplicating five root causes.
- **Try again** for that isolated module and **Skip** while a run is active.
- Collapsed **Technical evidence** with structured data, source command/adapter,
  exact status, errors, and copy-as-redacted-JSON.

Module-specific requirements:

- Route renders Device → Interface → Gateway → WAN and treats ICMP as supporting,
  not decisive, evidence.
- DNS compares resolvers in rows with result class, answer summary, blocking status,
  and latency. CDN answer variance is not framed as corruption.
- Wi-Fi displays signal, band, channel, link rate, and security only when collected;
  Ethernet users receive an informational not-applicable state.
- LAN labels passive cache evidence versus active responses, target interface,
  network, host limit, provenance, and age.
- mDNS reports the finite browse window and raw/unique counts. An empty window is an
  observation, not proof that no services exist.
- Ports describes the explicit target and distinguishes open, refused, timed out,
  filtered, and unreachable.

## Remediation experience

A remediation is presented from its structured action contract. The UI never sends
a shell string or arbitrary command arguments.

### Fix card

- Problem and stable finding code addressed.
- Expected benefit and confidence.
- Risk label: **Low risk and reversible**, **Needs care**, or **Guided only**; color
  is secondary.
- Permission and access prerequisites.
- Network interruption and reboot expectations.
- **Preview fix** is primary; there is no immediate **Fix all** for yellow or red
  actions.

### Preview

The preview shows current value, proposed value, exact bounded resources affected,
preconditions, estimated duration, verification, rollback, and how long rollback
material remains available. A changed precondition invalidates the preview. Apply
uses a single-use approval token bound to action ID, parameters, run evidence hash,
and expiry.

### Apply, verify, and rollback

The progress view names the lifecycle state: checking prerequisites, requesting OS
authorization, applying, verifying, rolling back, or complete. Closing the browser
does not imply cancellation. The server owns the action state and makes interruption
semantics explicit.

Results are one of:

- **Fixed and verified**
- **Applied; verification inconclusive**
- **Not fixed; original state restored**
- **Partial change; attention required**
- **Not applied**

The result includes before/after evidence and an audit record without secrets.
Rollback is visible while valid. Automatic rollback is permitted only when the
action contract defines a verified-safe trigger; the UI never invents it.

## Access prerequisites

An access item has a stable type, purpose, owner, where authorization happens,
retention statement, and readiness state. Examples include local administrator,
Wi-Fi access, router administrator, Pi-hole administrator, ISP account, BitLocker
recovery key, FileVault account/recovery key, and managed-organization support.

The UI may say "Windows will request administrator approval when you apply this
fix." It must not render a generic password, token, or recovery-key input. If a
future device connector genuinely requires a secret, it needs its own reviewed
credential broker and must keep the value in memory only; that is outside this
architecture's initial implementation.

## Visual design system

The product metaphor is a calm light along a path, not a hacker dashboard.

### Foundations

- System font stack: `ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI",
  sans-serif`; monospaced data uses the platform monospace stack.
- Type scale: 14 body small, 16 body, 20 section, 28 page, 36 assessment on wide
  screens. Use 1.4–1.6 line height for body copy.
- Eight-pixel spacing rhythm with 4-pixel exceptions for icon/text alignment.
- Panels use a 12-pixel radius, one-pixel boundary, and minimal shadow. Focus rings
  are at least two pixels with offset.
- Light theme starts with canvas `#F6F8FA`, surface `#FFFFFF`, primary text
  `#172033`, secondary text `#536276`, and warm Lantern accent `#9A5A00`.
- Status palettes use tested accessible foreground/background pairs and always add
  an icon and word: healthy, information, attention, critical, unknown, and blocked.
  Exact tokens must pass automated WCAG contrast checks before landing.
- Use the Lantern accent for progress and focus, never as a health synonym.
- Motion is brief and functional. Honor `prefers-reduced-motion`; never pulse an
  unresolved failure indefinitely.

### Components

Implement a small in-repository component set rather than importing a web framework:

- App shell, navigation rail/bottom bar, page header, scope badge
- Assessment banner and Lantern Path
- Status badge, issue card, module card, evidence row, metric tile
- Progress stepper, skeleton, inline error, empty state
- Consent panel, risk panel, approval summary, rollback banner
- Access prerequisite card
- Session identity/expiry card and pairing-code display
- Viability matrix and guided-step card
- Disclosure, dialog, toast, and offline notice

All components have documented default, hover, focus, active, disabled, loading,
empty, error, and permission-blocked states.

## Responsive and accessible behavior

- At 1024px and above, use a 240px navigation rail and a readable content column
  capped near 1200px. Evidence and action context may use a two-column layout.
- From 600–1023px, collapse the rail and keep the Lantern Path horizontally
  scrollable with explicit labels.
- Below 600px, use a compact app bar and no more than five bottom-navigation items.
  Stack cards, convert tables to labeled rows, keep primary actions reachable, and
  avoid horizontal scrolling for evidence text.
- Touch targets are at least 44×44 CSS pixels. The experience works at 200% zoom and
  supports reflow at 400% where required.
- Target WCAG 2.2 AA. Use semantic landmarks, one logical heading hierarchy, native
  controls where possible, visible focus, skip links, keyboard-complete dialogs,
  and screen-reader labels that include status words.
- Scan progress uses a polite live region; critical new findings do not steal focus.
  Pairing codes are grouped for reading but copy without spaces.
- Charts have equivalent text/tables. Color, position, and animation are never the
  only carriers of meaning.
- Plain language is the default; technical terms have an adjacent explanation.

## Loading, empty, error, and offline states

- Initial loading shows the shell immediately and a labeled skeleton, not a blank
  white page.
- Scan progress reports completed/remaining modules and elapsed time. Indeterminate
  progress is used only when a native probe has no meaningful fraction complete.
- Cancellation stops scheduling new probes, waits for or terminates only probes
  whose contract permits it, and preserves completed evidence.
- Empty evidence is specific: "No mDNS advertisements observed during 5 seconds" is
  different from "mDNS browser unavailable."
- A module error is contained in its card with error class, safe detail, retry, and
  alternative. The Overview remains usable.
- Loss of LAN connection freezes the last snapshot, marks it stale with a timestamp,
  and offers reconnect; it never presents cached data as current.
- The local UI and rescue guides work offline. Remote dependencies are not required
  for layout, fonts, icons, diagnosis, or report export.

## Runtime architecture

```text
platform adapters / checks
          │
          ▼
orchestrator → evidence + findings + action registry
          │
          ▼
versioned presentation model
          │
     ┌────┴──────────┐
     ▼               ▼
local policy      LAN read-only policy
     │               │
loopback HTTP      selected-interface HTTPS
     │               │
system browser     paired browser
```

The browser receives immutable snapshots and ordered progress events. Diagnosis and
remediation state stay server-side. A full page refresh reconstructs the current
view from the run ID stored in an HttpOnly session, not from browser-local evidence.

### Local server profile

- Bind `127.0.0.1` on an OS-assigned port; do not bind `0.0.0.0` or an interface IP.
- Generate a 256-bit launch secret. Put it in the URL fragment, exchange it once for
  an HttpOnly, SameSite=Strict session cookie, then remove the fragment with
  `history.replaceState`.
- Validate the exact `Host` and `Origin`, allow no CORS, reject non-JSON mutation
  bodies, require a per-session CSRF header, and set a restrictive Content Security
  Policy with no remote scripts, styles, images, fonts, frames, or connections.
- Serve only packaged files from a manifest; never map a URL to a filesystem path.
- Keep reports in memory by default. The current export is an explicit browser
  download generated from the already validated, identifier-free UI snapshot after
  an on-screen preview. There is no report-export HTTP endpoint or second provider
  call. Browser, operating-system, backup, and sync behavior after download remains
  outside Lantern's control and is disclosed before download.
- Stop after a bounded idle period when no scan/action is active. A launcher can
  reopen the extant session or start a new one.
- Treat malicious local processes and browser extensions as residual risks. The
  loopback UI is a presentation surface, not a privilege boundary. Elevated work,
  when added, belongs in a minimal separately reviewed helper with action-specific
  messages.

Current local endpoints in `0.3.0.dev5`:

```text
GET  /app/                    static app shell and allowlisted assets
POST /api/session/exchange    one-use launch-secret exchange
GET  /api/session             current local session and CSRF refresh
GET  /api/status              bounded immutable UI snapshot
GET  /api/status/events       bounded same-origin server-sent status stream
POST /api/diagnostics/start   one consent-bound allowlisted profile
POST /api/diagnostics/cancel  bounded cancellation request
POST /api/session/revoke      revoke and close the local session
```

The share-safe file is serialized locally from the exact snapshot the browser has
validated and previewed; no endpoint returns a downloadable report. Future action
endpoints must not be enabled until the core remediation contract, privileged-helper
boundary, and independent tests pass. No current endpoint accepts a program name,
command line, module path, report file path, or unrestricted target.

### Presentation model

Add a UI-facing versioned model rather than shipping raw `Report.data` as the only
contract. It should contain:

- Run state and progress
- Overall assessment and scope
- Path nodes and dependency relationships
- Prioritized finding cards with stable codes/confidence
- Evidence summaries and expandable structured evidence
- Supported actions and access prerequisites
- Capability/permission matrix
- Privacy and active-scan scope

The current UI downloads only its bounded share-safe presentation model, never raw
`Report.data`. The presentation model is derived in Python and snapshot-tested so
CLI and UI cannot disagree about severity, root cause, or action eligibility. A
future raw machine-integration export would require a separate typed contract,
preview, retention policy, and security review.

## Portable delivery

### Development artifacts

Use PyInstaller in one-folder mode for the first development builds. One-folder is
easier to inspect, starts faster, and avoids a self-extracting executable pattern
that attracts unnecessary endpoint-security suspicion. Keep PyInstaller a build
dependency, not a core runtime dependency.

Build on the target OS; do not claim cross-compiled equivalence:

- macOS: the current candidate supports arm64 only, built with the exact pinned arm64
  runtime. A future x86_64 or universal2 build requires its own pinned runtime,
  native test host, signing inventory, and minimum-OS proof. A development build is
  explicitly unsigned until Developer ID signing and notarization are completed.
- Windows: build an x64 application directory with `Start Lantern.exe`; add arm64
  only after collectors and CI actually run there. SmartScreen reputation and code
  signing remain release gates.
- Linux: build x86_64 and aarch64 directories for tested glibc baselines. AppImage
  may wrap the tested directory later; it is not the initial source of truth.

Suggested USB root:

```text
Start Lantern (macOS).app
Start Lantern (Windows).exe
linux-x86_64/start-lantern
linux-aarch64/start-lantern
README - Start Here.html
SHA256SUMS
```

Checksums detect accidental corruption but do not authenticate a writable USB. A
family-grade release requires signed artifacts, macOS notarization, protected build
provenance, and verified updates. The app never adds persistence, installs a service,
or changes host configuration merely because it runs from removable media.

The immutable dev4 family beta passed signing, notarization, stapling, independent
verification, and local launch gates, but its local page can open in Safari behind
other windows. Dev5 corrects that foreground-launch behavior and is not a family
handoff until a fresh artifact passes every release and clean-machine gate. Passing
those gates makes it a limited family beta, not a production release.

### Build inputs and outputs

- Pin build dependencies and emit an artifact manifest with app version, schema
  version, Git commit, platform, architecture, build time, and SHA-256.
- Bundle all HTML/CSS/JS/icons locally and verify their hashes during the build.
- Keep diagnostic native-tool availability explicit; packaging Python does not make
  `dig`, `ip`, `avahi-browse`, or platform recovery tools appear.
- Test the artifact from a path containing spaces, a read-only directory, a writable
  USB, a standard user account, and with no project checkout or Python installation.
- Store mutable state in a per-run temporary directory with mode `0700` where
  applicable, not beside the executable. Remove it on clean shutdown and redact any
  retained crash metadata.

### macOS neighbor visibility packaging gate

Do not re-execute the whole Lantern application under a system Python. Do not add a
system-Python neighbor subprocess: real-process testing showed that it inherits the
parent application's macOS responsibility and the same restricted PF_ROUTE view,
so it adds a trust boundary without restoring link-layer visibility. The current
safe behavior is a truthful `partial` result.

Any future full-visibility path requires a separately threat-modeled native C or
Swift component or app capability that:

1. performs only the bounded PF_ROUTE/sysctl neighbor read and accepts no commands,
   paths, credentials, targets, or arbitrary arguments;
2. uses a fixed, versioned, size-bounded typed protocol and validates every IP,
   interface index, network boundary, and MAC address again in the parent;
3. is built in the protected pipeline, bundled with Lantern, and signed with the
   parent application using the minimum reviewed entitlement or capability;
4. is tested under the actual signed/frozen process topology on every claimed
   architecture (currently arm64 only), including restricted visibility, malformed
   output, timeout, and cleanup cases.

This component would remain read-only and distinct from any future privileged
remediation helper. Until that gate passes, partial neighbor/MAC visibility is an
honest platform limitation rather than a device or network failure.

## LAN responder architecture

`Lantern LAN` is a different application policy around the same diagnostic engine.
It cannot be enabled by setting the local server's host to `0.0.0.0`.

### Startup policy

- Enumerate routes and private interfaces. Prefer the default LAN interface but show
  the chosen interface/IP/subnet before binding.
- Refuse public addresses, wildcard binding, loopback, known container bridges, and
  known VPN/tunnel interfaces by default. Ambiguity requires a local choice.
- The owner chooses a duration (default 15 minutes, maximum 60 for development) and
  whether a narrowly scoped active profile is allowed. Read-only does not mean
  passive; the distinction is shown separately.
- Bind exactly the selected address on an ephemeral or configured high port.
- Generate an ephemeral ECDSA certificate, server session key, eight-character
  unambiguous single-use code, and 256-bit session tokens in memory.
- Advertise `_lantern._tcp` only while serving, with minimal TXT data: protocol
  version, port, TLS required, and non-sensitive instance ID. Discovery is never
  treated as authentication.

An optional `lan` dependency group may add `cryptography` to generate an ephemeral
certificate safely. Shelling out to `openssl` is acceptable only as an explicitly
detected development fallback with tests; it is not the portable contract.

### Pairing and session policy

- TLS 1.2 minimum, TLS 1.3 preferred; disable compression and legacy protocol
  versions. The temporary private key is owner-readable and deleted at shutdown.
- Pairing code comparison is constant-time. The code expires after ten minutes, is
  single-use, and is replaced only from the host UI.
- Limit pairing attempts per source and globally, add increasing delays, and lock a
  code after five failures. Do not reveal whether the host identity or code portion
  was wrong.
- Successful pairing returns a random HttpOnly, Secure, SameSite=Strict cookie.
  Rotate the token after privilege/scope changes and reject it after idle timeout,
  absolute timeout, host revocation, or server restart.
- Validate Host and Origin, deny CORS, require CSRF tokens on mutations, set CSP and
  `frame-ancestors 'none'`, and send `Cache-Control: no-store` plus a strict referrer
  policy on every report response.
- Record connection, pairing, scan, export, expiry, and revocation events without
  code, token, secret, full report, or credentials.
- Display source IP and a client-provided friendly label on both ends. The label is
  untrusted display data and must be length-limited and escaped.
- The host can disconnect a client, rotate pairing, remove active-scan permission,
  or stop the service immediately.

### Read-only API allowlist

Initial remote capabilities are fixed:

- Read session identity/scope/expiry.
- Read the latest structurally redacted network summary.
- Start or retry only allowlisted network profiles permitted at host startup.
- Observe progress and download a redacted report.
- End the caller's session.

There is no filesystem browser, upload, Python/module import, subprocess, command,
terminal, package installation, generic port range, arbitrary hostname, or remote
remediation route. Target addresses come from the server's scoped LAN/network policy,
not untrusted request strings. Any later endpoint pairing is a separate mutually
authorized protocol and security review.

## Rescue architecture and platform boundaries

### Shared viability model

Each axis reports status, confidence, evidence source, blockers, data-safety impact,
and safest next action:

| Axis | Initial evidence examples | Never inferred from |
|---|---|---|
| Hardware | firmware diagnostics result, memory test, device enumeration | installed OS boot alone |
| Storage/filesystem | device visibility, SMART where supported, read-only filesystem check | free-space estimate alone |
| Operating system | boot stage, recovery visibility, logs, safe-mode result | disk visibility alone |
| Data recoverability | encrypted volume state, read-only mount/read sample, backup state | presence of a partition |
| Network | link, addressing, gateway, WAN, DNS from recovery context | installed OS's prior report |

### Windows

- The supported recovery path is Windows Recovery Environment and, later, a WinPE
  collector built with Microsoft's ADK/WinPE add-on on Windows.
- Development first: provide a signed-later PowerShell/read-only collector and a
  guide for Startup Settings, Safe Mode, Startup Repair, memory diagnostics, disk
  visibility, BitLocker state, event/log capture, and network tests.
- Do not redistribute Microsoft recovery binaries from this repository. A media
  builder may orchestrate an authorized local ADK installation; it must record the
  ADK version and artifact hash.
- Do not set persistent BCD Safe Mode flags automatically. Prefer the supported
  Startup Settings workflow. Never store or echo a BitLocker recovery key.
- `chkdsk /f`, partition changes, boot repair, reset/reinstall, and unlocking an
  encrypted volume are guided red-tier steps with explicit data-risk language.

This path is a design/prototype until Windows collectors exist and a WinRE/WinPE
artifact has been tested on physical or representative virtual hardware.

### Linux and generic PC

- First make the Python collector runnable from an existing reputable live Linux
  environment. Use `lsblk`, `/sys`, `ip`, filesystem tools in no-write mode, and
  SMART/NVMe tools only when installed and supported.
- A later Lantern live image should be derived reproducibly from a supported LTS
  distribution and retain its signed Secure Boot chain. Never instruct the user to
  disable Secure Boot as the normal path.
- Mount questionable filesystems read-only by default and avoid automatic assembly,
  repair, or write replay. The UI highlights evidence that requires a specialist.
- Memory tests may require a separate signed boot entry and architecture-specific
  support; do not imply that the running Python app has tested all RAM.

A zipapp/portable collector plus static rescue UI is a working development target.
A signed custom ISO, broad driver coverage, Secure Boot validation, and physical
hardware matrix are later build/manual gates.

### macOS

- Use built-in macOS Recovery, Safe Mode, Disk Utility, Share Disk/Target Disk Mode
  where supported, and Apple Diagnostics. Branch instructions by Apple silicon and
  Intel; do not provide one ambiguous startup sequence.
- Do not automate startup-security reduction, external-boot enablement, `nvram`
  boot arguments, FileVault unlock, or destructive Disk Utility operations.
- The normal Lantern application can collect recovery readiness and generate an
  offline guide. Do not assume Python or the packaged macOS app can run inside every
  Recovery environment.
- Record Apple Diagnostics reference codes as user-entered evidence, validate their
  shape, and avoid claiming a definitive hardware pass from absence of a code.
- Data-first guidance uses Share Disk or other supported read-only/copy workflows
  before repair when storage health is uncertain.

The initial deliverable is a tested guided workflow and evidence model. A universal
bootable macOS Lantern environment is explicitly out of scope.

## Proposed repository modules

These paths are an implementation map, not evidence that the feature exists today.
Keep the existing `netdiag` package/CLI compatible.

```text
netdiag/
  app.py                         visible local launcher entry point
  application.py                 run controller and capability composition
  presentation.py                versioned UI view-model builder
  consent.py                     scope/permission records
  ui/
    server.py                    loopback-only HTTP lifecycle
    routes.py                    explicit local API dispatch
    security.py                  launch exchange, CSRF, Host/Origin, headers
    events.py                    bounded ordered progress-event buffer
    assets.py                    packaged-asset manifest and MIME allowlist
    static/
      index.html
      app.js
      styles.css
      icons.svg
  lan/
    server.py                    selected-interface HTTPS lifecycle
    policy.py                    interface, target, and capability allowlist
    pairing.py                   code state and rate limiting
    sessions.py                  token expiry/revocation
    tls.py                       ephemeral certificate creation/configuration
    discovery.py                 bounded mDNS publish lifecycle
    audit.py                     redacted security-event log
  rescue/
    models.py                    five-axis viability model
    workflows.py                 versioned platform guide loader
    evaluation.py                conservative evidence aggregation
    content/
      windows.json
      linux.json
      macos_apple_silicon.json
      macos_intel.json

packaging/
  pyinstaller/lantern.spec
  macos/                         entitlements/sign/notarize inputs
  windows/                       icon/version/sign inputs
  linux/                         wrapper/AppImage inputs after one-folder proof
scripts/
  build_portable.py              reproducible build orchestrator
  verify_artifact.py             manifest/hash/launch checks
```

When remediation lands, keep its registry and privileged helper outside `ui/` and
`lan/`. Those layers receive action IDs and typed parameters only.

## Required tests

### UI and local server

- `tests/ui/test_server.py`: loopback-only bind, random port, shutdown, no wildcard,
  no directory traversal, exact static manifest.
- `tests/ui/test_security.py`: one-use launch exchange, entropy, cookie flags, Host,
  Origin, CSRF, content type, CSP/CORS/cache headers, expiry, replay rejection.
- `tests/ui/test_routes.py`: method/path allowlist, malformed JSON, length limits,
  unknown run/action IDs, no command/file parameters.
- `tests/ui/test_events.py`: ordering, reconnect cursor, bounded buffer, cancellation,
  slow client, completed snapshot preservation.
- `tests/ui/test_presentation.py`: snapshot the overview, path, modules, access items,
  unsupported/unknown states, redacted/unredacted variants, and CLI/UI severity
  agreement.
- `tests/ui/test_assets.py`: offline asset graph, no remote URL, SRI/build manifest,
  MIME types, accessibility lint and contrast tokens.
- Browser tests (development dependency only): first-run consent, responsive phone
  and laptop layouts, keyboard traversal, dialog focus, live progress, isolated
  module failure, report preview/download, and remediation lifecycle using fakes.
  Use Playwright plus axe-core or an equivalent pinned test tool; neither becomes a
  core runtime dependency.

### LAN

- `tests/lan/test_policy.py`: default interface selection, ambiguity, public/VPN/
  bridge/wildcard refusal, scoped targets, active-profile approval.
- `tests/lan/test_tls.py`: protocol minimum, ephemeral key permissions/deletion,
  certificate lifetime/fingerprint, no plaintext fallback.
- `tests/lan/test_pairing.py`: code entropy/expiry/single use, constant-time path,
  per-source/global rate limits, lockout, rotation, replay, concurrent attempts.
- `tests/lan/test_sessions.py`: Secure cookie, idle/absolute expiry, rotation,
  revocation, restart invalidation, client listing.
- `tests/lan/test_routes.py`: strict read-only allowlist, no arbitrary targets,
  uploads, shell/command/file routes, CORS, CSRF, Host/Origin, output limits.
- `tests/lan/test_discovery.py`: publish/withdraw lifecycle and minimal TXT fields;
  spoofed discovery never bypasses pairing.
- `tests/lan/test_audit.py`: events are complete enough to understand actions and
  contain no codes, tokens, credentials, report bodies, SSIDs, or MAC addresses.
- Integration tests: two clients, failed-pairing flood, expiry during a scan, host
  revocation, network disconnect/reconnect, and proof that an external interface
  cannot connect when it was not selected.

### Rescue

- `tests/rescue/test_workflows.py`: JSON schema, branch completeness, platform/model
  specificity, every risky step labeled, stop conditions, no secret-capture fields.
- `tests/rescue/test_evaluation.py`: unknown-preserving aggregation, contradictory
  evidence, encryption blockers, data-first recommendation, per-axis independence.
- `tests/rescue/test_content_safety.py`: no automatic BCD/NVRAM/Secure Boot/encryption,
  repair, reset, partition, or read-write-mount commands in automatic steps.
- Fixture tests for Windows Recovery, representative Linux live environments, and
  normal/recovery-readiness macOS outputs before any collector is called supported.

### Portable builds

- Artifact launches without Python/project checkout from paths with spaces and from
  removable media.
- UI works offline and all packaged asset hashes match.
- Standard-user scan does not elevate or write beside the executable.
- A clean shutdown removes session secrets and temporary TLS keys.
- OS/architecture/version metadata and checksums match the artifact manifest.
- Clean VM tests on every claimed OS/architecture; physical-device validation for
  USB launch, LAN interface selection, and recovery paths before release claims.

## Staged delivery and proof labels

Every milestone should label a capability as one of:

- **Working:** implemented, automated tests pass, and exercised in the stated real
  environment.
- **Prototype:** runnable but has named security, packaging, platform, or UX gates.
- **Designed:** module/API/content contract exists but is not runnable.
- **Manual:** supported operating-system workflow that Lantern guides but does not
  execute.

Recommended sequence:

1. Build the presentation model and static design system against deterministic report
   fixtures. Add local server security and an end-to-end read-only run.
2. Conduct a first-time-user pass from a packaged development artifact. Fix unclear
   consent, waiting, triage, empty/error, and export states before adding fixes.
3. Add the remediation lifecycle UI using fake actions, then connect only reviewed
   green actions once their engine contracts and rollback tests exist.
4. Build LAN policy, TLS, pairing, expiry, and read-only report API. Treat browser
   certificate trust as a visible prototype gate.
5. Add rescue viability models and tested platform guides, then introduce collectors
   one platform at a time.
6. Only after clean-machine evidence: signing/notarization, protected build pipeline,
   trusted LAN transport decision, and boot/recovery-media validation.

## Acceptance gates

The local UI is ready for development use when a person unfamiliar with the project
can launch it without Python or a terminal, understand the scope, finish a read-only
run, identify the top conclusion, inspect evidence, and export a redacted report.
The test must include a healthy run, one module failure, no network, unsupported
Wi-Fi, and cancellation.

Run the first-user pass from a clean account or VM and the actual portable artifact,
not from `pip install -e` or a terminal. Reset all remembered onboarding state; give
the tester only the USB/folder and the prompt "Find out why this computer cannot get
online." Observe without coaching whether they can identify the correct launcher,
understand read-only versus active scope, tell what Lantern concluded versus could
not test, find the best next action, and create a redacted report. Capture every
hesitation as an experience defect, fix the highest-impact issues, and repeat with a
new tester or fresh profile. A developer successfully navigating their own UI is a
smoke test, not first-user validation.

Lantern LAN is ready for development use only when interface binding, TLS, pairing,
rate limits, expiry, revocation, audit redaction, and the absence of arbitrary target
or execution paths are independently verified. Self-signed certificate handling must
remain plainly labeled.

Rescue is ready to describe as a guide when every platform branch and data-protection
stop condition is reviewed. It is ready to describe as automated only per collector
and per tested recovery environment. It is ready to describe as bootable only after
the exact signed image has been built and exercised on the claimed architecture.
