# Lantern threat model

Status: Phase 0 independent review
Review date: 2026-08-16
Reviewed baseline: `v0.2.1` / `0871248`
Applies to: Lantern Core, Portable, local UI, LAN responder, and Rescue

## Executive decision

**Verdict: PASS WITH CONDITIONS for architecture and read-only development.**

The v0.2.1 collector is an appropriate seed for a larger product: checks are separated from rendering, probe timeouts are bounded, the LAN scope has platform provenance, and current tests pass. It is not yet a safe base for privileged execution, remote access, or recovery writes. Those capabilities introduce materially different trust boundaries and must not be implemented as a thin wrapper around the current process.

Development may proceed on domain contracts, structural redaction, a read-only local UI, packaging experiments, mocks, fixtures, and dry-run remediation planning. The following remain gated until a later independent PASS:

- executing a remediation against the developer's real host;
- exposing a LAN listener beyond loopback;
- accepting or storing a credential or recovery key;
- changing boot configuration, mounting suspect storage read-write, or creating/running recovery media;
- enabling an updater or claiming signing, notarization, Secure Boot, or production readiness.

## System and security objectives

Lantern is intended to collect evidence, distinguish device faults from network faults, explain conclusions, propose bounded fixes, and guide recovery. Security objectives are:

1. Preserve host, network, storage, and boot integrity.
2. Keep the affected person in control of collection, elevation, active probing, remediation, disruption, and recovery.
3. Keep credentials, recovery keys, session secrets, and identifying evidence out of reports and logs.
4. Make remote access authenticated, temporary, locally visible, scoped, and revocable.
5. Represent uncertainty honestly. Unsupported, denied, skipped, failed, and not tested must never be rendered as healthy.
6. Preserve a verifiable record of approved actions and results without recording secrets.
7. Make distributed and recovery artifacts tamper-evident and attributable to a known build.

Availability is important, but never outranks data integrity or informed consent. A failed diagnostic is preferable to an unsafe repair.

## Scope

### Current baseline

The reviewed CLI runs read-only macOS and Linux collectors for routes, DNS, Wi-Fi, neighbor discovery, mDNS, and selected gateway ports. It emits human and JSON reports and supports identifier redaction. At the review snapshot, 29 tests passed in the project virtual environment. Static analysis was not clean: four existing lint findings remained. The baseline also has correctness and trust-model gaps called out below; passing unit tests do not close those gaps.

### Planned surfaces

- **Lantern Core:** evidence, diagnosis, findings, remediation plans, reports, registries, and platform adapters.
- **Lantern Portable:** visibly launched, self-contained removable-media application.
- **Lantern Local UI:** consent, progress, triage, evidence, recommended actions, and export.
- **Lantern LAN:** temporary node and technician UI reachable on an explicitly selected local interface.
- **Lantern Rescue:** Windows recovery integration, a signed Linux recovery environment, and guided macOS Recovery/Diagnostics workflows.
- **Build/update path:** reproducible artifacts, signing/notarization, dependency inventory, and a future verified updater.

Enterprise ingestion, multi-tenant storage, unattended endpoint management, and generic remote administration are not authorized by this phase.

## Assets

| Asset | Why it matters |
|---|---|
| User data and storage | A bad repair or recovery write can cause irreversible loss. |
| Host and network configuration | DNS, routes, proxies, adapters, firewall, DHCP, and services can remove connectivity or weaken security. |
| Boot and encryption state | BitLocker, FileVault, Secure Boot, firmware, partitions, and bootloaders are high-consequence controls. |
| Credentials and recovery keys | Disclosure can compromise the device, network, accounts, or encrypted data. |
| Diagnostic evidence | Hostnames, SSIDs, BSSIDs, MACs, IPs, mDNS names, OS/hardware versions, logs, and errors can identify people and devices. |
| Findings and recommendations | Incorrect confidence or severity can cause an unsafe human decision. |
| LAN session secret and identity | Compromise enables unauthorized observation or attempted remediation. |
| Audit record | It must establish who approved what without becoming a secret store. |
| Portable/rescue artifacts and updater | Compromise creates a privileged supply-chain execution path. |
| Product trust | The UI must never imply that an untested component is healthy or that a repair is guaranteed. |

## Actors and assumptions

- The **affected user** controls the local device and must authorize sensitive actions.
- The **technician** may be a trusted family helper today, but must not receive ambient authority over the endpoint.
- A **local unprivileged process** may attempt to impersonate the UI, alter environment variables, race state, or access local IPC.
- A **malicious LAN peer** may discover the service, brute-force pairing, replay messages, perform browser attacks, or exhaust resources.
- A **network intermediary** may observe or alter traffic and DNS.
- A **malicious or compromised device** may emit hostile hostnames, mDNS records, command output, protocol data, or filesystems.
- A **supply-chain attacker** may alter USB contents, dependencies, build artifacts, or updates.
- A well-intentioned user may misunderstand severity, consent, credentials, destructive impact, or recovery limitations.

The local network is not a trusted boundary. Physical possession of the USB is not proof that its contents are authentic. Administrator elevation is not blanket consent for later actions.

## Trust boundaries and data flow

```text
USB/build artifact -> unprivileged launcher and UI -> Lantern Core
                                                   -> platform collectors -> OS/kernel/native tools/network
                                                   -> report/redaction -> screen/export/support bundle

local UI -> authenticated narrow IPC -> privileged remediation helper -> allowlisted OS APIs/tools

technician browser -> authenticated encrypted pairing -> LAN responder -> read-only Core
affected user UI  -> local approval/revocation ------^

rescue image -> recovery runtime -> read-only device inspection -> explicit red-tier repair boundary
```

The following boundaries require an explicit design decision record before implementation:

1. UI technology and local transport.
2. Privilege separation and authorization lifetime.
3. LAN authenticated key establishment, browser security, and interface binding.
4. Report schema evolution and field classification.
5. Packaging/signing/update provenance.
6. Recovery approach for Windows, Linux, and macOS.

## Non-negotiable controls

### Consent and probe impact

Every collector and action must declare an impact class:

| Class | Examples | Default behavior |
|---|---|---|
| Passive local | OS configuration, link state, cached neighbors | Allowed after visible collection consent. |
| Low-impact external | Bounded DNS/HTTPS connectivity tests | Disclosed before the run; targets and data sent are visible. |
| Active local-network | Ping sweep, port connection, discovery query, device/API interrogation | Separate, explicit scope approval. Never inferred from USB insertion. |
| Configuration change | DNS, DHCP, proxy, VPN, service, firewall, adapter changes | Per-action approval after preview. |
| Disruptive/recovery | Reboot, filesystem repair, bootloader, partition, encryption, reset | Red tier; guided/manual unless separately authorized. |

USB insertion must not trigger stealth execution. Launch, scan, elevation, active probing, remediation, reboot, and recovery are separate consent events. Consent screens must state scope, data, targets, expected duration, likely interruption, and cancel behavior.

The current full scan automatically performs mDNS browsing and gateway TCP connection attempts. Before the local UI calls this behavior, these probes must be classified and either disclosed as low-impact or placed behind explicit active-network consent. Documentation and behavior must agree.

### Privilege separation

The diagnostic/UI process remains unprivileged. It must not simply relaunch the current Python process, GUI, web server, or all collectors as administrator/root. A future helper must expose a small, versioned, typed allowlist of remediation operations with independently validated parameters.

The helper must:

- authenticate its local client and require operating-system authorization;
- use absolute executable paths or native APIs, a minimal environment, a controlled working directory, and no shell;
- reject unknown action IDs, extra fields, paths, hosts, interfaces, and values;
- re-check preconditions immediately before apply;
- never accept arbitrary commands, scripts, environment variables, URLs, or shell fragments;
- return structured outcomes without reflecting secrets;
- have a short authorization lifetime and no hidden persistence;
- support cancellation only at declared safe points.

The existing command runner searches inherited `PATH`, merges standard error with output, inherits locale/environment, and has no typed result contract. It is acceptable only as a development collector boundary. It must not be reused inside an elevated helper.

### Evidence and diagnostic honesty

Evidence must include source, capture time, status, duration, platform, and sensitivity classification. Findings must include a stable code, severity, confidence, evidence references, applicable platform, and next action. Overall health and execution coverage are distinct values.

Required states include at least:

- healthy;
- degraded;
- failed;
- blocked or intentionally filtered;
- permission denied;
- unsupported;
- skipped by user;
- cancelled;
- timed out;
- inconclusive;
- not tested.

An empty findings list or all-skipped run must not produce an unconditional `OK`. Human copy should say “no problem detected in completed checks,” show coverage, and identify uncertainty.

Diagnosis rules must not turn one ambiguous signal into a root cause or remediation. Corroborate across layers and show counter-evidence. A fix recommendation needs a fresh precondition check because network and host state can change between diagnosis and apply.

Known false-positive traps requiring fixtures and rules include:

- a valid default route with no gateway address (VPN/PPP/point-to-point);
- captive portals and firewalls that permit TCP but not useful Internet access;
- ICMP filtering;
- intentional Pi-hole/DNS filtering, NXDOMAIN, IPv6-only answers, and CDN variance;
- VPN, multiple interfaces, VLANs, Docker/VM bridges, and changing default routes;
- a brief or incomplete ARP/mDNS window;
- Ethernet use being reported as a Wi-Fi problem;
- missing privileges or native tools being reported as healthy;
- a storage-health tool being unavailable being confused with a healthy disk;
- recovery visibility being confused with filesystem, OS, or data viability.

### Remediation lifecycle

Every action has a stable ID, typed parameters, platform support, preconditions, permission, risk tier, preview, apply, verify, rollback, interruption and reboot disclosures, plus an audit-safe result. Diagnosis never executes an action automatically.

Required state transitions are explicit and testable, including refused, denied, stale-precondition, applying, applied, verification-failed, rolling-back, rolled-back, rollback-failed, cancelled-before-apply, interrupted, and manual-follow-up-required.

Green does not mean risk-free. Yellow requires explicit approval and rollback evidence. Red remains instructions-only until separately authorized. “Rollback available” may be shown only when it has been implemented and tested for that platform/state. A failed rollback must escalate visibly and preserve recovery instructions.

Unattended development and first-user testing must use dry-run/mocked actions only. No real DNS, route, proxy, firewall, adapter, service, boot, disk, or credential changes are within the current approval.

### Reports, privacy, and credentials

Collection is local-first and data-minimized. Every schema field has a classification and export policy. Redacted export is the default sharing path, but must be described as **share-safe**, not anonymous: LAN/public addresses, timing, OS version, and topology may still identify a household.

Structural redaction must happen before rendering or transport. It must cover structured fields and derived prose, nested errors, command output, filenames, usernames, domains, service records, and future plugin data. The current global substring-replacement approach can corrupt unrelated diagnostic text and does not guarantee that unclassified strings are safe; it must not be the long-term boundary.

Reports and logs must never contain passwords, tokens, cookies, pairing codes, private keys, recovery keys, authorization headers, clipboard contents, or credential prompt values. Access requirements are declarative labels only. Credentials should be entered directly into an OS/device-owned prompt at the moment of use. If a future integration cannot avoid a secret, it requires a separate design review, memory-only handling where possible, OS-backed secure storage when persistence is essential, explicit deletion, and log canary tests.

Exports require a preview, clear destination, atomic write, restrictive permissions, bounded retention, and user deletion controls. Crash reports and telemetry remain off until separately designed and consented.

### Local and LAN web security

A loopback UI is still exposed to local browser-origin attacks. It must bind only to loopback, use an unguessable per-launch capability, validate `Origin`/`Host`, prevent CSRF and WebSocket hijacking, set a restrictive Content Security Policy, ship assets locally, escape all evidence, and avoid placing secrets in URLs. The browser must not be able to invoke privileged operations without fresh local approval.

The LAN responder adds stronger requirements:

- start only after local approval and display that it is active;
- bind to one selected local address, never wildcard interfaces by default;
- make no UPnP/NAT/firewall changes and fail closed if scope cannot be proven;
- advertise only while active and never advertise a pairing secret;
- use encrypted transport with authenticated key establishment bound to a high-entropy locally displayed code/QR and the intended device identity;
- rate-limit and lock out pairing attempts without enabling trivial denial of service;
- use short-lived, rotation-safe, replay-resistant sessions;
- protect HTTP and WebSocket endpoints against CSRF, cross-origin use, request smuggling, path traversal, injection, and oversized input;
- show paired technician identity, permissions, activity, expiry, and immediate local revocation;
- default to read-only and require a separate local approval for each future remediation class/action;
- expose no arbitrary command, file browser, shell, script, plugin upload, URL fetch, or generic proxy;
- bound concurrency, request size, scan scope, duration, and packet rate;
- leave no listener, advertisement, session, or firewall exception after shutdown/expiry.

The first LAN milestone should provide read-only network assessment only. Endpoint logs, storage, drivers, processes, and boot state are unavailable unless an affected endpoint independently runs Lantern and pairs. The UI and reports must not imply otherwise.

### Rescue boundary

Rescue is a different product mode, not an elevated Portable action. Its initial goal is viability assessment, not automatic repair.

- Preserve Secure Boot, FileVault, BitLocker, firmware passwords, driver-signature enforcement, and platform recovery protections.
- Require physical-presence startup actions and explain platform limitations.
- Mount suspect filesystems read-only by default; verify target identity and power state.
- Never request, echo, save, log, transmit, or include recovery keys in a report.
- Separate hardware viability, memory test coverage, storage visibility/health, filesystem readability, OS bootability, encryption/access state, data recoverability, and network viability.
- Do not infer disk health from SMART availability alone or OS viability from filesystem visibility.
- Treat repair, write mounting, imaging to a destination, partitioning, bootloader work, encryption operations, reinstall/reset, firmware changes, and Safe Mode boot changes as red tier.
- Validate recovery media integrity before boot and identify the exact build/version.
- For macOS, guide supported Recovery, Safe Mode, Share Disk, Disk Utility, and Apple Diagnostics workflows rather than promising a universal external image.

No rescue media creation, boot, or disk write is approved during unattended development.

### Build, portable media, and update chain

Build outputs require provenance, hashes, dependency inventory, supported-platform labels, and reproducible-build documentation. Unsigned development builds must say so prominently; never simulate a signed/notarized status in the UI.

A portable launcher must not load code, configuration, plugins, or libraries from arbitrary writable locations. It must resist path/DLL/dylib hijacking and show its version/build identity. An updater is a future privileged supply-chain boundary and requires signed metadata/artifacts, rollback protection, atomic installation, channel separation, expiry, and compromise recovery before use.

## Modern UI safety and quality requirements

The UI is a safety boundary, not decoration. All modules must share a coherent design system and status vocabulary while adapting to local, technician, portable, and rescue contexts.

Required behavior:

- **Consent clarity:** a short first screen explains local evidence, network traffic, storage, and what will not happen. Active discovery, elevation, fixes, and recovery receive separate just-in-time consent.
- **Progressive disclosure:** lead with prioritized symptoms/root-cause hypotheses and plain-language next actions; place raw evidence, command output, and advanced controls behind labeled detail views.
- **Honest state:** never use a green check for unsupported, skipped, denied, timed out, or inconclusive work. Show check coverage, evidence age, confidence, and why a conclusion was reached.
- **Risk communication:** actions show risk by text and icon as well as color, exact change, expected interruption, permission, verification, rollback confidence, and cancel point before approval.
- **Credential-safe UX:** do not build generic credential forms. State the access needed, then hand off to the OS/device-owned authorization surface. Masking a field does not make logging safe.
- **Error recovery:** errors retain completed results, identify what was not tested, offer a safe retry, and never recommend a fix solely because a collector crashed.
- **Accessibility:** complete keyboard use, visible focus, semantic headings/controls/live regions, descriptive labels, screen-reader status, sufficient contrast, zoom/text scaling, reduced-motion support, and no color-only meaning. Progress must not continuously steal focus.
- **Responsive technician view:** phone through desktop layouts preserve paired-device identity, read-only/remediation state, scope, expiry, connection loss, and the always-visible revoke/end-session control.
- **Rescue guardrails:** destructive paths are visually and structurally separate, name the selected disk/device, require a fresh confirmation, and do not use countdowns, dark patterns, or preselected repair options.
- **Offline behavior:** no CDN fonts/scripts, graceful lack of Internet, and no hidden telemetry.

UI tests must include keyboard-only, screen-reader semantics, 200% zoom, high contrast, reduced motion, narrow phone layout, long/localized strings, hostile evidence strings, permission denial, cancellation, timeout, partial coverage, offline mode, session expiry, and failed verification/rollback. Automated checks supplement rather than replace manual assistive-technology review.

## Required Phase 0/1 conditions

These are mandatory conditions of this PASS WITH CONDITIONS verdict:

1. **Architecture records:** approve ADRs for UI/local transport, privilege separation, report/schema evolution, LAN security, packaging, and platform-specific rescue boundaries before their implementations cross the relevant trust boundary.
2. **Core state model:** implement stable finding/action IDs, evidence provenance/time/status/sensitivity, confidence, coverage, access prerequisites, cancellation, and the full dry-run remediation lifecycle before feature UI hard-codes current ad hoc dictionaries.
3. **Privilege wall:** keep Core/UI unprivileged and document the narrow helper protocol. No shared generic subprocess API and no arbitrary execution.
4. **Data inventory:** create a field-classification/export policy and structural redaction tests before any LAN transport, support-bundle automation, or external upload.
5. **Probe inventory:** label each collector by impact and scope. The UI cannot silently run active local-network probes.
6. **Diagnostic safety:** address default-route/gateway conflation, isolated preflight failure, command-result ambiguity/locale, and all-skipped-equals-healthy before findings drive remediation.
7. **Remediation gate:** only mocks/dry runs until state transitions, stale preconditions, denial, interruption, verification, rollback, and audit-redaction tests pass and oversight reviews an actual action.
8. **LAN gate:** no non-loopback listener until the security ADR and automated interface-binding, pairing, replay, brute-force, CSRF/origin, expiry, revocation, input-limit, and shutdown-cleanup tests pass.
9. **Rescue gate:** keep prototypes read-only and offline. No boot/media/disk mutations until platform-specific review and explicit user authorization.
10. **UI gate:** produce the consent/state/risk/accessibility interaction specification with failure and partial-result states before calling the local experience complete.
11. **Build integrity:** clean tests and static checks, pin/record build inputs, scan secrets/dependencies, and identify unsigned artifacts honestly.
12. **First-time-user test:** use a clean profile/build and begin in read-only mode. During unattended work, do not enter credentials, elevate, expose a LAN service, run broad active discovery, perform remediation, or alter boot/storage. Record observed confusion, fix it, and rerun the same scenario.

## Required verification evidence by boundary

| Boundary | Minimum evidence before approval |
|---|---|
| Core schema | Unit/property tests for serialization, unknown fields, stable IDs, invalid states, time/status, and compatibility. |
| Redaction | Canary secrets in every field and derived string; nested errors; Unicode; substring collisions; default export; no mutation of source evidence. |
| Diagnosis | Captured multi-platform fixtures; counter-evidence; false-positive cases; all-skipped/denied/inconclusive behavior. |
| Remediation | Dry-run, typed validation, stale state, denial, cancellation, interruption, idempotence, verify failure, rollback success/failure, secret-free audit. |
| Local UI | Origin/CSRF/CSP if web-based, keyboard/accessibility, consent, offline, error, cancellation, and hostile-rendering tests. |
| LAN | Address binding, IPv4/IPv6, no wildcard/public exposure, authenticated pairing, brute force, replay, session fixation, expiry/revoke, origin controls, DoS bounds, cleanup. |
| Packaging | Clean VM, hash/provenance, no writable-path library loading, unsigned disclosure, dependency inventory. |
| Rescue | Read-only mounting, target identity, encrypted/unsupported media, damaged filesystem, safe cancellation, no key logging, platform-native recovery boundaries. |

## Residual risks accepted for early development

- Diagnostic rules will be incomplete and may be wrong; the UI must label confidence and evidence rather than imply certainty.
- Platform command formats and permissions change. Fixture breadth and explicit unsupported states reduce but do not eliminate parser drift.
- Local addresses and topology retained for diagnosis can still be identifying even in a share-safe report.
- A family-support tool cannot infer endpoint internals from network observation alone.
- Development artifacts are not trusted distribution artifacts until signing and provenance gates are complete.

These risks are acceptable only while the system remains visibly development-stage, local-first, read-only by default, and honest about incomplete coverage.
