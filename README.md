# Lantern Net (`netdiag`)

Lantern Net is a network troubleshooting project for helping family, friends, and eventually support teams understand what is wrong without changing the computer. The working development build includes the `netdiag` command-line utility and a local browser interface for macOS and Linux. It checks the path from the local connection outward—interface, gateway, internet access, DNS, Wi-Fi, nearby LAN devices, mDNS services, and selected TCP ports—and turns the results into plain-language findings and next steps.

> **Development status:** the current source line is `0.3.0.dev4`. It adds signing-aware packaging work, but it is not a distributable family beta unless and until a clean Developer ID signed, Apple-notarized, stapled artifact passes the release gates. Even then, it remains a limited family beta—not production software, a remote-support service, an organization-wide network assessment, or an automatic repair tool. Use it only on computers and networks you own, manage, or are explicitly authorized to assess.

## What works today

- A usable macOS and Linux CLI with bounded network probes and per-check failure isolation.
- A modern local UI launched with `netdiag ui`. It binds only to this computer, starts nothing automatically, defaults to passive observation, and requires fresh consent for each run.
- An evidence-bounded UI conclusion with confidence and coverage, up to three priority items, a safe next step, an independent five-layer **Lantern Path**, and identifier-free module detail.
- Goal-based presentation for troubleshooting, endpoint network evaluation, and recovery context. A goal can change wording and priority order, but never packet activity, targets, or diagnostic scope.
- Human-readable reports with an overall assessment, coverage, findings, and suggested next steps.
- Typed JSON reports using the additive `1.1` report schema, including stable finding codes, structured evidence, confidence, and check outcomes.
- A share-safe `--redact` mode for full reports. It structurally removes or replaces sensitive identifiers instead of relying on text replacement.
- Passive neighbor discovery scoped to the detected local interface and network, with the discovery source and status recorded.
- Explicit opt-in for LAN ping sweeps and explicit targets for port checks.

The project also contains safety foundations for the intended future product. These are not yet connected end-user features:

- A typed remediation planner and dry-run lifecycle. No real machine-changing repair is registered, and there is no `apply` command or credential collection.
- Read-only rescue assessment models and reviewed manual guidance. Lantern does not currently boot a computer, enter Safe Mode or Recovery, repair a disk, unlock encrypted data, or determine hardware viability on its own.
- Security building blocks for a future LAN support mode. Non-loopback serving is hard-disabled, so this build cannot expose Lantern to another device on the network.
- A disabled, offline authorized-assessment envelope and coverage planner for defining written authority, exact private scope, exclusions, hard stops, technique budgets, vantage points, and data handling before any future scanner exists. It produces no evidence or compliance conclusion and is not wired to the CLI or UI.
- A locked local-developer packaging pipeline for a visibly launched macOS app or Linux one-folder build. The dev4 line adds signing-aware macOS release foundations, while offline verification and explicit trust labels remain mandatory. No clean, signed, Apple-notarized, stapled family handoff has passed the release gates yet.

There is no USB launcher or automatic execution in this build, and Windows diagnostic parity has not been implemented.

## Product lanes

The working build is the **personal support** lane: one person, one computer, and its immediate network path. The **Evaluate this network** goal remains an endpoint view; it does not inspect an entire household, business, financial environment, or municipality and cannot certify security or compliance.

The planned **authorized network assessment** lane is intentionally separate. It will require written scope, exclusions, approved techniques, packet and time budgets, emergency stop contacts, evidence provenance, and multiple approved vantage points before broader discovery is enabled. Regulated-environment work will add reviewed framework mappings without turning Lantern into an auditor or attestation authority. See [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md) for the staged design and explicit non-goals.

## Install for development

Python 3.10 or newer is required.

```bash
git clone https://github.com/ps57lr/lantern-net.git
cd lantern-net
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

This is an editable development install, not a signed or notarized release package. On Linux, activate the virtual environment with the equivalent command for your shell.

Confirm the installed build:

```bash
netdiag --version
```

## Open the local interface

Launch the development UI:

```bash
netdiag ui
```

Lantern opens a private, temporary browser session on this computer. The launch link is single-use, the service listens only on loopback, and the process closes when the session ends or reaches its time limit. No check starts until you choose a profile and select **Start check**.

The default profile only reads local route, interface, Wi-Fi, and neighbor state. **Include basic network checks** opts that one run into small public reachability, DNS, and gateway-service probes. A brief mDNS browse is a separate choice. The UI cannot sweep the LAN, accept credentials, apply fixes, expose remote access, or upload a report. After a finished check, it can preview and explicitly download the same identifier-free, redacted presentation shown in the browser as a local JSON file. Lantern makes no network upload; browser, operating-system, backup, and sync behavior for the downloaded file is outside Lantern's control.

## Run and share a report

For a normal local troubleshooting session:

```bash
netdiag run
```

For a report you intend to send to someone helping you:

```bash
netdiag run --redact
```

For a machine-readable support file:

```bash
netdiag run --json --redact > netdiag-report.json
```

`--redact` hides hostnames, Wi-Fi names, service instance names, BSSIDs, MAC addresses, and other classified identifiers. Local and gateway IP addresses may remain because they are often necessary for network diagnosis. Review any report before sharing it; redaction reduces exposure but is not a substitute for choosing a trusted support channel.

## Commands

| Command | What it checks |
|---|---|
| `netdiag ui` | Opens the consent-based, loopback-only local interface |
| `netdiag run` | Full layered diagnostic report |
| `netdiag dns [DOMAIN]` | Resolver answers, likely blocking, failures, and response time |
| `netdiag wifi` | Association, signal, band, channel, rate, and security when the platform exposes them |
| `netdiag route` | Interfaces, default gateway, ICMP behavior, and outbound HTTPS path |
| `netdiag lan` | Passive ARP/neighbor discovery scoped to the default interface and LAN |
| `netdiag lan --ping` | Active ping discovery, limited to 256 hosts by default |
| `netdiag ports HOST` | Bounded TCP check of common management and service ports on one explicit host |
| `netdiag mdns` | Bounded Bonjour/Avahi service-type discovery |

Every subcommand supports `--json`. The share-safe `--redact` option currently applies to the full `run` report. Run `netdiag COMMAND --help` for command-specific options.

Examples:

```bash
# Compare a local Pi-hole with a public resolver
netdiag dns nest.com --resolvers 192.168.0.183,1.1.1.1

# Inspect Wi-Fi details available to this computer
netdiag wifi

# Check a router's common TCP services
netdiag ports 192.168.0.1

# Check only selected ports
netdiag ports 192.168.0.1 --ports 53,80,443

# Actively scan a local /24; larger networks are refused by the default limit
netdiag lan --ping
```

## Understand the result

- `OK` — the tested path worked.
- `INFO` — useful context, not necessarily a health problem.
- `WARN` — degraded or inconclusive; follow the printed next step.
- `CRIT` — a foundational function, such as the default route or all tested DNS resolution, failed.

Coverage is reported separately from severity. A partial or unsupported check is not silently treated as healthy. A gateway that ignores ping is also not automatically considered down: if outbound TCP works, Lantern reports that behavior as information because many routers block ICMP.

Exit codes are `0` for healthy or informational results, `1` for warnings, and `2` for critical findings or invalid CLI input.

## JSON report contract

Full JSON reports use schema `1.1` and include the tool version, an opaque report ID, UTC start time, duration, execution and outcome status, coverage, findings, checks, evidence, access prerequisites, and remediation state. Probe-specific data remains available under `data`. Optional probe failures are represented as structured outcomes rather than aborting the entire report.

The bundled [`report-1.1.schema.json`](netdiag/schemas/report-1.1.schema.json) defines the external contract. The `1.x` line is additive: existing field meanings are preserved, new fields may be added, and consumers should ignore fields they do not recognize.

Raw JSON can contain device and network identifiers. Prefer `netdiag run --json --redact` for support sharing.

## Safety and privacy

Diagnostics do not change system or network configuration, but several checks still generate ordinary network traffic. DNS and internet-path checks contact their displayed targets; mDNS browses the local network; `ports` attempts TCP connections to the explicit host; and `lan --ping` actively probes the detected subnet. Use active checks only within an authorized scope.

No report is uploaded by `netdiag`. The CLI and local UI provide no fields for passwords, API tokens, recovery keys, or router credentials. They do not install persistence, elevate privileges, execute arbitrary scripts, or open a LAN listener. The UI service binds to `127.0.0.1` on an operating-system-selected port, uses a unique per-launch `*.localhost` hostname, and expires automatically; that is local browser access, not remote support.

## Platform support

The diagnostic CLI currently supports macOS and Linux and uses native operating-system tools when available. Missing tools or restricted operating-system access are reported as unsupported or inconclusive instead of being presented as successful checks.

- **macOS:** route and interface tools, System Configuration data, available Wi-Fi tools, PF_ROUTE neighbor data, Bonjour, ping, and `dig`. Some modern app/process contexts restrict link-layer neighbor details; Lantern reports that as partial coverage rather than a network failure. Restoring full visibility will require a separately reviewed, signed native capability—not a whole-app Python re-execution.
- **Linux:** `ip`, `resolvectl`, NetworkManager/`nmcli`, available Wi-Fi tools, Avahi, ping, and `dig`.

Specific-resolver DNS comparison requires `dig`. Without it, system DNS can still use Python's resolver, and Lantern reports when it cannot query a chosen resolver rather than silently substituting another server.

Support depends on the host operating-system version, permissions, and installed native tools. Windows is a future platform, not a supported target in this development build.

## Develop and test

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check .
ruff format --check .
```

Checks return structured findings and evidence instead of printing directly. This keeps collection separate from terminal presentation, JSON serialization, the future local UI, and any later consent-based support transport.

Architecture and safety decisions are documented under [`docs/architecture`](docs/architecture). See the [assessment foundation](docs/architecture/ASSESSMENT_DESIGN.md), [packaging guide](docs/PACKAGING.md), [development release ledger](docs/RELEASES.md), and [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md) for the staged path from a dependable local utility to a consent-based product.

The repository also includes deterministic browser acceptance tests. They use a synthetic passive result through the real loopback/session/UI boundaries and do not run network collectors:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npx --no-install playwright install chromium
npm run test:browser
```

The browser matrix covers desktop, tablet, and phone layouts, keyboard/session lifecycle, local-origin enforcement, local report preview/download, and automated WCAG A/AA checks. CI runs the same matrix against source and an isolated built wheel, tests Python 3.10, 3.11, and 3.14, and inspects the packaged schema and assets.
