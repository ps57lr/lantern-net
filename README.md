# netdiag

`netdiag` is a read-only network troubleshooting CLI for macOS and Linux. It works from the physical link outward—local interface, router, internet path, DNS, Wi-Fi, nearby devices, and common gateway services—and turns probe results into plain-language findings and next steps.

It is designed for helping family remotely today and for stable machine integration later: no runtime dependencies, no root requirement for normal checks, bounded timeouts, deterministic JSON, documented exit codes, and failure isolation between probes.

## Install

```bash
cd ~/Projects/netdiag
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Python 3.10 or newer is required.

## Fastest support workflow

Ask the person at the affected computer to run:

```bash
netdiag run --redact
```

The report keeps the network addresses needed for diagnosis but hides hostnames, Wi-Fi names, service instance names, BSSIDs, and MAC addresses. Copy the complete output into a message.

For an automated support bundle:

```bash
netdiag run --json --redact > netdiag-report.json
```

## Commands

| Command | What it checks |
|---|---|
| `netdiag run` | Full layered diagnostic report |
| `netdiag dns [DOMAIN]` | Resolver answers, blocking, failures, and response time |
| `netdiag wifi` | Association, signal, band, channel, rate, and security |
| `netdiag route` | Interfaces, default gateway, ICMP, and outbound HTTPS path |
| `netdiag lan` | Passive ARP/neighbor discovery |
| `netdiag lan --ping` | Active ping discovery, limited to 256 hosts by default |
| `netdiag ports HOST` | Bounded TCP check of common management/service ports |
| `netdiag mdns` | Bounded Bonjour/Avahi service-type discovery |

Every subcommand supports `--json`. Run `netdiag COMMAND --help` for command-specific options.

## Examples

```bash
# Compare a local Pi-hole with a public resolver
netdiag dns nest.com --resolvers 192.168.0.183,1.1.1.1

# Check a router's common TCP services
netdiag ports 192.168.0.1

# Check only selected ports
netdiag ports 192.168.0.1 --ports 53,80,443

# Actively scan a /24 LAN; large networks are refused by the safety limit
netdiag lan --ping
```

## How to read the result

- `OK` — the tested path worked.
- `INFO` — useful context, not a health problem.
- `WARN` — degraded or inconclusive; follow the printed next step.
- `CRIT` — a foundational function such as the default route or all tested DNS resolution failed.

Exit codes are `0` for healthy/informational, `1` for warnings, and `2` for critical findings or invalid CLI input. A gateway that ignores ping is not automatically considered down: if outbound TCP works, it is reported as information because many routers block ICMP.

## JSON contract

Full reports include `schema_version`, `tool_version`, UTC start time, duration, overall severity, structured findings, and raw per-check evidence. Each probe also records its duration; DNS and TCP probes include response times. Optional probe failures are contained and represented as findings rather than aborting the report.

The `1.x` schema will remain backward compatible. New fields may be added; consumers should ignore fields they do not recognize.

## Safety and privacy

Normal checks are read-only. `lan --ping` and `ports` generate active traffic, so use them only on networks and hosts you are authorized to test. LAN sweeps are refused when the detected subnet exceeds the configured host safety limit.

An unredacted report may contain a computer name, SSID, BSSID, mDNS instance names, LAN IP addresses, and neighbor MAC addresses. Use `run --redact` before sharing outside a trusted support channel. Local IP addresses and gateway addresses remain because they are usually essential to troubleshooting.

No report is uploaded by `netdiag`. Internet-path, DNS, and port probes necessarily send ordinary network traffic to the displayed targets.

## Platform behavior

`netdiag` uses native tools when available:

- macOS: `route`, `ifconfig`, `scutil`, `networksetup`, `wdutil`/`airport`, `arp`, `dns-sd`, `ping`, and `dig`.
- Linux: `ip`, `resolvectl`, NetworkManager's `nmcli`, `iwgetid`, `avahi-browse`, `ping`, and `dig`.

Specific-resolver DNS comparison requires `dig`. Without it, system DNS still works through Python's resolver, and `netdiag` explicitly reports that it cannot query a chosen resolver—it never silently substitutes another server.

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
```

The check modules return `(findings, data)` and do not print directly. This boundary keeps the human UI, JSON API, and future remote collection layer independent from platform probes.

See [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md) for the staged path from local utility to a consent-based, multi-tenant product.
