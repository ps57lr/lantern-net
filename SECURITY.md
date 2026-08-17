# Security policy

## Intended use

Use `netdiag` only on computers, networks, and hosts that you own or are authorized to troubleshoot. Passive diagnostics run by default. Active LAN discovery requires `lan --ping`; port checks require an explicit host.

## Reporting a vulnerability

Please report security or privacy issues privately to the project maintainer. Include the affected version, platform, reproduction steps, and impact. Do not include real SSIDs, MAC addresses, device names, credentials, or public IP addresses in a report.

## Data handling

`netdiag` stores and uploads nothing by itself. Console output is the user's responsibility. Use `netdiag run --redact` before sharing a diagnostic report. Redaction is intended to remove common device identifiers, but users should still review output before posting it publicly.
