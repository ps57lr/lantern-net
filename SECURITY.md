# Security policy

## Intended use

Use `netdiag` only on computers, networks, and hosts that you own or are authorized to troubleshoot. Passive diagnostics run by default. Active LAN discovery requires `lan --ping`; port checks require an explicit host.

## Reporting a vulnerability

Please report security or privacy issues privately to the project maintainer. Include the affected version, platform, reproduction steps, and impact. Do not include real SSIDs, MAC addresses, device names, credentials, or public IP addresses in a report.

## Data handling

`netdiag` does not upload reports or include telemetry. Console output and explicitly downloaded files are under the user's control. The local UI previews its bounded, share-safe presentation before an explicit browser download; the browser, operating system, backup software, or sync service may then store or copy that file outside Lantern's control. Use `netdiag run --redact` before sharing a CLI diagnostic report. Redaction reduces exposure but is not anonymity, so review every file before sending or posting it.
