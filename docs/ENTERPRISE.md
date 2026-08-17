# Enterprise evolution

The local CLI is the collection engine, not the enterprise product by itself. Preserve that separation: checks should remain safe, bounded, platform-specific functions that return structured evidence without knowing about storage, tenants, or a web UI.

## Stage 1: dependable support utility

- Ship signed, reproducible macOS and Linux packages.
- Add Windows route, DNS, Wi-Fi, neighbor, and firewall probes behind the same JSON schema.
- Test parsers against captured outputs from supported OS releases and common locales.
- Add explicit captive-portal, proxy, IPv6, DHCP-lease, packet-loss, latency, and MTU checks.
- Add stable finding codes; do not make integrations depend on human-readable titles.

## Stage 2: consent-based remote support

- Generate a short-lived support session locally; require the end user to approve collection.
- Encrypt reports in transit and at rest and authenticate both technician and device.
- Default to redaction and data minimization. Make every collected field visible before upload.
- Sign the agent and update feed. Verify updates before installation.
- Keep active discovery opt-in, visibly scoped, rate-limited, and auditable.

## Stage 3: multi-tenant operations

- Put ingestion behind tenant-scoped authentication, RBAC, immutable audit logs, quotas, and abuse controls.
- Version the report and finding schemas independently. Support old agents during a published compatibility window.
- Separate raw evidence retention from normalized health signals; apply configurable regional retention policies.
- Use queued jobs and idempotent report IDs so reconnects cannot duplicate work.
- Export metrics and traces through standard observability interfaces without leaking device identifiers.

## Quality gates

- Parser fixtures for every supported OS/tool version.
- Unit, integration, privilege-boundary, and hostile-input tests.
- False-positive budgets for each finding and field validation against real incident outcomes.
- Performance budgets for runtime, CPU, memory, packets sent, and report size.
- Threat modeling for the local agent, update path, support-session enrollment, tenant isolation, and active probes.

Remote command execution, arbitrary scripts, credential collection, stealth scanning, and automatic configuration changes should remain outside the diagnostic agent. They greatly increase both product risk and compliance scope.
