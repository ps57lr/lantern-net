# Authorized network assessment evolution

Status: design contract. `0.3.0.dev5` corrects macOS browser foregrounding but
includes only a disabled, offline engagement envelope and coverage-planning
foundation; business, municipal, regulated, organization-wide scanning, evidence,
and assurance features remain unavailable. Packaging and launch work do not enable
an enterprise assessment capability or compliance claim.

Lantern's local diagnostic core can grow into an assessment product, but a larger
scan is not automatically a better assessment. The enterprise product must combine
technical observations with authorization, scope, coverage, evidence provenance,
and human review. It must never turn a short endpoint scan into a security or
compliance certification.

## Product lanes

Lantern should use one evidence engine through three deliberately separate lanes:

1. **Personal support** helps a family member or friend understand one computer and
   its immediate network path. It starts passive, keeps identifiers local, and leads
   with one plain-language next step.
2. **Authorized network assessment** evaluates an agreed business or municipal
   environment from multiple approved vantage points. Every active technique is
   separately scoped, budgeted, logged, interruptible, and attributed to a written
   rules-of-engagement record.
3. **Regulated assurance support** maps independently reviewed evidence to a
   versioned framework catalog. It helps an assessor organize evidence and gaps; it
   does not issue an attestation, legal conclusion, audit opinion, or guarantee.

The user interface must always identify the active lane. A personal run cannot be
silently upgraded into a network assessment, and an assessment cannot be relabeled
as compliance simply because findings have framework references.

## Rules of engagement before packets

Any future organization-wide assessment needs a signed or otherwise verifiable
engagement envelope before Lantern enables active techniques. The envelope is not a
free-form command channel. It contains only typed, bounded fields:

- customer and authorizing-party references;
- assessment purpose and data sensitivity;
- canonical included networks, hosts, sites, and vantage points;
- explicit exclusions, fragile systems, operational-technology zones, and third
  parties that are not covered by the authorization;
- approved technique classes and a per-technique packet, concurrency, timeout, and
  host budget;
- maintenance window, local time zone, start and hard-stop times;
- primary contact, emergency stop contact, and incident-escalation procedure;
- retention, redaction, encryption, export, and deletion requirements;
- expected service interruption and stop conditions;
- approval identity, version, expiry, and immutable plan digest.

The runtime must canonicalize scope and fail closed. It must reject host-bit CIDR
widening, public or VPN targets unless expressly authorized, mutable target lists,
DNS rebinding, redirects to out-of-scope addresses, wildcard targets, and targets
learned from untrusted responses. A visible **Stop assessment** control must cancel
new work immediately and terminate bounded in-flight work at its safe boundary.

## Assessment ladder

Each level requires a new preview and explicit authorization. Authorization never
flows upward automatically.

| Level | Capability | Default | Current state |
|---|---|---:|---|
| A | Endpoint and local network-path observation | Passive | Local preview available |
| B | Small public reachability, DNS, and gateway checks | Off | Local consent available |
| C | Bounded discovery of an approved private segment | Off | Disabled design-only planner; no collector or UI |
| D | Approved service identification and configuration review | Off | Not implemented |
| E | Credentialed device, firewall, switch, AP, or cloud review | Off | Not implemented |
| F | Vulnerability validation or adversarial testing | Off | Separate product/security phase |

Levels D–F must not be implemented as arbitrary shell execution. They require
vendor-specific, read-only adapters, least-privilege service accounts, OS-managed
credential prompts or vault references, fixed APIs, response budgets, audit events,
and independent threat modeling. Secrets are never report fields.

## Evidence and conclusion model

Every report item must keep these concepts separate:

- **Observation:** what a named collector saw, when, and from which authorized
  vantage point.
- **Interpretation:** the bounded rule that explains why the observation matters.
- **Coverage:** attempted, completed, skipped, blocked, unsupported, timed out, or
  permission denied.
- **Confidence:** evidence strength and corroboration, not visual certainty.
- **Affected scope:** one endpoint, one segment, one site, or an explicitly unknown
  blast radius.
- **Recommendation:** a proposed risk-reduction step with prerequisites, expected
  disruption, validation, and rollback guidance.
- **Framework mapping:** a versioned reference to an outcome or safeguard, never a
  claim that the control is satisfied.

One Lantern node describes only its vantage point. No response is not proof that a
host is absent; an open port is not proof of vulnerability; a visible service is not
proof of identity; and a healthy path test is not proof that segmentation, logging,
backups, or incident response are adequate.

## Network hardening domains

An authorized assessment should organize evidence and recommendations around the
environment rather than around scanner commands:

- authoritative asset and network-device inventory;
- trust zones, sensitive-data flows, inter-zone policy, and default-deny boundaries;
- administrative plane isolation, MFA, bastions, and vendor remote access;
- edge exposure, inbound services, egress controls, DNS, DHCP, NTP, and IPv6;
- wireless authentication, guest separation, management interfaces, and rogue APs;
- switch, router, firewall, AP, and endpoint configuration lifecycle;
- vulnerability and patch management with ownership and remediation deadlines;
- centralized logs, time synchronization, alert coverage, and tested escalation;
- backups, immutable/offline recovery, continuity, and ransomware readiness;
- cloud/SaaS connectivity, third-party dependencies, and supply-chain access;
- sensitive municipal, payment, financial, personnel, justice, and tax-data paths.

Many of these domains require interviews, diagrams, configuration evidence, and
recovery exercises. Lantern must show them as **not assessed** until that evidence is
actually collected and reviewed.

## Framework posture

Use a small baseline and version every mapping catalog:

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) provides
  the risk-outcome structure across Govern, Identify, Protect, Detect, Respond, and
  Recover.
- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) provides prioritized,
  implementation-oriented safeguards and Implementation Groups.
- [CISA Cross-Sector Cybersecurity Performance Goals](https://www.cisa.gov/cybersecurity-performance-goals)
  provide a high-impact baseline suitable for critical-infrastructure and
  resource-constrained organizations.
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) informs assessment
  planning, execution, analysis, and mitigation without implying that one technical
  method is comprehensive.

Customer-specific overlays—such as PCI DSS, CJIS, tax-information, state privacy,
contractual, insurance, or financial-sector requirements—must be selected and
versioned for the engagement by a qualified person. Lantern may display supporting
evidence and gaps; only the appropriate assessor or authority can make the final
applicability and conformity decision.

## Deliverables

The future assessment package should generate four separate views from the same
immutable evidence set:

1. **Executive brief:** mission impact, top risks, affected scope, immediate actions,
   and decisions needed.
2. **Technical findings:** observation, evidence provenance, confidence, exposure,
   recommendation, validation, rollback, and owner.
3. **Coverage statement:** every included and excluded site, network, technique,
   vantage point, limitation, and interruption.
4. **Remediation roadmap:** prioritized work, prerequisites, estimated disruption,
   dependency order, verification plan, and residual risk.

Reports are structurally redacted by default and previewed before local export.
Organization identifiers, public addresses, topology, device inventory, and control
gaps are sensitive even when they are not credentials. Future centralized storage
requires tenant isolation, encryption, region/retention policy, access review,
immutable audit, deletion workflows, and breach-response design before deployment.

## Quality and release gates

Before enabling an assessment level, require:

- hostile scope/parser/redirect/DNS-rebinding and authorization-expiry tests;
- packet, concurrency, duration, CPU, memory, and report-size budgets;
- real-device fixtures for every supported platform and vendor adapter;
- false-positive and unknown-coverage budgets per finding;
- explicit cancellation, interruption, restart, and idempotency tests;
- multi-vantage conflict handling and clock/source provenance;
- independent security review and clean-profile first-user acceptance;
- signed, reproducible artifacts, update verification, and rollback;
- legal and insurance review for the offered service and jurisdictions.

Remote command execution, arbitrary scripts, credential collection into reports,
stealth scanning, persistence, and automatic configuration changes remain outside
the diagnostic agent. A later remediation component must use typed allowlisted
actions with preview, fresh approval, verification, rollback, and audit boundaries
separate from assessment collection.

## Delivery sequence

1. Continue hardening the implemented local explanation preview: Lantern Path,
   bounded priorities, confidence, coverage, safe next steps, and share-safe local
   preview are present; signed family distribution and broader user testing remain.
2. Ship signed/notarized macOS and appropriately trusted Linux collectors with
   honest platform parity; Windows remains a separate implementation phase.
3. Preserve the implemented offline engagement-envelope and coverage planner as
   disabled/design-only until the separate runtime gates below pass.
4. Review and enable one bounded private-segment discovery profile with packet and
   authorization tests.
5. Add read-only vendor adapters individually; never add a generic executor.
6. Add encrypted local export and human-reviewed framework mapping.
7. Only then design tenant services, remote support, or continuous assessment as
   separately threat-modeled products.
