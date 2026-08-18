# Offline authorized-assessment foundation

Status: **DISABLED / DESIGN ONLY** in `0.3.0.dev6`.

The dev6 browser-foreground and gateway-ping serialization corrections, and earlier
signing-aware packaging work, do not enable this assessment lane. A notarized
family-beta artifact still provides only the local, disabled design foundation
described here—not organization-wide scanning or assurance.

This package is a safety boundary for planning a possible future authorized
network assessment. It does not scan, listen, connect, resolve names, launch a
process, write a file, store a credential, change a configuration, or expose a
CLI or UI action. Importing `netdiag.assessment` only defines immutable value
objects and pure validation, planning, and structural-export functions.

Business, nonprofit, and municipal labels describe an intended engagement
context only. They do not indicate a security audit, compliance review,
certification, attestation, legal conclusion, or suitability for a regulated
environment.

## Boundary and non-goals

The foundation currently supports exactly three operations in memory:

1. validate an immutable engagement envelope;
2. derive an immutable, disabled coverage plan; and
3. produce a structurally share-safe summary containing counts and fixed
   classifications rather than raw identifiers.

There is intentionally no CLI or local-UI wiring, collector registry,
networking, URL, DNS, redirect, plugin, shell, persistence, credential, report
evidence, finding, framework mapping, remediation, remote listener, or update
integration. A coverage-plan item always has state
`not_assessed_design_only`. An authorization record describes approval but
does not grant the running program any capability.

## Engagement envelope

`EngagementEnvelope` is a frozen, slot-backed value object. Its local schema is
`lantern.assessment-envelope.v1`, and the only valid foundation status is
`disabled`. It requires:

- opaque engagement, organization, scope-owner, assessor, authorizer,
  emergency-contact, incident-procedure, and deletion-procedure references;
- a descriptive environment kind, preparation purpose, and data-sensitivity
  classification chosen from fixed enums;
- UTC, whole-second authorization and operating times;
- an authorization issued before the operating window, valid through the
  hard stop, and lasting no longer than 30 days;
- an operating window no longer than 24 hours with a mandatory hard stop;
- the fixed authority statement `owner_confirmed` or
  `written_delegation_confirmed`;
- exact `True` values for explicit approval, emergency stop, exclusion review,
  local-only handling, encryption, and approved vantage points;
- exact canonical tuples in sorted, duplicate-free order; and
- a fixed structural-share-safe export policy and bounded retention period.

References are lowercase ASCII handles such as `principal.assessor-01`, not a
person's name, email address, phone number, incident instructions, password,
token, API key, recovery key, or other secret. Free-form note and secret fields
do not exist. Unknown fields fail validation at every JSON object boundary.

The deterministic local JSON round trip is explicitly named
`to_canonical_json` / `from_canonical_json`. It contains the sensitive local
scope and must not be shared. The parser rejects duplicate keys, non-finite
numbers, non-ASCII/noncanonical encoding, excessive size or depth, unknown
fields, and reordered or noncanonical values.

## Scope semantics

`AssessmentScope` is an exact allowlist plus explicit exclusions. Today it
requires the exact one-value target-realm enum `private_lan` and accepts only
canonical IPv4 RFC1918 targets directly managed as private LAN space. `vpn` and
`public` are not representable enum values. The model rejects:

- CIDRs with host bits, overlapping include ranges, and implicit widening;
- a range larger than 4,096 addresses or an effective scope larger than 4,096
  targets;
- public, shared/carrier, VPN-designated/non-LAN, loopback, link-local,
  multicast, documentation, and IPv6 targets;
- standalone hosts already covered by an included network;
- exclusions outside included scope and redundant overlapping exclusions;
- fragile or third-party assets that are not explicitly excluded; and
- an empty or fully excluded scope.

Private addressing alone does not prove ownership or authorization. The
organization and scope owner must independently establish that the targets are
directly managed and covered by the referenced approval. Supporting public or
VPN targets later requires a new policy, threat model, user experience, and
release gate; callers cannot opt into them by adding an unrecognized flag.

Site and asset values are opaque references. An approved vantage point must
bind to an included site and a non-excluded included asset. The model contains
no host name, interface command, login endpoint, listener address, credential,
or remote-control mechanism.

## Technique designs and budgets

The exact technique allowlist is:

- `passive_endpoint_observation_design`
- `low_impact_path_check_design`
- `private_segment_discovery_design`
- `service_identification_design`
- `read_only_configuration_review_design`

These are design classifications, not executable methods. Their only valid
state is `design_only`. Every approved technique must have exactly one budget,
and the ordered approved tuple must exactly match the ordered budget tuple.
Budgets bound target count, projected packets per target, concurrency, timeout,
and duration. Passive observation requires a zero packet budget. Discovery and
service-identification designs additionally require an explicitly included
private network. No budget can exceed effective scope.

Changing these enum values or limits is a security-relevant schema change. A
generic command, script, URL, protocol payload, vendor plugin, or arbitrary
target cannot be represented.

## Coverage plan and immutable digest

`build_coverage_plan` is a pure arithmetic transformation. It accepts an exact
`EngagementEnvelope` and a caller-supplied canonical UTC generation time. It
fails when authorization is not current or the hard stop has passed. It never
waits for the future start time, opens a socket, runs a command, or touches the
filesystem.

The returned `CoveragePlan` is frozen and records only disabled design steps.
Its SHA-256 digest binds the envelope digest, generation time, technique order,
approved vantage references, and every cap. `assert_matches` independently
checks that a plan has the exact approved techniques and vantage points, that
all caps match their budgets and scope, and that it was generated while the
authorization was current and before the hard stop. A self-consistent plan
constructed by a caller cannot be exported unless it passes that envelope
binding.

The digest detects accidental or adversarial mutation inside this local model;
it is not a signature, authorization token, or confidentiality mechanism. A
future signed artifact requires a separately designed key lifecycle and trust
model.

## Structural identifier-minimized export

`build_share_safe_export` constructs a new document from approved structural
fields. It does not redact a copy of the raw envelope. The export includes:

- fixed disabled/design-only notices;
- environment, purpose, sensitivity, and authority-statement enums;
- counts of included, excluded, fragile, and third-party scope entries;
- duration and hard-stop presence, without timestamps;
- vantage counts and roles, without vantage, site, or asset references;
- technique names and numeric budgets;
- confirmation that plan integrity was checked, without either stable digest,
  plus zero observation, evidence, finding, and conclusion counts; and
- bounded data-policy settings and explicit limitations.

It omits organization, engagement, principal, authorization, contact,
procedure, site, asset, vantage, IP, CIDR, and host values. Reports containing
those values need a separate encrypted local-export design and are not
share-safe merely because credentials are absent.

“Share-safe” means structurally identifier-minimized for a reviewed recipient;
it does not mean anonymous or suitable for public release. Environment and
sensitivity classes, entry counts, roles, technique choices, and budgets may
still disclose operational facts. The user must preview them and confirm the
recipient. Neither the local envelope digest nor the plan digest is exported:
both are stable correlation handles and the envelope digest transitively binds
sensitive, sometimes low-entropy values.

## Separation from evidence and conclusions

This package models planned authorization only. It deliberately has no
observation, evidence, result, finding, analyst conclusion, control outcome, or
framework-conformity type. Those records can exist only after separately
approved collection and evidence designs are implemented. A plan must never be
presented as coverage achieved, a passing result, or proof of security.

## Required gate before any activation

The `disabled` status must remain the only state until a separate phase supplies
and independently reviews all of the following:

- an authorization-bound runtime with packet, response, concurrency, memory,
  duration, and cancellation enforcement;
- DNS rebinding, redirect, target-learning, route-change, VPN, public-target,
  expiry, and hard-stop adversarial tests;
- exact packet-capture tests for each technique and supported platform;
- an emergency-stop experience and immutable audit events;
- safe interruption, crash recovery, artifact signing, and update rollback;
- evidence provenance, honest unknown coverage, and false-positive budgets;
- legal, insurance, privacy, records-retention, and customer rules-of-engagement
  review; and
- an independent security review plus real-environment pilot under written
  authority.

Enabling a scanner is not a valid modification to this package. Activation must
be delivered as a separately threat-modeled runtime phase that consumes a
validated plan without weakening these model invariants.
