"""Registered Lantern finding meanings and safe construction helpers."""

from __future__ import annotations

import ipaddress
import re
from string import Formatter

from netdiag.core.diagnostics import Confidence
from netdiag.core.redaction import RedactionPolicy, serialize_structured
from netdiag.core.registry import FindingDefinition, FindingRegistry
from netdiag.core.status import ConfidenceLevel, OutcomeStatus, Sensitivity
from netdiag.core.values import DiagnosticValue
from netdiag.models import Finding, Severity

_DEFINITIONS = (
    # Routing
    FindingDefinition(
        "NDG.ROUTE.DEFAULT_ROUTE_MISSING",
        "route",
        "No default route",
        "This machine has no default route, so an Internet path was not available.",
        "Check cable or Wi-Fi association and DHCP settings.",
    ),
    FindingDefinition(
        "NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE",
        "route",
        "Outbound TCP/443 works",
        "An Internet path completed a TCP connection through {target}.",
    ),
    FindingDefinition(
        "NDG.ROUTE.OUTBOUND_HTTPS_FAILED",
        "route",
        "Outbound TCP/443 failed",
        "Neither tested Internet endpoint accepted a TCP/443 connection.",
        "Check the firewall, captive portal, or WAN service.",
    ),
    FindingDefinition(
        "NDG.ROUTE.GATEWAY_REACHABLE",
        "route",
        "Default gateway reachable ({gateway})",
        "The gateway answered through {interface}.",
    ),
    FindingDefinition(
        "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP",
        "route",
        "Default gateway did not answer ping ({gateway})",
        "The gateway did not answer ICMP, but the external TCP path worked.",
        "Internet still works; the router likely blocks ICMP echo requests.",
    ),
    FindingDefinition(
        "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        "route",
        "Default gateway did not answer ping ({gateway})",
        "Neither gateway ICMP nor the tested external TCP path completed.",
        "Check the router, local link, VLAN, and DHCP settings.",
    ),
    FindingDefinition(
        "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP",
        "route",
        "Default route has no explicit next-hop address",
        "Traffic leaves through {interface}; a gateway ping does not apply to this route form.",
    ),
    FindingDefinition(
        "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP",
        "route",
        "Cannot ping {label} ({target})",
        "The ICMP probe did not answer, while the TCP path remained available.",
        "ICMP may be blocked; TCP and DNS checks are more conclusive.",
    ),
    FindingDefinition(
        "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        "route",
        "Cannot ping {label} ({target})",
        "Neither this ICMP probe nor the tested TCP path completed.",
        "Check the local link, captive portal, firewall, or WAN service.",
    ),
    FindingDefinition(
        "NDG.ROUTE.CHECK_FAILED",
        "route",
        "Routing check could not complete",
        "The collector stopped with {error_summary}; routing coverage is incomplete.",
        "Retry the routing check for a fresh result.",
    ),
    # DNS
    FindingDefinition(
        "NDG.DNS.FILTERING_DETECTED",
        "dns",
        "{domain} is blocked by {count} resolver(s)",
        "At least one resolver returned a loopback or unspecified address.",
        "This may be intentional filtering. Compare with a trusted resolver.",
    ),
    FindingDefinition(
        "NDG.DNS.RESOLVER_INCONSISTENT",
        "dns",
        "{domain} resolves inconsistently",
        "One or more resolver queries failed while another returned an address.",
        "Compare resolver reachability and policy before changing DNS settings.",
    ),
    FindingDefinition(
        "NDG.DNS.RESOLUTION_FAILED",
        "dns",
        "{domain} did not resolve",
        "None of the tested resolvers returned a usable IPv4 address.",
        "Check DNS settings, filtering, and Internet connectivity.",
    ),
    FindingDefinition(
        "NDG.DNS.ANSWER_VARIANCE",
        "dns",
        "{domain} returned different valid addresses",
        "This is commonly caused by CDNs, load balancing, or resolver location.",
    ),
    FindingDefinition(
        "NDG.DNS.RESOLUTION_SUCCEEDED",
        "dns",
        "{domain} resolved successfully",
        "{count} resolver(s) returned a usable IPv4 address.",
    ),
    FindingDefinition(
        "NDG.DNS.NO_RESOLVERS_CONFIGURED",
        "dns",
        "No DNS resolvers configured",
        "The system did not report a configured nameserver.",
        "Check Wi-Fi or Ethernet settings and DHCP.",
    ),
    FindingDefinition(
        "NDG.DNS.RESOLVER_CONFIGURATION",
        "dns",
        "System DNS resolvers: {resolvers}",
        "Resolver order matters because the first available resolver is normally tried first.",
    ),
    FindingDefinition(
        "NDG.DNS.CHECK_FAILED",
        "dns",
        "DNS check could not complete",
        "The collector stopped with {error_summary}; DNS coverage is incomplete.",
        "Retry the DNS check for a fresh result.",
    ),
    # Wi-Fi
    FindingDefinition(
        "NDG.WIFI.UNSUPPORTED",
        "wifi",
        "Wi-Fi check is unsupported",
        "Lantern does not yet collect Wi-Fi link evidence on {platform}.",
    ),
    FindingDefinition(
        "NDG.WIFI.NOT_CONNECTED",
        "wifi",
        "No active Wi-Fi connection detected",
        "This is normal when using Ethernet or when Wi-Fi is turned off.",
    ),
    FindingDefinition(
        "NDG.WIFI.CONNECTED",
        "wifi",
        "Connected to {ssid}",
        "{summary}",
    ),
    FindingDefinition(
        "NDG.WIFI.SIGNAL_STRONG",
        "wifi",
        "Signal strong ({rssi} dBm)",
        "The observed signal level is normally suitable for a stable link.",
    ),
    FindingDefinition(
        "NDG.WIFI.SIGNAL_FAIR",
        "wifi",
        "Signal fair ({rssi} dBm)",
        "The observed signal is usable but has less interference margin.",
    ),
    FindingDefinition(
        "NDG.WIFI.SIGNAL_WEAK",
        "wifi",
        "Signal weak ({rssi} dBm)",
        "Lower throughput and unreliable IoT pairing are more likely at this level.",
        "Move closer to the access point or check 2.4 GHz coverage for smart devices.",
    ),
    FindingDefinition(
        "NDG.WIFI.FIVE_GHZ_LINK",
        "wifi",
        "Connected on 5 GHz",
        "Channel {channel}; some IoT devices require a 2.4 GHz network.",
    ),
    FindingDefinition(
        "NDG.WIFI.LINK_RATE_OBSERVED",
        "wifi",
        "Link rate approximately {rate} Mbps",
        "The adapter reported this negotiated link rate; it is not an Internet speed test.",
    ),
    FindingDefinition(
        "NDG.WIFI.CHECK_FAILED",
        "wifi",
        "Wi-Fi check could not complete",
        "The collector stopped with {error_summary}; Wi-Fi coverage is incomplete.",
        "Retry the Wi-Fi check for a fresh result.",
    ),
    # LAN neighbors / active discovery
    FindingDefinition(
        "NDG.LAN.NEIGHBOR_CACHE_READ",
        "lan",
        "Neighbor cache: {count} entries on {interface}",
        "{addresses}",
    ),
    FindingDefinition(
        "NDG.LAN.NEIGHBOR_CACHE_PARTIAL",
        "lan",
        "Neighbor cache unavailable or incomplete ({cache_status})",
        "{reason}",
    ),
    FindingDefinition(
        "NDG.LAN.NEIGHBOR_CACHE_FAILED",
        "lan",
        "Neighbor cache could not be read",
        "Neighbor discovery evidence was not available.",
        "Retry the LAN check and inspect its normalized status.",
    ),
    FindingDefinition(
        "NDG.LAN.ACTIVE_DISCOVERY_NO_SCOPE",
        "lan",
        "Ping sweep was not run",
        "No primary LAN network was detected on the default interface.",
    ),
    FindingDefinition(
        "NDG.LAN.ACTIVE_DISCOVERY_SCOPE_TOO_LARGE",
        "lan",
        "Ping sweep was not run for this network",
        "The selected network exceeds the configured host safety limit.",
        "Narrow the scope before actively probing a large network.",
    ),
    FindingDefinition(
        "NDG.LAN.ACTIVE_DISCOVERY_COMPLETED",
        "lan",
        "Ping sweep {network}: {count} hosts responded",
        "{addresses}",
    ),
    FindingDefinition(
        "NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED",
        "lan",
        "Possible duplicate IP address",
        "Observed address-to-hardware conflicts: {conflicts}",
        "Confirm DHCP reservations and static address assignments.",
    ),
    FindingDefinition(
        "NDG.LAN.CHECK_FAILED",
        "lan",
        "LAN check could not complete",
        "The collector stopped with {error_summary}; LAN coverage is incomplete.",
        "Retry the LAN check for a fresh result.",
    ),
    # mDNS
    FindingDefinition(
        "NDG.MDNS.BROWSE_FAILED",
        "mdns",
        "mDNS browse failed",
        "The bounded service-discovery collector did not complete.",
        "Retry the mDNS check; completed modules remain valid.",
    ),
    FindingDefinition(
        "NDG.MDNS.UNSUPPORTED",
        "mdns",
        "mDNS browse is unavailable",
        "The required platform service-discovery utility was not found.",
        "Install avahi-utils on Linux; dns-sd is built into macOS.",
    ),
    FindingDefinition(
        "NDG.MDNS.SERVICES_DISCOVERED",
        "mdns",
        "Found {count} unique mDNS service advertisement(s)",
        "Observed service types: {types}",
    ),
    FindingDefinition(
        "NDG.MDNS.NO_SERVICES_OBSERVED",
        "mdns",
        "No mDNS services seen during the brief scan",
        "This can be normal when no service replied inside the bounded browse window.",
    ),
    FindingDefinition(
        "NDG.MDNS.CHECK_FAILED",
        "mdns",
        "mDNS check could not complete",
        "The collector stopped with {error_summary}; mDNS coverage is incomplete.",
        "Retry the mDNS check for a fresh result.",
    ),
    # TCP ports
    FindingDefinition(
        "NDG.PORTS.OPEN_PORTS_OBSERVED",
        "ports",
        "{host}: {count} tested port(s) open",
        "{ports}{omitted}",
    ),
    FindingDefinition(
        "NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE",
        "ports",
        "{host}: no tested ports open",
        "The host actively refused at least one connection, so it was reachable.",
    ),
    FindingDefinition(
        "NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED",
        "ports",
        "{host}: no tested ports open",
        "The target may be offline, unreachable, or filtering these probes.",
    ),
    FindingDefinition(
        "NDG.PORTS.CHECK_FAILED",
        "gateway_ports",
        "Gateway ports check could not complete",
        "The collector stopped with {error_summary}; gateway-port coverage is incomplete.",
        "Retry the ports check against the gateway for a fresh result.",
    ),
)


FINDING_REGISTRY = FindingRegistry()
FINDING_REGISTRY.register_many(_DEFINITIONS)
FINDING_REGISTRY.freeze()


_PARAMETER_SENSITIVITY: dict[tuple[str, str], Sensitivity] = {
    ("NDG.ROUTE.OUTBOUND_HTTPS_REACHABLE", "target"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.ROUTE.GATEWAY_REACHABLE", "gateway"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.ROUTE.GATEWAY_REACHABLE", "interface"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UP", "gateway"): Sensitivity.NETWORK_ADDRESS,
    (
        "NDG.ROUTE.GATEWAY_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        "gateway",
    ): Sensitivity.NETWORK_ADDRESS,
    (
        "NDG.ROUTE.DEFAULT_ROUTE_NO_EXPLICIT_NEXT_HOP",
        "interface",
    ): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP", "target"): Sensitivity.NETWORK_ADDRESS,
    (
        "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        "target",
    ): Sensitivity.NETWORK_ADDRESS,
    ("NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP", "label"): Sensitivity.PUBLIC,
    (
        "NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED",
        "label",
    ): Sensitivity.PUBLIC,
    ("NDG.ROUTE.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.DNS.FILTERING_DETECTED", "domain"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.DNS.FILTERING_DETECTED", "count"): Sensitivity.PUBLIC,
    ("NDG.DNS.RESOLVER_INCONSISTENT", "domain"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.DNS.RESOLUTION_FAILED", "domain"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.DNS.ANSWER_VARIANCE", "domain"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.DNS.RESOLUTION_SUCCEEDED", "domain"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.DNS.RESOLUTION_SUCCEEDED", "count"): Sensitivity.PUBLIC,
    ("NDG.DNS.RESOLVER_CONFIGURATION", "resolvers"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.DNS.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.WIFI.UNSUPPORTED", "platform"): Sensitivity.PUBLIC,
    ("NDG.WIFI.CONNECTED", "ssid"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.WIFI.CONNECTED", "summary"): Sensitivity.PUBLIC,
    ("NDG.WIFI.SIGNAL_STRONG", "rssi"): Sensitivity.PUBLIC,
    ("NDG.WIFI.SIGNAL_FAIR", "rssi"): Sensitivity.PUBLIC,
    ("NDG.WIFI.SIGNAL_WEAK", "rssi"): Sensitivity.PUBLIC,
    ("NDG.WIFI.FIVE_GHZ_LINK", "channel"): Sensitivity.PUBLIC,
    ("NDG.WIFI.LINK_RATE_OBSERVED", "rate"): Sensitivity.PUBLIC,
    ("NDG.WIFI.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.LAN.NEIGHBOR_CACHE_READ", "count"): Sensitivity.PUBLIC,
    ("NDG.LAN.NEIGHBOR_CACHE_READ", "interface"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.LAN.NEIGHBOR_CACHE_READ", "addresses"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.LAN.NEIGHBOR_CACHE_PARTIAL", "cache_status"): Sensitivity.PUBLIC,
    ("NDG.LAN.NEIGHBOR_CACHE_PARTIAL", "reason"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.LAN.ACTIVE_DISCOVERY_COMPLETED", "network"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.LAN.ACTIVE_DISCOVERY_COMPLETED", "count"): Sensitivity.PUBLIC,
    ("NDG.LAN.ACTIVE_DISCOVERY_COMPLETED", "addresses"): Sensitivity.NETWORK_ADDRESS,
    ("NDG.LAN.DUPLICATE_ADDRESS_SUSPECTED", "conflicts"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.LAN.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.MDNS.SERVICES_DISCOVERED", "count"): Sensitivity.PUBLIC,
    ("NDG.MDNS.SERVICES_DISCOVERED", "types"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.MDNS.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
    ("NDG.PORTS.OPEN_PORTS_OBSERVED", "host"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.PORTS.OPEN_PORTS_OBSERVED", "count"): Sensitivity.PUBLIC,
    ("NDG.PORTS.OPEN_PORTS_OBSERVED", "ports"): Sensitivity.PUBLIC,
    ("NDG.PORTS.OPEN_PORTS_OBSERVED", "omitted"): Sensitivity.PUBLIC,
    ("NDG.PORTS.NO_OPEN_PORTS_TARGET_REACHABLE", "host"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.PORTS.TARGET_UNREACHABLE_OR_FILTERED", "host"): Sensitivity.DEVICE_IDENTIFIER,
    ("NDG.PORTS.CHECK_FAILED", "error_summary"): Sensitivity.POTENTIAL_SECRET,
}

_COUNT_LIMITS = {
    ("NDG.DNS.FILTERING_DETECTED", "count"): 64,
    ("NDG.DNS.RESOLUTION_SUCCEEDED", "count"): 64,
    ("NDG.LAN.NEIGHBOR_CACHE_READ", "count"): 4096,
    ("NDG.LAN.ACTIVE_DISCOVERY_COMPLETED", "count"): 4096,
    ("NDG.MDNS.SERVICES_DISCOVERED", "count"): 256,
    ("NDG.PORTS.OPEN_PORTS_OBSERVED", "count"): 65_535,
}

_PUBLIC_LITERAL_VALUES = {
    ("NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UP", "label"): {
        "Cloudflare DNS",
        "Google DNS",
    },
    ("NDG.ROUTE.EXTERNAL_ICMP_UNANSWERED_PATH_UNCONFIRMED", "label"): {
        "Cloudflare DNS",
        "Google DNS",
    },
    ("NDG.WIFI.UNSUPPORTED", "platform"): {"Darwin", "Linux", "Windows"},
    ("NDG.LAN.NEIGHBOR_CACHE_PARTIAL", "cache_status"): {"partial", "empty"},
}

_PUBLIC_VALIDATED = (
    set(_COUNT_LIMITS)
    | set(_PUBLIC_LITERAL_VALUES)
    | {
        ("NDG.WIFI.CONNECTED", "summary"),
        ("NDG.WIFI.SIGNAL_STRONG", "rssi"),
        ("NDG.WIFI.SIGNAL_FAIR", "rssi"),
        ("NDG.WIFI.SIGNAL_WEAK", "rssi"),
        ("NDG.WIFI.FIVE_GHZ_LINK", "channel"),
        ("NDG.WIFI.LINK_RATE_OBSERVED", "rate"),
        ("NDG.PORTS.OPEN_PORTS_OBSERVED", "ports"),
        ("NDG.PORTS.OPEN_PORTS_OBSERVED", "omitted"),
    }
)


def _validate_parameter_classifications() -> None:
    expected: set[tuple[str, str]] = set()
    for definition in FINDING_REGISTRY:
        for template in (
            definition.title_template,
            definition.detail_template,
            definition.hint_template,
        ):
            expected.update(
                (definition.code, name) for _, name, _, _ in Formatter().parse(template) if name
            )
    configured = set(_PARAMETER_SENSITIVITY)
    if expected != configured:
        missing = sorted(expected - configured)
        extra = sorted(configured - expected)
        raise RuntimeError(
            f"finding parameter classifications are incomplete; missing={missing}, extra={extra}"
        )


_validate_parameter_classifications()


def finding_parameter_sensitivity(code: str, name: str) -> Sensitivity:
    """Return the frozen classification for one registered template parameter."""

    FINDING_REGISTRY.require(code)
    try:
        return _PARAMETER_SENSITIVITY[(code, name)]
    except KeyError as exc:
        raise ValueError(f"{code} parameter {name} has no sensitivity classification") from exc


def finding_parameter_names(code: str) -> frozenset[str]:
    """Return the exact reviewed template-parameter names for one finding."""

    FINDING_REGISTRY.require(code)
    return frozenset(name for finding_code, name in _PARAMETER_SENSITIVITY if finding_code == code)


def validate_finding_parameter_value(code: str, name: str, value: object) -> Sensitivity:
    """Revalidate one registered parameter at any presentation boundary."""

    sensitivity = finding_parameter_sensitivity(code, name)
    semantic_value = value
    if isinstance(value, DiagnosticValue):
        value.__post_init__()
        if value.sensitivity != sensitivity:
            raise ValueError(f"{code} parameter {name} must use {sensitivity.value} sensitivity")
        semantic_value = value.value
    _validate_parameter_semantics(code, name, semantic_value, sensitivity)
    return sensitivity


def make_finding(
    code: str,
    severity: Severity,
    status: OutcomeStatus,
    *,
    parameters: dict[str, object] | None = None,
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    rationale: str = "Diagnostic rule matched the collected observation.",
    data: dict | None = None,
    evidence_refs: tuple[str, ...] = (),
    remediation_refs: tuple[str, ...] = (),
) -> Finding:
    """Construct only registered findings and render raw prose structurally."""

    definition = FINDING_REGISTRY.require(code)
    supplied_parameters = dict(parameters or {})
    parameter_values: dict[str, object] = {}
    for name, value in supplied_parameters.items():
        sensitivity = validate_finding_parameter_value(code, name, value)
        if isinstance(value, DiagnosticValue):
            parameter_values[name] = value
        else:
            parameter_values[name] = DiagnosticValue(value, sensitivity)
    serialized = serialize_structured(parameter_values, policy=RedactionPolicy.raw())
    assert isinstance(serialized, dict)
    _require_template_parameters(definition, serialized)
    return Finding(
        severity,
        definition.category,
        definition.title_template.format_map(serialized),
        definition.detail_template.format_map(serialized),
        definition.hint_template.format_map(serialized) if definition.hint_template else "",
        data or {},
        code=definition.code,
        status=status,
        confidence=Confidence(confidence, rationale, evidence_refs),
        evidence_refs=evidence_refs,
        remediation_refs=remediation_refs,
        parameters=parameter_values,
    )


def _validate_parameter_semantics(
    code: str,
    name: str,
    value: object,
    sensitivity: Sensitivity,
) -> None:
    """Prove PUBLIC/network parameter meaning before it reaches a template."""

    key = (code, name)
    if key in _COUNT_LIMITS:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= _COUNT_LIMITS[key]
        ):
            raise ValueError(f"{code} parameter {name} must be a bounded count")
        return
    if key in _PUBLIC_LITERAL_VALUES:
        if value not in _PUBLIC_LITERAL_VALUES[key]:
            raise ValueError(f"{code} parameter {name} is not an allowlisted literal")
        return
    if key == ("NDG.WIFI.CONNECTED", "summary"):
        if not _is_wifi_summary(value):
            raise ValueError("NDG.WIFI.CONNECTED parameter summary is not normalized")
        return
    if key in {
        ("NDG.WIFI.SIGNAL_STRONG", "rssi"),
        ("NDG.WIFI.SIGNAL_FAIR", "rssi"),
        ("NDG.WIFI.SIGNAL_WEAK", "rssi"),
    }:
        if not isinstance(value, int) or isinstance(value, bool) or not -127 <= value <= 0:
            raise ValueError(f"{code} parameter rssi must be a dBm integer")
        return
    if key == ("NDG.WIFI.FIVE_GHZ_LINK", "channel"):
        if value != "unknown" and (
            not isinstance(value, str) or re.fullmatch(r"\d{1,3}", value) is None
        ):
            raise ValueError(f"{code} parameter channel must be numeric or unknown")
        return
    if key == ("NDG.WIFI.LINK_RATE_OBSERVED", "rate"):
        if not isinstance(value, str) or re.fullmatch(r"\d{1,6}(?:\.\d{1,3})?", value) is None:
            raise ValueError(f"{code} parameter rate must be normalized Mbps")
        return
    if key == ("NDG.PORTS.OPEN_PORTS_OBSERVED", "ports"):
        if not _is_port_summary(value):
            raise ValueError(f"{code} parameter ports is not a normalized port summary")
        return
    if key == ("NDG.PORTS.OPEN_PORTS_OBSERVED", "omitted"):
        if not _is_port_omission(value):
            raise ValueError(f"{code} parameter omitted is not a normalized omission summary")
        return
    if sensitivity == Sensitivity.PUBLIC and key not in _PUBLIC_VALIDATED:
        raise ValueError(f"{code} parameter {name} has no PUBLIC semantic validator")
    if sensitivity == Sensitivity.NETWORK_ADDRESS:
        _validate_network_parameter(code, name, value)


def _is_wifi_summary(value: object) -> bool:
    if value == "no details":
        return True
    if not isinstance(value, str) or not value or len(value) > 256:
        return False
    allowed_keys = {
        "band",
        "channel",
        "rssi_dbm",
        "signal_quality_percent",
        "tx_rate_mbps",
        "security",
    }
    seen: set[str] = set()
    for part in value.split(", "):
        key, separator, item = part.partition("=")
        if not separator or key not in allowed_keys or key in seen:
            return False
        if re.fullmatch(r"[A-Za-z0-9.,/+_-]{1,32}", item) is None:
            return False
        seen.add(key)
    return bool(seen)


def _is_port_summary(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    for item in value.split(", "):
        match = re.fullmatch(r"(\d{1,5})/([a-z0-9?-]{1,32})", item)
        if match is None or not 1 <= int(match.group(1)) <= 65_535:
            return False
    return True


def _is_port_omission(value: object) -> bool:
    if value == "":
        return True
    if not isinstance(value, str):
        return False
    match = re.fullmatch(
        r"; (\d{1,5}) additional open (port|ports) omitted from this summary",
        value,
    )
    if match is None:
        return False
    count = int(match.group(1))
    return 1 <= count <= 65_535 and (match.group(2) == "port") == (count == 1)


def _validate_network_parameter(code: str, name: str, value: object) -> None:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(f"{code} parameter {name} must be normalized network data")
    if name in {"target", "gateway"}:
        try:
            if str(ipaddress.ip_address(value)) != value:
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"{code} parameter {name} must be a canonical IP address") from exc
        return
    if name == "network":
        try:
            if str(ipaddress.ip_network(value, strict=True)) != value:
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"{code} parameter network must be a canonical CIDR") from exc
        return
    if name == "resolvers":
        values = value.split(", ")
        if not values or len(values) > 16:
            raise ValueError(f"{code} parameter resolvers is outside the supported bound")
        try:
            if any(str(ipaddress.ip_address(item)) != item for item in values):
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"{code} parameter resolvers must contain canonical IPs") from exc
        return
    if name == "addresses":
        if value == "No cached neighbors were in scope." or value == "":
            return
        cleaned = value.removesuffix("…")
        values = cleaned.split(", ")
        if len(values) > 12:
            raise ValueError(f"{code} parameter addresses exceeds the display bound")
        try:
            if any(str(ipaddress.ip_address(item)) != item for item in values):
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"{code} parameter addresses must contain canonical IPs") from exc


def _require_template_parameters(
    definition: FindingDefinition,
    parameters: dict[str, object],
) -> None:
    required = {
        name
        for template in (
            definition.title_template,
            definition.detail_template,
            definition.hint_template,
        )
        for _, name, _, _ in Formatter().parse(template)
        if name
    }
    missing = sorted(required - parameters.keys())
    if missing:
        raise ValueError(f"{definition.code} is missing template parameters: {', '.join(missing)}")


__all__ = [
    "FINDING_REGISTRY",
    "finding_parameter_names",
    "finding_parameter_sensitivity",
    "make_finding",
    "validate_finding_parameter_value",
]
