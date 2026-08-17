"""Security-first foundations for the temporary Lantern LAN responder.

The non-loopback transport is intentionally disabled pending independent review.
The modules in this package define and test the policy, pairing, session, TLS,
audit, discovery, and route boundaries without opening a listener.
"""

from netdiag.lan.audit import AuditEvent, AuditEventKind, AuditLog, AuditOutcome
from netdiag.lan.pairing import PairingAuthority, PairingDecision, PairingDisplay
from netdiag.lan.policy import InterfaceCandidate, LanScopePolicy, SelectedInterface
from netdiag.lan.sessions import SessionAuthority, SessionCredentials, SessionView
from netdiag.lan.tls import DevelopmentCertificate, EphemeralTlsProvider

__all__ = [
    "AuditEvent",
    "AuditEventKind",
    "AuditLog",
    "AuditOutcome",
    "DevelopmentCertificate",
    "EphemeralTlsProvider",
    "InterfaceCandidate",
    "LanScopePolicy",
    "PairingAuthority",
    "PairingDecision",
    "PairingDisplay",
    "SelectedInterface",
    "SessionAuthority",
    "SessionCredentials",
    "SessionView",
]
