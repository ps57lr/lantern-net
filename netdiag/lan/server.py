"""Explicitly gated lifecycle for the not-yet-enabled LAN HTTPS responder.

This file contains no socket or HTTP-server implementation.  Non-loopback
exposure remains blocked until the independent security review passes and a later
change adds a narrowly reviewed HTTPS transport.  Changing a constructor flag
cannot bypass the gate.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final

from netdiag.lan.audit import AuditAction, AuditEventKind, AuditLog, AuditOutcome, AuditReason
from netdiag.lan.pairing import PairingAuthority, PairingDisplay
from netdiag.lan.policy import LanScopePolicy
from netdiag.lan.sessions import SessionAuthority
from netdiag.lan.tls import DEVELOPMENT_TLS_LABEL, EphemeralTlsProvider, TlsMaterialLease

# Independent oversight must explicitly approve a later patch which implements
# transport.  The current development build has no code path that opens a socket.
NON_LOOPBACK_BINDING_ENABLED: Final[bool] = False
LAN_CAPABILITY_STATUS: Final[str] = "designed_security_foundation_listener_disabled"
TRANSPORT_GATE_REASONS: Final[tuple[str, ...]] = (
    "independent_security_review_required",
    "ip_host_cookie_port_scope_requires_transport_design",
    "self_signed_certificate_requires_manual_fingerprint_verification",
    "same_origin_get_origin_header_requires_real_browser_validation",
)

RandomBytes = Callable[[int], bytes]


class LanExposureDisabled(RuntimeError):
    """Raised whenever this development build is asked to expose a listener."""


class LifecycleState(str, Enum):
    CREATED = "created"
    TLS_PREPARED_FOR_REVIEW = "tls_prepared_for_review"
    EXPOSURE_BLOCKED = "exposure_blocked"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ResponderConfig:
    scope: LanScopePolicy
    port: int = 0
    duration_seconds: int = 900

    def __post_init__(self) -> None:
        if not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("responder port must be zero or a valid TCP port")
        if 0 < self.port < 1024:
            raise ValueError("responder cannot use a privileged TCP port")
        if not isinstance(self.duration_seconds, int) or not 60 <= self.duration_seconds <= 3600:
            raise ValueError("responder duration must be between one minute and one hour")


@dataclass(frozen=True, slots=True)
class ResponderPreview:
    capability_status: str
    binding_enabled: bool
    exact_interface: str
    exact_address: str
    exact_network: str
    requested_port: int
    duration_seconds: int
    tls_required: bool
    tls_label: str
    read_only: bool
    allowed_profiles: tuple[str, ...]
    fixed_target_count: int
    arbitrary_targets_allowed: bool
    commands_allowed: bool
    file_access_allowed: bool
    remediation_allowed: bool
    credentials_accepted: bool
    transport_gate_reasons: tuple[str, ...]


class LanResponderFoundation:
    """Own temporary secrets/material while refusing all non-loopback starts."""

    def __init__(
        self,
        config: ResponderConfig,
        *,
        tls_provider: EphemeralTlsProvider | None = None,
        pairing: PairingAuthority | None = None,
        sessions: SessionAuthority | None = None,
        audit: AuditLog | None = None,
        random_bytes: RandomBytes = secrets.token_bytes,
    ) -> None:
        self.config = config
        network = config.scope.interface.network
        self.pairing = pairing or PairingAuthority(source_network=network)
        self.sessions = sessions or SessionAuthority(source_network=network, pairing=self.pairing)
        if self.pairing.source_network != network or self.sessions.source_network != network:
            raise ValueError("injected LAN authorities must use the exact selected network")
        if self.sessions.pairing_authority is not self.pairing:
            raise ValueError(
                "session authority must consume grants from the selected pairing authority"
            )
        self.audit = audit or AuditLog()
        self._tls_provider = tls_provider or EphemeralTlsProvider()
        self._tls_material: TlsMaterialLease | None = None
        self._state = LifecycleState.CREATED
        instance_random = random_bytes(12)
        if not isinstance(instance_random, bytes) or len(instance_random) != 12:
            raise ValueError("responder random source returned the wrong number of bytes")
        self._instance_id = instance_random.hex()
        self._lock = threading.RLock()

    @property
    def state(self) -> LifecycleState:
        return self._state

    @property
    def instance_id(self) -> str:
        return self._instance_id

    def preview(self) -> ResponderPreview:
        scope = self.config.scope
        return ResponderPreview(
            capability_status=LAN_CAPABILITY_STATUS,
            binding_enabled=NON_LOOPBACK_BINDING_ENABLED,
            exact_interface=scope.interface.name,
            exact_address=scope.interface.address,
            exact_network=scope.interface.network,
            requested_port=self.config.port,
            duration_seconds=self.config.duration_seconds,
            tls_required=True,
            tls_label=DEVELOPMENT_TLS_LABEL,
            read_only=True,
            allowed_profiles=scope.allowed_profiles,
            fixed_target_count=len(scope.fixed_targets),
            arbitrary_targets_allowed=False,
            commands_allowed=False,
            file_access_allowed=False,
            remediation_allowed=False,
            credentials_accepted=False,
            transport_gate_reasons=TRANSPORT_GATE_REASONS,
        )

    def issue_pairing_for_host_display(self) -> PairingDisplay:
        """Rotate the host-visible code without logging or returning it elsewhere."""
        with self._lock:
            self._require_not_stopped()
            display = self.pairing.issue()
            self.audit.record(
                AuditEventKind.PAIRING_ROTATED,
                AuditOutcome.COMPLETED,
                action=AuditAction.ROTATE_PAIRING,
                reason=AuditReason.HOST_APPROVED,
            )
            return display

    def prepare_tls_for_review(self, *, base_directory: Path | None = None) -> TlsMaterialLease:
        """Prepare short-lived files for TLS tests, without opening a listener."""
        with self._lock:
            self._require_not_stopped()
            if self._tls_material is not None and not self._tls_material.closed:
                return self._tls_material
            self._tls_material = self._tls_provider.prepare(
                interface_address=self.config.scope.interface.address,
                base_directory=base_directory,
            )
            self._state = LifecycleState.TLS_PREPARED_FOR_REVIEW
            return self._tls_material

    def start(self) -> None:
        """Fail closed before certificate generation, discovery, or any bind call."""
        with self._lock:
            self._require_not_stopped()
            self._state = LifecycleState.EXPOSURE_BLOCKED
            raise LanExposureDisabled(
                "Lantern LAN non-loopback listening is disabled pending independent review; "
                "this build contains no listener implementation"
            )

    def shutdown(self) -> None:
        """Deterministically invalidate every secret and delete temporary TLS files."""
        with self._lock:
            if self._state is LifecycleState.STOPPED:
                return
            failures: list[Exception] = []
            _capture_cleanup(
                lambda: self.audit.record(
                    AuditEventKind.SERVICE_STOPPED,
                    AuditOutcome.COMPLETED,
                    action=AuditAction.STOP_SERVICE,
                    reason=AuditReason.SHUTDOWN,
                ),
                failures,
            )
            _capture_cleanup(self.pairing.close, failures)
            _capture_cleanup(self.sessions.close, failures)
            if self._tls_material is not None:
                _capture_cleanup(self._tls_material.close, failures)
                self._tls_material = None
            _capture_cleanup(self.audit.close, failures)
            self._state = LifecycleState.STOPPED
            if failures:
                raise RuntimeError(
                    "LAN responder shutdown completed with cleanup failures"
                ) from failures[0]

    def _require_not_stopped(self) -> None:
        if self._state is LifecycleState.STOPPED:
            raise RuntimeError("LAN responder foundation is stopped")


def _capture_cleanup(operation: Callable[[], object], failures: list[Exception]) -> None:
    """Continue bounded cleanup after the documented local failure classes."""
    try:
        operation()
    except (RuntimeError, ValueError, TypeError, OSError) as exc:
        failures.append(exc)
