"""Minimal, non-authenticating discovery contract for Lantern LAN.

No network publisher is provided by the core package.  A future reviewed adapter
must be injected and honor the bounded publish/withdraw calls.  Discovery data can
locate a host but can never create a paired or authenticated session.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Final, Protocol

SERVICE_TYPE: Final[str] = "_lantern._tcp.local."
PROTOCOL_VERSION: Final[str] = "1"
_INSTANCE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{24}$")


@dataclass(frozen=True, slots=True)
class DiscoveryDescriptor:
    instance_id: str
    address: str
    port: int

    def __post_init__(self) -> None:
        if _INSTANCE_RE.fullmatch(self.instance_id) is None:
            raise ValueError("discovery instance ID must be a 96-bit lowercase hex identifier")
        parsed = ipaddress.ip_address(self.address)
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if parsed.version != 4 or not any(parsed in network for network in private_networks):
            raise ValueError("discovery address must be exact RFC1918 IPv4")
        if not isinstance(self.port, int) or not 1024 <= self.port <= 65535:
            raise ValueError("discovery port must be non-privileged")

    @property
    def txt(self) -> tuple[tuple[str, str], ...]:
        """The fixed TXT allowlist deliberately excludes codes and identities."""
        return (
            ("proto", PROTOCOL_VERSION),
            ("port", str(self.port)),
            ("tls", "required"),
            ("instance", self.instance_id),
        )


class DiscoveryPublisher(Protocol):
    def publish(
        self,
        *,
        service_type: str,
        descriptor: DiscoveryDescriptor,
        timeout_seconds: float,
    ) -> object: ...

    def withdraw(self, handle: object, *, timeout_seconds: float) -> None: ...


class DiscoveryLease:
    """Deterministic owner of one advertisement handle."""

    def __init__(
        self,
        *,
        publisher: DiscoveryPublisher,
        handle: object,
        shutdown_timeout: float,
    ) -> None:
        self._publisher = publisher
        self._handle = handle
        self._shutdown_timeout = shutdown_timeout
        self._closed = False
        self._lock = threading.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._publisher.withdraw(self._handle, timeout_seconds=self._shutdown_timeout)
            self._closed = True

    def __enter__(self) -> DiscoveryLease:  # noqa: PYI034 -- Python 3.10 supports no typing.Self
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class DiscoveryController:
    """Starts discovery only through an explicit, injected reviewed adapter."""

    def __init__(self, *, operation_timeout: float = 2.0) -> None:
        if not 0.1 <= operation_timeout <= 5.0:
            raise ValueError("discovery timeout must be between 0.1 and 5 seconds")
        self._operation_timeout = operation_timeout

    def publish(
        self,
        publisher: DiscoveryPublisher,
        descriptor: DiscoveryDescriptor,
    ) -> DiscoveryLease:
        handle = publisher.publish(
            service_type=SERVICE_TYPE,
            descriptor=descriptor,
            timeout_seconds=self._operation_timeout,
        )
        return DiscoveryLease(
            publisher=publisher,
            handle=handle,
            shutdown_timeout=self._operation_timeout,
        )


def discovery_authenticates(_descriptor: DiscoveryDescriptor) -> bool:
    """Make the trust boundary executable: discovery never authenticates."""
    return False
