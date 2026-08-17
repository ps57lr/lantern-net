"""Shared, transport-neutral status enums for the Lantern core."""

from __future__ import annotations

from enum import Enum


class _StringEnum(str, Enum):
    """Python 3.10-compatible string enum."""

    def __str__(self) -> str:
        return self.value


class ExecutionStatus(_StringEnum):
    """Whether a check or lifecycle step executed."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NOT_RUN = "not_run"


class OutcomeStatus(_StringEnum):
    """What an observation or diagnostic rule concluded."""

    HEALTHY = "healthy"
    INFORMATIONAL = "informational"
    DEGRADED = "degraded"
    FAILED = "failed"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    CANCELLED = "cancelled"


class ConfidenceLevel(_StringEnum):
    """Qualitative diagnostic confidence; deliberately not a fake probability."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Sensitivity(_StringEnum):
    """Classification used by structural report redaction."""

    PUBLIC = "public"
    NETWORK_ADDRESS = "network_address"
    DEVICE_IDENTIFIER = "device_identifier"
    USER_IDENTIFIER = "user_identifier"
    POTENTIAL_SECRET = "potential_secret"


class ActivityLevel(_StringEnum):
    """Maximum diagnostic impact authorized by a scan policy."""

    PASSIVE = "passive"
    LOW_IMPACT_NETWORK = "low_impact_network"
    ACTIVE_DISCOVERY = "active_discovery"

    def permits(self, requested: ActivityLevel) -> bool:
        order = {
            ActivityLevel.PASSIVE: 0,
            ActivityLevel.LOW_IMPACT_NETWORK: 1,
            ActivityLevel.ACTIVE_DISCOVERY: 2,
        }
        return order[self] >= order[requested]


class RiskTier(_StringEnum):
    """User-facing remediation risk classification."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
