from enum import StrEnum


class SecurityStatus(StrEnum):
    SECURE = "secure"
    UNKNOWN = "unknown"
    AT_RISK = "at_risk"
    CRITICAL = "critical"
